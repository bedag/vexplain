/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Package collectorclient is the operator's side of the collector API, vexplain.collector.v1alpha1: it calls the
// collectors over mutual TLS, and keeps their streams of evidence open. The design of collectors, evidence and
// rules describes the API, in docs/design/2026-10-31-collectors-evidence-rules.md, section 5.3.
//
// A Pool holds one connection to each collector, which the deployer, the executor and the streams share. Streams
// keeps a Watch open for each Collector that may be used and that watches, in each role that it declares, and hands
// what the stream delivers to that role's Sink.
//
// What a collector sends is untrusted: a collector needn't be built with the SDK, whose server checks what it
// sends. So every event is checked again on this side, and what isn't valid evidence never reaches a sink or the
// caller of Invoke. The streams' logs say what they dropped, and never repeat what a collector chose, such as a
// subject, a type or the message of an error.
package collectorclient

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/backoff"
	"google.golang.org/grpc/credentials"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/util/validation"

	// gzip registers itself as a compressor. The pool compresses its calls with it, and a collector's server, which
	// registers it too, then compresses its answers.
	"google.golang.org/grpc/encoding/gzip"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
	"github.com/bedag/vexplain/internal/collector/certs"
	collectorv1alpha1 "github.com/bedag/vexplain/sdk/api/collector/v1alpha1"
)

const (
	// port is where a collector's Service serves the collector API.
	port = "9443"
	// maxMessageSize bounds every message, both ways, as the SDK's server bounds them: an item of a stream, or the
	// inputs of an operation. Evidence of several megabytes fits, where gRPC's default takes 4 MiB.
	maxMessageSize = 16 << 20
)

// connectBackoff is how long a connection waits before it connects again after a failure, as a broken stream does:
// a second, then twice as long as the last time, and a minute at most. The streams' own waits then hold, where
// gRPC's default would wait up to two minutes.
var connectBackoff = grpc.ConnectParams{
	Backoff:           backoff.Config{BaseDelay: firstRetry, Multiplier: 2, Jitter: 0.2, MaxDelay: maxRetry},
	MinConnectTimeout: 20 * time.Second,
}

// Pool holds the connections to the collectors, one to each, which every call to that collector shares. A
// connection opens at the first call, and Forget closes it. The pool is safe for concurrent use.
//
// The pool reaches a collector at its Service, vexplain-collector-<name>.<namespace>.svc, on port 9443, over mutual
// TLS: it checks the collector's certificate for that name, from certs.ServerName, and presents the operator's
// client certificate. Calls are compressed with gzip, and messages take up to 16 MiB.
//
// The message of an error that a call returns can hold text that the collector chose, as the message of the status
// that it answered with: a caller that shows or records it treats it as such.
type Pool struct {
	// Dialer opens the connection to a collector's address, host:port. NewPool sets a TCP dialer. Its keepalive
	// notices a collector that went away without closing its connections, such as one whose node failed, which a
	// Watch would never notice, since a client sends nothing on its stream. Tests replace it, before the first
	// call, to reach the collectors that they serve.
	Dialer func(ctx context.Context, address string) (net.Conn, error)

	clientTLS func() (*tls.Config, error)
	namespace string
	// answerEvents and answerBytes are how many events, and how many bytes of messages, an answer to Invoke may
	// hold: maxAnswerEvents and maxAnswerBytes.
	answerEvents, answerBytes int

	mu    sync.Mutex
	conns map[string]*grpc.ClientConn
}

// NewPool returns a pool of the collectors in namespace, the operator's. clientTLS gives the operator's side of the
// TLS: its client certificate, and the authority as its roots, as certs.Authority.ClientTLS does. The pool asks for
// it at each new connection, so a renewed certificate or a new authority takes effect at the next connection, and
// until clientTLS gives one, no connection gets through.
func NewPool(clientTLS func() (*tls.Config, error), namespace string) *Pool {
	var dialer net.Dialer
	return &Pool{
		Dialer: func(ctx context.Context, address string) (net.Conn, error) {
			return dialer.DialContext(ctx, "tcp", address)
		},
		clientTLS:    clientTLS,
		namespace:    namespace,
		answerEvents: maxAnswerEvents,
		answerBytes:  maxAnswerBytes,
		conns:        map[string]*grpc.ClientConn{},
	}
}

// Namespace returns the namespace of the collectors that the pool reaches: the operator's.
func (p *Pool) Namespace() string {
	return p.namespace
}

// conn returns the connection to the collector, which it opens at the first call. A connection connects at its
// first call, and connects again whenever it was lost.
func (p *Pool) conn(collector string) (*grpc.ClientConn, error) {
	// The name becomes part of a host name. A Collector's name is a DNS label, as its CRD requires, so that it adds
	// no label, port or path to the address.
	if problems := validation.IsDNS1123Label(collector); len(problems) > 0 {
		return nil, fmt.Errorf("%q can't be a Collector's name: %s", collector, strings.Join(problems, "; "))
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if conn, ok := p.conns[collector]; ok {
		return conn, nil
	}
	// The address names the Service, and gRPC's TLS checks the collector's certificate against the host of the
	// address: its server name.
	address := net.JoinHostPort(certs.ServerName(collector, p.namespace), port)
	conn, err := grpc.NewClient("passthrough:///"+address,
		grpc.WithTransportCredentials(handshakeTLS{clientTLS: p.clientTLS}),
		grpc.WithContextDialer(p.Dialer),
		grpc.WithConnectParams(connectBackoff),
		grpc.WithDefaultCallOptions(
			grpc.UseCompressor(gzip.Name),
			grpc.MaxCallRecvMsgSize(maxMessageSize),
			grpc.MaxCallSendMsgSize(maxMessageSize),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("prepare the connection to collector %s: %w", collector, err)
	}
	p.conns[collector] = conn
	return conn, nil
}

// Forget closes the connection to the collector, if the pool holds one, and the calls on it end. A later call
// opens a new one. The streams forget a collector whose Collector is gone, and so does the deployer.
func (p *Pool) Forget(collector string) {
	p.mu.Lock()
	conn, ok := p.conns[collector]
	delete(p.conns, collector)
	p.mu.Unlock()
	if ok {
		// Close fails only for a connection that is closed already.
		_ = conn.Close()
	}
}

// Info calls the collector's GetInfo: its name, its version, and the versions of the collector API that it speaks.
func (p *Pool) Info(ctx context.Context, collector string) (*collectorv1alpha1.GetInfoResponse, error) {
	conn, err := p.conn(collector)
	if err != nil {
		return nil, err
	}
	resp, err := collectorv1alpha1.NewIdentityClient(conn).GetInfo(ctx, &collectorv1alpha1.GetInfoRequest{})
	if err != nil {
		return nil, callError("GetInfo", collector, err)
	}
	return resp, nil
}

// Capabilities calls the collector's GetCapabilities: its roles, the evidence that it produces and consumes, whether
// it watches, its operations, the schema of its settings, and the permissions that it needs.
func (p *Pool) Capabilities(ctx context.Context, collector string) (*collectorv1alpha1.GetCapabilitiesResponse, error) {
	conn, err := p.conn(collector)
	if err != nil {
		return nil, err
	}
	resp, err := collectorv1alpha1.NewIdentityClient(conn).GetCapabilities(ctx,
		&collectorv1alpha1.GetCapabilitiesRequest{})
	if err != nil {
		return nil, callError("GetCapabilities", collector, err)
	}
	return resp, nil
}

// ValidateSettings asks the collector what is wrong with its settings, as JSON: none means that they are valid. The
// problems are the collector's text.
func (p *Pool) ValidateSettings(ctx context.Context, collector string, settings []byte) ([]string, error) {
	conn, err := p.conn(collector)
	if err != nil {
		return nil, err
	}
	resp, err := collectorv1alpha1.NewIdentityClient(conn).ValidateSettings(ctx,
		&collectorv1alpha1.ValidateSettingsRequest{Settings: settings})
	if err != nil {
		return nil, callError("ValidateSettings", collector, err)
	}
	return resp.GetProblems(), nil
}

// Health runs the standard gRPC health check of the collector, for its server as a whole. It returns nil when the
// collector answers SERVING, and an error otherwise: when it answers another status, and when the check gets no
// answer, as from a collector that can't be reached, whose code is that of the call.
//
// The deployer's check is the only source of a collector's health. A broken stream, or a failure of an operation
// for one subject, says nothing about it.
func (p *Pool) Health(ctx context.Context, collector string) error {
	conn, err := p.conn(collector)
	if err != nil {
		return err
	}
	resp, err := healthpb.NewHealthClient(conn).Check(ctx, &healthpb.HealthCheckRequest{})
	if err != nil {
		return callError("the health check", collector, err)
	}
	if served := resp.GetStatus(); served != healthpb.HealthCheckResponse_SERVING {
		return fmt.Errorf("collector %s answers the health check with %s", collector, served)
	}
	return nil
}

// callError says which call of which collector failed, and keeps err, so that status.Code reads the code of the
// call from it.
func callError(call, collector string, err error) error {
	return fmt.Errorf("%s of collector %s: %w", call, collector, err)
}

// Usable says whether streams and requests may use the collector: the deployer recorded its capabilities, its
// Collector isn't being deleted, and its Ready condition isn't False.
//
// Ready is False for the reasons that keep a collector from being used: PackageInvalid, IncompatibleAPI,
// SettingsInvalid, MissingPermissions, RuntimeConfigInvalid, WrongRole (from phase 6) and CollectorFailing. The
// reasons are an open set, so a reason that this version doesn't know keeps the collector from being used too:
// what it would have delivered is missing, and missing evidence settles nothing. Unknown is usable: NoData until the
// first health check, and Progressing while the Deployment rolls out. So is a Collector without Ready yet.
//
// A collector that isn't usable gets no new requests and no stream, and what it delivered before stays: its health
// gates new evidence, not what it already delivered (design 5.9).
func Usable(c *configv1alpha1.Collector) bool {
	if c.Status.Capabilities == nil || !c.DeletionTimestamp.IsZero() {
		return false
	}
	return !meta.IsStatusConditionFalse(c.Status.Conditions, configv1alpha1.ConditionReady)
}

// handshakeTLS are the transport credentials of the connections to the collectors. credentials.NewTLS copies its
// configuration once, so these ask clientTLS for a new one at each handshake. A renewed client certificate, or the
// new authority of a restarted operator, then takes effect at the next connection, without a restart.
//
// After a start of the operator, a collector refuses it until the kubelet has synced the collector's TLS Secret,
// which the new authority issued again, and the collector has loaded it, within about a minute. Until then a
// handshake fails, and the connection and the streams try again later, as with any connection that fails.
type handshakeTLS struct {
	clientTLS func() (*tls.Config, error)
}

func (h handshakeTLS) ClientHandshake(ctx context.Context, authority string, conn net.Conn) (
	net.Conn, credentials.AuthInfo, error) {
	config, err := h.clientTLS()
	if err != nil {
		return nil, nil, fmt.Errorf("the client's TLS: %w", err)
	}
	// gRPC's TLS checks the server's certificate against the host of authority, the address of the collector's
	// Service, and offers HTTP/2, as gRPC needs.
	return credentials.NewTLS(config).ClientHandshake(ctx, authority, conn)
}

func (handshakeTLS) ServerHandshake(net.Conn) (net.Conn, credentials.AuthInfo, error) {
	return nil, nil, errors.New("the collector client's credentials serve no connection")
}

func (handshakeTLS) Info() credentials.ProtocolInfo {
	return credentials.ProtocolInfo{SecurityProtocol: "tls"}
}

func (h handshakeTLS) Clone() credentials.TransportCredentials {
	return h
}

// OverrideServerName is unused by gRPC. The server name comes from the address, which names the collector.
func (handshakeTLS) OverrideServerName(string) error {
	return errors.New("the server name of a collector comes from its address")
}
