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

// Package collector serves the collector API, so that the author of a collector writes only what the
// collector does. Every collector, vexplain's own and any other, is served by this package.
//
// A collector describes itself with Info and Capabilities. It implements Watcher when it streams
// evidence, Invoker when it has operations, and SettingsValidator when it checks its settings beyond
// their schema. Serve then runs two servers:
//   - the services Identity and Evidence of the collector API, vexplain.collector.v1alpha1, and the
//     standard gRPC health service, over mutual TLS, on port 9443
//   - /healthz, /readyz and /metrics, in plain HTTP, on port 8081
//
// The server holds every collector to the API's contract, so that vexplain never gets what breaks it.
// Settings pass their schema and the collector's own checks before a Watch or an Invoke runs. A Watch
// stream keeps its order, and every event is valid evidence of a type that the collector declares.
// An Invoke gets parameters that pass its operation's schema, and valid inputs of the types that the
// operation consumes. A call that breaks the contract ends with an error. The design of collectors,
// evidence and rules gives the reasons, in docs/design/2026-10-31-collectors-evidence-rules.md,
// section 5.3.
package collector

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"

	// gzip registers itself as a compressor, so that a client can compress its calls, and the server
	// then compresses its answers, as vexplain's client asks for.
	_ "google.golang.org/grpc/encoding/gzip"

	collectorv1alpha1 "github.com/bedag/vexplain/sdk/api/collector/v1alpha1"
)

// The defaults of the options, which are the contract with vexplain's deployer: the ports of the
// collector's Service, and where the collector's TLS Secret is mounted.
const (
	defaultGRPCAddress   = ":9443"
	defaultHealthAddress = ":8081"
	defaultTLSDir        = "/run/vexplain/tls"
)

// The variables that OptionsFromEnv reads, which vexplain's deployer sets.
const (
	envGRPCAddress   = "VEXPLAIN_LISTEN"
	envHealthAddress = "VEXPLAIN_HEALTH_LISTEN"
	envTLSDir        = "VEXPLAIN_TLS_DIR"
)

// MaxMessageSize is the most bytes that a message of the collector API holds, both ways: an item of a
// stream, such as an event with its data, or a request with the inputs of an operation. Evidence of
// several megabytes fits, where gRPC's default allows 4 MiB. A receiver counts a message once it is
// decompressed, so an event whose message is larger is lost, however well it compresses: a collector
// that makes large evidence checks the size of its messages before it returns them.
const MaxMessageSize = 16 << 20

const (
	// reloadInterval is how often the server checks its TLS files. It loads them again within 30
	// seconds of a change, so that a renewed certificate is served well before the old one expires.
	reloadInterval = 10 * time.Second
	// shutdownGrace is how long a stopping server waits for the calls that run, whose contexts it
	// ended, before it closes their connections, and for the health server.
	shutdownGrace = 10 * time.Second
	// readHeaderTimeout bounds how long the health server waits for a request's headers.
	readHeaderTimeout = 10 * time.Second
)

// Options say where Serve listens, and where it finds its TLS files. Their zero values are the
// defaults, which are what vexplain's deployer sets.
type Options struct {
	// GRPCAddress is where the collector API is served: ":9443" by default.
	GRPCAddress string
	// HealthAddress is where /healthz, /readyz and /metrics are served: ":8081" by default.
	HealthAddress string
	// TLSDir holds tls.crt and tls.key, the server's certificate and key, and ca.crt, the certificate
	// of vexplain's authority, which must have signed a client's certificate: "/run/vexplain/tls" by
	// default.
	TLSDir string
	// Insecure serves the collector API without TLS, for tests only.
	Insecure bool
	// Registry takes the metrics of the server, and /metrics serves it. It is a registry of the
	// server's own when nil. A collector that has metrics of its own passes the registry that holds
	// them, which must be a prometheus.Gatherer too, as a *prometheus.Registry is.
	Registry prometheus.Registerer
	// GRPCListener, when set, is where the collector API is served instead of GRPCAddress, such as a
	// listener from bufconn, or on 127.0.0.1:0, that a test picked. Serve owns it from then on, and
	// closes it when it returns, however it returns.
	GRPCListener net.Listener
	// HealthListener, when set, is where the health server serves instead of HealthAddress. Serve owns
	// it as it owns GRPCListener.
	HealthListener net.Listener
}

// withDefaults fills in the options that are empty.
func (o Options) withDefaults() Options {
	if o.GRPCAddress == "" {
		o.GRPCAddress = defaultGRPCAddress
	}
	if o.HealthAddress == "" {
		o.HealthAddress = defaultHealthAddress
	}
	if o.TLSDir == "" {
		o.TLSDir = defaultTLSDir
	}
	return o
}

// OptionsFromEnv reads VEXPLAIN_LISTEN, VEXPLAIN_HEALTH_LISTEN and VEXPLAIN_TLS_DIR, which vexplain's
// deployer sets, into the addresses and the TLS directory. A variable that is empty or not set gives
// the default.
func OptionsFromEnv() Options {
	return Options{
		GRPCAddress:   os.Getenv(envGRPCAddress),
		HealthAddress: os.Getenv(envHealthAddress),
		TLSDir:        os.Getenv(envTLSDir),
	}.withDefaults()
}

// Serve serves the collector c until ctx ends, and returns nil then. It returns an error at once when
// the capabilities of c contradict themselves (see Capabilities), when c doesn't implement what they
// say, when its settings schema or the parameter schema of an operation doesn't compile, when the
// registry of the options can't be served, or when it can't listen, and later when one of its
// servers fails. It serves on the listeners of the options, and else listens
// on their addresses. Either way, every listener is closed when Serve returns.
//
// The health server starts first. Then Serve waits for the TLS files, unless Insecure, and serves the
// collector API once they load. /readyz answers 503 until then. Serve checks the files every 10
// seconds, and loads them again when they change. Files that don't load leave the server with the
// ones that loaded last.
//
// When ctx ends, Serve stops: /readyz answers 503, and the health service NOT_SERVING. The context of
// each call that runs ends, and the call ends with the code Unavailable, whatever the collector
// returns, so that a call that the stop cut short never looks complete. After a grace period, Serve
// closes the connections of the calls that are left.
func Serve(ctx context.Context, c Collector, opts Options) error {
	return serve(ctx, c, opts, reloadInterval)
}

// serve is Serve, which checks the TLS files every reload.
func serve(ctx context.Context, c Collector, opts Options, reload time.Duration) error {
	grpcListener, healthListener := opts.GRPCListener, opts.HealthListener
	defer func() {
		for _, listener := range []net.Listener{grpcListener, healthListener} {
			if listener != nil {
				_ = listener.Close()
			}
		}
	}()
	s, err := newServer(c, opts, reload)
	if err != nil {
		return err
	}
	var config net.ListenConfig
	if grpcListener == nil {
		if grpcListener, err = config.Listen(ctx, "tcp", s.opts.GRPCAddress); err != nil {
			return fmt.Errorf("listening for the collector API: %w", err)
		}
	}
	if healthListener == nil {
		if healthListener, err = config.Listen(ctx, "tcp", s.opts.HealthAddress); err != nil {
			return fmt.Errorf("listening for the health server: %w", err)
		}
	}
	return s.run(ctx, grpcListener, healthListener)
}

// server is what Serve runs for a collector.
type server struct {
	opts     Options
	reload   time.Duration
	identity *identityServer
	evidence *evidenceServer
	requests *prometheus.CounterVec
	gatherer prometheus.Gatherer
	// ready is whether the collector API is served, which /readyz answers.
	ready atomic.Bool
}

// newServer prepares the servers of c from what it declares, which it reads once. It checks that c
// implements what its capabilities say, and compiles its schemas. The TLS files are checked every
// reload.
func newServer(c Collector, opts Options, reload time.Duration) (*server, error) {
	caps := c.Capabilities()
	if err := checkCapabilities(caps); err != nil {
		return nil, err
	}
	validator, _ := c.(SettingsValidator)
	settings, err := newSettingsCheck(caps.SettingsSchema, validator)
	if err != nil {
		return nil, err
	}
	watcher, isWatcher := c.(Watcher)
	if caps.Watches && !isWatcher {
		return nil, errors.New("the capabilities say that the collector watches, and it has no Watch method")
	}
	if !caps.Watches {
		watcher = nil
	}
	invoker, isInvoker := c.(Invoker)
	if len(caps.Operations) > 0 && !isInvoker {
		return nil, errors.New("the capabilities declare operations, and the collector has no Invoke method")
	}
	operations := make(map[string]operation, len(caps.Operations))
	for _, op := range caps.Operations {
		compiled, err := newOperation(op)
		if err != nil {
			return nil, err
		}
		operations[op.Name] = compiled
	}
	// The registry comes last, so that a collector that is refused leaves nothing in it.
	requests, gatherer, err := newRequests(opts.Registry)
	if err != nil {
		return nil, err
	}

	produces := make([]string, 0, len(caps.Produces))
	for _, produced := range caps.Produces {
		produces = append(produces, produced.Type)
	}
	return &server{
		opts:   opts.withDefaults(),
		reload: reload,
		identity: &identityServer{
			info:         infoResponse(c.Info()),
			capabilities: capabilitiesResponse(caps),
			settings:     settings,
		},
		evidence: &evidenceServer{
			watcher:    watcher,
			invoker:    invoker,
			roles:      caps.Roles,
			produces:   setOf(produces),
			operations: operations,
			settings:   settings,
		},
		requests: requests,
		gatherer: gatherer,
	}, nil
}

// serveError is a server's failure, which ends Serve with the error.
type serveError struct{ error }

// run serves on the listeners until ctx ends, or until one of the servers fails.
func (s *server) run(ctx context.Context, grpcListener, healthListener net.Listener) error {
	ctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	var wg sync.WaitGroup

	probes := &http.Server{Handler: healthHandler(&s.ready, s.gatherer), ReadHeaderTimeout: readHeaderTimeout}
	wg.Go(func() {
		if err := probes.Serve(healthListener); !errors.Is(err, http.ErrServerClosed) {
			cancel(serveError{fmt.Errorf("the health server: %w", err)})
		}
	})

	if creds, err := s.transportCredentials(ctx, &wg); err == nil {
		grpcServer, checks := s.startGRPC(ctx, cancel, creds, grpcListener, &wg)
		s.ready.Store(true)
		slog.Info("Serving the collector API", "collector", s.identity.info.GetName(),
			"version", s.identity.info.GetVersion(), "address", grpcListener.Addr().String(),
			"healthAddress", healthListener.Addr().String(), "tls", !s.opts.Insecure)
		<-ctx.Done()
		s.ready.Store(false)
		checks.Shutdown()
		stopGRPC(grpcServer)
	}
	stopHTTP(probes)
	wg.Wait()

	var failed serveError
	if errors.As(context.Cause(ctx), &failed) {
		return failed.error
	}
	return nil
}

// transportCredentials returns the credentials of the gRPC server: none when insecure, and else TLS
// from the files in TLSDir, once they load. It waits for them until ctx ends, and then keeps them up
// to date until ctx ends.
func (s *server) transportCredentials(ctx context.Context, wg *sync.WaitGroup) (
	credentials.TransportCredentials, error) {
	if s.opts.Insecure {
		return insecure.NewCredentials(), nil
	}
	files := &certificates{dir: s.opts.TLSDir}
	if err := files.wait(ctx, s.reload); err != nil {
		return nil, err
	}
	wg.Go(func() { files.watch(ctx, s.reload) })
	return files.transport(), nil
}

// startGRPC serves the collector API and the health service on listener, and returns the server and
// the health service. The context of each call of the collector API ends with ctx. A failure of the
// server cancels ctx.
func (s *server) startGRPC(ctx context.Context, cancel context.CancelCauseFunc, creds credentials.TransportCredentials,
	listener net.Listener, wg *sync.WaitGroup) (*grpc.Server, *health.Server) {
	grpcServer := grpc.NewServer(
		grpc.Creds(creds),
		grpc.MaxRecvMsgSize(MaxMessageSize),
		grpc.MaxSendMsgSize(MaxMessageSize),
		grpc.ChainUnaryInterceptor(countUnary(s.requests)),
		grpc.ChainStreamInterceptor(countStream(s.requests)),
	)
	checks := newHealthService()
	healthpb.RegisterHealthServer(grpcServer, checks)
	collectorv1alpha1.RegisterIdentityServer(grpcServer, s.identity)
	s.evidence.stopping = ctx
	collectorv1alpha1.RegisterEvidenceServer(grpcServer, s.evidence)
	wg.Go(func() {
		if err := grpcServer.Serve(listener); err != nil {
			cancel(serveError{fmt.Errorf("the gRPC server: %w", err)})
		}
	})
	return grpcServer, checks
}

// stopGRPC lets the calls that run end, and closes their connections after shutdownGrace.
func stopGRPC(grpcServer *grpc.Server) {
	stopped := make(chan struct{})
	go func() {
		grpcServer.GracefulStop()
		close(stopped)
	}()
	grace := time.NewTimer(shutdownGrace)
	defer grace.Stop()
	select {
	case <-stopped:
	case <-grace.C:
		grpcServer.Stop()
		<-stopped
	}
}

// stopHTTP lets the requests that run end, and closes their connections after shutdownGrace.
func stopHTTP(probes *http.Server) {
	ctx, cancel := context.WithTimeout(context.Background(), shutdownGrace)
	defer cancel()
	if err := probes.Shutdown(ctx); err != nil {
		_ = probes.Close()
	}
}
