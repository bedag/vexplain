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

package collector_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cloudevents/sdk-go/binding/format/protobuf/v2/pb"
	cloudevents "github.com/cloudevents/sdk-go/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	collectorv1alpha1 "github.com/bedag/vexplain/sdk/api/collector/v1alpha1"
	"github.com/bedag/vexplain/sdk/collector"
	"github.com/bedag/vexplain/sdk/evidence"
	"github.com/bedag/vexplain/sdk/subject"
)

const (
	collectorName    = "hello"
	collectorVersion = "1.2.3"
	// typeHello is the type that the fake collector produces, and typeInput the one that its
	// operation consumes. typeUndeclared is neither.
	typeHello       = "com.example.hello.v1alpha1"
	typeInput       = "com.example.input.v1alpha1"
	typeUndeclared  = "com.example.undeclared.v1alpha1"
	operationGreet  = "greet"
	greetsAWorkload = "Greets a workload."
	clusterA        = "cluster-a"
	digest          = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	eventSource     = "/clusters/cluster-a/collectors/hello"

	// settingsSchema is the schema of the fake collector's settings. It takes an empty object.
	settingsSchema = `{
		"type": "object",
		"properties": {
			"greeting": {"type": "string", "minLength": 1},
			"repeat": {"type": "integer", "minimum": 1}
		},
		"additionalProperties": false
	}`
	validSettings = `{"greeting": "hello", "repeat": 2}`
	// brokenSettings break settingsSchema.
	brokenSettings = `{"repeat": 0}`
	// refusedSettings pass settingsSchema, and the fake collector's validator refuses them.
	refusedSettings = `{"greeting": "goodbye"}`
	refusal         = "greeting: the collector only says hello"
	helloSchema     = `{"type": "object", "properties": {"greeting": {"type": "string"}}, "required": ["greeting"]}`
	parameterSchema = `{"type": "object", "properties": {"name": {"type": "string"}}}`
	parameters      = `{"name": "web"}`

	// reload is how often the tests' servers check their TLS files.
	reload = 20 * time.Millisecond
	// wait bounds how long a test waits for a server.
	wait = 10 * time.Second
	// bufferSize is the size of a bufconn listener's buffer.
	bufferSize = 1 << 20

	// grpcServer and healthServer name the two servers that Serve runs.
	grpcServer   = "gRPC"
	healthServer = "health"
)

var (
	// workload is what the tests' events are about.
	workload = subject.ForWorkload(subject.Workload{
		Cluster: clusterA, Namespace: "team-a", Group: "apps", Kind: "Deployment", Name: "web",
	})
	// readPods is a permission that the fake collector needs.
	readPods = collector.Permission{
		APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get", "list", "watch"},
	}
)

// capabilities are what the fake collector declares: it takes the spoke role, watches, and has one
// operation, which consumes typeInput and produces typeHello.
func capabilities() collector.Capabilities {
	return collector.Capabilities{
		Roles:    []collector.Role{collector.RoleSpoke},
		Produces: []collector.EvidenceType{{Type: typeHello, Scope: collector.ScopeSpoke, Schema: []byte(helloSchema)}},
		Consumes: []string{typeInput},
		Watches:  true,
		Operations: []collector.Operation{{
			Name:            operationGreet,
			Description:     greetsAWorkload,
			Role:            collector.RoleSpoke,
			Produces:        []string{typeHello},
			Consumes:        []string{typeInput},
			ParameterSchema: []byte(parameterSchema),
		}},
		SettingsSchema: []byte(settingsSchema),
		Permissions:    []collector.Permission{readPods},
	}
}

// fakeCollector describes itself with caps, and watches, invokes and validates its settings with
// the functions that a test sets. Without them, it watches until its context ends, an invocation
// returns nothing, and it refuses only settings that say goodbye, as refusedSettings do.
type fakeCollector struct {
	caps     collector.Capabilities
	watch    func(ctx context.Context, req collector.WatchRequest, sink collector.Sink) error
	invoke   func(ctx context.Context, req collector.InvokeRequest) ([]cloudevents.Event, *collector.Failure, error)
	validate func(settings json.RawMessage) []string
}

func (f *fakeCollector) Info() collector.Info {
	return collector.Info{Name: collectorName, Version: collectorVersion}
}

func (f *fakeCollector) Capabilities() collector.Capabilities { return f.caps }

func (f *fakeCollector) Watch(ctx context.Context, req collector.WatchRequest, sink collector.Sink) error {
	if f.watch == nil {
		<-ctx.Done()
		return ctx.Err()
	}
	return f.watch(ctx, req, sink)
}

func (f *fakeCollector) Invoke(ctx context.Context, req collector.InvokeRequest) (
	[]cloudevents.Event, *collector.Failure, error) {
	if f.invoke == nil {
		return nil, nil, nil
	}
	return f.invoke(ctx, req)
}

func (f *fakeCollector) ValidateSettings(settings json.RawMessage) []string {
	if f.validate != nil {
		return f.validate(settings)
	}
	if strings.Contains(string(settings), "goodbye") {
		return []string{refusal}
	}
	return nil
}

// plainCollector only describes itself. It neither watches nor invokes, and leaves its settings to
// their schema.
type plainCollector struct{ caps collector.Capabilities }

func (p plainCollector) Info() collector.Info {
	return collector.Info{Name: collectorName, Version: collectorVersion}
}

func (p plainCollector) Capabilities() collector.Capabilities { return p.caps }

// running is a server that Serve runs until stop is called, or until the test ends.
type running struct {
	// health is the URL of the health server.
	health string
	cancel context.CancelFunc
	done   chan error
	once   sync.Once
	result error
}

// stop ends the server's context, and returns what Serve returned.
func (r *running) stop() error {
	r.once.Do(func() {
		r.cancel()
		select {
		case r.result = <-r.done:
		case <-time.After(wait):
			r.result = errors.New("Serve didn't return after its context ended")
		}
	})
	return r.result
}

// start runs Serve for c on the listener of opts, and on a health listener of its own, and checks
// the TLS files every reload. When the test ends, it stops the server and checks that Serve returned
// nil.
func start(t *testing.T, c collector.Collector, opts collector.Options) *running {
	t.Helper()
	require.NotNil(t, opts.GRPCListener, "the test picks the gRPC listener")
	healthListener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	opts.HealthListener = healthListener
	ctx, cancel := context.WithCancel(context.Background())
	r := &running{health: "http://" + healthListener.Addr().String(), cancel: cancel, done: make(chan error, 1)}
	go func() { r.done <- collector.ServeWithReload(ctx, c, opts, reload) }()
	t.Cleanup(func() { assert.NoError(t, r.stop(), "Serve returns nil once its context ends") })
	return r
}

// testServer is a server without TLS, over bufconn, and a client of it.
type testServer struct {
	*running
	conn *grpc.ClientConn
}

// serve runs a server without TLS for c until the test ends.
func serve(t *testing.T, c collector.Collector) *testServer {
	t.Helper()
	return serveWith(t, c, collector.Options{Insecure: true})
}

// serveWith runs a server for c with opts, over bufconn, until the test ends.
func serveWith(t *testing.T, c collector.Collector, opts collector.Options) *testServer {
	t.Helper()
	listener := bufconn.Listen(bufferSize)
	opts.GRPCListener = listener
	r := start(t, c, opts)
	return &testServer{running: r, conn: dial(t, listener)}
}

// dial returns a client of the server on listener, without TLS, which the test closes when it ends.
func dial(t *testing.T, listener *bufconn.Listener) *grpc.ClientConn {
	t.Helper()
	conn, err := grpc.NewClient("passthrough:///bufconn",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return listener.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func (s *testServer) identityClient() collectorv1alpha1.IdentityClient {
	return collectorv1alpha1.NewIdentityClient(s.conn)
}

func (s *testServer) evidenceClient() collectorv1alpha1.EvidenceClient {
	return collectorv1alpha1.NewEvidenceClient(s.conn)
}

// callContext bounds a test's call, so that a server that never answers fails the test instead of
// hanging it.
func callContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), wait)
	t.Cleanup(cancel)
	return ctx
}

// protoContext is the context that the tests' requests carry.
func protoContext() *collectorv1alpha1.Context {
	return &collectorv1alpha1.Context{
		Cluster:           clusterA,
		OperatorNamespace: "vexplain-system",
		OwnPodLabel:       "vexplain.bedag.ch/task",
		Scope:             []byte(`{"namespaces": {"exclude": ["kube-system"]}}`),
		OwnerAttribution:  []byte(`{"namespaceLabels": ["team"]}`),
	}
}

// watchRequest is a request for a Watch in the spoke role, with valid settings and a context.
func watchRequest() *collectorv1alpha1.WatchRequest {
	return &collectorv1alpha1.WatchRequest{
		Role:     collectorv1alpha1.Role_ROLE_SPOKE,
		Settings: []byte(validSettings),
		Context:  protoContext(),
	}
}

// invokeRequest is a request for the fake collector's operation in the spoke role, with valid
// settings, a context, parameters and inputs.
func invokeRequest(t *testing.T, inputs ...cloudevents.Event) *collectorv1alpha1.InvokeRequest {
	t.Helper()
	req := &collectorv1alpha1.InvokeRequest{
		Operation:  operationGreet,
		Subject:    workload,
		Parameters: []byte(parameters),
		Settings:   []byte(validSettings),
		Context:    protoContext(),
		Role:       collectorv1alpha1.Role_ROLE_SPOKE,
	}
	for _, input := range inputs {
		p, err := evidence.ToProto(input)
		require.NoError(t, err)
		req.Inputs = append(req.Inputs, p)
	}
	return req
}

// receiveAll reads a stream to its end. It returns the items, and the error that the stream ended
// with, which is nil for a stream that ended well.
func receiveAll[T any](stream grpc.ServerStreamingClient[T]) ([]*T, error) {
	var items []*T
	for {
		item, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			return items, nil
		}
		if err != nil {
			return items, err
		}
		items = append(items, item)
	}
}

// newEvent returns valid evidence of eventType about the workload.
func newEvent(t *testing.T, eventType string) cloudevents.Event {
	t.Helper()
	return eventAbout(t, eventType, workload)
}

// eventAbout returns evidence of eventType about what. It is valid unless what makes it not.
func eventAbout(t *testing.T, eventType, what string) cloudevents.Event {
	t.Helper()
	e, err := evidence.New(eventType, what, map[string]string{"greeting": "hello"}, evidence.WithSource(eventSource))
	require.NoError(t, err)
	return e
}

// requireEvent checks that p is the event want, after its trip through the wire.
func requireEvent(t *testing.T, want cloudevents.Event, p *pb.CloudEvent) {
	t.Helper()
	require.NotNil(t, p, "an event")
	got, err := evidence.FromProto(p)
	require.NoError(t, err)
	require.Equal(t, want, got)
}

// httpClient is the client of the tests' health servers. Its timeout fails a test where a server
// that doesn't answer would hang it.
var httpClient = &http.Client{Timeout: wait}

// httpStatus returns the status of a GET of url, or 0 when the request fails.
func httpStatus(url string) int {
	resp, err := httpClient.Get(url)
	if err != nil {
		return 0
	}
	_ = resp.Body.Close()
	return resp.StatusCode
}

func TestOptionsFromEnv(t *testing.T) {
	t.Run("reads the variables that the deployer sets", func(t *testing.T) {
		t.Setenv("VEXPLAIN_LISTEN", ":10443")
		t.Setenv("VEXPLAIN_HEALTH_LISTEN", "127.0.0.1:10081")
		t.Setenv("VEXPLAIN_TLS_DIR", "/etc/collector/tls")

		require.Equal(t, collector.Options{
			GRPCAddress:   ":10443",
			HealthAddress: "127.0.0.1:10081",
			TLSDir:        "/etc/collector/tls",
		}, collector.OptionsFromEnv())
	})
	t.Run("has the contract's defaults", func(t *testing.T) {
		t.Setenv("VEXPLAIN_LISTEN", "")
		t.Setenv("VEXPLAIN_HEALTH_LISTEN", "")
		t.Setenv("VEXPLAIN_TLS_DIR", "")

		require.Equal(t, collector.Options{
			GRPCAddress:   ":9443",
			HealthAddress: ":8081",
			TLSDir:        "/run/vexplain/tls",
		}, collector.OptionsFromEnv())
	})
}

// freeAddress returns a loopback address that nothing listens on, for Serve to listen on.
func freeAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	address := listener.Addr().String()
	require.NoError(t, listener.Close())
	return address
}

// serveInBackground runs Serve for c with opts until the returned function is called, or until the
// test ends. Either way, it stops the server and checks that Serve returned nil.
func serveInBackground(t *testing.T, c collector.Collector, opts collector.Options) func() {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	r := &running{cancel: cancel, done: make(chan error, 1)}
	go func() { r.done <- collector.Serve(ctx, c, opts) }()
	t.Cleanup(func() { assert.NoError(t, r.stop(), "Serve returns nil once its context ends") })
	return func() {
		t.Helper()
		require.NoError(t, r.stop(), "Serve returns nil once its context ends")
	}
}

// infoAt calls GetInfo on the server at address, without TLS, once it serves.
func infoAt(t *testing.T, address string) (*collectorv1alpha1.GetInfoResponse, error) {
	t.Helper()
	conn, err := grpc.NewClient("passthrough:///"+address, grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()
	return collectorv1alpha1.NewIdentityClient(conn).GetInfo(callContext(t), &collectorv1alpha1.GetInfoRequest{},
		grpc.WaitForReady(true))
}

func TestServe(t *testing.T) {
	grpcAddress, healthAddress := freeAddress(t), freeAddress(t)
	stop := serveInBackground(t, plainCollector{}, collector.Options{
		GRPCAddress: grpcAddress, HealthAddress: healthAddress, Insecure: true,
	})

	info, err := infoAt(t, grpcAddress)
	require.NoError(t, err)
	require.Equal(t, collectorName, info.GetName())
	require.Equal(t, http.StatusOK, httpStatus("http://"+healthAddress+"/healthz"))

	stop()
	_, err = net.Dial("tcp", grpcAddress)
	require.Error(t, err, "the gRPC listener is closed")
	_, err = net.Dial("tcp", healthAddress)
	require.Error(t, err, "the health listener is closed")
}

func TestServeOnTheListenersOfTheOptions(t *testing.T) {
	for _, given := range []string{grpcServer, healthServer} {
		t.Run("the "+given+" listener", func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			require.NoError(t, err)
			grpcAddress, healthAddress := freeAddress(t), freeAddress(t)
			opts := collector.Options{GRPCAddress: grpcAddress, HealthAddress: healthAddress, Insecure: true}
			// The address of the given listener is taken, so Serve would fail if it listened there.
			if given == grpcServer {
				opts.GRPCListener, opts.GRPCAddress = listener, takenAddress(t)
				grpcAddress = listener.Addr().String()
			} else {
				opts.HealthListener, opts.HealthAddress = listener, takenAddress(t)
				healthAddress = listener.Addr().String()
			}
			stop := serveInBackground(t, plainCollector{}, opts)

			info, err := infoAt(t, grpcAddress)
			require.NoError(t, err)
			require.Equal(t, collectorName, info.GetName())
			require.Equal(t, http.StatusOK, httpStatus("http://"+healthAddress+"/healthz"))

			stop()
			_, err = net.Dial("tcp", listener.Addr().String())
			require.Error(t, err, "Serve owns the listener that it was given, and closed it")
		})
	}
}

func TestServeClosesTheListenersOfTheOptionsWhenItRefuses(t *testing.T) {
	tests := map[string]struct {
		c             collector.Collector
		healthAddress func(t *testing.T) string
	}{
		"a collector that contradicts its capabilities": {
			c:             plainCollector{caps: collector.Capabilities{Watches: true}},
			healthAddress: freeAddress,
		},
		"an address that is taken": {c: plainCollector{}, healthAddress: takenAddress},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			require.NoError(t, err)

			requireRefused(t, tc.c, collector.Options{
				GRPCListener: listener, HealthAddress: tc.healthAddress(t), Insecure: true,
			})
			_, err = net.Dial("tcp", listener.Addr().String())
			require.Error(t, err, "Serve owns the listener that it was given, and closed it")
		})
	}
}

func TestServeRefuses(t *testing.T) {
	tests := map[string]struct {
		c    collector.Collector
		opts collector.Options
	}{
		"a collector that says it watches, and has no Watch": {
			c: plainCollector{caps: collector.Capabilities{Watches: true}},
		},
		"a collector that declares an operation, and has no Invoke": {
			c: plainCollector{caps: collector.Capabilities{
				Roles:      []collector.Role{collector.RoleSpoke},
				Operations: []collector.Operation{{Name: operationGreet, Role: collector.RoleSpoke}},
			}},
		},
		"an address that is taken": {
			c: plainCollector{},
			opts: collector.Options{
				GRPCAddress: takenAddress(t), HealthAddress: freeAddress(t), Insecure: true,
			},
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			opts := tc.opts
			if opts.GRPCAddress == "" {
				opts = collector.Options{GRPCAddress: freeAddress(t), HealthAddress: freeAddress(t), Insecure: true}
			}
			requireRefused(t, tc.c, opts)
		})
	}
}

// takenAddress returns an address that the test listens on until it ends.
func takenAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })
	return listener.Addr().String()
}

// requireRefused checks that Serve refuses c with opts: it returns an error, and at once.
func requireRefused(t *testing.T, c collector.Collector, opts collector.Options) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	err := collector.Serve(ctx, c, opts)
	require.Error(t, err)
	require.NoError(t, ctx.Err(), "Serve refuses at once, and doesn't serve until its context ends")
}

func TestServeEndsWhenAServerFails(t *testing.T) {
	for _, failing := range []string{grpcServer, healthServer} {
		t.Run("the "+failing+" server", func(t *testing.T) {
			grpcListener, err := net.Listen("tcp", "127.0.0.1:0")
			require.NoError(t, err)
			healthListener, err := net.Listen("tcp", "127.0.0.1:0")
			require.NoError(t, err)
			health := "http://" + healthListener.Addr().String()
			done := make(chan error, 1)
			go func() {
				done <- collector.Serve(context.Background(), plainCollector{}, collector.Options{
					Insecure: true, GRPCListener: grpcListener, HealthListener: healthListener,
				})
			}()
			require.Eventually(t, func() bool { return httpStatus(health+"/readyz") == http.StatusOK }, wait, reload)

			// Its listener fails under it.
			if failing == grpcServer {
				require.NoError(t, grpcListener.Close())
			} else {
				require.NoError(t, healthListener.Close())
			}
			select {
			case err := <-done:
				require.Error(t, err, "Serve returns the failure of a server")
			case <-time.After(wait):
				t.Fatal("Serve didn't return when a server failed")
			}
			_, err = net.Dial("tcp", grpcListener.Addr().String())
			require.Error(t, err, "the gRPC server has stopped")
			require.Zero(t, httpStatus(health+"/healthz"), "the health server has stopped")
		})
	}
}

func TestServeStopsWhileItWaitsForItsTLSFiles(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	r := start(t, plainCollector{}, collector.Options{TLSDir: t.TempDir(), GRPCListener: listener})
	require.Equal(t, http.StatusServiceUnavailable, httpStatus(r.health+"/readyz"))

	require.NoError(t, r.stop(), "Serve returns nil once its context ends")
	_, err = net.Dial("tcp", listener.Addr().String())
	require.Error(t, err, "the gRPC listener is closed, though it never served")
}

func TestServeEndsTheCallsThatRunWhenItStops(t *testing.T) {
	event := newEvent(t, typeHello)
	// A collector's call returns once the stop has ended its context. Whether it returns its context's
	// error or nil, the call ends with Unavailable: what it returns may be cut short, and must not
	// look complete.
	results := map[string]func(ctx context.Context) error{
		"returning its context's error": func(ctx context.Context) error { return ctx.Err() },
		"returning nil":                 func(context.Context) error { return nil },
	}
	for name, result := range results {
		t.Run("a Watch "+name, func(t *testing.T) {
			s := serve(t, &fakeCollector{caps: capabilities(), watch: func(ctx context.Context, _ collector.WatchRequest,
				sink collector.Sink) error {
				if err := sink.SnapshotStart(); err != nil {
					return err
				}
				<-ctx.Done()
				return result(ctx)
			}})
			stream, err := s.evidenceClient().Watch(callContext(t), watchRequest())
			require.NoError(t, err)
			item, err := stream.Recv()
			require.NoError(t, err)
			require.NotNil(t, item.GetSnapshotStart())

			stopping := time.Now()
			require.NoError(t, s.stop(), "Serve returns nil once its context ends")
			items, err := receiveAll(stream)
			require.Empty(t, items)
			requireStopping(t, err, stopping)
		})
		t.Run("an Invoke "+name+", with an answer", func(t *testing.T) {
			invoked := make(chan struct{})
			s := serve(t, &fakeCollector{caps: capabilities(), invoke: func(ctx context.Context, _ collector.InvokeRequest) (
				[]cloudevents.Event, *collector.Failure, error) {
				close(invoked)
				<-ctx.Done()
				return []cloudevents.Event{event}, nil, result(ctx)
			}})
			stream, err := s.evidenceClient().Invoke(callContext(t), invokeRequest(t, newEvent(t, typeInput)))
			require.NoError(t, err)
			select {
			case <-invoked:
			case <-time.After(wait):
				t.Fatal("the collector's Invoke wasn't called")
			}

			stopping := time.Now()
			require.NoError(t, s.stop(), "Serve returns nil once its context ends")
			items, err := receiveAll(stream)
			require.Empty(t, items, "nothing of an answer that the stop cut short arrives")
			requireStopping(t, err, stopping)
		})
	}
}

// requireStopping checks that a call ended with Unavailable because Serve stopped at stopping.
func requireStopping(t *testing.T, err error, stopping time.Time) {
	t.Helper()
	require.Equal(t, codes.Unavailable, status.Code(err), "a stopping collector is unavailable: %v", err)
	// The call ended because its context did, and not because its connection was closed when the
	// grace period was over.
	require.Equal(t, "the collector is stopping", status.Convert(err).Message())
	require.Less(t, time.Since(stopping), 5*time.Second)
}

// The test names the compressor rather than importing its package. A call with gzip then works only
// if the collector package registers the compressor.
func TestServerTakesGzip(t *testing.T) {
	event := newEvent(t, typeHello)
	c := &fakeCollector{caps: capabilities(), watch: func(ctx context.Context, _ collector.WatchRequest,
		sink collector.Sink) error {
		for _, call := range []func() error{sink.SnapshotStart, func() error { return sink.Event(event) }, sink.SnapshotEnd} {
			if err := call(); err != nil {
				return err
			}
		}
		return nil
	}}
	s := serve(t, c)
	gzip := grpc.UseCompressor("gzip")

	_, err := s.identityClient().GetInfo(callContext(t), &collectorv1alpha1.GetInfoRequest{}, gzip)
	require.NoError(t, err)

	stream, err := s.evidenceClient().Watch(callContext(t), watchRequest(), gzip)
	require.NoError(t, err)
	items, err := receiveAll(stream)
	require.NoError(t, err)
	require.Len(t, items, 3)
	requireEvent(t, event, items[1].GetEvent())
}

func TestMessagesUpTo16MiB(t *testing.T) {
	const mib = 1 << 20
	// sized returns valid evidence of eventType whose data is a little over size bytes.
	sized := func(t *testing.T, eventType string, size int) cloudevents.Event {
		t.Helper()
		e, err := evidence.New(eventType, workload, map[string]string{"blob": strings.Repeat("a", size)},
			evidence.WithSource(eventSource))
		require.NoError(t, err)
		return e
	}
	// echo answers with answer, or with evidence of typeHello as large as the first input.
	echo := func(answer *cloudevents.Event) *fakeCollector {
		return &fakeCollector{caps: capabilities(), invoke: func(_ context.Context, req collector.InvokeRequest) (
			[]cloudevents.Event, *collector.Failure, error) {
			if answer != nil {
				return []cloudevents.Event{*answer}, nil, nil
			}
			e, err := evidence.New(typeHello, workload, json.RawMessage(req.Inputs[0].Data()), evidence.WithSource(eventSource))
			return []cloudevents.Event{e}, nil, err
		}}
	}
	// The client takes up to 32 MiB, so that only the server's limit counts.
	clientLimit := grpc.MaxCallRecvMsgSize(32 * mib)

	t.Run("15 MiB each way", func(t *testing.T) {
		s := serve(t, echo(nil))
		stream, err := s.evidenceClient().Invoke(callContext(t), invokeRequest(t, sized(t, typeInput, 15*mib)), clientLimit)
		require.NoError(t, err)
		items, err := receiveAll(stream)
		require.NoError(t, err)
		require.Len(t, items, 1)
		require.Greater(t, len(items[0].GetEvent().GetBinaryData()), 15*mib)
	})
	t.Run("a request over 16 MiB is refused", func(t *testing.T) {
		s := serve(t, echo(nil))
		stream, err := s.evidenceClient().Invoke(callContext(t), invokeRequest(t, sized(t, typeInput, 17*mib)), clientLimit)
		require.NoError(t, err)
		_, err = receiveAll(stream)
		require.Equal(t, codes.ResourceExhausted, status.Code(err), "%v", err)
	})
	t.Run("an answer over 16 MiB is refused", func(t *testing.T) {
		answer := sized(t, typeHello, 17*mib)
		s := serve(t, echo(&answer))
		stream, err := s.evidenceClient().Invoke(callContext(t), invokeRequest(t, newEvent(t, typeInput)), clientLimit)
		require.NoError(t, err)
		_, err = receiveAll(stream)
		require.Equal(t, codes.ResourceExhausted, status.Code(err), "%v", err)
	})
}
