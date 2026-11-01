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

package collectorclient_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/go-logr/logr/testr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
	"github.com/bedag/vexplain/internal/collector/certs"
	"github.com/bedag/vexplain/internal/collectorclient"
	collectorv1alpha1 "github.com/bedag/vexplain/sdk/api/collector/v1alpha1"
	"github.com/bedag/vexplain/sdk/collector"
)

// These tests run the collector client against collectors that serve in the test's process, over mutual TLS with
// certificates from an authority of the operator's own, as in production. Most collectors are served by the SDK.
// Some send whatever a test tells them, without the SDK's checks, as a collector that isn't built with the SDK can.
// The Collectors and the OperatorConfig live in an API server of envtest, which the streams read as they read the
// manager's cache in production. Nothing else of the operator runs: the tests set the status of each Collector as
// the deployer would record it.

const (
	// namespace is the operator's namespace, where the TLS Secrets of the collectors are.
	namespace = "vexplain-system"

	// wait bounds how long a test waits for what must happen, and tick is how often it looks. quiet is how long a
	// test watches for what must not happen.
	wait  = 20 * time.Second
	tick  = 20 * time.Millisecond
	quiet = time.Second

	// resync is how often the streams of the tests read the Collectors and the context again, so that they follow a
	// change within a moment.
	resync = 50 * time.Millisecond
)

// cluster is the API server of the tests. It starts when the first test needs it, and TestMain stops it.
var cluster struct {
	once sync.Once
	env  *envtest.Environment
	api  client.Client
	err  error
}

func TestMain(m *testing.M) {
	// The SDK's servers log through slog. Their lines would only crowd the output of a test that fails.
	slog.SetDefault(slog.New(slog.DiscardHandler))
	code := m.Run()
	if cluster.env != nil {
		if err := cluster.env.Stop(); err != nil {
			fmt.Fprintln(os.Stderr, "stopping the API server:", err)
			code = 1
		}
	}
	os.Exit(code)
}

// apiServer returns a client of the API server, which it starts once, with the operator's CRDs and its namespace.
func apiServer(t *testing.T) client.Client {
	t.Helper()
	cluster.once.Do(func() {
		cluster.env = &envtest.Environment{
			CRDDirectoryPaths:     []string{filepath.Join("..", "..", "config", "crd", "bases")},
			ErrorIfCRDPathMissing: true,
			BinaryAssetsDirectory: assetsDirectory(),
		}
		cfg, err := cluster.env.Start()
		if err != nil {
			cluster.err = err
			return
		}
		scheme := runtime.NewScheme()
		if err := clientgoscheme.AddToScheme(scheme); err != nil {
			cluster.err = err
			return
		}
		if err := configv1alpha1.AddToScheme(scheme); err != nil {
			cluster.err = err
			return
		}
		api, err := client.New(cfg, client.Options{Scheme: scheme})
		if err == nil {
			err = api.Create(context.Background(), &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespace}})
		}
		cluster.api, cluster.err = api, err
	})
	require.NoError(t, cluster.err,
		"start the API server: KUBEBUILDER_ASSETS names its binaries, which `make setup-envtest` fetches")
	return cluster.api
}

// assetsDirectory is where the binaries of the API server are when KUBEBUILDER_ASSETS, which `make test` sets, is
// not: the repository's bin/k8s, which `make setup-envtest` fills. The tests then also run from an editor.
func assetsDirectory() string {
	if os.Getenv("KUBEBUILDER_ASSETS") != "" {
		return ""
	}
	root := filepath.Join("..", "..", "bin", "k8s")
	entries, err := os.ReadDir(root)
	if err != nil {
		return ""
	}
	for _, entry := range entries {
		if entry.IsDir() {
			return filepath.Join(root, entry.Name())
		}
	}
	return ""
}

// testEnv is what a test runs against: the API server, an authority of the operator's, a pool that takes its
// client's TLS from the authority, and the collectors that the test serves, which the pool's dialer reaches.
type testEnv struct {
	t         *testing.T
	api       client.Client
	authority *certs.Authority
	pool      *collectorclient.Pool

	mu sync.Mutex
	// routes are where the test serves each collector, by its name, or "" where it serves it no more. The pools of
	// the test forget each of them when the test ends.
	routes map[string]string
	// dialed are the addresses that the pool dialed, in order.
	dialed []string
}

// newEnv returns the environment of a test, with an authority that exists and a pool of its own.
func newEnv(t *testing.T) *testEnv {
	t.Helper()
	api := apiServer(t)
	authority := certs.NewAuthority(api, api, namespace, time.Now)
	require.NoError(t, authority.EnsureCA(t.Context()))
	e := &testEnv{t: t, api: api, authority: authority, routes: map[string]string{}}
	e.pool = e.newPool(authority.ClientTLS)
	return e
}

// newPool returns a pool of the operator's namespace, with clientTLS, whose dialer reaches the test's collectors.
// It closes the pool's connections when the test ends.
func (e *testEnv) newPool(clientTLS func() (*tls.Config, error)) *collectorclient.Pool {
	pool := collectorclient.NewPool(clientTLS, namespace)
	pool.Dialer = e.dial
	e.t.Cleanup(func() {
		e.mu.Lock()
		defer e.mu.Unlock()
		for name := range e.routes {
			pool.Forget(name)
		}
	})
	return pool
}

// address is where the pool reaches the collector of the name: its Service, in the operator's namespace, on port
// 9443.
func address(name string) string {
	return "vexplain-collector-" + name + "." + namespace + ".svc:9443"
}

// dial is the pool's dialer: it records the address, and connects to the collector that the test serves there.
func (e *testEnv) dial(ctx context.Context, to string) (net.Conn, error) {
	e.mu.Lock()
	e.dialed = append(e.dialed, to)
	target := ""
	for name, listen := range e.routes {
		if address(name) == to {
			target = listen
		}
	}
	e.mu.Unlock()
	if target == "" {
		return nil, fmt.Errorf("the test serves no collector at %s", to)
	}
	var dialer net.Dialer
	return dialer.DialContext(ctx, "tcp", target)
}

// route makes the pool reach the collector of the name at listen.
func (e *testEnv) route(name, listen string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.routes[name] = listen
}

// unroute makes the pool reach the collector of the name nowhere, as when it went away.
func (e *testEnv) unroute(name string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.routes[name] = ""
}

// dialedAddresses returns the addresses that the pool dialed, in order.
func (e *testEnv) dialedAddresses() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return slices.Clone(e.dialed)
}

// listen returns a listener on a port of its own, on the loopback interface.
func listen(t *testing.T) net.Listener {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	return listener
}

// tlsFiles writes the files of the collector's TLS Secret into a directory of their own, as the collector's
// Deployment mounts them, after the authority ensured the Secret. It returns the directory.
func (e *testEnv) tlsFiles(authority *certs.Authority, name string) string {
	e.t.Helper()
	_, err := authority.EnsureServer(e.t.Context(), name)
	require.NoError(e.t, err)
	var secret corev1.Secret
	require.NoError(e.t, e.api.Get(e.t.Context(), client.ObjectKey{Namespace: namespace, Name: certs.SecretName(name)},
		&secret))
	dir := e.t.TempDir()
	for _, file := range []string{"tls.crt", "tls.key", "ca.crt"} {
		require.NoError(e.t, os.WriteFile(filepath.Join(dir, file), secret.Data[file], 0o600))
	}
	return dir
}

// serve runs the SDK's server for c under the name until the test ends, with the TLS files that the authority of e
// issues for it, and routes the pool to it. It returns where the server listens.
func (e *testEnv) serve(name string, c collector.Collector) string {
	e.t.Helper()
	listener := listen(e.t)
	e.route(name, listener.Addr().String())
	startServer(e.t, c, e.tlsFiles(e.authority, name), listener)
	return listener.Addr().String()
}

// startServer runs the SDK's server for c, with the TLS files in dir, on listener. It returns a function that stops
// the server and waits for it, which also runs when the test ends.
func startServer(t *testing.T, c collector.Collector, dir string, listener net.Listener) func() {
	t.Helper()
	health := listen(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- collector.Serve(ctx, c, collector.Options{TLSDir: dir, GRPCListener: listener, HealthListener: health})
	}()
	var once sync.Once
	stop := func() {
		once.Do(func() {
			cancel()
			select {
			case err := <-done:
				assert.NoError(t, err, "Serve returns nil once its context ends")
			case <-time.After(wait):
				assert.Fail(t, "the collector's server didn't stop")
			}
		})
	}
	t.Cleanup(stop)
	return stop
}

// serveRaw runs a gRPC server for r under the name until the test ends, with mutual TLS from the TLS files that the
// authority of e issues for it, as the SDK's server would have, and routes the pool to it.
func (e *testEnv) serveRaw(name string, r *raw) {
	e.t.Helper()
	dir := e.tlsFiles(e.authority, name)
	pair, err := tls.LoadX509KeyPair(filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key"))
	require.NoError(e.t, err)
	caPEM, err := os.ReadFile(filepath.Join(dir, "ca.crt"))
	require.NoError(e.t, err)
	clients := x509.NewCertPool()
	require.True(e.t, clients.AppendCertsFromPEM(caPEM))
	server := grpc.NewServer(
		grpc.Creds(credentials.NewTLS(&tls.Config{
			MinVersion:   tls.VersionTLS13,
			Certificates: []tls.Certificate{pair},
			ClientAuth:   tls.RequireAndVerifyClientCert,
			ClientCAs:    clients,
		})),
		grpc.StatsHandler(r),
		grpc.MaxRecvMsgSize(16<<20),
		grpc.MaxSendMsgSize(16<<20),
	)
	collectorv1alpha1.RegisterEvidenceServer(server, r)
	healthpb.RegisterHealthServer(server, r.health)
	listener := listen(e.t)
	e.route(name, listener.Addr().String())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = server.Serve(listener)
	}()
	e.t.Cleanup(func() {
		server.Stop()
		<-done
	})
}

// startStreams runs the streams of e's pool with the sinks, and with the context that ClusterContext builds, until
// the test ends. They log to the test.
func (e *testEnv) startStreams(sinks map[configv1alpha1.CollectorRole]collectorclient.Sink) {
	e.t.Helper()
	e.startStreamsLogging(sinks, testr.New(e.t))
}

// startStreamsLogging is startStreams, with the streams logging to log.
func (e *testEnv) startStreamsLogging(sinks map[configv1alpha1.CollectorRole]collectorclient.Sink, log logr.Logger) {
	e.t.Helper()
	streams := collectorclient.NewStreams(e.pool, e.api, sinks, collectorclient.ClusterContext(e.api, namespace))
	streams.SetResync(resync)
	ctx, cancel := context.WithCancel(logr.NewContext(context.Background(), log))
	done := make(chan error, 1)
	go func() { done <- streams.Start(ctx) }()
	e.t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			assert.NoError(e.t, err, "Start returns nil once its context ends")
		case <-time.After(wait):
			assert.Fail(e.t, "the streams didn't stop")
		}
	})
}

// The Ready conditions that a test gives a Collector, as the deployer would set them.

// noData is Ready until the first health check: Unknown, with reason NoData.
func noData() metav1.Condition {
	return metav1.Condition{
		Type:    configv1alpha1.ConditionReady,
		Status:  metav1.ConditionUnknown,
		Reason:  configv1alpha1.ReasonNoData,
		Message: "The collector has not been checked yet.",
	}
}

// notReady is Ready False, with the reason.
func notReady(reason string) metav1.Condition {
	return metav1.Condition{
		Type:    configv1alpha1.ConditionReady,
		Status:  metav1.ConditionFalse,
		Reason:  reason,
		Message: "The collector can't be used.",
	}
}

// packageDigest is the digest of the image that runs a Collector of the tests, after n upgrades.
func packageDigest(n int) string {
	return fmt.Sprintf("sha256:%064x", 0xc0ffee+n)
}

// createCollector creates a Collector with the settings, unless they are empty, and gives it the status that the
// deployer would record for hello in the roles: its capabilities, its version, the digest that runs, and ready. It
// deletes the Collector when the test ends.
func (e *testEnv) createCollector(name, settings string, ready metav1.Condition, roles ...configv1alpha1.CollectorRole) {
	e.t.Helper()
	c := &configv1alpha1.Collector{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec:       configv1alpha1.CollectorSpec{Package: "artifacts.example/collectors/hello:0.1.0"},
	}
	if settings != "" {
		c.Spec.Settings = &runtime.RawExtension{Raw: []byte(settings)}
	}
	require.NoError(e.t, e.api.Create(e.t.Context(), c))
	e.t.Cleanup(func() {
		assert.NoError(e.t, client.IgnoreNotFound(e.api.Delete(context.Background(), c)))
	})
	c.Status.Capabilities = &configv1alpha1.CollectorCapabilities{
		Roles:      roles,
		Produces:   []configv1alpha1.ProducedType{{Type: helloType, Scope: configv1alpha1.EvidenceScopeSpoke}},
		Watch:      configv1alpha1.CollectorWatchSupported,
		Operations: []configv1alpha1.CollectorOperation{{Name: "greet", Produces: []string{helloType}}},
	}
	c.Status.Version = ptr.To("0.1.0")
	c.Status.PackageDigest = ptr.To(packageDigest(0))
	ready.ObservedGeneration = c.Generation
	meta.SetStatusCondition(&c.Status.Conditions, ready)
	require.NoError(e.t, e.api.Status().Update(e.t.Context(), c))
}

// updateCollector changes the Collector's spec, or its status when status is true, with change, until the API
// server takes it.
func (e *testEnv) updateCollector(name string, status bool, change func(*configv1alpha1.Collector)) {
	e.t.Helper()
	require.EventuallyWithT(e.t, func(c *assert.CollectT) {
		var obj configv1alpha1.Collector
		if !assert.NoError(c, e.api.Get(e.t.Context(), client.ObjectKey{Name: name}, &obj)) {
			return
		}
		change(&obj)
		if status {
			assert.NoError(c, e.api.Status().Update(e.t.Context(), &obj))
		} else {
			assert.NoError(c, e.api.Update(e.t.Context(), &obj))
		}
	}, wait, tick)
}

// setReady sets the Ready condition of the Collector, as the deployer would.
func (e *testEnv) setReady(name string, ready metav1.Condition) {
	e.t.Helper()
	e.updateCollector(name, true, func(c *configv1alpha1.Collector) {
		ready.ObservedGeneration = c.Generation
		meta.SetStatusCondition(&c.Status.Conditions, ready)
	})
}
