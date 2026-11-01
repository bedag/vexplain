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

package config_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	cloudevents "github.com/cloudevents/sdk-go/v2"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	eventsv1 "k8s.io/api/events/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
	"github.com/bedag/vexplain/internal/collector/certs"
	collectorv1alpha1 "github.com/bedag/vexplain/sdk/api/collector/v1alpha1"
	"github.com/bedag/vexplain/sdk/collector"
)

// The deployer's specs serve their collectors in the suite's process, over mutual TLS with the certificates that
// the operator's authority issued for them, as their Deployments would serve them. The suite's manager reaches
// them through collectorRoutes, the dialer of its collector pool. envtest runs no Deployment controller and no
// kubelet, so a spec writes the status of a collector's Deployment, and the pod that reports the digest it runs.

const (
	// collectorLabel is the label of everything that the deployer makes for a Collector, with the Collector's name.
	collectorLabel = "vexplain.bedag.ch/collector"
	// evidenceFinalizer is the finalizer through which the deployer deletes a deleted Collector's evidence.
	evidenceFinalizer = "vexplain.bedag.ch/evidence"
	// tlsDir is where a collector's Deployment mounts its TLS Secret, as the collector's contract says.
	tlsDir = "/run/vexplain/tls"
	// unhealthyReason is the reason of the event that reports a collector turning to Ready=False.
	unhealthyReason = "CollectorUnhealthy"

	// helloName is the name that the specs' collectors give themselves in GetInfo, helloType and greetingType are
	// the types of evidence that they produce, and greet the operation that they run.
	helloName    = "hello"
	helloType    = "com.example.hello.v1alpha1"
	greetingType = "com.example.greeting.v1alpha1"
	greet        = "greet"
	// speaks is the version of the collector API that the specs' collectors speak, the operator's.
	speaks = "v1alpha1"
	// collectorContainer is the name of the container that runs a collector.
	collectorContainer = "collector"
	// defaultRuntimeConfig is the runtime config of a Collector that names none.
	defaultRuntimeConfig = "default"
	// listenVariable names where the collector's contract has it serve the collector API, grpcListen.
	listenVariable = "VEXPLAIN_LISTEN"
	grpcListen     = ":9443"

	// deployTimeout bounds how long a spec waits for the deployer, which checks each Collector every second in
	// the suite, and deployPoll is how often it looks.
	deployTimeout = 30 * time.Second
	deployPoll    = 100 * time.Millisecond
)

// helloSettingsSchema is the settings schema of the specs' collectors: an object with a greeting, and nothing else.
const helloSettingsSchema = `{"type": "object", "properties": {"greeting": {"type": "string"}}, "additionalProperties": false}`

// fixtureT is what the fixtures need of a test: a *testing.T, or GinkgoT() in a spec.
type fixtureT interface {
	require.TestingT
	Helper()
	Cleanup(func())
	TempDir() string
}

// suiteClock is the clock of the suite's deployer: the wall clock, moved forward by what a spec asks for, until
// the spec ends.
type suiteClock struct{ offset atomic.Int64 }

func (c *suiteClock) now() time.Time { return time.Now().Add(time.Duration(c.offset.Load())) }

// advance moves the clock forward by d, and back again when the spec ends.
func (c *suiteClock) advance(d time.Duration) {
	c.offset.Add(int64(d))
	DeferCleanup(func() { c.offset.Add(-int64(d)) })
}

// collectorRoutes is the dialer of a collector pool: it reaches the collector of a name, whose Service the pool
// dials, where a test serves it.
type collectorRoutes struct {
	mu     sync.Mutex
	routes map[string]string
	dialed map[string]int
}

func newCollectorRoutes() *collectorRoutes {
	return &collectorRoutes{routes: map[string]string{}, dialed: map[string]int{}}
}

// route makes the pool reach the collector of the name at listen.
func (r *collectorRoutes) route(name, listen string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.routes[serviceAddress(name)] = listen
}

// dials says how often the pool dialed the collector of the name.
func (r *collectorRoutes) dials(name string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.dialed[serviceAddress(name)]
}

func (r *collectorRoutes) dial(ctx context.Context, address string) (net.Conn, error) {
	r.mu.Lock()
	r.dialed[address]++
	listen, ok := r.routes[address]
	r.mu.Unlock()
	if !ok {
		return nil, fmt.Errorf("no collector is served at %s", address)
	}
	var dialer net.Dialer
	return dialer.DialContext(ctx, "tcp", listen)
}

// serviceAddress is where the pool reaches the collector of the name: its Service, on port 9443.
func serviceAddress(name string) string {
	return net.JoinHostPort(certs.ServerName(name, operatorNamespace), "9443")
}

// writeTLSFiles writes the files of a collector's TLS Secret into a directory of their own, as its Deployment
// mounts them, and returns the directory.
func writeTLSFiles(t fixtureT, secret *corev1.Secret) string {
	t.Helper()
	dir := t.TempDir()
	for _, file := range []string{corev1.TLSCertKey, corev1.TLSPrivateKeyKey, "ca.crt"} {
		require.NotEmpty(t, secret.Data[file], file)
		require.NoError(t, os.WriteFile(filepath.Join(dir, file), secret.Data[file], 0o600))
	}
	return dir
}

// deployedTLSFiles waits for the TLS Secret that the deployer keeps for the Collector of the name, and writes its
// files, as writeTLSFiles does.
func deployedTLSFiles(name string) string {
	GinkgoHelper()
	var secret corev1.Secret
	Eventually(func() error {
		return k8sClient.Get(ctx, client.ObjectKey{Namespace: operatorNamespace, Name: certs.SecretName(name)}, &secret)
	}, deployTimeout, deployPoll).Should(Succeed())
	return writeTLSFiles(GinkgoT(), &secret)
}

// listen returns a listener on a port of its own, on the loopback interface, which the test closes.
func listen(t fixtureT) net.Listener {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	return listener
}

// fakeCollector serves the services of the collector API that the deployer calls, Identity and the standard
// health service, with whatever answers the test gives it, as a collector that isn't built with the SDK can. It
// answers SERVING until the test says otherwise.
type fakeCollector struct {
	collectorv1alpha1.UnimplementedIdentityServer
	health *health.Server

	mu           sync.Mutex
	info         *collectorv1alpha1.GetInfoResponse
	capabilities *collectorv1alpha1.GetCapabilitiesResponse
	problems     []string
}

// newFakeCollector returns a collector that speaks v1alpha1, and whose capabilities are helloCapabilities.
func newFakeCollector() *fakeCollector {
	return &fakeCollector{
		health:       health.NewServer(),
		info:         &collectorv1alpha1.GetInfoResponse{Name: helloName, Version: "0.1.0", ApiVersions: []string{speaks}},
		capabilities: helloCapabilities(),
	}
}

// helloCapabilities is what the fake collector answers to GetCapabilities until a test changes it: the spoke role,
// one type of evidence with its schema, a watch, and one operation.
func helloCapabilities() *collectorv1alpha1.GetCapabilitiesResponse {
	return &collectorv1alpha1.GetCapabilitiesResponse{
		Roles: []collectorv1alpha1.Role{collectorv1alpha1.Role_ROLE_SPOKE},
		Produces: []*collectorv1alpha1.EvidenceType{{
			Type: helloType, Scope: collectorv1alpha1.Scope_SCOPE_SPOKE, Schema: []byte(`{"type": "object"}`),
		}},
		Watches: true,
		Operations: []*collectorv1alpha1.Operation{{
			Name: greet, Role: collectorv1alpha1.Role_ROLE_SPOKE, Produces: []string{helloType},
		}},
		SettingsSchema: []byte(helloSettingsSchema),
	}
}

func (f *fakeCollector) GetInfo(context.Context, *collectorv1alpha1.GetInfoRequest) (*collectorv1alpha1.GetInfoResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.info, nil
}

func (f *fakeCollector) GetCapabilities(context.Context, *collectorv1alpha1.GetCapabilitiesRequest) (
	*collectorv1alpha1.GetCapabilitiesResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.capabilities, nil
}

func (f *fakeCollector) ValidateSettings(context.Context, *collectorv1alpha1.ValidateSettingsRequest) (
	*collectorv1alpha1.ValidateSettingsResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return &collectorv1alpha1.ValidateSettingsResponse{Problems: f.problems}, nil
}

// answer changes what the collector answers to GetInfo and GetCapabilities.
func (f *fakeCollector) answer(change func(*collectorv1alpha1.GetInfoResponse, *collectorv1alpha1.GetCapabilitiesResponse)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	change(f.info, f.capabilities)
}

// refuseSettings makes the collector's own check of the settings find the problems.
func (f *fakeCollector) refuseSettings(problems ...string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.problems = problems
}

// serve answers the health check with SERVING when serving is true, and with NOT_SERVING otherwise.
func (f *fakeCollector) serve(serving bool) {
	status := healthpb.HealthCheckResponse_NOT_SERVING
	if serving {
		status = healthpb.HealthCheckResponse_SERVING
	}
	f.health.SetServingStatus("", status)
}

// start serves the collector with the TLS files in dir until the test ends, and returns where it listens. It
// requires a client certificate that the authority of ca.crt signed, as the SDK's server does.
func (f *fakeCollector) start(t fixtureT, dir string) string {
	t.Helper()
	pair, err := tls.LoadX509KeyPair(filepath.Join(dir, corev1.TLSCertKey), filepath.Join(dir, corev1.TLSPrivateKeyKey))
	require.NoError(t, err)
	caPEM, err := os.ReadFile(filepath.Join(dir, "ca.crt"))
	require.NoError(t, err)
	clients := x509.NewCertPool()
	require.True(t, clients.AppendCertsFromPEM(caPEM))
	server := grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{pair},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clients,
	})))
	collectorv1alpha1.RegisterIdentityServer(server, f)
	healthpb.RegisterHealthServer(server, f.health)
	listener := listen(t)
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = server.Serve(listener)
	}()
	t.Cleanup(func() {
		server.Stop()
		<-done
	})
	return listener.Addr().String()
}

// serveFake serves f as the collector of the Collector of the name, with the certificates that the deployer keeps
// for it, until the spec ends.
func serveFake(name string, f *fakeCollector) {
	GinkgoHelper()
	collectors.route(name, f.start(GinkgoT(), deployedTLSFiles(name)))
}

// helloCollector is a collector of the specs that the SDK serves, as vexplain's own collectors are served. It takes
// both roles, produces two types of evidence, watches, runs greet in the hub role, and checks its settings against
// helloSettingsSchema and with refuse, when it is set.
type helloCollector struct {
	refuse func(settings json.RawMessage) []string
}

func (h *helloCollector) Info() collector.Info {
	return collector.Info{Name: helloName, Version: "1.2.3"}
}

func (h *helloCollector) Capabilities() collector.Capabilities {
	return collector.Capabilities{
		Roles: []collector.Role{collector.RoleSpoke, collector.RoleHub},
		Produces: []collector.EvidenceType{
			{Type: helloType, Scope: collector.ScopeSpoke, Schema: []byte(`{"type": "object"}`)},
			{Type: greetingType, Scope: collector.ScopeHub, Schema: []byte(`{"type": "object", "required": ["text"]}`)},
		},
		Consumes: []string{helloType},
		Watches:  true,
		Operations: []collector.Operation{{
			Name: greet, Role: collector.RoleHub, Produces: []string{greetingType}, Consumes: []string{helloType},
			ParameterSchema: []byte(`{"type": "object", "properties": {"name": {"type": "string"}}}`),
		}},
		SettingsSchema: []byte(helloSettingsSchema),
	}
}

func (h *helloCollector) Watch(ctx context.Context, _ collector.WatchRequest, _ collector.Sink) error {
	<-ctx.Done()
	return ctx.Err()
}

func (h *helloCollector) Invoke(context.Context, collector.InvokeRequest) ([]cloudevents.Event, *collector.Failure, error) {
	return nil, nil, nil
}

func (h *helloCollector) ValidateSettings(settings json.RawMessage) []string {
	if h.refuse == nil {
		return nil
	}
	return h.refuse(settings)
}

// serveSDK serves c with the SDK's server as the collector of the Collector of the name, with the certificates that
// the deployer keeps for it, until the spec ends.
func serveSDK(name string, c collector.Collector) {
	GinkgoHelper()
	dir := deployedTLSFiles(name)
	grpcListener, healthListener := listen(GinkgoT()), listen(GinkgoT())
	serving, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- collector.Serve(serving, c, collector.Options{TLSDir: dir, GRPCListener: grpcListener, HealthListener: healthListener})
	}()
	DeferCleanup(func() {
		cancel()
		Eventually(done, deployTimeout).Should(Receive(BeNil()))
	})
	collectors.route(name, grpcListener.Addr().String())
}

// newCollector creates a Collector with a name of its own and spec, and deletes it when the spec ends. It returns
// the name.
func newCollector(spec configv1alpha1.CollectorSpec) string {
	GinkgoHelper()
	name := apiName("hello")
	createObject(&configv1alpha1.Collector{ObjectMeta: metav1.ObjectMeta{Name: name}, Spec: spec})
	return name
}

// helloSpec is the spec of a Collector of the specs, with settings unless they are empty.
func helloSpec(settings string) configv1alpha1.CollectorSpec {
	spec := configv1alpha1.CollectorSpec{Package: examplePackage}
	if settings != "" {
		spec.Settings = &runtime.RawExtension{Raw: []byte(settings)}
	}
	return spec
}

// deploymentOf reads the Deployment that the deployer keeps for the Collector of the name, once it exists.
func deploymentOf(name string) *appsv1.Deployment {
	GinkgoHelper()
	var d appsv1.Deployment
	Eventually(func() error {
		return k8sClient.Get(ctx, client.ObjectKey{Namespace: operatorNamespace, Name: certs.ServiceName(name)}, &d)
	}, deployTimeout, deployPoll).Should(Succeed())
	return &d
}

// runningDigest is the digest of the image that the pods of the specs report as running.
var runningDigest = fmt.Sprintf("sha256:%064x", 0xc0ffee)

// makeAvailable creates the pod of the Collector's Deployment, whose container reports that it runs the image of
// digest, and then writes the status of the Deployment as the Deployment controller would once that pod is available.
// The pod is deleted when the spec ends.
func makeAvailable(name, digest string) {
	GinkgoHelper()
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: operatorNamespace, Name: certs.ServiceName(name) + "-5d8f9-x2k4p",
			Labels: map[string]string{collectorLabel: name},
		},
		Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: collectorContainer, Image: examplePackage}}},
	}
	createObject(pod)
	pod.Status = corev1.PodStatus{Phase: corev1.PodRunning, ContainerStatuses: []corev1.ContainerStatus{{
		Name: collectorContainer, Image: examplePackage, Ready: true,
		ImageID: "artifacts.example/vexplain/hello@" + digest,
	}}}
	Expect(k8sClient.Status().Update(ctx, pod)).To(Succeed())

	key := client.ObjectKeyFromObject(deploymentOf(name))
	Eventually(func(g Gomega) {
		var d appsv1.Deployment
		g.Expect(k8sClient.Get(ctx, key, &d)).To(Succeed())
		d.Status = appsv1.DeploymentStatus{
			ObservedGeneration: d.Generation, Replicas: 1, UpdatedReplicas: 1, ReadyReplicas: 1, AvailableReplicas: 1,
			Conditions: []appsv1.DeploymentCondition{{
				Type: appsv1.DeploymentAvailable, Status: corev1.ConditionTrue, Reason: "MinimumReplicasAvailable",
			}},
		}
		g.Expect(k8sClient.Status().Update(ctx, &d)).To(Succeed())
	}, deployTimeout, deployPoll).Should(Succeed())
}

// readyOf returns a function that reads the Collector of the name, and returns it with its Ready condition. It
// fails, so that an Eventually tries again, until the deployer has set the condition for the current generation.
func readyOf(name string) func(g Gomega) (*configv1alpha1.Collector, *metav1.Condition) {
	return func(g Gomega) (*configv1alpha1.Collector, *metav1.Condition) {
		var got configv1alpha1.Collector
		g.Expect(k8sClient.Get(ctx, client.ObjectKey{Name: name}, &got)).To(Succeed())
		ready := meta.FindStatusCondition(got.Status.Conditions, configv1alpha1.ConditionReady)
		g.Expect(ready).NotTo(BeNil())
		g.Expect(ready.ObservedGeneration).To(Equal(got.Generation))
		return &got, ready
	}
}

// expectReady waits until the Ready condition of the Collector of the name has the status and the reason, and
// returns the Collector and the condition.
func expectReady(name string, status metav1.ConditionStatus, reason string) (*configv1alpha1.Collector, *metav1.Condition) {
	GinkgoHelper()
	var got *configv1alpha1.Collector
	var ready *metav1.Condition
	Eventually(func(g Gomega) {
		got, ready = readyOf(name)(g)
		g.Expect(ready.Status).To(Equal(status), ready.Message)
		g.Expect(ready.Reason).To(Equal(reason), ready.Message)
	}, deployTimeout, deployPoll).Should(Succeed())
	return got, ready
}

// unhealthyEvents returns a function that lists the CollectorUnhealthy events about the Collector of the name. The
// events API files the events of a cluster-scoped object in the namespace default.
func unhealthyEvents(name string) func(g Gomega) []eventsv1.Event {
	return func(g Gomega) []eventsv1.Event {
		var list eventsv1.EventList
		g.Expect(k8sClient.List(ctx, &list,
			client.InNamespace(metav1.NamespaceDefault),
			client.MatchingFields{"regarding.name": name, "reason": unhealthyReason},
		)).To(Succeed())
		return list.Items
	}
}
