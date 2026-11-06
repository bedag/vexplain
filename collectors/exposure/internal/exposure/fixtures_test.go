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

package exposure

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	cloudevents "github.com/cloudevents/sdk-go/v2"
	"github.com/go-logr/logr"
	"github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/util/rand"
	"k8s.io/client-go/discovery"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	ctrllog "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/yaml"

	"github.com/bedag/vexplain/sdk/collector"
	"github.com/bedag/vexplain/sdk/evidence"
)

// The tests run the collector against an API server of envtest, through a cache of informers of its own, as the
// collector's main runs it against its cluster, with the Gateway API's CRDs installed. No controller runs: the tests
// create every object themselves, the ReplicaSet of a Deployment and its pods included. Each test makes namespaces of
// its own, and reads only what the collector says about the workloads in them. A Watch sees the whole cluster,
// though: a test that expects a workload not to be indirectly exposed gives it an ingress policy that no other
// test's workload passes.

const (
	// wait bounds how long a test waits for what must happen, and tick is how often it looks. quiet is how long a
	// test watches for what must not happen.
	wait  = 20 * time.Second
	tick  = 20 * time.Millisecond
	quiet = time.Second

	// settle is how long the watchers of the tests wait for more changes after one, which is short, so that a test
	// sees a change within a moment.
	settle = 10 * time.Millisecond

	// cluster is the cluster that the context of the tests names.
	cluster = "cluster-a"
	// operatorNamespace is the namespace of vexplain's operator in the context of the tests, and taskLabel the label
	// of vexplain's own pods there.
	operatorNamespace = "vexplain-system"
	taskLabel         = "vexplain.bedag.ch/task"
	// image is the image of the pods of the tests.
	image = "artifacts.example/team-a/app:1.0"
	// appLabel is the label that the Services and the policies of the tests select pods by, and tierLabel another
	// label of pods and namespaces.
	appLabel  = "app"
	tierLabel = "tier"
	// version is the version of the watchers of the tests.
	version = "0.1.0"
	// portName is the name of the port of the tests' Services.
	portName = "http"

	// The values of internalReach.
	reachNamespace  = "Namespace"
	reachPeers      = "Peers"
	reachNamespaces = "Namespaces"
	reachCluster    = "Cluster"

	// The names of the workloads of the tests.
	web, frontend, backend = "web", "frontend", "backend"
	// gatewayAPIVersion is the version of the Gateway API's kinds that the tests write.
	gatewayAPIVersion = "gateway.networking.k8s.io/v1"
)

// gatewayCRDs is the directory of the Gateway API's CRDs, which testdata/README describes.
var gatewayCRDs = filepath.Join("testdata", "gateway-api")

// api is the API server of the tests, with the Gateway API's CRDs, a direct client, the cache that the watchers read
// through, and a discovery client. It starts when the first test needs it, and TestMain stops it.
var api struct {
	once      sync.Once
	env       *envtest.Environment
	cfg       *rest.Config
	client    client.Client
	informers cache.Cache
	discovery discovery.DiscoveryInterface
	stop      context.CancelFunc
	err       error
}

func TestMain(m *testing.M) {
	// The cache and envtest log through controller-runtime's logger. Their lines would only crowd the output of a
	// test that fails.
	ctrllog.SetLogger(logr.Discard())
	code := m.Run()
	if api.stop != nil {
		api.stop()
	}
	if api.env != nil {
		if err := api.env.Stop(); err != nil {
			fmt.Fprintln(os.Stderr, "stopping the API server:", err)
			code = 1
		}
	}
	os.Exit(code)
}

// startAPI returns a client of the API server, and the cache of informers that reads it, which it starts once.
func startAPI(t *testing.T) (client.Client, cache.Cache) {
	t.Helper()
	api.once.Do(func() {
		api.env = &envtest.Environment{
			BinaryAssetsDirectory: assetsDirectory(),
			CRDDirectoryPaths:     []string{gatewayCRDs},
			ErrorIfCRDPathMissing: true,
		}
		api.cfg, api.err = api.env.Start()
		if api.err != nil {
			return
		}
		api.client, api.informers, api.discovery, api.stop, api.err = connect(api.cfg)
	})
	require.NoError(t, api.err,
		"start the API server: KUBEBUILDER_ASSETS names its binaries, which `make setup-envtest` fetches")
	return api.client, api.informers
}

// connect returns a client of the API server of cfg, a cache of informers with the collector's options, which it
// starts, the function that stops the cache, and a discovery client.
func connect(cfg *rest.Config) (client.Client, cache.Cache, discovery.DiscoveryInterface, context.CancelFunc, error) {
	c, err := client.New(cfg, client.Options{Scheme: clientgoscheme.Scheme})
	if err != nil {
		return nil, nil, nil, nil, err
	}
	informers, err := cache.New(cfg, CacheOptions())
	if err != nil {
		return nil, nil, nil, nil, err
	}
	d, err := discovery.NewDiscoveryClientForConfig(cfg)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	ctx, stop := context.WithCancel(context.Background())
	go func() { _ = informers.Start(ctx) }()
	return c, informers, d, stop, nil
}

// assetsDirectory is where the binaries of the API server are when KUBEBUILDER_ASSETS, which `make test` sets, is
// not: the repository's bin/k8s, which `make setup-envtest` fills. The tests then also run from an editor.
func assetsDirectory() string {
	if os.Getenv("KUBEBUILDER_ASSETS") != "" {
		return ""
	}
	root := filepath.Join("..", "..", "..", "..", "bin", "k8s")
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

// newWatcher returns a watcher of the tests, which reads the cache of the API server.
func newWatcher(t *testing.T) *Watcher {
	t.Helper()
	_, informers := startAPI(t)
	return NewWatcher(informers, api.discovery, Options{Name: collectorName, Version: version, Settle: settle})
}

// newNamespace creates a namespace with a name of its own and the labels, and deletes it when the test ends. It
// returns the namespace once the cache holds it.
func newNamespace(t *testing.T, labels map[string]string) *corev1.Namespace {
	t.Helper()
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "team-" + rand.String(6), Labels: labels}}
	create(t, ns)
	return ns
}

// create creates obj, deletes it when the test ends, and returns once the cache holds it.
func create(t *testing.T, obj client.Object) {
	t.Helper()
	c, _ := startAPI(t)
	require.NoError(t, c.Create(t.Context(), obj))
	t.Cleanup(func() { assert.NoError(t, client.IgnoreNotFound(c.Delete(context.Background(), obj))) })
	cached(t, obj)
}

// rewrite writes obj, and returns once the cache holds what it wrote.
func rewrite(t *testing.T, obj client.Object) {
	t.Helper()
	c, _ := startAPI(t)
	require.NoError(t, c.Update(t.Context(), obj))
	cached(t, obj)
}

// cached waits until the cache holds obj as the API server last returned it, in the form that the collector reads
// it in: whole for a pod, a Service, an EndpointSlice, an Ingress and a NetworkPolicy, as metadata for a namespace, an
// IngressClass, a ReplicaSet and a Job, and unstructured for a kind of the Gateway API. The informer of the form is
// the one that the collector's Watches share.
func cached(t *testing.T, obj client.Object) {
	t.Helper()
	_, informers := startAPI(t)
	var into client.Object
	switch obj.(type) {
	case *corev1.Namespace, *networkingv1.IngressClass, *appsv1.ReplicaSet, *batchv1.Job:
		gvk, err := api.client.GroupVersionKindFor(obj)
		require.NoError(t, err)
		metadata := &metav1.PartialObjectMetadata{}
		metadata.SetGroupVersionKind(gvk)
		into = metadata
	case *unstructured.Unstructured:
		u := &unstructured.Unstructured{}
		u.SetGroupVersionKind(obj.GetObjectKind().GroupVersionKind())
		into = u
	default:
		typed, ok := obj.DeepCopyObject().(client.Object)
		require.True(t, ok)
		into = typed
	}
	_, err := informers.GetInformer(t.Context(), into)
	require.NoError(t, err)
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		if assert.NoError(c, informers.Get(t.Context(), client.ObjectKeyFromObject(obj), into)) {
			assert.Equal(c, obj.GetResourceVersion(), into.GetResourceVersion())
		}
	}, wait, tick, "the cache holds %T %s", obj, client.ObjectKeyFromObject(obj))
}

// remove deletes obj, a pod or a Service, at once, and waits until the cache no longer holds it.
func remove(t *testing.T, obj client.Object) {
	t.Helper()
	c, informers := startAPI(t)
	require.NoError(t, c.Delete(t.Context(), obj, client.GracePeriodSeconds(0)))
	require.Eventually(t, func() bool {
		typed, ok := obj.DeepCopyObject().(client.Object)
		return ok && apierrors.IsNotFound(informers.Get(t.Context(), client.ObjectKeyFromObject(obj), typed))
	}, wait, tick, "the cache lets go of %s", client.ObjectKeyFromObject(obj))
}

// podOf returns a bare pod of the tests: no controller owns it, so it is a workload of its own, of kind Pod.
func podOf(namespace, name string, labels map[string]string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name, Labels: labels},
		Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "app", Image: image}}},
	}
}

// bare creates a bare pod with the labels app: name, and returns the subject of its workload.
func bare(t *testing.T, namespace, name string) string {
	t.Helper()
	create(t, podOf(namespace, name, map[string]string{appLabel: name}))
	return podSubject(namespace, name)
}

// podSubject is the subject of the workload of a bare pod.
func podSubject(namespace, name string) string {
	return "workload/" + cluster + "/" + namespace + "/Pod/" + name
}

// deployment creates the Deployment of the name in namespace, the ReplicaSet of it that runs its pods, and a pod of
// that, all labelled app: name, as the Deployment's controllers would. It returns the subject of the Deployment.
func deployment(t *testing.T, namespace, name string) string {
	t.Helper()
	return deploymentOf(t, namespace, name, func(*corev1.Pod) {})
}

// deploymentOf is deployment, with the pod as change makes it.
func deploymentOf(t *testing.T, namespace, name string, change func(*corev1.Pod)) string {
	t.Helper()
	labels := map[string]string{appLabel: name}
	template := corev1.PodTemplateSpec{
		ObjectMeta: metav1.ObjectMeta{Labels: labels},
		Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "app", Image: image}}},
	}
	d := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name},
		Spec:       appsv1.DeploymentSpec{Selector: &metav1.LabelSelector{MatchLabels: labels}, Template: template},
	}
	c, _ := startAPI(t)
	require.NoError(t, c.Create(t.Context(), d))
	rs := &appsv1.ReplicaSet{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace, Name: name + "-5d8f9",
			OwnerReferences: []metav1.OwnerReference{controlledBy(d, "apps/v1", "Deployment")},
		},
		Spec: appsv1.ReplicaSetSpec{Selector: &metav1.LabelSelector{MatchLabels: labels}, Template: template},
	}
	create(t, rs)
	pod := podOf(namespace, name+"-5d8f9-x2k4p", labels)
	pod.OwnerReferences = []metav1.OwnerReference{controlledBy(rs, "apps/v1", "ReplicaSet")}
	change(pod)
	create(t, pod)
	return "workload/" + cluster + "/" + namespace + "/Deployment.apps/" + name
}

// controlledBy is the owner reference of an object that obj controls.
func controlledBy(obj client.Object, apiVersion, kind string) metav1.OwnerReference {
	return metav1.OwnerReference{
		APIVersion: apiVersion, Kind: kind, Name: obj.GetName(), UID: obj.GetUID(), Controller: ptr.To(true),
	}
}

// service creates a Service of the type, the name and the annotations in namespace, which selects the pods labelled
// app: selected, and returns it. A Service of type LoadBalancer gets node ports only when nodePorts says so.
func service(t *testing.T, namespace, name string, kind corev1.ServiceType, selected string,
	annotations map[string]string, nodePorts bool) *corev1.Service {
	t.Helper()
	s := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name, Annotations: annotations},
		Spec: corev1.ServiceSpec{
			Type:     kind,
			Selector: map[string]string{appLabel: selected},
			Ports:    []corev1.ServicePort{{Name: portName, Port: 80}},
		},
	}
	if kind == corev1.ServiceTypeLoadBalancer {
		s.Spec.AllocateLoadBalancerNodePorts = ptr.To(nodePorts)
	}
	create(t, s)
	return s
}

// withHostPort gives the pod's container a port on its node.
func withHostPort(pod *corev1.Pod) {
	pod.Spec.Containers[0].Ports = []corev1.ContainerPort{{ContainerPort: 8080, HostPort: 8080}}
}

// serviceRef is how an event names the Service of the name in namespace.
func serviceRef(namespace, name string) evidence.ObjectRef {
	return evidence.ObjectRef{APIGroup: "", Kind: "Service", Namespace: namespace, Name: name}
}

// ingress creates an Ingress of the name and class in namespace, which routes to the Service of the name backend.
// An empty class gives an Ingress without a class.
func ingress(t *testing.T, namespace, name, class, backend string) {
	t.Helper()
	i := &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name},
		Spec: networkingv1.IngressSpec{
			Rules: []networkingv1.IngressRule{{
				Host: name + ".artifacts.example",
				IngressRuleValue: networkingv1.IngressRuleValue{HTTP: &networkingv1.HTTPIngressRuleValue{
					Paths: []networkingv1.HTTPIngressPath{{
						Path:     "/",
						PathType: ptr.To(networkingv1.PathTypePrefix),
						Backend: networkingv1.IngressBackend{Service: &networkingv1.IngressServiceBackend{
							Name: backend, Port: networkingv1.ServiceBackendPort{Number: 80},
						}},
					}},
				}},
			}},
		},
	}
	if class != "" {
		i.Spec.IngressClassName = ptr.To(class)
	}
	create(t, i)
}

// fromYAML creates the object that manifest describes, a kind of the Gateway API.
func fromYAML(t *testing.T, manifest string) {
	t.Helper()
	u := &unstructured.Unstructured{}
	require.NoError(t, yaml.Unmarshal([]byte(manifest), &u.Object))
	create(t, u)
}

// gateway creates a Gateway of the name in namespace, with one HTTP listener whose allowedRoutes are allowed, as
// YAML, or the default when allowed is empty.
func gateway(t *testing.T, namespace, name, allowed string) {
	t.Helper()
	listener := "  - name: http\n    port: 80\n    protocol: HTTP\n"
	if allowed != "" {
		listener += "    allowedRoutes:\n" + allowed
	}
	fromYAML(t, fmt.Sprintf(`apiVersion: %s
kind: Gateway
metadata:
  namespace: %s
  name: %s
spec:
  gatewayClassName: example
  listeners:
%s`, gatewayAPIVersion, namespace, name, listener))
}

// httpRoute creates an HTTPRoute of the name in namespace, attached to the Gateway parent in parentNamespace, which
// routes to the Service of the name backend in namespace.
func httpRoute(t *testing.T, namespace, name, parentNamespace, parent, backend string) {
	t.Helper()
	fromYAML(t, fmt.Sprintf(`apiVersion: %s
kind: HTTPRoute
metadata:
  namespace: %s
  name: %s
spec:
  parentRefs:
  - name: %s
    namespace: %s
  rules:
  - backendRefs:
    - name: %s
      port: 80
`, gatewayAPIVersion, namespace, name, parent, parentNamespace, backend))
}

// routeRef is how an event names the HTTPRoute of the name in namespace.
func routeRef(namespace, name string) evidence.ObjectRef {
	return evidence.ObjectRef{APIGroup: gatewayGroup, Kind: kindHTTPRoute, Namespace: namespace, Name: name}
}

// createPolicy creates the NetworkPolicy of the name in namespace with the spec.
func createPolicy(t *testing.T, namespace, name string,
	spec networkingv1.NetworkPolicySpec) *networkingv1.NetworkPolicy {
	t.Helper()
	p := &networkingv1.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name}, Spec: spec}
	create(t, p)
	return p
}

// selecting is the label selector of the pods labelled app: name.
func selecting(name string) *metav1.LabelSelector {
	return &metav1.LabelSelector{MatchLabels: map[string]string{appLabel: name}}
}

// namespaceNamed is the label selector of the namespaces of the names.
func namespaceNamed(names ...string) *metav1.LabelSelector {
	return &metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{{
		Key: corev1.LabelMetadataName, Operator: metav1.LabelSelectorOpIn, Values: names,
	}}}
}

// ingressFrom is the spec of a policy that selects the pods labelled app: name and lets in only from the peers.
func ingressFrom(name string, peers ...networkingv1.NetworkPolicyPeer) networkingv1.NetworkPolicySpec {
	return networkingv1.NetworkPolicySpec{
		PodSelector: *selecting(name),
		PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
		Ingress:     []networkingv1.NetworkPolicyIngressRule{{From: peers}},
	}
}

// everything is the scope that selects every pod, as the context carries it.
var everything = json.RawMessage(`{}`)

// contextWith is the context of a Watch of the tests, with the scope.
func contextWith(scope json.RawMessage) collector.Context {
	return collector.Context{
		Cluster: cluster, OperatorNamespace: operatorNamespace, OwnPodLabel: taskLabel, Scope: scope,
	}
}

// exposureSchema is the schema of the data of the exposure type, which every event of the tests must pass.
var exposureSchema = func() *jsonschema.Schema {
	raw, ok := evidence.Schema(evidence.TypeExposure)
	if !ok {
		panic("the SDK has no schema of the exposure type")
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		panic(err)
	}
	compiler := jsonschema.NewCompiler()
	const url = "urn:exposure-tests:schema"
	if err := compiler.AddResource(url, doc); err != nil {
		panic(err)
	}
	return compiler.MustCompile(url)
}()

// recordingSink is the sink of a Watch of the tests. It records what the Watch sends, checks each event as the SDK's
// sink does and its data against the schema of the exposure type, and closes ended at SnapshotEnd.
type recordingSink struct {
	mu        sync.Mutex
	snapshot  []cloudevents.Event
	changes   []change
	ended     chan struct{}
	endedOnce sync.Once
	problems  []string
}

// change is an event or a tombstone after the snapshot.
type change struct {
	event     *cloudevents.Event
	tombstone string // the subject of a tombstone
}

func newRecordingSink() *recordingSink { return &recordingSink{ended: make(chan struct{})} }

func (s *recordingSink) SnapshotStart() error { return nil }

func (s *recordingSink) Event(e cloudevents.Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := evidence.Validate(e); err != nil {
		s.problems = append(s.problems, fmt.Sprintf("event %s is not valid evidence: %v", e.Subject(), err))
	}
	if e.Type() != evidence.TypeExposure {
		s.problems = append(s.problems, fmt.Sprintf("event %s is of type %s", e.Subject(), e.Type()))
	}
	if e.Source() != "/clusters/"+cluster+"/collectors/exposure" {
		s.problems = append(s.problems, fmt.Sprintf("event %s has the source %s", e.Subject(), e.Source()))
	}
	if instance, err := jsonschema.UnmarshalJSON(bytes.NewReader(e.Data())); err != nil {
		s.problems = append(s.problems, fmt.Sprintf("the data of event %s is no JSON: %v", e.Subject(), err))
	} else if err := exposureSchema.Validate(instance); err != nil {
		s.problems = append(s.problems, fmt.Sprintf("the data of event %s fails the schema: %v", e.Subject(), err))
	}
	select {
	case <-s.ended:
		s.changes = append(s.changes, change{event: &e})
	default:
		s.snapshot = append(s.snapshot, e)
	}
	return nil
}

func (s *recordingSink) Tombstone(eventType, about string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if eventType != evidence.TypeExposure {
		s.problems = append(s.problems, fmt.Sprintf("a tombstone about %s is of type %s", about, eventType))
	}
	s.changes = append(s.changes, change{tombstone: about})
	return nil
}

func (s *recordingSink) SnapshotEnd() error {
	s.endedOnce.Do(func() { close(s.ended) })
	return nil
}

func (s *recordingSink) SourceChanged(...string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.problems = append(s.problems, "the collector sent SourceChanged, and it has no source of its own")
	return nil
}

// watch runs a Watch of w with the settings, as JSON, and a context whose scope selects everything, until the test
// ends, and returns its sink once the snapshot has ended.
func watch(t *testing.T, w *Watcher, settings string) *recordingSink {
	t.Helper()
	return startWatch(t, w, collector.WatchRequest{
		Role: collector.RoleSpoke, Settings: settingsOf(settings), Context: contextWith(everything),
	})
}

// settingsOf returns the settings as a Watch gets them: an empty object for none.
func settingsOf(settings string) json.RawMessage {
	if settings == "" {
		return json.RawMessage(`{}`)
	}
	return json.RawMessage(settings)
}

// startWatch runs a Watch of w for req until the test ends, and returns its sink once the snapshot has ended. When
// the test ends, it ends the Watch and waits until it has returned. The test fails when the Watch returns before its
// snapshot, or with anything but the end of its context, or when the sink recorded a problem.
func startWatch(t *testing.T, w *Watcher, req collector.WatchRequest) *recordingSink {
	t.Helper()
	sink := newRecordingSink()
	ctx, cancel := context.WithCancel(context.Background())
	var err error
	done := make(chan struct{})
	go func() {
		defer close(done)
		err = w.Watch(ctx, req, sink)
	}()
	var once sync.Once
	stop := func() {
		once.Do(func() {
			cancel()
			select {
			case <-done:
				assert.ErrorIs(t, err, context.Canceled, "the Watch ends with its context")
			case <-time.After(wait):
				assert.Fail(t, "the Watch didn't end with its context")
			}
			sink.mu.Lock()
			defer sink.mu.Unlock()
			assert.Empty(t, sink.problems)
		})
	}
	select {
	case <-sink.ended:
	case <-done:
		cancel()
		require.FailNow(t, "the Watch ended before its snapshot", "%v", err)
	case <-time.After(wait):
		cancel()
		require.FailNow(t, "the Watch sent no SnapshotEnd")
	}
	t.Cleanup(stop)
	return sink
}

// exposureIn returns what the events say about the workload of the subject: the data of the last event about it, and
// false when there is none.
func exposureIn(t *testing.T, events []cloudevents.Event, about string) (evidence.Exposure, bool) {
	t.Helper()
	var found *evidence.Exposure
	for _, e := range events {
		if e.Subject() != about {
			continue
		}
		var data evidence.Exposure
		require.NoError(t, json.Unmarshal(e.Data(), &data))
		found = &data
	}
	if found == nil {
		return evidence.Exposure{}, false
	}
	return *found, true
}

// inSnapshot returns what the snapshot says about the workload of the subject, and fails the test when it says
// nothing.
func (s *recordingSink) inSnapshot(t *testing.T, about string) evidence.Exposure {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	found, ok := exposureIn(t, s.snapshot, about)
	require.True(t, ok, "the snapshot has an event about %s", about)
	return found
}

// mentions reports whether the snapshot has an event about the subject.
func (s *recordingSink) mentions(t *testing.T, about string) bool {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := exposureIn(t, s.snapshot, about)
	return ok
}

// changesAbout returns the changes about the workload of the subject, in order.
func (s *recordingSink) changesAbout(about string) []change {
	s.mu.Lock()
	defer s.mu.Unlock()
	var found []change
	for _, ch := range s.changes {
		if ch.tombstone == about || (ch.event != nil && ch.event.Subject() == about) {
			found = append(found, ch)
		}
	}
	return found
}

// nextChange waits for the change about the workload of the subject that follows the n changes about it so far, and
// returns it.
func (s *recordingSink) nextChange(t *testing.T, about string, n int) change {
	t.Helper()
	require.Eventually(t, func() bool { return len(s.changesAbout(about)) > n }, wait, tick,
		"a change about %s", about)
	return s.changesAbout(about)[n]
}

// dataOf returns the exposure that the event of a change says.
func dataOf(t *testing.T, ch change) evidence.Exposure {
	t.Helper()
	require.NotNil(t, ch.event, "the change is an event, not a tombstone")
	var data evidence.Exposure
	require.NoError(t, json.Unmarshal(ch.event.Data(), &data))
	return data
}
