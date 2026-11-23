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
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/rand"
	"k8s.io/client-go/discovery"
	fakediscovery "k8s.io/client-go/discovery/fake"
	clienttesting "k8s.io/client-go/testing"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	"sigs.k8s.io/yaml"

	"github.com/bedag/vexplain/sdk/collector"
	"github.com/bedag/vexplain/sdk/evidence"
)

// The network-reach collector takes the spoke role, where the workloads are, and streams exposure, which goes to the
// hub. It reads, in the whole cluster, what decides exposure: pods, namespaces, Services and EndpointSlices,
// Ingresses, NetworkPolicies, the Gateway API's Gateways and routes, Cilium's two kinds of policy, and the
// ReplicaSets and Jobs through which it finds a pod's workload, and the nodes, on whose addresses node ports and host
// ports are reached. It only lists and watches.
func TestTheCapabilities(t *testing.T) {
	caps := newWatcher(t).Capabilities()

	require.Equal(t, []collector.Role{collector.RoleSpoke}, caps.Roles)
	require.True(t, caps.Watches)
	require.Empty(t, caps.Operations)
	require.Len(t, caps.Produces, 1)
	require.Equal(t, evidence.TypeExposure, caps.Produces[0].Type)
	require.Equal(t, collector.ScopeHub, caps.Produces[0].Scope)
	want, ok := evidence.Schema(evidence.TypeExposure)
	require.True(t, ok)
	require.JSONEq(t, string(want), string(caps.Produces[0].Schema))
	listAndWatch := []string{"list", "watch"}
	require.Equal(t, []collector.Permission{
		{APIGroups: []string{""}, Resources: []string{"pods", "namespaces", "services", "nodes"},
			Verbs: listAndWatch},
		{APIGroups: []string{"discovery.k8s.io"}, Resources: []string{"endpointslices"}, Verbs: listAndWatch},
		{APIGroups: []string{"networking.k8s.io"}, Resources: []string{"ingresses", "networkpolicies"},
			Verbs: listAndWatch},
		{APIGroups: []string{"gateway.networking.k8s.io"}, Resources: []string{"gateways", "httproutes", "tlsroutes",
			"grpcroutes"}, Verbs: listAndWatch},
		{APIGroups: []string{"cilium.io"}, Resources: []string{"ciliumnetworkpolicies",
			"ciliumclusterwidenetworkpolicies"}, Verbs: listAndWatch},
		{APIGroups: []string{"apps"}, Resources: []string{"replicasets"}, Verbs: listAndWatch},
		{APIGroups: []string{"batch"}, Resources: []string{"jobs"}, Verbs: listAndWatch},
	}, caps.Permissions)
}

// A Watch starts with a snapshot of every workload. After it, a workload whose exposure changed comes again, whole,
// and a workload that is gone comes as a tombstone.
func TestASnapshotThenAChangeForAWorkloadWhoseExposureChangedAndATombstoneForOneThatIsGone(t *testing.T) {
	ns := newNamespace(t, nil).Name
	pod := podOf(ns, web, map[string]string{appLabel: web})
	create(t, pod)
	subject := podSubject(ns, web)
	sink := watch(t, newWatcher(t), "")
	require.Equal(t, notExposed, sink.inSnapshot(t, subject).External)

	service(t, ns, web, corev1.ServiceTypeLoadBalancer, web, nil, false)
	require.Equal(t, exposedUnchecked(evidence.UncheckedNoAddress), dataOf(t, sink.nextChange(t, subject, 0)).External)

	remove(t, pod)
	require.Equal(t, change{tombstone: subject}, sink.nextChange(t, subject, 1))
}

// A Watch reports the workloads in the scope of its context, and none of vexplain's own pods. A workload outside the
// scope still counts, though: an exposed frontend outside it makes a backend inside it indirectly exposed.
func TestOnlyWorkloadsInScopeGetEventsButEveryWorkloadCounts(t *testing.T) {
	inside := newNamespace(t, map[string]string{"vexplain": "on"}).Name
	outside := newNamespace(t, nil).Name
	front := bare(t, outside, frontend)
	service(t, outside, frontend, corev1.ServiceTypeLoadBalancer, frontend, nil, false)
	back := bare(t, inside, backend)
	createPolicy(t, inside, backend, ingressFrom(backend, networkingv1.NetworkPolicyPeer{
		NamespaceSelector: namespaceNamed(outside), PodSelector: selecting(frontend),
	}))
	create(t, podOf(inside, "scan-0", map[string]string{taskLabel: "scan"}))
	scope := json.RawMessage(`{"includeNamespaces": {"matchLabels": {"vexplain": "on"}}}`)
	c := contextWith(scope)
	c.OperatorNamespace = inside

	sink := startWatch(t, newWatcher(t), collector.WatchRequest{
		Role: collector.RoleSpoke, Settings: settingsOf(""), Context: c,
	})

	require.False(t, sink.mentions(t, front), "a workload outside the scope gets no event")
	require.False(t, sink.mentions(t, podSubject(inside, "scan-0")), "vexplain's own pod gets no event")
	require.True(t, sink.inSnapshot(t, back).Indirect)
}

// A context or settings that the collector can't read fully are refused before the snapshot: a scope applied in part
// could report workloads that it leaves out, and settings read in part could count as internal what isn't.
func TestAWatchRefusesAContextOrSettingsThatItCantRead(t *testing.T) {
	for name, req := range map[string]collector.WatchRequest{
		"a scope that isn't JSON": {Context: contextWith(json.RawMessage(`{"includePods":`)), Settings: settingsOf("")},
		"a scope with a field that a scope lacks": {
			Context:  contextWith(json.RawMessage(`{"excludeNodes": {"matchLabels": {"pool": "gpu"}}}`)),
			Settings: settingsOf(""),
		},
		"settings that aren't JSON": {Context: contextWith(everything), Settings: settingsOf(`{"nodePorts":`)},
		"settings with a field that they lack": {
			Context: contextWith(everything), Settings: settingsOf(`{"ingressClass": ["public"]}`),
		},
		"node ports that are neither External nor Internal": {
			Context: contextWith(everything), Settings: settingsOf(`{"nodePorts": "Sometimes"}`),
		},
		"host ports that are neither External nor Internal": {
			Context: contextWith(everything), Settings: settingsOf(`{"hostPorts": "Sometimes"}`),
		},
		"a host network that is neither External nor Internal": {
			Context: contextWith(everything), Settings: settingsOf(`{"hostNetwork": "Sometimes"}`),
		},
		"a trusted peer that sets nothing, which would trust every peer": {
			Context: contextWith(everything), Settings: settingsOf(`{"trustedPeers": [{}]}`),
		},
		"a trusted peer whose selector Kubernetes refuses": {
			Context: contextWith(everything),
			Settings: settingsOf(`{"trustedPeers": [{"podSelector": {"matchExpressions": ` +
				`[{"key": "app", "operator": "In"}]}}]}`),
		},
		"a trusted service account without a name": {
			Context:  contextWith(everything),
			Settings: settingsOf(`{"trustedPeers": [{"serviceAccount": {"namespace": "monitoring"}}]}`),
		},
	} {
		t.Run(name, func(t *testing.T) {
			req.Role = collector.RoleSpoke
			sink := newRecordingSink()
			// A Watch that doesn't refuse runs until its context ends.
			ctx, cancel := context.WithTimeout(t.Context(), wait)
			defer cancel()
			err := newWatcher(t).Watch(ctx, req, sink)

			require.Equal(t, codes.InvalidArgument, status.Code(err), "%v", err)
			require.Empty(t, sink.snapshot)
			select {
			case <-sink.ended:
				require.Fail(t, "no snapshot ends")
			default:
			}
		})
	}
}

// limitedWatcher returns a watcher that reads the API server of the tests through a cache and an API discovery of a
// user of its own, which holds every permission that the collector declares, but the resource withheld, and nothing
// else. Its Watches wait a second for their informers.
func limitedWatcher(t *testing.T, withheld string) *Watcher {
	t.Helper()
	c, _ := startAPI(t)
	name := "exposure-" + rand.String(6)
	user, err := api.env.AddUser(envtest.User{Name: name}, nil)
	require.NoError(t, err)
	role := &rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: name}}
	for _, declared := range newWatcher(t).Capabilities().Permissions {
		resources := slices.DeleteFunc(slices.Clone(declared.Resources), func(r string) bool { return r == withheld })
		if len(resources) > 0 {
			role.Rules = append(role.Rules, rbacv1.PolicyRule{
				APIGroups: declared.APIGroups, Verbs: declared.Verbs, Resources: resources,
			})
		}
	}
	binding := &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: role.Name},
		RoleRef:    rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: role.Name},
		Subjects:   []rbacv1.Subject{{APIGroup: rbacv1.GroupName, Kind: rbacv1.UserKind, Name: name}},
	}
	for _, obj := range []client.Object{role, binding} {
		require.NoError(t, c.Create(t.Context(), obj))
		t.Cleanup(func() { assert.NoError(t, client.IgnoreNotFound(c.Delete(context.Background(), obj))) })
	}
	limited, err := cache.New(user.Config(), CacheOptions())
	require.NoError(t, err)
	d, err := discovery.NewDiscoveryClientForConfig(user.Config())
	require.NoError(t, err)
	ctx, stop := context.WithCancel(context.Background())
	t.Cleanup(stop)
	go func() { _ = limited.Start(ctx) }()
	return NewWatcher(limited, d, Options{Name: collectorName, Version: version, Settle: settle, SyncTimeout: time.Second})
}

// A collector whose service account lacks a right that it declares can't list a kind, and the informer of that kind
// never syncs. The Watch waits for the informers for Options.SyncTimeout, and then fails with Unavailable, naming the
// kind, rather than never sending its snapshot while the collector's health check says SERVING.
func TestAWatchWhoseInformerNeverSyncsFailsWithUnavailable(t *testing.T) {
	w := limitedWatcher(t, "endpointslices")
	ctx, stop := context.WithCancel(context.Background())
	t.Cleanup(stop)

	done := make(chan error, 1)
	go func() {
		done <- w.Watch(ctx, collector.WatchRequest{Role: collector.RoleSpoke, Settings: settingsOf(""),
			Context: contextWith(everything)}, newRecordingSink())
	}()

	select {
	case err := <-done:
		require.Equal(t, codes.Unavailable, status.Code(err), "%v", err)
		require.ErrorContains(t, err, "EndpointSlice.discovery.k8s.io")
	case <-time.After(wait):
		require.FailNow(t, "the Watch still waits for an informer that never syncs")
	}
}

// A collector whose service account holds the permissions that it declares, and no others, sends its snapshot: it
// reads no kind beyond what it declares, which is what vexplain's install grants it.
func TestAWatchNeedsNoMoreThanTheDeclaredPermissions(t *testing.T) {
	startWatch(t, limitedWatcher(t, ""), collector.WatchRequest{
		Role: collector.RoleSpoke, Settings: settingsOf(""), Context: contextWith(everything),
	})
}

// ownAPI is an API server of a test of its own, which starts without the Gateway API's CRDs.
type ownAPI struct {
	env       *envtest.Environment
	client    client.Client
	informers cache.Cache
	discovery discovery.DiscoveryInterface
}

// startOwnAPI starts an API server of the test's own, and stops it when the test ends.
func startOwnAPI(t *testing.T) ownAPI {
	t.Helper()
	env := &envtest.Environment{BinaryAssetsDirectory: assetsDirectory()}
	cfg, err := env.Start()
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, env.Stop()) })
	c, informers, d, stop, err := connect(cfg)
	require.NoError(t, err)
	t.Cleanup(stop)
	return ownAPI{env: env, client: c, informers: informers, discovery: d}
}

// createIn creates obj with the client of the API server, and waits until the cache holds it, in the form of into.
func (o ownAPI) createIn(t *testing.T, obj, into client.Object) {
	t.Helper()
	require.NoError(t, o.client.Create(t.Context(), obj))
	_, err := o.informers.GetInformer(t.Context(), into)
	require.NoError(t, err)
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		assert.NoError(c, o.informers.Get(t.Context(), client.ObjectKeyFromObject(obj), into))
	}, wait, tick)
}

// The collector finds out itself which APIs the cluster serves: the Gateway API's CRDs installed after a Watch
// started are watched within the discovery interval, and their routes expose what they route to. Once the CRDs are
// gone, the Watch stops their informers.
func TestTheGatewayAPIInstalledAfterTheStartIsWatchedWithinTheDiscoveryInterval(t *testing.T) {
	own := startOwnAPI(t)
	ns := "team-" + rand.String(6)
	namespace := &metav1.PartialObjectMetadata{}
	namespace.SetGroupVersionKind(corev1.SchemeGroupVersion.WithKind("Namespace"))
	own.createIn(t, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns}}, namespace)
	own.createIn(t, podOf(ns, web, map[string]string{appLabel: web}), &corev1.Pod{})
	own.createIn(t, &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: web},
		Spec:       corev1.ServiceSpec{Selector: map[string]string{appLabel: web}, Ports: []corev1.ServicePort{{Port: 80}}},
	}, &corev1.Service{})
	subject := podSubject(ns, web)
	w := NewWatcher(own.informers, own.discovery, Options{
		Name: collectorName, Version: version, Settle: settle, DiscoveryInterval: 100 * time.Millisecond,
	})
	sink := watch(t, w, "")
	require.Equal(t, notExposed, sink.inSnapshot(t, subject).External)

	crds := envtest.CRDInstallOptions{Paths: []string{gatewayCRDs}}
	_, err := envtest.InstallCRDs(own.env.Config, crds)
	require.NoError(t, err)
	for _, manifest := range []string{
		fmt.Sprintf("apiVersion: %s\nkind: Gateway\nmetadata: {namespace: %s, name: %s}\nspec:\n"+
			"  gatewayClassName: example\n  listeners: [{name: http, port: 80, protocol: HTTP}]\n",
			gatewayAPIVersion, ns, web),
		fmt.Sprintf("apiVersion: %s\nkind: HTTPRoute\nmetadata: {namespace: %s, name: %s}\nspec:\n"+
			"  parentRefs: [{name: %s}]\n  rules: [{backendRefs: [{name: %s, port: 80}]}]\n",
			gatewayAPIVersion, ns, web, web, web),
	} {
		u := &unstructured.Unstructured{}
		require.NoError(t, yaml.Unmarshal([]byte(manifest), &u.Object))
		require.EventuallyWithT(t, func(c *assert.CollectT) {
			assert.NoError(c, own.client.Create(t.Context(), u.DeepCopy()))
		}, wait, tick, "create %s", u.GetKind())
	}
	require.Equal(t, exposedUnchecked(evidence.UncheckedNoAddress), dataOf(t, sink.nextChange(t, subject, 0)).External)

	require.NoError(t, envtest.UninstallCRDs(own.env.Config, crds))
	require.Equal(t, notExposed, dataOf(t, sink.nextChange(t, subject, 1)).External)
	routes := &unstructured.UnstructuredList{}
	routes.SetGroupVersionKind(schema.GroupVersionKind{Group: gatewayGroup, Version: "v1", Kind: "HTTPRouteList"})
	require.Eventually(t, func() bool {
		var notCached *cache.ErrResourceNotCached
		return errors.As(own.informers.List(t.Context(), routes), &notCached)
	}, wait, tick, "the Watch stops its informer of HTTPRoutes")
}

// stableBuilds waits until the Watches of w build no more, and returns how often they built and how many namespaces
// they computed again: the informers replay what they hold to a new Watch, and a test's cleanup can still come in.
func stableBuilds(t *testing.T, w *Watcher) (builds, namespaces int64) {
	t.Helper()
	require.Eventually(t, func() bool {
		builds, namespaces = w.builds.Load(), w.recomputed.Load()
		time.Sleep(20 * settle)
		return w.builds.Load() == builds
	}, wait, tick)
	return builds, namespaces
}

// A change that can't change any exposure builds nothing: a pod's status, an annotation of a pod, or the conditions
// of an EndpointSlice's endpoints. A change of a pod's labels builds.
func TestAChangeThatCantChangeExposureBuildsNothing(t *testing.T) {
	ns := newNamespace(t, nil).Name
	pod := podOf(ns, web, map[string]string{appLabel: web})
	create(t, pod)
	slice := &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: web + "-x1",
			Labels: map[string]string{discoveryv1.LabelServiceName: web}},
		AddressType: discoveryv1.AddressTypeIPv4,
		Endpoints: []discoveryv1.Endpoint{{
			Addresses:  []string{"192.0.2.10"},
			Conditions: discoveryv1.EndpointConditions{Ready: ptr.To(false)},
			TargetRef:  &corev1.ObjectReference{Kind: kindPod, Namespace: ns, Name: web},
		}},
	}
	create(t, slice)
	w := newWatcher(t)
	watch(t, w, "")
	builds, _ := stableBuilds(t, w)

	pod.Status.Phase = corev1.PodRunning
	c, _ := startAPI(t)
	require.NoError(t, c.Status().Update(t.Context(), pod))
	cached(t, pod)
	pod.Annotations = map[string]string{"example.com/note": "seen"}
	rewrite(t, pod)
	slice.Endpoints[0].Conditions.Ready = ptr.To(true)
	rewrite(t, slice)
	require.Never(t, func() bool { return w.builds.Load() != builds }, quiet, tick, "nothing builds")

	pod.Labels = map[string]string{appLabel: web, tierLabel: frontend}
	rewrite(t, pod)
	require.Eventually(t, func() bool { return w.builds.Load() > builds }, wait, tick, "a label builds")
}

// A change in one namespace computes that namespace again, and no other.
func TestAChangeInOneNamespaceComputesThatNamespaceAlone(t *testing.T) {
	changed, untouched := newNamespace(t, nil).Name, newNamespace(t, nil).Name
	pod := podOf(changed, web, map[string]string{appLabel: web})
	create(t, pod)
	bare(t, untouched, web)
	w := newWatcher(t)
	watch(t, w, "")
	_, before := stableBuilds(t, w)

	pod.Labels = map[string]string{appLabel: web, tierLabel: frontend}
	rewrite(t, pod)

	_, after := stableBuilds(t, w)
	require.Equal(t, int64(1), after-before)
}

// A change of a node's addresses builds, and computes every namespace again: a node port is reached on the addresses
// of every node.
func TestAChangeOfANodesAddressRebuilds(t *testing.T) {
	c, _ := startAPI(t)
	bare(t, newNamespace(t, nil).Name, web)
	bare(t, newNamespace(t, nil).Name, web)
	node := newNode(t, corev1.NodeAddress{Type: corev1.NodeInternalIP, Address: "198.51.100.31"})
	w := newWatcher(t)
	watch(t, w, "")
	builds, before := stableBuilds(t, w)

	node.Status.Addresses = append(node.Status.Addresses,
		corev1.NodeAddress{Type: corev1.NodeExternalIP, Address: "198.51.100.41"})
	rewriteStatus(t, node)

	require.Eventually(t, func() bool { return w.builds.Load() > builds }, wait, tick, "a node's address builds")
	_, after := stableBuilds(t, w)
	var namespaces corev1.NamespaceList
	require.NoError(t, c.List(t.Context(), &namespaces))
	require.GreaterOrEqual(t, after-before, int64(len(namespaces.Items)), "the build computes every namespace")
}

// A change of the addresses in the status of a load balancer builds, as they are where it is reached from outside the
// cluster: a Service's of type LoadBalancer, an Ingress's, and a Gateway's.
func TestAChangeOfALoadBalancersStatusAddressRebuilds(t *testing.T) {
	ns := newNamespace(t, nil).Name
	bare(t, ns, web)
	svc := service(t, ns, web, corev1.ServiceTypeLoadBalancer, web, nil, false)
	ing := ingress(t, ns, web, "", web)
	gw := gateway(t, ns, web, "")
	w := newWatcher(t)
	watch(t, w, "")

	for name, write := range map[string]func(){
		"a Service's": func() {
			svc.Status.LoadBalancer.Ingress = []corev1.LoadBalancerIngress{{IP: "192.0.2.12"}}
			rewriteStatus(t, svc)
		},
		"an Ingress's": func() {
			ing.Status.LoadBalancer.Ingress = []networkingv1.IngressLoadBalancerIngress{{IP: "192.0.2.32"}}
			rewriteStatus(t, ing)
		},
		"a Gateway's": func() {
			require.NoError(t, unstructured.SetNestedSlice(gw.Object, []any{
				map[string]any{"type": "IPAddress", "value": "192.0.2.52"},
			}, "status", "addresses"))
			rewriteStatus(t, gw)
		},
	} {
		builds, _ := stableBuilds(t, w)
		write()
		require.Eventually(t, func() bool { return w.builds.Load() > builds }, wait, tick, "%s address builds", name)
	}
}

// A change of a condition in a status builds nothing: a kubelet and the controllers of Services and Gateways write
// them often, and exposure reads only the addresses of those statuses.
func TestAChangeOfAConditionInAStatusBuildsNothing(t *testing.T) {
	ns := newNamespace(t, nil).Name
	bare(t, ns, web)
	svc := service(t, ns, web, corev1.ServiceTypeLoadBalancer, web, nil, false)
	gw := gateway(t, ns, web, "")
	node := newNode(t, corev1.NodeAddress{Type: corev1.NodeInternalIP, Address: "198.51.100.32"})
	w := newWatcher(t)
	watch(t, w, "")
	builds, _ := stableBuilds(t, w)

	node.Status.Conditions = []corev1.NodeCondition{{Type: corev1.NodeReady, Status: corev1.ConditionTrue}}
	rewriteStatus(t, node)
	svc.Status.Conditions = []metav1.Condition{{Type: "Ready", Status: metav1.ConditionTrue, Reason: "Seen",
		Message: "seen", LastTransitionTime: metav1.Now()}}
	rewriteStatus(t, svc)
	require.NoError(t, unstructured.SetNestedSlice(gw.Object, []any{map[string]any{
		"type": "Accepted", "status": "True", "reason": "Accepted", "message": "accepted",
		"lastTransitionTime": "2026-11-22T00:00:00Z",
	}}, "status", "conditions"))
	rewriteStatus(t, gw)

	require.Never(t, func() bool { return w.builds.Load() != builds }, quiet, tick, "nothing builds")
}

// changedBy reports whether check sees a change between obj and obj as change makes it, both trimmed as the
// informers hold them.
func changedBy[T client.Object](t *testing.T, check func(old, updated any) bool, obj T, change func(T)) bool {
	t.Helper()
	updated, ok := obj.DeepCopyObject().(T)
	require.True(t, ok)
	change(updated)
	before, err := transform(obj)
	require.NoError(t, err)
	after, err := transform(updated)
	require.NoError(t, err)
	return check(before, after)
}

// The informers hold the objects trimmed, and each change check compares what the trims keep for the entry points: a
// change of a node's addresses, of a pod's node or of the protocol of its host port, of a Service's ports or of the
// addresses of its load balancer, of an Ingress's hosts or of its status's addresses, of a Gateway's listeners or of
// its status's addresses, or of a route's hostnames can change exposure. A change of a condition can't.
func TestTheChangeChecksCompareWhatTheTrimsKeep(t *testing.T) {
	node := &corev1.Node{Status: corev1.NodeStatus{Addresses: []corev1.NodeAddress{
		{Type: corev1.NodeInternalIP, Address: "198.51.100.14"},
	}}}
	pod := podOf(teamA, web, map[string]string{appLabel: web})
	withHostPort(pod)
	pod.Spec.NodeName = nodeA
	svc := &corev1.Service{
		Spec: corev1.ServiceSpec{Type: corev1.ServiceTypeLoadBalancer, Ports: []corev1.ServicePort{
			{Port: 443, Protocol: corev1.ProtocolTCP, NodePort: 30443},
		}},
		Status: corev1.ServiceStatus{LoadBalancer: corev1.LoadBalancerStatus{
			Ingress: []corev1.LoadBalancerIngress{{IP: "192.0.2.13"}},
		}},
	}
	ing := &networkingv1.Ingress{
		Spec: networkingv1.IngressSpec{
			Rules: []networkingv1.IngressRule{{Host: "shop.app.example"}},
			TLS:   []networkingv1.IngressTLS{{Hosts: []string{"shop.app.example"}}},
		},
		Status: networkingv1.IngressStatus{LoadBalancer: networkingv1.IngressLoadBalancerStatus{
			Ingress: []networkingv1.IngressLoadBalancerIngress{{IP: "192.0.2.33"}},
		}},
	}
	gw := decode(t, `apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata: {namespace: team-a, name: shared}
spec:
  listeners: [{name: https, hostname: "*.app.example", port: 443, protocol: HTTPS}]
status:
  addresses: [{type: IPAddress, value: 192.0.2.53}]
  conditions: [{type: Programmed, status: "False"}]
`)
	route := decode(t, `apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata: {namespace: team-a, name: api}
spec:
  parentRefs: [{name: shared}]
  hostnames: [api.app.example]
`)
	field := func(u *unstructured.Unstructured, path ...string) map[string]any {
		return sliceOf(u.Object, path...)[0].(map[string]any)
	}

	for name, tc := range map[string]struct{ got, want bool }{
		"a node's address": {changedBy(t, nodeChanged, node, func(n *corev1.Node) {
			n.Status.Addresses[0].Address = "198.51.100.15"
		}), true},
		"a node's condition": {changedBy(t, nodeChanged, node, func(n *corev1.Node) {
			n.Status.Conditions = []corev1.NodeCondition{{Type: corev1.NodeReady, Status: corev1.ConditionTrue}}
		}), false},
		"a pod's node": {changedBy(t, podChanged, pod, func(p *corev1.Pod) { p.Spec.NodeName = nodeB }), true},
		"the protocol of a host port": {changedBy(t, podChanged, pod, func(p *corev1.Pod) {
			p.Spec.Containers[0].Ports[0].Protocol = corev1.ProtocolUDP
		}), true},
		"a Service's port": {changedBy(t, serviceChanged, svc, func(s *corev1.Service) {
			s.Spec.Ports[0].Port = 8443
		}), true},
		"the protocol of a Service's port": {changedBy(t, serviceChanged, svc, func(s *corev1.Service) {
			s.Spec.Ports[0].Protocol = corev1.ProtocolUDP
		}), true},
		"the address of a Service's load balancer": {changedBy(t, serviceChanged, svc, func(s *corev1.Service) {
			s.Status.LoadBalancer.Ingress[0].IP = "192.0.2.14"
		}), true},
		"a Service's condition": {changedBy(t, serviceChanged, svc, func(s *corev1.Service) {
			s.Status.Conditions = []metav1.Condition{{Type: "Healthy", Status: metav1.ConditionTrue}}
		}), false},
		"an Ingress rule's host": {changedBy(t, ingressChanged, ing, func(i *networkingv1.Ingress) {
			i.Spec.Rules[0].Host = "web.app.example"
		}), true},
		"a host of an Ingress's TLS": {changedBy(t, ingressChanged, ing, func(i *networkingv1.Ingress) {
			i.Spec.TLS[0].Hosts = []string{"*.app.example"}
		}), true},
		"an Ingress's status address": {changedBy(t, ingressChanged, ing, func(i *networkingv1.Ingress) {
			i.Status.LoadBalancer.Ingress[0].IP = "192.0.2.34"
		}), true},
		"a listener's hostname": {changedBy(t, trimmedChanged, gw, func(u *unstructured.Unstructured) {
			field(u, "spec", "listeners")["hostname"] = "*.shop.example"
		}), true},
		"a listener's protocol": {changedBy(t, trimmedChanged, gw, func(u *unstructured.Unstructured) {
			field(u, "spec", "listeners")["protocol"] = "TLS"
		}), true},
		"a Gateway's status address": {changedBy(t, trimmedChanged, gw, func(u *unstructured.Unstructured) {
			field(u, "status", "addresses")["value"] = "192.0.2.54"
		}), true},
		"a Gateway's condition": {changedBy(t, trimmedChanged, gw, func(u *unstructured.Unstructured) {
			field(u, "status", "conditions")["status"] = "True"
		}), false},
		"a route's hostnames": {changedBy(t, trimmedChanged, route, func(u *unstructured.Unstructured) {
			require.NoError(t, unstructured.SetNestedStringSlice(u.Object, []string{"web.app.example"},
				"spec", "hostnames"))
		}), true},
	} {
		t.Run(name, func(t *testing.T) { require.Equal(t, tc.want, tc.got) })
	}
}

// The sink's checks hold for the tests too: an event that isn't valid evidence of the exposure type, or whose data
// fails the schema, fails the test that watches.
func TestTheSinkRefusesDataThatFailsTheSchema(t *testing.T) {
	sink := newRecordingSink()
	require.NoError(t, sink.SnapshotStart())
	e, err := evidence.New(evidence.TypeExposure, podSubject("team-a", web),
		json.RawMessage(`{"external": {"exposed": true, "entryPoints": [], "unchecked": ["HostNetwork"]},
			"internalReach": "Everywhere", "indirect": false}`),
		evidence.WithSource("/clusters/"+cluster+"/collectors/network-reach"))
	require.NoError(t, err)

	require.NoError(t, sink.Event(e))

	require.Len(t, sink.problems, 1)
}

// The collector reads an optional kind in the version that its group prefers, and in another version that serves it
// when the preferred one doesn't, as a cluster that serves TLSRoute only in v1alpha2 does. A kind that can't be listed
// and watched isn't served, and neither is one that no version has.
func TestDiscoveryFindsTheVersionThatServesEachKind(t *testing.T) {
	readable := append([]string{"get"}, listAndWatch...)
	apis := &fakediscovery.FakeDiscovery{Fake: &clienttesting.Fake{Resources: []*metav1.APIResourceList{
		{GroupVersion: gatewayGroup + "/v1", APIResources: []metav1.APIResource{
			{Name: gatewaysResource, Kind: kindGateway, Verbs: readable},
			{Name: httpRoutesResource, Kind: kindHTTPRoute, Verbs: readable},
			{Name: grpcRoutesResource, Kind: kindGRPCRoute, Verbs: []string{"get"}},
		}},
		{GroupVersion: gatewayGroup + "/v1alpha2", APIResources: []metav1.APIResource{
			{Name: httpRoutesResource, Kind: kindHTTPRoute, Verbs: readable},
			{Name: tlsRoutesResource, Kind: kindTLSRoute, Verbs: readable},
		}},
	}}}

	served, err := discover(apis)

	require.NoError(t, err)
	in := func(version, kind string) schema.GroupVersionKind {
		return schema.GroupVersionKind{Group: gatewayGroup, Version: version, Kind: kind}
	}
	require.Equal(t, map[schema.GroupKind]schema.GroupVersionKind{
		in("v1", kindGateway).GroupKind():        in("v1", kindGateway),
		in("v1", kindHTTPRoute).GroupKind():      in("v1", kindHTTPRoute),
		in("v1alpha2", kindTLSRoute).GroupKind(): in("v1alpha2", kindTLSRoute),
	}, served)
}

// ciliumCRDs is the directory of the stand-ins for Cilium's CRDs, which testdata/README describes.
var ciliumCRDs = filepath.Join("testdata", "cilium")

// Cilium's two kinds of policy, installed after a Watch started, are watched within the discovery interval, and change
// the reach of the workloads that they select: a namespaced policy, and then a clusterwide one, each in an event.
// Once the CRDs are gone, the Watch stops their informers, and the reach is what the remaining policies give.
func TestCiliumPoliciesInstalledAfterTheStartAreWatchedWithinTheDiscoveryInterval(t *testing.T) {
	own := startOwnAPI(t)
	ns, clients := "team-"+rand.String(6), "team-"+rand.String(6)
	for _, name := range []string{ns, clients} {
		namespace := &metav1.PartialObjectMetadata{}
		namespace.SetGroupVersionKind(corev1.SchemeGroupVersion.WithKind("Namespace"))
		own.createIn(t, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name}}, namespace)
	}
	own.createIn(t, podOf(ns, web, map[string]string{appLabel: web}), &corev1.Pod{})
	spec := ingressFrom(web, networkingv1.NetworkPolicyPeer{PodSelector: &metav1.LabelSelector{}})
	own.createIn(t, &networkingv1.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: web}, Spec: spec},
		&networkingv1.NetworkPolicy{})
	subject := podSubject(ns, web)
	w := NewWatcher(own.informers, own.discovery, Options{
		Name: collectorName, Version: version, Settle: settle, DiscoveryInterval: 100 * time.Millisecond,
	})
	sink := watch(t, w, "")
	require.Equal(t, reachNamespace, sink.inSnapshot(t, subject).InternalReach)

	crds := envtest.CRDInstallOptions{Paths: []string{ciliumCRDs}, ErrorIfPathMissing: true}
	_, err := envtest.InstallCRDs(own.env.Config, crds)
	require.NoError(t, err)
	create := func(manifest string) {
		u := &unstructured.Unstructured{}
		require.NoError(t, yaml.Unmarshal([]byte(manifest), &u.Object))
		require.EventuallyWithT(t, func(c *assert.CollectT) {
			assert.NoError(c, own.client.Create(t.Context(), u.DeepCopy()))
		}, wait, tick, "create %s", u.GetKind())
	}
	create(fmt.Sprintf(`apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata: {namespace: %s, name: clients}
spec:
  endpointSelector:
    matchLabels: {app: web}
  ingress:
  - fromEndpoints:
    - matchLabels:
        "k8s:io.kubernetes.pod.namespace": %s
        app: client
`, ns, clients))
	require.Equal(t, reachPeers, dataOf(t, sink.nextChange(t, subject, 0)).InternalReach)
	create(fmt.Sprintf(`apiVersion: cilium.io/v2
kind: CiliumClusterwideNetworkPolicy
metadata: {name: %s}
spec:
  endpointSelector:
    matchLabels:
      "k8s:io.kubernetes.pod.namespace": %s
      app: web
  ingress:
  - fromEntities: [cluster]
`, "everyone-"+rand.String(6), ns))
	require.Equal(t, reachCluster, dataOf(t, sink.nextChange(t, subject, 1)).InternalReach)

	require.NoError(t, envtest.UninstallCRDs(own.env.Config, crds))

	require.Eventually(t, func() bool {
		changes := sink.changesAbout(subject)
		last := changes[len(changes)-1]
		return last.event != nil && dataOf(t, last).InternalReach == reachNamespace
	}, wait, tick, "the reach that the NetworkPolicy gives")
	for _, kind := range []string{"CiliumNetworkPolicyList", "CiliumClusterwideNetworkPolicyList"} {
		list := &unstructured.UnstructuredList{}
		list.SetGroupVersionKind(schema.GroupVersionKind{Group: ciliumGroup, Version: "v2", Kind: kind})
		require.Eventually(t, func() bool {
			var notCached *cache.ErrResourceNotCached
			return errors.As(own.informers.List(t.Context(), list), &notCached)
		}, wait, tick, "the Watch stops its informer of %s", kind)
	}
}

// policyEngineCRDs is the directory of the stand-ins for the CRDs of the kinds of policy that the collector doesn't
// read, which testdata/README describes.
var policyEngineCRDs = filepath.Join("testdata", "policy-engines")

// The collector reads neither SIG Network's AdminNetworkPolicy and ClusterNetworkPolicy nor Calico's policies, whose
// rules can let in what the network policies deny. Once the cluster serves them, every workload's unseen names them
// within the discovery interval, and its reach stays what the policies that the collector reads give: what it can't
// see narrows nothing. Once they are gone, unseen names them no more. SIG Network's ClusterNetworkPolicy replaces its
// AdminNetworkPolicy, and Calico serves its policies in crd.projectcalico.org where its API server serves
// projectcalico.org, and in projectcalico.org itself where it runs without that server: each pair counts the same.
func TestPolicyKindsThatTheCollectorDoesntReadAreUnseen(t *testing.T) {
	own := startOwnAPI(t)
	ns := "team-" + rand.String(6)
	namespace := &metav1.PartialObjectMetadata{}
	namespace.SetGroupVersionKind(corev1.SchemeGroupVersion.WithKind("Namespace"))
	own.createIn(t, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns}}, namespace)
	own.createIn(t, podOf(ns, web, map[string]string{appLabel: web}), &corev1.Pod{})
	own.createIn(t, podOf(ns, backend, map[string]string{appLabel: backend}), &corev1.Pod{})
	spec := ingressFrom(backend, networkingv1.NetworkPolicyPeer{PodSelector: &metav1.LabelSelector{}})
	own.createIn(t, &networkingv1.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: backend}, Spec: spec},
		&networkingv1.NetworkPolicy{})
	open, closed := podSubject(ns, web), podSubject(ns, backend)
	w := NewWatcher(own.informers, own.discovery, Options{
		Name: collectorName, Version: version, Settle: settle, DiscoveryInterval: 100 * time.Millisecond,
	})
	sink := watch(t, w, "")
	require.Empty(t, sink.inSnapshot(t, open).Unseen)
	require.Empty(t, sink.inSnapshot(t, closed).Unseen)
	// last returns the exposure that the last change about the workload of the subject says.
	last := func(subject string) evidence.Exposure {
		changes := sink.changesAbout(subject)
		if len(changes) == 0 || changes[len(changes)-1].event == nil {
			return evidence.Exposure{}
		}
		return dataOf(t, changes[len(changes)-1])
	}

	unseen := []string{evidence.UnseenAdminNetworkPolicy, evidence.UnseenCalicoNetworkPolicy}
	for _, files := range [][]string{
		{"policy.networking.k8s.io_adminnetworkpolicies.yaml", "crd.projectcalico.org_networkpolicies.yaml"},
		{"policy.networking.k8s.io_clusternetworkpolicies.yaml", "projectcalico.org_networkpolicies.yaml"},
	} {
		var paths []string
		for _, file := range files {
			paths = append(paths, filepath.Join(policyEngineCRDs, file))
		}
		crds := envtest.CRDInstallOptions{Paths: paths, ErrorIfPathMissing: true}
		_, err := envtest.InstallCRDs(own.env.Config, crds)
		require.NoError(t, err)

		require.Eventually(t, func() bool {
			return slices.Equal(last(open).Unseen, unseen) && slices.Equal(last(closed).Unseen, unseen)
		}, wait, tick, "unseen names both kinds of %v", files)
		require.Equal(t, reachCluster, last(open).InternalReach)
		require.Equal(t, reachNamespace, last(closed).InternalReach)

		require.NoError(t, envtest.UninstallCRDs(own.env.Config, crds))
		require.Eventually(t, func() bool {
			return len(last(open).Unseen) == 0 && len(last(closed).Unseen) == 0
		}, wait, tick, "unseen names neither kind of %v", files)
	}
}

// The API discovery can't read the resources of an aggregated API while its server is down, as it can't read Calico's
// projectcalico.org while Calico's API server is down. A kind of such a group that the collector doesn't read counts
// as served then, since the group is there, and the Watch goes on: what the collector doesn't read narrows nothing.
func TestAKindThatTheCollectorDoesntReadCountsAsServedWhenItsGroupCantBeDiscovered(t *testing.T) {
	apis := failingDiscovery{failing: "projectcalico.org/v3", FakeDiscovery: &fakediscovery.FakeDiscovery{
		Fake: &clienttesting.Fake{Resources: []*metav1.APIResourceList{
			{GroupVersion: gatewayGroup + "/v1", APIResources: []metav1.APIResource{
				{Name: gatewaysResource, Kind: kindGateway, Verbs: listAndWatch},
			}},
			{GroupVersion: "projectcalico.org/v3"},
		}},
	}}

	served, err := discover(apis)

	require.NoError(t, err)
	require.Equal(t, []string{evidence.UnseenCalicoNetworkPolicy}, unreadServed(served))
	require.Contains(t, served, schema.GroupKind{Group: gatewayGroup, Kind: kindGateway})
}

// failingDiscovery is an API discovery that can't read the resources of one group version, as that of an aggregated
// API whose server is down.
type failingDiscovery struct {
	*fakediscovery.FakeDiscovery
	failing string
}

func (d failingDiscovery) ServerResourcesForGroupVersion(groupVersion string) (*metav1.APIResourceList, error) {
	if groupVersion == d.failing {
		return nil, errors.New("the server is currently unable to handle the request")
	}
	return d.FakeDiscovery.ServerResourcesForGroupVersion(groupVersion)
}
