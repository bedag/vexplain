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
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/rand"
	"k8s.io/utils/ptr"

	"github.com/bedag/vexplain/sdk/evidence"
)

// notExposed is what an event says of a workload that nothing outside the cluster reaches.
var notExposed = evidence.ExternalExposure{}

const (
	// schemeAnnotation is the annotation that the tests' settings name as the one that makes a load balancer
	// internal, with internalScheme as its value, and internalLB the settings that say so.
	schemeAnnotation = "lb.artifacts.example/scheme"
	internalScheme   = "internal"
	internalLB       = `{"internalLoadBalancerAnnotations": [{"key": "` + schemeAnnotation + `", "value": "` +
		internalScheme + `"}]}`
	// counted and other name the objects that the settings count, and the others.
	counted, other = "counted", "other"
)

// A Service of type LoadBalancer exposes the workload whose pods it selects, and the event names the Service. The
// workload is the pods' top-level owner: a pod of a ReplicaSet of a Deployment is the Deployment's.
func TestALoadBalancerServiceExposesItsWorkloadViaTheService(t *testing.T) {
	ns := newNamespace(t, nil).Name
	subject := deployment(t, ns, web)
	service(t, ns, web, corev1.ServiceTypeLoadBalancer, web, nil, false)

	sink := watch(t, newWatcher(t), "")

	require.Equal(t, evidence.ExternalExposure{Exposed: true, Via: []evidence.ObjectRef{serviceRef(ns, web)}},
		sink.inSnapshot(t, subject).External)
}

// A LoadBalancer Service with an annotation that the settings name as internal exposes nothing, while one without it
// does.
func TestALoadBalancerWithAnInternalAnnotationExposesNothing(t *testing.T) {
	ns := newNamespace(t, nil).Name
	internal, public := bare(t, ns, "internal"), bare(t, ns, "public")
	service(t, ns, "internal", corev1.ServiceTypeLoadBalancer, "internal",
		map[string]string{schemeAnnotation: internalScheme}, false)
	service(t, ns, "public", corev1.ServiceTypeLoadBalancer, "public",
		map[string]string{schemeAnnotation: "public"}, false)

	sink := watch(t, newWatcher(t),
		internalLB)

	require.Equal(t, notExposed, sink.inSnapshot(t, internal).External)
	require.Equal(t, evidence.ExternalExposure{Exposed: true, Via: []evidence.ObjectRef{serviceRef(ns, "public")}},
		sink.inSnapshot(t, public).External)
}

// An internal load balancer that has node ports is reachable through them, from outside the cluster unless the node
// ports are internal.
func TestAnInternalLoadBalancerWithNodePortsIsExposedThroughThem(t *testing.T) {
	ns := newNamespace(t, nil).Name
	subject := bare(t, ns, web)
	service(t, ns, web, corev1.ServiceTypeLoadBalancer, web, map[string]string{schemeAnnotation: internalScheme},
		true)

	external := watch(t, newWatcher(t), internalLB).inSnapshot(t, subject).External
	internal := watch(t, newWatcher(t), strings.Replace(internalLB, "}]", `}], "nodePorts": "Internal"`, 1)).
		inSnapshot(t, subject).External

	require.Equal(t, evidence.ExternalExposure{Exposed: true, Via: []evidence.ObjectRef{serviceRef(ns, web)}}, external)
	require.Equal(t, notExposed, internal)
}

// A NodePort Service exposes the workload whose pods it selects, unless the settings say that the node ports are
// internal.
func TestANodePortServiceExposesItsWorkloadUnlessNodePortsAreInternal(t *testing.T) {
	ns := newNamespace(t, nil).Name
	subject := bare(t, ns, web)
	service(t, ns, web, corev1.ServiceTypeNodePort, web, nil, true)

	byDefault := watch(t, newWatcher(t), "").inSnapshot(t, subject).External
	internal := watch(t, newWatcher(t), `{"nodePorts": "Internal"}`).inSnapshot(t, subject).External

	require.Equal(t, evidence.ExternalExposure{Exposed: true, Via: []evidence.ObjectRef{serviceRef(ns, web)}}, byDefault)
	require.Equal(t, notExposed, internal)
}

// An Ingress of a class that the settings count exposes the workload behind the Service that it routes to, and the
// event names the Ingress. An Ingress of another class exposes nothing.
func TestAnIngressOfACountedClassExposesItsBackendAndOneOfAnotherClassDoesNot(t *testing.T) {
	ns := newNamespace(t, nil).Name
	countedSubject, otherSubject := bare(t, ns, counted), bare(t, ns, other)
	for _, name := range []string{counted, other} {
		service(t, ns, name, corev1.ServiceTypeClusterIP, name, nil, false)
	}
	ingress(t, ns, counted, "public", counted)
	ingress(t, ns, other, "private", other)

	sink := watch(t, newWatcher(t), `{"ingressClasses": ["public"]}`)

	require.Equal(t, evidence.ExternalExposure{Exposed: true, Via: []evidence.ObjectRef{{
		APIGroup: "networking.k8s.io", Kind: "Ingress", Namespace: ns, Name: counted,
	}}}, sink.inSnapshot(t, countedSubject).External)
	require.Equal(t, notExposed, sink.inSnapshot(t, otherSubject).External)
}

// An Ingress without a class counts whatever the settings' classes, and whatever the cluster's default IngressClass:
// Kubernetes gives the default class only to an Ingress that it creates without one, so an Ingress without a class
// never had it, and whether a controller serves Ingresses without a class is that controller's own setting.
func TestAnIngressWithoutAClassCountsWhateverTheDefaultClass(t *testing.T) {
	ns := newNamespace(t, nil).Name
	subject := bare(t, ns, web)
	service(t, ns, web, corev1.ServiceTypeClusterIP, web, nil, false)
	// The Ingress comes before the default class, as one from before the cluster had it: Kubernetes gives an Ingress
	// that it creates without a class the default class.
	ingress(t, ns, web, "", web)
	class := "default-" + rand.String(6)
	other := fmt.Sprintf(`{"ingressClasses": ["%s"]}`, "other-"+rand.String(6))

	withoutDefault := watch(t, newWatcher(t), other).inSnapshot(t, subject).External.Exposed
	create(t, &networkingv1.IngressClass{
		ObjectMeta: metav1.ObjectMeta{Name: class, Annotations: map[string]string{
			networkingv1.AnnotationIsDefaultIngressClass: "true",
		}},
		Spec: networkingv1.IngressClassSpec{Controller: "artifacts.example/ingress"},
	})
	defaultCounted := watch(t, newWatcher(t), fmt.Sprintf(`{"ingressClasses": ["%s"]}`, class)).
		inSnapshot(t, subject).External.Exposed
	defaultNotCounted := watch(t, newWatcher(t), other).inSnapshot(t, subject).External.Exposed

	require.True(t, withoutDefault, "without a default class")
	require.True(t, defaultCounted, "under a default class that counts")
	require.True(t, defaultNotCounted, "under a default class that doesn't count")
}

// An HTTPRoute attached to a Gateway that the settings count exposes the workload behind the Service that it routes
// to, and the event names the route. A route on another Gateway exposes nothing.
func TestAnHTTPRouteOnACountedGatewayExposesItsBackend(t *testing.T) {
	ns := newNamespace(t, nil).Name
	countedSubject, otherSubject := bare(t, ns, counted), bare(t, ns, other)
	for _, name := range []string{counted, other} {
		service(t, ns, name, corev1.ServiceTypeClusterIP, name, nil, false)
		gateway(t, ns, name, "")
		httpRoute(t, ns, name, ns, name, name)
	}

	sink := watch(t, newWatcher(t), fmt.Sprintf(`{"gateways": [{"namespace": "%s", "name": "%s"}]}`, ns, counted))

	require.Equal(t, evidence.ExternalExposure{Exposed: true, Via: []evidence.ObjectRef{routeRef(ns, counted)}},
		sink.inSnapshot(t, countedSubject).External)
	require.Equal(t, notExposed, sink.inSnapshot(t, otherSubject).External)
}

// A route attaches to a Gateway in another namespace only where a listener of the Gateway allows routes from the
// route's namespace, as the Gateway API's allowedRoutes say: from the same namespace by default, from all of them, or
// from the namespaces that a selector selects.
func TestARouteFromAnotherNamespaceAttachesOnlyWhereTheGatewayAllowsIt(t *testing.T) {
	gateways := newNamespace(t, nil).Name
	ns := newNamespace(t, map[string]string{"gateway-access": "granted"}).Name
	const bySelector = "      namespaces:\n        from: Selector\n        selector:\n          matchLabels:\n"
	allowed := map[string]string{
		"same":       "",
		"all":        "      namespaces:\n        from: All\n",
		"selected":   bySelector + "            gateway-access: granted\n",
		"unselected": bySelector + "            gateway-access: other\n",
	}
	for name, routes := range allowed {
		gateway(t, gateways, name, routes)
		bare(t, ns, name)
		service(t, ns, name, corev1.ServiceTypeClusterIP, name, nil, false)
		httpRoute(t, ns, name, gateways, name, name)
	}

	sink := watch(t, newWatcher(t), "")

	for name, want := range map[string]bool{"same": false, "all": true, "selected": true, "unselected": false} {
		require.Equal(t, want, sink.inSnapshot(t, podSubject(ns, name)).External.Exposed, "the route on %s", name)
	}
}

// An event names at most eight objects that expose a workload, as the schema allows: the first eight, by kind,
// namespace and name.
func TestViaNamesAtMostEightObjects(t *testing.T) {
	ns := newNamespace(t, nil).Name
	subject := bare(t, ns, web)
	for i := 1; i <= 9; i++ {
		service(t, ns, fmt.Sprintf("web-%d", i), corev1.ServiceTypeLoadBalancer, web, nil, false)
	}

	sink := watch(t, newWatcher(t), "")

	var want []evidence.ObjectRef
	for i := 1; i <= 8; i++ {
		want = append(want, serviceRef(ns, fmt.Sprintf("web-%d", i)))
	}
	require.Equal(t, evidence.ExternalExposure{Exposed: true, Via: want}, sink.inSnapshot(t, subject).External)
}

// A Service without a selector exposes the pods that its EndpointSlices name, as Kubernetes routes its traffic to
// them, and no other pod.
func TestAServiceWithoutASelectorExposesThePodsThatItsEndpointSlicesName(t *testing.T) {
	ns := newNamespace(t, nil).Name
	named, unnamed := bare(t, ns, "named"), bare(t, ns, "unnamed")
	create(t, &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "manual"},
		Spec: corev1.ServiceSpec{Type: corev1.ServiceTypeLoadBalancer, AllocateLoadBalancerNodePorts: ptr.To(false),
			Ports: []corev1.ServicePort{{Name: portName, Port: 80}}},
	})
	create(t, &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "manual-x1",
			Labels: map[string]string{discoveryv1.LabelServiceName: "manual"}},
		AddressType: discoveryv1.AddressTypeIPv4,
		Endpoints: []discoveryv1.Endpoint{{
			Addresses: []string{"192.0.2.20"},
			TargetRef: &corev1.ObjectReference{Kind: kindPod, Namespace: ns, Name: "named"},
		}},
	})

	sink := watch(t, newWatcher(t), "")

	require.Equal(t, evidence.ExternalExposure{Exposed: true, Via: []evidence.ObjectRef{serviceRef(ns, "manual")}},
		sink.inSnapshot(t, named).External)
	require.Equal(t, notExposed, sink.inSnapshot(t, unnamed).External)
}

// A route sends the outside's requests to the Services of its backendRefs, in other namespaces too, and to those that
// a filter mirrors the requests to: each of them is exposed by the route.
func TestARouteExposesItsBackendsInOtherNamespacesAndTheOnesItMirrorsTo(t *testing.T) {
	ns, elsewhere := newNamespace(t, nil).Name, newNamespace(t, nil).Name
	api, shadow := bare(t, elsewhere, "api"), bare(t, ns, "shadow")
	service(t, elsewhere, "api", corev1.ServiceTypeClusterIP, "api", nil, false)
	service(t, ns, "shadow", corev1.ServiceTypeClusterIP, "shadow", nil, false)
	gateway(t, ns, web, "")
	fromYAML(t, fmt.Sprintf(`apiVersion: %s
kind: HTTPRoute
metadata:
  namespace: %s
  name: %s
spec:
  parentRefs:
  - name: %s
  rules:
  - backendRefs:
    - name: api
      namespace: %s
      port: 80
    filters:
    - type: RequestMirror
      requestMirror:
        backendRef:
          name: shadow
          port: 80
`, gatewayAPIVersion, ns, web, web, elsewhere))

	sink := watch(t, newWatcher(t), "")

	for _, subject := range []string{api, shadow} {
		require.Equal(t, evidence.ExternalExposure{Exposed: true, Via: []evidence.ObjectRef{routeRef(ns, web)}},
			sink.inSnapshot(t, subject).External, subject)
	}
}

// A GRPCRoute and a TLSRoute expose their backends as an HTTPRoute does.
func TestAGRPCRouteAndATLSRouteExposeTheirBackends(t *testing.T) {
	ns := newNamespace(t, nil).Name
	grpc, tls := bare(t, ns, "grpc"), bare(t, ns, "tls")
	for _, name := range []string{"grpc", "tls"} {
		service(t, ns, name, corev1.ServiceTypeClusterIP, name, nil, false)
	}
	gateway(t, ns, web, "")
	for _, manifest := range []string{
		"kind: GRPCRoute\nmetadata: {namespace: %[2]s, name: grpc}\nspec:\n  parentRefs: [{name: %[3]s}]\n" +
			"  rules: [{backendRefs: [{name: grpc, port: 80}]}]\n",
		"kind: TLSRoute\nmetadata: {namespace: %[2]s, name: tls}\nspec:\n  parentRefs: [{name: %[3]s}]\n" +
			"  hostnames: [tls.artifacts.example]\n  rules: [{backendRefs: [{name: tls, port: 80}]}]\n",
	} {
		fromYAML(t, fmt.Sprintf("apiVersion: %[1]s\n"+manifest, gatewayAPIVersion, ns, web))
	}

	sink := watch(t, newWatcher(t), "")

	require.Equal(t, evidence.ExternalExposure{Exposed: true, Via: []evidence.ObjectRef{
		{APIGroup: gatewayGroup, Kind: kindGRPCRoute, Namespace: ns, Name: "grpc"},
	}}, sink.inSnapshot(t, grpc).External)
	require.Equal(t, evidence.ExternalExposure{Exposed: true, Via: []evidence.ObjectRef{
		{APIGroup: gatewayGroup, Kind: kindTLSRoute, Namespace: ns, Name: "tls"},
	}}, sink.inSnapshot(t, tls).External)
}

// A route attaches only through the listeners that its parentRef names, by section name, and only to a listener that
// allows its kind. A route whose parent is a Service belongs to a mesh, inside the cluster, and exposes nothing. A
// route whose parent is of a kind that the collector doesn't read, such as a ListenerSet, may attach to any Gateway,
// and counts.
func TestWhereARouteAttaches(t *testing.T) {
	gateways := newNamespace(t, nil).Name
	ns := newNamespace(t, nil).Name
	fromYAML(t, fmt.Sprintf(`apiVersion: %s
kind: Gateway
metadata:
  namespace: %s
  name: shared
spec:
  gatewayClassName: example
  listeners:
  - name: open
    port: 80
    protocol: HTTP
    allowedRoutes:
      namespaces:
        from: All
  - name: closed
    port: 8080
    protocol: HTTP
  - name: grpc-only
    port: 9090
    protocol: HTTP
    allowedRoutes:
      namespaces:
        from: All
      kinds:
      - kind: GRPCRoute
`, gatewayAPIVersion, gateways))
	parents := map[string]string{
		"open":     fmt.Sprintf("{name: shared, namespace: %s, sectionName: open}", gateways),
		"closed":   fmt.Sprintf("{name: shared, namespace: %s, sectionName: closed}", gateways),
		"by-port":  fmt.Sprintf("{name: shared, namespace: %s, port: 80}", gateways),
		"by-kind":  fmt.Sprintf("{name: shared, namespace: %s, sectionName: grpc-only}", gateways),
		"mesh":     "{group: \"\", kind: Service, name: mesh}",
		"listener": "{kind: ListenerSet, name: shared-extra}",
	}
	for name, parent := range parents {
		bare(t, ns, name)
		service(t, ns, name, corev1.ServiceTypeClusterIP, name, nil, false)
		fromYAML(t, fmt.Sprintf("apiVersion: %s\nkind: HTTPRoute\nmetadata: {namespace: %s, name: %s}\nspec:\n"+
			"  parentRefs: [%s]\n  rules: [{backendRefs: [{name: %s, port: 80}]}]\n",
			gatewayAPIVersion, ns, name, parent, name))
	}

	sink := watch(t, newWatcher(t), "")

	for name, want := range map[string]bool{
		"open": true, "closed": false, "by-port": true, "by-kind": false, "mesh": false, "listener": true,
	} {
		require.Equal(t, want, sink.inSnapshot(t, podSubject(ns, name)).External.Exposed, "the route %s", name)
	}
}

// The annotation kubernetes.io/ingress.class names the class of an Ingress that has no ingressClassName, as Ingress
// controllers still honour it.
func TestTheAnnotationOfAnIngressNamesItsClass(t *testing.T) {
	ns := newNamespace(t, nil).Name
	countedSubject, otherSubject := bare(t, ns, counted), bare(t, ns, other)
	for name, class := range map[string]string{counted: "public", other: "private"} {
		service(t, ns, name, corev1.ServiceTypeClusterIP, name, nil, false)
		create(t, &networkingv1.Ingress{
			ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name,
				Annotations: map[string]string{"kubernetes.io/ingress.class": class}},
			Spec: networkingv1.IngressSpec{DefaultBackend: &networkingv1.IngressBackend{
				Service: &networkingv1.IngressServiceBackend{Name: name, Port: networkingv1.ServiceBackendPort{Number: 80}},
			}},
		})
	}

	sink := watch(t, newWatcher(t), `{"ingressClasses": ["public"]}`)

	require.True(t, sink.inSnapshot(t, countedSubject).External.Exposed)
	require.False(t, sink.inSnapshot(t, otherSubject).External.Exposed)
}

// A pod with a host port is reached on its node's address, as a node port is: it exposes its workload unless the
// settings say that the host ports are internal.
func TestAHostPortExposesItsWorkloadUnlessHostPortsAreInternal(t *testing.T) {
	ns := newNamespace(t, nil).Name
	pod := podOf(ns, web, map[string]string{appLabel: web})
	withHostPort(pod)
	create(t, pod)
	subject := podSubject(ns, web)

	byDefault := watch(t, newWatcher(t), "").inSnapshot(t, subject).External
	internal := watch(t, newWatcher(t), `{"hostPorts": "Internal"}`).inSnapshot(t, subject).External

	require.Equal(t, evidence.ExternalExposure{Exposed: true, Via: []evidence.ObjectRef{
		{APIGroup: "", Kind: "Pod", Namespace: ns, Name: web},
	}}, byDefault)
	require.Equal(t, notExposed, internal)
}

// A pod on its node's network is reached on its node's address too, whatever ports it declares: it exposes its
// workload unless the settings say that the host network is internal.
func TestAPodOnItsNodesNetworkExposesItsWorkloadUnlessTheHostNetworkIsInternal(t *testing.T) {
	ns := newNamespace(t, nil).Name
	pod := podOf(ns, web, map[string]string{appLabel: web})
	pod.Spec.HostNetwork = true
	create(t, pod)
	subject := podSubject(ns, web)

	byDefault := watch(t, newWatcher(t), "").inSnapshot(t, subject).External
	internal := watch(t, newWatcher(t), `{"hostNetwork": "Internal"}`).inSnapshot(t, subject).External

	require.Equal(t, evidence.ExternalExposure{Exposed: true, Via: []evidence.ObjectRef{
		{APIGroup: "", Kind: "Pod", Namespace: ns, Name: web},
	}}, byDefault)
	require.Equal(t, notExposed, internal)
}

// Each of the settings hostNetwork, hostPorts and nodePorts makes its own way to be reached on a node's address
// internal, and no other: a pod on its node's network, whose ports are host ports too, a pod with a host port, and
// the node ports of a Service. A pod on its node's network that faces no outside is still reached from the whole
// cluster: no policy applies to it.
func TestTheHostSettingsEachActAlone(t *testing.T) {
	ns := newNamespace(t, nil).Name
	onNode := podOf(ns, "host-network", map[string]string{appLabel: "host-network"})
	onNode.Spec.HostNetwork = true
	onNode.Spec.Containers[0].Ports = []corev1.ContainerPort{{ContainerPort: 9100, HostPort: 9100}}
	create(t, onNode)
	withPort := podOf(ns, "host-port", map[string]string{appLabel: "host-port"})
	withHostPort(withPort)
	create(t, withPort)
	nodePort := bare(t, ns, "node-port")
	service(t, ns, "node-port", corev1.ServiceTypeNodePort, "node-port", nil, true)
	subjects := map[string]string{
		"hostNetwork": podSubject(ns, "host-network"), "hostPorts": podSubject(ns, "host-port"), "nodePorts": nodePort,
	}

	for setting := range subjects {
		t.Run(setting+" Internal", func(t *testing.T) {
			sink := watch(t, newWatcher(t), fmt.Sprintf(`{%q: "Internal"}`, setting))

			for exposing, subject := range subjects {
				require.Equal(t, exposing != setting, sink.inSnapshot(t, subject).External.Exposed, exposing)
			}
			require.Equal(t, reachCluster, sink.inSnapshot(t, subjects["hostNetwork"]).InternalReach)
		})
	}
}

// What exposes a workload through a host port is the workload itself: the event names its own object, its top-level
// owner, whose name stays as its pods come and go.
func TestViaOfAHostPortNamesTheWorkloadsOwnObject(t *testing.T) {
	ns := newNamespace(t, nil).Name
	subject := deploymentOf(t, ns, web, withHostPort)

	sink := watch(t, newWatcher(t), "")

	require.Equal(t, evidence.ExternalExposure{Exposed: true, Via: []evidence.ObjectRef{
		{APIGroup: "apps", Kind: "Deployment", Namespace: ns, Name: web},
	}}, sink.inSnapshot(t, subject).External)
}

// A Service with external IPs is reached on them, whatever its type, and exposes the pods that it backs. No setting
// makes them internal.
func TestAServiceWithExternalIPsExposesThePodsThatItBacks(t *testing.T) {
	ns := newNamespace(t, nil).Name
	subject := bare(t, ns, web)
	create(t, &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: web},
		Spec: corev1.ServiceSpec{
			Type: corev1.ServiceTypeClusterIP, Selector: map[string]string{appLabel: web},
			Ports: []corev1.ServicePort{{Name: portName, Port: 80}}, ExternalIPs: []string{"192.0.2.40"},
		},
	})

	sink := watch(t, newWatcher(t), `{"nodePorts": "Internal"}`)

	require.Equal(t, evidence.ExternalExposure{Exposed: true, Via: []evidence.ObjectRef{serviceRef(ns, web)}},
		sink.inSnapshot(t, subject).External)
}

// A LoadBalancer that an annotation of the settings makes internal is reached on its external IPs all the same.
func TestAnInternalLoadBalancerWithExternalIPsIsExposedThroughThem(t *testing.T) {
	ns := newNamespace(t, nil).Name
	subject := bare(t, ns, web)
	create(t, &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: ns, Name: web, Annotations: map[string]string{schemeAnnotation: internalScheme},
		},
		Spec: corev1.ServiceSpec{
			Type: corev1.ServiceTypeLoadBalancer, AllocateLoadBalancerNodePorts: ptr.To(false),
			Selector: map[string]string{appLabel: web}, Ports: []corev1.ServicePort{{Name: portName, Port: 80}},
			ExternalIPs: []string{"192.0.2.41"},
		},
	})

	sink := watch(t, newWatcher(t),
		internalLB)

	require.Equal(t, evidence.ExternalExposure{Exposed: true, Via: []evidence.ObjectRef{serviceRef(ns, web)}},
		sink.inSnapshot(t, subject).External)
}
