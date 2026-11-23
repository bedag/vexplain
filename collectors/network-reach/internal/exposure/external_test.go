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
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/util/rand"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/yaml"

	"github.com/bedag/vexplain/sdk/evidence"
)

// notExposed is what an event says of a workload that nothing outside the cluster reaches. Its lists are empty, not
// left out, as every event writes them.
var notExposed = evidence.ExternalExposure{EntryPoints: []evidence.EntryPoint{}, Unchecked: []string{}}

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

// A Service of type LoadBalancer exposes the workload whose pods it selects: the pods' top-level owner, so a pod of a
// ReplicaSet of a Deployment is the Deployment's. Each port of the Service is an entry point through it, on the
// addresses of its load balancer's status. Until the status has an address, the Service exposes the workload all the
// same, and no entry point says where: NoAddress.
func TestALoadBalancerServiceNamesEachPortWithItsStatusAddresses(t *testing.T) {
	const address = "192.0.2.10"
	ns := newNamespace(t, nil).Name
	subject := deployment(t, ns, web)
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: web},
		Spec: corev1.ServiceSpec{
			Type: corev1.ServiceTypeLoadBalancer, AllocateLoadBalancerNodePorts: ptr.To(false),
			Selector: map[string]string{appLabel: web},
			Ports:    []corev1.ServicePort{{Name: portName, Port: 80}, {Name: securePortName, Port: 443}},
		},
	}
	create(t, svc)
	sink := watch(t, newWatcher(t), "")
	require.Equal(t, exposedUnchecked(evidence.UncheckedNoAddress), sink.inSnapshot(t, subject).External)

	svc.Status.LoadBalancer.Ingress = []corev1.LoadBalancerIngress{{IP: address}}
	rewriteStatus(t, svc)

	ref := serviceRef(ns, web)
	require.Equal(t, exposedThrough(
		evidence.EntryPoint{Addresses: []string{address}, Port: ptr.To[int32](80), Protocol: tcp,
			ObjectRef: ref, Subjects: []string{"address/192.0.2.10:80"}},
		evidence.EntryPoint{Addresses: []string{address}, Port: ptr.To[int32](443), Protocol: tcp,
			ObjectRef: ref, Subjects: []string{"address/192.0.2.10:443"}},
	), dataOf(t, sink.nextChange(t, subject, 0)).External)
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
	require.Equal(t, exposedUnchecked(evidence.UncheckedNoAddress), sink.inSnapshot(t, public).External)
}

// An internal load balancer that has node ports is reachable through them, from outside the cluster unless the node
// ports are internal: the node ports are its entry points, and its load balancer's status is none.
func TestAnInternalLoadBalancerWithNodePortsIsExposedThroughThem(t *testing.T) {
	ns := newNamespace(t, nil).Name
	subject := bare(t, ns, web)
	svc := service(t, ns, web, corev1.ServiceTypeLoadBalancer, web,
		map[string]string{schemeAnnotation: internalScheme}, true)

	external := watch(t, newWatcher(t), internalLB).inSnapshot(t, subject).External
	internal := watch(t, newWatcher(t), strings.Replace(internalLB, "}]", `}], "nodePorts": "Internal"`, 1)).
		inSnapshot(t, subject).External

	require.Equal(t, exposedThrough(entryPoint(serviceRef(ns, web), svc.Spec.Ports[0].NodePort, tcp,
		nodeAddresses()...)), external)
	require.Equal(t, notExposed, internal)
}

// A node port is reached on every node: its entry point names the InternalIP and ExternalIP addresses of all the
// nodes, sorted, with the node port and its protocol. Node ports that the settings say are internal expose nothing.
func TestANodePortNamesEveryNodesAddresses(t *testing.T) {
	ns := newNamespace(t, nil).Name
	subject := bare(t, ns, web)
	svc := service(t, ns, web, corev1.ServiceTypeNodePort, web, nil, true)

	byDefault := watch(t, newWatcher(t), "").inSnapshot(t, subject).External
	internal := watch(t, newWatcher(t), `{"nodePorts": "Internal"}`).inSnapshot(t, subject).External

	require.Equal(t, []string{"198.51.100.11", "198.51.100.12", "198.51.100.21", "198.51.100.22"}, nodeAddresses())
	require.Equal(t, exposedThrough(entryPoint(serviceRef(ns, web), svc.Spec.Ports[0].NodePort, tcp,
		nodeAddresses()...)), byDefault)
	require.Equal(t, notExposed, internal)
}

// A node that joins the cluster adds its addresses to the entry point of every node port, and one that leaves takes
// them away again: each is a change of the workloads behind node ports.
func TestANodeThatJoinsRewritesTheNodePortsEntryPoints(t *testing.T) {
	ns := newNamespace(t, nil).Name
	subject := bare(t, ns, web)
	svc := service(t, ns, web, corev1.ServiceTypeNodePort, web, nil, true)
	ref, port := serviceRef(ns, web), svc.Spec.Ports[0].NodePort
	fixed := exposedThrough(entryPoint(ref, port, tcp, nodeAddresses()...))
	sink := watch(t, newWatcher(t), "")
	require.Equal(t, fixed, sink.inSnapshot(t, subject).External)
	// last returns what the last change about the workload says of its external exposure.
	last := func() evidence.ExternalExposure {
		changes := sink.changesAbout(subject)
		if len(changes) == 0 || changes[len(changes)-1].event == nil {
			return evidence.ExternalExposure{}
		}
		return dataOf(t, changes[len(changes)-1]).External
	}

	node := newNode(t, corev1.NodeAddress{Type: corev1.NodeInternalIP, Address: "198.51.100.16"},
		corev1.NodeAddress{Type: corev1.NodeExternalIP, Address: "198.51.100.26"})

	joined := exposedThrough(entryPoint(ref, port, tcp, "198.51.100.11", "198.51.100.12", "198.51.100.16",
		"198.51.100.21", "198.51.100.22", "198.51.100.26"))
	require.EventuallyWithT(t, func(c *assert.CollectT) { assert.Equal(c, joined, last()) }, wait, tick,
		"the entry point names the node that joined")

	remove(t, node)

	require.EventuallyWithT(t, func(c *assert.CollectT) { assert.Equal(c, fixed, last()) }, wait, tick,
		"the entry point no longer names the node that left")
}

// A node without an InternalIP or ExternalIP address, such as one that its cloud controller hasn't initialised yet,
// serves node ports all the same: their entry points keep the other nodes' addresses, and NoAddress says that a node
// is missing. Once the node has an address, the entry points name it, and NoAddress goes.
func TestANodeWithoutAnAddressAddsNoAddressToNodePorts(t *testing.T) {
	ns := newNamespace(t, nil).Name
	subject := bare(t, ns, web)
	svc := service(t, ns, web, corev1.ServiceTypeNodePort, web, nil, true)
	ref, port := serviceRef(ns, web), svc.Spec.Ports[0].NodePort
	node := newNode(t)
	sink := watch(t, newWatcher(t), "")
	require.Equal(t, evidence.ExternalExposure{Exposed: true,
		EntryPoints: []evidence.EntryPoint{entryPoint(ref, port, tcp, nodeAddresses()...)},
		Unchecked:   []string{evidence.UncheckedNoAddress},
	}, sink.inSnapshot(t, subject).External)

	node.Status.Addresses = []corev1.NodeAddress{{Type: corev1.NodeInternalIP, Address: "198.51.100.17"}}
	rewriteStatus(t, node)

	require.Equal(t, exposedThrough(entryPoint(ref, port, tcp, "198.51.100.11", "198.51.100.12", "198.51.100.17",
		"198.51.100.21", "198.51.100.22")), dataOf(t, sink.nextChange(t, subject, 0)).External)
}

// An Ingress of a class that the settings count exposes the workload behind the Service that it routes to, through the
// host of its rule. An Ingress of another class exposes nothing.
func TestAnIngressOfACountedClassExposesItsBackendAndOneOfAnotherClassDoesNot(t *testing.T) {
	ns := newNamespace(t, nil).Name
	countedSubject, otherSubject := bare(t, ns, counted), bare(t, ns, other)
	for _, name := range []string{counted, other} {
		service(t, ns, name, corev1.ServiceTypeClusterIP, name, nil, false)
	}
	ingress(t, ns, counted, "public", counted)
	ingress(t, ns, other, "private", other)

	sink := watch(t, newWatcher(t), `{"ingressClasses": ["public"]}`)

	require.Equal(t, exposedThrough(entryPoint(ingressRef(ns, counted), 80, tcp, counted+".artifacts.example")),
		sink.inSnapshot(t, countedSubject).External)
	require.Equal(t, notExposed, sink.inSnapshot(t, otherSubject).External)
}

// An Ingress's host is on port 443 when an entry of the Ingress's TLS names it, a wildcard of the label in its place
// included, and on port 80 otherwise. Either way, the sources are asked about the host by its name.
func TestAnIngressHostIsOn443WhenItsTLSNamesIt(t *testing.T) {
	const shop = "shop.app.example"
	ns := newNamespace(t, nil).Name
	cases := map[string]struct {
		host string
		tls  []string
		port int32
	}{
		"exact":    {host: shop, tls: []string{shop}, port: 443},
		"wildcard": {host: shop, tls: []string{appWildcard}, port: 443},
		"plain":    {host: shop, port: 80},
		// A wildcard stands for one label, as in a certificate.
		"deeper": {host: "a." + shop, tls: []string{appWildcard}, port: 80},
	}
	for name, tc := range cases {
		bare(t, ns, name)
		service(t, ns, name, corev1.ServiceTypeClusterIP, name, nil, false)
		ing := ingressOf(ns, name, tc.host, name)
		if tc.tls != nil {
			ing.Spec.TLS = []networkingv1.IngressTLS{{Hosts: tc.tls}}
		}
		create(t, ing)
	}

	sink := watch(t, newWatcher(t), "")

	for name, tc := range cases {
		require.Equal(t, exposedThrough(evidence.EntryPoint{
			Addresses: []string{tc.host}, Port: ptr.To(tc.port), Protocol: tcp, ObjectRef: ingressRef(ns, name),
			Subjects: []string{"host/" + tc.host},
		}), sink.inSnapshot(t, podSubject(ns, name)).External, name)
	}
}

// An Ingress's rule without a host, and its default backend, are reached on the addresses of the Ingress's status,
// whose port the status doesn't say: an IP address gives an address subject without a port, and a hostname a host
// subject. Until the status has an address, they expose the workload all the same: NoAddress. A change of the status
// is a change of the workloads behind the Ingress.
func TestAnIngressWithoutAHostNamesItsStatusAddresses(t *testing.T) {
	const byRule, byDefault, hostname = "by-rule", "by-default", "edge.app.example"
	ns := newNamespace(t, nil).Name
	for _, name := range []string{byRule, byDefault} {
		bare(t, ns, name)
		service(t, ns, name, corev1.ServiceTypeClusterIP, name, nil, false)
	}
	withRule := ingressOf(ns, byRule, "", byRule)
	create(t, withRule)
	withDefault := &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: byDefault},
		Spec: networkingv1.IngressSpec{DefaultBackend: &networkingv1.IngressBackend{
			Service: &networkingv1.IngressServiceBackend{Name: byDefault, Port: networkingv1.ServiceBackendPort{
				Number: 80,
			}},
		}},
	}
	create(t, withDefault)
	sink := watch(t, newWatcher(t), "")
	for _, name := range []string{byRule, byDefault} {
		require.Equal(t, exposedUnchecked(evidence.UncheckedNoAddress), sink.inSnapshot(t, podSubject(ns, name)).External,
			name)
	}

	for _, ing := range []*networkingv1.Ingress{withRule, withDefault} {
		ing.Status.LoadBalancer.Ingress = []networkingv1.IngressLoadBalancerIngress{{Hostname: hostname}, {IP: "192.0.2.30"}}
		rewriteStatus(t, ing)
	}

	for _, name := range []string{byRule, byDefault} {
		require.Equal(t, exposedThrough(evidence.EntryPoint{
			Addresses: []string{"192.0.2.30", hostname}, ObjectRef: ingressRef(ns, name),
			Subjects: []string{"address/192.0.2.30", "host/" + hostname},
		}), dataOf(t, sink.nextChange(t, podSubject(ns, name), 0)).External, name)
	}
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
// to. A route on another Gateway exposes nothing. A route without hostnames, on a listener without one, is reached on
// the Gateway's status addresses: until it has some, NoAddress.
func TestAnHTTPRouteOnACountedGatewayExposesItsBackend(t *testing.T) {
	ns := newNamespace(t, nil).Name
	countedSubject, otherSubject := bare(t, ns, counted), bare(t, ns, other)
	for _, name := range []string{counted, other} {
		service(t, ns, name, corev1.ServiceTypeClusterIP, name, nil, false)
		gateway(t, ns, name, "")
		httpRoute(t, ns, name, ns, name, name)
	}

	sink := watch(t, newWatcher(t), fmt.Sprintf(`{"gateways": [{"namespace": "%s", "name": "%s"}]}`, ns, counted))

	require.Equal(t, exposedUnchecked(evidence.UncheckedNoAddress), sink.inSnapshot(t, countedSubject).External)
	require.Equal(t, notExposed, sink.inSnapshot(t, otherSubject).External)
}

// gatewayRef is how an event names the Gateway of the name in namespace, as a route's parentRef.
func gatewayRef(namespace, name string) *evidence.ObjectRef {
	return &evidence.ObjectRef{APIGroup: gatewayGroup, Kind: kindGateway, Namespace: namespace, Name: name}
}

// A route is reached through its hostnames, on the port of each listener that it attaches to, and the entry point
// names the Gateway as its parentRef. A listener of HTTP, HTTPS, TLS or TCP gives the protocol TCP, and one of UDP the
// protocol UDP. Two parentRefs that select one listener give one entry point.
func TestARouteNamesItsHostnamesAndItsGateway(t *testing.T) {
	ns := newNamespace(t, nil).Name
	fromYAML(t, fmt.Sprintf(`apiVersion: %s
kind: Gateway
metadata: {namespace: %s, name: shared}
spec:
  gatewayClassName: example
  listeners:
  - {name: https, port: 443, protocol: HTTPS, tls: {mode: Terminate, certificateRefs: [{name: shop-tls}]}}
  - {name: dns, port: 53, protocol: UDP}
`, gatewayAPIVersion, ns))
	routes := []struct {
		name, parents, protocol string
		port                    int32
	}{
		// A parentRef that names its namespace and one that doesn't are different parents to the Gateway API's
		// validation, and both select the listener https.
		{name: "storefront", port: 443, protocol: tcp, parents: fmt.Sprintf(
			"[{name: shared, sectionName: https}, {name: shared, namespace: %s, sectionName: https}]", ns)},
		{name: "resolver", port: 53, protocol: "UDP", parents: "[{name: shared, sectionName: dns}]"},
	}
	for _, route := range routes {
		bare(t, ns, route.name)
		service(t, ns, route.name, corev1.ServiceTypeClusterIP, route.name, nil, false)
		fromYAML(t, fmt.Sprintf("apiVersion: %s\nkind: HTTPRoute\nmetadata: {namespace: %s, name: %s}\nspec:\n"+
			"  parentRefs: %s\n  hostnames: [%s.app.example]\n  rules: [{backendRefs: [{name: %s, port: 80}]}]\n",
			gatewayAPIVersion, ns, route.name, route.parents, route.name, route.name))
	}

	sink := watch(t, newWatcher(t), "")

	for _, route := range routes {
		require.Equal(t, exposedThrough(evidence.EntryPoint{
			Addresses: []string{route.name + ".app.example"}, Port: ptr.To(route.port), Protocol: route.protocol,
			ObjectRef: routeRef(ns, route.name), ParentRef: gatewayRef(ns, "shared"),
			Subjects: []string{"host/" + route.name + ".app.example"},
		}), sink.inSnapshot(t, podSubject(ns, route.name)).External, route.name)
	}
}

// A route without hostnames is reached through the hostname of its listener, and on a listener without one through
// the addresses of its Gateway's status, with the listener's port: an IP address gives an address subject with the
// port, and a hostname a host subject. A NamedAddress, which isn't an address that a source can look up, is left out:
// NotASubject.
func TestARouteWithoutHostnamesNamesTheListenersHostnameOrTheGatewaysAddresses(t *testing.T) {
	// The names of the listeners, and of the routes on them.
	const onHostname, onStatus = "on-hostname", "on-status"
	ns := newNamespace(t, nil).Name
	gw := fromYAML(t, fmt.Sprintf(`apiVersion: %s
kind: Gateway
metadata: {namespace: %s, name: shared}
spec:
  gatewayClassName: example
  listeners:
  - {name: %s, hostname: %q, port: 443, protocol: HTTPS, tls: {mode: Terminate, certificateRefs: [{name: shop-tls}]}}
  - {name: %s, port: 8080, protocol: HTTP}
`, gatewayAPIVersion, ns, onHostname, appWildcard, onStatus))
	var addresses []any
	require.NoError(t, yaml.Unmarshal([]byte("[{type: IPAddress, value: 192.0.2.50}, "+
		"{type: Hostname, value: gw.app.example}, {type: NamedAddress, value: pool-a}]"), &addresses))
	require.NoError(t, unstructured.SetNestedSlice(gw.Object, addresses, "status", "addresses"))
	rewriteStatus(t, gw)
	for _, name := range []string{onHostname, onStatus} {
		bare(t, ns, name)
		service(t, ns, name, corev1.ServiceTypeClusterIP, name, nil, false)
		fromYAML(t, fmt.Sprintf("apiVersion: %s\nkind: HTTPRoute\nmetadata: {namespace: %s, name: %s}\nspec:\n"+
			"  parentRefs: [{name: shared, sectionName: %s}]\n  rules: [{backendRefs: [{name: %s, port: 80}]}]\n",
			gatewayAPIVersion, ns, name, name, name))
	}

	sink := watch(t, newWatcher(t), "")

	require.Equal(t, exposedThrough(evidence.EntryPoint{
		Addresses: []string{appWildcard}, Port: ptr.To[int32](443), Protocol: tcp,
		ObjectRef: routeRef(ns, onHostname), ParentRef: gatewayRef(ns, "shared"), Subjects: []string{"host/" + appWildcard},
	}), sink.inSnapshot(t, podSubject(ns, onHostname)).External)
	require.Equal(t, evidence.ExternalExposure{Exposed: true, EntryPoints: []evidence.EntryPoint{{
		Addresses: []string{"192.0.2.50", "gw.app.example"}, Port: ptr.To[int32](8080), Protocol: tcp,
		ObjectRef: routeRef(ns, onStatus), ParentRef: gatewayRef(ns, "shared"),
		Subjects: []string{"address/192.0.2.50:8080", "host/gw.app.example"},
	}}, Unchecked: []string{evidence.UncheckedNotASubject}}, sink.inSnapshot(t, podSubject(ns, onStatus)).External)
}

// A route that attaches through a parent of a kind that the collector doesn't read, such as a ListenerSet, is reached
// through its hostnames, on a port that the collector can't know, and without hostnames through nothing that it can
// name: NoAddress.
func TestARouteOfAnUnknownParentNamesItsHostnamesWithoutAPort(t *testing.T) {
	const withHostnames, withoutHostnames = "with-hostnames", "without-hostnames"
	ns := newNamespace(t, nil).Name
	for name, hostnames := range map[string]string{
		withHostnames: "\n  hostnames: [" + withHostnames + ".app.example]", withoutHostnames: "",
	} {
		bare(t, ns, name)
		service(t, ns, name, corev1.ServiceTypeClusterIP, name, nil, false)
		fromYAML(t, fmt.Sprintf("apiVersion: %s\nkind: HTTPRoute\nmetadata: {namespace: %s, name: %s}\nspec:\n"+
			"  parentRefs: [{kind: ListenerSet, name: extra}]%s\n  rules: [{backendRefs: [{name: %s, port: 80}]}]\n",
			gatewayAPIVersion, ns, name, hostnames, name))
	}

	sink := watch(t, newWatcher(t), "")

	require.Equal(t, exposedThrough(entryPoint(routeRef(ns, withHostnames), 0, "", withHostnames+".app.example")),
		sink.inSnapshot(t, podSubject(ns, withHostnames)).External)
	require.Equal(t, exposedUnchecked(evidence.UncheckedNoAddress),
		sink.inSnapshot(t, podSubject(ns, withoutHostnames)).External)
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

// An event names at most 32 entry points of a workload, as the schema allows: the first 32, sorted by object, port and
// addresses, and TooManyEntryPoints says that it left out the others.
func TestAWorkloadPastThirtyTwoEntryPointsKeepsTheFirst(t *testing.T) {
	ns := newNamespace(t, nil).Name
	subject := bare(t, ns, web)
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: web},
		Spec:       corev1.ServiceSpec{Selector: map[string]string{appLabel: web}, ExternalIPs: []string{"192.0.2.70"}},
	}
	// Each port of a Service with an external IP is an entry point on it: 33 ports give 33, in reverse.
	for port := int32(1033); port > 1000; port-- {
		svc.Spec.Ports = append(svc.Spec.Ports, corev1.ServicePort{Name: fmt.Sprintf("p%d", port), Port: port})
	}
	create(t, svc)

	sink := watch(t, newWatcher(t), "")

	want := evidence.ExternalExposure{Exposed: true, Unchecked: []string{evidence.UncheckedTooManyEntryPoints}}
	for port := int32(1001); port <= 1032; port++ {
		want.EntryPoints = append(want.EntryPoints, entryPoint(serviceRef(ns, web), port, tcp, "192.0.2.70"))
	}
	require.Equal(t, want, sink.inSnapshot(t, subject).External)
}

// An entry point names at most 256 addresses, as the schema allows: the first 256, sorted, and TooManyAddresses says
// that it left out the others.
func TestAnEntryPointPastTwoHundredFiftySixAddressesKeepsTheFirst(t *testing.T) {
	ns := newNamespace(t, nil).Name
	subject := bare(t, ns, web)
	svc := service(t, ns, web, corev1.ServiceTypeLoadBalancer, web, nil, false)
	addresses := []string{"198.51.100.1"}
	for i := 255; i >= 0; i-- {
		addresses = append(addresses, fmt.Sprintf("192.0.2.%d", i))
	}
	for _, address := range addresses {
		svc.Status.LoadBalancer.Ingress = append(svc.Status.LoadBalancer.Ingress, corev1.LoadBalancerIngress{IP: address})
	}
	rewriteStatus(t, svc)

	sink := watch(t, newWatcher(t), "")

	kept := slices.Sorted(slices.Values(addresses))[:256]
	require.Equal(t, "192.0.2.99", kept[255], "the addresses sort as text")
	require.Equal(t, evidence.ExternalExposure{Exposed: true,
		EntryPoints: []evidence.EntryPoint{entryPoint(serviceRef(ns, web), 80, tcp, kept...)},
		Unchecked:   []string{evidence.UncheckedTooManyAddresses},
	}, sink.inSnapshot(t, subject).External)
}

// An address that the SDK refuses as a subject, such as a hostname of a single label, is left out of its entry point,
// and NotASubject says so. An entry point that has no other address is left out whole.
func TestAnAddressTheSDKRefusesIsNotASubject(t *testing.T) {
	ns := newNamespace(t, nil).Name
	mixed, alone := bare(t, ns, "mixed"), bare(t, ns, "alone")
	for name, statuses := range map[string][]corev1.LoadBalancerIngress{
		"mixed": {{Hostname: "localhost"}, {IP: "192.0.2.60"}},
		"alone": {{Hostname: "localhost"}},
	} {
		svc := service(t, ns, name, corev1.ServiceTypeLoadBalancer, name, nil, false)
		svc.Status.LoadBalancer.Ingress = statuses
		rewriteStatus(t, svc)
	}

	sink := watch(t, newWatcher(t), "")

	require.Equal(t, evidence.ExternalExposure{Exposed: true,
		EntryPoints: []evidence.EntryPoint{entryPoint(serviceRef(ns, "mixed"), 80, tcp, "192.0.2.60")},
		Unchecked:   []string{evidence.UncheckedNotASubject},
	}, sink.inSnapshot(t, mixed).External)
	require.Equal(t, exposedUnchecked(evidence.UncheckedNotASubject), sink.inSnapshot(t, alone).External)
}

// A Service without a selector exposes the pods that its EndpointSlices name, as Kubernetes routes its traffic to
// them, and no other pod.
func TestAServiceWithoutASelectorExposesThePodsThatItsEndpointSlicesName(t *testing.T) {
	ns := newNamespace(t, nil).Name
	named, unnamed := bare(t, ns, "named"), bare(t, ns, "unnamed")
	manual := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "manual"},
		Spec: corev1.ServiceSpec{Type: corev1.ServiceTypeLoadBalancer, AllocateLoadBalancerNodePorts: ptr.To(false),
			Ports: []corev1.ServicePort{{Name: portName, Port: 80}}},
	}
	create(t, manual)
	manual.Status.LoadBalancer.Ingress = []corev1.LoadBalancerIngress{{IP: "192.0.2.19"}}
	rewriteStatus(t, manual)
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

	require.Equal(t, exposedThrough(entryPoint(serviceRef(ns, "manual"), 80, tcp, "192.0.2.19")),
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
  hostnames: [web.app.example]
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

	through := entryPoint(routeRef(ns, web), 80, tcp, "web.app.example")
	through.ParentRef = gatewayRef(ns, web)
	for _, subject := range []string{api, shadow} {
		require.Equal(t, exposedThrough(through), sink.inSnapshot(t, subject).External, subject)
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
			"  hostnames: [grpc.artifacts.example]\n  rules: [{backendRefs: [{name: grpc, port: 80}]}]\n",
		"kind: TLSRoute\nmetadata: {namespace: %[2]s, name: tls}\nspec:\n  parentRefs: [{name: %[3]s}]\n" +
			"  hostnames: [tls.artifacts.example]\n  rules: [{backendRefs: [{name: tls, port: 80}]}]\n",
	} {
		fromYAML(t, fmt.Sprintf("apiVersion: %[1]s\n"+manifest, gatewayAPIVersion, ns, web))
	}

	sink := watch(t, newWatcher(t), "")

	for subject, kind := range map[string]string{grpc: kindGRPCRoute, tls: kindTLSRoute} {
		name := strings.ToLower(strings.TrimSuffix(kind, "Route"))
		through := entryPoint(evidence.ObjectRef{APIGroup: gatewayGroup, Kind: kind, Namespace: ns, Name: name}, 80,
			tcp, name+".artifacts.example")
		through.ParentRef = gatewayRef(ns, web)
		require.Equal(t, exposedThrough(through), sink.inSnapshot(t, subject).External, kind)
	}
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
// settings say that the host ports are internal. A pod that no node runs yet has no address to be reached on:
// NoAddress.
func TestAHostPortExposesItsWorkloadUnlessHostPortsAreInternal(t *testing.T) {
	ns := newNamespace(t, nil).Name
	pod := podOf(ns, web, map[string]string{appLabel: web})
	withHostPort(pod)
	create(t, pod)
	subject := podSubject(ns, web)

	byDefault := watch(t, newWatcher(t), "").inSnapshot(t, subject).External
	internal := watch(t, newWatcher(t), `{"hostPorts": "Internal"}`).inSnapshot(t, subject).External

	require.Equal(t, exposedUnchecked(evidence.UncheckedNoAddress), byDefault)
	require.Equal(t, notExposed, internal)
}

// A pod on its node's network is reached on its node's address too, on whatever port it listens, declared or not: it
// exposes its workload unless the settings say that the host network is internal, and no entry point says where.
// HostNetwork says why.
func TestAPodOnItsNodesNetworkIsUncheckedWithoutAnEntryPoint(t *testing.T) {
	ns := newNamespace(t, nil).Name
	pod := podOf(ns, web, map[string]string{appLabel: web})
	pod.Spec.HostNetwork, pod.Spec.NodeName = true, nodeA
	// A port of a pod on its node's network is a host port too, as the API server defaults it.
	pod.Spec.Containers[0].Ports = []corev1.ContainerPort{{ContainerPort: 9100}}
	create(t, pod)
	subject := podSubject(ns, web)

	byDefault := watch(t, newWatcher(t), "").inSnapshot(t, subject).External
	internal := watch(t, newWatcher(t), `{"hostNetwork": "Internal"}`).inSnapshot(t, subject).External

	require.Equal(t, int32(9100), pod.Spec.Containers[0].Ports[0].HostPort)
	require.Equal(t, exposedUnchecked(evidence.UncheckedHostNetwork), byDefault)
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

// A host port is reached on the node of each pod that has it: its entry point names the workload's own object, its
// top-level owner, whose name stays as its pods come and go, with the host port, the protocol of its container's port,
// and the InternalIP and ExternalIP addresses of the nodes that run the workload's pods.
func TestAHostPortNamesTheNodesOfItsPods(t *testing.T) {
	ns := newNamespace(t, nil).Name
	subject := deploymentOf(t, ns, web, func(pod *corev1.Pod) {
		withHostPort(pod)
		pod.Spec.NodeName = nodeA
	})

	sink := watch(t, newWatcher(t), "")

	require.Equal(t, exposedThrough(entryPoint(deploymentRef(ns, web), 8080, tcp, "198.51.100.11", "198.51.100.21")),
		sink.inSnapshot(t, subject).External)
}

// A host port of a workload whose pods run on two nodes is reached on both: its one entry point names the addresses of
// both nodes. A pod that no node runs yet adds NoAddress, beside the entry point on the nodes of the others.
func TestAHostPortNamesTheNodesOfEveryPod(t *testing.T) {
	ns := newNamespace(t, nil).Name
	on := func(node string) func(*corev1.Pod) {
		return func(pod *corev1.Pod) {
			withHostPort(pod)
			pod.Spec.NodeName = node
		}
	}
	spread, pending := deploymentOf(t, ns, "spread", on(nodeA), on(nodeB)), deploymentOf(t, ns, "pending", on(nodeA), on(""))

	sink := watch(t, newWatcher(t), "")

	require.Equal(t, exposedThrough(entryPoint(deploymentRef(ns, "spread"), 8080, tcp, nodeAddresses()...)),
		sink.inSnapshot(t, spread).External)
	require.Equal(t, evidence.ExternalExposure{Exposed: true,
		EntryPoints: []evidence.EntryPoint{
			entryPoint(deploymentRef(ns, "pending"), 8080, tcp, "198.51.100.11", "198.51.100.21"),
		},
		Unchecked: []string{evidence.UncheckedNoAddress},
	}, sink.inSnapshot(t, pending).External)
}

// A Service with external IPs is reached on them, whatever its type, and exposes the pods that it backs: each of its
// ports is an entry point on all of them. No setting makes them internal.
func TestAServiceWithExternalIPsNamesEachPort(t *testing.T) {
	ns := newNamespace(t, nil).Name
	subject := bare(t, ns, web)
	create(t, &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: web},
		Spec: corev1.ServiceSpec{
			Type: corev1.ServiceTypeClusterIP, Selector: map[string]string{appLabel: web},
			Ports:       []corev1.ServicePort{{Name: portName, Port: 80}, {Name: securePortName, Port: 443}},
			ExternalIPs: []string{"192.0.2.21", "192.0.2.20"},
		},
	})

	sink := watch(t, newWatcher(t), `{"nodePorts": "Internal"}`)

	require.Equal(t, exposedThrough(
		entryPoint(serviceRef(ns, web), 80, tcp, "192.0.2.20", "192.0.2.21"),
		entryPoint(serviceRef(ns, web), 443, tcp, "192.0.2.20", "192.0.2.21"),
	), sink.inSnapshot(t, subject).External)
}

// A Service that counts through its external IPs, but has no port, as a headless Service may, exposes the pods that it
// selects on no port that an entry point can name: NoAddress.
func TestAServiceWithExternalIPsAndNoPortIsNoAddress(t *testing.T) {
	ns := newNamespace(t, nil).Name
	subject := bare(t, ns, web)
	create(t, &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: web},
		Spec: corev1.ServiceSpec{
			ClusterIP: corev1.ClusterIPNone, Selector: map[string]string{appLabel: web}, ExternalIPs: []string{"192.0.2.71"},
		},
	})

	sink := watch(t, newWatcher(t), "")

	require.Equal(t, exposedUnchecked(evidence.UncheckedNoAddress), sink.inSnapshot(t, subject).External)
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

	require.Equal(t, exposedThrough(entryPoint(serviceRef(ns, web), 80, tcp, "192.0.2.41")),
		sink.inSnapshot(t, subject).External)
}

// A workload is indirectly exposed when an exposed workload reaches it, whatever way in exposes the other: one that
// has an entry point, one whose status has no address yet, and a pod on its node's network alike. A workload that
// nothing exposes makes none indirectly exposed.
func TestIndirectExposureStaysAsItWas(t *testing.T) {
	cases := map[string]struct {
		expose func(t *testing.T, ns string)
		want   bool
	}{
		"a node port": {func(t *testing.T, ns string) {
			bare(t, ns, frontend)
			service(t, ns, frontend, corev1.ServiceTypeNodePort, frontend, nil, true)
		}, true},
		"a load balancer without an address": {func(t *testing.T, ns string) {
			bare(t, ns, frontend)
			service(t, ns, frontend, corev1.ServiceTypeLoadBalancer, frontend, nil, false)
		}, true},
		"the node's network": {func(t *testing.T, ns string) {
			pod := podOf(ns, frontend, map[string]string{appLabel: frontend})
			pod.Spec.HostNetwork = true
			create(t, pod)
		}, true},
		"nothing": {func(t *testing.T, ns string) {
			bare(t, ns, frontend)
			service(t, ns, frontend, corev1.ServiceTypeClusterIP, frontend, nil, false)
		}, false},
	}
	backends := map[string]string{}
	for name, tc := range cases {
		ns := newNamespace(t, nil).Name
		tc.expose(t, ns)
		backends[name] = bare(t, ns, backend)
		createPolicy(t, ns, backend, ingressFrom(backend, networkingv1.NetworkPolicyPeer{
			PodSelector: selecting(frontend),
		}))
	}

	sink := watch(t, newWatcher(t), "")

	for name, tc := range cases {
		require.Equal(t, tc.want, sink.inSnapshot(t, backends[name]).Indirect, name)
	}
}

// A build that computes a workload again, without a change of it, sends nothing about it: its entry points are sorted
// by object, port and addresses, and the addresses of each are sorted, in whatever order the cluster lists them.
func TestAnUnchangedWorkloadSendsNothing(t *testing.T) {
	ns := newNamespace(t, nil).Name
	subject := bare(t, ns, web)
	byNode := service(t, ns, "by-node", corev1.ServiceTypeNodePort, web, nil, true)
	byLB := service(t, ns, "by-lb", corev1.ServiceTypeLoadBalancer, web, nil, false)
	byLB.Status.LoadBalancer.Ingress = []corev1.LoadBalancerIngress{
		{IP: "192.0.2.82"}, {Hostname: "balancer.app.example"}, {IP: "192.0.2.81"},
	}
	rewriteStatus(t, byLB)
	ingress(t, ns, web, "", "by-lb")
	idle := podOf(ns, "idle", map[string]string{appLabel: "idle"})
	create(t, idle)
	w := newWatcher(t)
	sink := watch(t, w, "")
	require.Equal(t, exposedThrough(
		entryPoint(serviceRef(ns, "by-lb"), 80, tcp, "192.0.2.81", "192.0.2.82", "balancer.app.example"),
		entryPoint(serviceRef(ns, "by-node"), byNode.Spec.Ports[0].NodePort, tcp, nodeAddresses()...),
		entryPoint(ingressRef(ns, web), 80, tcp, web+".artifacts.example"),
	), sink.inSnapshot(t, subject).External)
	_, before := stableBuilds(t, w)

	for i := range 3 {
		idle.Labels = map[string]string{appLabel: "idle", tierLabel: fmt.Sprint(i)}
		rewrite(t, idle)
		require.Eventually(t, func() bool { return w.recomputed.Load() > before }, wait, tick,
			"the build computes the namespace again")
		_, before = stableBuilds(t, w)
	}

	require.Empty(t, sink.changesAbout(subject))
}

// Each trim keeps, besides what exposure reads already, what the entry points need of its kind, and drops the rest: a
// node's InternalIP and ExternalIP addresses; a pod's node and the protocols of its host ports; every port of a
// Service, with its protocol and node port, and the addresses of its load balancer; each rule of an Ingress with its
// host, the hosts of its TLS, and its status's addresses; the hostname, the port and the protocol of a Gateway's
// listeners, and its status's addresses; and a route's hostnames. The cache holds every object as transform trims it.
func TestTheTrimsKeepWhatEntryPointsNeed(t *testing.T) {
	const shop = "shop.app.example"
	node := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: nodeA, UID: "u-node", ResourceVersion: "7",
			Labels: map[string]string{corev1.LabelOSStable: "linux"}},
		Spec: corev1.NodeSpec{ProviderID: "example://node-a"},
		Status: corev1.NodeStatus{
			Addresses: []corev1.NodeAddress{
				{Type: corev1.NodeHostName, Address: nodeA},
				{Type: corev1.NodeInternalIP, Address: "198.51.100.13"},
				{Type: corev1.NodeExternalIP, Address: "198.51.100.23"},
				{Type: corev1.NodeInternalDNS, Address: "node-a.cluster.example"},
				{Type: corev1.NodeInternalIP, Address: "2001:db8::13"},
			},
			Conditions: []corev1.NodeCondition{{Type: corev1.NodeReady, Status: corev1.ConditionTrue}},
		},
	}
	pod := podOf(teamA, web, map[string]string{appLabel: web})
	pod.UID, pod.ResourceVersion = "u-pod", "7"
	pod.Annotations = map[string]string{lastApplied: "{}"}
	pod.Spec.NodeName, pod.Spec.ServiceAccountName = nodeA, web
	pod.Spec.InitContainers = []corev1.Container{{Name: "proxy", Image: image, Ports: []corev1.ContainerPort{
		{Name: "dns", ContainerPort: 53, HostPort: 5353, Protocol: corev1.ProtocolUDP},
	}}}
	pod.Spec.Containers[0].Ports = []corev1.ContainerPort{
		{Name: "http", ContainerPort: 8080, HostPort: 8080, Protocol: corev1.ProtocolTCP},
		{Name: "metrics", ContainerPort: 9090, Protocol: corev1.ProtocolTCP},
	}
	pod.Status.Phase = corev1.PodRunning
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Namespace: teamA, Name: web, UID: "u-svc", ResourceVersion: "7",
			Annotations: map[string]string{schemeAnnotation: internalScheme, lastApplied: "{}"}},
		Spec: corev1.ServiceSpec{
			Type: corev1.ServiceTypeLoadBalancer, Selector: map[string]string{appLabel: web},
			ClusterIP: "192.0.2.1", ExternalIPs: []string{"192.0.2.42"},
			Ports: []corev1.ServicePort{
				{Name: "https", Port: 443, Protocol: corev1.ProtocolTCP, NodePort: 30443},
				{Name: "dns", Port: 53, Protocol: corev1.ProtocolUDP},
			},
		},
		Status: corev1.ServiceStatus{
			LoadBalancer: corev1.LoadBalancerStatus{Ingress: []corev1.LoadBalancerIngress{
				{IP: "192.0.2.15", IPMode: ptr.To(corev1.LoadBalancerIPModeVIP),
					Ports: []corev1.PortStatus{{Port: 443, Protocol: corev1.ProtocolTCP}}},
				{Hostname: "lb.app.example"},
			}},
			Conditions: []metav1.Condition{{Type: "Programmed", Status: metav1.ConditionTrue}},
		},
	}
	routesTo := func(name string, port int32) networkingv1.IngressBackend {
		return networkingv1.IngressBackend{Service: &networkingv1.IngressServiceBackend{
			Name: name, Port: networkingv1.ServiceBackendPort{Number: port},
		}}
	}
	paths := func(backends ...networkingv1.IngressBackend) networkingv1.IngressRuleValue {
		value := &networkingv1.HTTPIngressRuleValue{}
		for _, backend := range backends {
			value.Paths = append(value.Paths, networkingv1.HTTPIngressPath{Backend: backend})
		}
		return networkingv1.IngressRuleValue{HTTP: value}
	}
	ing := &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{Namespace: teamA, Name: "shop", UID: "u-ing", ResourceVersion: "7",
			Annotations: map[string]string{ingressClassAnnotation: "edge", lastApplied: "{}"}},
		Spec: networkingv1.IngressSpec{
			DefaultBackend: ptr.To(routesTo("fallback", 80)),
			Rules: []networkingv1.IngressRule{
				{Host: shop, IngressRuleValue: paths(routesTo("shop", 80), networkingv1.IngressBackend{
					Resource: &corev1.TypedLocalObjectReference{Kind: "Bucket", Name: "static"},
				})},
				{IngressRuleValue: paths(routesTo("api", 8080))},
			},
			TLS: []networkingv1.IngressTLS{{Hosts: []string{shop}, SecretName: "shop-tls"}},
		},
		Status: networkingv1.IngressStatus{LoadBalancer: networkingv1.IngressLoadBalancerStatus{
			Ingress: []networkingv1.IngressLoadBalancerIngress{
				{IP: "192.0.2.35", Ports: []networkingv1.IngressPortStatus{{Port: 443, Protocol: corev1.ProtocolTCP}}},
				{Hostname: "ingress.app.example"},
			},
		}},
	}

	for name, tc := range map[string]struct{ in, want any }{
		"a node": {node, &corev1.Node{
			ObjectMeta: metav1.ObjectMeta{Name: nodeA, UID: "u-node", ResourceVersion: "7"},
			Status: corev1.NodeStatus{Addresses: []corev1.NodeAddress{
				{Type: corev1.NodeInternalIP, Address: "198.51.100.13"},
				{Type: corev1.NodeExternalIP, Address: "198.51.100.23"},
				{Type: corev1.NodeInternalIP, Address: "2001:db8::13"},
			}},
		}},
		"a pod": {pod, &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Namespace: teamA, Name: web, UID: "u-pod", ResourceVersion: "7",
				Labels: map[string]string{appLabel: web}},
			Spec: corev1.PodSpec{NodeName: nodeA, ServiceAccountName: web, Containers: []corev1.Container{{
				Ports: []corev1.ContainerPort{
					{HostPort: 5353, Protocol: corev1.ProtocolUDP}, {HostPort: 8080, Protocol: corev1.ProtocolTCP},
				},
			}}},
		}},
		"a Service": {svc, &corev1.Service{
			ObjectMeta: metav1.ObjectMeta{Namespace: teamA, Name: web, UID: "u-svc", ResourceVersion: "7",
				Annotations: map[string]string{schemeAnnotation: internalScheme}},
			Spec: corev1.ServiceSpec{
				Type: corev1.ServiceTypeLoadBalancer, Selector: map[string]string{appLabel: web},
				ExternalIPs: []string{"192.0.2.42"},
				Ports: []corev1.ServicePort{
					{Port: 443, Protocol: corev1.ProtocolTCP, NodePort: 30443}, {Port: 53, Protocol: corev1.ProtocolUDP},
				},
			},
			Status: corev1.ServiceStatus{LoadBalancer: corev1.LoadBalancerStatus{Ingress: []corev1.LoadBalancerIngress{
				{IP: "192.0.2.15"}, {Hostname: "lb.app.example"},
			}}},
		}},
		"an Ingress": {ing, &networkingv1.Ingress{
			ObjectMeta: metav1.ObjectMeta{Namespace: teamA, Name: "shop", UID: "u-ing", ResourceVersion: "7",
				Annotations: map[string]string{ingressClassAnnotation: "edge"}},
			Spec: networkingv1.IngressSpec{
				DefaultBackend: ptr.To(routesTo("fallback", 0)),
				Rules: []networkingv1.IngressRule{
					{Host: shop, IngressRuleValue: paths(routesTo("shop", 0))},
					{IngressRuleValue: paths(routesTo("api", 0))},
				},
				TLS: []networkingv1.IngressTLS{{Hosts: []string{shop}}},
			},
			Status: networkingv1.IngressStatus{LoadBalancer: networkingv1.IngressLoadBalancerStatus{
				Ingress: []networkingv1.IngressLoadBalancerIngress{{IP: "192.0.2.35"}, {Hostname: "ingress.app.example"}},
			}},
		}},
		"a Gateway": {decode(t, `apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata: {namespace: team-a, name: shared, uid: u-gw, resourceVersion: "7", generation: 2, labels: {app: shared}}
spec:
  gatewayClassName: example
  addresses: [{type: IPAddress, value: 192.0.2.49}]
  listeners:
  - name: https
    hostname: "*.app.example"
    port: 443
    protocol: HTTPS
    tls: {mode: Terminate, certificateRefs: [{name: shop-tls}]}
    allowedRoutes: {namespaces: {from: All}}
  - {name: dns, port: 53, protocol: UDP}
status:
  addresses: [{type: IPAddress, value: 192.0.2.50}, {type: Hostname, value: gw.app.example}]
  conditions: [{type: Programmed, status: "True"}]
  listeners: [{name: https, attachedRoutes: 1}]
`), decode(t, `apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata: {namespace: team-a, name: shared, uid: u-gw, resourceVersion: "7", generation: 2}
spec:
  listeners:
  - {name: https, hostname: "*.app.example", port: 443, protocol: HTTPS, allowedRoutes: {namespaces: {from: All}}}
  - {name: dns, port: 53, protocol: UDP}
status:
  addresses: [{type: IPAddress, value: 192.0.2.50}, {type: Hostname, value: gw.app.example}]
`)},
		"a route": {decode(t, `apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata: {namespace: team-a, name: api, uid: u-route, resourceVersion: "7", generation: 2, labels: {app: api}}
spec:
  parentRefs:
  - {group: gateway.networking.k8s.io, kind: Gateway, namespace: gateways, name: shared, sectionName: https, port: 443}
  hostnames: [api.app.example, "*.api.app.example"]
  rules:
  - matches: [{path: {type: PathPrefix, value: /}}]
    backendRefs: [{name: api, port: 80, weight: 1}]
    filters: [{type: RequestMirror, requestMirror: {backendRef: {name: shadow, port: 80}}}]
status:
  parents: [{parentRef: {name: shared}, controllerName: gateway.example/controller}]
`), decode(t, `apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata: {namespace: team-a, name: api, uid: u-route, resourceVersion: "7", generation: 2}
spec:
  parentRefs:
  - {group: gateway.networking.k8s.io, kind: Gateway, namespace: gateways, name: shared, sectionName: https, port: 443}
  hostnames: [api.app.example, "*.api.app.example"]
  rules:
  - backendRefs:
    - {group: "", kind: Service, namespace: team-a, name: api}
    - {group: "", kind: Service, namespace: team-a, name: shadow}
`)},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := transform(tc.in)

			require.NoError(t, err)
			require.Equal(t, tc.want, got)
		})
	}
}

// A route attaches to each listener of a Gateway that the settings count, among those that its parentRef names, by
// section name or port, or all of them when it names none, that allows routes of its namespace and kind. attached
// names each with its Gateway, and says whether a parentRef is of a kind that the collector doesn't read.
func TestAttachedNamesEachListenerThatARouteAttachesTo(t *testing.T) {
	gw := decode(t, `apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata: {namespace: gateways, name: shared}
spec:
  listeners:
  - {name: http, port: 80, protocol: HTTP, allowedRoutes: {namespaces: {from: All}}}
  - {name: https, hostname: "*.app.example", port: 443, protocol: HTTPS, allowedRoutes: {namespaces: {from: All}}}
  - {name: same, port: 8080, protocol: HTTP}
  - {name: grpc-only, port: 9090, protocol: HTTP, allowedRoutes: {namespaces: {from: All}, kinds: [{kind: GRPCRoute}]}}
`)
	// The parentRefs: to any listener of the Gateway, to a ListenerSet, and to the Gateway's listener of port 443.
	parents := sliceOf(decode(t, `apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata: {namespace: team-a, name: api}
spec:
  parentRefs:
  - {name: shared, namespace: gateways}
  - {kind: ListenerSet, name: extra}
  - {name: shared, namespace: gateways, port: 443}
`).Object, "spec", "parentRefs")
	shared := namespaced{Namespace: gw.GetNamespace(), Name: gw.GetName()}
	gateways := map[namespaced]map[string]any{shared: gw.Object}
	listeners := sliceOf(gw.Object, "spec", "listeners")
	listener := func(i int) attachment { return attachment{gateway: shared, listener: listeners[i].(map[string]any)} }
	namespaces := namespaceLabels{shared.Namespace: {}, teamA: {}}

	all, unseen := attached(parents[:2], teamA, kindHTTPRoute, gateways, settings{}, namespaces)
	require.Equal(t, []attachment{listener(0), listener(1)}, all)
	require.True(t, unseen)

	one, unseen := attached(parents[2:], teamA, kindHTTPRoute, gateways, settings{}, namespaces)
	require.Equal(t, []attachment{listener(1)}, one)
	require.False(t, unseen)

	other := settings{Gateways: []namespaced{{Namespace: shared.Namespace, Name: "other"}}}
	none, _ := attached(parents[:1], teamA, kindHTTPRoute, gateways, other, namespaces)
	require.Empty(t, none, "a Gateway that the settings don't count")
}
