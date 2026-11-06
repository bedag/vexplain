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
	"testing"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/rand"

	"github.com/bedag/vexplain/sdk/evidence"
)

// notExposed is what an event says of a workload that nothing outside the cluster reaches.
var notExposed = evidence.ExternalExposure{}

const (
	// schemeAnnotation is the annotation that the tests' settings name as the one that makes a load balancer
	// internal.
	schemeAnnotation = "lb.artifacts.example/scheme"
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
		map[string]string{schemeAnnotation: "internal"}, false)
	service(t, ns, "public", corev1.ServiceTypeLoadBalancer, "public",
		map[string]string{schemeAnnotation: "public"}, false)

	sink := watch(t, newWatcher(t),
		`{"internalLoadBalancerAnnotations": [{"key": "`+schemeAnnotation+`", "value": "internal"}]}`)

	require.Equal(t, notExposed, sink.inSnapshot(t, internal).External)
	require.Equal(t, evidence.ExternalExposure{Exposed: true, Via: []evidence.ObjectRef{serviceRef(ns, "public")}},
		sink.inSnapshot(t, public).External)
}

// An internal load balancer that has node ports is reachable through them, from outside the cluster unless the node
// ports are internal.
func TestAnInternalLoadBalancerWithNodePortsIsExposedThroughThem(t *testing.T) {
	ns := newNamespace(t, nil).Name
	subject := bare(t, ns, web)
	service(t, ns, web, corev1.ServiceTypeLoadBalancer, web, map[string]string{schemeAnnotation: "internal"},
		true)
	const internalLB = `"internalLoadBalancerAnnotations": [{"key": "` + schemeAnnotation + `", "value": "internal"}]`

	external := watch(t, newWatcher(t), "{"+internalLB+"}").inSnapshot(t, subject).External
	internal := watch(t, newWatcher(t), `{`+internalLB+`, "nodePorts": "Internal"}`).inSnapshot(t, subject).External

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

// An Ingress without a class belongs to the cluster's default IngressClass, and counts when that class does. While
// the cluster has no default class, no one can tell which controller serves the Ingress, and it counts.
func TestAnIngressWithoutAClassBelongsToTheDefaultClass(t *testing.T) {
	ns := newNamespace(t, nil).Name
	subject := bare(t, ns, web)
	service(t, ns, web, corev1.ServiceTypeClusterIP, web, nil, false)
	// The Ingress comes before the default class: Kubernetes gives a new Ingress without a class the default class.
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

	require.True(t, withoutDefault, "an Ingress whose class no one can tell counts")
	require.True(t, defaultCounted, "the default class counts")
	require.False(t, defaultNotCounted, "the default class doesn't count")
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
