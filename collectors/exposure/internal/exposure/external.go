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
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/utils/ptr"

	"github.com/bedag/vexplain/sdk/evidence"
)

// A workload is exposed when its pods back a Service that something outside the cluster reaches: a Service of type
// LoadBalancer that isn't internal, a Service with node ports unless they are internal, a Service that an Ingress of a
// class that counts routes to, or a Service that a route attached to a Gateway that counts routes to. The settings
// say what counts. Each setting that is left out counts everything of its kind, which errs towards urgency
// (decision 0006).

// settingsSchema is the schema of the collector's settings.
const settingsSchema = `{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "description": "What counts as reachable from outside the cluster. A setting that is left out counts everything of its kind as external, which errs towards urgency.",
  "type": "object",
  "additionalProperties": false,
  "properties": {
    "ingressClasses": {
      "description": "The ingress classes whose Ingresses count as external. Every class counts when the list is left out or empty. An Ingress without a class has the cluster's default class, and counts when no one can tell its class.",
      "type": "array",
      "maxItems": 64,
      "items": {"type": "string", "minLength": 1, "maxLength": 253}
    },
    "gateways": {
      "description": "The Gateways whose routes count as external, by namespace and name. Every Gateway counts when the list is left out or empty.",
      "type": "array",
      "maxItems": 64,
      "items": {
        "type": "object",
        "additionalProperties": false,
        "required": ["namespace", "name"],
        "properties": {
          "namespace": {"type": "string", "minLength": 1, "maxLength": 63},
          "name": {"type": "string", "minLength": 1, "maxLength": 253}
        }
      }
    },
    "internalLoadBalancerAnnotations": {
      "description": "Annotations that make a Service of type LoadBalancer internal: one that has any of them, with its value, isn't external through its load balancer. Its node ports count all the same, unless nodePorts is Internal.",
      "type": "array",
      "maxItems": 32,
      "items": {
        "type": "object",
        "additionalProperties": false,
        "required": ["key", "value"],
        "properties": {
          "key": {"type": "string", "minLength": 1, "maxLength": 317},
          "value": {"type": "string", "maxLength": 4096}
        }
      }
    },
    "nodePorts": {
      "description": "Whether something outside the cluster reaches the nodes' ports, and so the node ports of Services: External, the default, or Internal.",
      "enum": ["External", "Internal"]
    }
  }
}`

// The values of the setting nodePorts.
const (
	nodePortsExternal = "External"
	nodePortsInternal = "Internal"
)

// settings are the collector's settings.
type settings struct {
	IngressClasses                  []string     `json:"ingressClasses,omitempty"`
	Gateways                        []namespaced `json:"gateways,omitempty"`
	InternalLoadBalancerAnnotations []annotation `json:"internalLoadBalancerAnnotations,omitempty"`
	NodePorts                       string       `json:"nodePorts,omitempty"`
}

// namespaced names a namespaced object: a Gateway in the settings, and a Service or a pod in the collector's maps.
type namespaced struct {
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
}

// annotation is an annotation with its value.
type annotation struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// readSettings reads the settings, all of them: a field that it doesn't know could be one that makes a Service
// internal, and a Watch that ignored it would report what the admin said isn't exposed.
func readSettings(raw json.RawMessage) (settings, error) {
	var s settings
	if len(bytes.TrimSpace(raw)) == 0 {
		return s, nil
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&s); err != nil {
		return settings{}, fmt.Errorf("read the settings: %w", err)
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return settings{}, errors.New("read the settings: more JSON follows them")
	}
	if s.NodePorts != "" && s.NodePorts != nodePortsExternal && s.NodePorts != nodePortsInternal {
		return settings{}, fmt.Errorf("the settings: nodePorts is %s or %s", nodePortsExternal, nodePortsInternal)
	}
	return s, nil
}

// The objects that the collector reads to tell what exposes a Service.
const (
	// gatewayGroup is the API group of the Gateway API.
	gatewayGroup = "gateway.networking.k8s.io"
	// ingressClassAnnotation names the class of an Ingress from before the field ingressClassName, and Ingress
	// controllers still honour it.
	ingressClassAnnotation = "kubernetes.io/ingress.class"
	// lastApplied is the annotation in which kubectl keeps a copy of what it applied: the largest annotation that
	// objects commonly carry, which the collector never reads.
	lastApplied = corev1.LastAppliedConfigAnnotation
	// kindService and kindPod are the kinds of a Service and of a pod, as references name them.
	kindService = "Service"
	kindPod     = "Pod"
	// nameField is the field of a reference of the Gateway API, and of a listener, that holds a name.
	nameField = "name"
)

// The kinds of the Gateway API that the collector reads.
const (
	kindGateway   = "Gateway"
	kindHTTPRoute = "HTTPRoute"
	kindTLSRoute  = "TLSRoute"
	kindGRPCRoute = "GRPCRoute"
)

// serviceExposes reports whether a Service itself exposes the pods that it selects: a LoadBalancer that no
// annotation of the settings makes internal, or node ports, unless the settings say that they are internal. A
// LoadBalancer has node ports unless it was created without them, and an internal one is reached through them too.
func serviceExposes(svc *corev1.Service, s settings) bool {
	nodePorts := s.NodePorts != nodePortsInternal &&
		slices.ContainsFunc(svc.Spec.Ports, func(p corev1.ServicePort) bool { return p.NodePort != 0 })
	loadBalancer := svc.Spec.Type == corev1.ServiceTypeLoadBalancer &&
		!slices.ContainsFunc(s.InternalLoadBalancerAnnotations, func(a annotation) bool {
			value, ok := svc.Annotations[a.Key]
			return ok && value == a.Value
		})
	return nodePorts || loadBalancer
}

// selects reports whether the selector of a Service selects the pod. A Service without a selector selects no pod:
// its EndpointSlices name its pods, if any.
func selects(svc *corev1.Service, pod *corev1.Pod) bool {
	if len(svc.Spec.Selector) == 0 {
		return false
	}
	for key, value := range svc.Spec.Selector {
		if got, ok := pod.Labels[key]; !ok || got != value {
			return false
		}
	}
	return true
}

// defaultIngressClass returns the cluster's default IngressClass, the one that the annotation
// ingressclass.kubernetes.io/is-default-class marks, and false when no one class is marked.
func defaultIngressClass(classes []metav1.PartialObjectMetadata) (string, bool) {
	var marked []string
	for i := range classes {
		if classes[i].Annotations[networkingv1.AnnotationIsDefaultIngressClass] == "true" {
			marked = append(marked, classes[i].Name)
		}
	}
	if len(marked) != 1 {
		return "", false
	}
	return marked[0], true
}

// ingressCounts reports whether an Ingress counts as external under the settings: every Ingress counts without a
// list of classes, and else one whose class is in the list. An Ingress without a class has the cluster's default
// class, which is the class that Kubernetes gives a new Ingress. Where the cluster has no single default class, no
// one can tell which controller serves the Ingress, and it counts, erring towards urgency.
func ingressCounts(i *networkingv1.Ingress, defaultClass string, hasDefault bool, s settings) bool {
	if len(s.IngressClasses) == 0 {
		return true
	}
	class, known := "", false
	switch annotated, ok := i.Annotations[ingressClassAnnotation]; {
	case i.Spec.IngressClassName != nil:
		class, known = *i.Spec.IngressClassName, true
	case ok:
		class, known = annotated, true
	case hasDefault:
		class, known = defaultClass, true
	}
	return !known || slices.Contains(s.IngressClasses, class)
}

// ingressBackends returns the names of the Services that an Ingress routes to, in its namespace. A backend that is a
// resource of another kind is no Service, and no pod of the cluster's.
func ingressBackends(i *networkingv1.Ingress) []string {
	var names []string
	if b := i.Spec.DefaultBackend; b != nil && b.Service != nil {
		names = append(names, b.Service.Name)
	}
	for _, rule := range i.Spec.Rules {
		if rule.HTTP == nil {
			continue
		}
		for _, path := range rule.HTTP.Paths {
			if path.Backend.Service != nil {
				names = append(names, path.Backend.Service.Name)
			}
		}
	}
	return names
}

// gatewayCounts reports whether the settings count the Gateway: every Gateway counts without a list of Gateways.
func gatewayCounts(gateway namespaced, s settings) bool {
	return len(s.Gateways) == 0 || slices.Contains(s.Gateways, gateway)
}

// attached reports whether a route of the kind in routeNamespace attaches, through one of its parentRefs, to a
// Gateway that the settings count. The route attaches to a Gateway as the Gateway API has it: the Gateway exists, and
// a listener of it that the parentRef names, by its section name or its port, or any listener when it names none,
// allows routes of the route's namespace and kind. The listener's hostnames and protocol aren't read, and a listener
// that names no kinds allows every kind, which errs towards urgency.
//
// A parentRef to a Service attaches the route to a mesh, whose traffic comes from inside the cluster. A parentRef to
// a kind that the collector doesn't read, such as a ListenerSet, may attach the route to any Gateway, and counts.
func attached(parentRefs []any, routeNamespace, routeKind string, gateways map[namespaced]map[string]any,
	s settings, namespaces namespaceLabels) bool {
	for _, raw := range parentRefs {
		ref, ok := raw.(map[string]any)
		if !ok {
			return true
		}
		group, kind := stringOf(ref, "group", gatewayGroup), stringOf(ref, "kind", kindGateway)
		switch {
		case group == "" && kind == kindService:
			continue
		case group != gatewayGroup || kind != kindGateway:
			return true
		}
		name := namespaced{Namespace: stringOf(ref, "namespace", routeNamespace), Name: stringOf(ref, nameField, "")}
		gateway, exists := gateways[name]
		if exists && gatewayCounts(name, s) && listenerAllows(gateway, name.Namespace, ref, routeNamespace, routeKind,
			namespaces) {
			return true
		}
	}
	return false
}

// listenerAllows reports whether a listener of the Gateway in gatewayNamespace, among those that the parentRef names,
// allows a route of the kind in routeNamespace.
func listenerAllows(gateway map[string]any, gatewayNamespace string, ref map[string]any, routeNamespace,
	routeKind string, namespaces namespaceLabels) bool {
	listeners := sliceOf(gateway, "spec", "listeners")
	section, bySection := ref["sectionName"].(string)
	port, byPort := numberOf(ref["port"])
	for _, raw := range listeners {
		listener, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		if name, _ := listener[nameField].(string); bySection && name != section {
			continue
		}
		if listenerPort, _ := numberOf(listener["port"]); byPort && listenerPort != port {
			continue
		}
		allowed, _ := listener["allowedRoutes"].(map[string]any)
		if allowsNamespace(allowed, gatewayNamespace, routeNamespace, namespaces) && allowsKind(allowed, routeKind) {
			return true
		}
	}
	return false
}

// allowsNamespace reports whether a listener's allowedRoutes allow routes of routeNamespace: from the Gateway's own
// namespace by default, from all of them, or from those that a selector selects. A value that the collector can't
// read allows them, erring towards urgency.
func allowsNamespace(allowed map[string]any, gatewayNamespace, routeNamespace string, namespaces namespaceLabels) bool {
	from, _ := allowed["namespaces"].(map[string]any)
	switch stringOf(from, "from", "Same") {
	case "Same":
		return routeNamespace == gatewayNamespace
	case "Selector":
		raw, _ := from["selector"].(map[string]any)
		var selector metav1.LabelSelector
		if err := runtime.DefaultUnstructuredConverter.FromUnstructured(raw, &selector); err != nil {
			return true
		}
		selects, err := metav1.LabelSelectorAsSelector(&selector)
		return err != nil || selects.Matches(labels.Set(namespaces[routeNamespace]))
	}
	return true
}

// allowsKind reports whether a listener's allowedRoutes allow routes of the kind: those that it lists, and every kind
// when it lists none, where the Gateway API decides by the listener's protocol, which the collector doesn't read.
func allowsKind(allowed map[string]any, routeKind string) bool {
	kinds, _ := allowed["kinds"].([]any)
	if len(kinds) == 0 {
		return true
	}
	return slices.ContainsFunc(kinds, func(raw any) bool {
		kind, _ := raw.(map[string]any)
		return stringOf(kind, "group", gatewayGroup) == gatewayGroup && stringOf(kind, "kind", "") == routeKind
	})
}

// routeBackends returns the Services that a route sends traffic to, by namespace and name: those of its rules'
// backendRefs, in the route's namespace unless they name another, and the backends that a filter mirrors requests
// to, which get the outside's requests too. A backendRef to another namespace may need a ReferenceGrant there, which
// the collector doesn't read: it counts, erring towards urgency.
func routeBackends(route *unstructured.Unstructured) []namespaced {
	var backends []namespaced
	add := func(raw any) {
		ref, ok := raw.(map[string]any)
		if ok && stringOf(ref, "group", "") == "" && stringOf(ref, "kind", kindService) == kindService {
			backends = append(backends, namespaced{
				Namespace: stringOf(ref, "namespace", route.GetNamespace()), Name: stringOf(ref, nameField, ""),
			})
		}
	}
	mirrored := func(filters any) {
		list, _ := filters.([]any)
		for _, raw := range list {
			filter, _ := raw.(map[string]any)
			mirror, _ := filter["requestMirror"].(map[string]any)
			if ref, ok := mirror["backendRef"]; ok {
				add(ref)
			}
		}
	}
	rules := sliceOf(route.Object, "spec", "rules")
	for _, raw := range rules {
		rule, _ := raw.(map[string]any)
		refs, _ := rule["backendRefs"].([]any)
		for _, ref := range refs {
			add(ref)
			if m, ok := ref.(map[string]any); ok {
				mirrored(m["filters"])
			}
		}
		mirrored(rule["filters"])
	}
	return backends
}

// sliceOf returns the list under the fields of an unstructured object, without copying it, or nil when there is
// none.
func sliceOf(obj map[string]any, fields ...string) []any {
	value, _, _ := unstructured.NestedFieldNoCopy(obj, fields...)
	list, _ := value.([]any)
	return list
}

// stringOf returns the string under the key of m, or def when there is none.
func stringOf(m map[string]any, key, def string) string {
	if value, ok := m[key].(string); ok {
		return value
	}
	return def
}

// numberOf returns a number of an unstructured object, which JSON gives as an int64 or a float64.
func numberOf(raw any) (int64, bool) {
	switch n := raw.(type) {
	case int64:
		return n, true
	case float64:
		return int64(n), true
	case int:
		return int64(n), true
	}
	return 0, false
}

// slicePods returns the pods that an EndpointSlice of a Service names, by namespace and name, with the Service. A
// slice that no Service owns, by the label kubernetes.io/service-name, routes the traffic of none.
func slicePods(slice *discoveryv1.EndpointSlice) (service namespaced, pods []namespaced) {
	service = namespaced{Namespace: slice.Namespace, Name: slice.Labels[discoveryv1.LabelServiceName]}
	if service.Name == "" {
		return service, nil
	}
	for _, endpoint := range slice.Endpoints {
		if ref := endpoint.TargetRef; ref != nil && ref.Kind == kindPod {
			pods = append(pods, namespaced{Namespace: cmp.Or(ref.Namespace, slice.Namespace), Name: ref.Name})
		}
	}
	return service, pods
}

// objectRef is how an event names an object that exposes a workload.
func objectRef(group, kind, namespace, name string) evidence.ObjectRef {
	return evidence.ObjectRef{APIGroup: group, Kind: kind, Namespace: namespace, Name: name}
}

// trimService keeps what the collector reads of a Service: its annotations, but kubectl's copy of what it applied,
// its type, its selector and its node ports.
func trimService(svc *corev1.Service) *corev1.Service {
	trimmed := &corev1.Service{ObjectMeta: identity(svc.ObjectMeta), Spec: corev1.ServiceSpec{
		Type: svc.Spec.Type, Selector: svc.Spec.Selector,
	}}
	for key, value := range svc.Annotations {
		if key != lastApplied {
			if trimmed.Annotations == nil {
				trimmed.Annotations = map[string]string{}
			}
			trimmed.Annotations[key] = value
		}
	}
	for _, port := range svc.Spec.Ports {
		if port.NodePort != 0 {
			trimmed.Spec.Ports = append(trimmed.Spec.Ports, corev1.ServicePort{NodePort: port.NodePort})
		}
	}
	return trimmed
}

// trimEndpointSlice keeps what the collector reads of an EndpointSlice: its Service, and the pods that it names. The
// conditions and addresses of its endpoints change as pods come and go, and the collector reads none of them.
func trimEndpointSlice(slice *discoveryv1.EndpointSlice) *discoveryv1.EndpointSlice {
	trimmed := &discoveryv1.EndpointSlice{ObjectMeta: identity(slice.ObjectMeta), AddressType: slice.AddressType}
	if name, ok := slice.Labels[discoveryv1.LabelServiceName]; ok {
		trimmed.Labels = map[string]string{discoveryv1.LabelServiceName: name}
	}
	for _, endpoint := range slice.Endpoints {
		if ref := endpoint.TargetRef; ref != nil && ref.Kind == kindPod {
			trimmed.Endpoints = append(trimmed.Endpoints, discoveryv1.Endpoint{
				TargetRef: &corev1.ObjectReference{Kind: ref.Kind, Namespace: ref.Namespace, Name: ref.Name},
			})
		}
	}
	return trimmed
}

// trimIngress keeps what the collector reads of an Ingress: its class, and the Services that it routes to.
func trimIngress(i *networkingv1.Ingress) *networkingv1.Ingress {
	trimmed := &networkingv1.Ingress{ObjectMeta: identity(i.ObjectMeta), Spec: networkingv1.IngressSpec{
		IngressClassName: i.Spec.IngressClassName,
	}}
	if class, ok := i.Annotations[ingressClassAnnotation]; ok {
		trimmed.Annotations = map[string]string{ingressClassAnnotation: class}
	}
	backend := func(name string) networkingv1.IngressBackend {
		return networkingv1.IngressBackend{Service: &networkingv1.IngressServiceBackend{Name: name}}
	}
	if b := i.Spec.DefaultBackend; b != nil && b.Service != nil {
		trimmed.Spec.DefaultBackend = ptr.To(backend(b.Service.Name))
	}
	var paths []networkingv1.HTTPIngressPath
	for _, rule := range i.Spec.Rules {
		if rule.HTTP == nil {
			continue
		}
		for _, path := range rule.HTTP.Paths {
			if path.Backend.Service != nil {
				paths = append(paths, networkingv1.HTTPIngressPath{Backend: backend(path.Backend.Service.Name)})
			}
		}
	}
	if len(paths) > 0 {
		trimmed.Spec.Rules = []networkingv1.IngressRule{{IngressRuleValue: networkingv1.IngressRuleValue{
			HTTP: &networkingv1.HTTPIngressRuleValue{Paths: paths},
		}}}
	}
	return trimmed
}

// trimGateway keeps what the collector reads of a Gateway: the name, the port and the allowedRoutes of each listener.
func trimGateway(u *unstructured.Unstructured) *unstructured.Unstructured {
	trimmed := trimmedIdentity(u)
	listeners := sliceOf(u.Object, "spec", "listeners")
	kept := make([]any, 0, len(listeners))
	for _, raw := range listeners {
		listener, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		keep := map[string]any{}
		for _, field := range []string{nameField, "port", "allowedRoutes"} {
			if value, ok := listener[field]; ok {
				keep[field] = value
			}
		}
		kept = append(kept, keep)
	}
	trimmed.Object["spec"] = map[string]any{"listeners": kept}
	return trimmed
}

// trimRoute keeps what the collector reads of a route: its parentRefs, and the Services that it sends traffic to,
// each as a backendRef of one rule, which routeBackends reads as it reads the route whole.
func trimRoute(u *unstructured.Unstructured) *unstructured.Unstructured {
	trimmed := trimmedIdentity(u)
	parents := sliceOf(u.Object, "spec", "parentRefs")
	keptParents := make([]any, 0, len(parents))
	for _, raw := range parents {
		ref, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		keep := map[string]any{}
		for _, field := range []string{"group", "kind", "namespace", nameField, "sectionName", "port"} {
			if value, ok := ref[field]; ok {
				keep[field] = value
			}
		}
		keptParents = append(keptParents, keep)
	}
	backends := routeBackends(u)
	refs := make([]any, 0, len(backends))
	for _, backend := range backends {
		refs = append(refs, map[string]any{"group": "", "kind": kindService, "namespace": backend.Namespace,
			nameField: backend.Name})
	}
	spec := map[string]any{"parentRefs": keptParents}
	if len(refs) > 0 {
		spec["rules"] = []any{map[string]any{"backendRefs": refs}}
	}
	trimmed.Object["spec"] = spec
	return trimmed
}

// sortedRefs sorts refs by API group, kind, namespace and name, and drops duplicates.
func sortedRefs(refs []evidence.ObjectRef) []evidence.ObjectRef {
	slices.SortFunc(refs, func(a, b evidence.ObjectRef) int {
		return cmp.Or(cmp.Compare(a.APIGroup, b.APIGroup), cmp.Compare(a.Kind, b.Kind),
			cmp.Compare(a.Namespace, b.Namespace), cmp.Compare(a.Name, b.Name))
	})
	return slices.Compact(refs)
}
