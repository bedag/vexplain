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
	"strings"

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
// LoadBalancer that isn't internal, a Service with node ports unless they are internal, a Service with external IPs,
// a Service that an Ingress of a class that counts routes to, or a Service that a route attached to a Gateway that
// counts routes to. It is exposed too when a pod of it is reached on its node's address, as a node port is: on the
// node's network unless the host network is internal, and else through a host port unless the host ports are
// internal. The settings say what counts. Each setting that is left out counts everything of its kind, which errs
// towards urgency (decision 0006, and design 6.4).
//
// The settings also name the peers that the admin trusts, such as an ingress controller or monitoring: a peer of a
// policy's rule that one of them matches doesn't widen a workload's internal reach (decision 0048). Trust narrows
// nothing else, and a trusted workload that is exposed still exposes the workloads that it reaches, one hop away.

// settingsSchema is the schema of the collector's settings.
const settingsSchema = `{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "description": "What counts as reachable from outside the cluster, and the peers that the admin trusts. A setting that is left out counts everything of its kind as external, which errs towards urgency.",
  "type": "object",
  "additionalProperties": false,
  "properties": {
    "ingressClasses": {
      "description": "The ingress classes whose Ingresses count as external, by their field ingressClassName or the annotation kubernetes.io/ingress.class. Every class counts when the list is left out or empty. An Ingress without a class counts always: which controller serves it is the controllers' own setting.",
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
      "description": "Annotations that make a Service of type LoadBalancer internal: one that has any of them, with its value, isn't external through its load balancer. Its node ports count all the same, unless nodePorts is Internal, and so do its external IPs.",
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
      "description": "Whether something outside the cluster reaches the node ports of Services, of type NodePort or LoadBalancer: External, the default, or Internal.",
      "enum": ["External", "Internal"]
    },
    "hostPorts": {
      "description": "Whether something outside the cluster reaches the host ports of pods, on their node's address: External, the default, or Internal. The ports of a pod on its node's network count under hostNetwork.",
      "enum": ["External", "Internal"]
    },
    "hostNetwork": {
      "description": "Whether something outside the cluster reaches the pods on their node's network, on their node's address: External, the default, or Internal. The whole cluster reaches them whatever this says, since no policy of a pod applies to them.",
      "enum": ["External", "Internal"]
    },
    "trustedPeers": {
      "description": "The peers that the admin trusts, such as an ingress controller or monitoring. A peer of a policy's rule that an entry matches doesn't widen a workload's internal reach. Trust narrows nothing else: a workload that no policy selects, one on its node's network, and a rule that the collector can't read, such as one with an IP block, keep their reach, and a trusted workload that is exposed still makes the workloads that it reaches indirectly exposed. An entry matches a peer when each field that it sets matches every pod that the peer can let in: namespaceSelector the labels of their namespace, podSelector their labels, which the peer's selector must ask for, and serviceAccount their service account, which only the selector of a Cilium policy can ask for. The selectors are Kubernetes label selectors, and an empty one matches everything: an entry of an empty namespaceSelector alone trusts every pod of the cluster, so that no policy widens a reach beyond its namespace. Empty by default.",
      "type": "array",
      "maxItems": 32,
      "items": {
        "type": "object",
        "additionalProperties": false,
        "minProperties": 1,
        "properties": {
          "namespaceSelector": { "$ref": "#/$defs/labelSelector" },
          "podSelector": { "$ref": "#/$defs/labelSelector" },
          "serviceAccount": {
            "type": "object",
            "additionalProperties": false,
            "required": ["namespace", "name"],
            "properties": {
              "namespace": {"type": "string", "minLength": 1, "maxLength": 63},
              "name": {"type": "string", "minLength": 1, "maxLength": 253}
            }
          }
        }
      }
    }
  },
  "$defs": {
    "labelSelector": {
      "description": "A Kubernetes label selector, which matches what all of its matchLabels and matchExpressions match. An empty one matches everything.",
      "type": "object",
      "additionalProperties": false,
      "properties": {
        "matchLabels": {"type": "object", "additionalProperties": {"type": "string"}},
        "matchExpressions": {
          "type": "array",
          "items": {
            "type": "object",
            "additionalProperties": false,
            "required": ["key", "operator"],
            "properties": {
              "key": {"type": "string", "minLength": 1},
              "operator": {"enum": ["In", "NotIn", "Exists", "DoesNotExist"]},
              "values": {"type": "array", "items": {"type": "string"}}
            }
          }
        }
      }
    }
  }
}`

// The values of the settings nodePorts, hostPorts and hostNetwork.
const (
	settingExternal = "External"
	settingInternal = "Internal"
)

// settings are the collector's settings.
type settings struct {
	IngressClasses                  []string      `json:"ingressClasses,omitempty"`
	Gateways                        []namespaced  `json:"gateways,omitempty"`
	InternalLoadBalancerAnnotations []annotation  `json:"internalLoadBalancerAnnotations,omitempty"`
	NodePorts                       string        `json:"nodePorts,omitempty"`
	HostPorts                       string        `json:"hostPorts,omitempty"`
	HostNetwork                     string        `json:"hostNetwork,omitempty"`
	TrustedPeers                    []trustedPeer `json:"trustedPeers,omitempty"`
	// trusted are the entries of TrustedPeers, read.
	trusted []trusted
}

// trustedPeer is an entry of the setting trustedPeers.
type trustedPeer struct {
	NamespaceSelector *metav1.LabelSelector `json:"namespaceSelector,omitempty"`
	PodSelector       *metav1.LabelSelector `json:"podSelector,omitempty"`
	ServiceAccount    *namespaced           `json:"serviceAccount,omitempty"`
}

// read reads the entry. It refuses one that sets nothing, which would match every peer, a selector that Kubernetes
// refuses, and a service account without a namespace or a name.
func (p trustedPeer) read() (trusted, error) {
	var t trusted
	if p.NamespaceSelector == nil && p.PodSelector == nil && p.ServiceAccount == nil {
		return t, errors.New("it sets nothing, and would trust every peer")
	}
	var err error
	if p.NamespaceSelector != nil {
		if t.namespaces, err = metav1.LabelSelectorAsSelector(p.NamespaceSelector); err != nil {
			return t, fmt.Errorf("namespaceSelector: %w", err)
		}
	}
	if p.PodSelector != nil {
		if t.pods, err = metav1.LabelSelectorAsSelector(p.PodSelector); err != nil {
			return t, fmt.Errorf("podSelector: %w", err)
		}
	}
	if sa := p.ServiceAccount; sa != nil {
		if sa.Namespace == "" || sa.Name == "" {
			return t, errors.New("serviceAccount names a namespace and a name")
		}
		t.serviceAccount = sa
	}
	return t, nil
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
// internal, and a Watch that ignored it would report what the admin said isn't exposed. It reads each trusted peer as
// Kubernetes reads its selectors.
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
	for _, setting := range []struct{ name, value string }{
		{"nodePorts", s.NodePorts}, {"hostPorts", s.HostPorts}, {"hostNetwork", s.HostNetwork},
	} {
		if setting.value != "" && setting.value != settingExternal && setting.value != settingInternal {
			return settings{}, fmt.Errorf("the settings: %s is %s or %s", setting.name, settingExternal, settingInternal)
		}
	}
	for i, peer := range s.TrustedPeers {
		t, err := peer.read()
		if err != nil {
			return settings{}, fmt.Errorf("the settings: trustedPeers[%d]: %w", i, err)
		}
		s.trusted = append(s.trusted, t)
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
	// kindService, kindIngress and kindPod are the kinds of a Service, of an Ingress and of a pod, as references name
	// them.
	kindService = "Service"
	kindIngress = "Ingress"
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

// serviceWays reports whether a Service itself exposes the pods that it backs, and returns its ways in: a LoadBalancer
// that no annotation of the settings makes internal, on the addresses of its status; node ports, unless the settings
// say that they are internal, on the addresses of every node, nodeAddresses, with NoAddress while a node has none,
// which addressless says; or external IPs, which no setting makes internal, whatever the Service's type. Each port of
// the Service is an entry point on each of them, and a Service without a port, as a headless one may be, names no way
// in: NoAddress. A LoadBalancer has node ports unless it was created without them, and an internal one is reached
// through them, and through its external IPs, too.
func serviceWays(svc *corev1.Service, s settings, nodeAddresses []string, addressless bool) (exposer, bool) {
	nodePorts := s.NodePorts != settingInternal &&
		slices.ContainsFunc(svc.Spec.Ports, func(p corev1.ServicePort) bool { return p.NodePort != 0 })
	loadBalancer := svc.Spec.Type == corev1.ServiceTypeLoadBalancer &&
		!slices.ContainsFunc(s.InternalLoadBalancerAnnotations, func(a annotation) bool {
			value, ok := svc.Annotations[a.Key]
			return ok && value == a.Value
		})
	status := make([]string, 0, 2*len(svc.Status.LoadBalancer.Ingress))
	for _, ingress := range svc.Status.LoadBalancer.Ingress {
		status = append(status, ingress.IP, ingress.Hostname)
	}
	e := exposer{ref: objectRef("", kindService, svc.Namespace, svc.Name)}
	for _, port := range svc.Spec.Ports {
		protocol := cmp.Or(string(port.Protocol), tcp)
		if loadBalancer {
			e.way(nil, status, port.Port, protocol)
		}
		if len(svc.Spec.ExternalIPs) > 0 {
			e.way(nil, svc.Spec.ExternalIPs, port.Port, protocol)
		}
		if nodePorts && port.NodePort != 0 {
			e.way(nil, nodeAddresses, port.NodePort, protocol)
			if addressless {
				e.unchecked = append(e.unchecked, evidence.UncheckedNoAddress)
			}
		}
	}
	if len(svc.Spec.Ports) == 0 {
		e.unchecked = append(e.unchecked, evidence.UncheckedNoAddress)
	}
	return e, nodePorts || loadBalancer || len(svc.Spec.ExternalIPs) > 0
}

// onNodeAddress reports whether something outside the cluster reaches a pod on its node's address, as a node port
// is: a pod on its node's network, unless hostNetwork is Internal, or else a pod with a host port, unless hostPorts
// is Internal. The ports of a pod on its node's network are its node's, so hostNetwork alone decides them.
func (s settings) onNodeAddress(pod *corev1.Pod) bool {
	if pod.Spec.HostNetwork {
		return s.HostNetwork != settingInternal
	}
	return s.HostPorts != settingInternal && len(hostPorts(pod)) > 0
}

// hostPorts returns the host ports of a pod's containers, its init containers included, as a sidecar runs as one:
// the number and the protocol of each.
func hostPorts(pod *corev1.Pod) []corev1.ContainerPort {
	var ports []corev1.ContainerPort
	for _, container := range slices.Concat(pod.Spec.InitContainers, pod.Spec.Containers) {
		for _, port := range container.Ports {
			if port.HostPort != 0 {
				ports = append(ports, corev1.ContainerPort{HostPort: port.HostPort, Protocol: port.Protocol})
			}
		}
	}
	return ports
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

// ingressCounts reports whether an Ingress counts as external under the settings: every Ingress counts without a
// list of classes, and else one whose class is in the list, by its field ingressClassName or the annotation
// kubernetes.io/ingress.class. An Ingress without a class counts always, which errs towards urgency: Kubernetes gives
// the default IngressClass only to an Ingress that it creates without a class, so an Ingress without one never had
// it, and whether a controller serves Ingresses without a class is that controller's own setting, which the collector
// can't read.
func ingressCounts(i *networkingv1.Ingress, s settings) bool {
	if len(s.IngressClasses) == 0 {
		return true
	}
	switch annotated, ok := i.Annotations[ingressClassAnnotation]; {
	case i.Spec.IngressClassName != nil:
		return slices.Contains(s.IngressClasses, *i.Spec.IngressClassName)
	case ok:
		return slices.Contains(s.IngressClasses, annotated)
	}
	return true
}

// ingressWays returns the ways in through an Ingress, by the name of each Service in its namespace that it routes to:
// the host of each rule that routes to the Service, on port 443 when the Ingress's TLS names it, and else on port 80,
// as the Ingress API documents its two ports; and, for a rule without a host and for the default backend, the
// addresses of the Ingress's status, without a port, since the status doesn't say which. A backend that is a resource
// of another kind is no Service, and no pod of the cluster's.
func ingressWays(i *networkingv1.Ingress) map[string]*exposer {
	status := make([]string, 0, 2*len(i.Status.LoadBalancer.Ingress))
	for _, ingress := range i.Status.LoadBalancer.Ingress {
		status = append(status, ingress.IP, ingress.Hostname)
	}
	ways := map[string]*exposer{}
	way := func(backend *networkingv1.IngressServiceBackend, host string) {
		if backend == nil {
			return
		}
		e := ways[backend.Name]
		if e == nil {
			e = &exposer{ref: objectRef(networkingv1.GroupName, kindIngress, i.Namespace, i.Name)}
			ways[backend.Name] = e
		}
		switch {
		case host == "":
			e.way(nil, status, 0, "")
		case onTLS(host, i.Spec.TLS):
			e.way(nil, []string{host}, httpsPort, tcp)
		default:
			e.way(nil, []string{host}, httpPort, tcp)
		}
	}
	if b := i.Spec.DefaultBackend; b != nil {
		way(b.Service, "")
	}
	for _, rule := range i.Spec.Rules {
		if rule.HTTP == nil {
			continue
		}
		for _, path := range rule.HTTP.Paths {
			way(path.Backend.Service, rule.Host)
		}
	}
	return ways
}

// The ports of an Ingress's hosts, as the Ingress API documents them: HTTPS for a host that its TLS names, and HTTP
// for the others.
const httpsPort, httpPort = 443, 80

// tcp is the protocol of an entry point that Kubernetes defaults, and that of every listener's transport but UDP's.
const tcp = string(corev1.ProtocolTCP)

// The types of a Gateway's addresses that a source can look up: an IP address, which is the default, and a hostname.
const addressTypeIP, addressTypeHostname = "IPAddress", "Hostname"

// onTLS reports whether an entry of an Ingress's TLS names the host: the host itself, or a wildcard that stands for
// its first label, as in a certificate. Host names compare without regard to case.
func onTLS(host string, tls []networkingv1.IngressTLS) bool {
	_, parent, _ := strings.Cut(host, ".")
	return slices.ContainsFunc(tls, func(entry networkingv1.IngressTLS) bool {
		return slices.ContainsFunc(entry.Hosts, func(name string) bool {
			return strings.EqualFold(name, host) || (parent != "" && strings.EqualFold(name, "*."+parent))
		})
	})
}

// gatewayCounts reports whether the settings count the Gateway: every Gateway counts without a list of Gateways.
func gatewayCounts(gateway namespaced, s settings) bool {
	return len(s.Gateways) == 0 || slices.Contains(s.Gateways, gateway)
}

// attachment is a listener of a Gateway that a route attaches to: the Gateway, by namespace and name, and the
// listener, as the Gateway holds it.
type attachment struct {
	gateway  namespaced
	listener map[string]any
}

// attached returns the listeners that a route of the kind in routeNamespace attaches to, through its parentRefs, of
// the Gateways that the settings count, and whether a parentRef is of a kind that the collector can't read. The route
// attaches to a listener as the Gateway API has it: the Gateway exists, and the listener, among those that the
// parentRef names, by its section name or its port, or all of them when it names none, allows routes of the route's
// namespace and kind. The listener's hostname isn't matched against the route's, and a listener that names no kinds
// allows every kind, whatever its protocol, which errs towards urgency.
//
// A parentRef to a Service attaches the route to a mesh, whose traffic comes from inside the cluster. A parentRef to
// a kind that the collector doesn't read, such as a ListenerSet, may attach the route to any Gateway: the route
// counts, unseen, unless it attaches to a listener that the collector reads.
func attached(parentRefs []any, routeNamespace, routeKind string, gateways map[namespaced]map[string]any,
	s settings, namespaces namespaceLabels) (attachments []attachment, unseen bool) {
	for _, raw := range parentRefs {
		ref, ok := raw.(map[string]any)
		if !ok {
			unseen = true
			continue
		}
		group, kind := stringOf(ref, "group", gatewayGroup), stringOf(ref, "kind", kindGateway)
		switch {
		case group == "" && kind == kindService:
			continue
		case group != gatewayGroup || kind != kindGateway:
			unseen = true
			continue
		}
		name := namespaced{Namespace: stringOf(ref, "namespace", routeNamespace), Name: stringOf(ref, nameField, "")}
		gateway, exists := gateways[name]
		if !exists || !gatewayCounts(name, s) {
			continue
		}
		for _, listener := range listenersAllowing(gateway, name.Namespace, ref, routeNamespace, routeKind, namespaces) {
			attachments = append(attachments, attachment{gateway: name, listener: listener})
		}
	}
	return attachments, unseen
}

// listenersAllowing returns the listeners of the Gateway in gatewayNamespace, among those that the parentRef names,
// that allow a route of the kind in routeNamespace.
func listenersAllowing(gateway map[string]any, gatewayNamespace string, ref map[string]any, routeNamespace,
	routeKind string, namespaces namespaceLabels) []map[string]any {
	var allowing []map[string]any
	section, bySection := ref["sectionName"].(string)
	port, byPort := numberOf(ref["port"])
	for _, raw := range sliceOf(gateway, "spec", "listeners") {
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
			allowing = append(allowing, listener)
		}
	}
	return allowing
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
// when it lists none, where the Gateway API decides by the listener's protocol, which this doesn't check.
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

// routeWays returns the ways in through a route, ref: for each listener that it attaches to, its hostnames, or without
// any, the listener's hostname, or without that, the addresses of the Gateway's status, each on the listener's port,
// with the protocol of its transport, and with the Gateway as its parentRef. The route's hostnames aren't matched
// against the listener's, as attached doesn't match them: a hostname too many only asks a source about more. A
// NamedAddress, or an address of a type of an implementation's own, is no address that a source can look up. Through
// a parentRef of a kind that the collector doesn't read, which is unseen, the route is reached on its hostnames, on a
// port that the collector can't know, and without hostnames on nothing that it can name.
func routeWays(ref evidence.ObjectRef, route *unstructured.Unstructured, attachments []attachment, unseen bool,
	gateways map[namespaced]map[string]any) exposer {
	var hostnames []string
	for _, raw := range sliceOf(route.Object, "spec", "hostnames") {
		if hostname, ok := raw.(string); ok {
			hostnames = append(hostnames, hostname)
		}
	}
	e := exposer{ref: ref}
	for _, a := range attachments {
		parent := objectRef(gatewayGroup, kindGateway, a.gateway.Namespace, a.gateway.Name)
		number, _ := numberOf(a.listener["port"])
		port, protocol := int32(number), listenerProtocol(stringOf(a.listener, "protocol", ""))
		switch hostname := stringOf(a.listener, "hostname", ""); {
		case len(hostnames) > 0:
			e.way(&parent, hostnames, port, protocol)
		case hostname != "":
			e.way(&parent, []string{hostname}, port, protocol)
		default:
			var addresses []string
			named := false
			for _, raw := range sliceOf(gateways[a.gateway], "status", "addresses") {
				address, _ := raw.(map[string]any)
				switch stringOf(address, "type", addressTypeIP) {
				case addressTypeIP, addressTypeHostname:
					addresses = append(addresses, stringOf(address, "value", ""))
				default:
					named = true
				}
			}
			if named {
				e.unchecked = append(e.unchecked, evidence.UncheckedNotASubject)
			}
			if len(addresses) > 0 || !named {
				e.way(&parent, addresses, port, protocol)
			}
		}
	}
	if unseen {
		e.way(nil, hostnames, 0, "")
	}
	return e
}

// listenerProtocol returns the protocol of the transport of a listener of the protocol: TCP for HTTP, HTTPS, TLS and
// TCP, UDP for UDP, and none for a protocol of an implementation's own.
func listenerProtocol(protocol string) string {
	switch protocol {
	case "HTTP", "HTTPS", "TLS", tcp:
		return tcp
	case "UDP":
		return string(corev1.ProtocolUDP)
	}
	return ""
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

// exposer is an object that exposes the pods behind it, with its ways in: the entry points through it, and why a way
// in through it can't be asked about.
type exposer struct {
	ref         evidence.ObjectRef
	entryPoints []evidence.EntryPoint
	unchecked   []string
}

// way adds the way in through the exposer, and parent for a route, on the addresses, with the port and the protocol,
// or none for port 0: an entry point of the addresses that make subjects, sorted, with their subjects, at most
// evidence.MaxEntryPointAddresses of them. It records what keeps a source from being asked about the way in: no
// address, an address that makes no subject, and the addresses past the cap.
func (e *exposer) way(parent *evidence.ObjectRef, addresses []string, port int32, protocol string) {
	// An entry of a load balancer's status sets an IP or a hostname, and leaves the other empty.
	addresses = slices.DeleteFunc(slices.Sorted(slices.Values(addresses)), func(a string) bool { return a == "" })
	if len(addresses) == 0 {
		e.unchecked = append(e.unchecked, evidence.UncheckedNoAddress)
		return
	}
	kept, subjects, refused := evidence.EntryPointSubjects(slices.Compact(addresses), port)
	if refused > 0 {
		e.unchecked = append(e.unchecked, evidence.UncheckedNotASubject)
	}
	if len(kept) == 0 {
		return
	}
	if len(kept) > evidence.MaxEntryPointAddresses {
		kept, subjects = kept[:evidence.MaxEntryPointAddresses], subjects[:evidence.MaxEntryPointAddresses]
		e.unchecked = append(e.unchecked, evidence.UncheckedTooManyAddresses)
	}
	entryPoint := evidence.EntryPoint{Addresses: kept, ObjectRef: e.ref, ParentRef: parent, Subjects: subjects}
	if port != 0 {
		entryPoint.Port, entryPoint.Protocol = &port, protocol
	}
	e.entryPoints = append(e.entryPoints, entryPoint)
}

// compareEntryPoints orders entry points by object, port, addresses, protocol and parent. An entry point without a
// port comes first.
func compareEntryPoints(a, b evidence.EntryPoint) int {
	return cmp.Or(compareRefs(a.ObjectRef, b.ObjectRef), cmp.Compare(ptr.Deref(a.Port, 0), ptr.Deref(b.Port, 0)),
		slices.Compare(a.Addresses, b.Addresses), cmp.Compare(a.Protocol, b.Protocol),
		compareRefs(ptr.Deref(a.ParentRef, evidence.ObjectRef{}), ptr.Deref(b.ParentRef, evidence.ObjectRef{})))
}

// compareRefs orders references by API group, kind, namespace and name.
func compareRefs(a, b evidence.ObjectRef) int {
	return cmp.Or(cmp.Compare(a.APIGroup, b.APIGroup), cmp.Compare(a.Kind, b.Kind),
		cmp.Compare(a.Namespace, b.Namespace), cmp.Compare(a.Name, b.Name))
}

// trimService keeps what the collector reads of a Service: its annotations, but kubectl's copy of what it applied,
// its type, its selector, the port, the protocol and the node port of each of its ports, its external IPs, and the
// IPs and hostnames of its load balancer.
func trimService(svc *corev1.Service) *corev1.Service {
	trimmed := &corev1.Service{ObjectMeta: identity(svc.ObjectMeta), Spec: corev1.ServiceSpec{
		Type: svc.Spec.Type, Selector: svc.Spec.Selector, ExternalIPs: svc.Spec.ExternalIPs,
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
		trimmed.Spec.Ports = append(trimmed.Spec.Ports,
			corev1.ServicePort{Port: port.Port, Protocol: port.Protocol, NodePort: port.NodePort})
	}
	for _, ingress := range svc.Status.LoadBalancer.Ingress {
		trimmed.Status.LoadBalancer.Ingress = append(trimmed.Status.LoadBalancer.Ingress,
			corev1.LoadBalancerIngress{IP: ingress.IP, Hostname: ingress.Hostname})
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

// trimIngress keeps what the collector reads of an Ingress: its class, the Service of its default backend, the host
// of each of its rules with the Services that the rule routes to, the hosts of its TLS, and the IPs and hostnames of
// its load balancer.
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
	for _, rule := range i.Spec.Rules {
		kept := networkingv1.IngressRule{Host: rule.Host}
		if rule.HTTP != nil {
			kept.HTTP = &networkingv1.HTTPIngressRuleValue{}
			for _, path := range rule.HTTP.Paths {
				if path.Backend.Service != nil {
					kept.HTTP.Paths = append(kept.HTTP.Paths,
						networkingv1.HTTPIngressPath{Backend: backend(path.Backend.Service.Name)})
				}
			}
		}
		trimmed.Spec.Rules = append(trimmed.Spec.Rules, kept)
	}
	for _, tls := range i.Spec.TLS {
		trimmed.Spec.TLS = append(trimmed.Spec.TLS, networkingv1.IngressTLS{Hosts: tls.Hosts})
	}
	for _, ingress := range i.Status.LoadBalancer.Ingress {
		trimmed.Status.LoadBalancer.Ingress = append(trimmed.Status.LoadBalancer.Ingress,
			networkingv1.IngressLoadBalancerIngress{IP: ingress.IP, Hostname: ingress.Hostname})
	}
	return trimmed
}

// trimGateway keeps what the collector reads of a Gateway: the name, the hostname, the port, the protocol and the
// allowedRoutes of each listener, and the type and the value of each address of its status.
func trimGateway(u *unstructured.Unstructured) *unstructured.Unstructured {
	trimmed := trimmedIdentity(u)
	trimmed.Object["spec"] = map[string]any{"listeners": fieldsOf(sliceOf(u.Object, "spec", "listeners"),
		nameField, "hostname", "port", "protocol", "allowedRoutes")}
	trimmed.Object["status"] = map[string]any{"addresses": fieldsOf(sliceOf(u.Object, "status", "addresses"),
		"type", "value")}
	return trimmed
}

// trimRoute keeps what the collector reads of a route: its parentRefs, its hostnames, and the Services that it sends
// traffic to, each as a backendRef of one rule, which routeBackends reads as it reads the route whole.
func trimRoute(u *unstructured.Unstructured) *unstructured.Unstructured {
	trimmed := trimmedIdentity(u)
	backends := routeBackends(u)
	refs := make([]any, 0, len(backends))
	for _, backend := range backends {
		refs = append(refs, map[string]any{"group": "", "kind": kindService, "namespace": backend.Namespace,
			nameField: backend.Name})
	}
	spec := map[string]any{"parentRefs": fieldsOf(sliceOf(u.Object, "spec", "parentRefs"),
		"group", "kind", "namespace", nameField, "sectionName", "port")}
	if hostnames := sliceOf(u.Object, "spec", "hostnames"); hostnames != nil {
		spec["hostnames"] = hostnames
	}
	if len(refs) > 0 {
		spec["rules"] = []any{map[string]any{"backendRefs": refs}}
	}
	trimmed.Object["spec"] = spec
	return trimmed
}

// fieldsOf returns, of each object of list, the fields among fields that it has. It drops what isn't an object.
func fieldsOf(list []any, fields ...string) []any {
	kept := make([]any, 0, len(list))
	for _, raw := range list {
		object, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		keep := map[string]any{}
		for _, field := range fields {
			if value, ok := object[field]; ok {
				keep[field] = value
			}
		}
		kept = append(kept, keep)
	}
	return kept
}

// sortedRefs sorts refs by API group, kind, namespace and name, and drops duplicates.
func sortedRefs(refs []evidence.ObjectRef) []evidence.ObjectRef {
	slices.SortFunc(refs, compareRefs)
	return slices.Compact(refs)
}
