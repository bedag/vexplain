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
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/selection"
)

// The collector reads Cilium's CiliumNetworkPolicy and CiliumClusterwideNetworkPolicy as unstructured objects, so that
// it needs none of Cilium's code. It reads a subset of Cilium's policy model: endpoint selectors, and the entities
// world and cluster. A rule that goes beyond lets anything through, as far as the collector can tell, which errs
// towards urgency. The rules' ports, ICMP types and authentication narrow what a peer may do, and not which peers may:
// the collector counts a peer that may do one thing as one that reaches the workload.

// Cilium's policies: their API group, and their kinds.
const (
	ciliumGroup           = "cilium.io"
	ciliumPolicyKind      = "CiliumNetworkPolicy"
	clusterwidePolicyKind = "CiliumClusterwideNetworkPolicy"
)

// The keys of Cilium's labels that are no labels of a pod.
const (
	// ciliumNamespaceKey selects a pod's namespace by its name.
	ciliumNamespaceKey = "io.kubernetes.pod.namespace"
	// ciliumNamespaceLabelPrefix starts a key that selects a pod's namespace by one of its labels: the key of the
	// namespace's label follows it.
	ciliumNamespaceLabelPrefix = "io.cilium.k8s.namespace.labels."
	// serviceAccountKey selects a pod by its service account.
	serviceAccountKey = "io.cilium.k8s.policy.serviceaccount"
	// ciliumKeyPrefix starts every other key that Cilium derives itself, such as the name of its cluster, which the
	// collector can't tell.
	ciliumKeyPrefix = "io.cilium."
)

// The entities of Cilium's that the collector reads.
const (
	// entityWorld is everything outside the cluster.
	entityWorld = "world"
	// entityCluster is everything in the cluster.
	entityCluster = "cluster"
)

// ciliumView is how Cilium's endpoint selectors see a pod: its labels, and its service account under
// serviceAccountKey.
type ciliumView struct {
	labels         map[string]string
	serviceAccount string
}

func (v ciliumView) Lookup(key string) (string, bool) {
	if key == serviceAccountKey {
		return v.serviceAccount, true
	}
	value, ok := v.labels[key]
	return value, ok
}

func (v ciliumView) Has(key string) bool {
	_, ok := v.Lookup(key)
	return ok
}

func (v ciliumView) Get(key string) string {
	value, _ := v.Lookup(key)
	return value
}

// direction is how a rule of Cilium's names one direction: its rules that allow, its rules that deny, the fields of
// a rule that name peers by endpoint selectors and by entities, and its field in enableDefaultDeny.
type direction struct {
	allow, deny, endpoints, entities, defaultDeny string
}

var (
	ingressRules = direction{
		allow: "ingress", deny: "ingressDeny", endpoints: "fromEndpoints", entities: "fromEntities", defaultDeny: "ingress",
	}
	egressRules = direction{
		allow: "egress", deny: "egressDeny", endpoints: "toEndpoints", entities: "toEntities", defaultDeny: "egress",
	}
)

// narrowing are the fields of a rule of Cilium's that narrow what its peers may do, and not which peers may do it.
var narrowing = map[string]bool{"toPorts": true, "icmps": true, "authentication": true}

// ciliumPolicies reads the rules of a CiliumNetworkPolicy, or of a CiliumClusterwideNetworkPolicy, which has no
// namespace: its spec and each of its specs, each as a policy. A rule that selects nodes, a policy of their hosts,
// selects no pod. A rule that the collector can't read counts as one that selects every pod that it could select,
// and lets anything through.
func ciliumPolicies(u *unstructured.Unstructured) []*policy {
	var rules []any
	if spec, ok := u.Object["spec"]; ok {
		rules = append(rules, spec)
	}
	if specs, ok := u.Object["specs"]; ok {
		list, isList := specs.([]any)
		if !isList {
			return []*policy{openPolicy(u.GetNamespace())}
		}
		rules = append(rules, list...)
	}
	policies := make([]*policy, 0, len(rules))
	for _, raw := range rules {
		rule, ok := raw.(map[string]any)
		if !ok {
			policies = append(policies, openPolicy(u.GetNamespace()))
			continue
		}
		if _, host := rule["nodeSelector"]; host {
			continue
		}
		policies = append(policies, ciliumRule(u.GetNamespace(), rule))
	}
	return policies
}

// ciliumRule reads one rule of a policy in the namespace, or of the whole cluster for an empty namespace. A rule of a
// namespaced policy selects pods of its namespace alone, as Cilium has it.
func ciliumRule(namespace string, rule map[string]any) *policy {
	namespaces, pods, ok := ciliumSelector(rule["endpointSelector"])
	if !ok {
		return openPolicy(namespace)
	}
	return &policy{
		namespace: namespace, namespaces: namespaces, pods: pods, cilium: true,
		ingress: ciliumAccess(namespace, rule, ingressRules), egress: ciliumAccess(namespace, rule, egressRules),
	}
}

// ciliumAccess reads what a rule of a policy in the namespace lets through one way, or nil when it leaves the way
// alone, as a rule does that has neither rules that allow nor rules that deny that way. A rule that denies, or that
// asks for no default deny, lets anything through as far as the collector can tell: it reads neither.
func ciliumAccess(namespace string, rule map[string]any, d direction) *access {
	allows, allowsOK := listOf(rule, d.allow)
	denies, deniesOK := listOf(rule, d.deny)
	switch {
	case !allowsOK || !deniesOK:
		return &access{anything: true}
	case len(allows) == 0 && len(denies) == 0:
		return nil
	case len(denies) > 0 || defaultDenyOff(rule, d):
		return &access{anything: true}
	}
	var a access
	for _, raw := range allows {
		r, ok := raw.(map[string]any)
		if !ok {
			return &access{anything: true}
		}
		peers, ok := ciliumPeers(namespace, r, d)
		if !ok {
			return &access{anything: true}
		}
		a.peers = append(a.peers, peers...)
	}
	return &a
}

// listOf returns the list under the key of m, which may be missing, and false when it is there and is no list.
func listOf(m map[string]any, key string) ([]any, bool) {
	value, ok := m[key]
	if !ok || value == nil {
		return nil, true
	}
	list, ok := value.([]any)
	return list, ok
}

// defaultDenyOff reports whether a rule asks that the pods it selects not be denied by default the way of d, so that
// its rules add to what other policies let through, and select no pod for it alone.
func defaultDenyOff(rule map[string]any, d direction) bool {
	settings, ok := rule["enableDefaultDeny"].(map[string]any)
	if !ok {
		return false
	}
	on, ok := settings[d.defaultDeny].(bool)
	return ok && !on
}

// ciliumPeers reads the peers of one rule that allows, of a policy in the namespace, and returns false for a rule
// that may let anything through. An empty rule lets nothing through: it is how Cilium denies a way by default without
// letting anything in. A rule without peers that narrows only ports or the like lets every peer through, as Cilium
// has it for a rule of ports alone.
func ciliumPeers(namespace string, rule map[string]any, d direction) ([]*peer, bool) {
	var peers []*peer
	named := false
	for key, value := range rule {
		switch {
		case key == d.endpoints:
			selectors, ok := value.([]any)
			if !ok {
				return nil, false
			}
			for _, selector := range selectors {
				pe, ok := ciliumPeer(namespace, selector)
				if !ok {
					return nil, false
				}
				peers = append(peers, pe)
			}
			named = named || len(selectors) > 0
		case key == d.entities:
			entities, ok := value.([]any)
			if !ok {
				return nil, false
			}
			for _, entity := range entities {
				pe, ok := entityPeer(entity)
				if !ok {
					return nil, false
				}
				peers = append(peers, pe)
			}
			named = named || len(entities) > 0
		case narrowing[key]:
		default:
			// Another way to name peers, such as CIDRs, nodes or names that DNS resolves, or a field that the
			// collector doesn't know.
			return nil, false
		}
	}
	if !named && len(rule) > 0 {
		return nil, false
	}
	return peers, true
}

// entityPeer reads an entity of Cilium's, and returns false for one beyond world and cluster.
func entityPeer(entity any) (*peer, bool) {
	switch entity {
	case entityWorld:
		return &peer{outside: true}, true
	case entityCluster:
		return &peer{namespaces: labels.Everything(), pods: labels.Everything()}, true
	}
	return nil, false
}

// ciliumPeer reads an endpoint selector of a rule of a policy in the namespace. A selector that names no namespace
// selects pods of the policy's namespace, as Cilium adds it, or of every namespace for a policy of the whole cluster.
func ciliumPeer(namespace string, selector any) (*peer, bool) {
	namespaces, pods, ok := ciliumSelector(selector)
	if !ok {
		return nil, false
	}
	if namespaces == nil && namespace == "" {
		namespaces = labels.Everything()
	}
	return &peer{namespace: namespace, namespaces: namespaces, pods: pods, cilium: true}, true
}

// ciliumSelector reads an endpoint selector into what it asks of a pod's namespace, by the namespace's labels, and
// what it asks of the pod, by Cilium's view of it. namespaces is nil for a selector that asks nothing of the
// namespace. It returns false for a selector beyond what the collector reads: a field that a selector lacks, a label
// of a source other than Kubernetes, a label that Cilium derives itself, or an operator or a value that a label
// selector can't hold.
func ciliumSelector(raw any) (namespaces, pods labels.Selector, ok bool) {
	selector, ok := raw.(map[string]any)
	if !ok {
		return nil, nil, false
	}
	var onNamespace, onPod []labels.Requirement
	add := func(key string, op selection.Operator, values []string) bool {
		target, ofNamespace, ok := ciliumKey(key)
		if !ok {
			return false
		}
		requirement, err := labels.NewRequirement(target, op, values)
		if err != nil {
			return false
		}
		if ofNamespace {
			onNamespace = append(onNamespace, *requirement)
		} else {
			onPod = append(onPod, *requirement)
		}
		return true
	}
	for field, value := range selector {
		switch field {
		case "matchLabels":
			matchLabels, ok := value.(map[string]any)
			if !ok {
				return nil, nil, false
			}
			for key, raw := range matchLabels {
				value, ok := raw.(string)
				if !ok || !add(key, selection.Equals, []string{value}) {
					return nil, nil, false
				}
			}
		case "matchExpressions":
			expressions, ok := value.([]any)
			if !ok {
				return nil, nil, false
			}
			for _, raw := range expressions {
				key, op, values, ok := expressionOf(raw)
				if !ok || !add(key, op, values) {
					return nil, nil, false
				}
			}
		default:
			return nil, nil, false
		}
	}
	if len(onNamespace) > 0 {
		namespaces = labels.NewSelector().Add(onNamespace...)
	}
	return namespaces, labels.NewSelector().Add(onPod...), true
}

// expressionOf reads an expression of an endpoint selector.
func expressionOf(raw any) (key string, op selection.Operator, values []string, ok bool) {
	expression, ok := raw.(map[string]any)
	if !ok {
		return "", "", nil, false
	}
	key, keyOK := expression["key"].(string)
	operator, opOK := expression["operator"].(string)
	if !keyOK || !opOK {
		return "", "", nil, false
	}
	op, ok = map[string]selection.Operator{
		"In": selection.In, "NotIn": selection.NotIn, "Exists": selection.Exists, "DoesNotExist": selection.DoesNotExist,
	}[operator]
	if !ok {
		return "", "", nil, false
	}
	if raw, present := expression["values"]; present && raw != nil {
		list, isList := raw.([]any)
		if !isList {
			return "", "", nil, false
		}
		for _, item := range list {
			value, isString := item.(string)
			if !isString {
				return "", "", nil, false
			}
			values = append(values, value)
		}
	}
	return key, op, values, true
}

// ciliumKey reads the key of a label of an endpoint selector: the key of the label that it asks of the pod's
// namespace or of the pod, and whether it is of the namespace. Cilium's labels may name their source, k8s or any for
// a pod's labels. It returns false for any other source, or a label that Cilium derives itself and the collector
// can't tell, such as the name of Cilium's cluster.
func ciliumKey(key string) (target string, ofNamespace, ok bool) {
	if source, rest, found := strings.Cut(key, ":"); found {
		if source != "k8s" && source != "any" {
			return "", false, false
		}
		key = rest
	}
	switch {
	case key == ciliumNamespaceKey:
		return corev1.LabelMetadataName, true, true
	case strings.HasPrefix(key, ciliumNamespaceLabelPrefix):
		return strings.TrimPrefix(key, ciliumNamespaceLabelPrefix), true, true
	case key == serviceAccountKey:
		return serviceAccountKey, false, true
	case strings.HasPrefix(key, ciliumKeyPrefix):
		return "", false, false
	}
	return key, false, true
}

// trimCilium keeps what the collector reads of a Cilium policy: its rules, all of them, so that a rule beyond the
// subset that the collector reads is there to count as one.
func trimCilium(u *unstructured.Unstructured) *unstructured.Unstructured {
	trimmed := trimmedIdentity(u)
	for _, field := range []string{"spec", "specs"} {
		if value, ok := u.Object[field]; ok {
			trimmed.Object[field] = value
		}
	}
	return trimmed
}
