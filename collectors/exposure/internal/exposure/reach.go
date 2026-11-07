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
	"slices"

	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
)

// level is how far the rest of the cluster reaches a workload, from the narrowest to the widest, so that the wider of
// two levels is the greater.
type level int

const (
	// levelNamespace is the workload's own namespace alone.
	levelNamespace level = iota
	// levelPeers is specific pods in other namespaces.
	levelPeers
	// levelNamespaces is whole other namespaces.
	levelNamespaces
	// levelCluster is the whole cluster: anything.
	levelCluster
)

// String is the level as the exposure type's internalReach names it.
func (l level) String() string {
	return [...]string{"Namespace", "Peers", "Namespaces", "Cluster"}[l]
}

// podView is what the collector reads of a pod to tell whether a policy selects it, or a peer of a policy admits it.
type podView struct {
	namespace string
	labels    map[string]string
	// serviceAccount is the pod's service account, which Cilium's endpoint selectors can select.
	serviceAccount string
	// hostNetwork says that the pod uses its node's network, where no policy of a pod applies.
	hostNetwork bool
}

// namespaceLabels are the labels of the cluster's namespaces, by name. The labels of each hold
// kubernetes.io/metadata.name, which the API server gives every namespace, and by which the collector selects a
// namespace by its name.
type namespaceLabels map[string]map[string]string

// peer is the pods that a rule of a policy lets in, or lets the policy's pods reach.
type peer struct {
	// outside is a peer outside the cluster alone, as Cilium's entity world. It admits no pod of the cluster.
	outside bool
	// namespace is the namespace of the policy, whose pods the peer admits when namespaces is nil.
	namespace string
	// namespaces selects the namespaces of the pods that the peer admits, by their labels. nil selects namespace.
	namespaces labels.Selector
	// pods selects the pods, by their labels, or, for a peer of a Cilium policy, by Cilium's view of them.
	pods   labels.Selector
	cilium bool
	// levels are the levels of the peer for the pods of a namespace, by the namespace, once known. They depend on the
	// namespaces of the cluster, and a build asks for them only of the peers that it read: a change of the namespaces
	// makes a build read every policy again.
	levels map[string]level
}

// admits reports whether the peer admits the pod p, given the namespaces of the cluster.
func (pe *peer) admits(p podView, namespaces namespaceLabels) bool {
	switch {
	case pe.outside:
		return false
	case pe.namespaces == nil && p.namespace != pe.namespace:
		return false
	case pe.namespaces != nil && !pe.namespaces.Matches(labels.Set(namespaces[p.namespace])):
		return false
	}
	return pe.pods.Matches(viewOf(p, pe.cilium))
}

// level returns how far the peer reaches the pods of the namespace own: its own namespace when every namespace that it
// selects now is own, the whole cluster when it selects every pod of every namespace, whole namespaces when it selects
// every pod of some, and specific pods elsewhere when its pods' selector narrows them. A peer outside the cluster
// lets in no pod of the cluster, and counts as the whole cluster all the same: it lets in anything from outside, and a
// lower level would make the workload look less exposed than it is.
func (pe *peer) level(own string, namespaces namespaceLabels) level {
	if pe.outside {
		return levelCluster
	}
	if known, ok := pe.levels[own]; ok {
		return known
	}
	elsewhere := pe.namespace != own
	if pe.namespaces != nil {
		elsewhere = false
		for name, nsLabels := range namespaces {
			if name != own && pe.namespaces.Matches(labels.Set(nsLabels)) {
				elsewhere = true
				break
			}
		}
	}
	var l level
	switch {
	case !elsewhere:
		l = levelNamespace
	case !pe.pods.Empty():
		l = levelPeers
	case pe.namespaces != nil && pe.namespaces.Empty():
		l = levelCluster
	default:
		l = levelNamespaces
	}
	if pe.levels == nil {
		pe.levels = map[string]level{}
	}
	pe.levels[own] = l
	return l
}

// access is what the policies of one direction let through, for a pod or the pods of a workload: anything, or what
// their peers admit. The zero value lets nothing through.
type access struct {
	anything bool
	peers    []*peer
}

// openAccess lets anything through.
var openAccess = access{anything: true}

// union is what a and b let through together.
func (a access) union(b access) access {
	if a.anything || b.anything {
		return openAccess
	}
	union := access{peers: slices.Clip(a.peers)}
	for _, pe := range b.peers {
		if !slices.Contains(union.peers, pe) {
			union.peers = append(union.peers, pe)
		}
	}
	return union
}

// reach is how far the rest of the cluster reaches the pods of the namespace own through the access, as the
// exposure type's internalReach names it.
func (a access) reach(own string, namespaces namespaceLabels) string {
	return a.level(own, namespaces).String()
}

// level is how far the access lets the rest of the cluster reach the pods of the namespace own: the widest level of
// its peers. An access that lets nothing in reaches no further than its own namespace.
func (a access) level(own string, namespaces namespaceLabels) level {
	if a.anything {
		return levelCluster
	}
	widest := levelNamespace
	for _, pe := range a.peers {
		widest = max(widest, pe.level(own, namespaces))
	}
	return widest
}

// admits reports whether the access lets the pod p through.
func (a access) admits(p podView, namespaces namespaceLabels) bool {
	return a.anything || slices.ContainsFunc(a.peers, func(pe *peer) bool { return pe.admits(p, namespaces) })
}

// admitsAny reports whether the access lets one of the pods through.
func (a access) admitsAny(pods []podView, namespaces namespaceLabels) bool {
	return slices.ContainsFunc(pods, func(p podView) bool { return a.admits(p, namespaces) })
}

// policy is a network policy as the collector reads it: the pods that it selects, and what it lets in to them and
// lets them reach.
type policy struct {
	// namespace is the namespace of the pods that the policy selects, and empty for a policy of the whole cluster.
	namespace string
	// namespaces, when set, selects the namespaces of the pods that the policy selects, by their labels.
	namespaces labels.Selector
	// pods selects the pods, by their labels, or, for a Cilium policy, by Cilium's view of them.
	pods   labels.Selector
	cilium bool
	// ingress and egress are what the policy lets in to its pods and lets them reach. Each is nil when the policy
	// leaves its direction alone.
	ingress, egress *access
}

// openPolicy is a policy that selects every pod of the namespace, or of the cluster for an empty namespace, and lets
// anything through both ways: what a policy counts as when the collector can't tell which pods it selects.
func openPolicy(namespace string) *policy {
	in, out := openAccess, openAccess
	return &policy{namespace: namespace, pods: labels.Everything(), ingress: &in, egress: &out}
}

// selects reports whether the policy selects the pod p.
func (pol *policy) selects(p podView, namespaces namespaceLabels) bool {
	switch {
	case pol.namespace != "" && p.namespace != pol.namespace:
		return false
	case pol.namespaces != nil && !pol.namespaces.Matches(labels.Set(namespaces[p.namespace])):
		return false
	}
	return pol.pods.Matches(viewOf(p, pol.cilium))
}

// accessOf returns what the policies let in to the pod p, and what they let it reach. A pod that no policy of a
// direction selects is open that way, as Kubernetes and Cilium have it, and what the policies that select it let
// through adds up: Kubernetes and Cilium both document their rules' allows as a union. A pod on its node's network is
// open both ways: no policy of a pod applies to it.
func accessOf(p podView, policies []*policy, namespaces namespaceLabels) (ingress, egress access) {
	if p.hostNetwork {
		return openAccess, openAccess
	}
	isolatedIn, isolatedOut := false, false
	for _, pol := range policies {
		if !pol.selects(p, namespaces) {
			continue
		}
		if pol.ingress != nil {
			isolatedIn = true
			ingress = ingress.union(*pol.ingress)
		}
		if pol.egress != nil {
			isolatedOut = true
			egress = egress.union(*pol.egress)
		}
	}
	if !isolatedIn {
		ingress = openAccess
	}
	if !isolatedOut {
		egress = openAccess
	}
	return ingress, egress
}

// networkPolicy reads a NetworkPolicy. Its directions are those of its policyTypes, and without them ingress, and
// egress when it has egress rules, as Kubernetes defaults them.
func networkPolicy(np *networkingv1.NetworkPolicy) *policy {
	pods, err := metav1.LabelSelectorAsSelector(&np.Spec.PodSelector)
	if err != nil {
		// The API server validates the selector, so this doesn't happen. When it does, no one can tell which pods
		// the policy selects, and it counts for each.
		return openPolicy(np.Namespace)
	}
	pol := &policy{namespace: np.Namespace, pods: pods}
	ingress, egress := len(np.Spec.PolicyTypes) == 0, len(np.Spec.PolicyTypes) == 0 && len(np.Spec.Egress) > 0
	for _, t := range np.Spec.PolicyTypes {
		ingress = ingress || t == networkingv1.PolicyTypeIngress
		egress = egress || t == networkingv1.PolicyTypeEgress
	}
	if ingress {
		rules := make([][]networkingv1.NetworkPolicyPeer, 0, len(np.Spec.Ingress))
		for _, rule := range np.Spec.Ingress {
			rules = append(rules, rule.From)
		}
		in := networkAccess(np.Namespace, rules)
		pol.ingress = &in
	}
	if egress {
		rules := make([][]networkingv1.NetworkPolicyPeer, 0, len(np.Spec.Egress))
		for _, rule := range np.Spec.Egress {
			rules = append(rules, rule.To)
		}
		out := networkAccess(np.Namespace, rules)
		pol.egress = &out
	}
	return pol
}

// networkAccess is what the rules of a NetworkPolicy in the namespace let through, each rule as its peers. A rule
// without peers lets anything through, as the API says. An IP block lets anything through too: it can hold the
// addresses of pods, of nodes and of anything outside, which the collector can't tell apart. The rules' ports narrow
// nothing here: a peer that may reach one port reaches the workload.
func networkAccess(namespace string, rules [][]networkingv1.NetworkPolicyPeer) access {
	var a access
	for _, peers := range rules {
		if len(peers) == 0 {
			return openAccess
		}
		for _, np := range peers {
			pe, ok := networkPeer(namespace, np)
			if !ok {
				return openAccess
			}
			a.peers = append(a.peers, pe)
		}
	}
	return a
}

// networkPeer reads a peer of a NetworkPolicy in the namespace, and returns false for one that may be anything: an IP
// block, or a peer that names nothing, which the API server refuses.
func networkPeer(namespace string, np networkingv1.NetworkPolicyPeer) (*peer, bool) {
	if np.IPBlock != nil || (np.PodSelector == nil && np.NamespaceSelector == nil) {
		return nil, false
	}
	pe := &peer{namespace: namespace, pods: labels.Everything()}
	if np.PodSelector != nil {
		pods, err := metav1.LabelSelectorAsSelector(np.PodSelector)
		if err != nil {
			return nil, false
		}
		pe.pods = pods
	}
	if np.NamespaceSelector != nil {
		namespaces, err := metav1.LabelSelectorAsSelector(np.NamespaceSelector)
		if err != nil {
			return nil, false
		}
		pe.namespaces = namespaces
	}
	return pe, true
}

// viewOf is how a selector sees the pod p: by its labels, or, for Cilium, by its labels and its service account.
func viewOf(p podView, cilium bool) labels.Labels {
	if cilium {
		return ciliumView{labels: p.labels, serviceAccount: p.serviceAccount}
	}
	return labels.Set(p.labels)
}

// trimNetworkPolicy keeps what the collector reads of a NetworkPolicy: the pods that it selects, its directions, and
// the peers of its rules. The rules' ports narrow nothing that the collector reads.
func trimNetworkPolicy(np *networkingv1.NetworkPolicy) *networkingv1.NetworkPolicy {
	trimmed := &networkingv1.NetworkPolicy{ObjectMeta: identity(np.ObjectMeta), Spec: networkingv1.NetworkPolicySpec{
		PodSelector: np.Spec.PodSelector, PolicyTypes: np.Spec.PolicyTypes,
	}}
	for _, rule := range np.Spec.Ingress {
		trimmed.Spec.Ingress = append(trimmed.Spec.Ingress, networkingv1.NetworkPolicyIngressRule{From: rule.From})
	}
	for _, rule := range np.Spec.Egress {
		trimmed.Spec.Egress = append(trimmed.Spec.Egress, networkingv1.NetworkPolicyEgressRule{To: rule.To})
	}
	return trimmed
}
