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
	"cmp"
	"slices"

	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/selection"
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
}

// widening is what set a workload's reach, as the workload's widenedBy names it: a rule of a policy, or a reason
// without one, each with its reason. rule is noRule where no one rule did.
type widening struct {
	kind, namespace, name string
	rule                  int32
	reason                string
}

// noRule is the rule of a widening that no one rule of its object set.
const noRule = -1

// The reasons that a workload's widenedBy gives.
const (
	reasonNoPolicy = "no policy in the namespace"
	// reasonNotSelected starts the reason of a pod that no policy of a namespace with policies selects one way:
	// ingress or egress follows.
	reasonNotSelected = "no policy selects its pods for "
	reasonHostNetwork = "on its node's network, where no policy applies"
	reasonNoPeers     = "lets in anything: the rule names no peer"
	reasonIPBlock     = "lets in an IP block, which can hold any address"
	reasonUnread      = "beyond what the collector reads, so it counts as letting in anything"
	reasonOutside     = "lets in from outside the cluster"
	reasonEveryPod    = "lets in every pod of every namespace"
	reasonNamespaces  = "lets in whole other namespaces"
	reasonPeers       = "lets in pods of other namespaces"

	// reasonNoDefaultDeny is the reason of a Cilium rule that asks for no default deny, whose rules only add to what
	// other policies let in.
	reasonNoDefaultDeny = "asks for no default deny, so it isolates none of the pods that it selects"
)

// compareWidenings orders widenings by kind, namespace, name, rule and reason.
func compareWidenings(a, b widening) int {
	return cmp.Or(cmp.Compare(a.kind, b.kind), cmp.Compare(a.namespace, b.namespace), cmp.Compare(a.name, b.name),
		cmp.Compare(a.rule, b.rule), cmp.Compare(a.reason, b.reason))
}

// trusted is an entry of the setting trustedPeers, read: what it asks of the namespaces of a peer's pods, of their
// labels, and of their service account. A field that the entry leaves out asks nothing, and is nil.
type trusted struct {
	namespaces, pods labels.Selector
	serviceAccount   *namespaced
}

// matches reports whether the entry matches every pod of the namespace name, of the labels nsLabels, that the peer
// can let in: each field that it sets matches each such pod. The entry's podSelector matches through what the peer's
// selector asks for: each of its requirements is one that the peer's selector asks for too, or more narrowly. Its
// serviceAccount matches where the selector of a Cilium policy asks for that account alone, which is no label of a
// pod: Cilium reads the account under its own key.
func (t trusted) matches(name string, nsLabels map[string]string, pe *peer) bool {
	if t.namespaces != nil && !t.namespaces.Matches(labels.Set(nsLabels)) {
		return false
	}
	asked, _ := pe.pods.Requirements()
	account := func(q labels.Requirement) bool { return pe.cilium && q.Key() == serviceAccountKey }
	alone := func(q labels.Requirement, value string) bool { return q.Values().Len() == 1 && q.Values().Has(value) }
	if sa := t.serviceAccount; sa != nil && (sa.Namespace != name || !slices.ContainsFunc(asked,
		func(q labels.Requirement) bool { return account(q) && among(q) && alone(q, sa.Name) })) {
		return false
	}
	if t.pods == nil {
		return true
	}
	wanted, _ := t.pods.Requirements()
	return !slices.ContainsFunc(wanted, func(r labels.Requirement) bool {
		return !slices.ContainsFunc(asked, func(q labels.Requirement) bool { return !account(q) && narrows(q, r) })
	})
}

// narrows reports whether the requirement q of a peer's selector lets through only labels that the requirement r of
// a trusted entry lets through: it is r, or both ask for the same key among values, q among fewer.
func narrows(q, r labels.Requirement) bool {
	return q.Equal(r) || (q.Key() == r.Key() && among(q) && among(r) && r.Values().IsSuperset(q.Values()))
}

// among reports whether the requirement asks for its key among its values.
func among(r labels.Requirement) bool {
	return r.Operator() == selection.Equals || r.Operator() == selection.In
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
	// rule is the rule of a policy that the peer is of, which a workload's widenedBy names, with a reason, where the
	// peer sets its reach.
	rule widening
	// levels are the levels of the peer for the pods of a namespace, by the namespace, once known. They depend on the
	// namespaces of the cluster and on the trusted peers, which a Watch's settings fix, and a build asks for them only
	// of the peers that it read: a change of the namespaces makes a build read every policy again.
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

// level returns how far the peer reaches the pods of the namespace own: its own namespace when it lets in no pod of
// another namespace that it selects now but those that an entry of trust matches, the whole cluster when it selects
// every pod of every namespace, whole namespaces when it selects every pod of some, and specific pods elsewhere when
// its pods' selector narrows them. Trust matches the peer's pods of another namespace only where it matches all of
// them, and a peer that it matches in part reaches as far as it would without trust. A peer outside the cluster lets
// in no pod of the cluster, and counts as the whole cluster all the same: it lets in anything from outside, and a
// lower level would make the workload look less exposed than it is. No entry of trust matches it.
func (pe *peer) level(own string, namespaces namespaceLabels, trust []trusted) level {
	if pe.outside {
		return levelCluster
	}
	if known, ok := pe.levels[own]; ok {
		return known
	}
	var l level
	switch {
	case !pe.widens(own, namespaces, trust):
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

// widens reports whether the peer lets in pods of a namespace other than own, among the namespaces that it selects
// now, that no entry of trust matches.
func (pe *peer) widens(own string, namespaces namespaceLabels, trust []trusted) bool {
	untrusted := func(name string) bool {
		return !slices.ContainsFunc(trust, func(t trusted) bool { return t.matches(name, namespaces[name], pe) })
	}
	if pe.namespaces == nil {
		return pe.namespace != own && untrusted(pe.namespace)
	}
	for name, nsLabels := range namespaces {
		if name != own && pe.namespaces.Matches(labels.Set(nsLabels)) && untrusted(name) {
			return true
		}
	}
	return false
}

// because returns the rule of the peer, with the reason that its level l gives.
func (pe *peer) because(l level) widening {
	w := pe.rule
	switch {
	case pe.outside:
		w.reason = reasonOutside
	case l == levelCluster:
		w.reason = reasonEveryPod
	case l == levelNamespaces:
		w.reason = reasonNamespaces
	default:
		w.reason = reasonPeers
	}
	return w
}

// access is what the policies of one direction let through, for a pod or the pods of a workload: anything, where open
// names why, or what their peers admit. The zero value lets nothing through.
type access struct {
	open  []widening
	peers []*peer
}

// openTo returns the access that lets anything through, for the reason that why gives.
func openTo(why widening) access { return access{open: []widening{why}} }

// anything reports whether the access lets anything through.
func (a access) anything() bool { return len(a.open) > 0 }

// union is what a and b let through together. It keeps the peers of an access that lets anything through, so that
// what set its reach names them too.
func (a access) union(b access) access {
	union := access{open: slices.Clip(a.open), peers: slices.Clip(a.peers)}
	for _, why := range b.open {
		if !slices.Contains(union.open, why) {
			union.open = append(union.open, why)
		}
	}
	for _, pe := range b.peers {
		if !slices.Contains(union.peers, pe) {
			union.peers = append(union.peers, pe)
		}
	}
	return union
}

// widest returns how far the access lets the rest of the cluster reach the pods of the namespace own, where the
// peers that an entry of trust matches widen nothing, and what set that reach: why it lets anything through, if it
// does, and the peers of the widest level. An access that lets nothing in reaches no further than its own namespace,
// and nothing widened that.
func (a access) widest(own string, namespaces namespaceLabels, trust []trusted) (level, []widening) {
	widest := levelNamespace
	if a.anything() {
		widest = levelCluster
	}
	for _, pe := range a.peers {
		widest = max(widest, pe.level(own, namespaces, trust))
	}
	if widest == levelNamespace {
		return widest, nil
	}
	why := slices.Clone(a.open)
	for _, pe := range a.peers {
		if l := pe.level(own, namespaces, trust); l == widest {
			why = append(why, pe.because(l))
		}
	}
	return widest, why
}

// admits reports whether the access lets the pod p through.
func (a access) admits(p podView, namespaces namespaceLabels) bool {
	return a.anything() || slices.ContainsFunc(a.peers, func(pe *peer) bool { return pe.admits(p, namespaces) })
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

// openPolicy is a policy that selects every pod of the namespace of why, or of the cluster for one of no namespace,
// and lets anything through both ways, for the reason that why gives: what a policy counts as when the collector
// can't tell which pods it selects.
func openPolicy(why widening) *policy {
	in, out := openTo(why), openTo(why)
	return &policy{namespace: why.namespace, pods: labels.Everything(), ingress: &in, egress: &out}
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
// through adds up: Kubernetes and Cilium both document their rules' allows as a union. A pod on its node's network
// is open both ways, whatever the policies say: the caller tells, since no policy of a pod applies to it.
func accessOf(p podView, policies []*policy, namespaces namespaceLabels) (ingress, egress access) {
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
		ingress = openTo(unselected(p.namespace, policies, ingressRules.allow))
	}
	if !isolatedOut {
		egress = openTo(unselected(p.namespace, policies, egressRules.allow))
	}
	return ingress, egress
}

// unselected is why a pod of the namespace that no policy selects the way named way is open that way: its namespace
// has no policy, or none of its policies selects the pod that way.
func unselected(namespace string, policies []*policy, way string) widening {
	why := widening{kind: namespaceKind.Kind, name: namespace, rule: noRule, reason: reasonNoPolicy}
	if slices.ContainsFunc(policies, func(pol *policy) bool { return pol.namespace == namespace }) {
		why.reason = reasonNotSelected + way
	}
	return why
}

// networkPolicy reads a NetworkPolicy. Its directions are those of its policyTypes, and without them ingress, and
// egress when it has egress rules, as Kubernetes defaults them.
func networkPolicy(np *networkingv1.NetworkPolicy) *policy {
	named := widening{kind: policyKind.Kind, namespace: np.Namespace, name: np.Name, rule: noRule}
	pods, err := metav1.LabelSelectorAsSelector(&np.Spec.PodSelector)
	if err != nil {
		// The API server validates the selector, so this doesn't happen. When it does, no one can tell which pods
		// the policy selects, and it counts for each.
		named.reason = reasonUnread
		return openPolicy(named)
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
		in := networkAccess(named, rules)
		pol.ingress = &in
	}
	if egress {
		rules := make([][]networkingv1.NetworkPolicyPeer, 0, len(np.Spec.Egress))
		for _, rule := range np.Spec.Egress {
			rules = append(rules, rule.To)
		}
		out := networkAccess(named, rules)
		pol.egress = &out
	}
	return pol
}

// networkAccess is what the rules of the NetworkPolicy that named names let through, each rule as its peers. A rule
// without peers lets anything through, as the API says. An IP block lets anything through too: it can hold the
// addresses of pods, of nodes and of anything outside, which the collector can't tell apart. The rules' ports narrow
// nothing here: a peer that may reach one port reaches the workload.
func networkAccess(named widening, rules [][]networkingv1.NetworkPolicyPeer) access {
	var a access
	for i, peers := range rules {
		rule := named
		rule.rule = int32(i)
		if len(peers) == 0 {
			rule.reason = reasonNoPeers
			a = a.union(openTo(rule))
		}
		for _, np := range peers {
			pe, why := networkPeer(named.namespace, np)
			if why != "" {
				open := rule
				open.reason = why
				a = a.union(openTo(open))
				continue
			}
			pe.rule = rule
			a.peers = append(a.peers, pe)
		}
	}
	return a
}

// networkPeer reads a peer of a NetworkPolicy in the namespace, or returns why it may be anything: an IP block, or a
// peer that names nothing, which the API server refuses.
func networkPeer(namespace string, np networkingv1.NetworkPolicyPeer) (*peer, string) {
	switch {
	case np.IPBlock != nil:
		return nil, reasonIPBlock
	case np.PodSelector == nil && np.NamespaceSelector == nil:
		return nil, reasonUnread
	}
	pe := &peer{namespace: namespace, pods: labels.Everything()}
	if np.PodSelector != nil {
		pods, err := metav1.LabelSelectorAsSelector(np.PodSelector)
		if err != nil {
			return nil, reasonUnread
		}
		pe.pods = pods
	}
	if np.NamespaceSelector != nil {
		namespaces, err := metav1.LabelSelectorAsSelector(np.NamespaceSelector)
		if err != nil {
			return nil, reasonUnread
		}
		pe.namespaces = namespaces
	}
	return pe, ""
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
