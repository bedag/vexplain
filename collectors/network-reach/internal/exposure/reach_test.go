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
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	"github.com/bedag/vexplain/sdk/evidence"
)

// The ingress policies that select a workload's pods decide how far the rest of the cluster reaches it: its own
// namespace, specific pods elsewhere, whole namespaces, or the whole cluster. A namespace selector counts the
// namespaces that it selects now. What no policy can narrow, and what the collector can't tell apart from anything,
// counts as the whole cluster.
func TestTheIngressPoliciesThatSelectAWorkloadDecideItsInternalReach(t *testing.T) {
	another, third := newNamespace(t, nil).Name, newNamespace(t, nil).Name
	type reachCase struct {
		name string
		// spec is the spec of the policy in the workload's namespace own, or nil for none.
		spec        func(own string) *networkingv1.NetworkPolicySpec
		hostNetwork bool
		want        string
	}
	from := func(peers ...networkingv1.NetworkPolicyPeer) func(string) *networkingv1.NetworkPolicySpec {
		return func(string) *networkingv1.NetworkPolicySpec { spec := ingressFrom(web, peers...); return &spec }
	}
	nothingIn := func(string) *networkingv1.NetworkPolicySpec {
		return &networkingv1.NetworkPolicySpec{
			PodSelector: *selecting(web), PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
		}
	}
	cases := []reachCase{
		{name: "no policy gives Cluster", want: reachCluster},
		{name: "a policy for its own namespace only gives Namespace",
			spec: from(networkingv1.NetworkPolicyPeer{PodSelector: &metav1.LabelSelector{}}), want: reachNamespace},
		{name: "one peer in another namespace gives Peers", spec: from(networkingv1.NetworkPolicyPeer{
			NamespaceSelector: namespaceNamed(another), PodSelector: selecting("client"),
		}), want: reachPeers},
		{name: "two namespaces give Namespaces", spec: from(networkingv1.NetworkPolicyPeer{
			NamespaceSelector: namespaceNamed(another, third),
		}), want: reachNamespaces},
		{name: "a policy that lets nothing in gives Namespace", spec: nothingIn, want: reachNamespace},
		{name: "a namespace selector of its own namespace alone gives Namespace",
			spec: func(own string) *networkingv1.NetworkPolicySpec {
				spec := ingressFrom(web, networkingv1.NetworkPolicyPeer{NamespaceSelector: namespaceNamed(own)})
				return &spec
			}, want: reachNamespace},
		{name: "a namespace selector that selects no namespace lets nothing in", spec: from(networkingv1.NetworkPolicyPeer{
			NamespaceSelector: namespaceNamed("no-such-namespace"),
		}), want: reachNamespace},
		{name: "specific pods of every namespace give Peers", spec: from(networkingv1.NetworkPolicyPeer{
			NamespaceSelector: &metav1.LabelSelector{}, PodSelector: selecting("monitoring"),
		}), want: reachPeers},
		{name: "every pod of every namespace gives Cluster", spec: from(networkingv1.NetworkPolicyPeer{
			NamespaceSelector: &metav1.LabelSelector{},
		}), want: reachCluster},
		{name: "a rule that names no peer lets anything in", spec: from(), want: reachCluster},
		{name: "an IP block lets anything in", spec: from(networkingv1.NetworkPolicyPeer{
			IPBlock: &networkingv1.IPBlock{CIDR: testNet},
		}), want: reachCluster},
		{name: "a policy for egress alone leaves the reach at Cluster", spec: func(string) *networkingv1.NetworkPolicySpec {
			return &networkingv1.NetworkPolicySpec{
				PodSelector: *selecting(web), PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeEgress},
			}
		}, want: reachCluster},
		{name: "a pod on its node's network is reached from the whole cluster, whatever the policies say",
			spec: nothingIn, hostNetwork: true, want: reachCluster},
	}
	subjects := make([]string, len(cases))
	for i, tc := range cases {
		ns := newNamespace(t, nil).Name
		pod := podOf(ns, web, map[string]string{appLabel: web})
		pod.Spec.HostNetwork = tc.hostNetwork
		create(t, pod)
		subjects[i] = podSubject(ns, web)
		if tc.spec != nil {
			createPolicy(t, ns, web, *tc.spec(ns))
		}
	}

	sink := watch(t, newWatcher(t), "")

	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, sink.inSnapshot(t, subjects[i]).InternalReach)
		})
	}
}

// A backend whose ingress policy lets in the pods of an externally exposed frontend is indirectly exposed: one hop
// behind the frontend.
func TestABackendThatAnExposedFrontendReachesIsIndirect(t *testing.T) {
	ns := newNamespace(t, nil).Name
	front, back := bare(t, ns, frontend), bare(t, ns, backend)
	service(t, ns, frontend, corev1.ServiceTypeLoadBalancer, frontend, nil, false)
	createPolicy(t, ns, backend, ingressFrom(backend, networkingv1.NetworkPolicyPeer{PodSelector: selecting(frontend)}))

	sink := watch(t, newWatcher(t), "")

	require.True(t, sink.inSnapshot(t, front).External.Exposed)
	require.True(t, sink.inSnapshot(t, back).Indirect)
}

// A backend whose ingress policy lets in other pods, but not the exposed frontend's, is not indirectly exposed.
func TestABackendWhoseIngressPolicyBlocksTheFrontendIsNotIndirect(t *testing.T) {
	ns := newNamespace(t, nil).Name
	front, back := bare(t, ns, frontend), bare(t, ns, backend)
	service(t, ns, frontend, corev1.ServiceTypeLoadBalancer, frontend, nil, false)
	createPolicy(t, ns, backend, ingressFrom(backend, networkingv1.NetworkPolicyPeer{PodSelector: selecting("admin")}))

	sink := watch(t, newWatcher(t), "")

	require.True(t, sink.inSnapshot(t, front).External.Exposed)
	require.False(t, sink.inSnapshot(t, back).Indirect)
}

// The egress policies of an exposed frontend count too: a backend that lets the frontend in, but that the frontend's
// egress doesn't let it reach, is not indirectly exposed, while one that it does let it reach is.
func TestAFrontendWhoseEgressPolicyBlocksABackendLeavesItNotIndirect(t *testing.T) {
	ns := newNamespace(t, nil).Name
	bare(t, ns, frontend)
	blocked, reached := bare(t, ns, backend), bare(t, ns, "cache")
	service(t, ns, frontend, corev1.ServiceTypeLoadBalancer, frontend, nil, false)
	for _, name := range []string{backend, "cache"} {
		createPolicy(t, ns, name, ingressFrom(name, networkingv1.NetworkPolicyPeer{PodSelector: selecting(frontend)}))
	}
	createPolicy(t, ns, frontend, networkingv1.NetworkPolicySpec{
		PodSelector: *selecting(frontend),
		PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeEgress},
		Egress: []networkingv1.NetworkPolicyEgressRule{{
			To: []networkingv1.NetworkPolicyPeer{{PodSelector: selecting("cache")}},
		}},
	})

	sink := watch(t, newWatcher(t), "")

	require.False(t, sink.inSnapshot(t, blocked).Indirect)
	require.True(t, sink.inSnapshot(t, reached).Indirect)
}

// A workload that is exposed itself is not indirectly exposed through its own pods: indirect exposure needs another
// workload.
func TestAnExposedWorkloadIsNotIndirectThroughItself(t *testing.T) {
	ns := newNamespace(t, nil).Name
	front := bare(t, ns, frontend)
	service(t, ns, frontend, corev1.ServiceTypeLoadBalancer, frontend, nil, false)
	createPolicy(t, ns, frontend, ingressFrom(frontend, networkingv1.NetworkPolicyPeer{PodSelector: selecting(frontend)}))

	sink := watch(t, newWatcher(t), "")

	require.True(t, sink.inSnapshot(t, front).External.Exposed)
	require.False(t, sink.inSnapshot(t, front).Indirect)
}

// A frontend in another namespace makes a backend indirectly exposed, and once nothing exposes the frontend any more,
// the backend gets a change that says it isn't, though nothing changed in its own namespace.
func TestIndirectExposureFollowsAFrontendInAnotherNamespace(t *testing.T) {
	frontNS, backNS := newNamespace(t, nil).Name, newNamespace(t, nil).Name
	bare(t, frontNS, frontend)
	back := bare(t, backNS, backend)
	exposing := service(t, frontNS, frontend, corev1.ServiceTypeLoadBalancer, frontend, nil, false)
	createPolicy(t, backNS, backend, ingressFrom(backend, networkingv1.NetworkPolicyPeer{
		NamespaceSelector: namespaceNamed(frontNS), PodSelector: selecting(frontend),
	}))
	sink := watch(t, newWatcher(t), "")
	require.True(t, sink.inSnapshot(t, back).Indirect)

	remove(t, exposing)

	require.False(t, dataOf(t, sink.nextChange(t, back, 0)).Indirect)
}

// A change of a backend's ingress policy that lets an exposed frontend in makes the backend indirectly exposed.
func TestAPolicyThatStartsToLetTheFrontendInMakesTheBackendIndirect(t *testing.T) {
	ns := newNamespace(t, nil).Name
	bare(t, ns, frontend)
	back := bare(t, ns, backend)
	service(t, ns, frontend, corev1.ServiceTypeLoadBalancer, frontend, nil, false)
	p := createPolicy(t, ns, backend,
		ingressFrom(backend, networkingv1.NetworkPolicyPeer{PodSelector: selecting("admin")}))
	sink := watch(t, newWatcher(t), "")
	require.False(t, sink.inSnapshot(t, back).Indirect)

	p.Spec = ingressFrom(backend, networkingv1.NetworkPolicyPeer{PodSelector: selecting(frontend)})
	rewrite(t, p)

	require.True(t, dataOf(t, sink.nextChange(t, back, 0)).Indirect)
}

// A change of a namespace's labels changes what selects it: a backend whose policy lets in the frontends of the
// namespaces of a label becomes indirectly exposed once the exposed frontend's namespace gets the label.
func TestANamespaceThatGetsALabelIsSelectedByIt(t *testing.T) {
	front := newNamespace(t, nil)
	backNS := newNamespace(t, nil).Name
	bare(t, front.Name, frontend)
	back := bare(t, backNS, backend)
	service(t, front.Name, frontend, corev1.ServiceTypeLoadBalancer, frontend, nil, false)
	createPolicy(t, backNS, backend, ingressFrom(backend, networkingv1.NetworkPolicyPeer{
		NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{tierLabel: frontend}},
		PodSelector:       selecting(frontend),
	}))
	sink := watch(t, newWatcher(t), "")
	require.False(t, sink.inSnapshot(t, back).Indirect)

	front.Labels = map[string]string{tierLabel: frontend}
	rewrite(t, front)

	require.True(t, dataOf(t, sink.nextChange(t, back, 0)).Indirect)
}

// A workload that a host port exposes is a frontend like any other: a backend whose ingress lets its pods in is
// indirectly exposed.
func TestABackendThatAHostPortFrontendReachesIsIndirect(t *testing.T) {
	ns := newNamespace(t, nil).Name
	pod := podOf(ns, frontend, map[string]string{appLabel: frontend})
	withHostPort(pod)
	create(t, pod)
	back := bare(t, ns, backend)
	createPolicy(t, ns, backend, ingressFrom(backend, networkingv1.NetworkPolicyPeer{PodSelector: selecting(frontend)}))

	sink := watch(t, newWatcher(t), "")

	require.True(t, sink.inSnapshot(t, podSubject(ns, frontend)).External.Exposed)
	require.True(t, sink.inSnapshot(t, back).Indirect)
}

// trusting returns the settings that trust every pod of the namespaces of the names.
func trusting(names ...string) string {
	raw, err := json.Marshal(map[string]any{"trustedPeers": []any{map[string]any{
		"namespaceSelector": namespaceNamed(names...),
	}}})
	if err != nil {
		panic(err)
	}
	return string(raw)
}

// withRules is the spec of a policy that selects the pods labelled app: name and lets in what its rules' peers admit,
// each rule with the peers of one entry.
func withRules(name string, peers ...[]networkingv1.NetworkPolicyPeer) networkingv1.NetworkPolicySpec {
	spec := networkingv1.NetworkPolicySpec{
		PodSelector: *selecting(name), PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
	}
	for _, from := range peers {
		spec.Ingress = append(spec.Ingress, networkingv1.NetworkPolicyIngressRule{From: from})
	}
	return spec
}

// A policy that lets in a namespace that the settings trust, such as an ingress controller's, doesn't widen the reach:
// a workload that only its own namespace and the trusted one reach is reached from its namespace alone, which SSVC
// calls Small, while no exposed workload reaches it. A rule that lets in a namespace that isn't trusted still widens
// the reach, and widenedBy names that rule alone.
func TestAPolicyThatLetsInATrustedNamespaceDoesntWidenTheReach(t *testing.T) {
	trusted, untrusted, ns := newNamespace(t, nil).Name, newNamespace(t, nil).Name, newNamespace(t, nil).Name
	small, mixed := bare(t, ns, "small"), bare(t, ns, "mixed")
	createPolicy(t, ns, "small", ingressFrom("small", networkingv1.NetworkPolicyPeer{
		NamespaceSelector: namespaceNamed(trusted),
	}))
	createPolicy(t, ns, "mixed", withRules("mixed",
		[]networkingv1.NetworkPolicyPeer{{NamespaceSelector: namespaceNamed(trusted)}},
		[]networkingv1.NetworkPolicyPeer{{NamespaceSelector: namespaceNamed(untrusted)}}))

	withoutTrust := watch(t, newWatcher(t), "")
	sink := watch(t, newWatcher(t), trusting(trusted))

	require.Equal(t, reachNamespaces, withoutTrust.inSnapshot(t, small).InternalReach)
	require.Equal(t, evidence.Exposure{InternalReach: reachNamespace}, sink.inSnapshot(t, small),
		"reached from its namespace alone, by no exposed workload: Small")
	require.Equal(t, evidence.Exposure{InternalReach: reachNamespaces, WidenedBy: []evidence.Widening{{
		Kind: policyKind.Kind, Namespace: ns, Name: "mixed", Rule: ptr.To[int32](1), Reason: reasonNamespaces,
	}}}, sink.inSnapshot(t, mixed))
}

// Trust only keeps a rule from widening the reach, and narrows nothing that something else sets. Settings that trust
// every pod of the cluster leave the reach Cluster where no policy selects the pods, where a rule names no peer, where
// a rule lets in an ipBlock, which can hold any address, and for a pod on its node's network, where no policy applies.
// The rule that lets in every pod of every namespace is the one that they keep from widening the reach.
func TestTrustNarrowsNothingThatSomethingElseSets(t *testing.T) {
	type trustCase struct {
		name        string
		peers       []networkingv1.NetworkPolicyPeer
		policy      bool
		hostNetwork bool
		want        string
	}
	cases := []trustCase{
		{name: "no policy", want: reachCluster},
		{name: "a rule without peers", policy: true, want: reachCluster},
		{name: "an ipBlock", policy: true, peers: []networkingv1.NetworkPolicyPeer{{
			IPBlock: &networkingv1.IPBlock{CIDR: testNet},
		}}, want: reachCluster},
		{name: "a pod on its node's network", policy: true, peers: []networkingv1.NetworkPolicyPeer{{
			PodSelector: &metav1.LabelSelector{},
		}}, hostNetwork: true, want: reachCluster},
		{name: "every pod of every namespace", policy: true, peers: []networkingv1.NetworkPolicyPeer{{
			NamespaceSelector: &metav1.LabelSelector{},
		}}, want: reachNamespace},
	}
	subjects := make([]string, len(cases))
	for i, tc := range cases {
		ns := newNamespace(t, nil).Name
		pod := podOf(ns, web, map[string]string{appLabel: web})
		pod.Spec.HostNetwork = tc.hostNetwork
		create(t, pod)
		subjects[i] = podSubject(ns, web)
		if tc.policy {
			createPolicy(t, ns, web, withRules(web, tc.peers))
		}
	}

	sink := watch(t, newWatcher(t), `{"trustedPeers": [{"namespaceSelector": {}}]}`)

	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, sink.inSnapshot(t, subjects[i]).InternalReach)
		})
	}
}

// A trusted ingress controller still exposes what it routes to: a backend that lets in the trusted namespace of an
// ingress controller that faces outside is reached from its own namespace alone, and indirectly exposed.
func TestATrustedIngressControllerStillMakesItsBackendsIndirect(t *testing.T) {
	ingressNamespace, ns := newNamespace(t, nil).Name, newNamespace(t, nil).Name
	controller := bare(t, ingressNamespace, "controller")
	service(t, ingressNamespace, "controller", corev1.ServiceTypeLoadBalancer, "controller", nil, false)
	back := bare(t, ns, backend)
	createPolicy(t, ns, backend, ingressFrom(backend, networkingv1.NetworkPolicyPeer{
		NamespaceSelector: namespaceNamed(ingressNamespace),
	}))

	sink := watch(t, newWatcher(t), trusting(ingressNamespace))

	require.True(t, sink.inSnapshot(t, controller).External.Exposed)
	require.Equal(t, evidence.Exposure{InternalReach: reachNamespace, Indirect: true}, sink.inSnapshot(t, back))
}

// widenedBy names what set a workload's reach: of a policy whose rules let in its own namespace and every pod of every
// namespace, the second rule; in a namespace without a policy, the namespace, which has none; in a namespace whose
// policies select other pods, the namespace, where none selects the workload's; and for a pod on its node's network,
// its workload, which no policy applies to.
func TestWidenedByNamesWhatSetTheReach(t *testing.T) {
	ruled, none, others := newNamespace(t, nil).Name, newNamespace(t, nil).Name, newNamespace(t, nil).Name
	ruledSubject, noneSubject, othersSubject := bare(t, ruled, web), bare(t, none, web), bare(t, others, web)
	onNode := newNamespace(t, nil).Name
	host := deploymentOf(t, onNode, web, func(pod *corev1.Pod) { pod.Spec.HostNetwork = true })
	createPolicy(t, ruled, web, withRules(web,
		[]networkingv1.NetworkPolicyPeer{{PodSelector: &metav1.LabelSelector{}}},
		[]networkingv1.NetworkPolicyPeer{{NamespaceSelector: &metav1.LabelSelector{}}}))
	createPolicy(t, others, "admin", ingressFrom("admin", networkingv1.NetworkPolicyPeer{
		PodSelector: &metav1.LabelSelector{},
	}))

	sink := watch(t, newWatcher(t), "")

	require.Equal(t, []evidence.Widening{{
		Kind: policyKind.Kind, Namespace: ruled, Name: web, Rule: ptr.To[int32](1), Reason: reasonEveryPod,
	}}, sink.inSnapshot(t, ruledSubject).WidenedBy)
	require.Equal(t, []evidence.Widening{{Kind: namespaceKind.Kind, Name: none, Reason: reasonNoPolicy}},
		sink.inSnapshot(t, noneSubject).WidenedBy)
	require.Equal(t, []evidence.Widening{{Kind: namespaceKind.Kind, Name: others, Reason: reasonNotSelected + "ingress"}},
		sink.inSnapshot(t, othersSubject).WidenedBy)
	require.Equal(t, []evidence.Widening{{Kind: "Deployment", Namespace: onNode, Name: web, Reason: reasonHostNetwork}},
		sink.inSnapshot(t, host).WidenedBy)
}

// unseen names what the collector couldn't evaluate, which narrows nothing: a policy's ipBlock, which can hold any
// address, lets in anything, and a route whose parent is of a kind that the collector doesn't read, such as a
// ListenerSet, may attach to a Gateway that faces outside, so it exposes its backend. A route that attaches to a
// Gateway that counts exposes its backend whatever its other parents are, and leaves nothing unseen.
func TestUnseenNamesAnIPBlockAndAnUnknownParentRef(t *testing.T) {
	ns := newNamespace(t, nil).Name
	blocked := bare(t, ns, "blocked")
	createPolicy(t, ns, "blocked", ingressFrom("blocked", networkingv1.NetworkPolicyPeer{
		IPBlock: &networkingv1.IPBlock{CIDR: testNet},
	}))
	gateway(t, ns, web, "")
	for name, parents := range map[string]string{
		"unread": "[{kind: ListenerSet, name: shared-extra}]",
		"both":   "[{kind: ListenerSet, name: shared-extra}, {name: " + web + "}]",
	} {
		bare(t, ns, name)
		service(t, ns, name, corev1.ServiceTypeClusterIP, name, nil, false)
		fromYAML(t, "apiVersion: "+gatewayAPIVersion+"\nkind: HTTPRoute\nmetadata: {namespace: "+ns+", name: "+name+
			"}\nspec:\n  parentRefs: "+parents+"\n  rules: [{backendRefs: [{name: "+name+", port: 80}]}]\n")
	}

	sink := watch(t, newWatcher(t), "")

	got := sink.inSnapshot(t, blocked)
	require.Equal(t, reachCluster, got.InternalReach)
	require.Equal(t, []evidence.Widening{{
		Kind: policyKind.Kind, Namespace: ns, Name: "blocked", Rule: ptr.To[int32](0), Reason: reasonIPBlock,
	}}, got.WidenedBy)
	require.Equal(t, []string{evidence.UnseenIPBlock}, got.Unseen)
	unread := sink.inSnapshot(t, podSubject(ns, "unread"))
	require.True(t, unread.External.Exposed)
	require.Equal(t, []string{evidence.UnseenUnknownParentRef}, unread.Unseen)
	both := sink.inSnapshot(t, podSubject(ns, "both"))
	require.True(t, both.External.Exposed)
	require.Empty(t, both.Unseen)
}
