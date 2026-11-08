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
	"testing"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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
			IPBlock: &networkingv1.IPBlock{CIDR: "192.0.2.0/24"},
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
