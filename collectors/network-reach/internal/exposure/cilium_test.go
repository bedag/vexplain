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
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/yaml"
)

// The Cilium tests read policies from YAML, as the collector reads them from the cluster, unstructured: Cilium's CRDs
// aren't vendored, and the collector imports none of Cilium's code. The pods and namespaces are those of the
// collector's own model of a cluster.

// ciliumCluster are the namespaces of the Cilium tests, with the label that the API server gives each namespace.
var ciliumCluster = namespaceLabels{
	teamA:    {corev1.LabelMetadataName: teamA, tierLabel: web},
	teamB:    {corev1.LabelMetadataName: teamB, tierLabel: "data"},
	"team-c": {corev1.LabelMetadataName: "team-c", tierLabel: "data"},
}

// The namespaces of the web pod and of the frontend.
const teamA, teamB = "team-a", "team-b"

// The pods of the Cilium tests: the web pod in team-a, whose reach the tests read, and the frontend in team-b.
var (
	webPod      = podView{namespace: teamA, labels: map[string]string{appLabel: web}, serviceAccount: web}
	frontendPod = podView{namespace: teamB, labels: map[string]string{appLabel: frontend}, serviceAccount: frontend}
	backendPod  = podView{namespace: teamB, labels: map[string]string{appLabel: backend}, serviceAccount: backend}
)

// testPolicy is the name of the Cilium policies of the tests.
const testPolicy = "test"

// cilium reads the policies of a CiliumNetworkPolicy in team-a, or of a CiliumClusterwideNetworkPolicy when kind says
// so, whose spec is spec, as YAML indented by two spaces.
func cilium(t *testing.T, kind, spec string) []*policy {
	t.Helper()
	manifest := "apiVersion: cilium.io/v2\nkind: " + kind + "\nmetadata:\n  name: " + testPolicy + "\n"
	if kind == ciliumPolicyKind {
		manifest += "  namespace: team-a\n"
	}
	u := &unstructured.Unstructured{}
	require.NoError(t, yaml.Unmarshal([]byte(manifest+spec), &u.Object))
	return ciliumPolicies(u)
}

// webSelected is the start of a spec that selects the web pod.
const webSelected = "spec:\n  endpointSelector:\n    matchLabels:\n      app: web\n"

// reachOf is how far the access lets the rest of the cluster reach the web pod, as internalReach names it, with the
// trusted peers.
func reachOf(in access, trust ...trusted) string {
	l, _ := in.widest(webPod.namespace, ciliumCluster, trust)
	return l.String()
}

// trustOf returns the trusted peers of the settings whose trustedPeers is peers, as JSON.
func trustOf(t *testing.T, peers string) []trusted {
	t.Helper()
	s, err := readSettings(json.RawMessage(`{"trustedPeers": ` + peers + `}`))
	require.NoError(t, err)
	return s.trusted
}

// A Cilium policy decides the reach of the pods that its endpoint selector selects, as a NetworkPolicy does, with
// what Cilium means by its selectors: a selector of a namespaced policy selects pods of the policy's namespace unless
// it names a namespace or namespace labels. A rule outside what the collector reads, endpoint selectors and the
// entities world and cluster, counts as the whole cluster, and so do the entities, erring towards urgency.
func TestACiliumPolicyDecidesTheReachOfThePodsItSelects(t *testing.T) {
	for _, tc := range []struct {
		name, kind, spec, want string
	}{
		{name: "a selector without a namespace selects the policy's namespace",
			spec: webSelected + "  ingress:\n  - fromEndpoints:\n    - matchLabels:\n        app: client\n",
			want: reachNamespace},
		{name: "the policy's own namespace by name",
			spec: webSelected + "  ingress:\n  - fromEndpoints:\n    - matchLabels:\n" +
				"        k8s:io.kubernetes.pod.namespace: team-a\n",
			want: reachNamespace},
		{name: "pods of another namespace",
			spec: webSelected + "  ingress:\n  - fromEndpoints:\n    - matchLabels:\n" +
				"        k8s:io.kubernetes.pod.namespace: team-b\n        app: client\n",
			want: reachPeers},
		{name: "whole namespaces by their labels",
			spec: webSelected + "  ingress:\n  - fromEndpoints:\n    - matchLabels:\n" +
				"        io.cilium.k8s.namespace.labels.tier: data\n",
			want: reachNamespaces},
		{name: "a selector by an expression",
			spec: webSelected + "  ingress:\n  - fromEndpoints:\n    - matchExpressions:\n" +
				"      - {key: io.kubernetes.pod.namespace, operator: In, values: [team-b, team-c]}\n",
			want: reachNamespaces},
		{name: "the entity cluster", spec: webSelected + "  ingress:\n  - fromEntities: [cluster]\n",
			want: reachCluster},
		{name: "the entity world", spec: webSelected + "  ingress:\n  - fromEntities: [world]\n", want: reachCluster},
		{name: "an empty rule, Cilium's way to let nothing in", spec: webSelected + "  ingress:\n  - {}\n",
			want: reachNamespace},
		{name: "a rule of ports alone, which lets every peer in on them",
			spec: webSelected + "  ingress:\n  - toPorts:\n    - ports:\n      - {port: \"80\", protocol: TCP}\n",
			want: reachCluster},
		{name: "ports narrow nothing that a selector allows",
			spec: webSelected + "  ingress:\n  - fromEndpoints:\n    - matchLabels:\n        app: client\n" +
				"    toPorts:\n    - ports:\n      - {port: \"80\", protocol: TCP}\n",
			want: reachNamespace},
		{name: "a policy that selects other pods leaves the web pod open",
			spec: "spec:\n  endpointSelector:\n    matchLabels:\n      app: other\n  ingress:\n  - {}\n",
			want: reachCluster},
		{name: "a policy for egress alone leaves the web pod open",
			spec: webSelected + "  egress:\n  - toEndpoints:\n    - {}\n", want: reachCluster},
		{name: "a selector by the service account",
			spec: "spec:\n  endpointSelector:\n    matchLabels:\n      io.cilium.k8s.policy.serviceaccount: web\n" +
				"  ingress:\n  - fromEndpoints:\n    - matchLabels:\n        app: client\n",
			want: reachNamespace},
		{name: "every rule of specs counts",
			spec: "specs:\n- endpointSelector:\n    matchLabels:\n      app: web\n  ingress:\n  - fromEndpoints:\n" +
				"    - matchLabels:\n        app: client\n- endpointSelector:\n    matchLabels:\n      app: web\n" +
				"  ingress:\n  - fromEndpoints:\n    - matchLabels:\n        k8s:io.kubernetes.pod.namespace: team-b\n" +
				"        app: client\n",
			want: reachPeers},
		{name: "a clusterwide selector without a namespace selects pods of every namespace",
			kind: clusterwidePolicyKind,
			spec: webSelected + "  ingress:\n  - fromEndpoints:\n    - matchLabels:\n        app: client\n",
			want: reachPeers},
		{name: "a clusterwide empty selector selects every pod of every namespace",
			kind: clusterwidePolicyKind, spec: webSelected + "  ingress:\n  - fromEndpoints:\n    - {}\n",
			want: reachCluster},
		{name: "a host policy selects no pod",
			kind: clusterwidePolicyKind,
			spec: "spec:\n  nodeSelector:\n    matchLabels:\n      role: worker\n  ingress:\n  - {}\n",
			want: reachCluster},
	} {
		t.Run(tc.name, func(t *testing.T) {
			kind := tc.kind
			if kind == "" {
				kind = ciliumPolicyKind
			}
			in, _ := accessOf(webPod, cilium(t, kind, tc.spec), ciliumCluster)

			require.Equal(t, tc.want, reachOf(in))
		})
	}
}

// A rule outside the subset that the collector reads, endpoint selectors and the entities world and cluster, counts
// as the whole cluster: the collector can't tell what it lets in, and errs towards urgency.
func TestACiliumRuleOutsideTheSubsetCountsAsTheWholeCluster(t *testing.T) {
	const fromEndpoints = "  ingress:\n  - fromEndpoints:\n"
	for name, rules := range map[string]string{
		"a CIDR":                      "  ingress:\n  - fromCIDR: [192.0.2.0/24]\n",
		"a set of CIDRs":              "  ingress:\n  - fromCIDRSet:\n    - cidr: 192.0.2.0/24\n",
		"another entity":              "  ingress:\n  - fromEntities: [host]\n",
		"the entity all":              "  ingress:\n  - fromEntities: [all]\n",
		"requirements":                "  ingress:\n  - fromRequires:\n    - matchLabels:\n        env: prod\n",
		"nodes":                       "  ingress:\n  - fromNodes:\n    - matchLabels:\n        role: worker\n",
		"a field it doesn't know":     "  ingress:\n  - fromEverywhere: true\n",
		"a label of another source":   fromEndpoints + "    - matchLabels:\n        reserved:host: \"\"\n",
		"the cluster's own name":      fromEndpoints + "    - matchLabels:\n        io.cilium.k8s.policy.cluster: c1\n",
		"an operator it doesn't know": fromEndpoints + "    - matchExpressions:\n      - {key: app, operator: Gt}\n",
		"a deny rule":                 fromEndpoints + "    - {}\n  ingressDeny:\n  - fromEntities: [world]\n",
	} {
		t.Run(name, func(t *testing.T) {
			in, _ := accessOf(webPod, cilium(t, ciliumPolicyKind, webSelected+rules), ciliumCluster)

			require.Equal(t, reachCluster, reachOf(in))
		})
	}
}

// A rule that asks for no default deny isolates none of the pods that it selects: its rules only add to what other
// policies let in, so alone it lets anything in. The collector reads that, and what set the reach says so.
func TestACiliumRuleWithoutDefaultDenyIsolatesNoPod(t *testing.T) {
	in, _ := accessOf(webPod, cilium(t, ciliumPolicyKind, webSelected+
		"  enableDefaultDeny:\n    ingress: false\n  ingress:\n  - fromEndpoints:\n    - {}\n"), ciliumCluster)

	l, why := in.widest(webPod.namespace, ciliumCluster, nil)

	require.Equal(t, levelCluster, l)
	require.Equal(t, []widening{
		{kind: ciliumPolicyKind, namespace: teamA, name: testPolicy, rule: noRule, reason: reasonNoDefaultDeny},
	}, why)
}

// An endpoint selector of the subject that the collector can't read could select any pod of the policy's namespace,
// so it counts as selecting each, and as letting anything in.
func TestACiliumPolicyWhoseSubjectTheCollectorCantReadCountsForEveryPod(t *testing.T) {
	policies := cilium(t, ciliumPolicyKind, "spec:\n  endpointSelector:\n    matchLabels:\n"+
		"      reserved:host: \"\"\n  ingress:\n  - {}\n")

	in, _ := accessOf(webPod, policies, ciliumCluster)

	require.Equal(t, reachCluster, reachOf(in))
}

// For indirect exposure, the entity world lets in no pod of the cluster, and the entity cluster lets in every one.
func TestTheCiliumEntitiesLetInThePodsOfTheirName(t *testing.T) {
	world, _ := accessOf(webPod, cilium(t, ciliumPolicyKind, webSelected+"  ingress:\n  - fromEntities: [world]\n"),
		ciliumCluster)
	clusterWide, _ := accessOf(webPod,
		cilium(t, ciliumPolicyKind, webSelected+"  ingress:\n  - fromEntities: [cluster]\n"), ciliumCluster)

	require.False(t, world.admits(frontendPod, ciliumCluster))
	require.True(t, clusterWide.admits(frontendPod, ciliumCluster))
}

// A frontend's egress rules decide which backends it reaches: those that its endpoint selectors select, none for the
// entity world, and every one for a rule outside the subset, such as names that DNS resolves.
func TestACiliumEgressPolicyDecidesWhichPodsItsPodsReach(t *testing.T) {
	frontendSelected := strings.Replace(webSelected, "app: web", "app: frontend", 1)
	for _, tc := range []struct {
		name, rules string
		want        bool
	}{
		{name: "an endpoint selector of the backend",
			rules: "  egress:\n  - toEndpoints:\n    - matchLabels:\n        app: backend\n", want: true},
		{name: "an endpoint selector of another pod",
			rules: "  egress:\n  - toEndpoints:\n    - matchLabels:\n        app: db\n", want: false},
		{name: "the entity world", rules: "  egress:\n  - toEntities: [world]\n", want: false},
		{name: "names that DNS resolves", rules: "  egress:\n  - toFQDNs:\n    - matchName: artifacts.example\n",
			want: true},
		{name: "Services", rules: "  egress:\n  - toServices:\n    - k8sService: {serviceName: db, namespace: team-b}\n",
			want: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// The policy is in the frontend's namespace, team-b.
			u := &unstructured.Unstructured{}
			require.NoError(t, yaml.Unmarshal([]byte("apiVersion: cilium.io/v2\nkind: CiliumNetworkPolicy\n"+
				"metadata:\n  name: test\n  namespace: team-b\n"+frontendSelected+tc.rules), &u.Object))

			_, out := accessOf(frontendPod, ciliumPolicies(u), ciliumCluster)

			require.Equal(t, tc.want, out.admits(backendPod, ciliumCluster))
		})
	}
}

// A peer that a trusted entry matches doesn't widen the reach. An entry matches a peer when each field that it sets
// matches every pod that the peer can let in: namespaceSelector the labels of their namespace, podSelector their
// labels, which the peer's selector must ask for, and serviceAccount their service account, which the selector of a
// Cilium policy must ask for. A peer that can let in pods that the entry doesn't match widens the reach as before.
func TestATrustedPeerDoesntWidenTheReach(t *testing.T) {
	const (
		fromTeamB = webSelected + "  ingress:\n  - fromEndpoints:\n    - matchLabels:\n" +
			"        k8s:io.kubernetes.pod.namespace: team-b\n"
		byAccount = "        io.cilium.k8s.policy.serviceaccount: frontend\n"
		byLabel   = "        app: frontend\n"
		account   = `[{"serviceAccount": {"namespace": "team-b", "name": "frontend"}}]`
	)
	for _, tc := range []struct{ name, trust, peer, want string }{
		{name: "a trusted service account", trust: account, peer: byAccount, want: reachNamespace},
		{name: "a peer that asks for no service account", trust: account, peer: byLabel, want: reachPeers},
		{name: "the service account of another namespace",
			trust: `[{"serviceAccount": {"namespace": "team-c", "name": "frontend"}}]`, peer: byAccount, want: reachPeers},
		{name: "a trusted namespace", trust: `[{"namespaceSelector": {"matchLabels": {"tier": "data"}}}]`,
			peer: byLabel, want: reachNamespace},
		{name: "another namespace", trust: `[{"namespaceSelector": {"matchLabels": {"tier": "web"}}}]`,
			peer: byLabel, want: reachPeers},
		{name: "trusted pods that the peer narrows", trust: `[{"podSelector": {"matchLabels": {"app": "frontend"}}}]`,
			peer: byLabel + "        tier: web\n", want: reachNamespace},
		{name: "trusted pods that the peer asks less of",
			trust: `[{"podSelector": {"matchLabels": {"app": "frontend", "tier": "web"}}}]`, peer: byLabel,
			want: reachPeers},
		{name: "a value among the trusted ones", trust: `[{"podSelector": {"matchExpressions": ` +
			`[{"key": "app", "operator": "In", "values": ["frontend", "backend"]}]}}]`, peer: byLabel,
			want: reachNamespace},
		{name: "a label of the service account's key, which is no service account",
			trust: `[{"podSelector": {"matchLabels": {"io.cilium.k8s.policy.serviceaccount": "frontend"}}}]`,
			peer:  byAccount, want: reachPeers},
		{name: "an empty selector, which trusts every pod", trust: `[{"namespaceSelector": {}}]`, peer: byLabel,
			want: reachNamespace},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// A peer keeps its level for the trust that it was first asked with, which a Watch's settings fix: each
			// trust reads the policy again.
			reach := func(trust []trusted) string {
				in, _ := accessOf(webPod, cilium(t, ciliumPolicyKind, fromTeamB+tc.peer), ciliumCluster)
				return reachOf(in, trust...)
			}

			require.Equal(t, reachPeers, reach(nil), "without trust")
			require.Equal(t, tc.want, reach(trustOf(t, tc.trust)))
		})
	}
}

// widenedBy names the rule of a Cilium policy that set the reach: the policy, and the index of the rule among the
// ingress rules of its spec and then those of each of its specs. A rule that sets a narrower reach isn't named.
func TestWidenedByNamesTheCiliumRuleThatSetTheReach(t *testing.T) {
	policies := cilium(t, ciliumPolicyKind, "specs:\n- endpointSelector:\n    matchLabels:\n      app: web\n"+
		"  ingress:\n  - fromEndpoints:\n    - matchLabels:\n        app: client\n"+
		"- endpointSelector:\n    matchLabels:\n      app: web\n  ingress:\n  - fromEndpoints:\n    - {}\n"+
		"  - fromEntities: [world]\n")
	in, _ := accessOf(webPod, policies, ciliumCluster)

	l, why := in.widest(webPod.namespace, ciliumCluster, nil)

	require.Equal(t, levelCluster, l)
	require.Equal(t, []widening{
		{kind: ciliumPolicyKind, namespace: teamA, name: testPolicy, rule: 2, reason: reasonOutside},
	}, why)
}

// A rule of Cilium's that lets in a block of addresses lets in anything, as a NetworkPolicy's IP block does, and what
// set the reach says so, which the evidence's unseen names as IPBlock.
func TestACiliumRuleOfCIDRsLetsInAnIPBlock(t *testing.T) {
	for name, rule := range map[string]string{
		"a CIDR":         "  - fromCIDR: [192.0.2.0/24]\n",
		"a set of CIDRs": "  - fromCIDRSet:\n    - cidr: 192.0.2.0/24\n",
	} {
		t.Run(name, func(t *testing.T) {
			in, _ := accessOf(webPod, cilium(t, ciliumPolicyKind, webSelected+"  ingress:\n"+rule), ciliumCluster)

			l, why := in.widest(webPod.namespace, ciliumCluster, nil)

			require.Equal(t, levelCluster, l)
			require.Equal(t, []widening{
				{kind: ciliumPolicyKind, namespace: teamA, name: testPolicy, rule: 0, reason: reasonIPBlock},
			}, why)
		})
	}
}

// A rule that lets in a block of addresses and also names peers in a way that the collector doesn't read, such as by
// their nodes, lets in an IP block, whatever the order in which its fields come: a reason that changed from one build
// to the next would write the report again for nothing.
func TestACiliumRuleOfCIDRsAndOfPeersThatTheCollectorDoesntReadLetsInAnIPBlock(t *testing.T) {
	const rule = "  - fromCIDR: [192.0.2.0/24]\n    fromNodes:\n    - matchLabels:\n        role: worker\n"
	for range 64 {
		in, _ := accessOf(webPod, cilium(t, ciliumPolicyKind, webSelected+"  ingress:\n"+rule), ciliumCluster)

		_, why := in.widest(webPod.namespace, ciliumCluster, nil)

		require.Equal(t, []widening{
			{kind: ciliumPolicyKind, namespace: teamA, name: testPolicy, rule: 0, reason: reasonIPBlock},
		}, why)
	}
}

// Trust matches a peer only where it matches the pods of every other namespace that the peer selects: a peer of two
// namespaces, of which an entry trusts one, widens the reach as far as it would without trust.
func TestAPeerThatTrustMatchesInPartWidensTheReach(t *testing.T) {
	const dataNamespaces = webSelected + "  ingress:\n  - fromEndpoints:\n    - matchLabels:\n" +
		"        io.cilium.k8s.namespace.labels.tier: data\n"
	reach := func(trust []trusted) string {
		in, _ := accessOf(webPod, cilium(t, ciliumPolicyKind, dataNamespaces), ciliumCluster)
		return reachOf(in, trust...)
	}

	require.Equal(t, reachNamespaces, reach(nil))
	require.Equal(t, reachNamespaces,
		reach(trustOf(t, `[{"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "team-b"}}}]`)))
	require.Equal(t, reachNamespace, reach(trustOf(t, `[{"namespaceSelector": {"matchLabels": {"tier": "data"}}}]`)))
}
