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

// cilium reads the policies of a CiliumNetworkPolicy in team-a, or of a CiliumClusterwideNetworkPolicy when kind says
// so, whose spec is spec, as YAML indented by two spaces.
func cilium(t *testing.T, kind, spec string) []*policy {
	t.Helper()
	manifest := "apiVersion: cilium.io/v2\nkind: " + kind + "\nmetadata:\n  name: test\n"
	if kind == ciliumPolicyKind {
		manifest += "  namespace: team-a\n"
	}
	u := &unstructured.Unstructured{}
	require.NoError(t, yaml.Unmarshal([]byte(manifest+spec), &u.Object))
	return ciliumPolicies(u)
}

// webSelected is the start of a spec that selects the web pod.
const webSelected = "spec:\n  endpointSelector:\n    matchLabels:\n      app: web\n"

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

			require.Equal(t, tc.want, in.reach(webPod.namespace, ciliumCluster))
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
		"no default deny":             "  enableDefaultDeny:\n    ingress: false\n  ingress:\n  - fromEndpoints:\n    - {}\n",
	} {
		t.Run(name, func(t *testing.T) {
			in, _ := accessOf(webPod, cilium(t, ciliumPolicyKind, webSelected+rules), ciliumCluster)

			require.Equal(t, reachCluster, in.reach(webPod.namespace, ciliumCluster))
		})
	}
}

// An endpoint selector of the subject that the collector can't read could select any pod of the policy's namespace,
// so it counts as selecting each, and as letting anything in.
func TestACiliumPolicyWhoseSubjectTheCollectorCantReadCountsForEveryPod(t *testing.T) {
	policies := cilium(t, ciliumPolicyKind, "spec:\n  endpointSelector:\n    matchLabels:\n"+
		"      reserved:host: \"\"\n  ingress:\n  - {}\n")

	in, _ := accessOf(webPod, policies, ciliumCluster)

	require.Equal(t, reachCluster, in.reach(webPod.namespace, ciliumCluster))
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
