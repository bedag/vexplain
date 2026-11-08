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

package conformance_test

import (
	"testing"

	"github.com/stretchr/testify/require"
	rbacv1 "k8s.io/api/rbac/v1"

	"github.com/bedag/vexplain/sdk/collector"
	"github.com/bedag/vexplain/sdk/conformance"
)

// ceilingManifests are ClusterRoles as an install ships them: the two aggregated ceilings, which hold no rules of their
// own, a ClusterRole for each that carries its label, and others that carry neither, or a label that isn't "true".
const ceilingManifests = `# The ceiling of what a collector gets in the whole cluster.
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: collector
aggregationRule:
  clusterRoleSelectors:
  - matchLabels:
      rbac.vexplain.bedag.ch/aggregate-to-collector: "true"
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: collector
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: collector
subjects:
- kind: ServiceAccount
  name: controller-manager
  namespace: system
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: collector-defaults
  labels:
    rbac.vexplain.bedag.ch/aggregate-to-collector: "true"
rules:
- apiGroups: [""]
  resources: [pods, nodes]
  verbs: [list, watch]
- apiGroups: [apps]
  resources: ["*"]
  verbs: [get]
- apiGroups: [""]
  resources: ["*/log"]
  verbs: [get]
- apiGroups: [""]
  resources: [secrets]
  verbs: [get]
  resourceNames: [pull-secret]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: collector-namespaced-defaults
  labels:
    rbac.vexplain.bedag.ch/aggregate-to-collector-namespaced: "true"
rules:
- apiGroups: [batch]
  resources: [jobs]
  verbs: [create, delete]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: unlabelled
rules:
- apiGroups: ["*"]
  resources: ["*"]
  verbs: ["*"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: switched-off
  labels:
    rbac.vexplain.bedag.ch/aggregate-to-collector: "false"
rules:
- apiGroups: ["*"]
  resources: ["*"]
  verbs: ["*"]
`

// The API groups, resources and verbs that the tests of the ceilings name, as ceilingManifests names them.
const (
	appsGroup       = "apps"
	batchGroup      = "batch"
	podsResource    = "pods"
	nodesResource   = "nodes"
	jobsResource    = "jobs"
	secretsResource = "secrets"
	listVerb        = "list"
	watchVerb       = "watch"
	getVerb         = "get"
	createVerb      = "create"
	deleteVerb      = "delete"
)

func TestTheCeilingRulesAreThoseOfTheClusterRolesThatCarryTheirLabels(t *testing.T) {
	cluster, namespaced, err := conformance.CeilingRules([]byte(ceilingManifests))

	require.NoError(t, err)
	require.Equal(t, []rbacv1.PolicyRule{
		{APIGroups: []string{""}, Resources: []string{podsResource, nodesResource}, Verbs: []string{listVerb, watchVerb}},
		{APIGroups: []string{appsGroup}, Resources: []string{"*"}, Verbs: []string{getVerb}},
		{APIGroups: []string{""}, Resources: []string{"*/log"}, Verbs: []string{getVerb}},
		{
			APIGroups: []string{""}, Resources: []string{secretsResource}, Verbs: []string{getVerb},
			ResourceNames: []string{"pull-secret"},
		},
	}, cluster)
	require.Equal(t, []rbacv1.PolicyRule{
		{APIGroups: []string{batchGroup}, Resources: []string{jobsResource}, Verbs: []string{createVerb, deleteVerb}},
	}, namespaced)
}

func TestUncoveredNamesEachPermissionThatTheCeilingOfItsScopeDoesntCover(t *testing.T) {
	permissions := []collector.Permission{
		// Covered, by a rule that names them, by a star, and by a star for a subresource.
		{APIGroups: []string{""}, Resources: []string{podsResource, nodesResource}, Verbs: []string{listVerb}},
		{APIGroups: []string{appsGroup}, Resources: []string{"deployments", "replicasets"}, Verbs: []string{getVerb}},
		{APIGroups: []string{""}, Resources: []string{"pods/log"}, Verbs: []string{getVerb}},
		{APIGroups: []string{batchGroup}, Resources: []string{jobsResource}, Verbs: []string{createVerb}, Namespaced: true},
		// Not covered: a verb beyond the rule, every name of a resource whose rule names one, a permission of the
		// collector's namespace that only the other ceiling holds, and one across the cluster that only the
		// namespaced ceiling holds.
		{APIGroups: []string{""}, Resources: []string{podsResource}, Verbs: []string{listVerb, deleteVerb}},
		{APIGroups: []string{""}, Resources: []string{secretsResource}, Verbs: []string{getVerb}},
		{APIGroups: []string{""}, Resources: []string{nodesResource}, Verbs: []string{listVerb}, Namespaced: true},
		{APIGroups: []string{batchGroup}, Resources: []string{jobsResource}, Verbs: []string{deleteVerb}},
	}

	uncovered, err := conformance.Uncovered([]byte(ceilingManifests), permissions)

	require.NoError(t, err)
	require.Equal(t, []string{
		"delete pods across the cluster",
		"get secrets across the cluster",
		"list nodes in the collector's namespace",
		"delete jobs.batch across the cluster",
	}, uncovered)
}

func TestUncoveredRefusesManifestsThatArentYAML(t *testing.T) {
	_, err := conformance.Uncovered([]byte("kind: ClusterRole\nrules: [\n"), nil)

	require.Error(t, err)
}
