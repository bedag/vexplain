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

package setup_test

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	rbacv1 "k8s.io/api/rbac/v1"
	"sigs.k8s.io/yaml"

	inventoryv1alpha1 "github.com/bedag/vexplain/api/inventory/v1alpha1"
	triagev1alpha1 "github.com/bedag/vexplain/api/triage/v1alpha1"
)

// The inventory group is written only by the operator (design 6.1). Whoever could write Evidence could write evidence
// that settles findings, so the install ships no role that grants a write on the group, besides the operator's own:
// the manager's, and the agent workers', which write the tool outputs and the ledgers of their cases. It ships the
// roles that read it: reading settles nothing.
func TestTheInstallGrantsNoWriteOfTheInventoryGroupButTheOperators(t *testing.T) {
	dir := filepath.Join("..", "..", "config", "rbac")
	var kustomization struct {
		Resources []string `json:"resources"`
	}
	raw, err := os.ReadFile(filepath.Join(dir, "kustomization.yaml"))
	require.NoError(t, err)
	require.NoError(t, yaml.Unmarshal(raw, &kustomization))

	writes := []string{"create", "update", "patch", "delete", "deletecollection", "*"}
	var readers []string
	for _, file := range kustomization.Resources {
		raw, err := os.ReadFile(filepath.Join(dir, file))
		require.NoError(t, err)
		for doc := range strings.SplitSeq(string(raw), "\n---") {
			var role rbacv1.ClusterRole
			require.NoError(t, yaml.Unmarshal([]byte(doc), &role), file)
			if role.Kind != "ClusterRole" && role.Kind != "Role" {
				continue
			}
			for _, rule := range role.Rules {
				if !slices.Contains(rule.APIGroups, inventoryv1alpha1.GroupVersion.Group) && !slices.Contains(rule.APIGroups, "*") {
					continue
				}
				if role.Name == "manager-role" || role.Name == "agent-role" {
					continue
				}
				for _, verb := range rule.Verbs {
					require.NotContains(t, writes, verb, "%s in %s grants %s on %v", role.Name, file, verb, rule.Resources)
				}
				readers = append(readers, rule.Resources...)
			}
		}
	}
	require.ElementsMatch(t, []string{"evidences", "imageinventories", "imageinventories/status",
		"imageverdicts", "imageverdicts/status", "playbookclusterstatuses", "playbookclusterstatuses/status", "ledgers"},
		readers, "the viewer roles of the group stay")
}

// rolesIn returns the ClusterRoles and Roles of a file of config/rbac, by kind and name.
func rolesIn(t *testing.T, file string) map[string]rbacv1.ClusterRole {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "config", "rbac", file))
	require.NoError(t, err)
	roles := map[string]rbacv1.ClusterRole{}
	for doc := range strings.SplitSeq(string(raw), "\n---") {
		var role rbacv1.ClusterRole
		require.NoError(t, yaml.Unmarshal([]byte(doc), &role), file)
		roles[role.Kind+"/"+role.Name] = role
	}
	return roles
}

// verbsOn returns the verbs that the rules grant on the resource of the API group.
func verbsOn(rules []rbacv1.PolicyRule, group, resource string) []string {
	var verbs []string
	for _, rule := range rules {
		if slices.Contains(rule.APIGroups, group) && slices.Contains(rule.Resources, resource) {
			verbs = append(verbs, rule.Verbs...)
		}
	}
	slices.Sort(verbs)
	return slices.Compact(verbs)
}

// The manager no longer reads the LLM key, which only the agent workers read: no cache of the manager holds a Secret,
// so its roles watch none. What it keeps on Secrets serves its own code: the certificates that it issues, and the
// check of the MCP collectors' headers.
func TestTheManagersRoleWatchesNoSecret(t *testing.T) {
	roles := rolesIn(t, "role.yaml")
	require.Contains(t, roles, "Role/manager-role")
	for name, role := range roles {
		require.NotContains(t, verbsOn(role.Rules, "", "secrets"), "watch", name)
	}
}

// The workers' role comes from the markers of their own packages: they claim and judge the cases in the Assessments'
// status, and read the Secrets of the operator's namespace, the LLM key, the MCP collectors' headers and their client
// certificate, and no Secret elsewhere. Of the Leases of that namespace, the manager's among them, they read and renew
// their own alone; a create can't be narrowed by name.
func TestTheAgentsRoleJudgesTheCasesAndReadsTheSecretsOfItsNamespace(t *testing.T) {
	roles := rolesIn(t, filepath.Join("agent", "role.yaml"))
	cluster, namespaced := roles["ClusterRole/agent-role"], roles["Role/agent-role"]
	require.Contains(t, verbsOn(cluster.Rules, triagev1alpha1.GroupVersion.Group, "assessments/status"), "update")
	require.Empty(t, verbsOn(cluster.Rules, "", "secrets"), "no Secret outside the operator's namespace")
	require.Equal(t, "vexplain-system", namespaced.Namespace)
	require.Equal(t, []string{"get", "list", "watch"}, verbsOn(namespaced.Rules, "", "secrets"))
	require.Empty(t, verbsOn(cluster.Rules, "coordination.k8s.io", "leases"), "no Lease outside the operator's namespace")
	// The verbs on the workers' own Lease, by its name, and on any Lease.
	leases := map[bool][]string{}
	for _, rule := range namespaced.Rules {
		if slices.Contains(rule.Resources, "leases") {
			own := slices.Equal(rule.ResourceNames, []string{"agent.vexplain.bedag.ch"})
			leases[own] = append(leases[own], rule.Verbs...)
		}
	}
	require.Equal(t, map[bool][]string{true: {"get", "update"}, false: {"create"}}, leases)
}
