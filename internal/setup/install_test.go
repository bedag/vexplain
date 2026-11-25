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
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
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

	writes := []string{verbCreate, "update", "patch", "delete", "deletecollection", "*"}
	var readers []string
	for _, file := range kustomization.Resources {
		raw, err := os.ReadFile(filepath.Join(dir, file))
		require.NoError(t, err)
		for doc := range strings.SplitSeq(string(raw), "\n---") {
			var role rbacv1.ClusterRole
			require.NoError(t, yaml.Unmarshal([]byte(doc), &role), file)
			if role.Kind != kindClusterRole && role.Kind != kindRole {
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
	require.Equal(t, readVerbs, verbsOn(namespaced.Rules, "", "secrets"))
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

const (
	verbCreate = "create"
	// hubName is the hub's ServiceAccount on a spoke, with the install's prefix.
	hubName = "vexplain-hub"
	// kindClusterRole and collectorScanner are the names that the tests look for in a render.
	kindClusterRole  = "ClusterRole"
	kindRole         = "Role"
	collectorScanner = "scanner"
)

var readVerbs = []string{"get", "list", "watch"}

// On a spoke the hub reads what it copies and nothing more, and renews its own token: a read of five kinds, and the
// creation of the token of its own ServiceAccount alone. The manager's role has no part in it.
func TestTheHubsAccessOnASpokeOnlyReads(t *testing.T) {
	roles := rolesIn(t, filepath.Join("hub-access", "role.yaml"))
	require.Len(t, roles, 2)
	cluster, namespaced := roles["ClusterRole/hub-reader"], roles["Role/hub-reader"]

	var got []string
	for _, rule := range cluster.Rules {
		require.Equal(t, readVerbs, rule.Verbs)
		for _, group := range rule.APIGroups {
			for _, resource := range rule.Resources {
				got = append(got, group+"/"+resource)
			}
		}
	}
	slices.Sort(got)
	require.Equal(t, []string{
		"/namespaces",
		"config.vexplain.bedag.ch/collectors",
		"config.vexplain.bedag.ch/operatorconfigs",
		"inventory.vexplain.bedag.ch/evidences",
		"inventory.vexplain.bedag.ch/imageinventories",
	}, got)

	require.Equal(t, "vexplain-system", namespaced.Namespace)
	require.Equal(t, []rbacv1.PolicyRule{{
		APIGroups: []string{""}, Resources: []string{"serviceaccounts/token"},
		ResourceNames: []string{hubName}, Verbs: []string{verbCreate},
	}}, namespaced.Rules)

	// The hub's package is left out of the manager's role, which stays as it was.
	for name, role := range rolesIn(t, "role.yaml") {
		require.Empty(t, verbsOn(role.Rules, "", "serviceaccounts/token"), name)
	}
}

// render builds the install in config/<dir> with the kustomize that the Makefile pins, and returns its objects by
// kind and name.
func render(t *testing.T, dir string) map[string]map[string]any {
	t.Helper()
	kustomize := os.Getenv("KUSTOMIZE")
	if kustomize == "" {
		kustomize = filepath.Join("..", "..", "bin", "kustomize")
	}
	out, err := exec.Command(kustomize, "build", filepath.Join("..", "..", "config", dir)).CombinedOutput()
	require.NoError(t, err, string(out))
	objects := map[string]map[string]any{}
	for doc := range strings.SplitSeq(string(out), "\n---\n") {
		var object map[string]any
		require.NoError(t, yaml.Unmarshal([]byte(doc), &object))
		metadata, _ := object["metadata"].(map[string]any)
		objects[object["kind"].(string)+"/"+metadata["name"].(string)] = object
	}
	return objects
}

// as decodes a rendered object into a typed one.
func as[T any](t *testing.T, object map[string]any) T {
	t.Helper()
	var typed T
	raw, err := yaml.Marshal(object)
	require.NoError(t, err)
	require.NoError(t, yaml.Unmarshal(raw, &typed))
	return typed
}

// managerArgs returns the arguments of the manager's container in a rendered install.
func managerArgs(t *testing.T, objects map[string]map[string]any) []string {
	t.Helper()
	require.Contains(t, objects, "Deployment/vexplain-controller-manager")
	return as[appsv1.Deployment](t, objects["Deployment/vexplain-controller-manager"]).Spec.Template.Spec.Containers[0].Args
}

// kinds returns the names of the rendered objects of a kind.
func kinds(objects map[string]map[string]any, kind string) []string {
	var names []string
	for key := range objects {
		if name, ok := strings.CutPrefix(key, kind+"/"); ok {
			names = append(names, name)
		}
	}
	slices.Sort(names)
	return names
}

// Each install sets the mode that it runs (design 5.1). A spoke ships the collectors that need its cluster and the
// hub's access, and neither the scanner nor the agent. A hub ships no presence and no network reach. The single-cluster
// install passes no mode, so it stays HubAndSpoke.
func TestEachInstallRunsItsMode(t *testing.T) {
	hub, spoke, single := render(t, "hub"), render(t, "spoke"), render(t, "default")

	require.Contains(t, managerArgs(t, hub), "--mode=Hub")
	require.Equal(t, []string{"advisories", collectorScanner, "vulnerabilities"}, kinds(hub, "Collector"))
	require.Contains(t, hub, "Deployment/vexplain-agent")

	require.Contains(t, managerArgs(t, spoke), "--mode=Spoke")
	require.Equal(t, []string{"network-reach", "workloads"}, kinds(spoke, "Collector"))
	require.NotContains(t, spoke, "Deployment/vexplain-agent")
	for _, kind := range []string{"Rule", "Playbook", "CollectorRuntimeConfig", "PersistentVolumeClaim"} {
		require.Empty(t, kinds(spoke, kind), kind)
	}

	for _, arg := range managerArgs(t, single) {
		require.NotContains(t, arg, "--mode")
	}
	require.Contains(t, kinds(single, "Collector"), "workloads")
}

// A binding names a ServiceAccount that the install creates. One that it doesn't create would give its rights to
// whoever creates that account, in whatever namespace the name resolves to.
func TestEveryBindingOfAnInstallNamesItsOwnServiceAccount(t *testing.T) {
	for _, dir := range []string{"default", "hub", "spoke"} {
		objects := render(t, dir)
		accounts := map[string]bool{}
		for key, object := range objects {
			if name, ok := strings.CutPrefix(key, "ServiceAccount/"); ok {
				accounts[object["metadata"].(map[string]any)["namespace"].(string)+"/"+name] = true
			}
		}
		for key, object := range objects {
			if kind, _, _ := strings.Cut(key, "/"); kind != "RoleBinding" && kind != "ClusterRoleBinding" {
				continue
			}
			for _, subject := range as[rbacv1.RoleBinding](t, object).Subjects {
				if subject.Kind == "ServiceAccount" {
					require.True(t, accounts[subject.Namespace+"/"+subject.Name], "%s: %s binds %s/%s", dir, key, subject.Namespace, subject.Name)
				}
			}
		}
	}
}

// A spoke runs no scanner, and the hub reads what it copies from there: its manager holds no read of Secrets outside
// the operator's namespace and no write of Jobs, which decision 0066 keeps off a spoke. It serves its metrics, and
// shields the collectors' API like the other installs.
func TestASpokeHoldsNothingOfTheScanner(t *testing.T) {
	spoke := render(t, "spoke")
	for key, object := range spoke {
		kind, _, _ := strings.Cut(key, "/")
		if kind != kindClusterRole {
			continue
		}
		for _, rule := range as[rbacv1.ClusterRole](t, object).Rules {
			if slices.Contains(rule.Resources, "secrets") {
				require.NotContains(t, rule.Verbs, "get", key)
				require.NotContains(t, rule.Verbs, "list", key)
				require.NotContains(t, rule.Verbs, "watch", key)
			}
		}
	}
	for key, object := range spoke {
		kind, _, _ := strings.Cut(key, "/")
		if kind != kindClusterRole && kind != kindRole {
			continue
		}
		for _, rule := range as[rbacv1.ClusterRole](t, object).Rules {
			if slices.Contains(rule.Resources, "jobs") {
				require.Empty(t, slices.DeleteFunc(slices.Clone(rule.Verbs), func(v string) bool { return slices.Contains(readVerbs, v) }), key)
			}
		}
	}
	require.Contains(t, spoke, "Service/vexplain-controller-manager-metrics-service")
	require.Contains(t, spoke, "NetworkPolicy/vexplain-allow-manager-to-collectors")
	require.Contains(t, managerArgs(t, spoke), "--metrics-bind-address=:8443")
}

// The hub's access on a spoke, by the names that the prefix and the namespace give. The Role names the ServiceAccount,
// which kustomize's prefix doesn't do for resourceNames.
func TestTheHubsAccessRendersWithTheInstallsNames(t *testing.T) {
	spoke := render(t, "spoke")
	require.Contains(t, spoke, "ServiceAccount/"+hubName)
	require.Equal(t, "vexplain-system", spoke["ServiceAccount/"+hubName]["metadata"].(map[string]any)["namespace"])
	require.Contains(t, spoke, "Role/vexplain-hub-reader")
	role := as[rbacv1.Role](t, spoke["Role/vexplain-hub-reader"])
	require.Equal(t, "vexplain-system", role.Namespace)
	require.Equal(t, []string{hubName}, role.Rules[0].ResourceNames)
	require.Contains(t, spoke, "ClusterRole/vexplain-hub-reader")
	for binding, kind := range map[string]string{"RoleBinding/vexplain-hub-reader": "Role", "ClusterRoleBinding/vexplain-hub-reader": "ClusterRole"} {
		require.Contains(t, spoke, binding)
		b := as[rbacv1.RoleBinding](t, spoke[binding])
		require.Equal(t, rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: kind, Name: "vexplain-hub-reader"}, b.RoleRef, binding)
		require.Equal(t, []rbacv1.Subject{{Kind: "ServiceAccount", Name: hubName, Namespace: "vexplain-system"}}, b.Subjects, binding)
	}
}
