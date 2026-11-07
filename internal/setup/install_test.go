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
)

// The inventory group is written only by the operator (design 6.1). Whoever could write Evidence could write evidence
// that settles findings, so the install ships no role that grants a write on the group, besides the manager's own. It
// ships the roles that read it: reading settles nothing.
func TestTheInstallGrantsNoWriteOfTheInventoryGroupButTheManagers(t *testing.T) {
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
				if role.Name == "manager-role" {
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
		"imageverdicts", "imageverdicts/status"}, readers, "the viewer roles of the group stay")
}
