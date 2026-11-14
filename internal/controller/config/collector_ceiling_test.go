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

package config_test

import (
	"testing"

	"github.com/stretchr/testify/require"
	rbacv1 "k8s.io/api/rbac/v1"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
	configcontroller "github.com/bedag/vexplain/internal/controller/config"
	"github.com/bedag/vexplain/internal/settings"
	collectorv1alpha1 "github.com/bedag/vexplain/sdk/api/collector/v1alpha1"
)

// The guards that may refuse a rule that a collector declares, as the condition names them.
const (
	guardCeiling           = "ceiling"
	guardNamespacedCeiling = "namespaced ceiling"
	guardDenyList          = "deny list"
)

// declared is a rule that a collector declares, across the cluster.
func declared(groups, resources, verbs []string) *collectorv1alpha1.PolicyRule {
	return &collectorv1alpha1.PolicyRule{ApiGroups: groups, Resources: resources, Verbs: verbs}
}

// everything is a ceiling that covers every rule.
var everything = []rbacv1.PolicyRule{{APIGroups: []string{"*"}, Resources: []string{"*"}, Verbs: []string{"*"}}}

// The ceiling compares rules as the API server's escalation check compares a role with what its creator holds: each
// API group, resource and verb of the rule needs a rule of the ceiling that holds it, or a star in its place.
func TestTheCeilingCoversARuleAsTheEscalationCheckDoes(t *testing.T) {
	ceiling := []rbacv1.PolicyRule{
		{APIGroups: []string{""}, Resources: []string{pods, nodes}, Verbs: []string{verbGet, verbList, verbWatch}},
		{APIGroups: []string{groupApps}, Resources: []string{"*"}, Verbs: []string{verbList}},
		{APIGroups: []string{"*"}, Resources: []string{"events"}, Verbs: []string{"*"}},
		{APIGroups: []string{""}, Resources: []string{"*/log"}, Verbs: []string{verbGet}},
		{APIGroups: []string{""}, Resources: []string{resourceSecrets}, Verbs: []string{verbGet}, ResourceNames: []string{"pull-secret"}},
	}
	for name, tc := range map[string]struct {
		rule *collectorv1alpha1.PolicyRule
		ok   bool
	}{
		"an exact match": {declared([]string{""}, []string{pods}, []string{verbGet}), true},
		"each resource and verb of a rule in the ceiling": {
			declared([]string{""}, []string{pods, nodes}, []string{verbGet, verbWatch}), true},
		"a resource under the ceiling's star": {
			declared([]string{groupApps}, []string{resourceDeployments, "replicasets"}, []string{verbList}), true},
		"an API group and a verb under the ceiling's stars": {
			declared([]string{"events.k8s.io", ""}, []string{"events"}, []string{verbCreate, "patch"}), true},
		"a subresource under the ceiling's star for it": {declared([]string{""}, []string{"pods/log"}, []string{verbGet}), true},
		"a verb beyond the ceiling":                     {declared([]string{""}, []string{pods}, []string{verbGet, verbDelete}), false},
		"a resource beyond the ceiling":                 {declared([]string{""}, []string{pods, resourceConfigMaps}, []string{verbGet}), false},
		"an API group beyond the ceiling":               {declared([]string{groupApps, groupBatch}, []string{resourceJobs}, []string{verbList}), false},
		"a subresource of a resource in the ceiling": {
			declared([]string{""}, []string{"nodes/proxy"}, []string{verbGet}), false},
		"a resource whose ceiling names some objects alone": {
			declared([]string{""}, []string{resourceSecrets}, []string{verbGet}), false},
		"a star that the ceiling doesn't hold": {declared([]string{""}, []string{"*"}, []string{verbGet}), false},
	} {
		t.Run(name, func(t *testing.T) {
			ok, guard := configcontroller.Covered(ceiling, nil, tc.rule)

			require.Equal(t, tc.ok, ok)
			if tc.ok {
				require.Empty(t, guard)
			} else {
				require.Equal(t, guardCeiling, guard)
			}
		})
	}
}

// A rule for the collector's own namespace that the ceilings don't cover is refused by the namespaced ceiling, which
// is the one meant for it.
func TestARuleOfTheCollectorsNamespaceIsRefusedByTheNamespacedCeiling(t *testing.T) {
	rule := declared([]string{groupBatch}, []string{resourceJobs}, []string{verbCreate})
	rule.Namespaced = true

	ok, guard := configcontroller.Covered(nil, nil, rule)

	require.False(t, ok)
	require.Equal(t, guardNamespacedCeiling, guard)
}

// A rule of the deny list refuses a declared rule that shares an API group, a resource and a verb with it, a star
// standing for any, whatever the ceiling covers: deny wins, as an explicit deny does in AWS IAM.
func TestADenyOverlapWinsOverTheCeiling(t *testing.T) {
	denied := []configv1alpha1.PermissionRule{
		{APIGroups: []string{""}, Resources: []string{resourceSecrets}, Verbs: []string{verbWatch}},
		{APIGroups: []string{"*"}, Resources: []string{"*"}, Verbs: []string{"deletecollection"}},
		{APIGroups: []string{""}, Resources: []string{"*/exec"}, Verbs: []string{verbCreate}},
		{APIGroups: []string{""}, Resources: []string{"nodes/proxy"}, Verbs: []string{verbGet}},
	}
	for name, tc := range map[string]struct {
		rule *collectorv1alpha1.PolicyRule
		ok   bool
	}{
		"the denied permission": {declared([]string{""}, []string{resourceSecrets}, []string{verbWatch}), false},
		"a rule that holds it among others": {
			declared([]string{""}, []string{pods, resourceSecrets}, []string{verbGet, verbWatch}), false},
		"a star for the API group": {declared([]string{"*"}, []string{resourceSecrets}, []string{verbWatch}), false},
		"a star for the resource":  {declared([]string{""}, []string{"*"}, []string{verbWatch}), false},
		"a star for the verb":      {declared([]string{""}, []string{resourceSecrets}, []string{"*"}), false},
		"a denied verb on any resource of any group": {
			declared([]string{groupApps}, []string{resourceDeployments}, []string{"deletecollection"}), false},
		"a subresource that the deny list names of any resource": {
			declared([]string{""}, []string{"pods/exec"}, []string{verbCreate}), false},
		"a star for the resource of a denied subresource": {
			declared([]string{""}, []string{"*/proxy"}, []string{verbGet}), false},
		"another verb on the resource": {declared([]string{""}, []string{resourceSecrets}, []string{verbGet}), true},
		"the resource in another API group": {
			declared([]string{"example.com"}, []string{resourceSecrets}, []string{verbWatch}), true},
		"the resource of a denied subresource": {declared([]string{""}, []string{nodes}, []string{verbGet}), true},
	} {
		t.Run(name, func(t *testing.T) {
			ok, guard := configcontroller.Covered(everything, denied, tc.rule)

			require.Equal(t, tc.ok, ok)
			if tc.ok {
				require.Empty(t, guard)
			} else {
				require.Equal(t, guardDenyList, guard)
			}
		})
	}
}

// The deny list is named when it refuses a rule that the ceiling doesn't cover either: deny wins there too.
func TestTheDenyListIsNamedBeforeTheCeiling(t *testing.T) {
	denied := []configv1alpha1.PermissionRule{{APIGroups: []string{""}, Resources: []string{resourceSecrets}, Verbs: []string{verbList}}}

	ok, guard := configcontroller.Covered(nil, denied, declared([]string{""}, []string{resourceSecrets}, []string{verbList}))

	require.False(t, ok)
	require.Equal(t, guardDenyList, guard)
}

// The default deny list refuses listing and watching Secrets, which reveal every Secret's contents, and leaves the
// scanner's get on pull secrets, under any ceiling.
func TestTheDefaultDenyListRefusesListingSecretsAndAllowsGettingThem(t *testing.T) {
	denied := settings.DefaultDeniedPermissions

	for _, verb := range []string{verbList, verbWatch} {
		ok, guard := configcontroller.Covered(everything, denied, declared([]string{""}, []string{resourceSecrets}, []string{verb}))
		require.False(t, ok, verb)
		require.Equal(t, guardDenyList, guard, verb)
	}
	ok, guard := configcontroller.Covered(everything, denied, declared([]string{""}, []string{resourceSecrets}, []string{verbGet}))
	require.True(t, ok)
	require.Empty(t, guard)
}

// An empty deny list denies nothing.
func TestAnEmptyDenyListDeniesNothing(t *testing.T) {
	ok, _ := configcontroller.Covered(everything, []configv1alpha1.PermissionRule{},
		declared([]string{""}, []string{resourceSecrets}, []string{verbList}))

	require.True(t, ok)
}
