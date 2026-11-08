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

package collectorclient_test

import (
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
	"github.com/bedag/vexplain/internal/collectorclient"
	"github.com/bedag/vexplain/internal/settings"
	collectorv1alpha1 "github.com/bedag/vexplain/sdk/api/collector/v1alpha1"
	"github.com/bedag/vexplain/sdk/attribution"
	"github.com/bedag/vexplain/sdk/scope"
)

// The context carries OperatorConfig's scope and allowlists as the JSON of the API's types, and a collector reads them
// with the SDK's types, which refuse a field that they don't know. Go's conversion between the two types ignores their
// JSON names, so this pins them: a name that differs fails here, where every collector would refuse the context.
func TestTheContextReadsAsTheSDKReadsIt(t *testing.T) {
	// The label keys of the scope, and their values.
	const (
		teamKey, tierKey, appKey = "owner-team", "owner-tier", "owner-app"
		teamA, web               = "team-a", "web"
	)
	selects := func(key, value string) *metav1.LabelSelector {
		return &metav1.LabelSelector{MatchLabels: map[string]string{key: value}}
	}
	config := &configv1alpha1.OperatorConfig{
		ObjectMeta: metav1.ObjectMeta{Name: settings.ConfigName},
		Spec: configv1alpha1.OperatorConfigSpec{
			Scope: &configv1alpha1.Scope{
				IncludeNamespaces: selects(teamKey, teamA),
				ExcludeNamespaces: selects("vexplain", "off"),
				IncludePods:       selects(tierKey, web),
				ExcludePods:       selects(appKey, "debug"),
			},
			OwnerAttribution: &configv1alpha1.OwnerAttribution{
				NamespaceLabels:      []string{teamKey},
				NamespaceAnnotations: []string{"contact"},
				WorkloadLabels:       []string{"app.kubernetes.io/part-of"},
			},
		},
	}
	scheme := runtime.NewScheme()
	require.NoError(t, configv1alpha1.AddToScheme(scheme))
	reader := fake.NewClientBuilder().WithScheme(scheme).WithObjects(config).Build()

	sent, err := collectorclient.ClusterContext(reader, namespace)(t.Context())
	require.NoError(t, err)

	matcher, err := scope.Parse(sent.GetScope())
	require.NoError(t, err)
	in, webPod := map[string]string{teamKey: teamA}, map[string]string{tierKey: web}
	require.True(t, matcher.Matches(in, webPod))
	require.False(t, matcher.Matches(map[string]string{teamKey: "team-b"}, webPod), "includeNamespaces")
	require.False(t, matcher.Matches(map[string]string{teamKey: teamA, "vexplain": "off"}, webPod),
		"excludeNamespaces")
	require.False(t, matcher.Matches(in, map[string]string{tierKey: "api"}), "includePods")
	require.False(t, matcher.Matches(in, map[string]string{tierKey: web, appKey: "debug"}), "excludePods")

	allowlists, err := attribution.Parse(sent.GetOwnerAttribution())
	require.NoError(t, err)
	require.Equal(t, attribution.Allowlists{
		NamespaceLabels:      []string{teamKey},
		NamespaceAnnotations: []string{"contact"},
		WorkloadLabels:       []string{"app.kubernetes.io/part-of"},
	}, allowlists)
}

// Cluster labels and the policy on permissions are the operator's: a change of them would otherwise
// reopen every collector stream, and no collector needs them. The context of a config that sets them
// equals the context of one that doesn't.
func TestTheContextCarriesNoClusterLabelsOrPermissionPolicy(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, configv1alpha1.AddToScheme(scheme))
	contextOf := func(spec configv1alpha1.OperatorConfigSpec) *collectorv1alpha1.Context {
		config := &configv1alpha1.OperatorConfig{ObjectMeta: metav1.ObjectMeta{Name: settings.ConfigName}, Spec: spec}
		reader := fake.NewClientBuilder().WithScheme(scheme).WithObjects(config).Build()
		sent, err := collectorclient.ClusterContext(reader, namespace)(t.Context())
		require.NoError(t, err)
		return sent
	}

	plain := contextOf(configv1alpha1.OperatorConfigSpec{})
	labelled := contextOf(configv1alpha1.OperatorConfigSpec{
		ClusterLabels: map[string]configv1alpha1.LabelValue{"env": "prod"},
		Collectors: &configv1alpha1.CollectorPolicy{
			Permissions: ptr.To(configv1alpha1.PermissionsModeCheck),
			DeniedPermissions: []configv1alpha1.PermissionRule{
				{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get"}},
			},
		},
	})

	require.True(t, proto.Equal(plain, labelled), "plain %v, labelled %v", plain, labelled)
}
