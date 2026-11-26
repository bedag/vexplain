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

package cases_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
	"github.com/bedag/vexplain/internal/agent/cases"
)

// clusterA is a cluster beside clusterB that runs the images of a test.
const clusterA = "cluster-a"

// A playbook's cases count only the workloads of the clusters that its match selects (design of remote spokes 5.8): of
// an image that two clusters run, the case has the clusters, namespaces, workloads and owners of the one that matches.
func TestACaseCountsOnlyTheMatchingClustersWorkloads(t *testing.T) {
	manifest := digestOf(21)
	s := &sheets{}
	s.put(manifest, playbook, finding(cve1, "lib"))
	i := &images{}
	i.runs(manifest, in(clusterA, namespace("team-a", 4, 0)), in(clusterB, namespace("team-b", 1, 0), namespace("team-c", 0, 2)))

	selected, skipped := selectCases(t, s, i, cases.Selection{Clusters: []string{clusterB}, SkipNotRunning: true})

	require.Empty(t, skipped)
	require.Len(t, selected, 1)
	require.Equal(t, []string{clusterB}, selected[0].Clusters, "the case names the clusters whose workloads it counts")
	impact := selected[0].Impact
	require.Equal(t, []string{clusterB}, impact.ClusterNames)
	require.Equal(t, int32(1), impact.Clusters)
	require.Equal(t, int32(2), impact.Namespaces)
	require.Equal(t, int32(3), impact.Resources)
	require.Equal(t, map[configv1alpha1.SSVCExposure]int32{open: 1, small: 2, controlled: 0, unknown: 0}, impact.WorkloadsByExposure)
	owners := make([]string, 0, len(impact.Owners))
	for _, o := range impact.Owners {
		owners = append(owners, o.Cluster+"/"+o.Namespace)
	}
	require.Equal(t, []string{clusterB + "/team-b", clusterB + "/team-c"}, owners)

	selected, _ = selectCases(t, s, i, cases.Selection{})
	require.Equal(t, []string{clusterA, clusterB}, selected[0].Impact.ClusterNames, "without clusters, every cluster counts")
	require.Equal(t, int32(7), selected[0].Impact.Resources)
}

// The hub judges a platform manifest by the clusters that run it: those of each digest whose facts name it, but those
// whose nodes run another platform.
func TestAManifestRunsInTheClustersOfItsPlatform(t *testing.T) {
	manifest := digestOf(23)
	arm := in(clusterA, namespace("team-a", 1, 0))
	arm.Platforms = []string{"linux/arm64"}
	i := &images{}
	i.runs(manifest, arm, in(clusterB, namespace("team-b", 1, 0)), in("cluster-c", namespace("team-c", 1, 0)))

	clusters, err := cases.ClustersOf(ctx, i, manifest)

	require.NoError(t, err)
	require.Equal(t, []string{clusterB, "cluster-c"}, clusters)
}

// An image that runs only in clusters that the playbook's match doesn't select runs nowhere for the playbook: an
// investigation, which leaves out an image that runs nowhere, skips its case as not running. So does a match that
// selects no cluster at all.
func TestAnImageThatRunsOnlyInClustersThatDoNotMatchIsNotRunningForThePlaybook(t *testing.T) {
	manifest := digestOf(22)
	s := &sheets{}
	s.put(manifest, playbook, finding(cve1, "lib"))
	i := &images{}
	i.runs(manifest, in(clusterB, namespace("team-a", 1, 0)))
	notRunning := []cases.Skipped{{ManifestDigest: manifest, VulnerabilityID: cve1, Reason: "not running"}}

	for name, clusters := range map[string][]string{"another cluster": {clusterA}, "no cluster": {}} {
		t.Run(name, func(t *testing.T) {
			selected, skipped := selectCases(t, s, i, cases.Selection{Clusters: clusters, SkipNotRunning: true})

			require.Empty(t, selected)
			require.Equal(t, notRunning, skipped)
		})
	}
}
