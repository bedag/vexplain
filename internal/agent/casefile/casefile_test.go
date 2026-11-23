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

package casefile_test

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"k8s.io/utils/ptr"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
	inventoryv1alpha1 "github.com/bedag/vexplain/api/inventory/v1alpha1"
	"github.com/bedag/vexplain/internal/agent/casefile"
	"github.com/bedag/vexplain/internal/agent/cases"
)

const (
	manifest = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	clusterA = "cluster-a"
)

// aCase returns a case of one vulnerability in two packages, which runs in two namespaces whose owner values
// attribution copied.
func aCase() cases.Case {
	finding := func(id, name string) inventoryv1alpha1.Finding {
		return inventoryv1alpha1.Finding{
			VulnerabilityID: "CVE-2026-0001", Aliases: []string{"GHSA-aaaa-bbbb-cccc"},
			Package: inventoryv1alpha1.PackageReference{ID: id, Name: name, Version: ptr.To("1.0.9-2"), Type: "deb"},
			Status:  inventoryv1alpha1.VEXStatusUnderInvestigation, Rule: ptr.To("completeness-guard"),
			Reason: ptr.To("the image holds binaries that no package owns"), Severity: inventoryv1alpha1.SeverityHigh,
			FixState: inventoryv1alpha1.FixStateNotFixed, KnownExploited: inventoryv1alpha1.KnownExploitedNotListed,
		}
	}
	owner := func(source inventoryv1alpha1.OwnerSource, key, value string) inventoryv1alpha1.OwnerValue {
		return inventoryv1alpha1.OwnerValue{Source: source, Key: key, Value: ptr.To(value)}
	}
	return cases.Case{
		ManifestDigest: manifest, VulnerabilityID: "CVE-2026-0001",
		Findings: []inventoryv1alpha1.Finding{finding("pkg-1", "libbrotli1"), finding("pkg-2", "libbrotli-dev")},
		Subject: cases.Subject{ManifestDigest: manifest, Repositories: []string{"artifacts.example/team-a/app"},
			Platform: "linux/amd64"},
		Impact: cases.Impact{
			Clusters: 1, Namespaces: 2, Resources: 3, UrgentResources: 1,
			HighestExposure: configv1alpha1.SSVCExposureOpen, HighestUrgency: configv1alpha1.SSVCOutcomeOutOfCycle,
			WorkloadsByExposure: map[configv1alpha1.SSVCExposure]int32{configv1alpha1.SSVCExposureOpen: 1,
				configv1alpha1.SSVCExposureSmall: 2, configv1alpha1.SSVCExposureControlled: 0},
			ClusterNames: []string{clusterA},
			Owners: []cases.NamespaceOwners{
				{Cluster: clusterA, Namespace: "team-a", Owner: []inventoryv1alpha1.OwnerValue{
					owner(inventoryv1alpha1.OwnerSourceNamespaceLabel, "owner-label-key", "owner-label-value"),
					owner(inventoryv1alpha1.OwnerSourceNamespaceAnnotation, "owner-annotation-key", "owner-annotation-value"),
				}},
				{Cluster: clusterA, Namespace: "team-b"},
			},
		},
	}
}

// sbom is the case's SBOM, as its producer delivered it.
// brotliName is the SBOM's line of its package's name.
const brotliName = `packages[0].name = "libbrotli1"`

var sbom = map[string][]json.RawMessage{
	"sbom":     {json.RawMessage(`{"packages":[{"id":"pkg-1","name":"libbrotli1","version":"1.0.9-2"}]}`)},
	"contents": nil,
}

func TestTheCaseFileCarriesNoOwnerValues(t *testing.T) {
	file, err := casefile.Build(aCase(), sbom, nil, 64000)
	require.NoError(t, err)

	text := string(file.JSON)
	for _, owner := range []string{"owner-label-key", "owner-label-value", "owner-annotation-key", "owner-annotation-value",
		"NamespaceLabel", "NamespaceAnnotation"} {
		require.NotContains(t, text, owner)
	}
	// Where the subject runs stays: the clusters, the namespaces by name, and the workloads by exposure.
	var got struct {
		VulnerabilityID string `json:"vulnerabilityID"`
		Findings        []inventoryv1alpha1.Finding
		Subject         struct{ Repositories []string }
		RunsIn          struct {
			Clusters            []string
			Namespaces          []struct{ Cluster, Name string }
			WorkloadsByExposure map[string]int32
		}
		Evidence []struct {
			Name  string
			Lines int
		}
		Cut []string
	}
	require.NoError(t, json.Unmarshal(file.JSON, &got))
	require.Equal(t, "CVE-2026-0001", got.VulnerabilityID)
	require.Len(t, got.Findings, 2)
	require.Equal(t, "the image holds binaries that no package owns", *got.Findings[0].Reason)
	require.Equal(t, []string{"artifacts.example/team-a/app"}, got.Subject.Repositories)
	require.Equal(t, []string{clusterA}, got.RunsIn.Clusters)
	require.Equal(t, []struct{ Cluster, Name string }{{clusterA, "team-a"}, {clusterA, "team-b"}}, got.RunsIn.Namespaces)
	require.Equal(t, map[string]int32{"Open": 1, "Small": 2}, got.RunsIn.WorkloadsByExposure)
	require.Equal(t, []struct {
		Name  string
		Lines int
	}{{"contents", 0}, {"sbom", 3}}, got.Evidence)
	require.Empty(t, got.Cut)
}

// Over its cap, the case file keeps the names of its evidence, and says what it left out.
func TestACaseFileOverItsCapIsCutAndSaysSo(t *testing.T) {
	c := aCase()
	for i := range 400 {
		c.Impact.ClusterNames = append(c.Impact.ClusterNames, fmt.Sprintf("cluster-%03d", i))
	}

	file, err := casefile.Build(c, sbom, nil, 4000)

	require.NoError(t, err)
	require.LessOrEqual(t, len(file.JSON), 4000)
	text := string(file.JSON)
	require.Contains(t, text, `"sbom"`)
	require.Contains(t, text, `"contents"`)
	require.Contains(t, text, "libbrotli-dev", "the findings fit, once the clusters are cut")
	require.Len(t, file.Cut, 1)
	require.Contains(t, file.Cut[0], "of 401 clusters")
	require.Contains(t, text, file.Cut[0])

	_, err = casefile.Build(c, sbom, nil, 100)
	require.Error(t, err, "a case file that can't fit even cut")
}

// workloadOf returns the subject of the Deployment of the name in the namespace of cluster-a.
func workloadOf(namespace, name string) string {
	return "workload/" + clusterA + "/" + namespace + "/Deployment.apps/" + name
}

// The case file shows the workloads by their exposure, as design 5.8 shows it: each group with the rules that decided
// it, or the inputs that it lacked, its count, and its first workloads by subject, and none of the workloads' labels.
func TestTheCaseFileShowsTheWorkloadsByExposure(t *testing.T) {
	c := aCase()
	c.Impact.Exposure = []cases.ExposureGroup{
		{Exposure: configv1alpha1.SSVCExposureOpen, Rules: []string{"published-or-unchecked"}, Workloads: 1,
			First: []string{workloadOf("team-b", "admin")}},
		{Exposure: configv1alpha1.SSVCExposureUnknown, Missing: []string{"dmz"}, Workloads: 3,
			First: []string{workloadOf("team-c", "api")}},
		{Exposure: configv1alpha1.SSVCExposureControlled, Rules: []string{"exposed-not-published", "reachable-in-cluster"},
			Workloads: 1, First: []string{workloadOf("team-a", "shop")}},
	}

	file, err := casefile.Build(c, sbom, nil, 64000)

	require.NoError(t, err)
	var got struct {
		RunsIn struct {
			Exposure json.RawMessage `json:"exposure"`
		} `json:"runsIn"`
	}
	require.NoError(t, json.Unmarshal(file.JSON, &got))
	require.JSONEq(t, `[
		{"exposure": "Open", "rules": ["published-or-unchecked"], "workloads": 1,
		 "first": ["workload/cluster-a/team-b/Deployment.apps/admin"]},
		{"exposure": "Unknown", "missing": ["dmz"], "workloads": 3,
		 "first": ["workload/cluster-a/team-c/Deployment.apps/api"]},
		{"exposure": "Controlled", "rules": ["exposed-not-published", "reachable-in-cluster"], "workloads": 1,
		 "first": ["workload/cluster-a/team-a/Deployment.apps/shop"]}
	]`, string(got.RunsIn.Exposure), "the groups, by subject, without labels")
	require.NotContains(t, string(file.JSON), "owner-label-value")

	c.Impact.Exposure = nil
	file, err = casefile.Build(c, sbom, nil, 64000)
	require.NoError(t, err)
	require.NotContains(t, string(file.JSON), `"exposure"`, "a case without groups shows none")
}

// Over its cap, the case file cuts its groups by exposure from their end, the least exposed first, once it has cut
// the namespaces, and before the findings.
func TestACaseFileCutsTheExposureGroupsAfterTheNamespaces(t *testing.T) {
	c := aCase()
	for n := range 40 {
		c.Impact.Owners = append(c.Impact.Owners, cases.NamespaceOwners{Cluster: clusterA, Namespace: fmt.Sprintf("team-%02d", n)})
	}
	for n := range cases.MaxExposureGroups {
		g := cases.ExposureGroup{Exposure: configv1alpha1.SSVCExposureSmall, Rules: []string{fmt.Sprintf("rule-%02d", n)},
			Workloads: 5}
		if n == 0 {
			g.Exposure = configv1alpha1.SSVCExposureOpen
		}
		for w := range cases.MaxGroupFirst {
			g.First = append(g.First, workloadOf(fmt.Sprintf("team-%02d", n), fmt.Sprintf("app-%d", w)))
		}
		c.Impact.Exposure = append(c.Impact.Exposure, g)
	}

	file, err := casefile.Build(c, sbom, nil, 3000)

	require.NoError(t, err)
	require.LessOrEqual(t, len(file.JSON), 3000)
	at := func(path string) int {
		return slices.IndexFunc(file.Cut, func(note string) bool { return strings.HasPrefix(note, path+":") })
	}
	require.GreaterOrEqual(t, at("runsIn.namespaces"), 0, file.Cut)
	require.Greater(t, at("runsIn.exposure"), at("runsIn.namespaces"), file.Cut)
	require.Contains(t, file.Cut[at("runsIn.exposure")], "of 16 groups")
	require.Negative(t, at("findings"), "the findings fit once the groups are cut")
	require.Contains(t, string(file.JSON), `"exposure":"Open"`, "the most exposed group stays")
	require.NotContains(t, string(file.JSON), "rule-15", "the least exposed go first")
}

// The evidence is searched as path = value lines, ignoring case.
func TestTheEvidenceIsSearchedAsLines(t *testing.T) {
	file, err := casefile.Build(aCase(), sbom, nil, 64000)
	require.NoError(t, err)

	lines, total, ok := file.Search("sbom", "LIBBROTLI", 200)
	require.True(t, ok)
	require.Equal(t, 1, total)
	require.Equal(t, []string{brotliName}, lines)

	lines, total, ok = file.Search("sbom", "", 2)
	require.True(t, ok)
	require.Equal(t, 3, total)
	require.Equal(t, []string{`packages[0].id = "pkg-1"`, brotliName}, lines)

	_, _, ok = file.Search("secrets", "a", 200)
	require.False(t, ok)
	require.True(t, strings.Contains(strings.Join(file.Names(), ","), "contents"))
}

// Several terms separated by | find the lines that hold any of them, so that one search covers what took many.
func TestSeveralTermsFindTheLinesThatHoldAnyOfThem(t *testing.T) {
	file, err := casefile.Build(aCase(), sbom, nil, 64000)
	require.NoError(t, err)

	lines, total, ok := file.Search("sbom", "Brotli|1.0.9|absent", 200)
	require.True(t, ok)
	require.Equal(t, 2, total)
	require.Equal(t, []string{brotliName, `packages[0].version = "1.0.9-2"`}, lines)

	lines, total, _ = file.Search("sbom", "libbrotli|brotli1", 200)
	require.Equal(t, 1, total, "a line that holds two terms counts once")
	require.Equal(t, []string{brotliName}, lines)

	_, total, _ = file.Search("sbom", "libbrotli1 | pkg-1", 200)
	require.Equal(t, 2, total, "the spaces around a | are no part of a term")

	_, total, _ = file.Search("sbom", "absent | | other", 200)
	require.Zero(t, total, "a term of spaces only is empty, not one that every line holds")

	_, total, _ = file.Search("sbom", "pkg-1||absent", 200)
	require.Equal(t, 1, total, "an empty term is ignored, not taken as matching every line")

	_, total, _ = file.Search("sbom", "|", 200)
	require.Zero(t, total, "a query of separators only holds no term")
}

func TestTheCaseFileNamesEachFindingsPurlAndDistro(t *testing.T) {
	packages := map[string]casefile.Package{
		"pkg-1": {PURL: "pkg:deb/debian/libbrotli1@1.0.9-2", Distro: "debian-12"},
		"pkg-2": {PURL: "pkg:golang/stdlib@1.22.0"},
	}
	file, err := casefile.Build(aCase(), sbom, packages, 64000)
	require.NoError(t, err)

	var got struct {
		Findings []struct {
			Package struct{ ID string }
			PURL    string `json:"purl"`
			Distro  string `json:"distro"`
		}
	}
	require.NoError(t, json.Unmarshal(file.JSON, &got))
	require.Len(t, got.Findings, 2)
	require.Equal(t, "pkg:deb/debian/libbrotli1@1.0.9-2", got.Findings[0].PURL)
	require.Equal(t, "debian-12", got.Findings[0].Distro)
	require.Equal(t, "pkg:golang/stdlib@1.22.0", got.Findings[1].PURL)
	require.NotContains(t, string(file.JSON), `"distro":""`)
	require.Equal(t, 1, strings.Count(string(file.JSON), `"distro"`), "a Go module has no distro")
}
