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
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"
	"testing"

	cloudevents "github.com/cloudevents/sdk-go/v2"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/utils/ptr"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
	inventoryv1alpha1 "github.com/bedag/vexplain/api/inventory/v1alpha1"
	triagev1alpha1 "github.com/bedag/vexplain/api/triage/v1alpha1"
	"github.com/bedag/vexplain/internal/agent/cases"
	"github.com/bedag/vexplain/internal/evidence"
	"github.com/bedag/vexplain/internal/inventory"
	"github.com/bedag/vexplain/internal/rules/engine"
	"github.com/bedag/vexplain/internal/urgency"
	sdkevidence "github.com/bedag/vexplain/sdk/evidence"
	subjects "github.com/bedag/vexplain/sdk/subject"
)

const (
	playbook   = "container-cves"
	repository = "artifacts.example/team-a/web"
	amd64      = "linux/amd64"
	// criticalVector is a CVSS vector that reads as automatable, with a high human impact.
	criticalVector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
	cve1           = "CVE-2026-0001"
	// sbom and missing name evidence of a case file, sbom of the type sbomType.
	sbom     = "sbom"
	sbomType = "sbom-type"
	missing  = "missing"
	scanner  = "scanner"
	// clusterB is the cluster that runs the images of the tests, and exposedNotPublished an exposure rule of a source.
	clusterB            = "cluster-b"
	exposedNotPublished = "exposed-not-published"
)

var ctx = context.Background()

func digestOf(n int) string { return fmt.Sprintf("sha256:%064x", n) }

// finding returns an open finding of the vulnerability in the package, as a sheet holds it, which the rules can read.
func finding(id, pkg string) inventoryv1alpha1.Finding {
	return inventoryv1alpha1.Finding{
		VulnerabilityID: id,
		Package:         inventoryv1alpha1.PackageReference{ID: pkg + "-id", Name: pkg, Version: ptr.To("1.0"), Type: "apk"},
		Status:          inventoryv1alpha1.VEXStatusUnderInvestigation,
		Severity:        inventoryv1alpha1.SeverityHigh,
		FixState:        inventoryv1alpha1.FixStateNotFixed,
		KnownExploited:  inventoryv1alpha1.KnownExploitedNotListed,
	}
}

func exploited(f inventoryv1alpha1.Finding) inventoryv1alpha1.Finding {
	f.KnownExploited = inventoryv1alpha1.KnownExploitedListed
	return f
}

func withEPSS(f inventoryv1alpha1.Finding, permille int32) inventoryv1alpha1.Finding {
	f.EPSSPermille = ptr.To(permille)
	return f
}

// sheets is a VerdictsStore that holds sheets in memory.
type sheets struct {
	inventory.VerdictsStore
	list []inventoryv1alpha1.ImageVerdicts
}

func (s *sheets) put(manifest, playbook string, findings ...inventoryv1alpha1.Finding) {
	s.list = append(s.list, inventoryv1alpha1.ImageVerdicts{
		Spec:   inventoryv1alpha1.ImageVerdictsSpec{ManifestDigest: manifest, Playbook: playbook},
		Status: inventoryv1alpha1.ImageVerdictsStatus{Findings: findings},
	})
}

func (s *sheets) Each(_ context.Context, fn func(*inventoryv1alpha1.ImageVerdicts) error) error {
	for i := range s.list {
		if err := fn(&s.list[i]); err != nil {
			return err
		}
	}
	return nil
}

// images is an inventory Store that holds its objects in memory.
type images struct {
	inventory.Store
	objects map[string]*inventoryv1alpha1.ImageInventory
}

func (i *images) Get(_ context.Context, digest string) (*inventoryv1alpha1.ImageInventory, error) {
	return i.objects[digest], nil
}

func (i *images) ManifestReferences(_ context.Context, manifest string) ([]string, error) {
	var found []string
	for digest, obj := range i.objects {
		if obj.Status.Facts != nil && slices.ContainsFunc(obj.Status.Facts.Manifests,
			func(m inventoryv1alpha1.ManifestFact) bool { return m.Digest == manifest }) {
			found = append(found, digest)
		}
	}
	return found, nil
}

// runs has the image of one platform, whose manifest is its digest, run in the clusters.
func (i *images) runs(manifest string, clusters ...inventoryv1alpha1.ClusterPresence) {
	if i.objects == nil {
		i.objects = map[string]*inventoryv1alpha1.ImageInventory{}
	}
	i.objects[manifest] = &inventoryv1alpha1.ImageInventory{
		Spec: inventoryv1alpha1.ImageInventorySpec{Digest: manifest},
		Status: inventoryv1alpha1.ImageInventoryStatus{
			Clusters: clusters,
			Facts:    &inventoryv1alpha1.ImageFacts{Manifests: []inventoryv1alpha1.ManifestFact{{Platform: amd64, Digest: manifest}}},
		},
	}
}

// in returns a cluster's entry that runs workloads in the namespaces, each with its counts by exposure.
func in(cluster string, namespaces ...inventoryv1alpha1.NamespacePresence) inventoryv1alpha1.ClusterPresence {
	var workloads int32
	for _, ns := range namespaces {
		c := ns.WorkloadsByExposure
		workloads += ptr.Deref(c.Open, 0) + ptr.Deref(c.Controlled, 0) + ptr.Deref(c.Small, 0) + ptr.Deref(c.Unknown, 0)
	}
	return inventoryv1alpha1.ClusterPresence{
		Cluster: cluster, ClusterID: cluster + "-id", Repositories: []string{repository}, Platforms: []string{amd64},
		NamespaceCount: ptr.To(int32(len(namespaces))), WorkloadCount: ptr.To(workloads), Namespaces: namespaces,
	}
}

func namespace(name string, open, small int32) inventoryv1alpha1.NamespacePresence {
	return inventoryv1alpha1.NamespacePresence{
		Name:                name,
		Owner:               []inventoryv1alpha1.OwnerValue{{Source: inventoryv1alpha1.OwnerSourceNamespaceLabel, Key: "team", Value: ptr.To(name)}},
		WorkloadsByExposure: inventoryv1alpha1.ExposureCounts{Open: ptr.To(open), Small: ptr.To(small)},
	}
}

func conditions(t *testing.T, conds ...engine.Condition) *engine.Conditions {
	t.Helper()
	c, err := engine.CompileConditions(conds)
	require.NoError(t, err)
	return c
}

func selectCases(t *testing.T, s *sheets, i *images, sel cases.Selection) ([]cases.Case, []cases.Skipped) {
	t.Helper()
	if sel.Playbook == "" {
		sel.Playbook = playbook
	}
	selected, skipped, err := cases.Select(ctx, s, i, sel)
	require.NoError(t, err)
	return selected, skipped
}

func idsOf(selected []cases.Case) []string {
	ids := make([]string, 0, len(selected))
	for _, c := range selected {
		ids = append(ids, c.VulnerabilityID)
	}
	return ids
}

// Review Focus 1: the investigation names the CVE, and the finding is keyed by its GHSA ID.
func TestAnAliasSelectsTheCase(t *testing.T) {
	manifest := digestOf(1)
	ghsa := finding("GHSA-xxxx-xxxx-xxxx", "lib")
	ghsa.Aliases = []string{cve1}
	s := &sheets{}
	s.put(manifest, playbook, ghsa, finding("CVE-2026-0002", "other"))
	s.put(manifest, "another-playbook", ghsa)
	i := &images{}
	i.runs(manifest, in(clusterB, namespace("team-a", 1, 0)))

	selected, skipped := selectCases(t, s, i, cases.Selection{Vulnerabilities: []string{cve1}})

	require.Empty(t, skipped)
	require.Len(t, selected, 1)
	require.Equal(t, "GHSA-xxxx-xxxx-xxxx", selected[0].VulnerabilityID)
	require.Equal(t, manifest, selected[0].ManifestDigest)
	require.Equal(t, []string{repository}, selected[0].Subject.Repositories)
	require.Equal(t, amd64, selected[0].Subject.Platform)
}

func TestOneCaseCoversEveryPackageOfItsVulnerability(t *testing.T) {
	manifest := digestOf(2)
	s := &sheets{}
	s.put(manifest, playbook, finding(cve1, "lib-b"), finding(cve1, "lib-a"), finding("CVE-2026-0002", "lib-a"))
	i := &images{}
	i.runs(manifest, in(clusterB, namespace("team-a", 1, 0)))

	selected, _ := selectCases(t, s, i, cases.Selection{Vulnerabilities: []string{cve1}})

	require.Len(t, selected, 1)
	require.Len(t, selected[0].Findings, 2)
	require.Equal(t, "lib-a", selected[0].Findings[0].Package.Name, "the findings of a case are sorted by package")
}

func TestBothConditionSetsMustHold(t *testing.T) {
	manifest := digestOf(3)
	s := &sheets{}
	s.put(manifest, playbook,
		withEPSS(exploited(finding(cve1, "lib")), 500), // both hold
		exploited(finding("CVE-2026-0002", "lib")),     // the investigation's doesn't
		withEPSS(finding("CVE-2026-0003", "lib"), 500)) // the playbook's doesn't
	i := &images{}
	i.runs(manifest, in(clusterB, namespace("team-a", 1, 0)))

	selected, skipped := selectCases(t, s, i, cases.Selection{
		PlaybookConditions: conditions(t, engine.Condition{Name: "exploited", Expression: "finding.knownExploited"}),
		Conditions:         conditions(t, engine.Condition{Name: "likely", Expression: "has(finding.epssPermille) && finding.epssPermille >= 100"}),
	})

	require.Equal(t, []string{cve1}, idsOf(selected))
	require.Len(t, skipped, 2)
	reasons := map[string]string{}
	for _, k := range skipped {
		reasons[k.VulnerabilityID] = k.Reason
	}
	require.Contains(t, reasons["CVE-2026-0002"], `"likely"`)
	require.Contains(t, reasons["CVE-2026-0003"], `"exploited"`)
	require.Contains(t, reasons["CVE-2026-0003"], "playbook")
}

// The conditions see the finding as the rules made it (design 5.3): where the agent's verdict, or an accepted
// statement, changed the sheet's status, they read the rules' status that the agent field keeps. So the case that the
// agent judged stays selected by the playbook's condition of the cases that may go to the agent, and every other
// condition still applies.
func TestTheConditionsSeeTheRulesStatusOfACaseThatTheAgentJudged(t *testing.T) {
	manifest := digestOf(5)
	judged := func(id string, severity inventoryv1alpha1.Severity) inventoryv1alpha1.Finding {
		f := finding(id, "lib")
		f.Status, f.Severity = inventoryv1alpha1.VEXStatusAffected, severity
		f.Agent = &inventoryv1alpha1.AgentVerdict{Assessment: cases.Name(id, manifest), Status: inventoryv1alpha1.VEXStatusAffected,
			RuleStatus: ptr.To(inventoryv1alpha1.VEXStatusUnderInvestigation)}
		return f
	}
	// A rule's Affected that the agent's Affected confirms: the agent changed nothing, so the rules' status is the sheet's.
	byRule := finding("CVE-2026-0002", "lib")
	byRule.Status, byRule.Severity = inventoryv1alpha1.VEXStatusAffected, inventoryv1alpha1.SeverityCritical
	byRule.Agent = &inventoryv1alpha1.AgentVerdict{Assessment: cases.Name("CVE-2026-0002", manifest),
		Status: inventoryv1alpha1.VEXStatusAffected}
	s := &sheets{}
	s.put(manifest, playbook, judged(cve1, inventoryv1alpha1.SeverityCritical), byRule,
		judged("CVE-2026-0003", inventoryv1alpha1.SeverityLow))
	i := &images{}
	i.runs(manifest, in(clusterB, namespace("team-a", 1, 0)))

	selected, skipped := selectCases(t, s, i, cases.Selection{
		PlaybookConditions: conditions(t, engine.Condition{Name: "unsettled", Expression: `finding.status == "UnderInvestigation"`}),
		Conditions:         conditions(t, engine.Condition{Name: "critical", Expression: `finding.severity == "Critical"`}),
	})

	require.Equal(t, []string{cve1}, idsOf(selected))
	reasons := map[string]string{}
	for _, k := range skipped {
		reasons[k.VulnerabilityID] = k.Reason
	}
	require.Contains(t, reasons["CVE-2026-0002"], `"unsettled"`, "a rule's Affected is no case for the agent")
	require.Contains(t, reasons["CVE-2026-0003"], `"critical"`)
}

func TestAConditionThatFailsSkipsOnlyItsCase(t *testing.T) {
	manifest := digestOf(4)
	s := &sheets{}
	s.put(manifest, playbook,
		withEPSS(finding(cve1, "lib"), 500),
		finding("CVE-2026-0002", "lib"), // no EPSS: the condition fails to evaluate
		withEPSS(finding("CVE-2026-0003", "lib"), 900))
	i := &images{}
	i.runs(manifest, in(clusterB, namespace("team-a", 1, 0)))

	selected, skipped := selectCases(t, s, i, cases.Selection{
		Conditions: conditions(t, engine.Condition{Name: "likely", Expression: "finding.epssPermille >= 100"}),
	})

	require.ElementsMatch(t, []string{cve1, "CVE-2026-0003"}, idsOf(selected))
	require.Len(t, skipped, 1)
	require.Equal(t, "CVE-2026-0002", skipped[0].VulnerabilityID)
	require.Equal(t, manifest, skipped[0].ManifestDigest)
	require.Contains(t, skipped[0].Reason, `"likely"`)
}

// fourScores gives a finding four CVSS scores, as many as a sheet shows, so that rules.Matches can't give its match back
// for the rules.
func fourScores(f inventoryv1alpha1.Finding) inventoryv1alpha1.Finding {
	for _, v := range []string{"2.0", "3.0", "3.1", "4.0"} {
		f.CVSS = append(f.CVSS, inventoryv1alpha1.CVSS{Version: ptr.To(v), Vector: ptr.To(criticalVector)})
	}
	return f
}

// The conditions only select, so a finding that the rules couldn't evaluate again from its sheet is still read.
func TestAFindingWithManyScoresIsSelected(t *testing.T) {
	manifest := digestOf(10)
	s := &sheets{}
	s.put(manifest, playbook, fourScores(exploited(finding(cve1, "lib"))))
	i := &images{}
	i.runs(manifest, in(clusterB, namespace("team-a", 2, 0)))

	selected, skipped := selectCases(t, s, i, cases.Selection{PlaybookConditions: conditions(t), Conditions: conditions(t)})

	require.Empty(t, skipped)
	require.Len(t, selected, 1)
	require.Equal(t, int32(2), selected[0].Impact.Resources)
	require.Equal(t, configv1alpha1.SSVCExposureOpen, selected[0].Impact.HighestExposure)

	selected, skipped = selectCases(t, s, i, cases.Selection{Conditions: conditions(t, engine.Condition{Name: "read",
		Expression: `finding.knownExploited && size(finding.cvss) == 4 && finding.packageName == "lib" && ` +
			`finding.fixState == "not-fixed" && finding.status == "UnderInvestigation" && !has(finding.epssPermille)`})})

	require.Empty(t, skipped)
	require.Len(t, selected, 1)
}

func TestTheConditionsSeeTheSubjectAndTheImpact(t *testing.T) {
	manifest := digestOf(5)
	s := &sheets{}
	s.put(manifest, playbook, finding(cve1, "lib"))
	i := &images{}
	i.runs(manifest, in(clusterB, namespace("team-a", 2, 1)))

	selected, _ := selectCases(t, s, i, cases.Selection{Conditions: conditions(t, engine.Condition{Name: "where",
		Expression: `subject.manifestDigest == "` + manifest + `" && "` + repository + `" in subject.repositories && ` +
			`subject.platform == "linux/amd64" && impact.clusters == 1 && impact.namespaces == 1 && impact.resources == 3 && ` +
			`impact.highestExposure == "Open" && impact.highestUrgency != "" && finding.status == "UnderInvestigation" && ` +
			`finding.packageName == "lib"`})})

	require.Len(t, selected, 1)
}

func TestTheOrderIsByTiers(t *testing.T) {
	c := func(id string, u configv1alpha1.SSVCOutcome, known bool, epss int32, resources int32) cases.Case {
		f := withEPSS(finding(id, "lib"), epss)
		if known {
			f = exploited(f)
		}
		return cases.Case{VulnerabilityID: id, Findings: []inventoryv1alpha1.Finding{f},
			Impact: cases.Impact{HighestUrgency: u, Resources: resources}}
	}
	list := []cases.Case{
		c("a", configv1alpha1.SSVCOutcomeOutOfCycle, true, 900, 50),
		c("b", configv1alpha1.SSVCOutcomeImmediate, false, 10, 1),
		c("c", configv1alpha1.SSVCOutcomeImmediate, true, 10, 1),
		c("d", configv1alpha1.SSVCOutcomeImmediate, false, 500, 1),
		c("e", configv1alpha1.SSVCOutcomeImmediate, false, 500, 9),
	}

	slices.SortFunc(list, func(x, y cases.Case) int {
		if cases.Less(x, y) {
			return -1
		}
		if cases.Less(y, x) {
			return 1
		}
		return 0
	})

	require.Equal(t, []string{"c", "e", "d", "b", "a"}, idsOf(list))
}

func TestImpactCountsTheUrgentResources(t *testing.T) {
	manifest := digestOf(6)
	f := exploited(finding(cve1, "lib"))
	f.CVSS = []inventoryv1alpha1.CVSS{{Version: ptr.To("3.1"), Vector: ptr.To(criticalVector)}}
	s := &sheets{}
	s.put(manifest, playbook, f)
	i := &images{}
	names := []string{"team-a", "team-b", "team-c", "team-d", "team-e", "team-f"}
	presence := make([]inventoryv1alpha1.NamespacePresence, 0, len(names))
	presence = append(presence, namespace("team-a", 2, 1))
	for _, name := range names[1:] {
		presence = append(presence, namespace(name, 0, 0))
	}
	i.runs(manifest, in(clusterB, presence...))
	// A cluster whose nodes run another platform doesn't run this manifest.
	arm := in("cluster-c", namespace("team-z", 5, 0))
	arm.Platforms = []string{"linux/arm64"}
	i.objects[manifest].Status.Clusters = append(i.objects[manifest].Status.Clusters, arm)
	// The override has a small exposure defer the update, so the two levels decide differently.
	small := urgency.FromFinding(f, configv1alpha1.SSVCExposureSmall)
	overrides := []configv1alpha1.UrgencyOverride{{Exploitation: small.Exploitation, Exposure: small.Exposure,
		Automatable: small.Automatable, HumanImpact: small.HumanImpact, Outcome: configv1alpha1.SSVCOutcomeDefer}}

	selected, _ := selectCases(t, s, i, cases.Selection{Overrides: overrides})

	require.Len(t, selected, 1)
	impact := selected[0].Impact
	open := urgency.Decide(urgency.FromFinding(f, configv1alpha1.SSVCExposureOpen), overrides)
	want := int32(0)
	if open == configv1alpha1.SSVCOutcomeImmediate || open == configv1alpha1.SSVCOutcomeOutOfCycle {
		want = 2
	}
	require.Equal(t, want, impact.UrgentResources)
	require.Equal(t, open, impact.HighestUrgency)
	require.Equal(t, configv1alpha1.SSVCExposureOpen, impact.HighestExposure)
	require.Equal(t, int32(1), impact.Clusters)
	require.Equal(t, int32(6), impact.Namespaces)
	require.Equal(t, int32(3), impact.Resources)
	require.Len(t, impact.Owners, 5, "the owners of the first 5 namespaces")
	for n, owners := range impact.Owners {
		require.Equal(t, clusterB, owners.Cluster)
		require.Equal(t, names[n], owners.Namespace)
		require.Equal(t, names[n], *owners.Owner[0].Value)
	}
}

func TestTheNameIsStableAndValid(t *testing.T) {
	manifest := digestOf(7)
	name := cases.Name("RHSA-2026:1234", manifest)

	require.Equal(t, name, cases.Name("RHSA-2026:1234", manifest))
	require.Empty(t, validation.IsDNS1123Subdomain(name), name)
	require.True(t, strings.HasPrefix(name, "rhsa-2026-1234-"), name)
	require.NotEqual(t, name, cases.Name("RHSA-2026-1234", manifest), "IDs that differ in a replaced character")
	require.NotEqual(t, name, cases.Name("RHSA-2026:1234", digestOf(8)))
	long := cases.Name(strings.Repeat("X", 300), manifest)
	require.Empty(t, validation.IsDNS1123Subdomain(long), long)

	labels := cases.Labels("RHSA-2026:1234", manifest)
	require.Equal(t, "RHSA-2026_1234", labels[cases.VulnerabilityLabel])
	require.Equal(t, strings.TrimPrefix(manifest, "sha256:")[:63], labels[cases.DigestLabel])
	for key, value := range cases.Labels(strings.Repeat("a", 62)+":"+strings.Repeat("b", 10), manifest) {
		require.Empty(t, validation.IsQualifiedName(key), key)
		require.Empty(t, validation.IsValidLabelValue(value), value)
	}
}

func TestTheInputHashIgnoresEPSSAndTheDatabase(t *testing.T) {
	a, b := finding(cve1, "lib-a"), finding(cve1, "lib-b")
	data := map[string][]string{sbom: {"x"}}
	base := cases.InputHash([]inventoryv1alpha1.Finding{a, b}, data)
	require.True(t, strings.HasPrefix(base, "sha256:"), base)

	moved := a
	moved.EPSSPermille = ptr.To(int32(900))
	moved.KnownExploited = inventoryv1alpha1.KnownExploitedListed
	moved.CVSS = []inventoryv1alpha1.CVSS{{Version: ptr.To("3.1"), Vector: ptr.To(criticalVector)}}
	moved.FixState = inventoryv1alpha1.FixStateFixed
	moved.FixedVersions = []string{"1.1"}
	moved.Status = inventoryv1alpha1.VEXStatusAffected
	require.Equal(t, base, cases.InputHash([]inventoryv1alpha1.Finding{b, moved}, data),
		"EPSS, CVSS, KEV, a fix, the status and the order change nothing")

	other := a
	other.Package.Version = ptr.To("1.1")
	require.NotEqual(t, base, cases.InputHash([]inventoryv1alpha1.Finding{other, b}, data), "another package version")
	require.NotEqual(t, base, cases.InputHash([]inventoryv1alpha1.Finding{a, b}, map[string][]string{sbom: {"y"}}),
		"other evidence data")
	require.Equal(t, cases.InputHash([]inventoryv1alpha1.Finding{a}, nil), cases.InputHash([]inventoryv1alpha1.Finding{a}, map[string][]string{}))
}

// records is an evidence Store that holds records in memory.
type records struct {
	evidence.Store
	held map[evidence.Key][]byte
}

func (r *records) Get(_ context.Context, k evidence.Key) (*evidence.Record, error) {
	data, ok := r.held[k]
	if !ok {
		return nil, nil
	}
	e := cloudevents.NewEvent()
	if err := e.SetData(cloudevents.ApplicationJSON, data); err != nil {
		return nil, err
	}
	return &evidence.Record{Key: k, Event: e}, nil
}

// The database's version is in the sheet's evidence, and only the data of the case file's evidence counts.
func TestTheEvidenceHashesAreOfTheCaseFilesData(t *testing.T) {
	manifest := digestOf(9)
	sheet := &inventoryv1alpha1.ImageVerdicts{Spec: inventoryv1alpha1.ImageVerdictsSpec{ManifestDigest: manifest},
		Status: inventoryv1alpha1.ImageVerdictsStatus{Evidence: []inventoryv1alpha1.SheetEvidence{
			{Name: sbom, Source: scanner, Type: sbomType, Version: ptr.To("1")},
			{Name: sbom, Source: "scanner-b", Type: sbomType, Version: ptr.To("1")},
			{Name: "contents", Source: scanner, Type: "contents-type", Version: ptr.To("1")},
			{Name: missing, Source: scanner, Type: "missing-type"},
		}}}
	store := &records{held: map[evidence.Key][]byte{
		{Subject: subjects.Manifest(manifest), Type: sbomType, Source: scanner}:        []byte(`{"a":1}`),
		{Subject: subjects.Manifest(manifest), Type: sbomType, Source: "scanner-b"}:    []byte(`{"b":1}`),
		{Subject: subjects.Manifest(manifest), Type: "contents-type", Source: scanner}: []byte(`{"c":1}`),
	}}
	sum := func(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }

	hashes, err := cases.EvidenceHashes(ctx, store, sheet, []string{sbom, missing})

	require.NoError(t, err)
	want := []string{sum(`{"a":1}`), sum(`{"b":1}`)}
	slices.Sort(want)
	require.Equal(t, map[string][]string{sbom: want, missing: nil}, hashes)

	sheet.Status.Evidence[0].Version = ptr.To("2")
	again, err := cases.EvidenceHashes(ctx, store, sheet, []string{sbom, missing})
	require.NoError(t, err)
	require.Equal(t, hashes, again, "a new version of the collector with the same data")
}

// scanOf returns the data of a scan of the manifest, as the scanner writes it: the SBOM, with its producer and the
// producer's document, which names the directory that the image was unpacked to, and the image's contents. Each
// package has the ID that the producer gave it.
func scanOf(producerVersion, unpackedTo, libVersion, idPrefix string) (sbomData, contentsData []byte) {
	sbomData = fmt.Appendf(nil, `{"distro": {"id": "debian", "version": "12"},
		"packages": [
			{"id": "%[4]s-2", "name": "libexample2", "version": "2.0-1", "type": "deb", "purl": "pkg:deb/debian/libexample2@2.0-1?distro=debian-12"},
			{"id": "%[4]s-1", "name": "libexample1", "version": "%[3]s", "type": "deb", "purl": "pkg:deb/debian/libexample1@%[3]s?distro=debian-12", "cpes": ["cpe:2.3:a:%[4]s"]}
		],
		"producer": {"name": "syft", "version": "%[1]s"},
		"failedCatalogers": ["java"],
		"catalogerFailures": [{"cataloger": "java", "packageTypes": ["java-archive"]}],
		"document": {"format": "syft-json", "content": {
			"descriptor": {"name": "syft", "version": "%[1]s"},
			"source": {"id": "%[2]s", "name": "%[2]s", "metadata": {"path": "%[2]s"}}}}}`,
		producerVersion, unpackedTo, libVersion, idPrefix)
	contentsData = []byte(`{"platform": "linux/amd64", "digest": "sha256:1",
		"libraries": [{"path": "/usr/lib/libexample1.so.1", "soname": "libexample1.so.1", "reachedCount": 1}]}`)
	return sbomData, contentsData
}

// The hash of a case's inputs rests on facts: a rescan of the same image, by a newer producer that unpacks it to a
// directory of its own and numbers the packages anew, changes nothing, and a package of another version does.
func TestTheInputHashRestsOnTheFactsOfTheScan(t *testing.T) {
	const contents = "contents"
	manifest := digestOf(10)
	sheet := &inventoryv1alpha1.ImageVerdicts{Spec: inventoryv1alpha1.ImageVerdictsSpec{ManifestDigest: manifest},
		Status: inventoryv1alpha1.ImageVerdictsStatus{Evidence: []inventoryv1alpha1.SheetEvidence{
			{Name: sbom, Source: scanner, Type: sdkevidence.TypeSBOM, Version: ptr.To("1")},
			{Name: contents, Source: scanner, Type: "ch.bedag.vexplain.scanner.image-contents.v1alpha1", Version: ptr.To("1")},
		}}}
	hashOf := func(producerVersion, unpackedTo, libVersion, idPrefix string) string {
		t.Helper()
		sbomData, contentsData := scanOf(producerVersion, unpackedTo, libVersion, idPrefix)
		store := &records{held: map[evidence.Key][]byte{
			{Subject: subjects.Manifest(manifest), Type: sdkevidence.TypeSBOM, Source: scanner}:          sbomData,
			{Subject: subjects.Manifest(manifest), Type: sheet.Status.Evidence[1].Type, Source: scanner}: contentsData,
		}}
		hashes, err := cases.EvidenceHashes(ctx, store, sheet, []string{sbom, contents})
		require.NoError(t, err)
		f := finding(cve1, "libexample1")
		f.Package.ID, f.Package.Version = idPrefix+"-1", ptr.To(libVersion)
		return cases.InputHash([]inventoryv1alpha1.Finding{f}, hashes)
	}

	first := hashOf("1.0.0", "/tmp/manifest-111", "1.0-1", "a1b2")
	require.Equal(t, first, hashOf("1.1.0", "/tmp/manifest-222", "1.0-1", "c3d4"),
		"a rescan by a newer producer, unpacked elsewhere, with new package IDs")
	require.NotEqual(t, first, hashOf("1.0.0", "/tmp/manifest-111", "1.0-2", "a1b2"), "another version of the package")
}

func TestACaseWhoseImageRunsNowhereIsNotSelected(t *testing.T) {
	gone, running := digestOf(1), digestOf(2)
	s := &sheets{}
	s.put(gone, playbook, finding(cve1, "lib"))
	s.put(running, playbook, finding(cve1, "lib"))
	i := &images{}
	i.runs(running, in(clusterB, namespace("team-a", 1, 0)))

	// The condition fails on every case, but it isn't evaluated for the image that runs nowhere.
	selected, skipped := selectCases(t, s, i, cases.Selection{SkipNotRunning: true,
		Conditions: conditions(t, engine.Condition{Name: "broken", Expression: "finding.nothing == 1"}),
	})

	require.Empty(t, selected)
	require.Len(t, skipped, 2)
	for _, k := range skipped {
		if k.ManifestDigest == gone {
			require.Equal(t, "not running", k.Reason)
			require.False(t, k.Failed)
		} else {
			require.True(t, k.Failed)
		}
	}
}

func TestRebuildingACaseWhoseImageRunsNowhereStillYieldsIt(t *testing.T) {
	s := &sheets{}
	s.put(digestOf(1), playbook, finding(cve1, "lib"))

	selected, skipped := selectCases(t, s, &images{}, cases.Selection{Vulnerabilities: []string{cve1}})

	require.Equal(t, []string{cve1}, idsOf(selected))
	require.Empty(t, skipped)
}

// The exposures of the tests' workloads.
const (
	open       = configv1alpha1.SSVCExposureOpen
	unknown    = configv1alpha1.SSVCExposureUnknown
	controlled = configv1alpha1.SSVCExposureControlled
	small      = configv1alpha1.SSVCExposureSmall
)

// exposures is an Exposures that names, in each place whose presence it knows, the workloads that a test gives it,
// each with the exposure that the test gives it, as a playbook's exposure rules would decide it.
type exposures struct {
	named map[cases.Place][]cases.WorkloadExposure
	// asked records the playbook and the manifest of each call.
	asked []string
}

func (e *exposures) Of(_ context.Context, playbook, manifest string, places []cases.Place) (
	map[cases.Place][]cases.WorkloadExposure, error) {
	e.asked = append(e.asked, playbook+" "+manifest)
	found := map[cases.Place][]cases.WorkloadExposure{}
	for _, p := range places {
		if workloads, known := e.named[p]; known {
			found[p] = workloads
		}
	}
	return found, nil
}

// decided returns the Deployment of the name in team-a of cluster-b, whose exposure the rules decided.
func decided(name string, exposure configv1alpha1.SSVCExposure, rules ...string) cases.WorkloadExposure {
	return cases.WorkloadExposure{Subject: "workload/" + clusterB + "/team-a/Deployment.apps/" + name,
		WorkloadExposure: engine.WorkloadExposure{Exposure: exposure, Rules: rules}}
}

// The inventory counts both workloads at the spoke's Open, and the rules decide Controlled and Small: the case's
// groups, its highest exposure, its urgency and the conditions follow the rules.
func TestACasesWorkloadsTakeTheirExposureFromTheRules(t *testing.T) {
	manifest := digestOf(11)
	f := exploited(finding(cve1, "lib"))
	f.CVSS = []inventoryv1alpha1.CVSS{{Version: ptr.To("3.1"), Vector: ptr.To(criticalVector)}}
	s := &sheets{}
	s.put(manifest, playbook, f)
	i := &images{}
	i.runs(manifest, in(clusterB, namespace("team-a", 2, 0)))
	// Controlled and Small defer the case, so that an urgency at the inventory's Open can't pass for it.
	overrides := make([]configv1alpha1.UrgencyOverride, 0, 2)
	for _, exposure := range []configv1alpha1.SSVCExposure{controlled, small} {
		at := urgency.FromFinding(f, exposure)
		overrides = append(overrides, configv1alpha1.UrgencyOverride{Exploitation: at.Exploitation, Exposure: at.Exposure,
			Automatable: at.Automatable, HumanImpact: at.HumanImpact, Outcome: configv1alpha1.SSVCOutcomeDefer})
	}
	require.NotEqual(t, configv1alpha1.SSVCOutcomeDefer, urgency.Decide(urgency.FromFinding(f, open), overrides))
	shop := decided("shop", controlled, exposedNotPublished, "reachable-in-cluster")
	batch := decided("batch", small, "own-namespace-only")
	e := &exposures{named: map[cases.Place][]cases.WorkloadExposure{{Digest: manifest, Cluster: clusterB}: {batch, shop}}}

	selected, skipped := selectCases(t, s, i, cases.Selection{Exposures: e, Overrides: overrides, SkipNotRunning: true,
		Conditions: conditions(t, engine.Condition{Name: "rules", Expression: `impact.highestExposure == "Controlled" && ` +
			`impact.highestUrgency == "Defer"`})})

	require.Empty(t, skipped)
	require.Len(t, selected, 1)
	impact := selected[0].Impact
	require.Equal(t, []cases.ExposureGroup{
		{Exposure: controlled, Rules: []string{exposedNotPublished, "reachable-in-cluster"}, Workloads: 1,
			First: []string{shop.Subject}},
		{Exposure: small, Rules: []string{"own-namespace-only"}, Workloads: 1, First: []string{batch.Subject}},
	}, impact.Exposure)
	require.Equal(t, controlled, impact.HighestExposure)
	require.Equal(t, configv1alpha1.SSVCOutcomeDefer, impact.HighestUrgency)
	require.Equal(t, map[configv1alpha1.SSVCExposure]int32{controlled: 1, small: 1}, impact.WorkloadsByExposure)
	require.Zero(t, impact.UrgentResources)
	require.Equal(t, int32(2), impact.Resources, "the inventory still counts the workloads")
	require.Equal(t, []string{playbook + " " + manifest}, e.asked, "once for the manifest, under the case's playbook")
}

// Review Focus 1: a workload that the inventory counts and presence doesn't name is Unknown, so is every workload of a
// cluster whose presence hasn't reached the hub, and such a case still runs.
func TestACaseCountsWorkloadsThatPresenceDoesntNameAsUnknown(t *testing.T) {
	manifest := digestOf(12)
	s := &sheets{}
	s.put(manifest, playbook, finding(cve1, "lib"))
	i := &images{}
	i.runs(manifest, in(clusterB, namespace("team-a", 0, 3)))
	batch := decided("batch", small, "own-namespace-only")
	e := &exposures{named: map[cases.Place][]cases.WorkloadExposure{{Digest: manifest, Cluster: clusterB}: {batch}}}

	selected, skipped := selectCases(t, s, i, cases.Selection{Exposures: e, SkipNotRunning: true})

	require.Empty(t, skipped)
	require.Len(t, selected, 1)
	impact := selected[0].Impact
	require.Equal(t, []cases.ExposureGroup{
		{Exposure: unknown, Workloads: 2},
		{Exposure: small, Rules: []string{"own-namespace-only"}, Workloads: 1, First: []string{batch.Subject}},
	}, impact.Exposure, "the inventory counts 3, and presence names 1")
	require.Equal(t, unknown, impact.HighestExposure)
	require.Equal(t, urgency.Decide(urgency.FromFinding(finding(cve1, "lib"), open), nil), impact.HighestUrgency,
		"Unknown counts as Open")

	// The cluster's presence hasn't reached the hub.
	selected, skipped = selectCases(t, s, i, cases.Selection{Exposures: &exposures{}, SkipNotRunning: true})

	require.Empty(t, skipped, "a case whose presence isn't known still runs")
	require.Len(t, selected, 1)
	require.Equal(t, []cases.ExposureGroup{{Exposure: unknown, Workloads: 3}}, selected[0].Impact.Exposure)
	require.Equal(t, map[configv1alpha1.SSVCExposure]int32{unknown: 3}, selected[0].Impact.WorkloadsByExposure)
	require.Equal(t, int32(3), selected[0].Impact.Resources)
}

// A workload that runs the manifest under two reported digests, as an index's and the manifest's own, is one workload
// with one exposure, and counts once in the groups. The inventory counts it under each digest.
func TestAWorkloadUnderTwoDigestsCountsOnceInTheGroups(t *testing.T) {
	manifest, index := digestOf(13), digestOf(14)
	s := &sheets{}
	s.put(manifest, playbook, finding(cve1, "lib"))
	i := &images{}
	i.runs(manifest, in(clusterB, namespace("team-a", 1, 0)))
	i.runs(index, in(clusterB, namespace("team-a", 1, 0)))
	i.objects[index].Status.Facts.Manifests[0].Digest = manifest
	shop := decided("shop", open, "exposed-outside-cluster")
	e := &exposures{named: map[cases.Place][]cases.WorkloadExposure{
		{Digest: manifest, Cluster: clusterB}: {shop},
		{Digest: index, Cluster: clusterB}:    {shop},
	}}

	selected, _ := selectCases(t, s, i, cases.Selection{Exposures: e})

	require.Len(t, selected, 1)
	impact := selected[0].Impact
	require.Equal(t, []cases.ExposureGroup{{Exposure: open, Rules: []string{"exposed-outside-cluster"}, Workloads: 1,
		First: []string{shop.Subject}}}, impact.Exposure)
	require.Equal(t, map[configv1alpha1.SSVCExposure]int32{open: 1}, impact.WorkloadsByExposure)
	require.Equal(t, int32(2), impact.Resources)
}

// A group names its first 5 workloads, sorted, and its first 8 rules and missing inputs. A case keeps its first 16
// groups, Open first, and its counts by exposure hold every workload.
func TestTheGroupsKeepTheFirstFiveAndAtMostSixteen(t *testing.T) {
	manifest := digestOf(15)
	s := &sheets{}
	s.put(manifest, playbook, finding(cve1, "lib"))
	named := make([]cases.WorkloadExposure, 0, 29)
	for n := range 7 {
		named = append(named, decided(fmt.Sprintf("web-%d", 6-n), controlled, "reachable-in-cluster"))
	}
	for n := range 20 {
		named = append(named, decided(fmt.Sprintf("job-%02d", n), small, fmt.Sprintf("rule-%02d", n)))
	}
	many := decided("many", open)
	for n := range 10 {
		many.Rules = append(many.Rules, fmt.Sprintf("open-%d", n))
	}
	lacking := decided("lacking", unknown)
	for n := range 9 {
		lacking.Missing = append(lacking.Missing, fmt.Sprintf("input%d", n))
	}
	named = append(named, many, lacking)
	i := &images{}
	i.runs(manifest, in(clusterB, namespace("team-a", 0, int32(len(named)))))
	e := &exposures{named: map[cases.Place][]cases.WorkloadExposure{{Digest: manifest, Cluster: clusterB}: named}}

	selected, _ := selectCases(t, s, i, cases.Selection{Exposures: e})

	require.Len(t, selected, 1)
	groups := selected[0].Impact.Exposure
	require.Len(t, groups, 16)
	require.Equal(t, cases.ExposureGroup{Exposure: open, Workloads: 1, First: []string{many.Subject},
		Rules: []string{"open-0", "open-1", "open-2", "open-3", "open-4", "open-5", "open-6", "open-7"}}, groups[0])
	require.Equal(t, cases.ExposureGroup{Exposure: unknown, Workloads: 1, First: []string{lacking.Subject},
		Missing: []string{"input0", "input1", "input2", "input3", "input4", "input5", "input6", "input7"}}, groups[1])
	require.Equal(t, controlled, groups[2].Exposure)
	require.Equal(t, int32(7), groups[2].Workloads)
	require.Equal(t, []string{named[6].Subject, named[5].Subject, named[4].Subject, named[3].Subject, named[2].Subject},
		groups[2].First, "the first 5, sorted")
	for n, g := range groups[3:] {
		require.Equal(t, []string{fmt.Sprintf("rule-%02d", n)}, g.Rules, "then by rules")
	}
	require.Equal(t, map[configv1alpha1.SSVCExposure]int32{open: 1, unknown: 1, controlled: 7, small: 20},
		selected[0].Impact.WorkloadsByExposure, "every workload counts")
}

// Without Exposures, the workloads count by the exposure that the inventory holds, and the case has no groups.
func TestWithoutExposuresTheImpactIsAsToday(t *testing.T) {
	manifest := digestOf(16)
	s := &sheets{}
	s.put(manifest, playbook, finding(cve1, "lib"))
	i := &images{}
	i.runs(manifest, in(clusterB, namespace("team-a", 2, 1)))

	selected, _ := selectCases(t, s, i, cases.Selection{})

	require.Len(t, selected, 1)
	impact := selected[0].Impact
	require.Empty(t, impact.Exposure)
	require.Equal(t, open, impact.HighestExposure)
	require.Equal(t, map[configv1alpha1.SSVCExposure]int32{open: 2, small: 1, controlled: 0, unknown: 0},
		impact.WorkloadsByExposure, "each count of the inventory's, as before")
}

// The hub writes where a case runs into its Assessment's queue, and a worker lays it over the case that it rebuilds
// without the exposure rules: the urgency, the urgent workloads, and the workloads by exposure and their groups. The
// queue names the clusters whose workloads the case counts too, which the worker selects with: it can't read the
// Spokes, whose labels say which clusters a playbook's match selects.
func TestRunsInGoesThroughTheQueue(t *testing.T) {
	groups := []cases.ExposureGroup{
		{Exposure: controlled, Rules: []string{exposedNotPublished}, Workloads: 2,
			First: []string{"workload/cluster-b/team-a/Deployment.apps/shop"}},
		{Exposure: unknown, Missing: []string{"dmz"}, Workloads: 1},
	}
	hub := cases.Case{Clusters: []string{clusterB}, Impact: cases.Impact{Resources: 3, UrgentResources: 1,
		HighestExposure: unknown, HighestUrgency: configv1alpha1.SSVCOutcomeOutOfCycle, Exposure: groups,
		WorkloadsByExposure: map[configv1alpha1.SSVCExposure]int32{controlled: 2, unknown: 1}}}

	runsIn := cases.RunsInOf(hub)

	require.Equal(t, &triagev1alpha1.QueueRunsIn{
		HighestExposure: ptr.To(triagev1alpha1.SSVCExposureUnknown), HighestUrgency: ptr.To(triagev1alpha1.SSVCOutcomeOutOfCycle),
		UrgentWorkloads: ptr.To(int32(1)), Clusters: []string{clusterB}, Exposure: []triagev1alpha1.ExposureGroup{
			{Exposure: triagev1alpha1.SSVCExposureControlled, Rules: []string{exposedNotPublished},
				Workloads: ptr.To(int32(2)), First: []string{"workload/cluster-b/team-a/Deployment.apps/shop"}},
			{Exposure: triagev1alpha1.SSVCExposureUnknown, Missing: []string{"dmz"}, Workloads: ptr.To(int32(1))},
		}}, runsIn)

	queue := &triagev1alpha1.AssessmentQueue{RunsIn: runsIn, Order: cases.OrderOf(hub)}
	rebuilt := cases.Impact{Resources: 3, HighestExposure: open, HighestUrgency: configv1alpha1.SSVCOutcomeImmediate,
		UrgentResources: 3, WorkloadsByExposure: map[configv1alpha1.SSVCExposure]int32{open: 3}, ClusterNames: []string{clusterB}}
	rebuilt.LayRunsIn(queue)

	require.Equal(t, cases.Impact{Resources: 3, HighestExposure: unknown, HighestUrgency: configv1alpha1.SSVCOutcomeOutOfCycle,
		UrgentResources: 1, WorkloadsByExposure: map[configv1alpha1.SSVCExposure]int32{controlled: 2, unknown: 1},
		Exposure: groups, ClusterNames: []string{clusterB}}, rebuilt)

	unchanged := cases.Impact{Resources: 1, HighestExposure: open}
	unchanged.LayRunsIn(nil)
	require.Equal(t, cases.Impact{Resources: 1, HighestExposure: open}, unchanged, "a queue without runsIn changes nothing")
	unchanged.LayRunsIn(&triagev1alpha1.AssessmentQueue{})
	require.Equal(t, cases.Impact{Resources: 1, HighestExposure: open}, unchanged, "nor one whose runsIn is empty")
	require.Equal(t, &triagev1alpha1.QueueRunsIn{UrgentWorkloads: ptr.To(int32(0))}, cases.RunsInOf(cases.Case{}),
		"a case that runs nowhere")
}

// A case that several playbooks select is queued with the union of their matching clusters, and the groups of the most
// urgent playbook's view (design of remote spokes 5.8). The worker counts the workloads of the union, and those past
// the view's, as the queue's order counts them, go into the groups as Unknown: the case file never under-states where
// the case runs.
func TestTheWorkloadsPastTheQueuedViewAreUnknown(t *testing.T) {
	view := cases.Case{Clusters: []string{clusterB}, Impact: cases.Impact{Resources: 2, UrgentResources: 2,
		HighestExposure: open, HighestUrgency: configv1alpha1.SSVCOutcomeImmediate,
		WorkloadsByExposure: map[configv1alpha1.SSVCExposure]int32{open: 1, controlled: 1},
		Exposure: []cases.ExposureGroup{
			{Exposure: open, Rules: []string{"published"}, Workloads: 1},
			{Exposure: controlled, Rules: []string{exposedNotPublished}, Workloads: 1},
		}}}
	queue := &triagev1alpha1.AssessmentQueue{RunsIn: cases.RunsInOf(view), Order: cases.OrderOf(view)}
	union := cases.Impact{Resources: 5, ClusterNames: []string{"cluster-a", clusterB}}

	union.LayRunsIn(queue)

	require.Equal(t, map[configv1alpha1.SSVCExposure]int32{open: 1, unknown: 3, controlled: 1}, union.WorkloadsByExposure)
	require.Equal(t, []cases.ExposureGroup{
		{Exposure: open, Rules: []string{"published"}, Workloads: 1},
		{Exposure: unknown, Workloads: 3},
		{Exposure: controlled, Rules: []string{exposedNotPublished}, Workloads: 1},
	}, union.Exposure)
}

// Past the most clusters that an Assessment's queue names, the queue names none, so that a worker counts every
// cluster's workloads, which errs towards counting more, and not those of some of the clusters.
func TestPastTheCapTheQueueNamesNoCluster(t *testing.T) {
	many := make([]string, 257)
	for i := range many {
		many[i] = fmt.Sprintf("cluster-%03d", i)
	}

	require.Nil(t, cases.RunsInOf(cases.Case{Clusters: many}).Clusters)
	require.Equal(t, many[:256], cases.RunsInOf(cases.Case{Clusters: many[:256]}).Clusters)
}
