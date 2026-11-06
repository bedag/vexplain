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

package spoke_test

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"k8s.io/utils/ptr"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
	inventoryv1alpha1 "github.com/bedag/vexplain/api/inventory/v1alpha1"
	triagev1alpha1 "github.com/bedag/vexplain/api/triage/v1alpha1"
	"github.com/bedag/vexplain/internal/settings"
	"github.com/bedag/vexplain/internal/spoke"
	"github.com/bedag/vexplain/internal/urgency"
	"github.com/bedag/vexplain/sdk/evidence"
)

// The tests of Render hold its inputs in memory: the renderer is pure.

// The names that the tests of the renderer share.
const (
	webName    = "web"
	teamLabel  = "team"
	scanSource = "scanner"
)

// hexDigest returns the sha256 digest that is made of the number n.
func hexDigest(n int) string { return fmt.Sprintf("sha256:%064x", n) }

// The image of the tests, and the manifests of its two platforms.
var (
	imageDigest   = hexDigest(1)
	manifestAMD64 = hexDigest(2)
	manifestARM64 = hexDigest(3)
)

// factsOf returns the facts of an image with a manifest for each platform, and the evidence that the scanner
// delivered at coverage 100.
func factsOf() *inventoryv1alpha1.ImageFacts {
	return &inventoryv1alpha1.ImageFacts{
		Manifests: []inventoryv1alpha1.ManifestFact{
			{Platform: linuxAMD64, Digest: manifestAMD64}, {Platform: linuxARM64, Digest: manifestARM64},
		},
		Evidence: []inventoryv1alpha1.EvidenceFact{{
			Source: scanSource, Type: scannerType, Coverage: ptr.To(int32(100)),
		}},
	}
}

// openFinding returns an Affected finding of a package, with a fix.
func openFinding(id, pkg string) inventoryv1alpha1.Finding {
	return inventoryv1alpha1.Finding{
		VulnerabilityID: id,
		Package:         inventoryv1alpha1.PackageReference{ID: "id-" + pkg, Name: pkg, Version: ptr.To("1.0"), Type: "deb"},
		Status:          inventoryv1alpha1.VEXStatusAffected,
		Rule:            ptr.To("known-exploited"),
		Severity:        inventoryv1alpha1.SeverityHigh,
		FixState:        inventoryv1alpha1.FixStateFixed,
		FixedVersions:   []string{"1.1", "1.2"},
		KnownExploited:  inventoryv1alpha1.KnownExploitedNotListed,
	}
}

// sheetOf returns the sheet of a manifest with the findings, counted, and the coverage of its evidence.
func sheetOf(manifest string, coverage int32, findings ...inventoryv1alpha1.Finding) *inventoryv1alpha1.ImageVerdicts {
	var counts inventoryv1alpha1.FindingCounts
	counts.Affected, counts.UnderInvestigation = ptr.To(int32(0)), ptr.To(int32(0))
	counts.NotAffected, counts.Fixed = ptr.To(int32(0)), ptr.To(int32(0))
	for _, f := range findings {
		switch f.Status {
		case inventoryv1alpha1.VEXStatusAffected:
			*counts.Affected++
		case inventoryv1alpha1.VEXStatusUnderInvestigation:
			*counts.UnderInvestigation++
		case inventoryv1alpha1.VEXStatusNotAffected:
			*counts.NotAffected++
		case inventoryv1alpha1.VEXStatusFixed:
			*counts.Fixed++
		}
	}
	return &inventoryv1alpha1.ImageVerdicts{
		Spec: inventoryv1alpha1.ImageVerdictsSpec{ManifestDigest: manifest},
		Status: inventoryv1alpha1.ImageVerdictsStatus{
			Playbook: ptr.To("container-cves"), FindingsVersion: ptr.To("v1"), Findings: findings, Counts: &counts,
			Evidence: []inventoryv1alpha1.SheetEvidence{{
				Name: "scan", Source: scanSource, Type: scannerType,
				Coverage: ptr.To(coverage),
			}},
		},
	}
}

// renderOn renders the workload that runs the image on amd64, with the sheet of that platform's manifest.
func renderOn(sheet *inventoryv1alpha1.ImageVerdicts, exposure configv1alpha1.SSVCExposure,
) triagev1alpha1.WorkloadReportStatus {
	sheets := map[string]*inventoryv1alpha1.ImageVerdicts{}
	if sheet != nil {
		sheets[manifestAMD64] = sheet
	}
	return spoke.Render(running(teamA, webName, linuxAMD64), []spoke.RunningImage{{Digest: imageDigest,
		Platforms: []string{linuxAMD64}}}, sheets,
		map[string]*inventoryv1alpha1.ImageFacts{imageDigest: factsOf()}, exposure, settings.Effective{})
}

func TestRenderListsTheOpenFindingsWithTheirUrgencyAndNextStep(t *testing.T) {
	kev := openFinding("CVE-2026-0001", "libkev")
	kev.KnownExploited = inventoryv1alpha1.KnownExploitedListed
	unclear := openFinding("CVE-2026-0002", "libunclear")
	unclear.Status, unclear.Rule, unclear.FixState, unclear.FixedVersions = inventoryv1alpha1.VEXStatusUnderInvestigation, nil,
		inventoryv1alpha1.FixStateNotFixed, nil
	unfixable := openFinding("CVE-2026-0003", "libunfixable")
	unfixable.FixState, unfixable.FixedVersions = inventoryv1alpha1.FixStateNotFixed, nil
	settled := openFinding("CVE-2026-0004", "libsettled")
	settled.Status = inventoryv1alpha1.VEXStatusNotAffected
	fixed := openFinding("CVE-2026-0005", "libfixed")
	fixed.Status = inventoryv1alpha1.VEXStatusFixed

	got := renderOn(sheetOf(manifestAMD64, 100, kev, unclear, unfixable, settled, fixed), configv1alpha1.SSVCExposureOpen)

	require.Len(t, got.Findings, 3, "NotAffected and Fixed findings are counted, never listed")
	ids := []string{got.Findings[0].VulnerabilityID, got.Findings[1].VulnerabilityID, got.Findings[2].VulnerabilityID}
	require.Equal(t, []string{"CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003"}, ids,
		"the most urgent first, then the most severe, then by ID")
	first := got.Findings[0]
	require.Equal(t, triagev1alpha1.SSVCOutcomeImmediate, first.Urgency)
	require.Equal(t, triagev1alpha1.SSVCOutcome(urgency.Decide(urgency.FromFinding(unclear, configv1alpha1.SSVCExposureOpen), nil)),
		got.Findings[1].Urgency,
		"the urgency of a finding is what the deployer tree decides")
	require.Equal(t, triagev1alpha1.NextStepUpdate, first.NextStep)
	require.Equal(t, ptr.To("1.1"), first.FixedVersion, "the first fixed version")
	require.Equal(t, triagev1alpha1.ReviewStateRuleSettled, first.ReviewState)
	require.Equal(t, triagev1alpha1.NextStepInvestigate, got.Findings[1].NextStep, "unclear, and no fix")
	require.Equal(t, triagev1alpha1.ReviewStateOpen, got.Findings[1].ReviewState, "no rule settled it")
	require.Equal(t, triagev1alpha1.NextStepMitigate, got.Findings[2].NextStep, "affected, and no fix")
	require.Equal(t, triagev1alpha1.SeverityHigh, first.Severity)
	require.Equal(t, triagev1alpha1.ReportPackage{Name: "libkev", Version: ptr.To("1.0"), Type: "deb"}, first.Package)
	require.Equal(t, triagev1alpha1.ReportCounts{Affected: ptr.To(int32(2)), UnderInvestigation: ptr.To(int32(1)),
		NotAffected: ptr.To(int32(1)), Fixed: ptr.To(int32(1))}, *got.Counts, "counts covers every status")
	require.Equal(t, ptr.To(int32(0)), got.Omitted)
	require.Equal(t, ptr.To(triagev1alpha1.SSVCExposureOpen), got.Exposure)
}

func TestRenderTakesTheUrgencyFromTheExposureAndTheOverrides(t *testing.T) {
	f := openFinding("CVE-2026-0001", "libexample")
	f.CVSS = []inventoryv1alpha1.CVSS{{Version: ptr.To("3.1"), Vector: ptr.To("CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:L")}}
	sheet := sheetOf(manifestAMD64, 100, f)
	in := func(exposure configv1alpha1.SSVCExposure) urgency.Inputs { return urgency.FromFinding(f, exposure) }

	small := renderOn(sheet, configv1alpha1.SSVCExposureSmall)
	unknown := renderOn(sheet, configv1alpha1.SSVCExposureUnknown)

	require.Equal(t, triagev1alpha1.SSVCOutcome(urgency.Decide(in(configv1alpha1.SSVCExposureSmall), nil)), small.Findings[0].Urgency)
	require.Equal(t, triagev1alpha1.SSVCOutcome(urgency.Decide(in(configv1alpha1.SSVCExposureOpen), nil)), unknown.Findings[0].Urgency,
		"an unknown exposure counts as open")
	require.Equal(t, ptr.To(triagev1alpha1.SSVCExposureUnknown), unknown.Exposure, "the report says it is unknown")

	override := []configv1alpha1.UrgencyOverride{{
		Exploitation: in(configv1alpha1.SSVCExposureSmall).Exploitation, Exposure: configv1alpha1.SSVCExposureSmall,
		Automatable: in(configv1alpha1.SSVCExposureSmall).Automatable, HumanImpact: in(configv1alpha1.SSVCExposureSmall).HumanImpact,
		Outcome: configv1alpha1.SSVCOutcomeImmediate,
	}}
	got := spoke.Render(running(teamA, webName, linuxAMD64), []spoke.RunningImage{{Digest: imageDigest, Platforms: []string{linuxAMD64}}},
		map[string]*inventoryv1alpha1.ImageVerdicts{manifestAMD64: sheet},
		map[string]*inventoryv1alpha1.ImageFacts{imageDigest: factsOf()}, configv1alpha1.SSVCExposureSmall,
		settings.Effective{Urgency: configv1alpha1.Urgency{Overrides: override}})
	require.Equal(t, triagev1alpha1.SSVCOutcomeImmediate, got.Findings[0].Urgency, "an admin's override of the row wins")
}

func TestRenderGivesEachImageAStateFromItsSheet(t *testing.T) {
	counts := func(affected, settled int32) *inventoryv1alpha1.FindingCounts {
		return &inventoryv1alpha1.FindingCounts{Affected: ptr.To(affected), UnderInvestigation: ptr.To(int32(0)),
			NotAffected: ptr.To(settled), Fixed: ptr.To(int32(0))}
	}
	for name, tc := range map[string]struct {
		sheet *inventoryv1alpha1.ImageVerdicts
		want  triagev1alpha1.ReportImageState
	}{
		"no sheet": {nil, triagev1alpha1.ReportImageStatePending},
		"a sheet without counts": {&inventoryv1alpha1.ImageVerdicts{Status: inventoryv1alpha1.ImageVerdictsStatus{
			FindingsVersion: ptr.To("v1")}}, triagev1alpha1.ReportImageStatePending},
		"a sheet without a findings version": {&inventoryv1alpha1.ImageVerdicts{Status: inventoryv1alpha1.ImageVerdictsStatus{
			Counts: counts(0, 0)}}, triagev1alpha1.ReportImageStatePending},
		"a complete sheet": {&inventoryv1alpha1.ImageVerdicts{Status: inventoryv1alpha1.ImageVerdictsStatus{
			FindingsVersion: ptr.To("v1"), Counts: counts(2, 3), OmittedFindings: ptr.To(int32(0))}}, triagev1alpha1.ReportImageStateReady},
		"a sheet that left out settled findings only": {&inventoryv1alpha1.ImageVerdicts{Status: inventoryv1alpha1.ImageVerdictsStatus{
			FindingsVersion: ptr.To("v1"), Counts: counts(2, 3), OmittedFindings: ptr.To(int32(3))}}, triagev1alpha1.ReportImageStateReady},
		"a sheet that left out more than the settled findings": {&inventoryv1alpha1.ImageVerdicts{Status: inventoryv1alpha1.ImageVerdictsStatus{
			FindingsVersion: ptr.To("v1"), Counts: counts(2, 3), OmittedFindings: ptr.To(int32(4))}}, triagev1alpha1.ReportImageStateIncomplete},
	} {
		t.Run(name, func(t *testing.T) {
			if tc.sheet != nil {
				tc.sheet.Spec.ManifestDigest = manifestAMD64
			}

			got := renderOn(tc.sheet, configv1alpha1.SSVCExposureSmall)

			require.Len(t, got.Images, 1)
			require.Equal(t, tc.want, got.Images[0].State)
			require.Equal(t, imageDigest, got.Images[0].Digest)
			require.Equal(t, ptr.To(linuxAMD64), got.Images[0].Platform)
			if tc.sheet != nil {
				require.Equal(t, ptr.To(manifestAMD64), got.Images[0].ManifestDigest)
			} else {
				require.Equal(t, ptr.To(manifestAMD64), got.Images[0].ManifestDigest,
					"the facts name the manifest, though no sheet of it exists yet")
			}
		})
	}
}

// An image whose evidence covers little, and which has no findings, is Ready. The core shows the coverage and never
// reads it.
func TestRenderShowsTheCoverageOfAnImageWithoutFindingsAndKeepsItReady(t *testing.T) {
	got := renderOn(sheetOf(manifestAMD64, 80), configv1alpha1.SSVCExposureSmall)

	require.Equal(t, triagev1alpha1.ReportImageStateReady, got.Images[0].State)
	require.Equal(t, []triagev1alpha1.ReportCoverage{{Source: scanSource,
		Type: scannerType, Coverage: ptr.To(int32(80))}}, got.Images[0].Coverage)
	require.Empty(t, got.Findings)
}

// A sheet's evidence is per manifest, so it gives the coverage of a platform. The facts keep the lowest across
// platforms, and so give it only where no sheet exists.
func TestRenderTakesCoverageFromTheSheetAndFromTheFactsOnlyWithoutOne(t *testing.T) {
	withSheet := renderOn(sheetOf(manifestAMD64, 80), configv1alpha1.SSVCExposureSmall)
	without := renderOn(nil, configv1alpha1.SSVCExposureSmall)

	require.Equal(t, ptr.To(int32(80)), withSheet.Images[0].Coverage[0].Coverage, "the sheet's, and not the facts' 100")
	require.Equal(t, ptr.To(int32(100)), without.Images[0].Coverage[0].Coverage, "the facts'")
	require.Equal(t, triagev1alpha1.ReportImageStatePending, without.Images[0].State)
}

func TestRenderGivesAnImageOnePerPlatformItsPodsRun(t *testing.T) {
	w := running(teamA, webName, linuxAMD64, linuxARM64)
	sheets := map[string]*inventoryv1alpha1.ImageVerdicts{
		manifestAMD64: sheetOf(manifestAMD64, 100, openFinding("CVE-2026-0001", "libexample")),
		manifestARM64: sheetOf(manifestARM64, 100, openFinding("CVE-2026-0001", "libexample"), openFinding("CVE-2026-0002", "libarm")),
	}

	got := spoke.Render(w, []spoke.RunningImage{{Digest: imageDigest, Platforms: []string{linuxAMD64, linuxARM64}}}, sheets,
		map[string]*inventoryv1alpha1.ImageFacts{imageDigest: factsOf()}, configv1alpha1.SSVCExposureSmall, settings.Effective{})

	require.Len(t, got.Images, 2)
	require.Equal(t, ptr.To(manifestAMD64), got.Images[0].ManifestDigest)
	require.Equal(t, ptr.To(manifestARM64), got.Images[1].ManifestDigest)
	require.Len(t, got.Findings, 2, "a vulnerability in a package is listed once, whatever the platform")
	require.Equal(t, ptr.To(int32(3)), got.Counts.Affected, "counts adds up the sheets, as each platform has its own")
}

// A pod that says no platform gives no manifest, unless the image has only one: no sheet is guessed.
func TestRenderLeavesTheManifestOutWhenNoPodSaysThePlatformAndTheImageHasSeveral(t *testing.T) {
	got := spoke.Render(running(teamA, webName), []spoke.RunningImage{{Digest: imageDigest}}, nil,
		map[string]*inventoryv1alpha1.ImageFacts{imageDigest: factsOf()}, configv1alpha1.SSVCExposureSmall, settings.Effective{})

	require.Len(t, got.Images, 1)
	require.Nil(t, got.Images[0].Platform)
	require.Nil(t, got.Images[0].ManifestDigest)
	require.Equal(t, triagev1alpha1.ReportImageStatePending, got.Images[0].State)
}

func TestRenderMakesTextFromImageContentPrintableAndBounded(t *testing.T) {
	f := openFinding("CVE-2026-0001\x1b[31m", strings.Repeat("p", 300))
	f.Reason = ptr.To("known\nexploited\x00" + strings.Repeat("r", 300))
	f.Package.Version = ptr.To("1.0\u202e")
	f.FixedVersions = []string{"\x07" + strings.Repeat("v", 200)}

	got := renderOn(sheetOf(manifestAMD64, 100, f), configv1alpha1.SSVCExposureSmall)

	out := got.Findings[0]
	require.Equal(t, "CVE-2026-0001\ufffd[31m", out.VulnerabilityID)
	require.Equal(t, strings.Repeat("p", 253), out.Package.Name)
	require.Equal(t, ptr.To("1.0\ufffd"), out.Package.Version)
	require.True(t, strings.HasPrefix(*out.Reason, "known\ufffdexploited\ufffd"), *out.Reason)
	require.Len(t, []rune(*out.Reason), 256)
	require.Len(t, []rune(*out.FixedVersion), 128)
	require.True(t, strings.HasPrefix(*out.FixedVersion, "\ufffd"))
}

func TestRenderCarriesTheNotesOfTheRules(t *testing.T) {
	f := openFinding("CVE-2026-0001", "libexample")
	f.StatusNotes = []inventoryv1alpha1.StatusNote{{Rule: "load-check", Text: "nothing in the image names libexample.so\x1b"}}

	got := renderOn(sheetOf(manifestAMD64, 100, f), configv1alpha1.SSVCExposureSmall)

	require.Equal(t, []triagev1alpha1.ReportStatusNote{{Rule: "load-check", Text: "nothing in the image names libexample.so\ufffd"}},
		got.Findings[0].StatusNotes)
}

func manyFindings(n int) []inventoryv1alpha1.Finding {
	findings := make([]inventoryv1alpha1.Finding, 0, n)
	for i := range n {
		findings = append(findings, openFinding(fmt.Sprintf("CVE-2026-%05d", i), "libexample"))
	}
	return findings
}

func TestRenderListsAtMostAThousandFindingsAndCountsTheRest(t *testing.T) {
	got := renderOn(sheetOf(manifestAMD64, 100, manyFindings(1001)...), configv1alpha1.SSVCExposureSmall)

	require.Len(t, got.Findings, 1000)
	require.Equal(t, ptr.To(int32(1)), got.Omitted)
	require.Equal(t, ptr.To(int32(1001)), got.Counts.Affected, "counts covers the finding that the list leaves out")
	require.Equal(t, "CVE-2026-00999", got.Findings[999].VulnerabilityID, "the end of the order is what goes")
}

// At the schema's maximum for every string, a full status is about 2.35 MiB, and etcd takes 1.5 MiB. The report keeps
// its status below 1 MiB, as a sheet does, and cuts the end of the order.
func TestRenderCutsTheFindingsByBytesAtTheLimitsOfEveryString(t *testing.T) {
	findings := make([]inventoryv1alpha1.Finding, 0, 1000)
	for i := range 1000 {
		f := openFinding(fmt.Sprintf("%064d", i), strings.Repeat("p", 253))
		f.Package.Version = ptr.To(strings.Repeat("v", 128))
		f.Package.Type = strings.Repeat("t", 32)
		f.FixedVersions = []string{strings.Repeat("f", 128)}
		f.Reason = ptr.To(strings.Repeat("r", 256))
		for range 4 {
			f.StatusNotes = append(f.StatusNotes, inventoryv1alpha1.StatusNote{Rule: strings.Repeat("n", 63), Text: strings.Repeat("x", 256)})
		}
		findings = append(findings, f)
	}
	w := running(teamA, webName, linuxAMD64)
	for i := range 16 {
		w.Labels = append(w.Labels, evidence.KeyValue{Key: fmt.Sprintf("label-%d", i), Value: strings.Repeat("l", 256)})
		w.NamespaceLabels = append(w.NamespaceLabels, evidence.KeyValue{Key: fmt.Sprintf("label-%d", i), Value: strings.Repeat("l", 256)})
		w.NamespaceAnnotations = append(w.NamespaceAnnotations, evidence.KeyValue{Key: fmt.Sprintf("note-%d", i), Value: strings.Repeat("l", 256)})
	}
	images := make([]spoke.RunningImage, 0, 8)
	facts := map[string]*inventoryv1alpha1.ImageFacts{}
	sheets := map[string]*inventoryv1alpha1.ImageVerdicts{}
	for i := range 8 {
		digest := hexDigest(100 + i)
		images = append(images, spoke.RunningImage{Digest: digest, Platforms: []string{linuxAMD64}})
		manifest := hexDigest(200 + i)
		facts[digest] = &inventoryv1alpha1.ImageFacts{Manifests: []inventoryv1alpha1.ManifestFact{{Platform: linuxAMD64, Digest: manifest}}}
		sheets[manifest] = sheetOf(manifest, 100)
	}
	sheets[hexDigest(200)] = sheetOf(hexDigest(200), 100, findings...)

	got := spoke.Render(w, images, sheets, facts, configv1alpha1.SSVCExposureOpen, settings.Effective{})

	encoded, err := json.Marshal(got)
	require.NoError(t, err)
	require.LessOrEqual(t, len(encoded), 1<<20, "the status stays below 1 MiB")
	require.Greater(t, len(encoded), 1<<20-4096, "and holds as many findings as fit")
	require.Less(t, len(got.Findings), 1000)
	require.Equal(t, int32(1000-len(got.Findings)), *got.Omitted, "omitted counts the rest")
	require.Equal(t, ptr.To(int32(1000)), got.Counts.Affected)
	require.Len(t, got.Owner, 48)
}

func TestRenderCopiesTheOwnerValuesAndBoundsThem(t *testing.T) {
	w := running(teamA, webName, linuxAMD64)
	w.Labels = []evidence.KeyValue{{Key: teamLabel, Value: teamA}, {Key: "empty", Value: ""}}
	w.NamespaceLabels = []evidence.KeyValue{{Key: "owner", Value: strings.Repeat("o", 300)}}
	w.NamespaceAnnotations = []evidence.KeyValue{{Key: "example.org/contact", Value: "a\x1bb"}}

	got := spoke.Render(w, nil, nil, nil, configv1alpha1.SSVCExposureSmall, settings.Effective{})

	require.Equal(t, []triagev1alpha1.OwnerValue{
		{Source: triagev1alpha1.OwnerSourceNamespaceLabel, Key: "owner", Value: ptr.To(strings.Repeat("o", 256))},
		{Source: triagev1alpha1.OwnerSourceNamespaceAnnotation, Key: "example.org/contact", Value: ptr.To("a\ufffdb")},
		{Source: triagev1alpha1.OwnerSourceWorkloadLabel, Key: "empty", Value: ptr.To("")},
		{Source: triagev1alpha1.OwnerSourceWorkloadLabel, Key: teamLabel, Value: ptr.To(teamA)},
	}, got.Owner)
}

func TestRenderListsNoImageItCannotName(t *testing.T) {
	got := spoke.Render(running(teamA, webName, linuxAMD64), []spoke.RunningImage{{Digest: "sha512:abc", Platforms: []string{linuxAMD64}}},
		nil, nil, configv1alpha1.SSVCExposureSmall, settings.Effective{})

	require.Empty(t, got.Images, "a digest that isn't a sha256 digest is no digest of the API")
}

func TestReportNameIsTheKindAndTheNameOrAHashWhenThatIsTooLong(t *testing.T) {
	require.Equal(t, "deployment-web", spoke.ReportName(running(teamA, webName)))
	long := running(teamA, strings.Repeat("n", 250))
	name := spoke.ReportName(long)
	require.LessOrEqual(t, len(name), 253)
	require.True(t, strings.HasPrefix(name, "deployment-"))
	require.NotEqual(t, name, spoke.ReportName(running(teamA, strings.Repeat("n", 251))), "a hash tells long names apart")
	require.Equal(t, name, spoke.ReportName(long), "and is stable")
}

// An image past the 32 entries of the list has no entry, but its sheet still counts and its findings are still listed:
// a limit never hides a finding.
func TestRenderCountsAndListsTheFindingsOfImagesPastTheEntryLimit(t *testing.T) {
	images := make([]spoke.RunningImage, 0, 40)
	facts := map[string]*inventoryv1alpha1.ImageFacts{}
	sheets := map[string]*inventoryv1alpha1.ImageVerdicts{}
	for i := range 40 {
		digest, manifest := hexDigest(1000+i), hexDigest(2000+i)
		images = append(images, spoke.RunningImage{Digest: digest, Platforms: []string{linuxAMD64}})
		facts[digest] = &inventoryv1alpha1.ImageFacts{Manifests: []inventoryv1alpha1.ManifestFact{{Platform: linuxAMD64, Digest: manifest}}}
		sheets[manifest] = sheetOf(manifest, 100, openFinding(fmt.Sprintf("CVE-2026-%05d", i), "libexample"))
	}

	got := spoke.Render(running(teamA, webName, linuxAMD64), images, sheets, facts, configv1alpha1.SSVCExposureSmall, settings.Effective{})

	require.Len(t, got.Images, 32, "the list holds 32 entries")
	require.Len(t, got.Findings, 40, "the findings cover every image")
	require.Equal(t, ptr.To(int32(40)), got.Counts.Affected, "and so do the counts")
	require.Equal(t, ptr.To(int32(0)), got.Omitted)
}
