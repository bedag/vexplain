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

// version12 is a plain fixed version of the tests.
const version12 = "1.2"

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

// openFinding returns an Affected finding of a package, with one fixed version.
func openFinding(id, pkg string) inventoryv1alpha1.Finding {
	return inventoryv1alpha1.Finding{
		VulnerabilityID: id,
		Package:         inventoryv1alpha1.PackageReference{ID: "id-" + pkg, Name: pkg, Version: ptr.To("1.0"), Type: "deb"},
		Status:          inventoryv1alpha1.VEXStatusAffected,
		Rule:            ptr.To("known-exploited"),
		Severity:        inventoryv1alpha1.SeverityHigh,
		FixState:        inventoryv1alpha1.FixStateFixed,
		FixedVersions:   []string{"1.1"},
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
		map[string]*inventoryv1alpha1.ImageFacts{imageDigest: factsOf()}, spoke.WorkloadExposure{SSVC: exposure}, settings.Effective{})
}

// lowCVSS reads as neither automatable nor of high impact, so that with no known exploitation and a Small exposure the
// table defers the finding. A finding without a vector is automatable and of high impact, which the table schedules
// there, and one that is also known to be exploited it takes out of cycle.
var lowCVSS = []inventoryv1alpha1.CVSS{{Version: ptr.To("3.1"), Vector: ptr.To("CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:L")}}

// deferred returns an open finding that the table defers at a Small exposure.
func deferred(id, pkg string) inventoryv1alpha1.Finding {
	f := openFinding(id, pkg)
	f.CVSS = lowCVSS
	return f
}

// exploitedFinding returns an open finding that is known to be exploited.
func exploitedFinding(id, pkg string) inventoryv1alpha1.Finding {
	f := openFinding(id, pkg)
	f.KnownExploited = inventoryv1alpha1.KnownExploitedListed
	return f
}

// withoutFix returns the finding with no fix known, at the status given.
func withoutFix(f inventoryv1alpha1.Finding, status inventoryv1alpha1.VEXStatus) inventoryv1alpha1.Finding {
	f.Status, f.FixState, f.FixedVersions = status, inventoryv1alpha1.FixStateNotFixed, nil
	if status == inventoryv1alpha1.VEXStatusUnderInvestigation {
		f.Rule = nil
	}
	return f
}

// actionOf returns the action of the package with the step, or fails.
func actionOf(t *testing.T, status triagev1alpha1.WorkloadReportStatus, pkg string, step triagev1alpha1.NextStep) triagev1alpha1.ReportAction {
	t.Helper()
	for _, a := range status.Actions {
		if a.Package.Name == pkg && a.Step == step {
			return a
		}
	}
	require.Failf(t, "no action", "the report has no %s of %s: %+v", step, pkg, status.Actions)
	return triagev1alpha1.ReportAction{}
}

// summaryOf returns the summary that the counts give, with the highest urgency.
func summaryOf(affected, underInvestigation, notAffected, fixed, updates, mitigations, investigations, omitted, critical,
	exploited int32, highest *triagev1alpha1.SSVCOutcome) triagev1alpha1.ReportSummary {
	return triagev1alpha1.ReportSummary{
		Affected: ptr.To(affected), UnderInvestigation: ptr.To(underInvestigation), NotAffected: ptr.To(notAffected),
		Fixed: ptr.To(fixed), Actions: ptr.To(updates + mitigations + investigations), Updates: ptr.To(updates),
		Mitigations: ptr.To(mitigations), Investigations: ptr.To(investigations), OmittedActions: ptr.To(omitted),
		HighestUrgency: highest, Critical: ptr.To(critical), KnownExploited: ptr.To(exploited),
	}
}

func TestRenderGivesAnActionForEachPackageWithItsUrgencyAndStepAndASummary(t *testing.T) {
	kev := exploitedFinding("CVE-2026-0001", "libkev")
	unclear := withoutFix(openFinding("CVE-2026-0002", "libunclear"), inventoryv1alpha1.VEXStatusUnderInvestigation)
	unfixable := withoutFix(openFinding("CVE-2026-0003", "libunfixable"), inventoryv1alpha1.VEXStatusAffected)
	settled := openFinding("CVE-2026-0004", "libsettled")
	settled.Status = inventoryv1alpha1.VEXStatusNotAffected
	fixed := openFinding("CVE-2026-0005", "libfixed")
	fixed.Status = inventoryv1alpha1.VEXStatusFixed

	got := renderOn(sheetOf(manifestAMD64, 100, kev, unclear, unfixable, settled, fixed), configv1alpha1.SSVCExposureOpen)

	require.Len(t, got.Actions, 3, "NotAffected and Fixed findings are counted, never in an action")
	packages := []string{got.Actions[0].Package.Name, got.Actions[1].Package.Name, got.Actions[2].Package.Name}
	require.Equal(t, []string{"libkev", "libunclear", "libunfixable"}, packages,
		"the most urgent first, then the most severe, then by package")
	first := got.Actions[0]
	require.Equal(t, triagev1alpha1.ReportAction{
		Step:             triagev1alpha1.NextStepUpdate,
		Package:          triagev1alpha1.ReportPackage{Name: "libkev", Version: ptr.To("1.0"), Type: "deb"},
		FixedVersion:     ptr.To("1.1"),
		Severity:         triagev1alpha1.SeverityHigh,
		Urgency:          triagev1alpha1.SSVCOutcomeImmediate,
		KnownExploited:   triagev1alpha1.KnownExploitedListed,
		Vulnerabilities:  1,
		VulnerabilityIDs: []string{"CVE-2026-0001"},
		Digests:          []string{imageDigest},
	}, first, "the one fixed version of its one vulnerability")
	require.Equal(t, triagev1alpha1.SSVCOutcome(urgency.Decide(urgency.FromFinding(unclear, configv1alpha1.SSVCExposureOpen), nil)),
		got.Actions[1].Urgency, "the urgency of an action is what the deployer tree decides for its findings")
	require.Equal(t, triagev1alpha1.NextStepInvestigate, got.Actions[1].Step, "unclear, and no fix")
	require.Nil(t, got.Actions[1].FixedVersion)
	require.Equal(t, triagev1alpha1.KnownExploitedNotListed, got.Actions[1].KnownExploited)
	require.Equal(t, triagev1alpha1.NextStepMitigate, got.Actions[2].Step, "affected, and no fix")
	require.Equal(t, summaryOf(2, 1, 1, 1, 1, 1, 1, 0, 0, 1, ptr.To(triagev1alpha1.SSVCOutcomeImmediate)), *got.Summary,
		"the summary covers every status, every step, and how urgent and exploited the open findings are")
	require.Equal(t, ptr.To(triagev1alpha1.SSVCExposureOpen), got.Exposure)
}

func TestRenderTakesTheUrgencyFromTheExposureAndTheOverrides(t *testing.T) {
	f := openFinding("CVE-2026-0001", "libexample")
	f.CVSS = lowCVSS
	sheet := sheetOf(manifestAMD64, 100, f)
	in := func(exposure configv1alpha1.SSVCExposure) urgency.Inputs { return urgency.FromFinding(f, exposure) }

	small := renderOn(sheet, configv1alpha1.SSVCExposureSmall)
	unknown := renderOn(sheet, configv1alpha1.SSVCExposureUnknown)

	require.Equal(t, triagev1alpha1.SSVCOutcome(urgency.Decide(in(configv1alpha1.SSVCExposureSmall), nil)), small.Actions[0].Urgency)
	require.Equal(t, triagev1alpha1.SSVCOutcome(urgency.Decide(in(configv1alpha1.SSVCExposureOpen), nil)), unknown.Actions[0].Urgency,
		"an unknown exposure counts as open")
	require.Equal(t, ptr.To(triagev1alpha1.SSVCExposureUnknown), unknown.Exposure, "the report says it is unknown")

	override := []configv1alpha1.UrgencyOverride{{
		Exploitation: in(configv1alpha1.SSVCExposureSmall).Exploitation, Exposure: configv1alpha1.SSVCExposureSmall,
		Automatable: in(configv1alpha1.SSVCExposureSmall).Automatable, HumanImpact: in(configv1alpha1.SSVCExposureSmall).HumanImpact,
		Outcome: configv1alpha1.SSVCOutcomeImmediate,
	}}
	got := spoke.Render(running(teamA, webName, linuxAMD64), []spoke.RunningImage{{Digest: imageDigest, Platforms: []string{linuxAMD64}}},
		map[string]*inventoryv1alpha1.ImageVerdicts{manifestAMD64: sheet},
		map[string]*inventoryv1alpha1.ImageFacts{imageDigest: factsOf()}, spoke.WorkloadExposure{SSVC: configv1alpha1.SSVCExposureSmall},
		settings.Effective{Urgency: configv1alpha1.Urgency{Overrides: override}})
	require.Equal(t, triagev1alpha1.SSVCOutcomeImmediate, got.Actions[0].Urgency, "an admin's override of the row wins")
	require.Equal(t, ptr.To(triagev1alpha1.SSVCOutcomeImmediate), got.Summary.HighestUrgency)
}

// One update fixes every vulnerability of a package that its version fixes, so the findings of a package at one
// version that a fix names are one Update, to the highest fixed version among them, and those that no fix names are
// one action of their own (decision 0038).
func TestRenderGroupsTheFindingsOfAPackageByNextStepAndUpdatesToTheHighestFix(t *testing.T) {
	for _, tc := range []struct {
		status inventoryv1alpha1.VEXStatus
		step   triagev1alpha1.NextStep
	}{
		{inventoryv1alpha1.VEXStatusUnderInvestigation, triagev1alpha1.NextStepInvestigate},
		{inventoryv1alpha1.VEXStatusAffected, triagev1alpha1.NextStepMitigate},
	} {
		t.Run(string(tc.status), func(t *testing.T) {
			first, second := openFinding("CVE-2026-0001", "libexample"), openFinding("CVE-2026-0002", "libexample")
			first.FixedVersions, second.FixedVersions = []string{version12}, []string{"1.4"}
			unfixed := withoutFix(openFinding("CVE-2026-0003", "libexample"), tc.status)

			got := renderOn(sheetOf(manifestAMD64, 100, first, second, unfixed), configv1alpha1.SSVCExposureSmall)

			require.Len(t, got.Actions, 2)
			update := actionOf(t, got, "libexample", triagev1alpha1.NextStepUpdate)
			require.Equal(t, ptr.To("1.4"), update.FixedVersion, "the highest of their fixed versions")
			require.EqualValues(t, 2, update.Vulnerabilities)
			require.Equal(t, []string{"CVE-2026-0001", "CVE-2026-0002"}, update.VulnerabilityIDs)
			rest := actionOf(t, got, "libexample", tc.step)
			require.EqualValues(t, 1, rest.Vulnerabilities)
			require.Equal(t, []string{"CVE-2026-0003"}, rest.VulnerabilityIDs)
			require.Nil(t, rest.FixedVersion, "only an update has a fixed version")
		})
	}
	t.Run("a package at another version is another action", func(t *testing.T) {
		other := openFinding("CVE-2026-0002", "libexample")
		other.Package.Version = ptr.To("2.0")

		got := renderOn(sheetOf(manifestAMD64, 100, openFinding("CVE-2026-0001", "libexample"), other), configv1alpha1.SSVCExposureSmall)

		require.Len(t, got.Actions, 2)
	})
}

// An update names its target only where the order of the fixed versions is unambiguous (decision 0038): each
// vulnerability of the action names one fixed version, and each is plain dotted numbers with at most one release
// suffix, -rN, -N or .elN, of one kind. The highest is then the target, its numbers compared one by one and the release
// last. One version that every vulnerability names is always the target. Anything else names none, since a wrong
// target is worse than none: the sheets keep each vulnerability's fixed versions.
func TestAnUpdateNamesItsTargetOnlyWhereTheOrderOfTheFixedVersionsIsUnambiguous(t *testing.T) {
	for name, tc := range map[string]struct {
		fixes [][]string
		want  *string
	}{
		"plain numbers":                      {[][]string{{version12}, {"1.4"}}, ptr.To("1.4")},
		"numbers by their value":             {[][]string{{"1.10"}, {"1.9"}}, ptr.To("1.10")},
		"a longer version of the same start": {[][]string{{"1.2.1"}, {version12}}, ptr.To("1.2.1")},
		"an Alpine release":                  {[][]string{{"1.2.3-r9"}, {"1.2.3-r10"}}, ptr.To("1.2.3-r10")},
		"a release after the numbers":        {[][]string{{"1.2.4-r1"}, {"1.2.3-r10"}}, ptr.To("1.2.4-r1")},
		"a release over none":                {[][]string{{"1.2.3"}, {"1.2.3-r1"}}, ptr.To("1.2.3-r1")},
		"a numeric release":                  {[][]string{{"1.2.3-4"}, {"1.2.3-12"}}, ptr.To("1.2.3-12")},
		"an el release":                      {[][]string{{"1.2.3.el8"}, {"1.2.4.el8"}}, ptr.To("1.2.4.el8")},
		"one version that every CVE names":   {[][]string{{"2:1.0~rc1+dfsg-3"}, {"2:1.0~rc1+dfsg-3"}}, ptr.To("2:1.0~rc1+dfsg-3")},
		"epochs":                             {[][]string{{"1:1.0"}, {"2.0"}}, nil},
		"a pre-release":                      {[][]string{{"1.0.0-rc1"}, {"1.0.0"}}, nil},
		"a tilde":                            {[][]string{{"1.0~rc1"}, {"1.0"}}, nil},
		"an Alpine _rc":                      {[][]string{{"1.2.3_rc1"}, {"1.2.3"}}, nil},
		"a Go pseudo-version":                {[][]string{{"v0.0.0-20260101000000-abcdef123456"}, {"v0.1.0"}}, nil},
		"v1.2 and 1.2":                       {[][]string{{"v1.2"}, {version12}}, nil},
		"a CVE with fixes on two branches":   {[][]string{{"1.2.9", "1.3.4"}, {"1.3.1"}}, nil},
		"letters in a version":               {[][]string{{"1.2.3a"}, {"1.2.4"}}, nil},
		"two kinds of release":               {[][]string{{"1.2.3-r1"}, {"1.2.3-1"}}, nil},
		"the same numbers spelt apart":       {[][]string{{"1.02"}, {version12}}, nil},
		"a CVE whose fix names no version":   {[][]string{{version12}, {}}, nil},
		"a version longer than the field":    {[][]string{{"1." + strings.Repeat("1", 200)}, {version12}}, nil},
		"a version that isn't printable":     {[][]string{{"1.2\x07"}, {"1.2\x07"}}, nil},
		"two releases":                       {[][]string{{"1.2.3-4.el8"}, {"1.2.3-5.el8"}}, nil},
	} {
		t.Run(name, func(t *testing.T) {
			findings := make([]inventoryv1alpha1.Finding, 0, len(tc.fixes))
			for i, fixes := range tc.fixes {
				f := openFinding(fmt.Sprintf("CVE-2026-%04d", i+1), "libexample")
				f.FixedVersions = fixes
				findings = append(findings, f)
			}

			got := renderOn(sheetOf(manifestAMD64, 100, findings...), configv1alpha1.SSVCExposureSmall)

			require.Len(t, got.Actions, 1, "an update either way, since a fix exists")
			require.Equal(t, triagev1alpha1.NextStepUpdate, got.Actions[0].Step)
			require.Equal(t, tc.want, got.Actions[0].FixedVersion)
		})
	}
}

func TestAnActionKeepsTheHighestSeverityAndUrgencyAndIsKnownExploitedWhenOneFindingIs(t *testing.T) {
	scheduled := openFinding("CVE-2026-0001", "libexample")
	critical := deferred("CVE-2026-0002", "libexample")
	critical.Severity = inventoryv1alpha1.SeverityCritical
	kev := exploitedFinding("CVE-2026-0003", "libexample")
	kev.Severity = inventoryv1alpha1.SeverityLow
	quiet := deferred("CVE-2026-0004", "libquiet")

	got := renderOn(sheetOf(manifestAMD64, 100, scheduled, critical, kev, quiet), configv1alpha1.SSVCExposureSmall)

	action := actionOf(t, got, "libexample", triagev1alpha1.NextStepUpdate)
	require.Equal(t, triagev1alpha1.SeverityCritical, action.Severity, "the most severe of its findings")
	require.Equal(t, triagev1alpha1.SSVCOutcomeOutOfCycle, action.Urgency, "the most urgent of its findings")
	require.Equal(t, triagev1alpha1.KnownExploitedListed, action.KnownExploited, "one of its findings is known exploited")
	require.Equal(t, triagev1alpha1.KnownExploitedNotListed, actionOf(t, got, "libquiet", triagev1alpha1.NextStepUpdate).KnownExploited)
	require.EqualValues(t, 1, *got.Summary.Critical, "the summary counts the open findings, not the actions")
	require.EqualValues(t, 1, *got.Summary.KnownExploited)
	require.Equal(t, ptr.To(triagev1alpha1.SSVCOutcomeOutOfCycle), got.Summary.HighestUrgency)
}

func TestAnActionListsTheFirstFiveIDsMostUrgentThenMostSevereAndCountsThemAll(t *testing.T) {
	withSeverity := func(f inventoryv1alpha1.Finding, s inventoryv1alpha1.Severity) inventoryv1alpha1.Finding {
		f.Severity = s
		return f
	}
	findings := []inventoryv1alpha1.Finding{
		withSeverity(deferred("CVE-2026-0001", "libexample"), inventoryv1alpha1.SeverityMedium),
		withSeverity(deferred("CVE-2026-0002", "libexample"), inventoryv1alpha1.SeverityLow),
		withSeverity(deferred("CVE-2026-0003", "libexample"), inventoryv1alpha1.SeverityCritical),
		withSeverity(openFinding("CVE-2026-0004", "libexample"), inventoryv1alpha1.SeverityHigh),
		withSeverity(openFinding("CVE-2026-0005", "libexample"), inventoryv1alpha1.SeverityHigh),
		withSeverity(openFinding("CVE-2026-0006", "libexample"), inventoryv1alpha1.SeverityCritical),
		withSeverity(exploitedFinding("CVE-2026-0007", "libexample"), inventoryv1alpha1.SeverityLow),
	}

	got := renderOn(sheetOf(manifestAMD64, 100, findings...), configv1alpha1.SSVCExposureSmall)

	require.Len(t, got.Actions, 1)
	require.EqualValues(t, 7, got.Actions[0].Vulnerabilities)
	require.Equal(t, []string{"CVE-2026-0007", "CVE-2026-0006", "CVE-2026-0004", "CVE-2026-0005", "CVE-2026-0003"},
		got.Actions[0].VulnerabilityIDs, "out of cycle, then scheduled from critical down and by ID, then deferred")
}

// At most 256 actions are listed, most urgent first, and the summary counts every action, those left out included.
func TestRenderListsAtMost256ActionsMostUrgentFirstAndCountsTheRest(t *testing.T) {
	findings := make([]inventoryv1alpha1.Finding, 0, 300)
	for i := range 300 {
		id, pkg := fmt.Sprintf("CVE-2026-%04d", i), fmt.Sprintf("lib%03d", i)
		f := openFinding(id, pkg)
		switch {
		case i >= 250:
			f = exploitedFinding(id, pkg)
		case i < 10:
			f.Severity = inventoryv1alpha1.SeverityCritical
		}
		findings = append(findings, f)
	}

	got := renderOn(sheetOf(manifestAMD64, 100, findings...), configv1alpha1.SSVCExposureSmall)

	require.Len(t, got.Actions, 256)
	require.EqualValues(t, 44, *got.Summary.OmittedActions)
	require.EqualValues(t, 300, *got.Summary.Actions)
	require.EqualValues(t, 300, *got.Summary.Updates, "the counts of the steps cover the actions left out")
	require.Equal(t, "lib250", got.Actions[0].Package.Name, "the out-of-cycle actions first")
	require.Equal(t, triagev1alpha1.SSVCOutcomeOutOfCycle, got.Actions[49].Urgency)
	require.Equal(t, "lib000", got.Actions[50].Package.Name, "then the critical ones")
	require.Equal(t, triagev1alpha1.SeverityCritical, got.Actions[59].Severity)
	require.Equal(t, "lib010", got.Actions[60].Package.Name, "then by package")
	require.Equal(t, "lib205", got.Actions[255].Package.Name, "the end of the order is what goes")
	require.EqualValues(t, 300, *got.Summary.Affected, "the summary counts the findings of the actions left out")
}

// A package that two images hold is one thing to do: one action, which names both images.
func TestThePackageFoundInTwoImagesIsOneActionWithBothDigests(t *testing.T) {
	other, otherManifest := hexDigest(9), hexDigest(10)
	images := []spoke.RunningImage{{Digest: other, Platforms: []string{linuxAMD64}}, {Digest: imageDigest, Platforms: []string{linuxAMD64}}}
	sheets := map[string]*inventoryv1alpha1.ImageVerdicts{
		manifestAMD64: sheetOf(manifestAMD64, 100, openFinding("CVE-2026-0001", "libexample")),
		otherManifest: sheetOf(otherManifest, 100, openFinding("CVE-2026-0001", "libexample"), openFinding("CVE-2026-0002", "libexample")),
	}
	facts := map[string]*inventoryv1alpha1.ImageFacts{
		imageDigest: factsOf(),
		other:       {Manifests: []inventoryv1alpha1.ManifestFact{{Platform: linuxAMD64, Digest: otherManifest}}},
	}

	got := spoke.Render(running(teamA, webName, linuxAMD64), images, sheets, facts,
		spoke.WorkloadExposure{SSVC: configv1alpha1.SSVCExposureSmall}, settings.Effective{})

	require.Len(t, got.Actions, 1)
	require.Equal(t, []string{imageDigest, other}, got.Actions[0].Digests, "both images, sorted")
	require.EqualValues(t, 2, got.Actions[0].Vulnerabilities, "each vulnerability once")
	require.EqualValues(t, 2, *got.Summary.Affected, "each vulnerability and package once, as the metrics count")
}

func TestRenderShowsTheReachThatTheExposureGivesAndNoneWithout(t *testing.T) {
	reach := &triagev1alpha1.ReportReach{InternalReach: triagev1alpha1.InternalReachPeers,
		Indirect: triagev1alpha1.IndirectExposureIndirect}
	images := []spoke.RunningImage{{Digest: imageDigest, Platforms: []string{linuxAMD64}}}
	facts := map[string]*inventoryv1alpha1.ImageFacts{imageDigest: factsOf()}

	with := spoke.Render(running(teamA, webName, linuxAMD64), images, nil, facts,
		spoke.WorkloadExposure{SSVC: configv1alpha1.SSVCExposureControlled, Reach: reach}, settings.Effective{})
	without := spoke.Render(running(teamA, webName, linuxAMD64), images, nil, facts, spoke.WorkloadExposure{}, settings.Effective{})

	require.Equal(t, reach, with.Reach)
	require.Equal(t, ptr.To(triagev1alpha1.SSVCExposureControlled), with.Exposure)
	require.Nil(t, without.Reach, "no evidence says how far the workload is reached")
	require.Equal(t, ptr.To(triagev1alpha1.SSVCExposureUnknown), without.Exposure)
}

// The notes of the rules that settle nothing are per vulnerability, and stay in the sheets. A settled finding asks
// for nothing, so only the summary counts it.
func TestTheReportHasNoNoteOfTheLoadCheckAndSettledFindingsOnlyInTheSummary(t *testing.T) {
	f := openFinding("CVE-2026-0001", "libexample")
	f.StatusNotes = []inventoryv1alpha1.StatusNote{{Rule: "load-check", Text: "nothing in the image names libexample.so"}}
	f.Reason = ptr.To("held open by a rule")
	settled := openFinding("CVE-2026-0009", "libsettled")
	settled.Status, settled.Justification = inventoryv1alpha1.VEXStatusNotAffected,
		ptr.To(inventoryv1alpha1.VEXJustificationVulnerableCodeNotPresent)

	got := renderOn(sheetOf(manifestAMD64, 100, f, settled), configv1alpha1.SSVCExposureSmall)

	encoded, err := json.Marshal(got)
	require.NoError(t, err)
	for _, absent := range []string{"load-check", "libexample.so", "held open", "CVE-2026-0009", "libsettled"} {
		require.NotContains(t, string(encoded), absent)
	}
	require.Len(t, got.Actions, 1)
	require.EqualValues(t, 1, *got.Summary.NotAffected)
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
	require.Empty(t, got.Actions)
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
		map[string]*inventoryv1alpha1.ImageFacts{imageDigest: factsOf()}, spoke.WorkloadExposure{SSVC: configv1alpha1.SSVCExposureSmall},
		settings.Effective{})

	require.Len(t, got.Images, 2)
	require.Equal(t, ptr.To(manifestAMD64), got.Images[0].ManifestDigest)
	require.Equal(t, ptr.To(manifestARM64), got.Images[1].ManifestDigest)
	require.EqualValues(t, 1, actionOf(t, got, "libexample", triagev1alpha1.NextStepUpdate).Vulnerabilities,
		"a vulnerability in a package is counted once, whatever the platform")
	require.Equal(t, []string{imageDigest}, actionOf(t, got, "libexample", triagev1alpha1.NextStepUpdate).Digests)
	require.Len(t, got.Actions, 2)
	require.Equal(t, ptr.To(int32(2)), got.Summary.Affected, "the summary counts a vulnerability and package once, as the metrics do")
}

// A pod that says no platform gives no manifest, unless the image has only one: no sheet is guessed.
func TestRenderLeavesTheManifestOutWhenNoPodSaysThePlatformAndTheImageHasSeveral(t *testing.T) {
	got := spoke.Render(running(teamA, webName), []spoke.RunningImage{{Digest: imageDigest}}, nil,
		map[string]*inventoryv1alpha1.ImageFacts{imageDigest: factsOf()}, spoke.WorkloadExposure{SSVC: configv1alpha1.SSVCExposureSmall},
		settings.Effective{})

	require.Len(t, got.Images, 1)
	require.Nil(t, got.Images[0].Platform)
	require.Nil(t, got.Images[0].ManifestDigest)
	require.Equal(t, triagev1alpha1.ReportImageStatePending, got.Images[0].State)
}

func TestRenderMakesTextFromImageContentPrintableAndBounded(t *testing.T) {
	f := openFinding("CVE-2026-0001\x1b[31m", strings.Repeat("p", 300))
	f.Package.Version = ptr.To("1.0\u202e")
	f.Package.Type = "deb\n" + strings.Repeat("t", 40)
	f.FixedVersions = []string{"\x07" + strings.Repeat("v", 200)}

	got := renderOn(sheetOf(manifestAMD64, 100, f), configv1alpha1.SSVCExposureSmall)

	out := got.Actions[0]
	require.Equal(t, []string{"CVE-2026-0001\ufffd[31m"}, out.VulnerabilityIDs)
	require.Equal(t, strings.Repeat("p", 253), out.Package.Name)
	require.Equal(t, ptr.To("1.0\ufffd"), out.Package.Version)
	require.Equal(t, "deb\ufffd"+strings.Repeat("t", 28), out.Package.Type)
	require.Nil(t, out.FixedVersion, "a fixed version that would have to be changed to fit names no target")
}

// maxedSheets gives a workload images whose sheets, entries and actions reach every limit of a report: 32 images, each
// with 32 coverage entries of the longest source and type, and 300 packages of the longest texts, each with 7
// vulnerabilities, in 9 of the images. text makes a text of the length that its limit gives.
func maxedSheets(text func(n int) string) ([]spoke.RunningImage, map[string]*inventoryv1alpha1.ImageVerdicts,
	map[string]*inventoryv1alpha1.ImageFacts) {
	findings := make([]inventoryv1alpha1.Finding, 0, 300*7)
	for p := range 300 {
		for v := range 7 {
			f := openFinding(fmt.Sprintf("%03d%01d", p, v)+text(60), fmt.Sprintf("%03d", p)+text(250))
			f.Package.Version = ptr.To(text(128))
			f.Package.Type = text(32)
			f.FixedVersions = []string{text(128)}
			findings = append(findings, f)
		}
	}
	images := make([]spoke.RunningImage, 0, 32)
	facts := map[string]*inventoryv1alpha1.ImageFacts{}
	sheets := map[string]*inventoryv1alpha1.ImageVerdicts{}
	for i := range 32 {
		digest, manifest := hexDigest(100+i), hexDigest(200+i)
		images = append(images, spoke.RunningImage{Digest: digest, Platforms: []string{linuxAMD64}})
		facts[digest] = &inventoryv1alpha1.ImageFacts{Manifests: []inventoryv1alpha1.ManifestFact{{Platform: linuxAMD64, Digest: manifest}}}
		sheet := sheetOf(manifest, 100)
		if i < 9 {
			sheet = sheetOf(manifest, 100, findings...)
		}
		sheet.Status.Evidence = nil
		for n := range 32 {
			sheet.Status.Evidence = append(sheet.Status.Evidence, inventoryv1alpha1.SheetEvidence{
				Name: fmt.Sprintf("e%d", n), Source: fmt.Sprintf("%02d", n) + strings.Repeat("s", 42),
				Type: fmt.Sprintf("%02d", n) + strings.Repeat("t", 251), Coverage: ptr.To(int32(100))})
		}
		sheets[manifest] = sheet
	}
	return images, sheets, facts
}

// maxedOwner gives a workload the most owner values, each with the longest key and value.
func maxedOwner() evidence.PresenceWorkload {
	w := running(teamA, webName, linuxAMD64)
	key := func(i int) string {
		return fmt.Sprintf("%s%02d/%s", strings.Repeat("k", 251), i, strings.Repeat("n", 63))
	}
	for i := range 16 {
		w.Labels = append(w.Labels, evidence.KeyValue{Key: key(i), Value: strings.Repeat("l", 256)})
		w.NamespaceLabels = append(w.NamespaceLabels, evidence.KeyValue{Key: key(i), Value: strings.Repeat("l", 256)})
		w.NamespaceAnnotations = append(w.NamespaceAnnotations, evidence.KeyValue{Key: key(i), Value: strings.Repeat("l", 256)})
	}
	return w
}

// At every limit of the schema, with texts of one byte for each character, a report's status fits in 1 MiB with all
// of its 256 actions. Texts whose JSON takes more bytes than characters would pass it, as '<' does, which JSON spells in
// 6 bytes, so the renderer cuts the actions by bytes too: the status stays below 1 MiB, holds as many actions as fit,
// and the summary counts the rest.
func TestRenderKeepsTheStatusBelow1MiBAtEveryLimit(t *testing.T) {
	for name, tc := range map[string]struct {
		char rune
		cut  bool
	}{
		"texts of one byte for each character": {'a', false},
		"texts that JSON spells in 6 bytes":    {'<', true},
	} {
		t.Run(name, func(t *testing.T) {
			text := func(n int) string { return strings.Repeat(string(tc.char), n) }
			images, sheets, facts := maxedSheets(text)

			got := spoke.Render(maxedOwner(), images, sheets, facts, spoke.WorkloadExposure{SSVC: configv1alpha1.SSVCExposureOpen,
				Reach: &triagev1alpha1.ReportReach{InternalReach: triagev1alpha1.InternalReachNamespaces,
					Indirect: triagev1alpha1.IndirectExposureNotIndirect}}, settings.Effective{})

			encoded, err := json.Marshal(got)
			require.NoError(t, err)
			require.LessOrEqual(t, len(encoded), 1<<20, "the status stays below 1 MiB")
			require.Len(t, got.Images, 32)
			require.Len(t, got.Images[0].Coverage, 32)
			require.Len(t, got.Owner, 48)
			require.Len(t, got.Actions[0].VulnerabilityIDs, 5)
			require.Len(t, got.Actions[0].Digests, 8)
			require.Len(t, []rune(ptr.Deref(got.Actions[0].FixedVersion, "")), 128, "one fixed version that every CVE names")
			require.Equal(t, int32(300-len(got.Actions)), *got.Summary.OmittedActions, "the summary counts the rest")
			require.EqualValues(t, 300*7, *got.Summary.Affected)
			if !tc.cut {
				require.Len(t, got.Actions, 256, "every action that the schema allows fits")
				return
			}
			require.Less(t, len(got.Actions), 256)
			require.Greater(t, len(encoded), 1<<20-8192, "and holds as many actions as fit")
		})
	}
}

func TestRenderCopiesTheOwnerValuesAndBoundsThem(t *testing.T) {
	w := running(teamA, webName, linuxAMD64)
	w.Labels = []evidence.KeyValue{{Key: teamLabel, Value: teamA}, {Key: "empty", Value: ""}}
	w.NamespaceLabels = []evidence.KeyValue{{Key: "owner", Value: strings.Repeat("o", 300)}}
	w.NamespaceAnnotations = []evidence.KeyValue{{Key: "example.org/contact", Value: "a\x1bb"}}

	got := spoke.Render(w, nil, nil, nil, spoke.WorkloadExposure{SSVC: configv1alpha1.SSVCExposureSmall}, settings.Effective{})

	require.Equal(t, []triagev1alpha1.OwnerValue{
		{Source: triagev1alpha1.OwnerSourceNamespaceLabel, Key: "owner", Value: ptr.To(strings.Repeat("o", 256))},
		{Source: triagev1alpha1.OwnerSourceNamespaceAnnotation, Key: "example.org/contact", Value: ptr.To("a\ufffdb")},
		{Source: triagev1alpha1.OwnerSourceWorkloadLabel, Key: "empty", Value: ptr.To("")},
		{Source: triagev1alpha1.OwnerSourceWorkloadLabel, Key: teamLabel, Value: ptr.To(teamA)},
	}, got.Owner)
}

func TestRenderListsNoImageItCannotName(t *testing.T) {
	got := spoke.Render(running(teamA, webName, linuxAMD64), []spoke.RunningImage{{Digest: "sha512:abc", Platforms: []string{linuxAMD64}}},
		nil, nil, spoke.WorkloadExposure{SSVC: configv1alpha1.SSVCExposureSmall}, settings.Effective{})

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

// An image past the 32 entries of the list has no entry, but its sheet still counts and its findings are still in the
// actions: a limit never hides a finding.
func TestRenderCountsAndGroupsTheFindingsOfImagesPastTheEntryLimit(t *testing.T) {
	images := make([]spoke.RunningImage, 0, 40)
	facts := map[string]*inventoryv1alpha1.ImageFacts{}
	sheets := map[string]*inventoryv1alpha1.ImageVerdicts{}
	for i := range 40 {
		digest, manifest := hexDigest(1000+i), hexDigest(2000+i)
		images = append(images, spoke.RunningImage{Digest: digest, Platforms: []string{linuxAMD64}})
		facts[digest] = &inventoryv1alpha1.ImageFacts{Manifests: []inventoryv1alpha1.ManifestFact{{Platform: linuxAMD64, Digest: manifest}}}
		sheets[manifest] = sheetOf(manifest, 100, openFinding(fmt.Sprintf("CVE-2026-%05d", i), "libexample"))
	}

	got := spoke.Render(running(teamA, webName, linuxAMD64), images, sheets, facts,
		spoke.WorkloadExposure{SSVC: configv1alpha1.SSVCExposureSmall}, settings.Effective{})

	require.Len(t, got.Images, 32, "the list holds 32 entries")
	require.Len(t, got.Actions, 1, "one package, at one version, with one step")
	require.EqualValues(t, 40, got.Actions[0].Vulnerabilities, "the action covers every image")
	require.Equal(t, []string{hexDigest(1000), hexDigest(1001), hexDigest(1002), hexDigest(1003), hexDigest(1004),
		hexDigest(1005), hexDigest(1006), hexDigest(1007)}, got.Actions[0].Digests, "the first 8 digests")
	require.Equal(t, ptr.To(int32(40)), got.Summary.Affected, "and so does the summary")
	require.Equal(t, ptr.To(int32(0)), got.Summary.OmittedActions)
}
