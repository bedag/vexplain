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
	sdkworkloads "github.com/bedag/vexplain/sdk/workloads"
)

// The tests of Render hold its inputs in memory: the renderer is pure.

// The names that the tests of the renderer share.
const (
	webName   = "web"
	teamLabel = "team"
	// webLocation is where the container web is in the Deployment of the tests.
	webLocation = "spec.template.spec.containers[web]"
	// strictPlaybook is a second playbook, beside the default one.
	strictPlaybook = "strict"
	// libExample is the package that most findings of the tests are in.
	libExample = "libexample"
	// The containers of the tests beside web: an init container, a sidecar, and the container of an image without a
	// digest.
	migrateName = "migrate"
	proxyName   = "proxy"
	nextName    = "next"
	// scanSource is the Collector that scans the images of the tests.
	scanSource = "scanner"
)

// hexDigest returns the sha256 digest that is made of the number n.
func hexDigest(n int) string { return fmt.Sprintf("sha256:%064x", n) }

// version12 is a fixed version that several tests name.
const version12 = "1.2"

// The package types of the tests.
const (
	typeDeb = "deb"
	typeNPM = "npm"
	typeGo  = "go-module"
)

// The image of the tests, and the manifests of its two platforms.
var (
	imageDigest   = hexDigest(1)
	manifestAMD64 = hexDigest(2)
	manifestARM64 = hexDigest(3)
)

// defaultPlaybooks holds the one playbook whose results the reports of the tests hold, unless a test names others.
var defaultPlaybooks = []string{defaultPlaybook}

// factsOf returns the facts of an image with a manifest for each platform.
func factsOf() *inventoryv1alpha1.ImageFacts {
	return &inventoryv1alpha1.ImageFacts{Manifests: []inventoryv1alpha1.ManifestFact{
		{Platform: linuxAMD64, Digest: manifestAMD64}, {Platform: linuxARM64, Digest: manifestARM64},
	}}
}

// imageRun returns an image of a repository digest that the containers of the names run, on amd64.
func imageRun(digest string, containers ...string) spoke.RunningImage {
	image := spoke.RunningImage{Digest: digest, Platforms: []string{linuxAMD64}, Kind: evidence.DigestKindRepoDigest}
	for _, name := range containers {
		image.Containers = append(image.Containers, sdkworkloads.ContainerRef{Name: name, Kind: sdkworkloads.ContainerKindContainer})
	}
	return image
}

// openFinding returns an Affected finding of a package, with one fixed version, which is its target.
func openFinding(id, pkg string) inventoryv1alpha1.Finding {
	return inventoryv1alpha1.Finding{
		VulnerabilityID: id,
		Package:         inventoryv1alpha1.PackageReference{ID: "id-" + pkg, Name: pkg, Version: ptr.To("1.0"), Type: typeDeb},
		Status:          inventoryv1alpha1.VEXStatusAffected,
		Rule:            ptr.To("known-exploited"),
		Severity:        inventoryv1alpha1.SeverityHigh,
		FixState:        inventoryv1alpha1.FixStateFixed,
		FixedVersions:   []string{"1.1"},
		FixTarget:       ptr.To("1.1"),
		UpdateTarget:    ptr.To("1.1"),
		KnownExploited:  inventoryv1alpha1.KnownExploitedNotListed,
	}
}

// sheetOf returns the default playbook's sheet of a manifest with the findings, counted.
func sheetOf(manifest string, findings ...inventoryv1alpha1.Finding) *inventoryv1alpha1.ImageVerdicts {
	return playbookSheet(defaultPlaybook, manifest, findings...)
}

// playbookSheet returns the playbook's sheet of a manifest with the findings, counted.
func playbookSheet(playbook, manifest string, findings ...inventoryv1alpha1.Finding) *inventoryv1alpha1.ImageVerdicts {
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
		Spec: inventoryv1alpha1.ImageVerdictsSpec{ManifestDigest: manifest, Playbook: playbook},
		Status: inventoryv1alpha1.ImageVerdictsStatus{
			Playbook: ptr.To(playbook), FindingsVersion: ptr.To("v1"), Findings: findings, Counts: &counts,
		},
	}
}

// sheetsOf returns the sheets by the digests of their manifests, as the renderer reads them.
func sheetsOf(sheets ...*inventoryv1alpha1.ImageVerdicts) map[string][]inventoryv1alpha1.ImageVerdicts {
	out := map[string][]inventoryv1alpha1.ImageVerdicts{}
	for _, sheet := range sheets {
		if sheet != nil {
			out[sheet.Spec.ManifestDigest] = append(out[sheet.Spec.ManifestDigest], *sheet)
		}
	}
	return out
}

// renderImages renders the Deployment web of team-a, which runs the images, with the default playbook and at a Small
// exposure.
func renderImages(images []spoke.RunningImage, sheets map[string][]inventoryv1alpha1.ImageVerdicts,
	facts map[string]*inventoryv1alpha1.ImageFacts) triagev1alpha1.ResourceReportStatus {
	return spoke.Render(running(teamA, webName, linuxAMD64), images, defaultPlaybooks, sheets, facts,
		spoke.WorkloadExposure{SSVC: configv1alpha1.SSVCExposureSmall}, settings.Effective{})
}

// renderOn renders the workload whose container web runs the image on amd64, with the sheet of that platform's
// manifest.
func renderOn(sheet *inventoryv1alpha1.ImageVerdicts, exposure configv1alpha1.SSVCExposure,
) triagev1alpha1.ResourceReportStatus {
	return spoke.Render(running(teamA, webName, linuxAMD64), []spoke.RunningImage{imageRun(imageDigest, webName)},
		defaultPlaybooks, sheetsOf(sheet), map[string]*inventoryv1alpha1.ImageFacts{imageDigest: factsOf()},
		spoke.WorkloadExposure{SSVC: exposure}, settings.Effective{})
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
	f.FixTarget, f.UpdateTarget = nil, nil
	if status == inventoryv1alpha1.VEXStatusUnderInvestigation {
		f.Rule = nil
	}
	return f
}

// actionOf returns the action of the package with the step, or fails.
func actionOf(t *testing.T, status triagev1alpha1.ResourceReportStatus, pkg string,
	step triagev1alpha1.ResourceStep) triagev1alpha1.ResourceAction {
	t.Helper()
	for _, a := range status.Actions {
		if a.Package != nil && a.Package.Name == pkg && a.Step == step {
			return a
		}
	}
	require.Failf(t, "no action", "the report has no %s of %s: %+v", step, pkg, status.Actions)
	return triagev1alpha1.ResourceAction{}
}

// summaryOf returns the summary of a workload whose every image has its verdict: its actions by step, those that the
// list leaves out, the critical ones and those known to be exploited, and the highest severity and urgency.
func summaryOf(updates, mitigations, investigations, omitted, critical, exploited int32, severity *triagev1alpha1.Severity,
	highest *triagev1alpha1.SSVCOutcome) triagev1alpha1.ResourceSummary {
	return triagev1alpha1.ResourceSummary{
		Actions: ptr.To(updates + mitigations + investigations), Updates: ptr.To(updates), Changes: ptr.To(int32(0)),
		Mitigations: ptr.To(mitigations), Investigations: ptr.To(investigations), OmittedActions: ptr.To(omitted),
		HighestSeverity: severity, HighestUrgency: highest, Critical: ptr.To(critical), KnownExploited: ptr.To(exploited),
		PendingImages: ptr.To(int32(0)), UnscannableImages: ptr.To(int32(0)),
	}
}

func TestRenderGivesAnActionForEachPackageWithItsUrgencyStepAndLocationAndASummary(t *testing.T) {
	kev := exploitedFinding("CVE-2026-0001", "libkev")
	unclear := withoutFix(openFinding("CVE-2026-0002", "libunclear"), inventoryv1alpha1.VEXStatusUnderInvestigation)
	unfixable := withoutFix(openFinding("CVE-2026-0003", "libunfixable"), inventoryv1alpha1.VEXStatusAffected)
	settled := openFinding("CVE-2026-0004", "libsettled")
	settled.Status = inventoryv1alpha1.VEXStatusNotAffected
	fixed := openFinding("CVE-2026-0005", "libfixed")
	fixed.Status = inventoryv1alpha1.VEXStatusFixed

	got := renderOn(sheetOf(manifestAMD64, kev, unclear, unfixable, settled, fixed), configv1alpha1.SSVCExposureOpen)

	require.Len(t, got.Actions, 3, "NotAffected and Fixed findings ask for nothing")
	packages := []string{got.Actions[0].Package.Name, got.Actions[1].Package.Name, got.Actions[2].Package.Name}
	require.Equal(t, []string{"libkev", "libunclear", "libunfixable"}, packages,
		"the most urgent first, then the most severe, then by package")
	require.Equal(t, triagev1alpha1.ResourceAction{
		Step:             triagev1alpha1.ResourceStepUpdate,
		Title:            "Update libkev to 1.1",
		Locations:        []string{webLocation},
		Severity:         triagev1alpha1.SeverityHigh,
		Urgency:          ptr.To(triagev1alpha1.SSVCOutcomeImmediate),
		Requirement:      triagev1alpha1.ResourceRequirement{Playbook: defaultPlaybook},
		Package:          &triagev1alpha1.ReportPackage{Name: "libkev", Version: ptr.To("1.0"), Type: typeDeb},
		FixedVersion:     ptr.To("1.1"),
		Vulnerabilities:  ptr.To(int32(1)),
		VulnerabilityIDs: []string{"CVE-2026-0001"},
		KnownExploited:   ptr.To(triagev1alpha1.KnownExploitedListed),
		Digest:           ptr.To(imageDigest),
	}, got.Actions[0], "the one fixed version of its one vulnerability, in the container that runs the image")
	require.Equal(t, ptr.To(triagev1alpha1.SSVCOutcome(urgency.Decide(urgency.FromFinding(unclear, configv1alpha1.SSVCExposureOpen), nil))),
		got.Actions[1].Urgency, "the urgency of an action is what the deployer tree decides for its findings")
	require.Equal(t, triagev1alpha1.ResourceStepInvestigate, got.Actions[1].Step, "unclear, and no fix")
	require.Equal(t, "Investigate libunclear", got.Actions[1].Title)
	require.Nil(t, got.Actions[1].FixedVersion)
	require.Equal(t, ptr.To(triagev1alpha1.KnownExploitedNotListed), got.Actions[1].KnownExploited)
	require.Equal(t, triagev1alpha1.ResourceStepMitigate, got.Actions[2].Step, "affected, and no fix")
	require.Equal(t, "Mitigate libunfixable", got.Actions[2].Title)
	require.Equal(t, summaryOf(1, 1, 1, 0, 0, 1, ptr.To(triagev1alpha1.SeverityHigh), ptr.To(triagev1alpha1.SSVCOutcomeImmediate)),
		*got.Summary, "the summary counts the actions by step, and how severe, urgent and exploited they are")
	require.Equal(t, ptr.To(triagev1alpha1.SSVCExposureOpen), got.Exposure)
}

func TestRenderTakesTheUrgencyFromTheExposureAndTheOverrides(t *testing.T) {
	f := openFinding("CVE-2026-0001", "libexample")
	f.CVSS = lowCVSS
	sheet := sheetOf(manifestAMD64, f)
	in := func(exposure configv1alpha1.SSVCExposure) urgency.Inputs { return urgency.FromFinding(f, exposure) }

	small := renderOn(sheet, configv1alpha1.SSVCExposureSmall)
	unknown := renderOn(sheet, configv1alpha1.SSVCExposureUnknown)

	require.Equal(t, triagev1alpha1.SSVCOutcome(urgency.Decide(in(configv1alpha1.SSVCExposureSmall), nil)), *small.Actions[0].Urgency)
	require.Equal(t, triagev1alpha1.SSVCOutcome(urgency.Decide(in(configv1alpha1.SSVCExposureOpen), nil)), *unknown.Actions[0].Urgency,
		"an unknown exposure counts as open")
	require.Equal(t, ptr.To(triagev1alpha1.SSVCExposureUnknown), unknown.Exposure, "the report says it is unknown")

	override := []configv1alpha1.UrgencyOverride{{
		Exploitation: in(configv1alpha1.SSVCExposureSmall).Exploitation, Exposure: configv1alpha1.SSVCExposureSmall,
		Automatable: in(configv1alpha1.SSVCExposureSmall).Automatable, HumanImpact: in(configv1alpha1.SSVCExposureSmall).HumanImpact,
		Outcome: configv1alpha1.SSVCOutcomeImmediate,
	}}
	got := spoke.Render(running(teamA, webName, linuxAMD64), []spoke.RunningImage{imageRun(imageDigest, webName)},
		defaultPlaybooks, sheetsOf(sheet), map[string]*inventoryv1alpha1.ImageFacts{imageDigest: factsOf()},
		spoke.WorkloadExposure{SSVC: configv1alpha1.SSVCExposureSmall}, settings.Effective{Urgency: configv1alpha1.Urgency{Overrides: override}})
	require.Equal(t, ptr.To(triagev1alpha1.SSVCOutcomeImmediate), got.Actions[0].Urgency, "an admin's override of the row wins")
	require.Equal(t, ptr.To(triagev1alpha1.SSVCOutcomeImmediate), got.Summary.HighestUrgency)
}

// One update fixes every vulnerability of a package that its version fixes, so the findings of a package at one
// version that a fix names are one Update, to the update target that they carry, and those that no fix names are one
// action of their own (decision 0038).
func TestRenderGroupsTheFindingsOfAPackageByNextStepAndUpdatesToTheHighestFix(t *testing.T) {
	for _, tc := range []struct {
		status inventoryv1alpha1.VEXStatus
		step   triagev1alpha1.ResourceStep
	}{
		{inventoryv1alpha1.VEXStatusUnderInvestigation, triagev1alpha1.ResourceStepInvestigate},
		{inventoryv1alpha1.VEXStatusAffected, triagev1alpha1.ResourceStepMitigate},
	} {
		t.Run(string(tc.status), func(t *testing.T) {
			first, second := openFinding("CVE-2026-0001", "libexample"), openFinding("CVE-2026-0002", "libexample")
			first.FixedVersions, second.FixedVersions = []string{version12}, []string{"1.4"}
			first.UpdateTarget, second.UpdateTarget = ptr.To("1.4"), ptr.To("1.4")
			unfixed := withoutFix(openFinding("CVE-2026-0003", "libexample"), tc.status)

			got := renderOn(sheetOf(manifestAMD64, first, second, unfixed), configv1alpha1.SSVCExposureSmall)

			require.Len(t, got.Actions, 2)
			update := actionOf(t, got, "libexample", triagev1alpha1.ResourceStepUpdate)
			require.Equal(t, ptr.To("1.4"), update.FixedVersion, "the update target of the package")
			require.Equal(t, ptr.To(int32(2)), update.Vulnerabilities)
			require.Equal(t, []string{"CVE-2026-0001", "CVE-2026-0002"}, update.VulnerabilityIDs)
			rest := actionOf(t, got, "libexample", tc.step)
			require.Equal(t, ptr.To(int32(1)), rest.Vulnerabilities)
			require.Equal(t, []string{"CVE-2026-0003"}, rest.VulnerabilityIDs)
			require.Nil(t, rest.FixedVersion, "only an update has a fixed version")
		})
	}
	t.Run("a package at another version is another action", func(t *testing.T) {
		other := openFinding("CVE-2026-0002", "libexample")
		other.Package.Version = ptr.To("2.0")

		got := renderOn(sheetOf(manifestAMD64, openFinding("CVE-2026-0001", "libexample"), other), configv1alpha1.SSVCExposureSmall)

		require.Len(t, got.Actions, 2)
	})
}

// An update goes to the update target that its findings carry: the collector has ordered the fixed versions in the
// scheme of the package's ecosystem, which the report doesn't repeat. A finding without one names no target, and so
// does an action whose findings carry two, since a wrong target is worse than none.
func TestAnUpdateGoesToTheUpdateTargetOfItsFindings(t *testing.T) {
	for name, tc := range map[string]struct {
		pkgType string
		targets []*string
		want    *string
	}{
		"a Debian version with a tilde":  {typeDeb, []*string{ptr.To("2:1.0~rc1+dfsg-3")}, ptr.To("2:1.0~rc1+dfsg-3")},
		"a Go module with a v":           {typeGo, []*string{ptr.To("v1.2.5")}, ptr.To("v1.2.5")},
		"an npm pre-release":             {typeNPM, []*string{ptr.To("1.2.3-1")}, ptr.To("1.2.3-1")},
		"every finding the same target":  {typeDeb, []*string{ptr.To("1.4"), ptr.To("1.4")}, ptr.To("1.4")},
		"a finding without a target":     {typeDeb, []*string{nil}, nil},
		"one finding of two without one": {typeDeb, []*string{ptr.To("1.4"), nil}, nil},
		"two targets":                    {typeDeb, []*string{ptr.To("1.4"), ptr.To("1.5")}, nil},
		"a target longer than the field": {typeDeb, []*string{ptr.To("1." + strings.Repeat("1", 200))}, nil},
		"a target that isn't printable":  {typeDeb, []*string{ptr.To("1.2\x07")}, nil},
		"an empty target":                {typeDeb, []*string{ptr.To("")}, nil},
	} {
		t.Run(name, func(t *testing.T) {
			findings := make([]inventoryv1alpha1.Finding, 0, len(tc.targets))
			for i, v := range tc.targets {
				f := openFinding(fmt.Sprintf("CVE-2026-%04d", i+1), "libexample")
				f.Package.Type = tc.pkgType
				f.UpdateTarget = v
				findings = append(findings, f)
			}

			got := renderOn(sheetOf(manifestAMD64, findings...), configv1alpha1.SSVCExposureSmall)

			require.Len(t, got.Actions, 1, "an update either way, since a fix exists")
			require.Equal(t, triagev1alpha1.ResourceStepUpdate, got.Actions[0].Step)
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

	got := renderOn(sheetOf(manifestAMD64, scheduled, critical, kev, quiet), configv1alpha1.SSVCExposureSmall)

	action := actionOf(t, got, "libexample", triagev1alpha1.ResourceStepUpdate)
	require.Equal(t, triagev1alpha1.SeverityCritical, action.Severity, "the most severe of its findings")
	require.Equal(t, ptr.To(triagev1alpha1.SSVCOutcomeOutOfCycle), action.Urgency, "the most urgent of its findings")
	require.Equal(t, ptr.To(triagev1alpha1.KnownExploitedListed), action.KnownExploited, "one of its findings is known exploited")
	require.Equal(t, ptr.To(triagev1alpha1.KnownExploitedNotListed),
		actionOf(t, got, "libquiet", triagev1alpha1.ResourceStepUpdate).KnownExploited)
	require.Equal(t, ptr.To(int32(1)), got.Summary.Critical, "the summary counts the actions")
	require.Equal(t, ptr.To(int32(1)), got.Summary.KnownExploited)
	require.Equal(t, ptr.To(triagev1alpha1.SeverityCritical), got.Summary.HighestSeverity)
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

	got := renderOn(sheetOf(manifestAMD64, findings...), configv1alpha1.SSVCExposureSmall)

	require.Len(t, got.Actions, 1)
	require.Equal(t, ptr.To(int32(7)), got.Actions[0].Vulnerabilities)
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

	got := renderOn(sheetOf(manifestAMD64, findings...), configv1alpha1.SSVCExposureSmall)

	require.Len(t, got.Actions, 256)
	require.EqualValues(t, 44, *got.Summary.OmittedActions)
	require.EqualValues(t, 300, *got.Summary.Actions)
	require.EqualValues(t, 300, *got.Summary.Updates, "the counts of the steps cover the actions left out")
	require.EqualValues(t, 10, *got.Summary.Critical, "and so do the other counts")
	require.EqualValues(t, 50, *got.Summary.KnownExploited)
	require.Equal(t, "lib250", got.Actions[0].Package.Name, "the out-of-cycle actions first")
	require.Equal(t, ptr.To(triagev1alpha1.SSVCOutcomeOutOfCycle), got.Actions[49].Urgency)
	require.Equal(t, "lib000", got.Actions[50].Package.Name, "then the critical ones")
	require.Equal(t, triagev1alpha1.SeverityCritical, got.Actions[59].Severity)
	require.Equal(t, "lib010", got.Actions[60].Package.Name, "then by package")
	require.Equal(t, "lib205", got.Actions[255].Package.Name, "the end of the order is what goes")
}

// Containers that run one image share its actions: an action names the location of each of them, sorted, and the
// image names them all.
func TestTheContainersOfOneImageShareItsActionWhichNamesEachOfThem(t *testing.T) {
	got := renderImages([]spoke.RunningImage{imageRun(imageDigest, webName, "api")},
		sheetsOf(sheetOf(manifestAMD64, openFinding("CVE-2026-0001", "libexample"))),
		map[string]*inventoryv1alpha1.ImageFacts{imageDigest: factsOf()})

	require.Len(t, got.Actions, 1)
	require.Equal(t, []string{"spec.template.spec.containers[api]", webLocation}, got.Actions[0].Locations)
	require.Equal(t, []string{"api", webName}, got.Images[0].Containers)
}

// An action names the locations of the first 8 containers that run its image, by their locations: the image names
// them all.
func TestAnActionNamesTheLocationsOfAtMost8Containers(t *testing.T) {
	names := make([]string, 0, 10)
	for i := range 10 {
		names = append(names, fmt.Sprintf("c%02d", i))
	}

	got := renderImages([]spoke.RunningImage{imageRun(imageDigest, names...)},
		sheetsOf(sheetOf(manifestAMD64, openFinding("CVE-2026-0001", "libexample"))),
		map[string]*inventoryv1alpha1.ImageFacts{imageDigest: factsOf()})

	require.Len(t, got.Actions[0].Locations, 8)
	require.Equal(t, "spec.template.spec.containers[c07]", got.Actions[0].Locations[7], "the first 8 by location")
	require.Equal(t, names, got.Images[0].Containers)
}

// A workload whose pods name no container still gets actions that say where they apply: its pod spec.
func TestAnActionOfAnImageWhoseContainersArentKnownNamesThePodSpec(t *testing.T) {
	got := renderImages([]spoke.RunningImage{imageRun(imageDigest)},
		sheetsOf(sheetOf(manifestAMD64, openFinding("CVE-2026-0001", "libexample"))),
		map[string]*inventoryv1alpha1.ImageFacts{imageDigest: factsOf()})

	require.Equal(t, []string{"spec.template.spec"}, got.Actions[0].Locations)
	require.Empty(t, got.Images[0].Containers)
}

// Actions merge only within one image (decision 0042): two images that hold a package at one version each have an
// action of their own, in their own containers, to the target that their own findings carry.
func TestEachImageHasActionsOfItsOwnWithItsOwnTarget(t *testing.T) {
	other, otherManifest := hexDigest(9), hexDigest(10)
	newer := openFinding("CVE-2026-0001", "libexample")
	newer.FixedVersions, newer.FixTarget, newer.UpdateTarget = []string{version12}, ptr.To(version12), ptr.To(version12)
	second := openFinding("CVE-2026-0002", "libexample")
	second.FixedVersions, second.FixTarget, second.UpdateTarget = []string{version12}, ptr.To(version12), ptr.To(version12)

	got := renderImages([]spoke.RunningImage{imageRun(imageDigest, webName), imageRun(other, "api")},
		sheetsOf(sheetOf(manifestAMD64, openFinding("CVE-2026-0001", "libexample")), sheetOf(otherManifest, newer, second)),
		map[string]*inventoryv1alpha1.ImageFacts{
			imageDigest: factsOf(),
			other:       {Manifests: []inventoryv1alpha1.ManifestFact{{Platform: linuxAMD64, Digest: otherManifest}}},
		})

	require.Len(t, got.Actions, 2, "one for each image, though both hold the package at one version")
	byDigest := map[string]triagev1alpha1.ResourceAction{}
	for _, a := range got.Actions {
		byDigest[ptr.Deref(a.Digest, "")] = a
	}
	web, api := byDigest[imageDigest], byDigest[other]
	require.Equal(t, ptr.To("1.1"), web.FixedVersion)
	require.Equal(t, []string{webLocation}, web.Locations)
	require.Equal(t, ptr.To(int32(1)), web.Vulnerabilities)
	require.Equal(t, ptr.To(version12), api.FixedVersion, "each image's own target")
	require.Equal(t, []string{"spec.template.spec.containers[api]"}, api.Locations)
	require.Equal(t, ptr.To(int32(2)), api.Vulnerabilities)
	require.Equal(t, ptr.To(int32(2)), got.Summary.Updates)
}

// variantFacts returns the facts of an image whose manifests are listed under the platforms, one digest each from
// hexDigest(10).
func variantFacts(platforms ...string) (*inventoryv1alpha1.ImageFacts, []string) {
	facts := &inventoryv1alpha1.ImageFacts{}
	digests := make([]string, 0, len(platforms))
	for i, p := range platforms {
		d := hexDigest(10 + i)
		digests = append(digests, d)
		facts.Manifests = append(facts.Manifests, inventoryv1alpha1.ManifestFact{Platform: p, Digest: d})
	}
	return facts, digests
}

// Two sheets of one image can give one vulnerability of one package apart, as for two variants of it that a pod's
// platform can't tell apart. Whichever sheet comes first, the action takes the more urgent value of each (decision
// 0038): the more urgent urgency, the more severe severity, and known exploited where either sheet lists it. The fixed
// versions of both count, so an update names a target only where the sheets name one version between them.
func TestAVulnerabilityThatTheVariantsOfAnImageGiveApartTakesTheMoreUrgentValueOfEach(t *testing.T) {
	facts, d := variantFacts("linux/arm/v6", "linux/arm/v7")
	image := imageRun(imageDigest, webName)
	image.Platforms = []string{"linux/arm"}
	// One sheet doesn't list the vulnerability as exploited, which the table schedules at a Small exposure, and the
	// other lists it as exploited and critical, which the table takes out of cycle.
	quiet := openFinding("CVE-2026-0001", "libexample")
	loud := exploitedFinding("CVE-2026-0001", "libexample")
	loud.Severity = inventoryv1alpha1.SeverityCritical
	render := func(first, second inventoryv1alpha1.Finding) triagev1alpha1.ResourceReportStatus {
		return renderImages([]spoke.RunningImage{image}, sheetsOf(sheetOf(d[0], first), sheetOf(d[1], second)),
			map[string]*inventoryv1alpha1.ImageFacts{imageDigest: facts})
	}

	for name, sheets := range map[string][2]inventoryv1alpha1.Finding{
		"the quiet sheet first": {quiet, loud},
		"the loud sheet first":  {loud, quiet},
	} {
		t.Run(name, func(t *testing.T) {
			got := render(sheets[0], sheets[1])

			require.Len(t, got.Actions, 1, "one vulnerability of one package of one image")
			action := got.Actions[0]
			require.Equal(t, ptr.To(triagev1alpha1.KnownExploitedListed), action.KnownExploited, "one sheet lists it")
			require.Equal(t, ptr.To(triagev1alpha1.SSVCOutcomeOutOfCycle), action.Urgency, "the more urgent of the two")
			require.Equal(t, triagev1alpha1.SeverityCritical, action.Severity, "the more severe of the two")
			require.Equal(t, ptr.To("1.1"), action.FixedVersion, "both sheets name the one fixed version")
			require.Equal(t, ptr.To(imageDigest), action.Digest)
			require.Equal(t, summaryOf(1, 0, 0, 0, 1, 1, ptr.To(triagev1alpha1.SeverityCritical),
				ptr.To(triagev1alpha1.SSVCOutcomeOutOfCycle)), *got.Summary)
		})
	}

	t.Run("two update targets", func(t *testing.T) {
		fixedLater := loud
		fixedLater.FixedVersions, fixedLater.UpdateTarget = []string{version12}, ptr.To(version12)

		got := render(quiet, fixedLater)

		require.Len(t, got.Actions, 1)
		require.Nil(t, got.Actions[0].FixedVersion, "the sheets name two targets for one vulnerability, which can't be ordered here")
	})
}

// A report holds the results of each playbook that matches its workload, each action naming its playbook. Each playbook
// is read from its own sheets: an image that a playbook has no verdict on yet is Pending, and takes nothing of another
// playbook's verdicts. A sheet of a playbook that the report doesn't hold adds nothing.
func TestAReportHoldsTheResultsOfEachOfItsPlaybooksFromItsOwnSheets(t *testing.T) {
	images := []spoke.RunningImage{imageRun(imageDigest, webName)}
	facts := map[string]*inventoryv1alpha1.ImageFacts{imageDigest: factsOf()}
	render := func(playbooks []string, sheets ...*inventoryv1alpha1.ImageVerdicts) triagev1alpha1.ResourceReportStatus {
		return spoke.Render(running(teamA, webName, linuxAMD64), images, playbooks, sheetsOf(sheets...), facts,
			spoke.WorkloadExposure{SSVC: configv1alpha1.SSVCExposureSmall}, settings.Effective{})
	}
	defaults := sheetOf(manifestAMD64, exploitedFinding("CVE-2026-0001", "libexample"))
	both := []string{defaultPlaybook, strictPlaybook}

	t.Run("a playbook without a verdict yet", func(t *testing.T) {
		got := render(both, defaults)

		require.Equal(t, triagev1alpha1.ResourceImageStatePending, got.Images[0].State, "the strict playbook has no verdict yet")
		require.Equal(t, ptr.To(int32(1)), got.Summary.PendingImages)
		require.Len(t, got.Actions, 1)
		require.Equal(t, triagev1alpha1.ResourceRequirement{Playbook: defaultPlaybook}, got.Actions[0].Requirement,
			"the strict playbook takes nothing of the default playbook's verdicts")
	})

	t.Run("each playbook with its verdict", func(t *testing.T) {
		got := render(both, defaults, playbookSheet(strictPlaybook, manifestAMD64, openFinding("CVE-2026-0001", "libexample"),
			openFinding("CVE-2026-0002", "libother")))

		require.Equal(t, triagev1alpha1.ResourceImageStateReady, got.Images[0].State)
		require.Equal(t, ptr.To(int32(0)), got.Summary.PendingImages)
		requirements := map[string][]string{}
		for _, a := range got.Actions {
			requirements[a.Package.Name] = append(requirements[a.Package.Name], a.Requirement.Playbook)
		}
		require.Equal(t, map[string][]string{libExample: {defaultPlaybook, strictPlaybook}, "libother": {strictPlaybook}},
			requirements, "each playbook's actions, each naming its playbook")
	})

	t.Run("a sheet of a playbook that the report doesn't hold", func(t *testing.T) {
		got := render(defaultPlaybooks, defaults, playbookSheet(strictPlaybook, manifestAMD64, openFinding("CVE-2026-0002", "libother")))

		require.Len(t, got.Actions, 1)
		require.Equal(t, defaultPlaybook, got.Actions[0].Requirement.Playbook)
		require.Equal(t, triagev1alpha1.ResourceImageStateReady, got.Images[0].State)
	})

	t.Run("no playbook", func(t *testing.T) {
		got := render(nil, defaults)

		require.Empty(t, got.Actions)
		require.Equal(t, triagev1alpha1.ResourceImageStatePending, got.Images[0].State,
			"no requirement has looked at the image, which never reads as clean")
		require.Equal(t, ptr.To(int32(1)), got.Summary.PendingImages)
	})
}

// An image that has no digest, only a reference, and one of an image ID can't be pulled for a scan, so no verdict will
// come for them: they are Unscannable, not Pending. The one without a digest is named by its reference.
func TestAnImageWithoutADigestAndAnImageIDAreUnscannable(t *testing.T) {
	reference := "registry.example/team-a/app:2.0"
	imageID := imageRun(hexDigest(20))
	imageID.Kind = evidence.DigestKindImageID
	imageID.Containers = []sdkworkloads.ContainerRef{{Name: migrateName, Kind: sdkworkloads.ContainerKindInitContainer}}
	withoutDigest := imageRun(sdkworkloads.ReferenceDigest(reference), nextName)
	withoutDigest.Kind, withoutDigest.Ref = evidence.DigestKindReference, reference

	got := renderImages([]spoke.RunningImage{imageID, withoutDigest}, nil, nil)

	require.ElementsMatch(t, []triagev1alpha1.ResourceImage{
		{Digest: ptr.To(hexDigest(20)), State: triagev1alpha1.ResourceImageStateUnscannable, Containers: []string{migrateName}},
		{Ref: ptr.To(reference), State: triagev1alpha1.ResourceImageStateUnscannable, Containers: []string{nextName}},
	}, got.Images)
	require.Equal(t, ptr.To(int32(2)), got.Summary.UnscannableImages)
	require.Equal(t, ptr.To(int32(0)), got.Summary.PendingImages, "neither waits for a verdict")
	require.Empty(t, got.Actions)

	withoutDigest.Ref = strings.Repeat("r", 513)
	got = renderImages([]spoke.RunningImage{withoutDigest}, nil, nil)
	require.Nil(t, got.Images[0].Ref, "a reference cut to fit would name another image")
}

func TestRenderShowsTheReachThatTheExposureGivesAndNoneWithout(t *testing.T) {
	reach := &triagev1alpha1.ReportReach{InternalReach: triagev1alpha1.InternalReachPeers,
		Indirect: triagev1alpha1.IndirectExposureIndirect}
	images := []spoke.RunningImage{imageRun(imageDigest, webName)}
	facts := map[string]*inventoryv1alpha1.ImageFacts{imageDigest: factsOf()}

	with := spoke.Render(running(teamA, webName, linuxAMD64), images, defaultPlaybooks, nil, facts,
		spoke.WorkloadExposure{SSVC: configv1alpha1.SSVCExposureControlled, Reach: reach}, settings.Effective{})
	without := spoke.Render(running(teamA, webName, linuxAMD64), images, defaultPlaybooks, nil, facts, spoke.WorkloadExposure{},
		settings.Effective{})

	require.Equal(t, reach, with.Reach)
	require.Equal(t, ptr.To(triagev1alpha1.SSVCExposureControlled), with.Exposure)
	require.Nil(t, without.Reach, "no evidence says how far the workload is reached")
	require.Equal(t, ptr.To(triagev1alpha1.SSVCExposureUnknown), without.Exposure)
}

// The notes of the rules that settle nothing are per vulnerability, and stay in the sheets. A settled finding asks
// for nothing, so the report says nothing of it.
func TestTheReportHasNoNoteOfTheLoadCheckAndNoSettledFinding(t *testing.T) {
	f := openFinding("CVE-2026-0001", "libexample")
	f.StatusNotes = []inventoryv1alpha1.StatusNote{{Rule: "load-check", Text: "nothing in the image names libexample.so"}}
	f.Reason = ptr.To("held open by a rule")
	settled := openFinding("CVE-2026-0009", "libsettled")
	settled.Status, settled.Justification = inventoryv1alpha1.VEXStatusNotAffected,
		ptr.To(inventoryv1alpha1.VEXJustificationVulnerableCodeNotPresent)

	got := renderOn(sheetOf(manifestAMD64, f, settled), configv1alpha1.SSVCExposureSmall)

	encoded, err := json.Marshal(got)
	require.NoError(t, err)
	for _, absent := range []string{"load-check", "libexample.so", "held open", "CVE-2026-0009", "libsettled"} {
		require.NotContains(t, string(encoded), absent)
	}
	require.Len(t, got.Actions, 1)
}

func TestRenderGivesEachImageAStateFromItsSheet(t *testing.T) {
	counts := func(affected, settled int32) *inventoryv1alpha1.FindingCounts {
		return &inventoryv1alpha1.FindingCounts{Affected: ptr.To(affected), UnderInvestigation: ptr.To(int32(0)),
			NotAffected: ptr.To(settled), Fixed: ptr.To(int32(0))}
	}
	for name, tc := range map[string]struct {
		sheet *inventoryv1alpha1.ImageVerdicts
		want  triagev1alpha1.ResourceImageState
	}{
		"no sheet": {nil, triagev1alpha1.ResourceImageStatePending},
		"a sheet without counts": {&inventoryv1alpha1.ImageVerdicts{Status: inventoryv1alpha1.ImageVerdictsStatus{
			FindingsVersion: ptr.To("v1")}}, triagev1alpha1.ResourceImageStatePending},
		"a sheet without a findings version": {&inventoryv1alpha1.ImageVerdicts{Status: inventoryv1alpha1.ImageVerdictsStatus{
			Counts: counts(0, 0)}}, triagev1alpha1.ResourceImageStatePending},
		"a complete sheet": {&inventoryv1alpha1.ImageVerdicts{Status: inventoryv1alpha1.ImageVerdictsStatus{
			FindingsVersion: ptr.To("v1"), Counts: counts(2, 3), OmittedFindings: ptr.To(int32(0))}}, triagev1alpha1.ResourceImageStateReady},
		"a sheet that left out settled findings only": {&inventoryv1alpha1.ImageVerdicts{Status: inventoryv1alpha1.ImageVerdictsStatus{
			FindingsVersion: ptr.To("v1"), Counts: counts(2, 3), OmittedFindings: ptr.To(int32(3))}}, triagev1alpha1.ResourceImageStateReady},
		"a sheet that left out more than the settled findings": {&inventoryv1alpha1.ImageVerdicts{Status: inventoryv1alpha1.ImageVerdictsStatus{
			FindingsVersion: ptr.To("v1"), Counts: counts(2, 3), OmittedFindings: ptr.To(int32(4))}}, triagev1alpha1.ResourceImageStateIncomplete},
	} {
		t.Run(name, func(t *testing.T) {
			if tc.sheet != nil {
				tc.sheet.Spec = inventoryv1alpha1.ImageVerdictsSpec{ManifestDigest: manifestAMD64, Playbook: defaultPlaybook}
			}

			got := renderOn(tc.sheet, configv1alpha1.SSVCExposureSmall)

			require.Len(t, got.Images, 1)
			require.Equal(t, tc.want, got.Images[0].State)
			require.Equal(t, ptr.To(imageDigest), got.Images[0].Digest)
			require.Equal(t, []string{manifestAMD64}, got.Images[0].ManifestDigests,
				"the facts name the manifest, whether or not a sheet of it exists yet")
			require.Equal(t, []string{webName}, got.Images[0].Containers)
		})
	}
}

// An image has one entry, which names the manifest of each platform that its pods run on. A vulnerability of a package
// that both platforms have is one action of the image.
func TestRenderGivesAnImageOneEntryWithTheManifestOfEachPlatformItsPodsRun(t *testing.T) {
	image := imageRun(imageDigest, webName)
	image.Platforms = []string{linuxAMD64, linuxARM64}

	got := renderImages([]spoke.RunningImage{image}, sheetsOf(
		sheetOf(manifestAMD64, openFinding("CVE-2026-0001", "libexample")),
		sheetOf(manifestARM64, openFinding("CVE-2026-0001", "libexample"), openFinding("CVE-2026-0002", "libarm")),
	), map[string]*inventoryv1alpha1.ImageFacts{imageDigest: factsOf()})

	require.Len(t, got.Images, 1)
	require.Equal(t, []string{manifestAMD64, manifestARM64}, got.Images[0].ManifestDigests)
	require.Equal(t, triagev1alpha1.ResourceImageStateReady, got.Images[0].State)
	require.Equal(t, ptr.To(int32(1)), actionOf(t, got, "libexample", triagev1alpha1.ResourceStepUpdate).Vulnerabilities,
		"a vulnerability in a package is counted once, whatever the platform")
	require.Len(t, got.Actions, 2)
}

// A pod that says no platform gives no manifest, unless the image has only one: no sheet is guessed. A platform that
// no manifest covers has no verdict, so the image waits, while the actions of the platforms that have one are there.
func TestAnImageWithAPlatformThatNoManifestCoversIsPending(t *testing.T) {
	got := spoke.Render(running(teamA, webName), []spoke.RunningImage{{Digest: imageDigest}}, defaultPlaybooks, nil,
		map[string]*inventoryv1alpha1.ImageFacts{imageDigest: factsOf()}, spoke.WorkloadExposure{SSVC: configv1alpha1.SSVCExposureSmall},
		settings.Effective{})

	require.Len(t, got.Images, 1)
	require.Nil(t, got.Images[0].ManifestDigests)
	require.Equal(t, triagev1alpha1.ResourceImageStatePending, got.Images[0].State)

	image := imageRun(imageDigest, webName)
	image.Platforms = []string{linuxAMD64, "linux/riscv64"}
	got = renderImages([]spoke.RunningImage{image}, sheetsOf(sheetOf(manifestAMD64, openFinding("CVE-2026-0001", "libexample"))),
		map[string]*inventoryv1alpha1.ImageFacts{imageDigest: factsOf()})

	require.Equal(t, []string{manifestAMD64}, got.Images[0].ManifestDigests)
	require.Equal(t, triagev1alpha1.ResourceImageStatePending, got.Images[0].State, "riscv64 has no verdict")
	require.Len(t, got.Actions, 1, "amd64 has one")
}

func TestRenderMakesTextFromImageContentPrintableAndBounded(t *testing.T) {
	f := openFinding("CVE-2026-0001\x1b[31m", strings.Repeat("p", 300))
	f.Package.Version = ptr.To("1.0\u202e")
	f.Package.Type = "deb\n" + strings.Repeat("t", 40)
	f.UpdateTarget = ptr.To("\x07" + strings.Repeat("v", 200))

	got := renderImages([]spoke.RunningImage{imageRun(imageDigest, "a\x1bb", strings.Repeat("c", 70))},
		sheetsOf(sheetOf(manifestAMD64, f)), map[string]*inventoryv1alpha1.ImageFacts{imageDigest: factsOf()})

	out := got.Actions[0]
	require.Equal(t, []string{"CVE-2026-0001�[31m"}, out.VulnerabilityIDs)
	require.Equal(t, strings.Repeat("p", 253), out.Package.Name)
	require.Equal(t, ptr.To("1.0�"), out.Package.Version)
	require.Equal(t, "deb�"+strings.Repeat("t", 28), out.Package.Type)
	require.Nil(t, out.FixedVersion, "a target that would have to be changed to fit names none")
	require.Equal(t, "Update "+strings.Repeat("p", 249), out.Title, "cut to 256 characters")
	require.Equal(t, []string{"a�b", strings.Repeat("c", 63)}, got.Images[0].Containers)
	require.Equal(t, "spec.template.spec.containers[a�b]", out.Locations[0])
}

// maxedSheets gives a CronJob images whose sheets, entries and actions reach every limit of a report: 32 images, each
// run by 32 containers of the longest names, and 300 packages of the longest texts, each with 7 vulnerabilities, in 9 of
// the images. text makes a text of the length that its limit gives.
func maxedSheets(text func(n int) string) ([]spoke.RunningImage, map[string][]inventoryv1alpha1.ImageVerdicts,
	map[string]*inventoryv1alpha1.ImageFacts) {
	findings := make([]inventoryv1alpha1.Finding, 0, 300*7)
	for p := range 300 {
		for v := range 7 {
			f := openFinding(fmt.Sprintf("%03d%01d", p, v)+text(60), fmt.Sprintf("%03d", p)+text(250))
			f.Package.Version = ptr.To(text(128))
			f.Package.Type = text(32)
			f.FixedVersions, f.UpdateTarget = []string{text(128)}, ptr.To(text(128))
			findings = append(findings, f)
		}
	}
	containers := make([]string, 0, 32)
	for n := range 32 {
		containers = append(containers, fmt.Sprintf("%02d", n)+text(61))
	}
	images := make([]spoke.RunningImage, 0, 32)
	facts := map[string]*inventoryv1alpha1.ImageFacts{}
	sheets := map[string][]inventoryv1alpha1.ImageVerdicts{}
	for i := range 32 {
		digest, manifest := hexDigest(100+i), hexDigest(200+i)
		images = append(images, imageRun(digest, containers...))
		facts[digest] = &inventoryv1alpha1.ImageFacts{Manifests: []inventoryv1alpha1.ManifestFact{{Platform: linuxAMD64, Digest: manifest}}}
		sheet := sheetOf(manifest)
		if i < 9 {
			sheet = sheetOf(manifest, findings...)
		}
		sheets[manifest] = []inventoryv1alpha1.ImageVerdicts{*sheet}
	}
	return images, sheets, facts
}

// maxedOwner gives a CronJob the most owner values, each with the longest key and value. A CronJob's containers have
// the longest locations.
func maxedOwner() evidence.PresenceWorkload {
	w := running(teamA, webName, linuxAMD64)
	w.APIGroup, w.Kind = "batch", "CronJob"
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

			got := spoke.Render(maxedOwner(), images, defaultPlaybooks, sheets, facts, spoke.WorkloadExposure{
				SSVC: configv1alpha1.SSVCExposureOpen, Reach: &triagev1alpha1.ReportReach{InternalReach: triagev1alpha1.InternalReachNamespaces,
					Indirect: triagev1alpha1.IndirectExposureNotIndirect}}, settings.Effective{})

			encoded, err := json.Marshal(got)
			require.NoError(t, err)
			require.LessOrEqual(t, len(encoded), 1<<20, "the status stays below 1 MiB")
			require.Len(t, got.Images, 32)
			require.Len(t, got.Images[0].Containers, 32)
			require.Len(t, got.Owner, 48)
			require.Len(t, got.Actions[0].VulnerabilityIDs, 5)
			require.Len(t, got.Actions[0].Locations, 8)
			require.Len(t, []rune(got.Actions[0].Title), 256)
			require.Len(t, []rune(ptr.Deref(got.Actions[0].FixedVersion, "")), 128, "one fixed version that every CVE names")
			require.Equal(t, int32(300*9-len(got.Actions)), *got.Summary.OmittedActions, "the summary counts the rest")
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

	got := spoke.Render(w, nil, defaultPlaybooks, nil, nil, spoke.WorkloadExposure{SSVC: configv1alpha1.SSVCExposureSmall},
		settings.Effective{})

	require.Equal(t, []triagev1alpha1.OwnerValue{
		{Source: triagev1alpha1.OwnerSourceNamespaceLabel, Key: "owner", Value: ptr.To(strings.Repeat("o", 256))},
		{Source: triagev1alpha1.OwnerSourceNamespaceAnnotation, Key: "example.org/contact", Value: ptr.To("a�b")},
		{Source: triagev1alpha1.OwnerSourceWorkloadLabel, Key: "empty", Value: ptr.To("")},
		{Source: triagev1alpha1.OwnerSourceWorkloadLabel, Key: teamLabel, Value: ptr.To(teamA)},
	}, got.Owner)
}

func TestRenderListsNoImageItCannotName(t *testing.T) {
	got := renderImages([]spoke.RunningImage{imageRun("sha512:abc", webName)}, nil, nil)

	require.Empty(t, got.Images, "a digest that isn't a sha256 digest is no digest that presence names")
	require.Equal(t, ptr.To(int32(0)), got.Summary.PendingImages)
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

// manyImages returns 40 images, each with a manifest for amd64, whose sheet sheet gives, and none where it gives nil.
func manyImages(sheet func(i int, manifest string) *inventoryv1alpha1.ImageVerdicts) ([]spoke.RunningImage,
	map[string][]inventoryv1alpha1.ImageVerdicts, map[string]*inventoryv1alpha1.ImageFacts) {
	images := make([]spoke.RunningImage, 0, 40)
	facts := map[string]*inventoryv1alpha1.ImageFacts{}
	sheets := make([]*inventoryv1alpha1.ImageVerdicts, 0, 40)
	for i := range 40 {
		digest, manifest := hexDigest(1000+i), hexDigest(2000+i)
		images = append(images, imageRun(digest, webName))
		facts[digest] = &inventoryv1alpha1.ImageFacts{Manifests: []inventoryv1alpha1.ManifestFact{{Platform: linuxAMD64, Digest: manifest}}}
		sheets = append(sheets, sheet(i, manifest))
	}
	return images, sheetsOf(sheets...), facts
}

// An image past the 32 entries of the list has no entry, but its sheet still counts and its findings are still in the
// actions: a limit never hides a finding.
func TestRenderGivesTheActionsOfImagesPastTheEntryLimit(t *testing.T) {
	images, sheets, facts := manyImages(func(i int, manifest string) *inventoryv1alpha1.ImageVerdicts {
		return sheetOf(manifest, openFinding(fmt.Sprintf("CVE-2026-%05d", i), "libexample"))
	})

	got := renderImages(images, sheets, facts)

	require.Len(t, got.Images, 32, "the list holds 32 entries")
	require.Len(t, got.Actions, 40, "one for each image")
	require.Equal(t, ptr.To(hexDigest(1039)), got.Actions[39].Digest)
	require.Equal(t, ptr.To(int32(0)), got.Summary.OmittedActions)
}

// An image without a verdict adds nothing to the actions, so a summary of zeros alone would read as a clean workload.
// The summary counts the images that have no verdict yet, which its default column shows, so that a report whose
// images aren't settled never reads as clean (decision 0038).
func TestASummaryCountsTheImagesThatHaveNoVerdictYet(t *testing.T) {
	failed := hexDigest(9)
	images := []spoke.RunningImage{imageRun(imageDigest, webName), imageRun(failed, "api")}
	facts := map[string]*inventoryv1alpha1.ImageFacts{
		// The scan of the image named the manifest of each platform, and the sheet of amd64's has no verdict yet.
		imageDigest: factsOf(),
		// The scan of the other image keeps failing, so its facts name no manifest.
		failed: {Failures: []inventoryv1alpha1.ScanFailure{{Source: scanSource, Reason: inventoryv1alpha1.ScanFailureReasonUnauthorized,
			Attempts: 3}}},
	}
	sheets := sheetsOf(&inventoryv1alpha1.ImageVerdicts{
		Spec:   inventoryv1alpha1.ImageVerdictsSpec{ManifestDigest: manifestAMD64, Playbook: defaultPlaybook},
		Status: inventoryv1alpha1.ImageVerdictsStatus{Playbook: ptr.To(defaultPlaybook)},
	})

	got := renderImages(images, sheets, facts)

	want := summaryOf(0, 0, 0, 0, 0, 0, nil, nil)
	want.PendingImages = ptr.To(int32(2))
	require.Equal(t, want, *got.Summary, "nothing is known of the findings, and both images wait for their verdict")
	require.Empty(t, got.Actions)
}

// A sheet that left out open findings gives the report only those that it lists, so its image is Incomplete: its
// actions are not the whole answer.
func TestAnImageWhoseSheetLeftOutOpenFindingsIsIncomplete(t *testing.T) {
	sheet := sheetOf(manifestAMD64, openFinding("CVE-2026-0001", "libexample"))
	sheet.Status.Counts.Affected, sheet.Status.OmittedFindings = ptr.To(int32(500)), ptr.To(int32(499))

	got := renderOn(sheet, configv1alpha1.SSVCExposureSmall)

	require.Equal(t, triagev1alpha1.ResourceImageStateIncomplete, got.Images[0].State)
	require.Equal(t, ptr.To(int32(0)), got.Summary.PendingImages)
	require.Len(t, got.Actions, 1, "only the findings that the sheet lists")
}

// The summary counts every image of the workload that waits for its verdict, those past the 32 that the list holds
// included: an image that the list leaves out still says that the report isn't the whole answer yet.
func TestASummaryCountsTheImagesWithoutAVerdictPastTheEntryLimit(t *testing.T) {
	images, sheets, facts := manyImages(func(i int, manifest string) *inventoryv1alpha1.ImageVerdicts {
		switch {
		case i < 32:
			return sheetOf(manifest)
		case i < 37:
			return nil // no sheet yet: Pending
		}
		sheet := sheetOf(manifest, openFinding(fmt.Sprintf("CVE-2026-%05d", i), "libexample"))
		sheet.Status.OmittedFindings = ptr.To(int32(1))
		return sheet
	})

	got := renderImages(images, sheets, facts)

	require.Len(t, got.Images, 32)
	for _, image := range got.Images {
		require.Equal(t, triagev1alpha1.ResourceImageStateReady, image.State, "the list holds the first 32, each Ready")
	}
	require.Equal(t, ptr.To(int32(5)), got.Summary.PendingImages, "the images past the list that wait for their verdict")
	require.Len(t, got.Actions, 3, "the findings that the Incomplete images past the list give")
}

func renderPodOn(pod string, facts *inventoryv1alpha1.ImageFacts, sheets map[string][]inventoryv1alpha1.ImageVerdicts) triagev1alpha1.ResourceReportStatus {
	image := imageRun(imageDigest, webName)
	image.Platforms = []string{pod}
	return renderImages([]spoke.RunningImage{image}, sheets, map[string]*inventoryv1alpha1.ImageFacts{imageDigest: facts})
}

// A node says no variant of its architecture, so a manifest that an image lists only under a variant is the one that
// runs on it.
func TestRenderReadsTheManifestListedUnderAVariantOfTheNodesPlatform(t *testing.T) {
	facts, d := variantFacts("linux/arm64/v8")
	got := renderPodOn(linuxARM64, facts, sheetsOf(sheetOf(d[0], openFinding("CVE-2026-0001", "libexample"))))

	require.Len(t, got.Images, 1)
	require.Equal(t, []string{d[0]}, got.Images[0].ManifestDigests)
	require.Equal(t, triagev1alpha1.ResourceImageStateReady, got.Images[0].State)
	require.Len(t, got.Actions, 1)
}

// Where the variants that match differ, the report reads them all: it never shows no findings for a variant that it
// could not tell apart.
func TestRenderReadsEveryVariantThatMatchesAPodWithNone(t *testing.T) {
	facts, d := variantFacts("linux/arm/v6", "linux/arm/v7", "linux/amd64")
	got := renderPodOn("linux/arm", facts, sheetsOf(
		sheetOf(d[0], openFinding("CVE-2026-0001", "libexample")),
		sheetOf(d[1], openFinding("CVE-2026-0002", "libother")),
	))

	require.Len(t, got.Images, 1)
	require.Equal(t, []string{d[0], d[1]}, got.Images[0].ManifestDigests)
	require.Len(t, got.Actions, 2, "the findings of both are distinct")
}

// A manifest of the pod's exact platform is the one that runs: a variant-less one does not join it.
func TestRenderPrefersTheExactPlatformToAManifestWithoutVariant(t *testing.T) {
	facts, d := variantFacts("linux/arm", "linux/arm/v7")
	got := renderPodOn("linux/arm/v7", facts, nil)

	require.Len(t, got.Images, 1)
	require.Equal(t, []string{d[1]}, got.Images[0].ManifestDigests)

	// Without an exact one, the variant-less manifest covers the pod.
	facts, d = variantFacts("linux/arm", "linux/arm/v6")
	got = renderPodOn("linux/arm/v7", facts, nil)
	require.Len(t, got.Images, 1)
	require.Equal(t, []string{d[0]}, got.Images[0].ManifestDigests)
}
