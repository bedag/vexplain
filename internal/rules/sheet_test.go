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

package rules_test

import (
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
	inventoryv1alpha1 "github.com/bedag/vexplain/api/inventory/v1alpha1"
	"github.com/bedag/vexplain/internal/rules"
	"github.com/bedag/vexplain/internal/rules/engine"
	"github.com/bedag/vexplain/sdk/evidence"
)

// These tests cover the sheet of a platform manifest: how Sheet orders and caps its findings, how the
// engine's findings become the sheet's, and how a sheet's findings give back the matches that the
// rules can evaluate again. A sheet that leaves out open findings, or a match given back that differs
// from the one that the rules saw, could hide or settle a finding, so most of the cases are about those.

const (
	cve1      = "CVE-1"
	cve2      = "CVE-2"
	pkgID     = "pkg-1"
	pkgA      = "pkg-a"
	pkgB      = "pkg-b"
	libName   = "libfoo"
	typeAPK   = "apk"
	version1  = "1.2.3-r0"
	holdRule  = "hold"
	noteRule  = "note"
	settled   = "removed-in-later-layer"
	cvss31    = "3.1"
	vector31  = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
	reachedBy = "reached by /usr/bin/curl"
	fix124    = "1.2.4-r0"
	fix130    = "1.3.0-r0"
	// The severities and fix states of a source, as the engine spells them.
	mostSevere = "Critical"
	medium     = "Medium"
	negligible = "Negligible"
	unknown    = "Unknown"
	stateNone  = "unknown"
	stateFixed = "fixed"
)

const (
	affected           = inventoryv1alpha1.VEXStatusAffected
	underInvestigation = inventoryv1alpha1.VEXStatusUnderInvestigation
	notAffected        = inventoryv1alpha1.VEXStatusNotAffected
	fixed              = inventoryv1alpha1.VEXStatusFixed
	listed             = inventoryv1alpha1.KnownExploitedListed
	notListed          = inventoryv1alpha1.KnownExploitedNotListed
)

// ---- Sheet ----

// sheetFinding is a finding with the fields that Sheet orders by.
func sheetFinding(status inventoryv1alpha1.VEXStatus, severity inventoryv1alpha1.Severity, vulnerabilityID, packageID string) inventoryv1alpha1.Finding {
	f := inventoryv1alpha1.Finding{
		VulnerabilityID: vulnerabilityID,
		Package:         inventoryv1alpha1.PackageReference{ID: packageID, Name: libName, Type: typeAPK},
		Status:          status,
		Severity:        severity,
		FixState:        inventoryv1alpha1.FixStateUnknown,
		KnownExploited:  notListed,
	}
	if status == notAffected {
		f.Justification = ptr.To(inventoryv1alpha1.VEXJustificationComponentNotPresent)
	}
	return f
}

// exploitedFinding is sheetFinding of a vulnerability that the source lists as known to be exploited.
func exploitedFinding(status inventoryv1alpha1.VEXStatus, severity inventoryv1alpha1.Severity, vulnerabilityID, packageID string) inventoryv1alpha1.Finding {
	f := sheetFinding(status, severity, vulnerabilityID, packageID)
	f.KnownExploited = listed
	return f
}

// sheetBytes is the size that Sheet counts for findings: the JSON of each and one byte to separate it.
func sheetBytes(t *testing.T, findings []inventoryv1alpha1.Finding) int {
	t.Helper()
	size := 0
	for _, f := range findings {
		raw, err := json.Marshal(f)
		require.NoError(t, err)
		size += len(raw) + 1
	}
	return size
}

func counts(affectedCount, underInvestigationCount, notAffectedCount, fixedCount int32) inventoryv1alpha1.FindingCounts {
	return inventoryv1alpha1.FindingCounts{
		Affected:           ptr.To(affectedCount),
		UnderInvestigation: ptr.To(underInvestigationCount),
		NotAffected:        ptr.To(notAffectedCount),
		Fixed:              ptr.To(fixedCount),
	}
}

func mustMarshal(v any) []byte {
	raw, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return raw
}

func TestSheetOrdersByStatusThenExploitationThenSeverityThenVulnerabilityThenPackage(t *testing.T) {
	const (
		critical   = inventoryv1alpha1.SeverityCritical
		high       = inventoryv1alpha1.SeverityHigh
		medium     = inventoryv1alpha1.SeverityMedium
		low        = inventoryv1alpha1.SeverityLow
		negligible = inventoryv1alpha1.SeverityNegligible
		unknown    = inventoryv1alpha1.SeverityUnknown
	)
	// In the order that Sheet must give: the open findings first, Affected and then UnderInvestigation,
	// and then the settled ones, Fixed and then NotAffected. Within a status, a vulnerability that the
	// source lists as known to be exploited comes first, though it is less severe. The vulnerability IDs
	// run against the severities, so that severity is seen to come first.
	want := []inventoryv1alpha1.Finding{
		exploitedFinding(affected, low, "CVE-8", pkgA),
		sheetFinding(affected, critical, "CVE-9", pkgA),
		exploitedFinding(underInvestigation, low, "CVE-7", pkgA),
		sheetFinding(underInvestigation, critical, cve2, pkgA),
		sheetFinding(underInvestigation, critical, cve2, pkgB),
		sheetFinding(underInvestigation, critical, "CVE-6", pkgA),
		sheetFinding(underInvestigation, high, "CVE-5", pkgA),
		sheetFinding(underInvestigation, medium, "CVE-4", pkgA),
		sheetFinding(underInvestigation, low, "CVE-3", pkgA),
		sheetFinding(underInvestigation, negligible, cve2, pkgA),
		sheetFinding(underInvestigation, unknown, cve1, pkgA),
		sheetFinding(fixed, critical, cve1, pkgA),
		sheetFinding(notAffected, critical, cve1, pkgA),
		sheetFinding(notAffected, unknown, "CVE-0", pkgA),
	}
	rng := rand.New(rand.NewPCG(3, 5))
	for range 50 {
		input := slices.Clone(want)
		rng.Shuffle(len(input), func(i, j int) { input[i], input[j] = input[j], input[i] })
		kept, omitted, got, _ := rules.Sheet(input)
		require.Equal(t, want, kept)
		require.Zero(t, omitted)
		require.Equal(t, counts(2, 9, 2, 1), got)
	}
}

func TestSheetKeepsWhatItDoesNotKnowAheadOfWhatItCanLeaveOut(t *testing.T) {
	// A later version of the API may add a status, a severity or a word for known exploitation. Sheet
	// puts such a value where a cut leaves it out last: a status before the settled findings, a severity
	// after the known ones, and an exploitation ahead of NotListed, since it may say that the
	// vulnerability is exploited.
	unknownStatus := sheetFinding("Waived", inventoryv1alpha1.SeverityCritical, cve1, pkgA)
	unknownSeverity := sheetFinding(underInvestigation, "Severe", cve1, pkgA)
	unknownExploitation := sheetFinding(underInvestigation, inventoryv1alpha1.SeverityLow, "CVE-9", pkgB)
	unknownExploitation.KnownExploited = "Reported"
	want := []inventoryv1alpha1.Finding{
		unknownExploitation,
		sheetFinding(underInvestigation, inventoryv1alpha1.SeverityUnknown, "CVE-9", pkgA),
		unknownSeverity,
		unknownStatus,
		sheetFinding(fixed, inventoryv1alpha1.SeverityCritical, "CVE-0", pkgA),
		sheetFinding(notAffected, inventoryv1alpha1.SeverityCritical, "CVE-0", pkgA),
	}
	input := slices.Clone(want)
	slices.Reverse(input)
	kept, omitted, got, _ := rules.Sheet(input)
	require.Equal(t, want, kept)
	require.Zero(t, omitted)
	require.Equal(t, counts(0, 3, 1, 1), got, "a status that it doesn't know counts as none of the four")
}

func TestSheetKeeps2048FindingsAndLeavesOutSettledOnes(t *testing.T) {
	findings := make([]inventoryv1alpha1.Finding, 0, 2100)
	for i := range 1000 {
		findings = append(findings, sheetFinding(underInvestigation, inventoryv1alpha1.SeverityHigh, fmt.Sprintf("CVE-2026-%05d", i), pkgID))
	}
	for i := range 48 {
		findings = append(findings, exploitedFinding(underInvestigation, inventoryv1alpha1.SeverityHigh, fmt.Sprintf("CVE-2026-9%04d", i), pkgID))
	}
	for i := range 20 {
		findings = append(findings, sheetFinding(fixed, inventoryv1alpha1.SeverityHigh, fmt.Sprintf("CVE-2026-8%04d", i), pkgID))
	}
	for i := range 1032 {
		findings = append(findings, sheetFinding(notAffected, inventoryv1alpha1.SeverityHigh, fmt.Sprintf("CVE-2026-%05d", i), pkgID))
	}
	require.Len(t, findings, 2100)
	rng := rand.New(rand.NewPCG(1, 2))
	rng.Shuffle(len(findings), func(i, j int) { findings[i], findings[j] = findings[j], findings[i] })

	kept, omitted, got, _ := rules.Sheet(findings)
	require.Len(t, kept, 2048)
	require.Equal(t, int32(52), omitted)
	require.Equal(t, counts(0, 1048, 1032, 20), got, "the counts cover the findings that the sheet leaves out")
	require.LessOrEqual(t, omitted, *got.NotAffected+*got.Fixed, "only settled findings are left out, so no more than there are")
	require.Less(t, sheetBytes(t, kept), 1<<20, "the count is what stops the sheet here, not the size")

	byStatus := map[inventoryv1alpha1.VEXStatus]int{}
	for _, f := range kept {
		byStatus[f.Status]++
	}
	require.Equal(t, map[inventoryv1alpha1.VEXStatus]int{underInvestigation: 1048, fixed: 20, notAffected: 980}, byStatus,
		"only findings that are NotAffected are left out: they come last")
}

func TestSheetStopsBeforeAFindingThatWouldPushTheJSONPast1MiB(t *testing.T) {
	longReason := ptr.To(strings.Repeat("r", 256))
	longVersions := make([]string, 8)
	for i := range longVersions {
		longVersions[i] = strings.Repeat(string(rune('a'+i)), 128)
	}
	findings := make([]inventoryv1alpha1.Finding, 0, 1500)
	for i := range 1500 {
		f := sheetFinding(underInvestigation, inventoryv1alpha1.SeverityHigh, fmt.Sprintf("CVE-2026-%05d", i), pkgID)
		f.Reason, f.FixedVersions = longReason, longVersions
		findings = append(findings, f)
	}

	kept, omitted, got, _ := rules.Sheet(findings)
	require.NotEmpty(t, kept)
	require.Less(t, len(kept), 2048, "the size stops the sheet before the count does")
	require.Equal(t, findings[:len(kept)], kept, "the findings that it keeps are the first ones")

	size := sheetBytes(t, kept)
	require.LessOrEqual(t, size, 1<<20)
	require.Greater(t, size+sheetBytes(t, findings[len(kept):len(kept)+1]), 1<<20, "the next finding would not have fit")
	require.Equal(t, int32(len(findings)-len(kept)), omitted)
	require.Equal(t, counts(0, 1500, 0, 0), got)
}

func TestSheetCountsOneByteForEachFindingToSeparateIt(t *testing.T) {
	// Three findings whose JSON, with a byte to separate each, adds up to 1 MiB exactly fit. One byte
	// more and the last does not.
	sized := func(reasonBytes int) []inventoryv1alpha1.Finding {
		findings := make([]inventoryv1alpha1.Finding, 0, 3)
		for i := range 3 {
			f := sheetFinding(underInvestigation, inventoryv1alpha1.SeverityCritical, fmt.Sprintf("CVE-%d", i), pkgID)
			f.Reason = ptr.To(strings.Repeat("x", 400_000))
			findings = append(findings, f)
		}
		findings[2].Reason = ptr.To(strings.Repeat("x", reasonBytes))
		return findings
	}
	// The JSON grows by one byte for each byte of the reason, which is plain ASCII.
	exact := 1<<20 - sheetBytes(t, sized(0))
	require.Equal(t, 1<<20, sheetBytes(t, sized(exact)))

	kept, omitted, _, _ := rules.Sheet(sized(exact))
	require.Len(t, kept, 3)
	require.Zero(t, omitted)

	kept, omitted, got, _ := rules.Sheet(sized(exact + 1))
	require.Len(t, kept, 2)
	require.Equal(t, int32(1), omitted)
	require.Equal(t, counts(0, 3, 0, 0), got)
}

func TestSheetNeverSkipsOverAFindingThatDoesNotFit(t *testing.T) {
	// Findings that a sheet leaves out are the last ones in its order, so that what comes first is
	// never dropped for something that comes after it.
	findings := make([]inventoryv1alpha1.Finding, 0, 5)
	for i := range 5 {
		findings = append(findings, sheetFinding(underInvestigation, inventoryv1alpha1.SeverityCritical, fmt.Sprintf("CVE-%d", i), pkgID))
	}
	findings[2].Reason = ptr.To(strings.Repeat("x", 2<<20))

	kept, omitted, got, _ := rules.Sheet(findings)
	require.Equal(t, findings[:2], kept)
	require.Equal(t, int32(3), omitted, "the two small findings after the large one are left out with it")
	require.Equal(t, counts(0, 5, 0, 0), got)
}

func TestSheetOfNothing(t *testing.T) {
	kept, omitted, got, _ := rules.Sheet(nil)
	require.Empty(t, kept)
	require.Zero(t, omitted)
	require.Equal(t, counts(0, 0, 0, 0), got, "the counts are required, so zeros are set")
}

func TestSheetLeavesItsInputAlone(t *testing.T) {
	findings := []inventoryv1alpha1.Finding{
		sheetFinding(notAffected, inventoryv1alpha1.SeverityLow, cve2, pkgID),
		sheetFinding(underInvestigation, inventoryv1alpha1.SeverityHigh, cve1, pkgID),
	}
	before := mustMarshal(findings)
	kept, _, _, _ := rules.Sheet(findings)
	require.JSONEq(t, string(before), string(mustMarshal(findings)), "the input keeps its order")

	// What it returns is its own too: appending to it doesn't write into the input's array.
	_ = append(kept, sheetFinding(affected, inventoryv1alpha1.SeverityLow, "CVE-3", pkgID))
	require.JSONEq(t, string(before), string(mustMarshal(findings)))
}

// openFindings returns n findings that no rule settled, in the order of a sheet: the first half
// Critical and the second half Medium. Long ones carry the longest reason and fixed versions that the
// schema allows.
func openFindings(n int, long bool) []inventoryv1alpha1.Finding {
	longVersions := make([]string, 8)
	for i := range longVersions {
		longVersions[i] = strings.Repeat(string(rune('a'+i)), 128)
	}
	findings := make([]inventoryv1alpha1.Finding, 0, n)
	for i := range n {
		severity := inventoryv1alpha1.SeverityCritical
		if i >= n/2 {
			severity = inventoryv1alpha1.SeverityMedium
		}
		f := sheetFinding(underInvestigation, severity, fmt.Sprintf("CVE-2026-%05d", i), pkgID)
		if long {
			f.Reason, f.FixedVersions = ptr.To(strings.Repeat("r", 256)), longVersions
		}
		findings = append(findings, f)
	}
	return findings
}

func TestSheetPastALimitLeavesOutTheLeastSevereOpenFindingsBeforeAnyKnownExploitedOne(t *testing.T) {
	// A vulnerability that is known to be exploited is the most urgent, so its findings are the last of
	// their status that a cut leaves out. When the open findings alone pass a limit, the sheet leaves out
	// the end of its order: every settled finding first, then the least severe of the open ones, and
	// never one known to be exploited, though each of those is less severe than the rest.
	exploitedFindings := make([]inventoryv1alpha1.Finding, 0, 20)
	for i := range 20 {
		exploitedFindings = append(exploitedFindings,
			exploitedFinding(underInvestigation, inventoryv1alpha1.SeverityLow, fmt.Sprintf("CVE-2026-9%04d", i), pkgID))
	}
	settledFindings := make([]inventoryv1alpha1.Finding, 0, 100)
	for i := range 100 {
		settledFindings = append(settledFindings,
			sheetFinding(notAffected, inventoryv1alpha1.SeverityCritical, fmt.Sprintf("CVE-2026-%05d", i), pkgID))
	}

	for name, open := range map[string][]inventoryv1alpha1.Finding{
		"more than 2048 findings": openFindings(2040, false),
		"more than 1 MiB":         openFindings(1500, true),
	} {
		t.Run(name, func(t *testing.T) {
			findings := slices.Concat(open, exploitedFindings, settledFindings)
			rng := rand.New(rand.NewPCG(9, 4))
			rng.Shuffle(len(findings), func(i, j int) { findings[i], findings[j] = findings[j], findings[i] })

			kept, omitted, got, _ := rules.Sheet(findings)
			require.Greater(t, len(kept), len(exploitedFindings))
			require.Equal(t, exploitedFindings, kept[:len(exploitedFindings)], "every exploited finding is kept, and comes first")
			rest := kept[len(exploitedFindings):]
			require.Less(t, len(rest), len(open), "the other open findings don't all fit")
			require.Equal(t, open[:len(rest)], rest, "of those, the most severe are kept")
			require.Equal(t, int32(len(findings)-len(kept)), omitted, "the 100 settled findings and the end of the others")
			require.Greater(t, omitted, *got.NotAffected+*got.Fixed, "the sheet leaves out open findings: it is incomplete")
			require.Equal(t, counts(0, int32(len(open)+len(exploitedFindings)), 100, 0), got, "the counts include every finding")
		})
	}
}

// ---- the summary ----

// summary returns the summary of a sheet with as many findings of each kind.
func summary(open, fixable, held, settledCount, omitted int32) inventoryv1alpha1.SheetSummary {
	return inventoryv1alpha1.SheetSummary{
		Open: ptr.To(open), Fixable: ptr.To(fixable), Held: ptr.To(held), Settled: ptr.To(settledCount), Omitted: ptr.To(omitted),
	}
}

// requireAgreesWithCounts checks the summary against the counts and the number left out, which the schema checks
// too: open is Affected and UnderInvestigation, settled is NotAffected and Fixed.
func requireAgreesWithCounts(t *testing.T, got inventoryv1alpha1.SheetSummary, c inventoryv1alpha1.FindingCounts, omitted int32) {
	t.Helper()
	require.Equal(t, *c.Affected+*c.UnderInvestigation, *got.Open)
	require.Equal(t, *c.NotAffected+*c.Fixed, *got.Settled)
	require.Equal(t, omitted, *got.Omitted)
}

// The summary feeds the columns of a sheet (decision 0039): its open findings, of them those that an update fixes
// and those that a rule decided, its settled findings, and the findings that it leaves out.
func TestSheetSummarizesFindingsOfEveryKind(t *testing.T) {
	ruled := func(f inventoryv1alpha1.Finding, rule string) inventoryv1alpha1.Finding {
		f.Rule = ptr.To(rule)
		return f
	}
	fixState := func(f inventoryv1alpha1.Finding, state inventoryv1alpha1.FixState, versions ...string) inventoryv1alpha1.Finding {
		f.FixState, f.FixedVersions = state, versions
		return f
	}
	findings := []inventoryv1alpha1.Finding{
		// A rule decided each of these two, so they are held; an update fixes the first.
		fixState(ruled(sheetFinding(affected, inventoryv1alpha1.SeverityHigh, "CVE-1", pkgA), "reached"),
			inventoryv1alpha1.FixStateFixed, fix124),
		ruled(sheetFinding(affected, inventoryv1alpha1.SeverityLow, "CVE-2", pkgA), "reached"),
		// The hold of a vulnerability known to be exploited, and the completeness guard.
		fixState(ruled(exploitedFinding(underInvestigation, inventoryv1alpha1.SeverityCritical, "CVE-3", pkgB), holdRule),
			inventoryv1alpha1.FixStateNotFixed),
		ruled(sheetFinding(underInvestigation, inventoryv1alpha1.SeverityMedium, "CVE-4", pkgB), "completeness-guard"),
		// No rule decided these: a fixed version is listed, a fix is known to exist without one, and none is.
		fixState(sheetFinding(underInvestigation, inventoryv1alpha1.SeverityHigh, "CVE-5", pkgID), inventoryv1alpha1.FixStateUnknown, fix130),
		fixState(sheetFinding(underInvestigation, inventoryv1alpha1.SeverityHigh, "CVE-6", pkgID), inventoryv1alpha1.FixStateFixed),
		fixState(sheetFinding(underInvestigation, inventoryv1alpha1.SeverityNegligible, "CVE-7", pkgID), inventoryv1alpha1.FixStateWontFix),
		// Settled findings are neither fixable nor held, whatever their fix and their rule.
		fixState(ruled(sheetFinding(notAffected, inventoryv1alpha1.SeverityCritical, "CVE-8", pkgID), settled),
			inventoryv1alpha1.FixStateFixed, fix124),
		ruled(sheetFinding(fixed, inventoryv1alpha1.SeverityCritical, "CVE-9", pkgID), "backported-fix"),
	}

	kept, omitted, c, got := rules.Sheet(findings)
	require.Len(t, kept, len(findings))
	require.Equal(t, summary(7, 3, 4, 2, 0), got)
	requireAgreesWithCounts(t, got, c, omitted)
}

// The cut of a sheet leaves findings out, and its summary still counts every finding of the manifest: those that
// the cut leaves out, settled ones and open ones, are fixable and held as much as those that it keeps.
func TestSheetSummarizesEveryFindingAlsoPastItsCut(t *testing.T) {
	for name, open := range map[string][]inventoryv1alpha1.Finding{
		"more than 2048 findings": openFindings(2100, false),
		"more than 1 MiB":         openFindings(1500, true),
	} {
		t.Run(name, func(t *testing.T) {
			// The long findings list fixed versions, each of them; of the others, every third does.
			var fixable, held int32
			for i := range open {
				if i%3 == 0 && len(open[i].FixedVersions) == 0 {
					open[i].FixedVersions = []string{fix124}
				}
				if len(open[i].FixedVersions) > 0 {
					fixable++
				}
				if i%2 == 0 {
					open[i].Rule = ptr.To(holdRule)
					held++
				}
			}
			settledFindings := make([]inventoryv1alpha1.Finding, 0, 50)
			for i := range 50 {
				settledFindings = append(settledFindings,
					sheetFinding(notAffected, inventoryv1alpha1.SeverityCritical, fmt.Sprintf("CVE-2026-8%04d", i), pkgID))
			}

			kept, omitted, c, got := rules.Sheet(slices.Concat(open, settledFindings))
			require.Greater(t, omitted, int32(len(settledFindings)), "the cut leaves out open findings too")
			require.Less(t, len(kept), len(open))
			require.Equal(t, summary(int32(len(open)), fixable, held, 50, omitted), got)
			requireAgreesWithCounts(t, got, c, omitted)
		})
	}
}

func TestSheetSummaryOfNothing(t *testing.T) {
	_, _, _, got := rules.Sheet(nil)
	require.Equal(t, summary(0, 0, 0, 0, 0), got, "the counts of the summary are required, so zeros are set")
}

// ---- from the engine's findings to the sheet's ----

// engineFinding is a finding as the engine makes it: the match as it shows it, and what the steps made
// of it.
func engineFinding() engine.Finding {
	return engine.Finding{
		Match: evidence.Match{
			VulnerabilityID: cve1, PackageID: pkgID, PackageName: libName, PackageVersion: version1, PackageType: typeAPK,
			Severity: mostSevere, FixState: stateFixed, FixedVersions: []string{fix124, fix130}, KnownExploited: true,
			CVSS: []evidence.CVSS{{Version: cvss31, Vector: vector31}},
		},
		Status: configv1alpha1.VEXStatusUnderInvestigation,
		Rule:   holdRule,
		Reason: "known exploited",
		Notes:  []engine.Note{{Rule: noteRule, Text: reachedBy}},
	}
}

func TestFindingsCarryWhatTheEngineMadeOfEachFinding(t *testing.T) {
	got := rules.Findings([]engine.Finding{engineFinding()})

	require.Equal(t, []inventoryv1alpha1.Finding{{
		VulnerabilityID: cve1,
		Package:         inventoryv1alpha1.PackageReference{ID: pkgID, Name: libName, Version: ptr.To(version1), Type: typeAPK},
		Status:          underInvestigation,
		Rule:            ptr.To(holdRule),
		Reason:          ptr.To("known exploited"),
		StatusNotes:     []inventoryv1alpha1.StatusNote{{Rule: noteRule, Text: reachedBy}},
		Severity:        inventoryv1alpha1.SeverityCritical,
		FixState:        inventoryv1alpha1.FixStateFixed,
		FixedVersions:   []string{fix124, fix130},
		KnownExploited:  listed,
		CVSS:            []inventoryv1alpha1.CVSS{{Version: ptr.To(cvss31), Vector: ptr.To(vector31)}},
	}}, got)
}

// The schema leaves out what is empty, and takes a justification exactly for a finding that is
// NotAffected.
func TestFindingsLeaveOutWhatIsEmpty(t *testing.T) {
	f := engineFinding()
	f.Match.PackageVersion, f.Match.FixedVersions, f.Match.KnownExploited = "", nil, false
	f.Match.CVSS = []evidence.CVSS{{Vector: vector31}, {Version: cvss31}, {}}
	f.Status, f.Rule, f.Reason, f.Notes = configv1alpha1.VEXStatusUnderInvestigation, "", "", nil
	settledFinding := engineFinding()
	settledFinding.Status, settledFinding.Rule = configv1alpha1.VEXStatusNotAffected, settled
	settledFinding.Justification, settledFinding.Reason = configv1alpha1.VEXJustificationComponentNotPresent, ""

	got := rules.Findings([]engine.Finding{f, settledFinding})

	require.Nil(t, got[0].Package.Version)
	require.Nil(t, got[0].Rule)
	require.Nil(t, got[0].Reason)
	require.Nil(t, got[0].Justification)
	require.Nil(t, got[0].StatusNotes)
	require.Nil(t, got[0].FixedVersions)
	require.Equal(t, notListed, got[0].KnownExploited)
	require.Equal(t, []inventoryv1alpha1.CVSS{
		{Version: ptr.To(""), Vector: ptr.To(vector31)}, {Version: ptr.To(cvss31), Vector: ptr.To("")},
		{Version: ptr.To(""), Vector: ptr.To("")},
	}, got[0].CVSS, "a score keeps what the source gave, so that the rules read the same again")
	require.Equal(t, ptr.To(inventoryv1alpha1.VEXJustificationComponentNotPresent), got[1].Justification)
	require.Equal(t, notAffected, got[1].Status)
}

func TestFindingsMapTheSeveritiesAndTheFixStates(t *testing.T) {
	for _, tc := range []struct {
		severity, fixState string
		want               inventoryv1alpha1.Finding
	}{
		{mostSevere, stateFixed, inventoryv1alpha1.Finding{Severity: mostSevere, FixState: "Fixed"}},
		{"High", "not-fixed", inventoryv1alpha1.Finding{Severity: "High", FixState: "NotFixed"}},
		{medium, "wont-fix", inventoryv1alpha1.Finding{Severity: medium, FixState: "WontFix"}},
		{"Low", stateNone, inventoryv1alpha1.Finding{Severity: "Low", FixState: unknown}},
		{negligible, stateNone, inventoryv1alpha1.Finding{Severity: negligible, FixState: unknown}},
		{unknown, stateNone, inventoryv1alpha1.Finding{Severity: unknown, FixState: unknown}},
	} {
		f := engineFinding()
		f.Match.Severity, f.Match.FixState = tc.severity, tc.fixState

		got := rules.Findings([]engine.Finding{f})[0]

		require.Equal(t, tc.want.Severity, got.Severity)
		require.Equal(t, tc.want.FixState, got.FixState)
	}
}

// ---- from the sheet's findings back to matches ----

// stepsOf compiles rules that read the finding alone: a hold of the vulnerabilities known to be
// exploited, a rule that settles the findings in pkg-b, and a hint on every finding.
func stepsOf(t *testing.T) []*engine.Compiled {
	t.Helper()
	of := func(name string, outcome configv1alpha1.RuleOutcome, condition, reason string) *engine.Compiled {
		c, err := engine.Compile(&configv1alpha1.Rule{
			ObjectMeta: metav1.ObjectMeta{Name: name},
			Spec: configv1alpha1.RuleSpec{
				Condition: condition, Outcome: &outcome, Reason: ptr.To(reason),
			},
		})
		require.NoError(t, err)
		return c
	}
	return []*engine.Compiled{
		of(holdRule, configv1alpha1.RuleOutcome{Status: ptr.To(configv1alpha1.VEXStatusUnderInvestigation)},
			"finding.knownExploited", "'known exploited'"),
		of(settled, configv1alpha1.RuleOutcome{
			Status:        ptr.To(configv1alpha1.VEXStatusNotAffected),
			Justification: ptr.To(configv1alpha1.VEXJustificationComponentNotPresent),
		}, "finding.packageID == 'pkg-b'", "'gone'"),
		of(noteRule, configv1alpha1.RuleOutcome{}, "true", "'seen ' + finding.packageName"),
	}
}

// matchesOfASheet are matches whose findings a sheet shows exactly: of two vulnerabilities, in two
// packages, one known to be exploited, one with two scores, and one with a package without a version.
func matchesOfASheet() []evidence.Match {
	return []evidence.Match{
		{VulnerabilityID: cve1, PackageID: pkgA, PackageName: libName, PackageVersion: version1, PackageType: typeAPK,
			Severity: "high", FixState: stateFixed, FixedVersions: []string{fix130, fix124}, KnownExploited: true},
		{VulnerabilityID: cve1, PackageID: pkgA, PackageName: libName, PackageVersion: version1, PackageType: typeAPK,
			Severity: mostSevere, FixState: "not-fixed", CVSS: []evidence.CVSS{{Version: "2.0", Vector: "AV:N"}, {Version: cvss31, Vector: vector31}}},
		{VulnerabilityID: cve2, PackageID: pkgB, PackageName: "libbar", PackageType: "deb", Severity: negligible, FixState: "wont-fix"},
		{VulnerabilityID: cve2, PackageID: pkgA, PackageName: libName, PackageVersion: version1, PackageType: typeAPK, Severity: medium},
	}
}

// What a sheet shows of its findings gives the rules the matches that they saw, so evaluating them
// again gives the same findings, without a new match.
func TestMatchesGiveTheRulesWhatTheySawWhenTheSheetShowsItExactly(t *testing.T) {
	steps := stepsOf(t)
	first := engine.Evaluate(steps, nil, matchesOfASheet())
	sheetFindings := rules.Findings(first.Findings)

	matches, ok := rules.Matches(sheetFindings)

	require.True(t, ok)
	again := engine.Evaluate(steps, nil, matches)
	require.Equal(t, first, again, "the same findings, notes and counts")
	require.Equal(t, sheetFindings, rules.Findings(again.Findings))
}

// A finding that showing may have changed can't give back the match that the rules saw: a placeholder,
// a replaced character or a cut package ID could find another package, and settle the finding. The
// sheet then gives back no matches at all, and the hub matches again.
func TestMatchesRefuseASheetWhoseFindingMayShowAnotherMatch(t *testing.T) {
	for name, change := range map[string]func(*evidence.Match){
		"an empty package ID, which a finding shows as unknown": func(m *evidence.Match) { m.PackageID = "" },
		"a package ID with a control character":                 func(m *evidence.Match) { m.PackageID = "pkg-b\x00" },
		"a package ID longer than a finding shows":              func(m *evidence.Match) { m.PackageID = strings.Repeat("p", 70) },
		"more fixed versions than a finding shows": func(m *evidence.Match) {
			m.FixedVersions = strings.Split("1 2 3 4 5 6 7 8 9", " ")
		},
	} {
		t.Run(name, func(t *testing.T) {
			matches := matchesOfASheet()
			change(&matches[2])
			sheetFindings := rules.Findings(engine.Evaluate(stepsOf(t), nil, matches).Findings)

			got, ok := rules.Matches(sheetFindings)

			require.False(t, ok)
			require.Nil(t, got)
		})
	}
}

// A value that this version of the API doesn't know, such as one that a newer hub wrote, says nothing
// that the rules can read.
func TestMatchesRefuseAValueThatThisVersionDoesNotKnow(t *testing.T) {
	for name, change := range map[string]func(*inventoryv1alpha1.Finding){
		"a severity":            func(f *inventoryv1alpha1.Finding) { f.Severity = "Severe" },
		"a fix state":           func(f *inventoryv1alpha1.Finding) { f.FixState = "Deferred" },
		"a known exploitation":  func(f *inventoryv1alpha1.Finding) { f.KnownExploited = "Reported" },
		"no known exploitation": func(f *inventoryv1alpha1.Finding) { f.KnownExploited = "" },
	} {
		t.Run(name, func(t *testing.T) {
			sheetFindings := rules.Findings(engine.Evaluate(stepsOf(t), nil, matchesOfASheet()).Findings)
			change(&sheetFindings[1])

			_, ok := rules.Matches(sheetFindings)

			require.False(t, ok)
		})
	}
}

func TestMatchesOfNoFindingsAreNone(t *testing.T) {
	matches, ok := rules.Matches(nil)

	require.True(t, ok)
	require.Empty(t, matches)
}
