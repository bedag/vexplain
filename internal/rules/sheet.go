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

// Package rules makes the result sheet of a platform manifest from what the rules of a playbook made of
// its findings (decision 0025). The engine of internal/rules/engine evaluates the rules; this package
// turns the engine's findings into the sheet's, orders them, keeps as many of them as a sheet holds, and
// counts them all. It also gives back the matches that a sheet shows, so that the rules can evaluate
// them again without a new match, where that gives what a new match would.
//
// The package is pure. It reads nothing but its arguments, and keeps nothing between calls.
package rules

import (
	"cmp"
	"encoding/json"
	"slices"
	"strings"

	"k8s.io/utils/ptr"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
	inventoryv1alpha1 "github.com/bedag/vexplain/api/inventory/v1alpha1"
	"github.com/bedag/vexplain/internal/rules/engine"
	"github.com/bedag/vexplain/sdk/evidence"
)

// The limits of the schema of a sheet.
const (
	// maxFindings is the most findings that a sheet lists, as the schema allows.
	maxFindings = 2048
	// maxSheetBytes is the most JSON that the findings of a sheet add up to. A sheet is one object,
	// which must stay below etcd's limit for a request, so its findings may take 1 MiB of it.
	maxSheetBytes = 1 << 20
)

// The fix states of a match, as the sources spell them, which the engine merges matches by. Each maps
// to one of the API's.
var fixStates = map[string]inventoryv1alpha1.FixState{
	"fixed":     inventoryv1alpha1.FixStateFixed,
	"not-fixed": inventoryv1alpha1.FixStateNotFixed,
	"wont-fix":  inventoryv1alpha1.FixStateWontFix,
	"unknown":   inventoryv1alpha1.FixStateUnknown,
}

// severities lists the severities from the most severe down. The engine spells a match's severity as
// the API does.
var severities = []inventoryv1alpha1.Severity{
	inventoryv1alpha1.SeverityCritical,
	inventoryv1alpha1.SeverityHigh,
	inventoryv1alpha1.SeverityMedium,
	inventoryv1alpha1.SeverityLow,
	inventoryv1alpha1.SeverityNegligible,
	inventoryv1alpha1.SeverityUnknown,
}

// Findings returns the sheet's findings of the engine's: one for each, in the same order, with what the
// engine made of it. The engine has made every string printable and cut it to the schema's limits
// already. What is empty is left out, as the schema has it: a package without a version, a finding that
// no rule decided, and a reason. A score keeps both its parts, either of which may be empty. A
// justification is there exactly for a finding that is NotAffected.
func Findings(found []engine.Finding) []inventoryv1alpha1.Finding {
	findings := make([]inventoryv1alpha1.Finding, 0, len(found))
	for _, f := range found {
		m := f.Match
		finding := inventoryv1alpha1.Finding{
			VulnerabilityID: m.VulnerabilityID,
			Package: inventoryv1alpha1.PackageReference{
				ID: m.PackageID, Name: m.PackageName, Version: nonEmpty(m.PackageVersion), Type: m.PackageType,
			},
			Status:         inventoryv1alpha1.VEXStatus(f.Status),
			Rule:           nonEmpty(f.Rule),
			Reason:         nonEmpty(f.Reason),
			Severity:       inventoryv1alpha1.Severity(m.Severity),
			FixState:       cmp.Or(fixStates[m.FixState], inventoryv1alpha1.FixStateUnknown),
			FixedVersions:  slices.Clone(m.FixedVersions),
			KnownExploited: inventoryv1alpha1.KnownExploitedNotListed,
		}
		if f.Status == configv1alpha1.VEXStatusNotAffected {
			finding.Justification = ptr.To(inventoryv1alpha1.VEXJustification(f.Justification))
		}
		if m.KnownExploited {
			finding.KnownExploited = inventoryv1alpha1.KnownExploitedListed
		}
		for _, note := range f.Notes {
			finding.StatusNotes = append(finding.StatusNotes, inventoryv1alpha1.StatusNote{Rule: note.Rule, Text: note.Text})
		}
		for _, score := range m.CVSS {
			finding.CVSS = append(finding.CVSS, inventoryv1alpha1.CVSS{Version: ptr.To(score.Version), Vector: ptr.To(score.Vector)})
		}
		findings = append(findings, finding)
	}
	return findings
}

// Matches returns the matches that the findings of a sheet show, one for each, and reports whether the
// rules can evaluate them in place of the matches that they were made of. They can when every finding
// shows its match exactly, as engine.Exact tells, and holds only values that this version knows: the
// engine then gives the rules the same matches as before, and so makes the same findings. They can't
// when showing may have changed a finding's match: the rules could then find another package than the
// match named, such as by a placeholder or a cut package ID, and settle the finding. Matches then
// returns none, and the matches must be made again.
//
// The findings of a sheet that leaves some out are not all the findings of the manifest: the caller
// checks omittedFindings itself.
func Matches(findings []inventoryv1alpha1.Finding) ([]evidence.Match, bool) {
	matches := make([]evidence.Match, 0, len(findings))
	for _, f := range findings {
		m, ok := matchOf(f)
		if !ok || !engine.Exact(m) {
			return nil, false
		}
		matches = append(matches, m)
	}
	return matches, true
}

// matchOf returns the match that a finding shows, and false when the finding holds a severity, a fix
// state or an exploitation that this version doesn't know, which says nothing that a rule can read.
func matchOf(f inventoryv1alpha1.Finding) (evidence.Match, bool) {
	fixState := ""
	for word, state := range fixStates {
		if state == f.FixState {
			fixState = word
		}
	}
	var exploited bool
	switch f.KnownExploited {
	case inventoryv1alpha1.KnownExploitedListed:
		exploited = true
	case inventoryv1alpha1.KnownExploitedNotListed:
	default:
		return evidence.Match{}, false
	}
	if fixState == "" || !slices.Contains(severities, f.Severity) {
		return evidence.Match{}, false
	}
	m := evidence.Match{
		VulnerabilityID: f.VulnerabilityID,
		PackageID:       f.Package.ID,
		PackageName:     f.Package.Name,
		PackageVersion:  ptr.Deref(f.Package.Version, ""),
		PackageType:     f.Package.Type,
		Severity:        string(f.Severity),
		FixState:        fixState,
		FixedVersions:   slices.Clone(f.FixedVersions),
		KnownExploited:  exploited,
	}
	for _, score := range f.CVSS {
		m.CVSS = append(m.CVSS, evidence.CVSS{Version: ptr.Deref(score.Version, ""), Vector: ptr.Deref(score.Vector, "")})
	}
	return m, true
}

// nonEmpty returns a pointer to s, or nil when s is empty: the schema leaves out what says nothing.
func nonEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// Sheet orders the findings of a manifest, keeps as many of them as a sheet may hold, and counts
// them all.
//
// The order puts the open findings first, Affected and then UnderInvestigation, and the settled ones
// last, Fixed and then NotAffected. Within a status, the findings of a vulnerability that the source
// lists as known to be exploited come first: they are the most urgent, and the last that a cut leaves
// out. Then come the most severe findings, from Critical down, then by vulnerability ID, then by package
// ID. A status that Sheet doesn't know goes just before the settled findings, a severity that it doesn't
// know after Unknown, and an exploitation that it doesn't know before NotListed, so that a cut never
// leaves out a finding that may need attention before a settled one.
//
// A sheet holds at most 2048 findings and 1 MiB of JSON, where each finding counts the length of its
// json.Marshal and one byte to separate it from the next. Sheet keeps findings in order until the
// next would break a limit. It stops there and never skips a finding to fit a later one, so what it
// leaves out is the end of the order: the settled findings go first, then the least severe open
// findings, and open findings that are known to be exploited go only when they alone pass a limit.
//
// omitted is the number of findings that were left out, and counts covers every finding, those left
// out included. Sheet changes neither the findings nor their order in the argument, and returns a
// slice of its own.
func Sheet(findings []inventoryv1alpha1.Finding) (kept []inventoryv1alpha1.Finding, omitted int32, counts inventoryv1alpha1.FindingCounts) {
	ordered := slices.Clone(findings)
	slices.SortStableFunc(ordered, compareFindings)

	var affected, underInvestigation, notAffected, fixed int32
	for _, f := range ordered {
		switch f.Status {
		case inventoryv1alpha1.VEXStatusAffected:
			affected++
		case inventoryv1alpha1.VEXStatusUnderInvestigation:
			underInvestigation++
		case inventoryv1alpha1.VEXStatusNotAffected:
			notAffected++
		case inventoryv1alpha1.VEXStatusFixed:
			fixed++
		}
	}

	size, n := 0, 0
	for n < len(ordered) && n < maxFindings {
		encoded, err := json.Marshal(ordered[n])
		if err != nil || size+len(encoded)+1 > maxSheetBytes {
			break
		}
		size += len(encoded) + 1
		n++
	}

	return slices.Clone(ordered[:n]), int32(len(ordered) - n), inventoryv1alpha1.FindingCounts{
		Affected:           ptr.To(affected),
		UnderInvestigation: ptr.To(underInvestigation),
		NotAffected:        ptr.To(notAffected),
		Fixed:              ptr.To(fixed),
	}
}

// compareFindings is the order of a sheet.
func compareFindings(a, b inventoryv1alpha1.Finding) int {
	return cmp.Or(
		cmp.Compare(statusRank(a.Status), statusRank(b.Status)),
		cmp.Compare(exploitedRank(a.KnownExploited), exploitedRank(b.KnownExploited)),
		cmp.Compare(severityRank(a.Severity), severityRank(b.Severity)),
		strings.Compare(a.VulnerabilityID, b.VulnerabilityID),
		strings.Compare(a.Package.ID, b.Package.ID),
	)
}

// statusRank is the place of a status in the order of a sheet: the open ones first, the most cautious
// first, and the settled ones last. A status that this code doesn't know comes before the settled
// ones, so that a cut leaves out a settled finding before one that may need attention.
func statusRank(s inventoryv1alpha1.VEXStatus) int {
	switch s {
	case inventoryv1alpha1.VEXStatusAffected:
		return 0
	case inventoryv1alpha1.VEXStatusUnderInvestigation:
		return 1
	case inventoryv1alpha1.VEXStatusFixed:
		return 3
	case inventoryv1alpha1.VEXStatusNotAffected:
		return 4
	}
	return 2
}

// exploitedRank puts the findings of a vulnerability that is known to be exploited first. A value that
// this code doesn't know may say that it is, and goes with them.
func exploitedRank(k inventoryv1alpha1.KnownExploited) int {
	if k == inventoryv1alpha1.KnownExploitedNotListed {
		return 1
	}
	return 0
}

// severityRank is the place of a severity in severities: the lower, the more severe. A severity that
// the list doesn't have comes after all that it has.
func severityRank(s inventoryv1alpha1.Severity) int {
	if i := slices.Index(severities, s); i >= 0 {
		return i
	}
	return len(severities)
}
