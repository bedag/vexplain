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
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"

	"github.com/stretchr/testify/require"
	"k8s.io/utils/ptr"

	inventoryv1alpha1 "github.com/bedag/vexplain/api/inventory/v1alpha1"
	"github.com/bedag/vexplain/internal/matchapi"
	"github.com/bedag/vexplain/internal/rules"
	"github.com/bedag/vexplain/internal/scan/result"
)

// These tests cover the rules: how Evaluate settles each finding, and how Sheet orders and caps
// the findings of a manifest. A finding wrongly settled as not affected is the worst error the
// operator can make, so most of the cases below are about when a rule must not settle.

const (
	someCVE       = "CVE-2026-0001"
	cve1          = "CVE-1"
	cve2          = "CVE-2"
	pkgID         = "pkg-1"
	pkg2          = "pkg-2"
	pkgA          = "pkg-a"
	pkgB          = "pkg-b"
	libPath       = "/usr/lib/libfoo.so.1"
	libSoname     = "libfoo.so.1"
	libAPath      = "/usr/lib/liba.so.1"
	libASoname    = "liba.so.1"
	libBPath      = "/usr/lib/libb.so.1"
	libBSoname    = "libb.so.1"
	libfooName    = "libfoo"
	libfooVersion = "1.2.3-r0"
	pkgGhost      = "pkg-ghost"
	fromTheMatch  = "name-in-the-match"
	typeAPK       = "apk"
	typeDeb       = "deb"
	curlPath      = "/usr/bin/curl"
	loadPy        = "/app/load.py"

	// Grype's words for severities and fix states, as the matcher passes them on.
	grypeCritical        = "Critical"
	grypeHigh            = "High"
	grypeMedium          = "Medium"
	grypeLow             = "Low"
	grypeNegligible      = "Negligible"
	grypeUnknownSeverity = "Unknown"
	grypeFixed           = "fixed"
	grypeNotFixed        = "not-fixed"
	grypeWontFix         = "wont-fix"
	grypeUnknownState    = "unknown"

	// The reasons that the rules give for what they leave open.
	guardAt80      = "completeness 80% is below 90%"
	reachedByCurl  = "reached by " + curlPath
	namedInLoadPy  = "named in " + loadPy
	preloads       = "the image preloads libraries"
	incompleteLibs = "the library evidence is incomplete"
	nothingReaches = "nothing in the image reaches or names its libraries"
)

const (
	needsAssessment = inventoryv1alpha1.OutcomeNeedsAssessment
	tracked         = inventoryv1alpha1.OutcomeTracked
	suppressed      = inventoryv1alpha1.OutcomeSuppressed
)

// defaultSettings are the settings of an operator that nobody configured.
var defaultSettings = rules.Settings{MinCompletenessPercent: 90}

// ---- fixtures ----

// artifact is a package of Syft's JSON, as far as the rules read it.
type artifact struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Version string `json:"version"`
	Type    string `json:"type"`
}

func sbomOf(artifacts ...artifact) json.RawMessage {
	return mustMarshal(struct {
		Artifacts []artifact `json:"artifacts"`
	}{artifacts})
}

func mustMarshal(v any) []byte {
	raw, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return raw
}

// libraryManifest is the evidence of an image of one OS package that owns one shared library, which
// nothing reaches or names, and whose ELF files packages account for entirely: the load check keeps
// its findings open, with that as the reason. Each test changes what it is about.
func libraryManifest() result.Manifest {
	return result.Manifest{
		Platform: "linux/amd64",
		SBOM:     sbomOf(artifact{ID: pkgID, Name: libfooName, Version: libfooVersion, Type: typeAPK}),
		Packages: []result.PackageFacts{{ID: pkgID, FilesListed: 4, FilesPresent: 4, SharedLibraries: 1}},
		ELF:      result.ELFSummary{Total: 10, Owned: 10},
		Libraries: []result.Library{
			{Path: libPath, Soname: libSoname, PackageID: pkgID},
		},
	}
}

// matchOf is a match of a vulnerability in a package, as the matcher reports it.
func matchOf(packageID string) matchapi.Match {
	return matchapi.Match{
		VulnerabilityID: someCVE, PackageID: packageID, Severity: grypeHigh, FixState: grypeNotFixed,
		PackageName: libfooName, PackageVersion: libfooVersion, PackageType: typeAPK,
	}
}

// requireValid checks what the schema of a finding demands, so that every finding that a test makes
// is one that the API server would accept. The limits are those of the markers on Finding and
// PackageReference in api/inventory/v1alpha1.
func requireValid(t *testing.T, f inventoryv1alpha1.Finding) {
	t.Helper()
	chars := utf8.RuneCountInString
	require.NotEmpty(t, f.VulnerabilityID)
	require.LessOrEqual(t, chars(f.VulnerabilityID), 64)
	require.NotEmpty(t, f.Package.ID)
	require.LessOrEqual(t, chars(f.Package.ID), 64)
	require.NotEmpty(t, f.Package.Name)
	require.LessOrEqual(t, chars(f.Package.Name), 253)
	if f.Package.Version != nil {
		require.NotEmpty(t, *f.Package.Version, "an absent version is nil, never empty")
		require.LessOrEqual(t, chars(*f.Package.Version), 128)
	}
	require.NotEmpty(t, f.Package.Type)
	require.LessOrEqual(t, chars(f.Package.Type), 32)

	requirePrintable(t, "the vulnerability ID", f.VulnerabilityID)
	requirePrintable(t, "the package ID", f.Package.ID)
	requirePrintable(t, "the package name", f.Package.Name)
	requirePrintable(t, "the package version", ptr.Deref(f.Package.Version, ""))
	requirePrintable(t, "the package type", f.Package.Type)
	requirePrintable(t, "the reason", ptr.Deref(f.Reason, ""))
	for _, v := range f.FixedVersions {
		requirePrintable(t, "a fixed version", v)
	}

	require.Contains(t, []inventoryv1alpha1.Outcome{suppressed, tracked, needsAssessment}, f.Outcome)
	require.Contains(t, []inventoryv1alpha1.Severity{
		inventoryv1alpha1.SeverityCritical, inventoryv1alpha1.SeverityHigh, inventoryv1alpha1.SeverityMedium,
		inventoryv1alpha1.SeverityLow, inventoryv1alpha1.SeverityNegligible, inventoryv1alpha1.SeverityUnknown,
	}, f.Severity)
	require.Contains(t, []inventoryv1alpha1.FixState{
		inventoryv1alpha1.FixStateFixed, inventoryv1alpha1.FixStateNotFixed,
		inventoryv1alpha1.FixStateWontFix, inventoryv1alpha1.FixStateUnknown,
	}, f.FixState)
	if f.Rule != nil {
		require.Contains(t, []inventoryv1alpha1.Rule{
			inventoryv1alpha1.RuleKnownExploited, inventoryv1alpha1.RuleCompletenessGuard,
			inventoryv1alpha1.RuleRemovedInLaterLayer, inventoryv1alpha1.RuleLoadCheck,
		}, *f.Rule)
	}

	// The schema's rule: a justification is set exactly for a suppressed finding.
	require.Equal(t, f.Outcome == suppressed, f.Justification != nil, "justification is set exactly when suppressed")
	// Conditions are what a suppression depends on, so no other finding has one.
	if len(f.Conditions) > 0 {
		require.Equal(t, suppressed, f.Outcome)
	}
	require.LessOrEqual(t, len(f.Conditions), 4)

	if f.Reason != nil {
		require.NotEmpty(t, *f.Reason)
		require.LessOrEqual(t, len(*f.Reason), 256, "the reason is cut in bytes")
		require.True(t, utf8.ValidString(*f.Reason), "the reason is cut on a character boundary")
	}
	require.LessOrEqual(t, len(f.FixedVersions), 8)
	for _, v := range f.FixedVersions {
		require.LessOrEqual(t, chars(v), 128)
	}
}

// requirePrintable checks that a string of a finding is valid UTF-8 and holds no character that Go
// doesn't call printable. A finding's text comes from images and databases, which can be crafted,
// and kubectl prints status strings as they are.
func requirePrintable(t *testing.T, what, s string) {
	t.Helper()
	require.True(t, utf8.ValidString(s), "%s is valid UTF-8", what)
	for _, r := range s {
		require.True(t, unicode.IsPrint(r), "%s has the unprintable character %U", what, r)
	}
}

// evaluateAll runs the rules and checks that every finding is valid, and that the load check settled none:
// it keeps a finding open, whatever the evidence says.
func evaluateAll(t *testing.T, ev result.Manifest, matches []matchapi.Match, s rules.Settings) []inventoryv1alpha1.Finding {
	t.Helper()
	findings := rules.Evaluate(ev, matches, s)
	for _, f := range findings {
		requireValid(t, f)
		if f.Rule != nil && *f.Rule == inventoryv1alpha1.RuleLoadCheck {
			require.Equal(t, needsAssessment, f.Outcome, "the load check settles nothing")
		}
	}
	return findings
}

// evaluate runs the rules over one match and returns its one finding.
func evaluate(t *testing.T, ev result.Manifest, m matchapi.Match) inventoryv1alpha1.Finding {
	t.Helper()
	findings := evaluateAll(t, ev, []matchapi.Match{m}, defaultSettings)
	require.Len(t, findings, 1)
	return findings[0]
}

// settled is what the rules made of a finding, without the package, the severity and the fixes.
type settled struct {
	Outcome       inventoryv1alpha1.Outcome
	Rule          *inventoryv1alpha1.Rule
	Justification *inventoryv1alpha1.Justification
	Conditions    []inventoryv1alpha1.FindingCondition
	Reason        *string
}

func settledOf(f inventoryv1alpha1.Finding) settled {
	return settled{f.Outcome, f.Rule, f.Justification, f.Conditions, f.Reason}
}

var (
	// undecided is a finding that no rule settled and none blocked.
	undecided = settled{Outcome: needsAssessment}
	// exploited is a finding that the known exploited rule tracks.
	exploited = settled{Outcome: tracked, Rule: ptr.To(inventoryv1alpha1.RuleKnownExploited)}
	// removed is a finding that the rule for a package gone from the filesystem suppresses.
	removed = settled{
		Outcome:       suppressed,
		Rule:          ptr.To(inventoryv1alpha1.RuleRemovedInLaterLayer),
		Justification: ptr.To(inventoryv1alpha1.JustificationComponentNotPresent),
	}
	// unreached is a finding in a library that nothing in the image reaches or names. The load check keeps
	// it open and settles nothing: it has no justification and no condition.
	unreached = keptOpen(inventoryv1alpha1.RuleLoadCheck, nothingReaches)
)

// keptOpen is a finding that a rule keeps open, with its reason.
func keptOpen(rule inventoryv1alpha1.Rule, reason string) settled {
	return settled{Outcome: needsAssessment, Rule: ptr.To(rule), Reason: ptr.To(reason)}
}

// ---- the rules, in their order ----

func TestEvaluateSettlesEachFindingByTheFirstRuleThatApplies(t *testing.T) {
	kev := func(m *matchapi.Match) { m.KnownExploited = true }
	belowMinimum := func(ev *result.Manifest) { ev.ELF.Owned = 8 }
	goneFromImage := func(ev *result.Manifest) { ev.Packages[0].FilesListed, ev.Packages[0].FilesPresent = 3, 0 }
	reached := func(ev *result.Manifest) {
		ev.Libraries[0].ReachedBy, ev.Libraries[0].ReachedCount = []string{curlPath}, 1
	}

	tests := []struct {
		name  string
		ev    func(*result.Manifest)
		match func(*matchapi.Match)
		want  settled
	}{
		// The first rule: a known exploited vulnerability is tracked, whatever else holds.
		{name: "KEV wins over the load check", match: kev, want: exploited},
		{name: "KEV wins over the guard", ev: belowMinimum, match: kev, want: exploited},
		{name: "KEV wins over removal in a later layer", ev: goneFromImage, match: kev, want: exploited},
		{name: "KEV wins over a finding that waits anyway", ev: reached, match: kev, want: exploited},

		// The guard: below the minimum, no rule may settle a finding as not affected.
		{name: "the guard keeps a finding open below the minimum", ev: belowMinimum, want: keptOpen(inventoryv1alpha1.RuleCompletenessGuard, guardAt80)},
		{
			name: "the guard blocks removal in a later layer", want: keptOpen(inventoryv1alpha1.RuleCompletenessGuard, guardAt80),
			ev: func(ev *result.Manifest) { belowMinimum(ev); goneFromImage(ev) },
		},
		{name: "at the minimum the rules decide", ev: func(ev *result.Manifest) { ev.ELF.Owned = 9 }, want: unreached},

		// Removed in a later layer: the database lists files, and none is left.
		{name: "removed in a later layer", ev: goneFromImage, want: removed},
		{
			name: "files that are left mean the package is there",
			ev:   func(ev *result.Manifest) { ev.Packages[0].FilesListed, ev.Packages[0].FilesPresent = 3, 1 }, want: unreached,
		},
		{
			name: "a package that lists no files is not removed",
			ev:   func(ev *result.Manifest) { ev.Packages[0].FilesListed, ev.Packages[0].FilesPresent = 0, 0 }, want: unreached,
		},

		// The load check keeps every finding open, and gives what it found as the reason.
		{name: "a library that nothing reaches or names", want: unreached},
		{name: "a library that an executable reaches", ev: reached, want: keptOpen(inventoryv1alpha1.RuleLoadCheck, reachedByCurl)},
		{
			name: "a library that a file names",
			ev: func(ev *result.Manifest) {
				ev.Libraries[0].NameHits, ev.Libraries[0].NameHitCount = []string{loadPy}, 1
			},
			want: keptOpen(inventoryv1alpha1.RuleLoadCheck, namedInLoadPy),
		},
		{
			name: "LD_PRELOAD in the image configuration", ev: func(ev *result.Manifest) { ev.Preload.LDPreload = true },
			want: keptOpen(inventoryv1alpha1.RuleLoadCheck, preloads),
		},
		{
			name: "LD_AUDIT in the image configuration", ev: func(ev *result.Manifest) { ev.Preload.LDAudit = true },
			want: keptOpen(inventoryv1alpha1.RuleLoadCheck, preloads),
		},
		{
			name: "a non-empty /etc/ld.so.preload", ev: func(ev *result.Manifest) { ev.Preload.EtcLdSoPreload = true },
			want: keptOpen(inventoryv1alpha1.RuleLoadCheck, preloads),
		},

		// The load check doesn't apply to these packages, and no rule settles them.
		{name: "a package that owns an executable", ev: func(ev *result.Manifest) { ev.Packages[0].OtherELFFiles = 1 }, want: undecided},
		{
			name: "a package that owns no library, such as a language package",
			ev: func(ev *result.Manifest) {
				ev.Packages[0] = result.PackageFacts{ID: pkgID}
				ev.Libraries = nil
			},
			want: undecided,
		},

		// The evidence doesn't know the package.
		{name: "a package ID that the evidence doesn't have", match: func(m *matchapi.Match) { m.PackageID = pkgGhost }, want: undecided},
		{name: "a package that the SBOM names and the facts don't", ev: func(ev *result.Manifest) { ev.Packages = nil }, want: undecided},
		{
			name: "a package that has facts and no entry in the SBOM",
			ev:   func(ev *result.Manifest) { goneFromImage(ev); ev.SBOM = sbomOf() }, want: undecided,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ev, m := libraryManifest(), matchOf(pkgID)
			if tc.ev != nil {
				tc.ev(&ev)
			}
			if tc.match != nil {
				tc.match(&m)
			}
			require.Equal(t, tc.want, settledOf(evaluate(t, ev, m)))
		})
	}
}

func TestTheGuardReadsTheMinimumFromTheSettings(t *testing.T) {
	// 89 of 100 ELF files are owned.
	ev := libraryManifest()
	ev.ELF = result.ELFSummary{Total: 100, Owned: 89}
	m := []matchapi.Match{matchOf(pkgID)}

	tests := []struct {
		name string
		min  int32
		want settled
	}{
		{"above the completeness", 90, keptOpen(inventoryv1alpha1.RuleCompletenessGuard, "completeness 89% is below 90%")},
		{"as high as the completeness", 89, unreached},
		{"a minimum of 100 asks for everything", 100, keptOpen(inventoryv1alpha1.RuleCompletenessGuard, "completeness 89% is below 100%")},
		{"a minimum of 0 is a minimum", 0, unreached},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			findings := evaluateAll(t, ev, m, rules.Settings{MinCompletenessPercent: tc.min})
			require.Len(t, findings, 1)
			require.Equal(t, tc.want, settledOf(findings[0]))
		})
	}
}

func TestTheGuardHoldsBackWhenTheCountsCantBeTrue(t *testing.T) {
	// The completeness of an image with no ELF files is 100: there is nothing to account for. Counts
	// that can't be true count as 0, so that they hold a verdict back and never let one through.
	tests := []struct {
		name string
		elf  result.ELFSummary
		want settled
	}{
		{"no ELF files", result.ELFSummary{}, unreached},
		{"more files owned than found", result.ELFSummary{Total: 5, Owned: 6}, keptOpen(inventoryv1alpha1.RuleCompletenessGuard, "completeness 0% is below 90%")},
		{"a negative count", result.ELFSummary{Total: 5, Owned: -1}, keptOpen(inventoryv1alpha1.RuleCompletenessGuard, "completeness 0% is below 90%")},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ev := libraryManifest()
			ev.ELF = tc.elf
			require.Equal(t, tc.want, settledOf(evaluate(t, ev, matchOf(pkgID))))
		})
	}
}

func TestEvidenceThatDoesNotAddUpNeverGivesTheReasonThatNothingReachesTheLibraries(t *testing.T) {
	// A library that the evidence lacks, or a count that can't be true, could be the one that something
	// reaches. The reason then says that the evidence is incomplete, and never that nothing reaches or names
	// the libraries.
	tests := []struct {
		name string
		ev   func(*result.Manifest)
	}{
		{"fewer library entries than the package owns", func(ev *result.Manifest) { ev.Packages[0].SharedLibraries = 2 }},
		{"more library entries than the package owns", func(ev *result.Manifest) {
			ev.Libraries = append(ev.Libraries, result.Library{Path: "/usr/lib/libbar.so.1", Soname: "libbar.so.1", PackageID: pkgID})
		}},
		{"no library entries", func(ev *result.Manifest) { ev.Libraries = nil }},
		{"entries of another package only", func(ev *result.Manifest) { ev.Libraries[0].PackageID = pkg2 }},
		{"an entry that no package owns", func(ev *result.Manifest) { ev.Libraries[0].PackageID = "" }},
		{"a negative count of reaching files", func(ev *result.Manifest) { ev.Libraries[0].ReachedCount = -1 }},
		{"a negative count of naming files", func(ev *result.Manifest) { ev.Libraries[0].NameHitCount = -1 }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ev := libraryManifest()
			tc.ev(&ev)
			require.Equal(t, keptOpen(inventoryv1alpha1.RuleLoadCheck, incompleteLibs), settledOf(evaluate(t, ev, matchOf(pkgID))))
		})
	}

	t.Run("paths without a count are still use", func(t *testing.T) {
		ev := libraryManifest()
		ev.Libraries[0].ReachedBy = []string{curlPath}
		require.Equal(t, keptOpen(inventoryv1alpha1.RuleLoadCheck, reachedByCurl), settledOf(evaluate(t, ev, matchOf(pkgID))))

		ev = libraryManifest()
		ev.Libraries[0].NameHits = []string{loadPy}
		require.Equal(t, keptOpen(inventoryv1alpha1.RuleLoadCheck, namedInLoadPy), settledOf(evaluate(t, ev, matchOf(pkgID))))
	})
}

func TestTheLoadCheckLooksAtEveryLibraryOfThePackage(t *testing.T) {
	twoLibraries := func() result.Manifest {
		ev := libraryManifest()
		ev.Packages[0].SharedLibraries = 2
		ev.Libraries = []result.Library{
			{Path: libAPath, Soname: libASoname, PackageID: pkgID},
			{Path: libBPath, Soname: libBSoname, PackageID: pkgID},
		}
		return ev
	}

	require.Equal(t, unreached, settledOf(evaluate(t, twoLibraries(), matchOf(pkgID))))

	for _, reached := range []int{0, 1} {
		ev := twoLibraries()
		ev.Libraries[reached].ReachedBy, ev.Libraries[reached].ReachedCount = []string{curlPath}, 1
		require.Equal(t, keptOpen(inventoryv1alpha1.RuleLoadCheck, reachedByCurl), settledOf(evaluate(t, ev, matchOf(pkgID))), "library %d", reached)

		ev = twoLibraries()
		ev.Libraries[reached].NameHits, ev.Libraries[reached].NameHitCount = []string{loadPy}, 1
		require.Equal(t, keptOpen(inventoryv1alpha1.RuleLoadCheck, namedInLoadPy), settledOf(evaluate(t, ev, matchOf(pkgID))), "library %d", reached)
	}
}

func TestEachPackageGetsTheReasonOfItsOwnLibraries(t *testing.T) {
	// One library file that two packages own has one entry for each. What reaches it from outside one
	// package says nothing about the other: a finding covers one package only.
	ev := result.Manifest{
		SBOM: sbomOf(
			artifact{ID: pkgA, Name: "liba", Version: "1", Type: typeAPK},
			artifact{ID: pkgB, Name: "libb", Version: "1", Type: typeAPK},
		),
		Packages: []result.PackageFacts{
			{ID: pkgA, FilesListed: 1, FilesPresent: 1, SharedLibraries: 1},
			{ID: pkgB, FilesListed: 1, FilesPresent: 1, SharedLibraries: 1},
		},
		ELF: result.ELFSummary{Total: 1, Owned: 1},
		Libraries: []result.Library{
			{Path: libPath, Soname: libSoname, PackageID: pkgA},
			{Path: libPath, Soname: libSoname, PackageID: pkgB, ReachedBy: []string{"/opt/b/tool"}, ReachedCount: 1},
		},
	}
	findings := evaluateAll(t, ev, []matchapi.Match{matchOf(pkgB), matchOf(pkgA)}, defaultSettings)
	require.Len(t, findings, 2)
	require.Equal(t, pkgA, findings[0].Package.ID)
	require.Equal(t, unreached, settledOf(findings[0]))
	require.Equal(t, pkgB, findings[1].Package.ID)
	require.Equal(t, keptOpen(inventoryv1alpha1.RuleLoadCheck, "reached by /opt/b/tool"), settledOf(findings[1]))
}

// ---- the reasons ----

func TestTheReasonNamesTheFirstPathInAFixedOrder(t *testing.T) {
	// Libraries come in the order of their paths, and a library's paths in the order it lists them,
	// whatever order the manifest holds the libraries in.
	twoLibraries := func(a, b result.Library) result.Manifest {
		a.Path, a.Soname, a.PackageID = libAPath, libASoname, pkgID
		b.Path, b.Soname, b.PackageID = libBPath, libBSoname, pkgID
		ev := libraryManifest()
		ev.Packages[0].SharedLibraries = 2
		ev.Libraries = []result.Library{b, a}
		return ev
	}
	paths := func(p ...string) []string { return p }

	tests := []struct {
		name string
		ev   result.Manifest
		want string
	}{
		{
			"the first reaching path of the first library that is reached",
			twoLibraries(
				result.Library{ReachedBy: paths("/usr/bin/z", "/usr/bin/a"), ReachedCount: 2},
				result.Library{ReachedBy: paths("/usr/bin/b"), ReachedCount: 1},
			),
			"reached by /usr/bin/z",
		},
		{
			"a library further on, when the first isn't reached",
			twoLibraries(result.Library{}, result.Library{ReachedBy: paths("/usr/bin/b"), ReachedCount: 1}),
			"reached by /usr/bin/b",
		},
		{
			"reach wins over a name hit, even of an earlier library",
			twoLibraries(
				result.Library{NameHits: paths("/app/a.py"), NameHitCount: 1},
				result.Library{ReachedBy: paths("/usr/bin/b"), ReachedCount: 1},
			),
			"reached by /usr/bin/b",
		},
		{
			"the first name hit of the first library that is named",
			twoLibraries(
				result.Library{NameHits: paths("/app/z.py", "/app/a.py"), NameHitCount: 2},
				result.Library{NameHits: paths("/app/b.py"), NameHitCount: 1},
			),
			"named in /app/z.py",
		},
		{
			"a name hit wins over preload",
			func() result.Manifest {
				ev := twoLibraries(result.Library{NameHits: paths(loadPy), NameHitCount: 1}, result.Library{})
				ev.Preload = result.Preload{LDPreload: true, LDAudit: true, EtcLdSoPreload: true}
				return ev
			}(),
			namedInLoadPy,
		},
		{
			"reach wins over preload",
			func() result.Manifest {
				ev := twoLibraries(result.Library{ReachedBy: paths(curlPath), ReachedCount: 1}, result.Library{})
				ev.Preload.LDPreload = true
				return ev
			}(),
			reachedByCurl,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, keptOpen(inventoryv1alpha1.RuleLoadCheck, tc.want), settledOf(evaluate(t, tc.ev, matchOf(pkgID))))
		})
	}
}

func TestTheReasonCountsWhenThereAreNoPaths(t *testing.T) {
	// The scanner always lists the first paths of a count that isn't zero. Should a count come with none,
	// the finding stays open and the reason gives the count: nothing panics, and nothing settles.
	tests := []struct {
		name string
		lib  result.Library
		want string
	}{
		{"reaching files", result.Library{ReachedCount: 3}, "reached by 3 ELF files"},
		{"naming files", result.Library{NameHitCount: 2}, "named in 2 files"},
		{"a count of reach wins over a name hit with a path", result.Library{ReachedCount: 3, NameHits: []string{loadPy}, NameHitCount: 1}, "reached by 3 ELF files"},
		{"a name hit with a path is named by its path, though the count is larger", result.Library{NameHits: []string{loadPy}, NameHitCount: 4}, namedInLoadPy},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ev := libraryManifest()
			tc.lib.Path, tc.lib.Soname, tc.lib.PackageID = libPath, libSoname, pkgID
			ev.Libraries[0] = tc.lib
			require.Equal(t, keptOpen(inventoryv1alpha1.RuleLoadCheck, tc.want), settledOf(evaluate(t, ev, matchOf(pkgID))))
		})
	}

	t.Run("a path is named in preference to a count of another library", func(t *testing.T) {
		ev := libraryManifest()
		ev.Packages[0].SharedLibraries = 2
		ev.Libraries = []result.Library{
			{Path: libAPath, Soname: libASoname, PackageID: pkgID, ReachedCount: 7},
			{Path: libBPath, Soname: libBSoname, PackageID: pkgID, ReachedBy: []string{curlPath}, ReachedCount: 1},
		}
		require.Equal(t, keptOpen(inventoryv1alpha1.RuleLoadCheck, reachedByCurl), settledOf(evaluate(t, ev, matchOf(pkgID))))
	})
}

func TestEveryReasonIsCutToTheSchemaOnACharacterBoundary(t *testing.T) {
	// "reached by " takes 11 bytes, and the path's characters follow at once. With two-byte
	// characters the 256th byte is inside one, and three-byte and four-byte characters put it inside
	// one at other offsets.
	tests := []struct {
		name      string
		character string
		wantBytes int
	}{
		{"one-byte characters", "a", 256},
		{"two-byte characters", "é", 255},
		{"three-byte characters", "€", 254},
		{"four-byte characters", "😀", 255},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			path := strings.Repeat(tc.character, 300)
			ev := libraryManifest()
			ev.Libraries[0].ReachedBy, ev.Libraries[0].ReachedCount = []string{path}, 1

			reason := ptr.Deref(evaluate(t, ev, matchOf(pkgID)).Reason, "")
			require.True(t, utf8.ValidString(reason))
			require.Len(t, reason, tc.wantBytes)
			require.True(t, strings.HasPrefix("reached by "+path, reason), "the reason is the start of the text, not a rewrite of it")
		})
	}
}

// ---- the package ----

func TestThePackageComesFromTheSBOMEntry(t *testing.T) {
	m := matchOf(pkgID)
	m.PackageName, m.PackageVersion, m.PackageType = fromTheMatch, "9.9", typeDeb
	f := evaluate(t, libraryManifest(), m)
	require.Equal(t, inventoryv1alpha1.PackageReference{ID: pkgID, Name: libfooName, Version: ptr.To(libfooVersion), Type: typeAPK}, f.Package)

	t.Run("a package without a version has none", func(t *testing.T) {
		ev := libraryManifest()
		ev.SBOM = sbomOf(artifact{ID: pkgID, Name: libfooName, Type: typeAPK})
		m := matchOf(pkgID)
		m.PackageVersion = "1.0"
		require.Equal(t, inventoryv1alpha1.PackageReference{ID: pkgID, Name: libfooName, Type: typeAPK}, evaluate(t, ev, m).Package)
	})
}

func TestAPackageTheEvidenceLacksComesFromTheMatch(t *testing.T) {
	m := matchOf(pkgGhost)
	m.PackageName, m.PackageVersion, m.PackageType = "libghost", "0.1", typeDeb
	f := evaluate(t, libraryManifest(), m)
	require.Equal(t, inventoryv1alpha1.PackageReference{ID: pkgGhost, Name: "libghost", Version: ptr.To("0.1"), Type: typeDeb}, f.Package)
	require.Equal(t, undecided, settledOf(f))

	m.PackageVersion = ""
	require.Nil(t, evaluate(t, libraryManifest(), m).Package.Version)
}

func TestAPackageTheEvidenceLacksIsStillTrackedWhenItIsKnownExploited(t *testing.T) {
	// The known exploited rule needs no evidence about the package, and it never says "not affected".
	m := matchOf(pkgGhost)
	m.KnownExploited = true
	require.Equal(t, exploited, settledOf(evaluate(t, libraryManifest(), m)))
}

func TestAnSBOMThatCantBeUsedSettlesNothing(t *testing.T) {
	// Evaluate has no error to return, so an SBOM that it can't read makes every finding take its
	// package from the match, and no rule settles one, whatever the facts say.
	tests := []struct {
		name string
		sbom json.RawMessage
	}{
		{"none", nil},
		{"not JSON", json.RawMessage("not JSON")},
		{"an array", json.RawMessage("[]")},
		{"a string", json.RawMessage(`"artifacts"`)},
		{"artifacts that aren't a list", json.RawMessage(`{"artifacts": "none"}`)},
		{"a package of the wrong shape", json.RawMessage(`{"artifacts": [{"id": "pkg-1", "name": 5}]}`)},
		{"null", json.RawMessage("null")},
		{"no packages", json.RawMessage("{}")},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ev := libraryManifest()
			ev.SBOM = tc.sbom
			ev.Packages[0].FilesListed, ev.Packages[0].FilesPresent = 3, 0 // would be removed

			m := matchOf(pkgID)
			m.PackageName, m.PackageVersion, m.PackageType = fromTheMatch, "7.7", typeDeb
			f := evaluate(t, ev, m)
			require.Equal(t, undecided, settledOf(f))
			require.Equal(t, inventoryv1alpha1.PackageReference{ID: pkgID, Name: fromTheMatch, Version: ptr.To("7.7"), Type: typeDeb}, f.Package)
		})
	}

	t.Run("the rules that need no package evidence still apply", func(t *testing.T) {
		ev := libraryManifest()
		ev.SBOM = json.RawMessage("not JSON")
		m := matchOf(pkgID)
		m.KnownExploited = true
		require.Equal(t, exploited, settledOf(evaluate(t, ev, m)))

		ev.ELF.Owned = 8
		require.Equal(t, keptOpen(inventoryv1alpha1.RuleCompletenessGuard, guardAt80), settledOf(evaluate(t, ev, matchOf(pkgID))))
	})
}

func TestEvidenceThatSaysTwoThingsOfOnePackageSettlesNothing(t *testing.T) {
	t.Run("two entries of one ID in the SBOM", func(t *testing.T) {
		ev := libraryManifest()
		ev.SBOM = sbomOf(
			artifact{ID: pkgID, Name: libfooName, Version: libfooVersion, Type: typeAPK},
			artifact{ID: pkgID, Name: "libother", Version: "9", Type: typeAPK},
		)
		ev.Packages[0].FilesListed, ev.Packages[0].FilesPresent = 3, 0 // would be removed
		m := matchOf(pkgID)
		m.PackageName = fromTheMatch
		f := evaluate(t, ev, m)
		require.Equal(t, undecided, settledOf(f))
		require.Equal(t, fromTheMatch, f.Package.Name, "the package then comes from the match")
	})

	t.Run("two sets of facts of one ID", func(t *testing.T) {
		ev := libraryManifest()
		ev.Packages = []result.PackageFacts{
			{ID: pkgID, FilesListed: 3, FilesPresent: 0},
			{ID: pkgID, FilesListed: 3, FilesPresent: 3, SharedLibraries: 1},
		}
		require.Equal(t, undecided, settledOf(evaluate(t, ev, matchOf(pkgID))))
	})

	t.Run("an entry without an ID names nobody", func(t *testing.T) {
		ev := libraryManifest()
		ev.SBOM = sbomOf(artifact{Name: libfooName, Type: typeAPK})
		ev.Packages = []result.PackageFacts{{FilesListed: 3, FilesPresent: 0}}
		require.Equal(t, undecided, settledOf(evaluate(t, ev, matchOf(""))))
	})
}

// ---- what a finding carries ----

func TestSeverityFixStateAndFixedVersionsAreCarriedThrough(t *testing.T) {
	const earlier, later = "1.2.3-r1", "1.2.4-r0"
	m := matchOf(pkgID)
	m.Severity, m.FixState, m.FixedVersions = grypeCritical, grypeFixed, []string{later, earlier}
	f := evaluate(t, libraryManifest(), m)
	require.Equal(t, someCVE, f.VulnerabilityID)
	require.Equal(t, inventoryv1alpha1.SeverityCritical, f.Severity)
	require.Equal(t, inventoryv1alpha1.FixStateFixed, f.FixState)
	require.Equal(t, []string{earlier, later}, f.FixedVersions, "sorted, as a merged list is")
	require.Equal(t, []string{later, earlier}, m.FixedVersions, "the match keeps its own order")

	require.Nil(t, evaluate(t, libraryManifest(), matchOf(pkgID)).FixedVersions)
}

func TestSeverityMapsOneToOneWithoutRegardToCase(t *testing.T) {
	tests := map[string]inventoryv1alpha1.Severity{
		"Critical": inventoryv1alpha1.SeverityCritical, "High": inventoryv1alpha1.SeverityHigh,
		"Medium": inventoryv1alpha1.SeverityMedium, "Low": inventoryv1alpha1.SeverityLow,
		"Negligible": inventoryv1alpha1.SeverityNegligible, "Unknown": inventoryv1alpha1.SeverityUnknown,
		"critical": inventoryv1alpha1.SeverityCritical, "HIGH": inventoryv1alpha1.SeverityHigh,
		"mEdIuM": inventoryv1alpha1.SeverityMedium, "negligible": inventoryv1alpha1.SeverityNegligible,
		// Anything else is unknown.
		"": inventoryv1alpha1.SeverityUnknown, "Moderate": inventoryv1alpha1.SeverityUnknown,
		"Critical ": inventoryv1alpha1.SeverityUnknown,
	}
	for grype, want := range tests {
		m := matchOf(pkgID)
		m.Severity = grype
		require.Equal(t, want, evaluate(t, libraryManifest(), m).Severity, "severity %q", grype)
	}
}

func TestFixStateMapsAsGrypeWritesIt(t *testing.T) {
	tests := map[string]inventoryv1alpha1.FixState{
		"fixed":     inventoryv1alpha1.FixStateFixed,
		"not-fixed": inventoryv1alpha1.FixStateNotFixed,
		"wont-fix":  inventoryv1alpha1.FixStateWontFix,
		"unknown":   inventoryv1alpha1.FixStateUnknown,
		// An empty state is a real value: Grype writes it for an NVD match that names no fix. Anything
		// else that it might write is unknown too.
		"":        inventoryv1alpha1.FixStateUnknown,
		"pending": inventoryv1alpha1.FixStateUnknown,
	}
	for grype, want := range tests {
		m := matchOf(pkgID)
		m.FixState = grype
		require.Equal(t, want, evaluate(t, libraryManifest(), m).FixState, "fix state %q", grype)
	}
}

// ---- schema limits ----

func TestEvaluateCutsEveryValueToTheSchema(t *testing.T) {
	long := func(s string, n int) string { return strings.Repeat(s, n) }

	t.Run("a package from the match", func(t *testing.T) {
		m := matchapi.Match{
			VulnerabilityID: long("c", 100), PackageID: long("i", 100), Severity: grypeHigh, FixState: grypeFixed,
			PackageName: long("n", 300), PackageVersion: long("v", 200), PackageType: long("t", 50),
		}
		f := evaluate(t, libraryManifest(), m)
		require.Equal(t, long("c", 64), f.VulnerabilityID)
		require.Equal(t, inventoryv1alpha1.PackageReference{
			ID: long("i", 64), Name: long("n", 253), Version: ptr.To(long("v", 128)), Type: long("t", 32),
		}, f.Package)
	})

	t.Run("a package from the SBOM", func(t *testing.T) {
		ev := libraryManifest()
		ev.SBOM = sbomOf(artifact{ID: pkgID, Name: long("n", 300), Version: long("v", 200), Type: long("t", 50)})
		f := evaluate(t, ev, matchOf(pkgID))
		require.Equal(t, inventoryv1alpha1.PackageReference{
			ID: pkgID, Name: long("n", 253), Version: ptr.To(long("v", 128)), Type: long("t", 32),
		}, f.Package)
	})

	t.Run("the schema counts characters, not bytes", func(t *testing.T) {
		m := matchOf(pkgGhost)
		m.PackageName = long("é", 300)
		f := evaluate(t, libraryManifest(), m)
		require.Equal(t, long("é", 253), f.Package.Name)

		// 253 two-byte characters are 506 bytes, and within the limit: they are not cut.
		m.PackageName = long("é", 253)
		require.Equal(t, long("é", 253), evaluate(t, libraryManifest(), m).Package.Name)
	})

	t.Run("the first eight of the sorted fixed versions, each cut", func(t *testing.T) {
		m := matchOf(pkgID)
		m.FixState = grypeFixed
		for i := 9; i >= 0; i-- {
			m.FixedVersions = append(m.FixedVersions, fmt.Sprintf("1.0.%d", i))
		}
		m.FixedVersions = append(m.FixedVersions, long("9", 200))
		f := evaluate(t, libraryManifest(), m)
		require.Equal(t, []string{"1.0.0", "1.0.1", "1.0.2", "1.0.3", "1.0.4", "1.0.5", "1.0.6", "1.0.7"}, f.FixedVersions)

		m.FixedVersions = []string{long("9", 200)}
		f = evaluate(t, libraryManifest(), m)
		require.Equal(t, []string{long("9", 128)}, f.FixedVersions)
	})
}

// ---- one finding for each vulnerability and package ----

func TestMatchesOfOneVulnerabilityAndPackageMakeOneFinding(t *testing.T) {
	const v11, v12, v13 = "1.1", "1.2", "1.3"
	a := matchOf(pkgID)
	a.Severity, a.FixState, a.FixedVersions = grypeLow, "", []string{v12, v11}
	b := matchOf(pkgID)
	b.Severity, b.FixState, b.FixedVersions = grypeCritical, grypeWontFix, []string{v13, v11}
	c := matchOf(pkgID)
	c.Severity, c.FixState, c.KnownExploited = grypeUnknownSeverity, grypeNotFixed, true

	findings := evaluateAll(t, libraryManifest(), []matchapi.Match{a, b, c}, defaultSettings)
	require.Len(t, findings, 1)
	f := findings[0]
	require.Equal(t, exploited, settledOf(f), "known exploited if any match says so")
	require.Equal(t, inventoryv1alpha1.SeverityCritical, f.Severity, "the most severe")
	require.Equal(t, inventoryv1alpha1.FixStateWontFix, f.FixState)
	require.Equal(t, []string{v11, v12, v13}, f.FixedVersions, "the sorted union")
}

func TestMergedSeverityIsTheMostSevere(t *testing.T) {
	tests := []struct {
		severities []string
		want       inventoryv1alpha1.Severity
	}{
		{[]string{grypeLow, grypeHigh}, inventoryv1alpha1.SeverityHigh},
		{[]string{grypeHigh, grypeCritical, grypeLow}, inventoryv1alpha1.SeverityCritical},
		{[]string{grypeNegligible, grypeMedium}, inventoryv1alpha1.SeverityMedium},
		{[]string{grypeUnknownSeverity, grypeLow}, inventoryv1alpha1.SeverityLow},
		{[]string{"", grypeNegligible}, inventoryv1alpha1.SeverityNegligible},
		{[]string{grypeUnknownSeverity, ""}, inventoryv1alpha1.SeverityUnknown},
	}
	for _, tc := range tests {
		matches := make([]matchapi.Match, 0, len(tc.severities))
		for _, s := range tc.severities {
			m := matchOf(pkgID)
			m.Severity = s
			matches = append(matches, m)
		}
		findings := evaluateAll(t, libraryManifest(), matches, defaultSettings)
		require.Len(t, findings, 1)
		require.Equal(t, tc.want, findings[0].Severity, "severities %q", tc.severities)
	}
}

func TestMergedFixStateIsFixedThenWontFixThenNotFixedThenUnknown(t *testing.T) {
	tests := []struct {
		states []string
		want   inventoryv1alpha1.FixState
	}{
		{[]string{grypeWontFix, grypeFixed, grypeNotFixed}, inventoryv1alpha1.FixStateFixed},
		{[]string{grypeNotFixed, grypeWontFix, grypeUnknownState}, inventoryv1alpha1.FixStateWontFix},
		{[]string{grypeUnknownState, grypeNotFixed}, inventoryv1alpha1.FixStateNotFixed},
		{[]string{"", grypeNotFixed}, inventoryv1alpha1.FixStateNotFixed},
		{[]string{"", grypeUnknownState, "pending"}, inventoryv1alpha1.FixStateUnknown},
	}
	for _, tc := range tests {
		matches := make([]matchapi.Match, 0, len(tc.states))
		for _, s := range tc.states {
			m := matchOf(pkgID)
			m.FixState = s
			matches = append(matches, m)
		}
		findings := evaluateAll(t, libraryManifest(), matches, defaultSettings)
		require.Len(t, findings, 1)
		require.Equal(t, tc.want, findings[0].FixState, "states %q", tc.states)
	}
}

func TestOtherVulnerabilitiesAndPackagesAreOtherFindings(t *testing.T) {
	ev := libraryManifest()
	ev.SBOM = sbomOf(
		artifact{ID: pkgID, Name: libfooName, Version: "1", Type: typeAPK},
		artifact{ID: pkg2, Name: "libbar", Version: "1", Type: typeAPK},
	)
	other := matchOf(pkgID)
	other.VulnerabilityID = "CVE-2026-0002"
	otherPackage := matchOf(pkg2)

	findings := evaluateAll(t, ev, []matchapi.Match{matchOf(pkgID), other, otherPackage}, defaultSettings)
	require.Len(t, findings, 3)
	require.Equal(t, [][2]string{{someCVE, pkgID}, {someCVE, pkg2}, {"CVE-2026-0002", pkgID}}, idsOf(findings))
}

func idsOf(findings []inventoryv1alpha1.Finding) [][2]string {
	ids := make([][2]string, 0, len(findings))
	for _, f := range findings {
		ids = append(ids, [2]string{f.VulnerabilityID, f.Package.ID})
	}
	return ids
}

// ---- determinism ----

// The packages of mixedEvidence.
const (
	unusedPkg     = "lib-unused"
	reachedPkg    = "lib-reached"
	executablePkg = "has-executable"
	languagePkg   = "language"
	gonePkg       = "gone"
)

// mixedEvidence is an image of five kinds of package, and mixedMatches the matches against it: some
// repeated, some that disagree with another about the same finding, and some for a package that the
// evidence lacks, whose matches disagree even about the package.
func mixedEvidence() result.Manifest {
	artifacts := []artifact{
		{ID: unusedPkg, Name: "libunused", Version: "1", Type: typeAPK},
		{ID: reachedPkg, Name: "libreached", Version: "2", Type: typeAPK},
		{ID: executablePkg, Name: "tool", Version: "3", Type: typeAPK},
		{ID: languagePkg, Name: "gopkg", Version: "4", Type: "go-module"},
		{ID: gonePkg, Name: "libgone", Version: "5", Type: typeAPK},
	}
	return result.Manifest{
		SBOM: sbomOf(artifacts...),
		Packages: []result.PackageFacts{
			{ID: unusedPkg, FilesListed: 2, FilesPresent: 2, SharedLibraries: 1},
			{ID: reachedPkg, FilesListed: 2, FilesPresent: 2, SharedLibraries: 1},
			{ID: executablePkg, FilesListed: 2, FilesPresent: 2, SharedLibraries: 1, OtherELFFiles: 1},
			{ID: languagePkg},
			{ID: gonePkg, FilesListed: 2},
		},
		ELF: result.ELFSummary{Total: 3, Owned: 3},
		Libraries: []result.Library{
			{Path: "/usr/lib/libreached.so.1", Soname: "libreached.so.1", PackageID: reachedPkg, ReachedBy: []string{curlPath}, ReachedCount: 1},
			{Path: "/usr/lib/libtool.so.1", Soname: "libtool.so.1", PackageID: executablePkg},
			{Path: "/usr/lib/libunused.so.1", Soname: "libunused.so.1", PackageID: unusedPkg},
		},
	}
}

func mixedMatches() []matchapi.Match {
	matches := make([]matchapi.Match, 0, 2*3*6)
	for _, pkg := range []string{unusedPkg, reachedPkg, executablePkg, languagePkg, gonePkg, "ghost"} {
		for i, severity := range []string{grypeLow, grypeHigh, grypeCritical} {
			m := matchOf(pkg)
			m.VulnerabilityID = fmt.Sprintf("CVE-2026-%04d", 100-i)
			m.Severity = severity
			m.FixState = []string{grypeFixed, grypeWontFix, ""}[i]
			m.FixedVersions = []string{fmt.Sprintf("%d.%d", i, 9-i), "0.1"}
			m.KnownExploited = pkg == executablePkg && i == 1
			matches = append(matches, m)
		}
	}
	// The same findings again, with other severities and fix states, and for the package that the
	// evidence lacks with another name, version and type.
	for _, m := range slices.Clone(matches) {
		m.Severity, m.FixState, m.FixedVersions = grypeMedium, grypeNotFixed, []string{"7.0"}
		if m.PackageID == "ghost" {
			m.PackageName, m.PackageVersion, m.PackageType = "libghost-alias", "", typeDeb
		}
		matches = append(matches, m)
	}
	return matches
}

func TestEvaluateGivesTheSameFindingsForAnyOrderAndForRepeatedMatches(t *testing.T) {
	ev, matches := mixedEvidence(), mixedMatches()
	want := evaluateAll(t, ev, matches, defaultSettings)
	require.Len(t, want, 6*3, "one finding for each vulnerability and package")
	require.True(t, slices.IsSortedFunc(want, func(a, b inventoryv1alpha1.Finding) int {
		return strings.Compare(a.VulnerabilityID+"/"+a.Package.ID, b.VulnerabilityID+"/"+b.Package.ID)
	}), "sorted by vulnerability ID, then package ID")

	rng := rand.New(rand.NewPCG(7, 11))
	for range 100 {
		shuffled := slices.Clone(matches)
		rng.Shuffle(len(shuffled), func(i, j int) { shuffled[i], shuffled[j] = shuffled[j], shuffled[i] })
		require.Equal(t, want, rules.Evaluate(ev, shuffled, defaultSettings))

		doubled := append(slices.Clone(shuffled), matches...)
		rng.Shuffle(len(doubled), func(i, j int) { doubled[i], doubled[j] = doubled[j], doubled[i] })
		require.Equal(t, want, rules.Evaluate(ev, doubled, defaultSettings))
	}
}

func TestEvaluateSortsByVulnerabilityThenPackage(t *testing.T) {
	ev := libraryManifest()
	ev.SBOM = sbomOf(
		artifact{ID: pkgA, Name: "liba", Version: "1", Type: typeAPK},
		artifact{ID: pkgB, Name: "libb", Version: "1", Type: typeAPK},
	)
	matches := make([]matchapi.Match, 0, 4)
	for _, ids := range [][2]string{{cve2, pkgB}, {cve1, pkgB}, {cve2, pkgA}, {cve1, pkgA}} {
		m := matchOf(ids[1])
		m.VulnerabilityID = ids[0]
		matches = append(matches, m)
	}
	require.Equal(t,
		[][2]string{{cve1, pkgA}, {cve1, pkgB}, {cve2, pkgA}, {cve2, pkgB}},
		idsOf(evaluateAll(t, ev, matches, defaultSettings)))
}

func TestEvaluateLeavesItsInputsAlone(t *testing.T) {
	ev, matches := mixedEvidence(), mixedMatches()
	slices.Reverse(ev.Libraries) // not in the order of their paths
	// A finding of one match alone, whose fixed versions are not in order: sorting them must not
	// reorder the match's own list.
	alone := matchOf(unusedPkg)
	alone.VulnerabilityID, alone.FixedVersions = "CVE-2026-0200", []string{"2.0", "1.0"}
	matches = append(matches, alone)
	evBefore, matchesBefore := mustMarshal(ev), mustMarshal(matches)

	findings := rules.Evaluate(ev, matches, defaultSettings)
	require.NotEmpty(t, findings)
	require.JSONEq(t, string(evBefore), string(mustMarshal(ev)))
	require.JSONEq(t, string(matchesBefore), string(mustMarshal(matches)))

	// The findings share nothing with the inputs, or with each other.
	for i := range findings {
		findings[i].FixedVersions = append(findings[i].FixedVersions[:0], "changed")
		findings[i].Conditions = append(findings[i].Conditions[:0], "changed")
	}
	require.JSONEq(t, string(matchesBefore), string(mustMarshal(matches)))
	require.Equal(t, unreached, settledOf(evaluate(t, libraryManifest(), matchOf(pkgID))), "no state is kept between calls")
}

func TestEvaluateOfNothing(t *testing.T) {
	require.Empty(t, rules.Evaluate(result.Manifest{}, nil, defaultSettings))
	require.Empty(t, rules.Evaluate(libraryManifest(), []matchapi.Match{}, defaultSettings))

	// An empty manifest is complete (it has no ELF files) and knows no package.
	f := evaluate(t, result.Manifest{}, matchOf(pkgID))
	require.Equal(t, undecided, settledOf(f))
}

// ---- the golden output of the matcher ----

// goldenMatches reads the matches in the matcher's fixture, which is what Grype printed for the
// fixture's SBOM, and converts them as the matcher does.
func goldenMatches(t *testing.T) []matchapi.Match {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "matcher", "testdata", "grype-output.json"))
	require.NoError(t, err)
	var output struct {
		Matches []struct {
			Vulnerability struct {
				ID             string            `json:"id"`
				Severity       string            `json:"severity"`
				KnownExploited []json.RawMessage `json:"knownExploited"`
				Fix            struct {
					State    string   `json:"state"`
					Versions []string `json:"versions"`
				} `json:"fix"`
			} `json:"vulnerability"`
			Artifact struct {
				ID      string `json:"id"`
				Name    string `json:"name"`
				Version string `json:"version"`
				Type    string `json:"type"`
			} `json:"artifact"`
		} `json:"matches"`
	}
	require.NoError(t, json.Unmarshal(raw, &output))
	matches := make([]matchapi.Match, 0, len(output.Matches))
	for _, m := range output.Matches {
		match := matchapi.Match{
			VulnerabilityID: m.Vulnerability.ID, PackageID: m.Artifact.ID, Severity: m.Vulnerability.Severity,
			FixState: m.Vulnerability.Fix.State, KnownExploited: len(m.Vulnerability.KnownExploited) > 0,
			PackageName: m.Artifact.Name, PackageVersion: m.Artifact.Version, PackageType: m.Artifact.Type,
		}
		if len(m.Vulnerability.Fix.Versions) > 0 {
			match.FixedVersions = m.Vulnerability.Fix.Versions
		}
		matches = append(matches, match)
	}
	return matches
}

func TestEvaluateOnTheMatchersGoldenOutput(t *testing.T) {
	const (
		brotliID = "d116986055f229b7"
		muslID   = "9153588f3b163ab9"
	)
	sbom, err := os.ReadFile(filepath.Join("..", "matcher", "testdata", "sbom.json"))
	require.NoError(t, err)
	matches := goldenMatches(t)
	require.Len(t, matches, 4)

	// One of the matches names no fix state at all: Grype writes an empty state for an NVD entry that
	// names no fix.
	var noState []matchapi.Match
	for _, m := range matches {
		if m.FixState == "" {
			noState = append(noState, m)
		}
	}
	require.Len(t, noState, 1, "the fixture must keep the match without a fix state that this test is about")
	require.Equal(t, "CVE-2026-40200", noState[0].VulnerabilityID)

	// What the scan would have found in that image: musl owns the C library that everything runs on,
	// and brotli-libs three libraries that nothing reaches.
	ev := result.Manifest{
		SBOM: sbom,
		Packages: []result.PackageFacts{
			{ID: brotliID, FilesListed: 6, FilesPresent: 6, SharedLibraries: 3},
			{ID: muslID, FilesListed: 4, FilesPresent: 4, SharedLibraries: 1},
		},
		ELF: result.ELFSummary{Total: 4, Owned: 4},
		Libraries: []result.Library{
			{Path: "/usr/lib/libbrotlicommon.so.1", Soname: "libbrotlicommon.so.1", PackageID: brotliID},
			{Path: "/usr/lib/libbrotlidec.so.1", Soname: "libbrotlidec.so.1", PackageID: brotliID},
			{Path: "/usr/lib/libbrotlienc.so.1", Soname: "libbrotlienc.so.1", PackageID: brotliID},
			{Path: "/lib/ld-musl-x86_64.so.1", Soname: "libc.musl-x86_64.so.1", PackageID: muslID, ReachedBy: []string{"/bin/busybox"}, ReachedCount: 1},
		},
	}
	musl := inventoryv1alpha1.PackageReference{ID: muslID, Name: "musl", Version: ptr.To("1.1.24-r8"), Type: typeAPK}
	brotli := inventoryv1alpha1.PackageReference{ID: brotliID, Name: "brotli-libs", Version: ptr.To("1.0.9-r1"), Type: typeAPK}
	reachedByBusybox := keptOpen(inventoryv1alpha1.RuleLoadCheck, "reached by /bin/busybox")

	findings := evaluateAll(t, ev, matches, defaultSettings)
	require.Len(t, findings, 4)
	type finding struct {
		VulnerabilityID string
		Package         inventoryv1alpha1.PackageReference
		Settled         settled
		Severity        inventoryv1alpha1.Severity
		FixState        inventoryv1alpha1.FixState
		FixedVersions   []string
	}
	got := make([]finding, 0, len(findings))
	for _, f := range findings {
		got = append(got, finding{f.VulnerabilityID, f.Package, settledOf(f), f.Severity, f.FixState, f.FixedVersions})
	}
	require.Equal(t, []finding{
		{"CVE-2020-28928", musl, reachedByBusybox, inventoryv1alpha1.SeverityMedium, inventoryv1alpha1.FixStateFixed, []string{"1.1.24-r10"}},
		{"CVE-2025-26519", musl, reachedByBusybox, inventoryv1alpha1.SeverityHigh, inventoryv1alpha1.FixStateUnknown, nil},
		// Known exploited, and known by Grype's own list.
		{"CVE-2026-111497", brotli, exploited, inventoryv1alpha1.SeverityCritical, inventoryv1alpha1.FixStateUnknown, nil},
		// No state at all is unknown, and the finding fits the schema, which names four states.
		{"CVE-2026-40200", musl, reachedByBusybox, inventoryv1alpha1.SeverityHigh, inventoryv1alpha1.FixStateUnknown, nil},
	}, got)
}

// ---- empty text, and text that can't be printed ----

// placeholder is what a finding says where the schema requires text and the match or the SBOM has
// none.
const placeholder = "unknown"

// dirty is what a crafted file name or package field can carry: an escape sequence, a newline, a
// right-to-left override, a NUL and a zero-width joiner. clean is what a finding shows of it: each
// character that Go doesn't call printable is one U+FFFD.
const (
	dirty = "a\x1b[31m\n\u202eb\x00\u200dc"
	clean = "a\ufffd[31m\ufffd\ufffdb\ufffd\ufffdc"
)

func TestEmptyStringsTheSchemaRequiresBecomeUnknown(t *testing.T) {
	t.Run("the vulnerability ID", func(t *testing.T) {
		m := matchOf(pkgID)
		m.VulnerabilityID = ""
		f := evaluate(t, libraryManifest(), m)
		require.Equal(t, placeholder, f.VulnerabilityID)
		require.Equal(t, unreached, settledOf(f), "the package still decides")
	})

	t.Run("the package ID", func(t *testing.T) {
		f := evaluate(t, libraryManifest(), matchOf(""))
		require.Equal(t, inventoryv1alpha1.PackageReference{
			ID: placeholder, Name: libfooName, Version: ptr.To(libfooVersion), Type: typeAPK,
		}, f.Package)
		require.Equal(t, undecided, settledOf(f), "no package has no ID")
	})

	t.Run("the name and the type of a package from the match", func(t *testing.T) {
		m := matchOf(pkgGhost)
		m.PackageName, m.PackageType = "", ""
		f := evaluate(t, libraryManifest(), m)
		require.Equal(t, inventoryv1alpha1.PackageReference{
			ID: pkgGhost, Name: placeholder, Version: ptr.To(libfooVersion), Type: placeholder,
		}, f.Package)
	})

	t.Run("the name and the type of a package from the SBOM", func(t *testing.T) {
		ev := libraryManifest()
		ev.SBOM = sbomOf(artifact{ID: pkgID, Version: libfooVersion})
		f := evaluate(t, ev, matchOf(pkgID))
		require.Equal(t, inventoryv1alpha1.PackageReference{
			ID: pkgID, Name: placeholder, Version: ptr.To(libfooVersion), Type: placeholder,
		}, f.Package)
		require.Equal(t, unreached, settledOf(f), "the package is still the one that the SBOM names")
	})

	t.Run("an absent version stays absent", func(t *testing.T) {
		m := matchOf(pkgGhost)
		m.PackageVersion = ""
		require.Nil(t, evaluate(t, libraryManifest(), m).Package.Version)
	})

	t.Run("all of them at once", func(t *testing.T) {
		f := evaluate(t, result.Manifest{}, matchapi.Match{Severity: grypeHigh})
		require.Equal(t, placeholder, f.VulnerabilityID)
		require.Equal(t, inventoryv1alpha1.PackageReference{ID: placeholder, Name: placeholder, Type: placeholder}, f.Package)
	})
}

func TestThePlaceholderIsNeverTakenForAPackageID(t *testing.T) {
	// The rules decide by the package ID that the match gives. A package that the evidence really calls
	// "unknown" has facts of its own, which a match without a package ID must not pick up.
	ev := libraryManifest()
	ev.SBOM = sbomOf(artifact{ID: placeholder, Name: libfooName, Version: libfooVersion, Type: typeAPK})
	ev.Packages = []result.PackageFacts{{ID: placeholder, FilesListed: 3, FilesPresent: 0}}

	require.Equal(t, removed, settledOf(evaluate(t, ev, matchOf(placeholder))))

	f := evaluate(t, ev, matchOf(""))
	require.Equal(t, placeholder, f.Package.ID)
	require.Equal(t, undecided, settledOf(f))
}

func TestCharactersThatAreNotPrintableAreReplacedInEveryString(t *testing.T) {
	t.Run("the vulnerability ID and the package ID", func(t *testing.T) {
		m := matchOf(pkgGhost)
		m.VulnerabilityID, m.PackageID = dirty, dirty
		f := evaluate(t, libraryManifest(), m)
		require.Equal(t, clean, f.VulnerabilityID)
		require.Equal(t, clean, f.Package.ID)
	})

	t.Run("a package from the match", func(t *testing.T) {
		m := matchOf(pkgGhost)
		m.PackageName, m.PackageVersion, m.PackageType = dirty, dirty, dirty
		f := evaluate(t, libraryManifest(), m)
		require.Equal(t, inventoryv1alpha1.PackageReference{ID: pkgGhost, Name: clean, Version: ptr.To(clean), Type: clean}, f.Package)
	})

	t.Run("a package from the SBOM", func(t *testing.T) {
		ev := libraryManifest()
		ev.SBOM = sbomOf(artifact{ID: pkgID, Name: dirty, Version: dirty, Type: dirty})
		f := evaluate(t, ev, matchOf(pkgID))
		require.Equal(t, inventoryv1alpha1.PackageReference{ID: pkgID, Name: clean, Version: ptr.To(clean), Type: clean}, f.Package)
		require.Equal(t, unreached, settledOf(f), "what the SBOM calls the package doesn't change what the rules decide")
	})

	t.Run("the reasons that name a path", func(t *testing.T) {
		ev := libraryManifest()
		ev.Libraries[0].ReachedBy, ev.Libraries[0].ReachedCount = []string{dirty}, 1
		require.Equal(t, keptOpen(inventoryv1alpha1.RuleLoadCheck, "reached by "+clean), settledOf(evaluate(t, ev, matchOf(pkgID))))

		ev = libraryManifest()
		ev.Libraries[0].NameHits, ev.Libraries[0].NameHitCount = []string{dirty}, 1
		require.Equal(t, keptOpen(inventoryv1alpha1.RuleLoadCheck, "named in "+clean), settledOf(evaluate(t, ev, matchOf(pkgID))))
	})

	t.Run("a path that clears the terminal and starts a line of its own", func(t *testing.T) {
		ev := libraryManifest()
		ev.Libraries[0].ReachedBy, ev.Libraries[0].ReachedCount = []string{"/opt/\x1b[2J\x1b[31mred\nreached by /usr/bin/safe"}, 1
		reason := ptr.Deref(evaluate(t, ev, matchOf(pkgID)).Reason, "")
		require.Equal(t, "reached by /opt/\ufffd[2J\ufffd[31mred\ufffdreached by /usr/bin/safe", reason)
		require.NotContains(t, reason, "\n", "the reason stays one line")
	})

	t.Run("a name with a right-to-left override", func(t *testing.T) {
		m := matchOf(pkgGhost)
		m.PackageName = "invoice\u202efdp.exe"
		require.Equal(t, "invoice\ufffdfdp.exe", evaluate(t, libraryManifest(), m).Package.Name)
	})

	t.Run("the fixed versions, sorted and made unique as they are shown", func(t *testing.T) {
		// As they come, "\x01x" sorts before "a", and "1.0\x01" and "1.0\x02" are two. As they are
		// shown, "\ufffdx" sorts after "a", and the other two are one.
		m := matchOf(pkgID)
		m.FixedVersions = []string{"a", "\x01x", "1.0\x01", "1.0\x02"}
		require.Equal(t, []string{"1.0\ufffd", "a", "\ufffdx"}, evaluate(t, libraryManifest(), m).FixedVersions)
	})

	t.Run("text that isn't valid UTF-8", func(t *testing.T) {
		m := matchOf(pkgGhost)
		m.PackageName = "lib\xffname"
		require.Equal(t, "lib\ufffdname", evaluate(t, libraryManifest(), m).Package.Name)
	})

	t.Run("the ASCII space is the one space that is printable", func(t *testing.T) {
		m := matchOf(pkgGhost)
		m.PackageName = "a b\u00a0c\u2003d\te" // a no-break space, an em space and a tab
		require.Equal(t, "a b\ufffdc\ufffdd\ufffde", evaluate(t, libraryManifest(), m).Package.Name)
	})
}

func TestThePackageIDInTheEvidenceIsMatchedAsItIsAndShownPrintable(t *testing.T) {
	// The evidence keys a package by its ID, whatever characters it holds. Replacing them is for what a
	// finding shows: the facts and the libraries are still found, and the rules still decide by them.
	ev := libraryManifest()
	ev.SBOM = sbomOf(artifact{ID: dirty, Name: libfooName, Version: libfooVersion, Type: typeAPK})
	ev.Packages[0].ID = dirty
	ev.Libraries[0].PackageID = dirty

	f := evaluate(t, ev, matchOf(dirty))
	require.Equal(t, unreached, settledOf(f))
	require.Equal(t, clean, f.Package.ID)
}

func TestPrintableTextIsNotChanged(t *testing.T) {
	// Letters of other scripts, symbols, emoji and the ASCII space are printable, and a finding keeps them.
	const text = "libé€ 中文 😀"
	m := matchOf(pkgGhost)
	m.PackageName = text
	require.Equal(t, text, evaluate(t, libraryManifest(), m).Package.Name)
}

func TestTheCutsHoldAfterTheReplacement(t *testing.T) {
	// An escape character is one byte, and its replacement three. A reason that is under 256 bytes as
	// it comes is over that once its characters are replaced, so the cut must follow the replacement.
	t.Run("the reason, in bytes", func(t *testing.T) {
		ev := libraryManifest()
		ev.Libraries[0].ReachedBy, ev.Libraries[0].ReachedCount = []string{strings.Repeat("\x1b", 200)}, 1 // 211 bytes with "reached by "
		reason := ptr.Deref(evaluate(t, ev, matchOf(pkgID)).Reason, "")
		require.Equal(t, "reached by "+strings.Repeat("\ufffd", 81), reason, "11 bytes and the 81 whole characters that fit in 256")
	})

	t.Run("a name, in characters", func(t *testing.T) {
		m := matchOf(pkgGhost)
		m.PackageName = strings.Repeat("\x1b", 300)
		require.Equal(t, strings.Repeat("\ufffd", 253), evaluate(t, libraryManifest(), m).Package.Name)
	})
}

// ---- Sheet ----

// sheetFinding is a finding with the fields that Sheet orders by.
func sheetFinding(outcome inventoryv1alpha1.Outcome, severity inventoryv1alpha1.Severity, vulnerabilityID, packageID string) inventoryv1alpha1.Finding {
	f := inventoryv1alpha1.Finding{
		VulnerabilityID: vulnerabilityID,
		Package:         inventoryv1alpha1.PackageReference{ID: packageID, Name: libfooName, Type: typeAPK},
		Outcome:         outcome,
		Severity:        severity,
		FixState:        inventoryv1alpha1.FixStateUnknown,
	}
	if outcome == suppressed {
		f.Justification = ptr.To(inventoryv1alpha1.JustificationComponentNotPresent)
	}
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

func counts(suppressedCount, trackedCount, needsAssessmentCount int32) inventoryv1alpha1.FindingCounts {
	return inventoryv1alpha1.FindingCounts{
		Suppressed:      ptr.To(suppressedCount),
		Tracked:         ptr.To(trackedCount),
		NeedsAssessment: ptr.To(needsAssessmentCount),
	}
}

func TestSheetOrdersByOutcomeThenSeverityThenVulnerabilityThenPackage(t *testing.T) {
	const (
		critical   = inventoryv1alpha1.SeverityCritical
		high       = inventoryv1alpha1.SeverityHigh
		medium     = inventoryv1alpha1.SeverityMedium
		low        = inventoryv1alpha1.SeverityLow
		negligible = inventoryv1alpha1.SeverityNegligible
		unknown    = inventoryv1alpha1.SeverityUnknown
	)
	// In the order that Sheet must give: tracked, then needing an assessment, then suppressed. The
	// vulnerability IDs run against the severities, so that severity is seen to come first.
	want := []inventoryv1alpha1.Finding{
		sheetFinding(tracked, critical, "CVE-9", pkgA),
		sheetFinding(tracked, low, "CVE-0", pkgA),
		sheetFinding(needsAssessment, critical, cve2, pkgA),
		sheetFinding(needsAssessment, critical, cve2, pkgB),
		sheetFinding(needsAssessment, critical, "CVE-6", pkgA),
		sheetFinding(needsAssessment, high, "CVE-5", pkgA),
		sheetFinding(needsAssessment, medium, "CVE-4", pkgA),
		sheetFinding(needsAssessment, low, "CVE-3", pkgA),
		sheetFinding(needsAssessment, negligible, cve2, pkgA),
		sheetFinding(needsAssessment, unknown, cve1, pkgA),
		sheetFinding(suppressed, critical, cve1, pkgA),
		sheetFinding(suppressed, unknown, "CVE-0", pkgA),
	}
	rng := rand.New(rand.NewPCG(3, 5))
	for range 50 {
		input := slices.Clone(want)
		rng.Shuffle(len(input), func(i, j int) { input[i], input[j] = input[j], input[i] })
		kept, omitted, got := rules.Sheet(input)
		require.Equal(t, want, kept)
		require.Zero(t, omitted)
		require.Equal(t, counts(2, 2, 8), got)
	}
}

func TestSheetKeepsWhatItDoesNotKnowAheadOfWhatItCanLeaveOut(t *testing.T) {
	// A later version of the API may add an outcome or a severity. Sheet puts such a value where a cut
	// leaves it out last: before the suppressed findings, and after the known severities.
	unknownOutcome := sheetFinding("Waived", inventoryv1alpha1.SeverityCritical, cve1, pkgA)
	unknownSeverity := sheetFinding(needsAssessment, "Severe", cve1, pkgA)
	want := []inventoryv1alpha1.Finding{
		sheetFinding(tracked, inventoryv1alpha1.SeverityLow, "CVE-9", pkgA),
		sheetFinding(needsAssessment, inventoryv1alpha1.SeverityUnknown, "CVE-9", pkgA),
		unknownSeverity,
		unknownOutcome,
		sheetFinding(suppressed, inventoryv1alpha1.SeverityCritical, "CVE-0", pkgA),
	}
	kept, omitted, got := rules.Sheet([]inventoryv1alpha1.Finding{want[4], want[3], want[2], want[1], want[0]})
	require.Equal(t, want, kept)
	require.Zero(t, omitted)
	require.Equal(t, counts(1, 1, 2), got, "an outcome that it doesn't know counts as none of the three")
}

func TestSheetKeeps2048FindingsAndLeavesOutSuppressedOnes(t *testing.T) {
	findings := make([]inventoryv1alpha1.Finding, 0, 2100)
	for i := range 1000 {
		findings = append(findings, sheetFinding(needsAssessment, inventoryv1alpha1.SeverityHigh, fmt.Sprintf("CVE-2026-%05d", i), pkgID))
	}
	for i := range 48 {
		findings = append(findings, sheetFinding(tracked, inventoryv1alpha1.SeverityHigh, fmt.Sprintf("CVE-2026-%05d", i), pkgID))
	}
	for i := range 1052 {
		findings = append(findings, sheetFinding(suppressed, inventoryv1alpha1.SeverityHigh, fmt.Sprintf("CVE-2026-%05d", i), pkgID))
	}
	require.Len(t, findings, 2100)
	rng := rand.New(rand.NewPCG(1, 2))
	rng.Shuffle(len(findings), func(i, j int) { findings[i], findings[j] = findings[j], findings[i] })

	kept, omitted, got := rules.Sheet(findings)
	require.Len(t, kept, 2048)
	require.Equal(t, int32(52), omitted)
	require.Equal(t, counts(1052, 48, 1000), got, "the counts cover the findings that the sheet leaves out")
	require.LessOrEqual(t, omitted, *got.Suppressed, "only suppressed findings are left out, so no more than there are")
	require.Less(t, sheetBytes(t, kept), 1<<20, "the count is what stops the sheet here, not the size")

	byOutcome := map[inventoryv1alpha1.Outcome]int{}
	for _, f := range kept {
		byOutcome[f.Outcome]++
	}
	require.Equal(t, map[inventoryv1alpha1.Outcome]int{needsAssessment: 1000, tracked: 48, suppressed: 1000}, byOutcome,
		"only suppressed findings are left out")
}

func TestSheetStopsBeforeAFindingThatWouldPushTheJSONPast1MiB(t *testing.T) {
	longReason := ptr.To(strings.Repeat("r", 256))
	longVersions := make([]string, 8)
	for i := range longVersions {
		longVersions[i] = strings.Repeat(string(rune('a'+i)), 128)
	}
	findings := make([]inventoryv1alpha1.Finding, 0, 1500)
	for i := range 1500 {
		f := sheetFinding(needsAssessment, inventoryv1alpha1.SeverityHigh, fmt.Sprintf("CVE-2026-%05d", i), pkgID)
		f.Reason, f.FixedVersions = longReason, longVersions
		findings = append(findings, f)
	}

	kept, omitted, got := rules.Sheet(findings)
	require.NotEmpty(t, kept)
	require.Less(t, len(kept), 2048, "the size stops the sheet before the count does")
	require.Equal(t, findings[:len(kept)], kept, "the findings that it keeps are the first ones")

	size := sheetBytes(t, kept)
	require.LessOrEqual(t, size, 1<<20)
	require.Greater(t, size+sheetBytes(t, findings[len(kept):len(kept)+1]), 1<<20, "the next finding would not have fit")
	require.Equal(t, int32(len(findings)-len(kept)), omitted)
	require.Equal(t, counts(0, 0, 1500), got)
}

func TestSheetCountsOneByteForEachFindingToSeparateIt(t *testing.T) {
	// Three findings whose JSON, with a byte to separate each, adds up to 1 MiB exactly fit. One byte
	// more and the last does not.
	sized := func(reasonBytes int) []inventoryv1alpha1.Finding {
		findings := make([]inventoryv1alpha1.Finding, 0, 3)
		for i := range 3 {
			f := sheetFinding(needsAssessment, inventoryv1alpha1.SeverityCritical, fmt.Sprintf("CVE-%d", i), pkgID)
			f.Reason = ptr.To(strings.Repeat("x", 400_000))
			findings = append(findings, f)
		}
		findings[2].Reason = ptr.To(strings.Repeat("x", reasonBytes))
		return findings
	}
	// The JSON grows by one byte for each byte of the reason, which is plain ASCII.
	exact := 1<<20 - sheetBytes(t, sized(0))
	require.Equal(t, 1<<20, sheetBytes(t, sized(exact)))

	kept, omitted, _ := rules.Sheet(sized(exact))
	require.Len(t, kept, 3)
	require.Zero(t, omitted)

	kept, omitted, got := rules.Sheet(sized(exact + 1))
	require.Len(t, kept, 2)
	require.Equal(t, int32(1), omitted)
	require.Equal(t, counts(0, 0, 3), got)
}

func TestSheetNeverSkipsOverAFindingThatDoesNotFit(t *testing.T) {
	// Findings that a sheet leaves out are the last ones in its order, so that what comes first is
	// never dropped for something that comes after it.
	findings := make([]inventoryv1alpha1.Finding, 0, 5)
	for i := range 5 {
		findings = append(findings, sheetFinding(needsAssessment, inventoryv1alpha1.SeverityCritical, fmt.Sprintf("CVE-%d", i), pkgID))
	}
	findings[2].Reason = ptr.To(strings.Repeat("x", 2<<20))

	kept, omitted, got := rules.Sheet(findings)
	require.Equal(t, findings[:2], kept)
	require.Equal(t, int32(3), omitted, "the two small findings after the large one are left out with it")
	require.Equal(t, counts(0, 0, 5), got)
}

func TestSheetOfNothing(t *testing.T) {
	kept, omitted, got := rules.Sheet(nil)
	require.Empty(t, kept)
	require.Zero(t, omitted)
	require.Equal(t, counts(0, 0, 0), got, "the counts are required, so zeros are set")
}

func TestSheetLeavesItsInputAlone(t *testing.T) {
	findings := []inventoryv1alpha1.Finding{
		sheetFinding(suppressed, inventoryv1alpha1.SeverityLow, cve2, pkgID),
		sheetFinding(needsAssessment, inventoryv1alpha1.SeverityHigh, cve1, pkgID),
	}
	before := mustMarshal(findings)
	kept, _, _ := rules.Sheet(findings)
	require.JSONEq(t, string(before), string(mustMarshal(findings)), "the input keeps its order")

	// What it returns is its own too: appending to it doesn't write into the input's array.
	_ = append(kept, sheetFinding(tracked, inventoryv1alpha1.SeverityLow, "CVE-3", pkgID))
	require.JSONEq(t, string(before), string(mustMarshal(findings)))
}

func TestEvaluateThenSheet(t *testing.T) {
	// The two together, as the hub runs them: the findings of the evidence in the order of the sheet.
	ev := mixedEvidence()
	findings := evaluateAll(t, ev, mixedMatches(), defaultSettings)
	kept, omitted, got := rules.Sheet(findings)
	require.Equal(t, len(findings), len(kept))
	require.Zero(t, omitted)

	var total int32
	for _, n := range []*int32{got.Suppressed, got.Tracked, got.NeedsAssessment} {
		require.NotNil(t, n)
		total += *n
	}
	require.Equal(t, int32(len(findings)), total)
	require.True(t, slices.IsSortedFunc(kept, func(a, b inventoryv1alpha1.Finding) int {
		rank := map[inventoryv1alpha1.Outcome]int{tracked: 0, needsAssessment: 1, suppressed: 2}
		return rank[a.Outcome] - rank[b.Outcome]
	}))
}

// needingAssessment returns n findings that need an assessment, in the order of a sheet: the first
// half Critical and the second half Medium. Long ones carry the longest reason and fixed versions that
// the schema allows.
func needingAssessment(n int, long bool) []inventoryv1alpha1.Finding {
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
		f := sheetFinding(needsAssessment, severity, fmt.Sprintf("CVE-2026-%05d", i), pkgID)
		if long {
			f.Reason, f.FixedVersions = ptr.To(strings.Repeat("r", 256)), longVersions
		}
		findings = append(findings, f)
	}
	return findings
}

func TestSheetPastALimitLeavesOutTheLeastSevereOpenFindingsBeforeAnyTrackedOne(t *testing.T) {
	// A vulnerability that is known to be exploited is patched, not argued about, so its finding is the
	// last that a cut leaves out. When the open findings alone pass a limit, the sheet leaves out the
	// end of its order: all the suppressed findings first, then the least severe of those that need an
	// assessment, and never a tracked one, though every tracked one here is less severe than the rest.
	trackedFindings := make([]inventoryv1alpha1.Finding, 0, 20)
	for i := range 20 {
		trackedFindings = append(trackedFindings, sheetFinding(tracked, inventoryv1alpha1.SeverityLow, fmt.Sprintf("CVE-2026-9%04d", i), pkgID))
	}
	suppressedFindings := make([]inventoryv1alpha1.Finding, 0, 100)
	for i := range 100 {
		suppressedFindings = append(suppressedFindings, sheetFinding(suppressed, inventoryv1alpha1.SeverityCritical, fmt.Sprintf("CVE-2026-%05d", i), pkgID))
	}

	for name, needing := range map[string][]inventoryv1alpha1.Finding{
		"more than 2048 findings": needingAssessment(2040, false),
		"more than 1 MiB":         needingAssessment(1500, true),
	} {
		t.Run(name, func(t *testing.T) {
			findings := slices.Concat(needing, trackedFindings, suppressedFindings)
			rng := rand.New(rand.NewPCG(9, 4))
			rng.Shuffle(len(findings), func(i, j int) { findings[i], findings[j] = findings[j], findings[i] })

			kept, omitted, got := rules.Sheet(findings)
			require.Greater(t, len(kept), len(trackedFindings))
			require.Equal(t, trackedFindings, kept[:len(trackedFindings)], "every tracked finding is kept, and comes first")
			rest := kept[len(trackedFindings):]
			require.Less(t, len(rest), len(needing), "the findings that need an assessment don't all fit")
			require.Equal(t, needing[:len(rest)], rest, "of those, the most severe are kept")
			require.Equal(t, int32(len(findings)-len(kept)), omitted, "the 100 suppressed findings and the end of the others")
			require.Greater(t, int(omitted), len(suppressedFindings))
			require.Equal(t, counts(100, 20, int32(len(needing))), got, "the counts include every finding")
		})
	}
}
