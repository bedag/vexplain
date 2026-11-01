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

package engine_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/stretchr/testify/require"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/yaml"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
	"github.com/bedag/vexplain/internal/rules/engine"
	"github.com/bedag/vexplain/internal/scan/result"
	"github.com/bedag/vexplain/sdk/evidence"
)

// These tests run the default rules, as the install ships them in config/rules, over the scanner's
// evidence. They replay the decisions of phase 2a's rules, which were written in Go: known exploited,
// the completeness guard, removed in a later layer and the load check. Phase 2b changes three things
// about them:
//   - known exploited holds a finding open, as UnderInvestigation, and no longer claims it affected
//     (decision 0035)
//   - the load check is a hint: what it found is a status note, and it settles nothing (decision 0028)
//   - the rules apply each on their own, and the notes add up, so a finding that a rule holds open
//     or settles still carries the load check's note where the load check applies
//
// The rules read the package facts by the package ID that the match gives, and tie them to a package
// only where the SBOM names that ID once and the facts describe it once: evidence that is missing,
// unreadable or says two things about a package is short of the evidence that a rule needs.

// The names of the default rules.
const (
	knownExploitedRule = "known-exploited"
	guardRule          = "completeness-guard"
	removedRule        = "removed-in-later-layer"
	loadCheckRule      = "load-check"
)

const (
	pkgID         = "pkg-1"
	pkg2          = "pkg-2"
	pkgGhost      = "pkg-ghost"
	libPath       = "/usr/lib/libfoo.so.1"
	libSoname     = "libfoo.so.1"
	libAPath      = "/usr/lib/liba.so.1"
	libASoname    = "liba.so.1"
	libBPath      = "/usr/lib/libb.so.1"
	libBSoname    = "libb.so.1"
	libfooName    = "libfoo"
	libfooVersion = "1.2.3-r0"
	typeAPK       = "apk"
	curlPath      = "/usr/bin/curl"
	loadPy        = "/app/load.py"

	// What the default rules say.
	guardAt80      = "completeness 80% is below 90%"
	reachedByCurl  = "reached by " + curlPath
	namedInLoadPy  = "named in " + loadPy
	preloads       = "the image preloads libraries"
	incompleteLibs = "the library evidence is incomplete"
	nothingReaches = "nothing in the image reaches or names its libraries"
)

// defaultSteps compiles the default rules as config/rules ships them: every file that its
// kustomization lists, each a Rule.
func defaultSteps(t testing.TB) []*engine.Compiled {
	t.Helper()
	dir := filepath.Join("..", "..", "..", "config", "rules")
	raw, err := os.ReadFile(filepath.Join(dir, "kustomization.yaml"))
	require.NoError(t, err)
	var kustomization struct {
		Resources []string `json:"resources"`
	}
	require.NoError(t, yaml.UnmarshalStrict(raw, &kustomization))
	require.Equal(t, []string{
		"known-exploited.yaml", "completeness-guard.yaml", "removed-in-later-layer.yaml", "load-check.yaml",
	}, kustomization.Resources)

	steps := make([]*engine.Compiled, 0, len(kustomization.Resources))
	for _, file := range kustomization.Resources {
		raw, err := os.ReadFile(filepath.Join(dir, file))
		require.NoError(t, err)
		var r configv1alpha1.Rule
		require.NoError(t, yaml.UnmarshalStrict(raw, &r), file)
		require.Equal(t, configv1alpha1.GroupVersion.String(), r.APIVersion, file)
		require.Equal(t, "Rule", r.Kind, file)
		require.Equal(t, strings.TrimSuffix(file, ".yaml"), r.Name, "the file is named after its rule")
		c, err := engine.Compile(&r)
		require.NoError(t, err, file)
		steps = append(steps, c)
	}
	return steps
}

// readRule reads a Rule from a YAML file below the root of the repository.
func readRule(t *testing.T, path ...string) *configv1alpha1.Rule {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(append([]string{"..", "..", ".."}, path...)...))
	require.NoError(t, err)
	var r configv1alpha1.Rule
	require.NoError(t, yaml.UnmarshalStrict(raw, &r))
	return &r
}

func TestTheSampleOfARuleIsTheDefaultRuleThatItShows(t *testing.T) {
	// config/samples documents the shape of a Rule with one of the default rules. It says so, so it
	// must be the rule that the install ships, which the engine compiles.
	sample := readRule(t, "config", "samples", "config_v1alpha1_rule.yaml")
	shipped := readRule(t, "config", "rules", sample.Name+".yaml")
	require.Equal(t, shipped.Spec, sample.Spec)
	_, err := engine.Compile(sample)
	require.NoError(t, err)
}

// ---- the scanner's evidence ----

// scanned is the data of the scanner's evidence, ch.bedag.vexplain.scanner.image-contents.v1alpha1:
// the JSON of what a scan found in one platform manifest. The operator won't import the scanner's
// types once the scanner is a collector of its own, so the tests write the JSON with types of their
// own. TestTheFixturesWriteTheScannersJSON holds them to the scanner's.
type scanned struct {
	Platform  string          `json:"platform"`
	Digest    string          `json:"digest"`
	SBOM      json.RawMessage `json:"sbom"`
	Packages  []packageFacts  `json:"packages"`
	ELF       elfSummary      `json:"elf"`
	Libraries []library       `json:"libraries"`
	Preload   preload         `json:"preload"`
}

type packageFacts struct {
	ID              string `json:"id"`
	FilesListed     int    `json:"filesListed"`
	FilesPresent    int    `json:"filesPresent"`
	SharedLibraries int    `json:"sharedLibraries"`
	OtherELFFiles   int    `json:"otherElfFiles"`
}

type elfSummary struct {
	Total   int      `json:"total"`
	Owned   int      `json:"owned"`
	Unowned []string `json:"unowned,omitempty"`
}

type library struct {
	Path         string   `json:"path"`
	Soname       string   `json:"soname"`
	PackageID    string   `json:"packageId,omitempty"`
	ReachedBy    []string `json:"reachedBy,omitempty"`
	ReachedCount int      `json:"reachedCount"`
	NameHits     []string `json:"nameHits,omitempty"`
	NameHitCount int      `json:"nameHitCount"`
}

type preload struct {
	LDPreload      bool `json:"ldPreload"`
	LDAudit        bool `json:"ldAudit"`
	EtcLdSoPreload bool `json:"etcLdSoPreload"`
}

// artifact is a package of Syft's JSON, as far as the rules read it.
type artifact struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Version string `json:"version"`
	Type    string `json:"type"`
}

func sbomOf(artifacts ...artifact) json.RawMessage {
	if artifacts == nil {
		artifacts = []artifact{}
	}
	return jsonOf(struct {
		Artifacts []artifact `json:"artifacts"`
	}{artifacts})
}

// nullJSON is JSON's null.
var nullJSON = json.RawMessage("null")

// jsonOf returns the JSON of a fixture, which always has some.
func jsonOf(v any) json.RawMessage {
	raw, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return raw
}

// libraryManifest is the evidence of an image of one OS package that owns one shared library, which
// nothing reaches or names. The load check notes that, and no rule settles or holds its findings.
// Each test changes what it is about.
func libraryManifest() scanned {
	return scanned{
		Platform: "linux/amd64",
		Digest:   "sha256:" + strings.Repeat("ab", 32),
		SBOM:     sbomOf(artifact{ID: pkgID, Name: libfooName, Version: libfooVersion, Type: typeAPK}),
		Packages: []packageFacts{{ID: pkgID, FilesListed: 4, FilesPresent: 4, SharedLibraries: 1}},
		ELF:      elfSummary{Total: 10, Owned: 10},
		Libraries: []library{
			{Path: libPath, Soname: libSoname, PackageID: pkgID},
		},
	}
}

// scanOf supplies the evidence as the playbook does: under the name contents, its data decoded from
// JSON, and its coverage the completeness that the scan reports.
func scanOf(ev scanned, coverage int32) map[string]engine.Input {
	var data any
	if err := json.Unmarshal(jsonOf(ev), &data); err != nil {
		panic(err)
	}
	return map[string]engine.Input{contents: {
		Present: true, Data: data, Coverage: ptr.To(coverage), Time: seen, Source: scannerEvent,
	}}
}

// decide runs the default rules over the evidence for one match, and returns its verdict.
func decide(t *testing.T, ev scanned, coverage int32, m evidence.Match) verdict {
	t.Helper()
	verdicts := evaluate(t, defaultSteps(t), scanOf(ev, coverage), []evidence.Match{m})
	require.Len(t, verdicts, 1)
	return verdicts[0]
}

var (
	// exploited is a finding that known-exploited holds open.
	exploited = verdict{Status: underInvestigation, Rule: knownExploitedRule, Reason: "known exploited"}
	// removed is a finding that removed-in-later-layer settles.
	removed = verdict{Status: notAffected, Rule: removedRule, Justification: componentNotPresent}
	// guarded is a finding that the completeness guard holds open in evidence of 80%.
	guarded = verdict{Status: underInvestigation, Rule: guardRule, Reason: guardAt80}
)

// noting adds the load check's note to v.
func noting(v verdict, text string) verdict {
	v.Notes = append(slices.Clone(v.Notes), engine.Note{Rule: loadCheckRule, Text: text})
	return v
}

// noted is a finding that no rule settles or holds, with the load check's note.
func noted(text string) verdict {
	return noting(open, text)
}

// Changes to libraryManifest and to its match.
var (
	kev = func(m *evidence.Match) { m.KnownExploited = true }
	// goneFromImage makes the package database list files of the package that the final filesystem
	// doesn't have. A package whose files are gone owns no ELF file of the image, so it has no
	// library either, as a scan reports it.
	goneFromImage = func(ev *scanned) {
		ev.Packages[0] = packageFacts{ID: pkgID, FilesListed: 3, FilesPresent: 0}
		ev.Libraries = nil
	}
	reached = func(ev *scanned) { ev.Libraries[0].ReachedBy, ev.Libraries[0].ReachedCount = []string{curlPath}, 1 }
	named   = func(ev *scanned) { ev.Libraries[0].NameHits, ev.Libraries[0].NameHitCount = []string{loadPy}, 1 }
)

// ---- phase 2a's decision table ----

func TestTheDefaultRulesReplayPhase2asDecisionTable(t *testing.T) {
	tests := []struct {
		name     string
		ev       func(*scanned)
		coverage int32
		match    func(*evidence.Match)
		want     verdict
	}{
		{name: "KEV, even where removed in a later layer would settle it", ev: goneFromImage, match: kev, want: exploited},
		// The load check's evidence doesn't depend on the completeness: what reaches a library is
		// searched in every file, whichever package owns it. So its note stands next to the guard.
		{name: "completeness 80", coverage: 80, want: noting(guarded, nothingReaches)},
		{name: "files listed 3, files present 0", ev: goneFromImage, want: removed},
		{name: "an unreached library package", want: noted(nothingReaches)},
		{name: "reached", ev: reached, want: noted(reachedByCurl)},
		{name: "named", ev: named, want: noted(namedInLoadPy)},
		{name: "LD_PRELOAD", ev: func(ev *scanned) { ev.Preload.LDPreload = true }, want: noted(preloads)},
		{name: "LD_AUDIT", ev: func(ev *scanned) { ev.Preload.LDAudit = true }, want: noted(preloads)},
		{name: "a non-empty /etc/ld.so.preload", ev: func(ev *scanned) { ev.Preload.EtcLdSoPreload = true }, want: noted(preloads)},
		{
			// The package owns two libraries, and the evidence lists one of them twice: the other,
			// which could be the one that something reaches, is missing, though the count adds up.
			name: "a repeated library entry", want: noted(incompleteLibs),
			ev: func(ev *scanned) {
				ev.Packages[0].SharedLibraries = 2
				ev.Libraries = append(ev.Libraries, ev.Libraries[0])
			},
		},
		{name: "owns an executable", ev: func(ev *scanned) { ev.Packages[0].OtherELFFiles = 1 }, want: open},
		{
			name: "owns no library, such as a language package", want: open,
			ev: func(ev *scanned) {
				ev.Packages[0] = packageFacts{ID: pkgID}
				ev.Libraries = nil
			},
		},
		{name: "an unknown package ID", match: func(m *evidence.Match) { m.PackageID = pkgGhost }, want: open},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ev, m := libraryManifest(), matchOf(someCVE, pkgID)
			if tc.ev != nil {
				tc.ev(&ev)
			}
			if tc.match != nil {
				tc.match(&m)
			}
			coverage := int32(100)
			if tc.coverage != 0 {
				coverage = tc.coverage
			}
			require.Equal(t, tc.want, decide(t, ev, coverage, m))
		})
	}
}

func TestEachDefaultRuleAppliesOnItsOwn(t *testing.T) {
	tests := []struct {
		name     string
		ev       func(*scanned)
		coverage int32
		match    func(*evidence.Match)
		want     verdict
	}{
		// Known exploited holds a finding open, whatever else holds, and the load check notes what it
		// found next to it.
		{name: "KEV and an unreached library", match: kev, want: noting(exploited, nothingReaches)},
		{name: "KEV and a reached library", ev: reached, match: kev, want: noting(exploited, reachedByCurl)},
		// Between two rules that hold a finding open, the first by name is the one that it records:
		// the guard. The finding still says that the vulnerability is known to be exploited, which
		// urgency reads.
		{name: "KEV below the minimum completeness", coverage: 80, match: kev, want: noting(guarded, nothingReaches)},

		// The guard: below 90%, no rule may settle a finding.
		{name: "the guard blocks removal in a later layer", ev: goneFromImage, coverage: 80, want: guarded},
		{name: "at 90% the rules decide", coverage: 90, want: noted(nothingReaches)},
		{name: "at 89% the guard holds", coverage: 89, want: noting(
			verdict{Status: underInvestigation, Rule: guardRule, Reason: "completeness 89% is below 90%"}, nothingReaches)},

		// Removed in a later layer: the database lists files, and none is left.
		{
			name: "files that are left mean the package is there", want: noted(nothingReaches),
			ev: func(ev *scanned) { ev.Packages[0].FilesListed, ev.Packages[0].FilesPresent = 3, 1 },
		},
		{
			name: "a package that lists no files is not removed", want: noted(nothingReaches),
			ev: func(ev *scanned) { ev.Packages[0].FilesListed, ev.Packages[0].FilesPresent = 0, 0 },
		},

		// The evidence doesn't know the package.
		{name: "a package that the SBOM names and the facts don't", ev: func(ev *scanned) { ev.Packages = nil }, want: open},
		{
			name: "a package that has facts and no entry in the SBOM", want: open,
			ev: func(ev *scanned) { goneFromImage(ev); ev.SBOM = sbomOf() },
		},
		{name: "known exploited needs no evidence of the package", match: func(m *evidence.Match) {
			m.PackageID = pkgGhost
			m.KnownExploited = true
		}, want: exploited},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ev, m := libraryManifest(), matchOf(someCVE, pkgID)
			if tc.ev != nil {
				tc.ev(&ev)
			}
			if tc.match != nil {
				tc.match(&m)
			}
			coverage := int32(100)
			if tc.coverage != 0 {
				coverage = tc.coverage
			}
			require.Equal(t, tc.want, decide(t, ev, coverage, m))
		})
	}
}

func TestTheGuardAtNoCoverageAtAll(t *testing.T) {
	require.Equal(t, noting(verdict{Status: underInvestigation, Rule: guardRule, Reason: "completeness 0% is below 90%"}, nothingReaches),
		decide(t, libraryManifest(), 0, matchOf(someCVE, pkgID)))
}

// ---- missing evidence ----

func TestEvidenceWithoutCoverageHoldsEveryFindingOpen(t *testing.T) {
	// The guard can't be evaluated without the scanner's coverage, so it fails closed, and removal in a
	// later layer can't settle the finding.
	ev := libraryManifest()
	goneFromImage(&ev)
	inputs := scanOf(ev, 100)
	in := inputs[contents]
	in.Coverage = nil
	inputs[contents] = in

	verdicts := evaluate(t, defaultSteps(t), inputs, []evidence.Match{matchOf(someCVE, pkgID)})
	requireHeldBy(t, verdicts[0], guardRule, inCondition, "no such key: coverage")
}

func TestWithoutTheScannersEvidenceNothingIsSettledAndOnlyKEVIsKnown(t *testing.T) {
	// A missing input is evidence that no rule may settle a finding on: the guard holds every finding
	// open, and says why. It sorts before known-exploited, so a finding of a vulnerability that is
	// known to be exploited records the guard as well.
	missing := heldBy(guardRule, `the input "contents" is missing`)
	exploitedMatch := matchOf("CVE-2026-0002", pkgID)
	exploitedMatch.KnownExploited = true
	verdicts := evaluate(t, defaultSteps(t), nil, []evidence.Match{matchOf(someCVE, pkgID), exploitedMatch})
	require.Equal(t, []verdict{missing, missing}, verdicts)
}

// ---- evidence that doesn't add up ----

func TestEvidenceThatDoesNotAddUpNeverGivesTheNoteThatNothingReachesTheLibraries(t *testing.T) {
	// A library that the evidence lacks, or a count that can't be true, could be the one that something
	// reaches. The note then says that the evidence is incomplete, and never that nothing reaches or
	// names the libraries.
	tests := []struct {
		name string
		ev   func(*scanned)
	}{
		{"fewer library entries than the package owns", func(ev *scanned) { ev.Packages[0].SharedLibraries = 2 }},
		{"more library entries than the package owns", func(ev *scanned) {
			ev.Libraries = append(ev.Libraries, library{Path: "/usr/lib/libbar.so.1", Soname: "libbar.so.1", PackageID: pkgID})
		}},
		{"no library entries", func(ev *scanned) { ev.Libraries = nil }},
		{"entries of another package only", func(ev *scanned) { ev.Libraries[0].PackageID = pkg2 }},
		{"an entry that no package owns", func(ev *scanned) { ev.Libraries[0].PackageID = "" }},
		{"a negative count of reaching files", func(ev *scanned) { ev.Libraries[0].ReachedCount = -1 }},
		{"a negative count of naming files", func(ev *scanned) { ev.Libraries[0].NameHitCount = -1 }},
		{"one entry twice, where the package owns two", func(ev *scanned) {
			ev.Packages[0].SharedLibraries = 2
			ev.Libraries = append(ev.Libraries, ev.Libraries[0])
		}},
		{"one entry twice, though the first is reached", func(ev *scanned) {
			ev.Packages[0].SharedLibraries = 2
			reached(ev)
			ev.Libraries = append(ev.Libraries, ev.Libraries[0])
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ev := libraryManifest()
			tc.ev(&ev)
			require.Equal(t, noted(incompleteLibs), decide(t, ev, 100, matchOf(someCVE, pkgID)))
		})
	}

	t.Run("paths without a count are still use", func(t *testing.T) {
		ev := libraryManifest()
		ev.Libraries[0].ReachedBy = []string{curlPath}
		require.Equal(t, noted(reachedByCurl), decide(t, ev, 100, matchOf(someCVE, pkgID)))

		ev = libraryManifest()
		ev.Libraries[0].NameHits = []string{loadPy}
		require.Equal(t, noted(namedInLoadPy), decide(t, ev, 100, matchOf(someCVE, pkgID)))
	})
}

func TestTheLoadCheckLooksAtEveryLibraryOfThePackage(t *testing.T) {
	twoLibraries := func() scanned {
		ev := libraryManifest()
		ev.Packages[0].SharedLibraries = 2
		ev.Libraries = []library{
			{Path: libAPath, Soname: libASoname, PackageID: pkgID},
			{Path: libBPath, Soname: libBSoname, PackageID: pkgID},
		}
		return ev
	}

	require.Equal(t, noted(nothingReaches), decide(t, twoLibraries(), 100, matchOf(someCVE, pkgID)))

	for _, which := range []int{0, 1} {
		ev := twoLibraries()
		ev.Libraries[which].ReachedBy, ev.Libraries[which].ReachedCount = []string{curlPath}, 1
		require.Equal(t, noted(reachedByCurl), decide(t, ev, 100, matchOf(someCVE, pkgID)), "library %d", which)

		ev = twoLibraries()
		ev.Libraries[which].NameHits, ev.Libraries[which].NameHitCount = []string{loadPy}, 1
		require.Equal(t, noted(namedInLoadPy), decide(t, ev, 100, matchOf(someCVE, pkgID)), "library %d", which)
	}
}

func TestEachPackageGetsTheNoteOfItsOwnLibraries(t *testing.T) {
	// One library file that two packages own has one entry for each. What reaches it from outside one
	// package says nothing about the other: a finding covers one package only.
	const pkgA1, pkgB1 = "pkg-a", "pkg-b"
	ev := scanned{
		SBOM: sbomOf(
			artifact{ID: pkgA1, Name: "liba", Version: "1", Type: typeAPK},
			artifact{ID: pkgB1, Name: "libb", Version: "1", Type: typeAPK},
		),
		Packages: []packageFacts{
			{ID: pkgA1, FilesListed: 1, FilesPresent: 1, SharedLibraries: 1},
			{ID: pkgB1, FilesListed: 1, FilesPresent: 1, SharedLibraries: 1},
		},
		ELF: elfSummary{Total: 1, Owned: 1},
		Libraries: []library{
			{Path: libPath, Soname: libSoname, PackageID: pkgA1},
			{Path: libPath, Soname: libSoname, PackageID: pkgB1, ReachedBy: []string{"/opt/b/tool"}, ReachedCount: 1},
		},
	}
	verdicts := evaluate(t, defaultSteps(t), scanOf(ev, 100), []evidence.Match{matchOf(someCVE, pkgB1), matchOf(someCVE, pkgA1)})
	require.Equal(t, []verdict{noted(nothingReaches), noted("reached by /opt/b/tool")}, verdicts)
}

// ---- the notes ----

func TestTheNoteNamesTheFirstPathInAFixedOrder(t *testing.T) {
	// Libraries come in the order of their paths, and a library's paths in the order it lists them,
	// whatever order the evidence holds the libraries in.
	twoLibraries := func(a, b library) scanned {
		a.Path, a.Soname, a.PackageID = libAPath, libASoname, pkgID
		b.Path, b.Soname, b.PackageID = libBPath, libBSoname, pkgID
		ev := libraryManifest()
		ev.Packages[0].SharedLibraries = 2
		ev.Libraries = []library{b, a}
		return ev
	}
	paths := func(p ...string) []string { return p }

	tests := []struct {
		name string
		ev   scanned
		want string
	}{
		{
			"the first reaching path of the first library that is reached",
			twoLibraries(
				library{ReachedBy: paths("/usr/bin/z", "/usr/bin/a"), ReachedCount: 2},
				library{ReachedBy: paths("/usr/bin/b"), ReachedCount: 1},
			),
			"reached by /usr/bin/z",
		},
		{
			"a library further on, when the first isn't reached",
			twoLibraries(library{}, library{ReachedBy: paths("/usr/bin/b"), ReachedCount: 1}),
			"reached by /usr/bin/b",
		},
		{
			"reach wins over a name hit, even of an earlier library",
			twoLibraries(
				library{NameHits: paths("/app/a.py"), NameHitCount: 1},
				library{ReachedBy: paths("/usr/bin/b"), ReachedCount: 1},
			),
			"reached by /usr/bin/b",
		},
		{
			"the first name hit of the first library that is named",
			twoLibraries(
				library{NameHits: paths("/app/z.py", "/app/a.py"), NameHitCount: 2},
				library{NameHits: paths("/app/b.py"), NameHitCount: 1},
			),
			"named in /app/z.py",
		},
		{
			"a name hit wins over preload",
			func() scanned {
				ev := twoLibraries(library{NameHits: paths(loadPy), NameHitCount: 1}, library{})
				ev.Preload = preload{LDPreload: true, LDAudit: true, EtcLdSoPreload: true}
				return ev
			}(),
			namedInLoadPy,
		},
		{
			"reach wins over preload",
			func() scanned {
				ev := twoLibraries(library{ReachedBy: paths(curlPath), ReachedCount: 1}, library{})
				ev.Preload.LDPreload = true
				return ev
			}(),
			reachedByCurl,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, noted(tc.want), decide(t, tc.ev, 100, matchOf(someCVE, pkgID)))
		})
	}
}

func TestTheNoteCountsWhenThereAreNoPaths(t *testing.T) {
	// The scanner always lists the first paths of a count that isn't zero. Should a count come with none,
	// the note gives the count: it is still evidence that something reaches or names a library.
	tests := []struct {
		name string
		lib  library
		want string
	}{
		{"reaching files", library{ReachedCount: 3}, "reached by 3 ELF files"},
		{"naming files", library{NameHitCount: 2}, "named in 2 files"},
		{"a count of reach wins over a name hit with a path", library{ReachedCount: 3, NameHits: []string{loadPy}, NameHitCount: 1}, "reached by 3 ELF files"},
		{"a name hit with a path is named by its path, though the count is larger", library{NameHits: []string{loadPy}, NameHitCount: 4}, namedInLoadPy},
		{"a count of a million is written in full", library{ReachedCount: 1_000_000}, "reached by 1000000 ELF files"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ev := libraryManifest()
			tc.lib.Path, tc.lib.Soname, tc.lib.PackageID = libPath, libSoname, pkgID
			ev.Libraries[0] = tc.lib
			require.Equal(t, noted(tc.want), decide(t, ev, 100, matchOf(someCVE, pkgID)))
		})
	}

	t.Run("a path is named in preference to a count of another library", func(t *testing.T) {
		ev := libraryManifest()
		ev.Packages[0].SharedLibraries = 2
		ev.Libraries = []library{
			{Path: libAPath, Soname: libASoname, PackageID: pkgID, ReachedCount: 7},
			{Path: libBPath, Soname: libBSoname, PackageID: pkgID, ReachedBy: []string{curlPath}, ReachedCount: 1},
		}
		require.Equal(t, noted(reachedByCurl), decide(t, ev, 100, matchOf(someCVE, pkgID)))
	})
}

func TestTheNoteIsPrintableAndCutTo256Characters(t *testing.T) {
	t.Run("the paths that it names", func(t *testing.T) {
		ev := libraryManifest()
		ev.Libraries[0].ReachedBy, ev.Libraries[0].ReachedCount = []string{dirty}, 1
		require.Equal(t, noted("reached by "+clean), decide(t, ev, 100, matchOf(someCVE, pkgID)))

		ev = libraryManifest()
		ev.Libraries[0].NameHits, ev.Libraries[0].NameHitCount = []string{dirty}, 1
		require.Equal(t, noted("named in "+clean), decide(t, ev, 100, matchOf(someCVE, pkgID)))
	})

	t.Run("a path that clears the terminal and starts a line of its own", func(t *testing.T) {
		ev := libraryManifest()
		ev.Libraries[0].ReachedBy, ev.Libraries[0].ReachedCount = []string{"/opt/\x1b[2J\x1b[31mred\nreached by /usr/bin/safe"}, 1
		require.Equal(t, noted("reached by /opt/\ufffd[2J\ufffd[31mred\ufffdreached by /usr/bin/safe"),
			decide(t, ev, 100, matchOf(someCVE, pkgID)))
	})

	for name, character := range map[string]string{"one byte": "a", "two bytes": "é", "four bytes": "😀", "an escape": "\x1b"} {
		t.Run(name, func(t *testing.T) {
			ev := libraryManifest()
			ev.Libraries[0].ReachedBy, ev.Libraries[0].ReachedCount = []string{strings.Repeat(character, 300)}, 1
			got := decide(t, ev, 100, matchOf(someCVE, pkgID))
			require.Len(t, got.Notes, 1)
			note := got.Notes[0].Text
			require.Equal(t, 256, utf8.RuneCountInString(note))
			shown := strings.Repeat(strings.ReplaceAll(character, "\x1b", "\ufffd"), 300)
			require.True(t, strings.HasPrefix("reached by "+shown, note), "the note is the start of the text, not a rewrite of it")
		})
	}
}

// ---- evidence that can't be used ----

func TestAnSBOMThatCantBeUsedSettlesNothing(t *testing.T) {
	// The rules that need the package's evidence never apply without an SBOM that names the package,
	// whatever the facts say.
	tests := []struct {
		name string
		sbom json.RawMessage
	}{
		{"none", nil},
		{"null", nullJSON},
		{"an array", json.RawMessage("[]")},
		{"a string", json.RawMessage(`"artifacts"`)},
		{"artifacts that aren't a list", json.RawMessage(`{"artifacts": "none"}`)},
		{"artifacts that are null", json.RawMessage(`{"artifacts": null}`)},
		{"no packages", json.RawMessage("{}")},
		{"a package without an ID", json.RawMessage(`{"artifacts": [{"id": "pkg-1"}, {"name": "libbar"}]}`)},
		{"a package that is no object", json.RawMessage(`{"artifacts": [{"id": "pkg-1"}, 5]}`)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ev := libraryManifest()
			ev.SBOM = tc.sbom
			gone := libraryManifest()
			gone.SBOM = tc.sbom
			goneFromImage(&gone)
			require.Equal(t, open, decide(t, ev, 100, matchOf(someCVE, pkgID)), "no note")
			require.Equal(t, open, decide(t, gone, 100, matchOf(someCVE, pkgID)), "no removal")
		})
	}

	t.Run("the rules that need no package evidence still apply", func(t *testing.T) {
		ev := libraryManifest()
		ev.SBOM = nullJSON
		m := matchOf(someCVE, pkgID)
		m.KnownExploited = true
		require.Equal(t, exploited, decide(t, ev, 100, m))
		require.Equal(t, guarded, decide(t, ev, 80, matchOf(someCVE, pkgID)))
	})
}

func TestEvidenceThatSaysTwoThingsOfOnePackageSettlesNothing(t *testing.T) {
	t.Run("two entries of one ID in the SBOM", func(t *testing.T) {
		ev := libraryManifest()
		goneFromImage(&ev)
		ev.SBOM = sbomOf(
			artifact{ID: pkgID, Name: libfooName, Version: libfooVersion, Type: typeAPK},
			artifact{ID: pkgID, Name: "libother", Version: "9", Type: typeAPK},
		)
		require.Equal(t, open, decide(t, ev, 100, matchOf(someCVE, pkgID)))
	})

	t.Run("two sets of facts of one ID", func(t *testing.T) {
		// Either set alone would decide: the first that the package is removed, the second that its
		// library is unreached. Together they decide nothing, in either order.
		ev := libraryManifest()
		ev.Packages = []packageFacts{
			{ID: pkgID, FilesListed: 3, FilesPresent: 0},
			{ID: pkgID, FilesListed: 3, FilesPresent: 3, SharedLibraries: 1},
		}
		require.Equal(t, open, decide(t, ev, 100, matchOf(someCVE, pkgID)))
		slices.Reverse(ev.Packages)
		require.Equal(t, open, decide(t, ev, 100, matchOf(someCVE, pkgID)))
	})

	t.Run("an entry without an ID names nobody", func(t *testing.T) {
		ev := libraryManifest()
		ev.SBOM = sbomOf(artifact{Name: libfooName, Type: typeAPK})
		ev.Packages = []packageFacts{{FilesListed: 3, FilesPresent: 0}}
		require.Equal(t, open, decide(t, ev, 100, matchOf(someCVE, "")))
	})
}

func TestThePlaceholderIsNeverTakenForAPackageID(t *testing.T) {
	// The rules decide by the package ID that the match gives. A package that the evidence really calls
	// "unknown" has facts of its own, which a match without a package ID must not pick up.
	ev := libraryManifest()
	goneFromImage(&ev)
	ev.SBOM = sbomOf(artifact{ID: placeholder, Name: libfooName, Version: libfooVersion, Type: typeAPK})
	ev.Packages[0].ID = placeholder

	require.Equal(t, removed, decide(t, ev, 100, matchOf(someCVE, placeholder)))

	findings := engine.Evaluate(defaultSteps(t), scanOf(ev, 100), []evidence.Match{matchOf(someCVE, "")}).Findings
	require.Len(t, findings, 1)
	require.Equal(t, placeholder, findings[0].Match.PackageID)
	require.Equal(t, open, verdictOf(findings[0]))
}

func TestThePackageIDInTheEvidenceIsMatchedAsItIsAndShownPrintable(t *testing.T) {
	// The evidence keys a package by its ID, whatever characters it holds. Replacing them is for what a
	// finding shows: the facts and the libraries are still found, and the rules still decide by them.
	ev := libraryManifest()
	ev.SBOM = sbomOf(artifact{ID: dirty, Name: libfooName, Version: libfooVersion, Type: typeAPK})
	ev.Packages[0].ID = dirty
	ev.Libraries[0].PackageID = dirty

	findings := engine.Evaluate(defaultSteps(t), scanOf(ev, 100), []evidence.Match{matchOf(someCVE, dirty)}).Findings
	require.Len(t, findings, 1)
	require.Equal(t, noted(nothingReaches), verdictOf(findings[0]))
	require.Equal(t, clean, findings[0].Match.PackageID)
}

// ---- determinism ----

// The packages of mixedEvidence.
const (
	unusedPkg     = "lib-unused"
	reachedPkg    = "lib-reached"
	executablePkg = "has-executable"
	languagePkg   = "language"
	gonePkg       = "gone"
	// ghostPkg is a package that the evidence lacks.
	ghostPkg = "ghost"
)

// mixedEvidence is an image of five kinds of package, and mixedMatches the matches against it: some
// repeated, some that disagree with another about the same finding, and some for a package that the
// evidence lacks.
func mixedEvidence() scanned {
	return scanned{
		SBOM: sbomOf(
			artifact{ID: unusedPkg, Name: "libunused", Version: "1", Type: typeAPK},
			artifact{ID: reachedPkg, Name: "libreached", Version: "2", Type: typeAPK},
			artifact{ID: executablePkg, Name: "tool", Version: "3", Type: typeAPK},
			artifact{ID: languagePkg, Name: "gopkg", Version: "4", Type: "go-module"},
			artifact{ID: gonePkg, Name: "libgone", Version: "5", Type: typeAPK},
		),
		Packages: []packageFacts{
			{ID: unusedPkg, FilesListed: 2, FilesPresent: 2, SharedLibraries: 1},
			{ID: reachedPkg, FilesListed: 2, FilesPresent: 2, SharedLibraries: 1},
			{ID: executablePkg, FilesListed: 2, FilesPresent: 2, SharedLibraries: 1, OtherELFFiles: 1},
			{ID: languagePkg},
			{ID: gonePkg, FilesListed: 2},
		},
		ELF: elfSummary{Total: 3, Owned: 3},
		Libraries: []library{
			{Path: "/usr/lib/libreached.so.1", Soname: "libreached.so.1", PackageID: reachedPkg, ReachedBy: []string{curlPath}, ReachedCount: 1},
			{Path: "/usr/lib/libtool.so.1", Soname: "libtool.so.1", PackageID: executablePkg},
			{Path: "/usr/lib/libunused.so.1", Soname: "libunused.so.1", PackageID: unusedPkg},
		},
	}
}

func mixedMatches() []evidence.Match {
	matches := make([]evidence.Match, 0, 2*3*6)
	for _, pkg := range []string{unusedPkg, reachedPkg, executablePkg, languagePkg, gonePkg, ghostPkg} {
		for i, severity := range []string{severityLow, severityHigh, severityCritical} {
			m := matchOf(fmt.Sprintf("CVE-2026-%04d", 100-i), pkg)
			m.Severity = severity
			m.FixState = []string{stateFixed, stateWontFix, ""}[i]
			m.FixedVersions = []string{fmt.Sprintf("%d.%d", i, 9-i), "0.1"}
			m.KnownExploited = pkg == executablePkg && i == 1
			matches = append(matches, m)
		}
	}
	for _, m := range slices.Clone(matches) {
		m.Severity, m.FixState, m.FixedVersions = severityMedium, stateNotFixed, []string{"7.0"}
		if m.PackageID == ghostPkg {
			m.PackageName, m.PackageVersion, m.PackageType = "libghost-alias", "", "deb"
		}
		matches = append(matches, m)
	}
	return matches
}

func TestTheDefaultRulesGiveTheSameFindingsForAnyOrderOfStepsAndMatches(t *testing.T) {
	steps, inputs, matches := defaultSteps(t), scanOf(mixedEvidence(), 100), mixedMatches()
	want := engine.Evaluate(steps, inputs, matches)
	require.Len(t, want.Findings, 6*3, "one finding for each vulnerability and package")
	require.Equal(t, map[string]int{knownExploitedRule: 0, guardRule: 0, removedRule: 0, loadCheckRule: 0}, want.NotEvaluated)

	byPackage := map[string]verdict{}
	for _, f := range want.Findings {
		requireValid(t, f)
		if !f.Match.KnownExploited {
			byPackage[f.Match.PackageID] = verdictOf(f)
		}
	}
	require.Equal(t, map[string]verdict{
		unusedPkg: noted(nothingReaches), reachedPkg: noted(reachedByCurl), executablePkg: open,
		languagePkg: open, gonePkg: removed, ghostPkg: open,
	}, byPackage, "the fixture has every kind of finding")

	reversed := slices.Clone(steps)
	slices.Reverse(reversed)
	require.Equal(t, want, engine.Evaluate(reversed, inputs, matches))

	rng := rand.New(rand.NewPCG(7, 11))
	for range 20 {
		shuffledSteps := slices.Clone(steps)
		rng.Shuffle(len(shuffledSteps), func(i, j int) { shuffledSteps[i], shuffledSteps[j] = shuffledSteps[j], shuffledSteps[i] })
		shuffled := slices.Clone(matches)
		rng.Shuffle(len(shuffled), func(i, j int) { shuffled[i], shuffled[j] = shuffled[j], shuffled[i] })
		require.Equal(t, want, engine.Evaluate(shuffledSteps, inputs, shuffled))
	}
}

// ---- speed ----

// largeImage is evidence about the size of the largest image of phase 2a's measurement, with as many
// findings as a sheet holds: 2,048 findings over 600 packages. Two in five packages own shared libraries
// only, which the load check looks at, two in five a program and a library, and one in five is a
// language package. The evidence cap keeps an SBOM to about this many packages.
func largeImage() (scanned, []evidence.Match) {
	const packages, findings = 600, 2048
	ev := scanned{ELF: elfSummary{Total: 1000, Owned: 1000}}
	artifacts := make([]artifact, 0, packages)
	for i := range packages {
		id := fmt.Sprintf("pkg-%04d", i)
		artifacts = append(artifacts, artifact{ID: id, Name: "lib" + id, Version: version1, Type: typeAPK})
		lib := library{Path: "/usr/lib/" + id + ".so.1", Soname: id + ".so.1", PackageID: id}
		switch i % 5 {
		case 0, 1:
			ev.Packages = append(ev.Packages, packageFacts{ID: id, FilesListed: 4, FilesPresent: 4, SharedLibraries: 1})
			if i%10 == 0 {
				lib.ReachedBy, lib.ReachedCount = []string{curlPath}, 1
			}
			ev.Libraries = append(ev.Libraries, lib)
		case 2, 3:
			ev.Packages = append(ev.Packages, packageFacts{ID: id, FilesListed: 6, FilesPresent: 6, SharedLibraries: 1, OtherELFFiles: 1})
			ev.Libraries = append(ev.Libraries, lib)
		default:
			ev.Packages = append(ev.Packages, packageFacts{ID: id})
		}
	}
	ev.SBOM = sbomOf(artifacts...)
	return ev, findingsOver(packages, findings)
}

// craftedImage is evidence that an image can be crafted to give: 200 packages that own 100 small
// shared libraries each, 20,000 in all, which compress well enough to stay below the evidence cap, and
// 2,048 findings in them. The load check goes through every library for each finding.
func craftedImage() (scanned, []evidence.Match) {
	const packages, librariesEach, findings = 200, 100, 2048
	ev := scanned{ELF: elfSummary{Total: packages * librariesEach, Owned: packages * librariesEach}}
	artifacts := make([]artifact, 0, packages)
	for i := range packages {
		id := fmt.Sprintf("pkg-%04d", i)
		artifacts = append(artifacts, artifact{ID: id, Name: "lib" + id, Version: version1, Type: typeAPK})
		ev.Packages = append(ev.Packages, packageFacts{
			ID: id, FilesListed: librariesEach, FilesPresent: librariesEach, SharedLibraries: librariesEach,
		})
		for j := range librariesEach {
			ev.Libraries = append(ev.Libraries, library{
				Path: fmt.Sprintf("/usr/lib/%s/l%03d.so", id, j), Soname: fmt.Sprintf("l%03d.so", j), PackageID: id,
			})
		}
	}
	ev.SBOM = sbomOf(artifacts...)
	return ev, findingsOver(packages, findings)
}

// findingsOver returns the given number of findings, each of another vulnerability, spread evenly over
// the packages of largeImage and craftedImage.
func findingsOver(packages, findings int) []evidence.Match {
	matches := make([]evidence.Match, 0, findings)
	for i := range findings {
		matches = append(matches, matchOf(fmt.Sprintf("CVE-2026-%05d", i), fmt.Sprintf("pkg-%04d", i%packages)))
	}
	return matches
}

func BenchmarkTheDefaultRulesOnALargeImage(b *testing.B) {
	ev, matches := largeImage()
	steps, inputs := defaultSteps(b), scanOf(ev, 100)
	for b.Loop() {
		engine.Evaluate(steps, inputs, matches)
	}
}

func BenchmarkTheDefaultRulesOnACraftedImage(b *testing.B) {
	ev, matches := craftedImage()
	steps, inputs := defaultSteps(b), scanOf(ev, 100)
	for b.Loop() {
		engine.Evaluate(steps, inputs, matches)
	}
}

// ---- the fixtures ----

func TestTheFixturesWriteTheScannersJSON(t *testing.T) {
	// The tests write the scanner's evidence with types of their own. This holds them to the JSON of
	// result.Manifest, every field and its name, and which fields are left out when empty, while the
	// scanner's types are in this module.
	full := result.Manifest{
		Platform: "linux/arm64/v8", Digest: "sha256:" + strings.Repeat("cd", 32),
		SBOM:     json.RawMessage(`{"artifacts":[{"id":"a","name":"n","version":"v","type":"t"}]}`),
		Packages: []result.PackageFacts{{ID: "a", FilesListed: 1, FilesPresent: 2, SharedLibraries: 3, OtherELFFiles: 4}},
		ELF:      result.ELFSummary{Total: 5, Owned: 6, Unowned: []string{"/x"}},
		Libraries: []result.Library{
			{Path: "/p", Soname: "s", PackageID: "a", ReachedBy: []string{"/r"}, ReachedCount: 7, NameHits: []string{"/h"}, NameHitCount: 8},
			{},
		},
		Preload: result.Preload{LDPreload: true, LDAudit: true, EtcLdSoPreload: true},
	}
	for name, m := range map[string]result.Manifest{"every field": full, "no field": {}} {
		t.Run(name, func(t *testing.T) {
			raw := jsonOf(m)
			var mirrored scanned
			decoder := json.NewDecoder(bytes.NewReader(raw))
			decoder.DisallowUnknownFields()
			require.NoError(t, decoder.Decode(&mirrored))
			require.JSONEq(t, string(raw), string(jsonOf(mirrored)))
		})
	}
}
