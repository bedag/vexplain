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

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/yaml"

	inventoryv1alpha1 "github.com/bedag/vexplain/api/inventory/v1alpha1"
	"github.com/bedag/vexplain/internal/inventory"
	"github.com/bedag/vexplain/internal/matchapi"
	"github.com/bedag/vexplain/internal/rules"
	"github.com/bedag/vexplain/internal/scan/result"
)

// These tests cover the evaluation of the measurement: how a case's answer is read from its sheet, how the
// answer without the known-exploited override is rebuilt, how answers are compared with the known ones, and
// what the tool prints and exits with. A false "not affected" is the error that the tool exists to find, so
// most of the tests below are about when it must say so.

const (
	// cve is the target CVE of the tests, otherCVE one that no catalog lists, and fixedCVE one that has a fix.
	cve        = "CVE-2026-111497"
	otherCVE   = "CVE-2020-0001"
	fixedCVE   = "CVE-2020-0002"
	registryAt = "localhost:5001"
	arm64      = "linux/arm64"
	version    = "1.0.9-r1"

	// Grype's words for severities, as the matcher passes them on. Those for fixes are in main.go.
	grypeCritical = "Critical"
	grypeHigh     = "High"
	grypeMedium   = "Medium"

	// The packages of the fixtures: a library, a command that links it, and something else.
	libsID   = "pkg-libs"
	cliID    = "pkg-cli"
	otherID  = "pkg-other"
	libsName = "brotli-libs"
	cliName  = "brotli"
	otherPkg = "busybox"
	cliPath  = "/usr/bin/brotli"
	typeAPK  = "apk"

	// The names of cases, and the texts that the tests look for.
	nameInstalled   = "installed-not-linked"
	nameLinked      = "linked"
	nameScratch     = "scratch"
	nameStatic      = "static-copy"
	flagCases       = "--cases"
	flagRegistry    = "--registry"
	flagTimeout     = "--timeout"
	sleepProgram    = "sleep"
	fieldWithoutKEV = "expectedWithoutKEV"
	noCases         = "no cases"
	rowOK           = "ok"
)

const (
	suppressed      = inventoryv1alpha1.OutcomeSuppressed
	tracked         = inventoryv1alpha1.OutcomeTracked
	needsAssessment = inventoryv1alpha1.OutcomeNeedsAssessment
)

// The answers as the cases file writes them.
var (
	answerTracked         = string(tracked)
	answerSuppressed      = string(suppressed)
	answerNeedsAssessment = string(needsAssessment)
)

var defaultSettings = rules.Settings{MinCompletenessPercent: 90}

// ---- fixtures ----

func digestOf(seed string) string {
	sum := sha256.Sum256([]byte(seed))
	return "sha256:" + hex.EncodeToString(sum[:])
}

type artifact struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Version string `json:"version"`
	Type    string `json:"type"`
}

func sbomOf(artifacts ...artifact) json.RawMessage {
	raw, err := json.Marshal(struct {
		Artifacts []artifact `json:"artifacts"`
	}{artifacts})
	if err != nil {
		panic(err)
	}
	return raw
}

// brotliEvidence is the evidence of an Alpine image with the three Brotli libraries in one package, the
// brotli command in another when withCLI is set, and a third package that owns an executable. Nothing
// reaches or names the libraries unless reachedBy says what does. Packages account for every ELF file.
func brotliEvidence(digest string, withCLI bool, reachedBy ...string) result.Manifest {
	libraries := make([]result.Library, 0, 3)
	for _, soname := range []string{"libbrotlicommon.so.1", "libbrotlidec.so.1", "libbrotlienc.so.1"} {
		libraries = append(libraries, result.Library{
			Path: "/usr/lib/" + soname, Soname: soname, PackageID: libsID,
			ReachedBy: reachedBy, ReachedCount: len(reachedBy),
		})
	}
	artifacts := []artifact{
		{ID: libsID, Name: libsName, Version: version, Type: typeAPK},
		{ID: otherID, Name: otherPkg, Version: "1.31.1-r22", Type: typeAPK},
	}
	facts := []result.PackageFacts{
		{ID: libsID, FilesListed: 6, FilesPresent: 6, SharedLibraries: 3},
		{ID: otherID, FilesListed: 10, FilesPresent: 10, OtherELFFiles: 1},
	}
	elfFiles := 4
	if withCLI {
		artifacts = append(artifacts, artifact{ID: cliID, Name: cliName, Version: version, Type: typeAPK})
		facts = append(facts, result.PackageFacts{ID: cliID, FilesListed: 1, FilesPresent: 1, OtherELFFiles: 1})
		elfFiles++
	}
	return result.Manifest{
		Platform: arm64, Digest: digest, SBOM: sbomOf(artifacts...), Packages: facts,
		ELF: result.ELFSummary{Total: elfFiles, Owned: elfFiles}, Libraries: libraries,
	}
}

// exploitedMatch is the matcher's match of the target CVE in a package, which the catalog of known exploited
// vulnerabilities lists.
func exploitedMatch(packageID, packageName string) matchapi.Match {
	return matchapi.Match{
		VulnerabilityID: cve, PackageID: packageID, Severity: grypeCritical, FixState: grypeUnknown,
		KnownExploited: true, PackageName: packageName, PackageVersion: version, PackageType: typeAPK,
	}
}

// otherMatches are two more vulnerabilities that no catalog lists: one in the library package, with a fix, and
// one in the package that owns an executable.
func otherMatches() []matchapi.Match {
	return []matchapi.Match{
		{
			VulnerabilityID: fixedCVE, PackageID: libsID, Severity: grypeMedium, FixState: grypeFixed,
			FixedVersions: []string{"1.0.9-r2"}, PackageName: libsName, PackageVersion: version, PackageType: typeAPK,
		},
		{
			VulnerabilityID: otherCVE, PackageID: otherID, Severity: grypeHigh, FixState: grypeNotFixed,
			PackageName: otherPkg, PackageVersion: "1.31.1-r22", PackageType: typeAPK,
		},
	}
}

// findingsOf returns what the rules make of the matches of a manifest.
func findingsOf(ev result.Manifest, matches ...matchapi.Match) []inventoryv1alpha1.Finding {
	return rules.Evaluate(ev, matches, defaultSettings)
}

func indexOf(t *testing.T, findings []inventoryv1alpha1.Finding, vulnerability, packageID string) int {
	t.Helper()
	for i, f := range findings {
		if f.VulnerabilityID == vulnerability && f.Package.ID == packageID {
			return i
		}
	}
	require.FailNow(t, "no finding", "%s in %s", vulnerability, packageID)
	return -1
}

// targetIn returns the finding of the target CVE in a package.
func targetIn(t *testing.T, findings []inventoryv1alpha1.Finding, packageID string) inventoryv1alpha1.Finding {
	t.Helper()
	return findings[indexOf(t, findings, cve, packageID)]
}

// ---- the cases file ----

const sha = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// goodCases has one case of each kind: one that is built, and one that is copied.
const goodCases = `
targetCVE: CVE-2026-111497
approved: false
cases:
  - name: installed-not-linked
    build: images/installed-not-linked
    expected: Tracked
    expectedWithoutKEV: Suppressed
    basis: "apk info shows brotli-libs; readelf finds no DT_NEEDED on it; no file names it"
  - name: node
    image: docker.io/library/node@` + sha + `
    package: libbrotli1
    command: ["sleep", "3600"]
    expected: NotFound
    expectedWithoutKEV: NotFound
    basis: "no Brotli package; the node binary bundles a copy"
`

func TestParseCases(t *testing.T) {
	file, err := parseCases([]byte(goodCases))

	require.NoError(t, err)
	require.Equal(t, cve, file.TargetCVE)
	require.False(t, file.Approved)
	require.Len(t, file.Cases, 2)
	require.Equal(t, testCase{
		Name: nameInstalled, Build: "images/installed-not-linked", Expected: answerTracked,
		ExpectedWithoutKEV: answerSuppressed,
		Basis:              "apk info shows brotli-libs; readelf finds no DT_NEEDED on it; no file names it",
	}, file.Cases[0])
	require.Equal(t, "docker.io/library/node@"+sha, file.Cases[1].Image)
	require.Equal(t, []string{debianLibrary}, file.Cases[1].libraryPackages())
	require.Equal(t, []string{sleepProgram, "3600"}, file.Cases[1].Command)
	require.Equal(t, []string{libsName, debianLibrary}, file.Cases[0].libraryPackages(),
		"a case that names no library package takes the two names of the distributions")
}

func TestParseCasesRejectsWhatCannotBeMeasured(t *testing.T) {
	edit := func(from, to string) string {
		require.Contains(t, goodCases, from)
		return strings.Replace(goodCases, from, to, 1)
	}
	const bothOrNeither = "exactly one of build and image"
	tracked2suppressed := "expected: Tracked\n    expectedWithoutKEV: Suppressed"
	notFound2notFound := "expected: NotFound\n    expectedWithoutKEV: NotFound"
	for what, tc := range map[string]struct{ yaml, want string }{
		"an unknown field":            {edit("approved: false", "approved: false\nsurprise: 1"), "surprise"},
		"no target CVE":               {edit("targetCVE: CVE-2026-111497\n", ""), "targetCVE"},
		"a target that is no CVE":     {edit("CVE-2026-111497", "GHSA-1234"), "targetCVE"},
		"no cases":                    {"targetCVE: CVE-2026-111497\ncases: []\n", noCases},
		"a name twice":                {edit("name: node", "name: installed-not-linked"), "twice"},
		"a name that is no DNS label": {edit("name: node", "name: Not_A_Label"), "Not_A_Label"},
		"build and image":             {edit("    package:", "    build: images/x\n    package:"), bothOrNeither},
		"neither build nor image":     {edit("    build: images/installed-not-linked\n", ""), bothOrNeither},
		"an image that is not pinned": {edit("node@"+sha, "node:24-slim"), "digest"},
		"an unknown expected answer":  {edit("expected: Tracked", "expected: Maybe"), "expected"},
		"an answer of None":           {edit("expected: Tracked", "expected: None"), "expected"},
		"Tracked without the override": {
			edit("expectedWithoutKEV: Suppressed", "expectedWithoutKEV: Tracked"), fieldWithoutKEV,
		},
		"no basis": {
			edit("    basis: \"no Brotli package; the node binary bundles a copy\"\n", ""), "basis",
		},
		"a finding that changes by itself": {
			edit(tracked2suppressed, "expected: Suppressed\n    expectedWithoutKEV: NeedsAssessment"), fieldWithoutKEV,
		},
		"no finding that turns into one": {
			edit(notFound2notFound, "expected: NotFound\n    expectedWithoutKEV: Suppressed"), fieldWithoutKEV,
		},
		"a finding that vanishes": {
			edit(tracked2suppressed, "expected: Tracked\n    expectedWithoutKEV: NotFound"), fieldWithoutKEV,
		},
	} {
		t.Run(what, func(t *testing.T) {
			_, err := parseCases([]byte(tc.yaml))
			require.ErrorContains(t, err, tc.want)
		})
	}
}

func TestEveryPairOfAnswersThatTheRulesCanGiveIsAccepted(t *testing.T) {
	for _, pair := range [][2]string{
		{answerTracked, answerSuppressed}, {answerTracked, answerNeedsAssessment},
		{answerSuppressed, answerSuppressed}, {answerNeedsAssessment, answerNeedsAssessment},
		{answerNotFound, answerNotFound}, {answerNoPackage, answerNoPackage},
	} {
		yml := strings.NewReplacer("expected: Tracked", "expected: "+pair[0],
			"expectedWithoutKEV: Suppressed", "expectedWithoutKEV: "+pair[1]).Replace(goodCases)
		_, err := parseCases([]byte(yml))
		require.NoError(t, err, "%v", pair)
	}
}

func TestReadCasesFindsTheDockerfileOfEveryBuild(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cases.yaml")
	require.NoError(t, os.WriteFile(path, []byte(goodCases), 0o600))

	_, err := readCases(path)
	require.ErrorContains(t, err, nameInstalled)
	require.ErrorContains(t, err, "Dockerfile")

	build := filepath.Join(dir, "images", nameInstalled)
	require.NoError(t, os.MkdirAll(build, 0o750))
	require.NoError(t, os.WriteFile(filepath.Join(build, "Dockerfile"), []byte("FROM scratch\n"), 0o600))
	file, err := readCases(path)

	require.NoError(t, err)
	require.Equal(t, build, file.Cases[0].Build,
		"the directory of a build is read from the place of the cases file, wherever the tool runs")
}

func TestTheShippedCasesAreValid(t *testing.T) {
	file, err := readCases("cases.yaml")

	require.NoError(t, err)
	require.Equal(t, cve, file.TargetCVE)
	require.NotEmpty(t, file.Cases)
}

// ---- the answers ----

func TestCompare(t *testing.T) {
	for _, tc := range []struct {
		expected, actual string
		want             check
	}{
		{answerTracked, answerTracked, checkMatches},
		{answerSuppressed, answerSuppressed, checkMatches},
		{answerNeedsAssessment, answerNeedsAssessment, checkMatches},
		{answerNotFound, answerNone, checkMatches},
		{answerNoPackage, answerNone, checkMatches},

		// A difference that errs towards a person looking is a difference, and no worse.
		{answerSuppressed, answerNeedsAssessment, checkDiffers},
		{answerSuppressed, answerTracked, checkDiffers},
		{answerSuppressed, answerNone, checkDiffers},
		{answerTracked, answerNeedsAssessment, checkDiffers},
		{answerTracked, answerNone, checkDiffers},
		{answerNotFound, answerTracked, checkDiffers},
		{answerNoPackage, answerNeedsAssessment, checkDiffers},

		// An answer of "not affected" where the known answer is anything else is the worst error.
		{answerTracked, answerSuppressed, checkFalseNotAffected},
		{answerNeedsAssessment, answerSuppressed, checkFalseNotAffected},
		{answerNotFound, answerSuppressed, checkFalseNotAffected},
		{answerNoPackage, answerSuppressed, checkFalseNotAffected},
	} {
		require.Equal(t, tc.want, compare(tc.expected, tc.actual), "%s expected, %s actual", tc.expected, tc.actual)
	}
}

func TestAnswerOf(t *testing.T) {
	finding := func(o inventoryv1alpha1.Outcome) inventoryv1alpha1.Finding {
		return inventoryv1alpha1.Finding{Outcome: o}
	}

	require.Equal(t, answerNone, answerOf(nil))
	require.Equal(t, answerTracked, answerOf([]inventoryv1alpha1.Finding{finding(tracked)}))
	require.Equal(t, answerSuppressed, answerOf([]inventoryv1alpha1.Finding{finding(suppressed), finding(suppressed)}))

	// Two manifests that disagree: the answer is the one that keeps a finding open, so that a "not
	// affected" is never what the case says when any manifest says something else.
	require.Equal(t, answerTracked,
		answerOf([]inventoryv1alpha1.Finding{finding(suppressed), finding(tracked), finding(needsAssessment)}))
	require.Equal(t, answerNeedsAssessment,
		answerOf([]inventoryv1alpha1.Finding{finding(suppressed), finding(needsAssessment)}))
}

func TestLibraryFindingsDecideAndOtherBrotliPackagesOnlyAppear(t *testing.T) {
	ev := brotliEvidence(digestOf(nameLinked), true, cliPath)
	findings := findingsOf(ev, append(otherMatches(), exploitedMatch(libsID, libsName), exploitedMatch(cliID, cliName))...)
	names := []string{libsName, debianLibrary}

	library := libraryFindings(findings, cve, names)
	require.Len(t, library, 1)
	require.Equal(t, libsID, library[0].Package.ID)

	others := otherBrotliFindings(findings, cve, names)
	require.Len(t, others, 1)
	require.Equal(t, cliName, others[0].Package.Name, "the command package has a finding of its own, and doesn't decide")

	require.Empty(t, libraryFindings(findings, cve, []string{debianLibrary}),
		"a package of another name is not the library")
	require.Empty(t, libraryFindings(findings, "CVE-2020-9999", []string{libsName}), "only the target CVE counts")
	byName := libraryFindings(findings, cve, []string{cliName})
	require.Len(t, byName, 1, "a case can name its library package")
	require.Equal(t, cliName, byName[0].Package.Name)
}

// ---- the answer without the known-exploited override ----

func TestWithoutOverrideSettlesWhatTheLaterRulesSettle(t *testing.T) {
	// Nothing reaches or names the libraries, so the load check settles the finding that the catalog took first.
	ev := brotliEvidence(digestOf(nameInstalled), false)
	findings := findingsOf(ev, append(otherMatches(), exploitedMatch(libsID, libsName))...)
	recorded := targetIn(t, findings, libsID)
	require.Equal(t, tracked, recorded.Outcome)
	require.Equal(t, inventoryv1alpha1.RuleKnownExploited, ptr.Deref(recorded.Rule, ""))

	got, err := withoutOverride(ev, findings, defaultSettings)

	require.NoError(t, err)
	require.Len(t, got, len(findings))
	target := targetIn(t, got, libsID)
	require.Equal(t, suppressed, target.Outcome)
	require.Equal(t, inventoryv1alpha1.RuleLoadCheck, ptr.Deref(target.Rule, ""))
	require.Equal(t, inventoryv1alpha1.JustificationVulnerableCodeNotInExecutePath, ptr.Deref(target.Justification, ""))
	require.Equal(t, []inventoryv1alpha1.FindingCondition{inventoryv1alpha1.FindingConditionNoPreloadEnvironment},
		target.Conditions)
	require.Equal(t, inventoryv1alpha1.SeverityCritical, target.Severity,
		"the rebuild keeps what the sheet says of the finding")
	// Every finding that the catalog did not take keeps its answer, and everything else about it.
	for i, f := range findings {
		if ptr.Deref(f.Rule, "") != inventoryv1alpha1.RuleKnownExploited {
			require.Equal(t, f, got[i], "%s in %s", f.VulnerabilityID, f.Package.Name)
		}
	}
}

func TestWithoutOverrideKeepsAFindingOpenThatSomethingReaches(t *testing.T) {
	ev := brotliEvidence(digestOf(nameLinked), true, cliPath)
	findings := findingsOf(ev, exploitedMatch(libsID, libsName), exploitedMatch(cliID, cliName))

	got, err := withoutOverride(ev, findings, defaultSettings)

	require.NoError(t, err)
	library := targetIn(t, got, libsID)
	require.Equal(t, needsAssessment, library.Outcome)
	require.Equal(t, inventoryv1alpha1.RuleLoadCheck, ptr.Deref(library.Rule, ""))
	require.Equal(t, "reached by "+cliPath, ptr.Deref(library.Reason, ""))
	// The command package owns an executable, which no rule settles.
	command := targetIn(t, got, cliID)
	require.Equal(t, needsAssessment, command.Outcome)
	require.Nil(t, command.Rule)
}

func TestWithoutOverrideAppliesTheGuardOfTheHub(t *testing.T) {
	// Packages account for half of the ELF files, so no rule may settle a finding as not affected.
	ev := brotliEvidence(digestOf("guarded"), false)
	ev.ELF = result.ELFSummary{Total: 8, Owned: 4}
	findings := findingsOf(ev, exploitedMatch(libsID, libsName))

	got, err := withoutOverride(ev, findings, defaultSettings)

	require.NoError(t, err)
	require.Equal(t, needsAssessment, got[0].Outcome)
	require.Equal(t, inventoryv1alpha1.RuleCompletenessGuard, ptr.Deref(got[0].Rule, ""))

	loose, err := withoutOverride(ev, findings, rules.Settings{MinCompletenessPercent: 0})
	require.NoError(t, err)
	require.Equal(t, suppressed, loose[0].Outcome, "the settings of the hub are the ones that count")
}

func TestTheRebuildGivesBackEveryFindingOfTheRules(t *testing.T) {
	// Each fix state, with and without versions, and a package that the SBOM doesn't name: whatever the rules
	// read from a finding, the rebuilt match carries.
	ev := brotliEvidence(digestOf("rebuild"), false)
	matches := make([]matchapi.Match, 0, 6)
	for i, fix := range []string{grypeFixed, grypeNotFixed, grypeWontFix, grypeUnknown, ""} {
		var versions []string
		if fix == grypeFixed {
			versions = []string{"1.0.9-r3", "1.0.9-r2"}
		}
		matches = append(matches, matchapi.Match{
			VulnerabilityID: "CVE-2021-000" + strconv.Itoa(i+1), PackageID: libsID, Severity: grypeHigh, FixState: fix,
			FixedVersions: versions, KnownExploited: i%2 == 0, PackageName: libsName, PackageVersion: version,
			PackageType: typeAPK,
		})
	}
	matches = append(matches, matchapi.Match{
		VulnerabilityID: "CVE-2021-0009", PackageID: "pkg-not-in-the-sbom", Severity: "Low", FixState: grypeFixed,
		FixedVersions: []string{"2.0"}, PackageName: "ghost", PackageType: "deb",
	})
	for _, f := range findingsOf(ev, matches...) {
		exploited := ptr.Deref(f.Rule, "") == inventoryv1alpha1.RuleKnownExploited
		again := rules.Evaluate(ev, []matchapi.Match{matchFrom(f, exploited)}, defaultSettings)
		require.Equal(t, []inventoryv1alpha1.Finding{f}, again, "%s in %s", f.VulnerabilityID, f.Package.Name)
	}
}

func TestWithoutOverrideStopsWhenARebuildDoesNotGiveBackTheSheet(t *testing.T) {
	// The sheet says a finding is suppressed by the load check, and the evidence says that /usr/bin/brotli reaches
	// the library. The rebuild lost an input, or the sheet came from other rules. Either way the second column
	// would be wrong, and nobody would see it.
	ev := brotliEvidence(digestOf(nameLinked), true, cliPath)
	findings := findingsOf(ev, exploitedMatch(libsID, libsName), otherMatches()[0])
	i := indexOf(t, findings, fixedCVE, libsID)
	require.Equal(t, needsAssessment, findings[i].Outcome)
	findings[i].Outcome = suppressed
	findings[i].Justification = ptr.To(inventoryv1alpha1.JustificationVulnerableCodeNotInExecutePath)
	findings[i].Reason = nil

	_, err := withoutOverride(ev, findings, defaultSettings)

	require.Error(t, err)
	require.ErrorContains(t, err, fixedCVE)
	require.ErrorContains(t, err, libsName)
	require.ErrorContains(t, err, answerSuppressed)
	require.ErrorContains(t, err, answerNeedsAssessment)
}

func TestWithoutOverrideChecksTheFindingsTheCatalogDecidedToo(t *testing.T) {
	// A finding that the catalog decided is rebuilt with the flag set, and must come back as it is on the sheet.
	ev := brotliEvidence(digestOf(nameLinked), false)
	findings := findingsOf(ev, exploitedMatch(libsID, libsName))
	findings[0].Outcome = needsAssessment // the sheet says something else than the rules make of its inputs

	_, err := withoutOverride(ev, findings, defaultSettings)

	require.ErrorContains(t, err, cve)
}

// ---- the totals ----

func TestTallyCountsByOutcomeSeverityFixStateAndRule(t *testing.T) {
	const critical, high = inventoryv1alpha1.SeverityCritical, inventoryv1alpha1.SeverityHigh
	const low = inventoryv1alpha1.SeverityLow
	const fixed, notFixed = inventoryv1alpha1.FixStateFixed, inventoryv1alpha1.FixStateNotFixed
	const wontFix, unknown = inventoryv1alpha1.FixStateWontFix, inventoryv1alpha1.FixStateUnknown
	const loadCheck, exploited = inventoryv1alpha1.RuleLoadCheck, inventoryv1alpha1.RuleKnownExploited
	finding := func(o inventoryv1alpha1.Outcome, s inventoryv1alpha1.Severity, f inventoryv1alpha1.FixState,
		rule ...inventoryv1alpha1.Rule) inventoryv1alpha1.Finding {
		found := inventoryv1alpha1.Finding{Outcome: o, Severity: s, FixState: f}
		if len(rule) > 0 {
			found.Rule = &rule[0]
		}
		return found
	}
	got := tally([]inventoryv1alpha1.Finding{
		finding(needsAssessment, critical, fixed), finding(needsAssessment, high, fixed, loadCheck),
		finding(needsAssessment, high, notFixed), finding(tracked, critical, unknown, exploited),
		finding(suppressed, low, wontFix, loadCheck), finding(suppressed, high, fixed, loadCheck),
	})

	require.Equal(t, 6, got.total)
	require.Equal(t, map[inventoryv1alpha1.Outcome]int{needsAssessment: 3, tracked: 1, suppressed: 2}, got.outcome)
	require.Equal(t, map[inventoryv1alpha1.Severity]int{critical: 2, high: 3, low: 1}, got.severity)
	require.Equal(t, map[inventoryv1alpha1.FixState]int{fixed: 3, notFixed: 1, unknown: 1, wontFix: 1}, got.fixState)
	// The residual, the findings that wait for an assessment, labelled by severity and by fix state.
	require.Equal(t, map[inventoryv1alpha1.Severity]int{critical: 1, high: 2}, got.outcomeBySeverity[needsAssessment])
	require.Equal(t, map[inventoryv1alpha1.FixState]int{fixed: 2, notFixed: 1}, got.outcomeByFixState[needsAssessment])
	require.Equal(t, 1, got.outcomeByFixState[suppressed][wontFix])
	// What decided each outcome: no rule is the empty one.
	require.Equal(t, map[inventoryv1alpha1.Rule]int{"": 2, loadCheck: 1}, got.outcomeByRule[needsAssessment])
	require.Equal(t, map[inventoryv1alpha1.Rule]int{loadCheck: 2}, got.outcomeByRule[suppressed])
	require.Equal(t, map[inventoryv1alpha1.Rule]int{exploited: 1}, got.outcomeByRule[tracked])
}

func TestTallyOfNothingIsZero(t *testing.T) {
	got := tally(nil)

	require.Zero(t, got.total)
	require.Zero(t, got.outcome[needsAssessment])
	require.Zero(t, got.outcomeBySeverity[needsAssessment][inventoryv1alpha1.SeverityHigh])
}

func TestSizesAreCountedAgainstTheTrigger(t *testing.T) {
	require.Equal(t, "0%", against(0))
	require.Equal(t, "50%", against(256*1024))
	require.Equal(t, "99%", against(512*1024-1), "rounded down: a size under the trigger never says 100%")
	require.Equal(t, "100%", against(512*1024), "a size at the trigger is not over it")
	require.Equal(t, "100% OVER", against(512*1024+1))
	require.Equal(t, "250% OVER", against(1280*1024))
}

// ---- the images ----

func TestPushedDigestIsTheDigestOfTheOutputOfDockerPush(t *testing.T) {
	output := "The push refers to repository [localhost:5001/linked]\n" +
		"e2e: digest: sha256:" + strings.Repeat("ab", 32) + " size: 527\n"
	got, ok := pushedDigest(output)

	require.True(t, ok)
	require.Equal(t, "sha256:"+strings.Repeat("ab", 32), got)

	_, ok = pushedDigest("denied: requested access to the resource is denied\n")
	require.False(t, ok)
}

// parse returns the reference that a string names.
func parse(t *testing.T, reference string) name.Reference {
	t.Helper()
	parsed, err := name.ParseReference(reference)
	require.NoError(t, err)
	return parsed
}

func newRegistry(t *testing.T) string {
	t.Helper()
	server := httptest.NewServer(registry.New(registry.Logger(log.New(io.Discard, "", 0))))
	t.Cleanup(server.Close)
	return strings.TrimPrefix(server.URL, "http://")
}

func TestCopyImageKeepsTheDigestOfAnIndexAndOfItsPlatforms(t *testing.T) {
	from, to := newRegistry(t), newRegistry(t)
	index, err := random.Index(256, 1, 2)
	require.NoError(t, err)
	indexDigest, err := index.Digest()
	require.NoError(t, err)
	require.NoError(t, remote.WriteIndex(parse(t, from+"/src:v1"), index))
	manifest, err := index.IndexManifest()
	require.NoError(t, err)

	ctx := context.Background()
	require.NoError(t, copyImage(ctx, from+"/src@"+indexDigest.String(), to+"/case@"+indexDigest.String()))
	// A second copy finds the image there, and goes on.
	require.NoError(t, copyImage(ctx, from+"/src@"+indexDigest.String(), to+"/case@"+indexDigest.String()))

	got, err := remote.Head(parse(t, to+"/case@"+indexDigest.String()))
	require.NoError(t, err)
	require.Equal(t, indexDigest, got.Digest, "an index that was copied has the digest that it had")
	for _, entry := range manifest.Manifests {
		child, err := remote.Head(parse(t, to+"/case@"+entry.Digest.String()))
		require.NoError(t, err)
		require.Equal(t, entry.Digest, child.Digest)
	}
}

func TestCopyImageFailsForAnImageThatIsNotThere(t *testing.T) {
	host := newRegistry(t)

	err := copyImage(context.Background(), host+"/missing@"+digestOf("nothing"), host+"/case@"+digestOf("nothing"))

	require.Error(t, err)
}

func TestDeploymentRunsTheCaseWithACommandThatKeepsItAlive(t *testing.T) {
	deployment := deploymentFor(testCase{Name: nameLinked}, registryAt+"/linked@"+sha)

	require.Equal(t, nameLinked, deployment.Name)
	require.Equal(t, namespaceName, deployment.Namespace)
	require.Equal(t, ptr.To(int32(1)), deployment.Spec.Replicas)
	require.Equal(t, map[string]string{"app": nameLinked}, deployment.Spec.Selector.MatchLabels)
	pod := deployment.Spec.Template.Spec
	require.Len(t, pod.Containers, 1)
	require.Equal(t, registryAt+"/linked@"+sha, pod.Containers[0].Image)
	require.Equal(t, []string{sleepProgram, "86400"}, pod.Containers[0].Command, "no server of the image starts")
	require.Equal(t, ptr.To(false), pod.AutomountServiceAccountToken)
	require.Equal(t, ptr.To(int64(1)), pod.TerminationGracePeriodSeconds)

	own := deploymentFor(testCase{Name: nameStatic, Command: []string{"/static-copy"}}, registryAt+"/static-copy@"+sha)
	require.Equal(t, []string{"/static-copy"}, own.Spec.Template.Spec.Containers[0].Command,
		"an image without sleep names its own program")
}

// ---- the whole tool, on a fake cluster ----

// world is a fake cluster whose stores hold what the operator would have made of the cases.
type world struct {
	t        *testing.T
	api      client.Client
	inv      inventory.Store
	packages inventory.PackagesStore
	verdicts inventory.VerdictsStore
	// beforePods, when set, runs before each time that the tool lists pods, which it does at every look at a case.
	// A test uses it to make something happen while the tool waits.
	beforePods func()
}

// hooked is the client of a world that has a hook: it calls beforePods before it lists pods.
type hooked struct {
	client.Client
	beforePods func()
}

func (h hooked) List(ctx context.Context, list client.ObjectList, opts ...client.ListOption) error {
	if _, isPods := list.(*corev1.PodList); isPods {
		h.beforePods()
	}
	return h.Client.List(ctx, list, opts...)
}

func newWorld(t *testing.T) *world {
	t.Helper()
	scheme, err := newScheme()
	require.NoError(t, err)
	api := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&inventoryv1alpha1.ImageInventory{}, &inventoryv1alpha1.ImageVerdicts{}).Build()
	noName := func() string { return "" }
	return &world{
		t: t, api: api,
		inv:      inventory.NewCRDStore(api, nil, noName),
		packages: inventory.NewCRDPackagesStore(api, nil, noName),
		verdicts: inventory.NewCRDVerdictsStore(api, noName),
	}
}

const (
	scannerImage = "example.com/vexplain-scanner:v0.0.1"
	databaseAt   = "v6.1.10+2026-10-30T06:23:28Z"
)

// plant stores what a scan of the case's image and a match of its packages leave behind: the image's
// ImageInventory with its facts, the evidence of its one platform manifest, and the sheet. The manifest of
// the evidence is the image itself, as for an image that is no index. The scan ends seven seconds after the
// inventory first saw the image.
func (w *world) plant(caseName string, ev result.Manifest, matches ...matchapi.Match) {
	w.t.Helper()
	ctx := context.Background()
	w.observe(caseName, ev.Digest)
	scanned := w.firstSeen(ev.Digest).Add(7 * time.Second)

	require.NoError(w.t, w.packages.Put(ctx, scannerImage, scanned, ev))
	kept, omitted, counts := rules.Sheet(rules.Evaluate(ev, matches, defaultSettings))
	require.NoError(w.t, w.verdicts.Put(ctx, ev.Digest, inventoryv1alpha1.ImageVerdictsStatus{
		DatabaseVersion: ptr.To(databaseAt), ScannerImage: ptr.To(scannerImage),
		Findings: kept, OmittedFindings: ptr.To(omitted), Counts: &counts,
	}))
	completeness := ev.Completeness()
	// The facts come last, as the runner writes them, so that whoever sees them can rely on the rest.
	_, err := w.inv.SetFacts(ctx, ev.Digest, &inventoryv1alpha1.ImageFacts{
		ScannerImage: ptr.To(scannerImage), ScannedTime: ptr.To(metav1.NewTime(scanned)),
		Platforms: []inventoryv1alpha1.PlatformFacts{{
			Platform: ev.Platform, ManifestDigest: ev.Digest, CompletenessPercent: &completeness,
			ELFFiles: ptr.To(int32(ev.ELF.Total)), Packages: ptr.To(int32(len(ev.Packages))),
		}},
	})
	require.NoError(w.t, err)
}

// observe makes the ImageInventory of a digest, as the pod inventory does when a pod reports it.
func (w *world) observe(caseName, digest string) {
	w.t.Helper()
	require.NoError(w.t, w.inv.Observe(context.Background(), digest, inventory.Observation{
		Cluster: "local", ClusterID: "cluster-id", DigestKind: inventoryv1alpha1.DigestKindRepoDigest,
		Repositories: []string{registryAt + "/" + caseName}, NamespaceCount: 1,
	}))
}

func (w *world) firstSeen(digest string) time.Time {
	w.t.Helper()
	found, err := w.inv.Get(context.Background(), digest)
	require.NoError(w.t, err)
	require.NotNil(w.t, found)
	return found.Status.Clusters[0].FirstSeenTime.Time
}

// The planted images that most tests use, as the operator would have found them.
func (w *world) plantInstalledNotLinked() {
	ev := brotliEvidence(digestOf(nameInstalled), false)
	w.plant(nameInstalled, ev, append(otherMatches(), exploitedMatch(libsID, libsName))...)
}

func (w *world) plantLinked() {
	ev := brotliEvidence(digestOf(nameLinked), true, cliPath)
	w.plant(nameLinked, ev, append(otherMatches(), exploitedMatch(libsID, libsName), exploitedMatch(cliID, cliName))...)
}

func (w *world) plantNoPackages(caseName string) {
	w.plant(caseName, result.Manifest{
		Platform: arm64, Digest: digestOf(caseName), SBOM: sbomOf(), ELF: result.ELFSummary{Total: 1},
	})
}

// podOf returns a pod of a case that runs an image. It reports the digest, as the pod of an image that was pulled
// does, unless reported is empty, as for a pod that waits for its image.
func podOf(podName, caseName, image, reported string) *corev1.Pod {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: podName, Namespace: namespaceName, Labels: map[string]string{appLabel: caseName}},
		Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: containerName, Image: image}}},
	}
	if reported != "" {
		pod.Status.ContainerStatuses = []corev1.ContainerStatus{{
			Name: containerName, ImageID: registryAt + "/" + caseName + "@" + reported,
		}}
	}
	return pod
}

func caseOf(caseName, expected, withoutKEV string) testCase {
	return testCase{
		Name: caseName, Image: "docker.io/library/" + caseName + "@" + digestOf(caseName), Expected: expected,
		ExpectedWithoutKEV: withoutKEV, Basis: "worked out from the package database, readelf and a search",
	}
}

// writeCases writes a cases file for the tests, and returns its path.
func writeCases(t *testing.T, approved bool, cases ...testCase) string {
	t.Helper()
	raw, err := yaml.Marshal(caseFile{TargetCVE: cve, Approved: approved, Cases: cases})
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), "cases.yaml")
	require.NoError(t, os.WriteFile(path, raw, 0o600))
	return path
}

// run runs the tool on the world with the cases, and returns the exit code and the output. The images are
// "prepared" with the digests that the world planted, and a look at the stores takes a few milliseconds.
func (w *world) run(path string, args ...string) (int, string) {
	w.t.Helper()
	var out bytes.Buffer
	env := environment{
		connect: func() (client.Client, error) {
			if w.beforePods != nil {
				return hooked{Client: w.api, beforePods: w.beforePods}, nil
			}
			return w.api, nil
		},
		prepare: func(_ context.Context, _ string, cases []testCase, _ io.Writer) (map[string]string, error) {
			digests := map[string]string{}
			for _, c := range cases {
				digests[c.Name] = digestOf(c.Name)
			}
			return digests, nil
		},
		poll: 5 * time.Millisecond,
	}
	all := append([]string{flagCases, path, flagRegistry, registryAt, flagTimeout, "300ms"}, args...)
	code := run(context.Background(), all, &out, env)
	return code, out.String()
}

// sectionOf returns the text of a section of the output, from its heading to the next.
func sectionOf(t *testing.T, out, heading string) string {
	t.Helper()
	_, rest, found := strings.Cut(out, "== "+heading)
	require.True(t, found, "the output has no section %q:\n%s", heading, out)
	if next := strings.Index(rest, "\n== "); next >= 0 {
		rest = rest[:next]
	}
	return rest
}

// row finds the line of a section of the output that starts with the name of a case.
func row(t *testing.T, out, section, caseName string) string {
	t.Helper()
	for line := range strings.SplitSeq(sectionOf(t, out, section), "\n") {
		if strings.HasPrefix(line, caseName+" ") {
			return line
		}
	}
	require.FailNow(t, "no row", "section %q has no row for %s:\n%s", section, caseName, out)
	return ""
}

// fields splits a row of the output at its runs of spaces.
func fields(line string) []string {
	return regexp.MustCompile(`\s{2,}`).Split(strings.TrimSpace(line), -1)
}

const answersSection = "answers"

func TestRunReportsTheKnownAnswersOfEveryCase(t *testing.T) {
	w := newWorld(t)
	w.plantInstalledNotLinked()
	w.plantLinked()
	w.plantNoPackages(nameScratch)
	w.plantNoPackages(nameStatic)
	path := writeCases(t, false,
		caseOf(nameInstalled, answerTracked, answerSuppressed),
		caseOf(nameLinked, answerTracked, answerNeedsAssessment),
		caseOf(nameStatic, answerNotFound, answerNotFound),
		caseOf(nameScratch, answerNoPackage, answerNoPackage),
	)

	code, out := w.run(path)

	require.Equal(t, exitOK, code, out)
	require.Contains(t, out, "provisional", "while the known answers are not approved, the output says so")
	require.Contains(t, out, databaseAt, "the database of the sheets")
	require.Contains(t, out, cve)

	// CASE, PLATFORM, LIBRARY, then the expected and the actual answer and the check, as built and then
	// without the known-exploited override, and the other Brotli findings.
	require.Equal(t, []string{nameInstalled, arm64, libsName, answerTracked, answerTracked, rowOK,
		answerSuppressed, answerSuppressed, rowOK, "-"}, fields(row(t, out, answersSection, nameInstalled)))
	require.Equal(t, []string{nameLinked, arm64, libsName, answerTracked, answerTracked, rowOK,
		answerNeedsAssessment, answerNeedsAssessment, rowOK, "brotli:Tracked"},
		fields(row(t, out, answersSection, nameLinked)), "the command package's finding appears, and doesn't decide")
	require.Equal(t, []string{nameStatic, arm64, "-", answerNotFound, answerNone, rowOK,
		answerNotFound, answerNone, rowOK, "-"}, fields(row(t, out, answersSection, nameStatic)))
	require.Equal(t, []string{nameScratch, arm64, "-", answerNoPackage, answerNone, rowOK,
		answerNoPackage, answerNone, rowOK, "-"}, fields(row(t, out, answersSection, nameScratch)))
	require.Contains(t, out, "as built: 4 of 4 as expected, 0 differ, 0 false not-affected")
	require.Contains(t, out, "without the override: 4 of 4 as expected, 0 differ, 0 false not-affected")
}

func TestRunApprovedKnownAnswersAreNotCalledProvisional(t *testing.T) {
	w := newWorld(t)
	w.plantNoPackages(nameScratch)
	path := writeCases(t, true, caseOf(nameScratch, answerNoPackage, answerNoPackage))

	code, out := w.run(path)

	require.Equal(t, exitOK, code, out)
	require.NotContains(t, out, "provisional")
	require.Contains(t, out, "approved")
}

func TestRunDeploysOneDeploymentPerCaseInItsNamespace(t *testing.T) {
	w := newWorld(t)
	w.plantNoPackages(nameScratch)
	own := caseOf(nameScratch, answerNoPackage, answerNoPackage)
	own.Command = []string{"/pause"}
	path := writeCases(t, false, own)

	code, out := w.run(path)

	require.Equal(t, exitOK, code, out)
	var deployment appsv1.Deployment
	key := client.ObjectKey{Namespace: namespaceName, Name: nameScratch}
	require.NoError(t, w.api.Get(context.Background(), key, &deployment))
	require.Equal(t, registryAt+"/scratch@"+digestOf(nameScratch), deployment.Spec.Template.Spec.Containers[0].Image)
	require.Equal(t, []string{"/pause"}, deployment.Spec.Template.Spec.Containers[0].Command)
	var namespace corev1.Namespace
	require.NoError(t, w.api.Get(context.Background(), client.ObjectKey{Name: namespaceName}, &namespace))

	// A second run, as after a failed one, finds the deployments there and goes on.
	code, out = w.run(path)
	require.Equal(t, exitOK, code, out)
}

func TestRunExitsWithOneOnAFalseNotAffected(t *testing.T) {
	w := newWorld(t)
	w.plantInstalledNotLinked()
	// The known answer says that something loads the library, and the rules suppress the finding.
	path := writeCases(t, false, caseOf(nameInstalled, answerTracked, answerNeedsAssessment))

	code, out := w.run(path)

	require.Equal(t, exitFailure, code, out)
	line := row(t, out, answersSection, nameInstalled)
	require.Contains(t, line, "FALSE NOT-AFFECTED")
	require.Equal(t, 1, strings.Count(line, "FALSE NOT-AFFECTED"),
		"the column as built is fine, and only the second is not")
	require.Contains(t, out, "as built: 1 of 1 as expected, 0 differ, 0 false not-affected")
	require.Contains(t, out, "without the override: 0 of 1 as expected, 0 differ, 1 false not-affected")
}

func TestRunCallsASuppressionAsBuiltAFalseNotAffectedToo(t *testing.T) {
	w := newWorld(t)
	// The catalog doesn't list the vulnerability, so the rules as built suppress it. The known answer for the
	// column as built is Tracked.
	unlisted := exploitedMatch(libsID, libsName)
	unlisted.KnownExploited = false
	w.plant(nameInstalled, brotliEvidence(digestOf(nameInstalled), false), unlisted)
	path := writeCases(t, false, caseOf(nameInstalled, answerTracked, answerSuppressed))

	code, out := w.run(path)

	require.Equal(t, exitFailure, code, out)
	require.Contains(t, row(t, out, answersSection, nameInstalled), "FALSE NOT-AFFECTED")
	require.Contains(t, out, "as built: 0 of 1 as expected, 0 differ, 1 false not-affected")
}

func TestRunCountsADifferenceThatIsNotAFalseNotAffected(t *testing.T) {
	w := newWorld(t)
	w.plantLinked()
	// The known answer says that nothing loads the library, and the rules keep the finding open, because
	// /usr/bin/brotli reaches it. The finding is more careful than the known answer. No exit with 1.
	path := writeCases(t, false, caseOf(nameLinked, answerTracked, answerSuppressed))

	code, out := w.run(path)

	require.Equal(t, exitOK, code, out)
	require.Contains(t, row(t, out, answersSection, nameLinked), "DIFFERS")
	require.Contains(t, out, "without the override: 0 of 1 as expected, 1 differ, 0 false not-affected")
}

func TestRunReportsACaseWhoseSheetNeverComesAndExitsWithOne(t *testing.T) {
	w := newWorld(t)
	w.plantNoPackages(nameScratch)
	// The pod's image was seen, and the scan done, but the matcher never answered: there is no sheet.
	ev := brotliEvidence(digestOf(nameLinked), true, cliPath)
	w.observe(nameLinked, ev.Digest)
	require.NoError(t, w.packages.Put(context.Background(), scannerImage, time.Now(), ev))
	_, err := w.inv.SetFacts(context.Background(), ev.Digest, &inventoryv1alpha1.ImageFacts{
		ScannerImage: ptr.To(scannerImage),
		Platforms:    []inventoryv1alpha1.PlatformFacts{{Platform: ev.Platform, ManifestDigest: ev.Digest}},
	})
	require.NoError(t, err)
	path := writeCases(t, false,
		caseOf(nameLinked, answerTracked, answerNeedsAssessment), caseOf(nameScratch, answerNoPackage, answerNoPackage))

	code, out := w.run(path)

	require.Equal(t, exitFailure, code, "a measurement with a case missing is not a measurement")
	require.Regexp(t, `linked\s+no answer: timed out after 300ms, waiting for the sheet of linux/arm64`, out)
	require.Contains(t, row(t, out, answersSection, nameScratch), rowOK, "the other cases are still measured")
	require.Contains(t, out, "1 case without an answer")
}

func TestRunReportsAFailedScanWithItsReason(t *testing.T) {
	w := newWorld(t)
	w.observe(nameScratch, digestOf(nameScratch))
	_, err := w.inv.SetFacts(context.Background(), digestOf(nameScratch), &inventoryv1alpha1.ImageFacts{
		Failure: &inventoryv1alpha1.ScanFailure{
			Reason: inventoryv1alpha1.ScanFailureReasonNoMatchingPlatform, Time: ptr.To(metav1.Now()), Attempts: 1,
		},
	})
	require.NoError(t, err)
	path := writeCases(t, false, caseOf(nameScratch, answerNoPackage, answerNoPackage))

	code, out := w.run(path, flagTimeout, "10s")

	require.Equal(t, exitFailure, code, out)
	require.Regexp(t, `scratch\s+no answer: the scan failed with NoMatchingPlatform`, out,
		"a failed scan is not waited for until the timeout")
}

func TestRunReadsTheDigestThatThePodReports(t *testing.T) {
	w := newWorld(t)
	// The pod reports another digest than the one that the tool pinned: the digest of the index of the image,
	// and not of the platform manifest. The inventory has the digest that the pod reports.
	reported := digestOf("scratch-as-the-pod-reports-it")
	ev := result.Manifest{
		Platform: arm64, Digest: digestOf("scratch-platform-manifest"), SBOM: sbomOf(), ELF: result.ELFSummary{Total: 1},
	}
	w.observe(nameScratch, reported)
	scanned := w.firstSeen(reported).Add(3 * time.Second)
	ctx := context.Background()
	require.NoError(t, w.packages.Put(ctx, scannerImage, scanned, ev))
	require.NoError(t, w.verdicts.Put(ctx, ev.Digest, inventoryv1alpha1.ImageVerdictsStatus{
		DatabaseVersion: ptr.To("v1"), Counts: &inventoryv1alpha1.FindingCounts{
			Suppressed: ptr.To(int32(0)), Tracked: ptr.To(int32(0)), NeedsAssessment: ptr.To(int32(0)),
		},
	}))
	_, err := w.inv.SetFacts(ctx, reported, &inventoryv1alpha1.ImageFacts{
		ScannedTime: ptr.To(metav1.NewTime(scanned)),
		Platforms:   []inventoryv1alpha1.PlatformFacts{{Platform: ev.Platform, ManifestDigest: ev.Digest}},
	})
	require.NoError(t, err)
	pod := podOf("scratch-0", nameScratch, registryAt+"/scratch@"+digestOf(nameScratch), reported)
	require.NoError(t, w.api.Create(ctx, pod))
	path := writeCases(t, false, caseOf(nameScratch, answerNoPackage, answerNoPackage))

	code, out := w.run(path)

	require.Equal(t, exitOK, code, out)
	require.Contains(t, row(t, out, answersSection, nameScratch), rowOK)
}

func TestRunGradesTheImageThatItDeployedAndNotTheOneOfAnEarlierRun(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	// An earlier run deployed another image under the same name. While the Deployment rolls out the new image, the
	// pod of the earlier one keeps running, and reports its digest, for which the stores hold complete data.
	earlier := brotliEvidence(digestOf("linked-of-an-earlier-run"), true, cliPath)
	w.plant(nameLinked, earlier,
		append(otherMatches(), exploitedMatch(libsID, libsName), exploitedMatch(cliID, cliName))...)
	earlierImage := registryAt + "/linked@" + earlier.Digest
	require.NoError(t, w.api.Create(ctx, podOf("linked-earlier", nameLinked, earlierImage, earlier.Digest)))
	// The pod of the image that this run deployed hasn't pulled it yet, so it reports no digest. The scan of the
	// image, its evidence and its sheet come while the tool waits: the first two looks find nothing, and the third
	// finds them.
	deployed := digestOf(nameLinked)
	require.NoError(t, w.api.Create(ctx, podOf("linked-now", nameLinked, registryAt+"/linked@"+deployed, "")))
	looks := 0
	w.beforePods = func() {
		if looks++; looks == 3 {
			w.plantNoPackages(nameLinked)
		}
	}
	path := writeCases(t, false, caseOf(nameLinked, answerNoPackage, answerNoPackage))

	code, out := w.run(path)

	require.Equal(t, exitOK, code, out)
	// The image that was deployed has no package, so its answer is none, and not the Tracked of the earlier one.
	require.Equal(t, []string{nameLinked, arm64, "-", answerNoPackage, answerNone, rowOK,
		answerNoPackage, answerNone, rowOK, "-"}, fields(row(t, out, answersSection, nameLinked)))
	require.GreaterOrEqual(t, looks, 3, "the tool waited for the data of the image that it deployed")
}

func TestRunStopsWhenTheRebuildOfASheetIsNotFaithful(t *testing.T) {
	w := newWorld(t)
	w.plantLinked()
	// A sheet that says suppressed what the evidence says is reached: it was made by other rules than these.
	ctx := context.Background()
	sheet, err := w.verdicts.Get(ctx, digestOf(nameLinked))
	require.NoError(t, err)
	status := *sheet.Status.DeepCopy()
	i := indexOf(t, status.Findings, fixedCVE, libsID)
	status.Findings[i].Outcome = suppressed
	status.Findings[i].Justification = ptr.To(inventoryv1alpha1.JustificationVulnerableCodeNotInExecutePath)
	status.Findings[i].Reason = nil
	require.NoError(t, w.verdicts.Put(ctx, digestOf(nameLinked), status))
	path := writeCases(t, false, caseOf(nameLinked, answerTracked, answerNeedsAssessment))

	code, out := w.run(path)

	require.Equal(t, exitFailure, code, out)
	require.Contains(t, out, fixedCVE)
	require.Contains(t, out, nameLinked)
	require.NotContains(t, out, "== answers", "no second column that nobody can trust")
}

func TestRunTotalsCoverTheFindingsOfTheCasesManifests(t *testing.T) {
	w := newWorld(t)
	w.plantInstalledNotLinked()
	w.plantLinked()
	// Another manifest in the cluster, which belongs to no case and counts for nothing.
	w.plant("not-a-case", brotliEvidence(digestOf("not-a-case"), false), otherMatches()...)
	path := writeCases(t, false,
		caseOf(nameInstalled, answerTracked, answerSuppressed), caseOf(nameLinked, answerTracked, answerNeedsAssessment))

	code, out := w.run(path)

	require.Equal(t, exitOK, code, out)
	// installed-not-linked: the target, the fixed one in the library, the one in busybox. linked: those three
	// and the target in the command package. Seven findings in all, two manifests.
	require.Contains(t, out, "== findings: 7 in 2 manifests")
	require.Contains(t, out, "== findings of "+cve+": 3 in 2 manifests")
	// All three findings of the target are Tracked and Critical, and none has a known fix.
	require.Regexp(t, `Tracked\s+3\s+3\s+0\s+0`, sectionOf(t, out, "findings of "+cve))
	// What decided each outcome: the catalog tracks three, and nothing applies to the one in busybox of each image.
	require.Regexp(t, `Tracked\s+KnownExploited\s+3`, sectionOf(t, out, "findings: 7"))
	require.Regexp(t, `NeedsAssessment\s+-\s+2`, sectionOf(t, out, "findings: 7"))
	// Without the override the catalog's findings go to the later rules: one is suppressed, and two stay open.
	without := sectionOf(t, out, "findings without the known-exploited override")
	require.Regexp(t, `Tracked\s+0`, without)
	require.Regexp(t, `Suppressed\s+2`, without, "the fixed one in the library of each image, and the target in the first")
	// Each case has its own row of findings, by outcome. In the first image nothing reaches the library, so the
	// load check suppresses the one that the catalog doesn't list. In the second a command reaches it.
	const byCase = "findings of each case"
	require.Equal(t, []string{nameInstalled, "3", "1", "1", "1"}, fields(row(t, out, byCase, nameInstalled)))
	require.Equal(t, []string{nameLinked, "4", "2", "2", "0"}, fields(row(t, out, byCase, nameLinked)))
}

func TestRunReportsCompletenessSizesScansAndTheResultLineOfEveryCase(t *testing.T) {
	w := newWorld(t)
	w.plantLinked()
	path := writeCases(t, false, caseOf(nameLinked, answerTracked, answerNeedsAssessment))

	code, out := w.run(path)

	require.Equal(t, exitOK, code, out)
	// CASE, PLATFORM, ELF FILES, OWNED, COMPLETENESS
	require.Equal(t, []string{nameLinked, arm64, "5", "5", "100%"}, fields(row(t, out, "completeness", nameLinked)))
	sizes := fields(row(t, out, "sizes", nameLinked))
	require.Equal(t, nameLinked, sizes[0])
	require.Regexp(t, `^\d+ B \(\d+%\)$`, sizes[2], "the compressed evidence, against the trigger of 512 KiB")
	require.Regexp(t, `^\d+ B \(\d+%\)$`, sizes[3], "the evidence as base64, which is how the object holds it")
	require.Regexp(t, `^\d+ B$`, sizes[4], "the evidence once decoded")
	require.Regexp(t, `^\d+ B \(\d+%\)$`, sizes[5], "the sheet")

	// The scan took 7 seconds from the first sight of the digest, as the evidence says, and the line is the one that
	// the scanner makes of the evidence: its log line and the newline that ends it.
	ev := brotliEvidence(digestOf(nameLinked), true, cliPath)
	line, err := result.Encode(result.Result{Image: registryAt + "/linked@" + ev.Digest, Manifests: []result.Manifest{ev}})
	require.NoError(t, err)
	require.Equal(t, []string{nameLinked, arm64, "7s", strconv.Itoa(len(line)+1) + " B"},
		fields(row(t, out, "scans", nameLinked)))
}

func TestRunRefusesAClusterThatIsNotLocal(t *testing.T) {
	var prepared atomic.Bool
	env := environment{
		connect: func() (client.Client, error) { return nil, errors.New("the API server is not on a loopback address") },
		prepare: func(context.Context, string, []testCase, io.Writer) (map[string]string, error) {
			prepared.Store(true)
			return nil, nil
		},
		poll: time.Millisecond,
	}
	path := writeCases(t, false, caseOf(nameScratch, answerNoPackage, answerNoPackage))
	var out bytes.Buffer

	code := run(context.Background(), []string{flagCases, path, flagRegistry, registryAt}, &out, env)

	require.Equal(t, exitFailure, code)
	require.Contains(t, out.String(), "loopback")
	require.False(t, prepared.Load(), "no image is built, copied or pushed before the cluster is known to be local")
}

func TestRunRefusesARegistryThatIsNotLocal(t *testing.T) {
	var connected atomic.Bool
	env := environment{
		connect: func() (client.Client, error) { connected.Store(true); return nil, errors.New("not reached") },
		poll:    time.Millisecond,
	}
	path := writeCases(t, false, caseOf(nameScratch, answerNoPackage, answerNoPackage))
	var out bytes.Buffer

	code := run(context.Background(), []string{flagCases, path, flagRegistry, "registry.example:5000"}, &out, env)

	require.Equal(t, exitUsage, code)
	require.Contains(t, out.String(), "loopback")
	require.False(t, connected.Load())
}

func TestUsageErrors(t *testing.T) {
	path := writeCases(t, false, caseOf(nameScratch, answerNoPackage, answerNoPackage))
	for what, args := range map[string][]string{
		"no arguments":          {},
		"no registry":           {flagCases, path},
		"no cases":              {flagRegistry, registryAt},
		"an unknown flag":       {flagCases, path, flagRegistry, registryAt, "--nope"},
		"an extra argument":     {flagCases, path, flagRegistry, registryAt, "extra"},
		"a timeout of nothing":  {flagCases, path, flagRegistry, registryAt, flagTimeout, "0s"},
		"a timeout in nonsense": {flagCases, path, flagRegistry, registryAt, flagTimeout, "soon"},
	} {
		var out bytes.Buffer
		code := run(context.Background(), args, &out, environment{})

		require.Equal(t, exitUsage, code, what)
		require.Contains(t, out.String(), "Usage:", what)
	}
}

func TestACasesFileThatCannotBeReadFailsBeforeTheClusterIsTouched(t *testing.T) {
	var connected atomic.Bool
	env := environment{connect: func() (client.Client, error) { connected.Store(true); return nil, nil }}
	var out bytes.Buffer
	missing := filepath.Join(t.TempDir(), "missing.yaml")

	code := run(context.Background(), []string{flagCases, missing, flagRegistry, registryAt}, &out, env)

	require.Equal(t, exitFailure, code)
	require.False(t, connected.Load())
}
