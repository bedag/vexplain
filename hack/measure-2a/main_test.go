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

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
	inventoryv1alpha1 "github.com/bedag/vexplain/api/inventory/v1alpha1"
	"github.com/bedag/vexplain/internal/evidence"
	"github.com/bedag/vexplain/internal/inventory"
	"github.com/bedag/vexplain/internal/rules"
	"github.com/bedag/vexplain/internal/rules/engine"
	"github.com/bedag/vexplain/internal/testenv/imagecontents"
	sdkevidence "github.com/bedag/vexplain/sdk/evidence"
	subjects "github.com/bedag/vexplain/sdk/subject"
)

// These tests cover the evaluation of the measurement: how a case's answer is read from its sheet, how the
// answer without the known-exploited hold is rebuilt, how answers are compared with the known ones, and what
// the tool prints and exits with. A false "not affected" is the error that the tool exists to find, so most
// of the tests below are about when it must say so. The rules are the default ones, as config/rules ships
// them, and the playbook the default one of config/playbooks.

const (
	// cve is the target CVE of the tests, otherCVE one that no catalog lists, and fixedCVE one that has a fix.
	cve        = "CVE-2026-111497"
	otherCVE   = "CVE-2020-0001"
	fixedCVE   = "CVE-2020-0002"
	registryAt = "localhost:5001"
	arm64      = "linux/arm64"
	version    = "1.0.9-r1"
	// The versions of the library package that fix a vulnerability, the earlier one first.
	fixedVersion      = "1.0.9-r2"
	laterFixedVersion = "1.0.9-r3"

	// Grype's words for severities and fix states, as the matcher passes them on.
	grypeCritical = "Critical"
	grypeHigh     = "High"
	grypeMedium   = "Medium"
	grypeFixed    = "fixed"
	grypeNotFixed = "not-fixed"
	grypeWontFix  = "wont-fix"
	grypeUnknown  = "unknown"

	// The default playbook, and its rules that decide the findings of the tests.
	playbookName       = "container-cves"
	knownExploitedRule = "known-exploited"
	guardRule          = "completeness-guard"
	removedRule        = "removed-in-later-layer"
	loadCheckRule      = "load-check"

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
	nameRemoved     = "removed-files"
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
	affected           = inventoryv1alpha1.VEXStatusAffected
	underInvestigation = inventoryv1alpha1.VEXStatusUnderInvestigation
	notAffected        = inventoryv1alpha1.VEXStatusNotAffected
	fixed              = inventoryv1alpha1.VEXStatusFixed
)

// The answers as the cases file writes them.
var (
	answerAffected           = string(affected)
	answerUnderInvestigation = string(underInvestigation)
	answerNotAffected        = string(notAffected)
	answerFixed              = string(fixed)
)

// readYAML reads a YAML file below the root of the repository into out.
func readYAML(t testing.TB, out any, path ...string) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(append([]string{"..", ".."}, path...)...))
	require.NoError(t, err)
	require.NoError(t, yaml.UnmarshalStrict(raw, out))
}

// defaultRules reads the default rules, as config/rules ships them.
func defaultRules(t testing.TB) []*configv1alpha1.Rule {
	t.Helper()
	var kustomization struct {
		Resources []string `json:"resources"`
	}
	readYAML(t, &kustomization, "config", "rules", "kustomization.yaml")
	defaults := make([]*configv1alpha1.Rule, 0, len(kustomization.Resources))
	for _, file := range kustomization.Resources {
		rule := &configv1alpha1.Rule{}
		readYAML(t, rule, "config", "rules", file)
		defaults = append(defaults, rule)
	}
	return defaults
}

// defaultPlaybook reads the default playbook, as config/playbooks ships it.
func defaultPlaybook(t testing.TB) *configv1alpha1.Playbook {
	t.Helper()
	playbook := &configv1alpha1.Playbook{}
	readYAML(t, playbook, "config", "playbooks", playbookName+".yaml")
	return playbook
}

// stepsOf compiles the rules, as the hub compiles them.
func stepsOf(t testing.TB, ruleObjects ...*configv1alpha1.Rule) []*engine.Compiled {
	t.Helper()
	steps := make([]*engine.Compiled, 0, len(ruleObjects))
	for _, rule := range ruleObjects {
		compiled, err := engine.Compile(rule)
		require.NoError(t, err, rule.Name)
		steps = append(steps, compiled)
	}
	return steps
}

// defaultSteps are the default rules, compiled.
func defaultSteps(t testing.TB) []*engine.Compiled {
	t.Helper()
	return stepsOf(t, defaultRules(t)...)
}

// inputsOf returns the scanner's evidence ev as the default playbook supplies it to its rules.
func inputsOf(t testing.TB, ev imagecontents.Manifest) map[string]engine.Input {
	t.Helper()
	raw, err := json.Marshal(ev)
	require.NoError(t, err)
	var data any
	require.NoError(t, json.Unmarshal(raw, &data))
	return map[string]engine.Input{"contents": {Present: true, Data: data, Coverage: ptr.To(ev.Completeness())}}
}

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
func brotliEvidence(digest string, withCLI bool, reachedBy ...string) imagecontents.Manifest {
	libraries := make([]imagecontents.Library, 0, 3)
	for _, soname := range []string{"libbrotlicommon.so.1", "libbrotlidec.so.1", "libbrotlienc.so.1"} {
		libraries = append(libraries, imagecontents.Library{
			Path: "/usr/lib/" + soname, Soname: soname, PackageID: libsID,
			ReachedBy: reachedBy, ReachedCount: len(reachedBy),
		})
	}
	artifacts := []artifact{
		{ID: libsID, Name: libsName, Version: version, Type: typeAPK},
		{ID: otherID, Name: otherPkg, Version: "1.31.1-r22", Type: typeAPK},
	}
	facts := []imagecontents.PackageFacts{
		{ID: libsID, FilesListed: 6, FilesPresent: 6, SharedLibraries: 3},
		{ID: otherID, FilesListed: 10, FilesPresent: 10, OtherELFFiles: 1},
	}
	elfFiles := 4
	if withCLI {
		artifacts = append(artifacts, artifact{ID: cliID, Name: cliName, Version: version, Type: typeAPK})
		facts = append(facts, imagecontents.PackageFacts{ID: cliID, FilesListed: 1, FilesPresent: 1, OtherELFFiles: 1})
		elfFiles++
	}
	return imagecontents.Manifest{
		Platform: arm64, Digest: digest, SBOM: sbomOf(artifacts...), Packages: facts,
		ELF: imagecontents.ELFSummary{Total: elfFiles, Owned: elfFiles}, Libraries: libraries,
	}
}

// removedEvidence is the evidence of an Alpine image whose Brotli library package lists six files, of which a later
// layer deleted every one: none is left in the final filesystem, so the scan finds no library of the package. The
// package that owns an executable is as in brotliEvidence, and packages account for every ELF file.
func removedEvidence(digest string) imagecontents.Manifest {
	ev := brotliEvidence(digest, false)
	ev.Packages[0] = imagecontents.PackageFacts{ID: libsID, FilesListed: 6}
	ev.Libraries = nil
	ev.ELF = imagecontents.ELFSummary{Total: 1, Owned: 1}
	return ev
}

// exploitedMatch is the matcher's match of the target CVE in a package, which the catalog of known exploited
// vulnerabilities lists.
func exploitedMatch(packageID, packageName string) sdkevidence.Match {
	return sdkevidence.Match{
		VulnerabilityID: cve, PackageID: packageID, Severity: grypeCritical, FixState: grypeUnknown,
		KnownExploited: true, PackageName: packageName, PackageVersion: version, PackageType: typeAPK,
	}
}

// otherMatches are two more vulnerabilities that no catalog lists: one in the library package, with a fix, and
// one in the package that owns an executable.
func otherMatches() []sdkevidence.Match {
	return []sdkevidence.Match{
		{
			VulnerabilityID: fixedCVE, PackageID: libsID, Severity: grypeMedium, FixState: grypeFixed,
			FixedVersions: []string{fixedVersion}, PackageName: libsName, PackageVersion: version, PackageType: typeAPK,
		},
		{
			VulnerabilityID: otherCVE, PackageID: otherID, Severity: grypeHigh, FixState: grypeNotFixed,
			PackageName: otherPkg, PackageVersion: "1.31.1-r22", PackageType: typeAPK,
		},
	}
}

// findingsOf returns what the default rules make of the matches of a manifest, as a sheet holds it.
func findingsOf(t testing.TB, ev imagecontents.Manifest, matches ...sdkevidence.Match) []inventoryv1alpha1.Finding {
	t.Helper()
	return rules.Findings(engine.Evaluate(defaultSteps(t), inputsOf(t, ev), matches).Findings)
}

func indexOf(t testing.TB, findings []inventoryv1alpha1.Finding, vulnerability, packageID string) int {
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
func targetIn(t testing.TB, findings []inventoryv1alpha1.Finding, packageID string) inventoryv1alpha1.Finding {
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
    expected: UnderInvestigation
    expectedWithoutKEV: UnderInvestigation
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
		Name: nameInstalled, Build: "images/installed-not-linked", Expected: answerUnderInvestigation,
		ExpectedWithoutKEV: answerUnderInvestigation,
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
	const bothOrNeither, fieldExpected = "exactly one of build and image", "expected"
	held2held := "expected: UnderInvestigation\n    expectedWithoutKEV: UnderInvestigation"
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
		"an unknown expected answer":  {edit("expected: UnderInvestigation", "expected: Maybe"), fieldExpected},
		"an answer of None":           {edit("expected: UnderInvestigation", "expected: None"), fieldExpected},
		"an answer of phase 2a":       {edit("expected: UnderInvestigation", "expected: Tracked"), fieldExpected},
		"Affected without the hold": {
			edit("expectedWithoutKEV: UnderInvestigation", "expectedWithoutKEV: Affected"), fieldWithoutKEV,
		},
		"no basis": {
			edit("    basis: \"no Brotli package; the node binary bundles a copy\"\n", ""), "basis",
		},
		"a finding that changes by itself": {
			edit(held2held, "expected: NotAffected\n    expectedWithoutKEV: UnderInvestigation"), fieldWithoutKEV,
		},
		"no finding that turns into one": {
			edit(notFound2notFound, "expected: NotFound\n    expectedWithoutKEV: NotAffected"), fieldWithoutKEV,
		},
		"a finding that vanishes": {
			edit(held2held, "expected: UnderInvestigation\n    expectedWithoutKEV: NotFound"), fieldWithoutKEV,
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
		{answerUnderInvestigation, answerNotAffected}, {answerUnderInvestigation, answerFixed},
		{answerUnderInvestigation, answerUnderInvestigation}, {answerAffected, answerAffected},
		{answerNotAffected, answerNotAffected}, {answerFixed, answerFixed},
		{answerNotFound, answerNotFound}, {answerNoPackage, answerNoPackage},
	} {
		yml := strings.NewReplacer("expected: UnderInvestigation", "expected: "+pair[0],
			"expectedWithoutKEV: UnderInvestigation", "expectedWithoutKEV: "+pair[1]).Replace(goodCases)
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
		{answerUnderInvestigation, answerUnderInvestigation, checkMatches},
		{answerNotAffected, answerNotAffected, checkMatches},
		{answerAffected, answerAffected, checkMatches},
		{answerNotFound, answerNone, checkMatches},
		{answerNoPackage, answerNone, checkMatches},

		// A difference that errs towards a person looking is a difference, and no worse.
		{answerNotAffected, answerUnderInvestigation, checkDiffers},
		{answerNotAffected, answerAffected, checkDiffers},
		{answerNotAffected, answerNone, checkDiffers},
		{answerUnderInvestigation, answerAffected, checkDiffers},
		{answerUnderInvestigation, answerNone, checkDiffers},
		{answerNotFound, answerUnderInvestigation, checkDiffers},
		{answerNoPackage, answerUnderInvestigation, checkDiffers},

		// An answer of "not affected" where the known answer is anything else is the worst error.
		{answerUnderInvestigation, answerNotAffected, checkFalseNotAffected},
		{answerAffected, answerNotAffected, checkFalseNotAffected},
		{answerFixed, answerNotAffected, checkFalseNotAffected},
		{answerNotFound, answerNotAffected, checkFalseNotAffected},
		{answerNoPackage, answerNotAffected, checkFalseNotAffected},
	} {
		require.Equal(t, tc.want, compare(tc.expected, tc.actual), "%s expected, %s actual", tc.expected, tc.actual)
	}
}

func TestAnswerOf(t *testing.T) {
	finding := func(s inventoryv1alpha1.VEXStatus) inventoryv1alpha1.Finding {
		return inventoryv1alpha1.Finding{Status: s}
	}

	require.Equal(t, answerNone, answerOf(nil))
	require.Equal(t, answerUnderInvestigation, answerOf([]inventoryv1alpha1.Finding{finding(underInvestigation)}))
	require.Equal(t, answerNotAffected, answerOf([]inventoryv1alpha1.Finding{finding(notAffected), finding(notAffected)}))

	// Two manifests that disagree: the answer is the most cautious, so that a "not affected" is never what
	// the case says when any manifest says something else.
	require.Equal(t, answerAffected,
		answerOf([]inventoryv1alpha1.Finding{finding(notAffected), finding(affected), finding(underInvestigation)}))
	require.Equal(t, answerUnderInvestigation,
		answerOf([]inventoryv1alpha1.Finding{finding(notAffected), finding(underInvestigation), finding(fixed)}))
	require.Equal(t, answerFixed, answerOf([]inventoryv1alpha1.Finding{finding(notAffected), finding(fixed)}))
}

func TestLibraryFindingsDecideAndOtherBrotliPackagesOnlyAppear(t *testing.T) {
	ev := brotliEvidence(digestOf(nameLinked), true, cliPath)
	matches := append(otherMatches(), exploitedMatch(libsID, libsName), exploitedMatch(cliID, cliName))
	findings := findingsOf(t, ev, matches...)
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

// ---- the answer without the known-exploited hold ----

func TestWithoutHoldSettlesWhatTheOtherRulesSettle(t *testing.T) {
	// A later layer deleted every file of the library package, so the rule for a package that is gone settles the
	// finding that the catalog's hold kept open.
	ev := removedEvidence(digestOf(nameRemoved))
	findings := findingsOf(t, ev, append(otherMatches(), exploitedMatch(libsID, libsName))...)
	recorded := targetIn(t, findings, libsID)
	require.Equal(t, underInvestigation, recorded.Status)
	require.Equal(t, knownExploitedRule, ptr.Deref(recorded.Rule, ""))

	got, err := withoutHold(defaultSteps(t), inputsOf(t, ev), findings)

	require.NoError(t, err)
	require.Len(t, got, len(findings))
	target := targetIn(t, got, libsID)
	require.Equal(t, notAffected, target.Status)
	require.Equal(t, removedRule, ptr.Deref(target.Rule, ""))
	require.Equal(t, inventoryv1alpha1.VEXJustificationComponentNotPresent, ptr.Deref(target.Justification, ""))
	require.Equal(t, inventoryv1alpha1.SeverityCritical, target.Severity,
		"the rebuild keeps what the sheet says of the finding")
	require.Equal(t, inventoryv1alpha1.KnownExploitedNotListed, target.KnownExploited, "as if the catalog listed it not")
	// Every finding that the catalog did not take keeps its answer, and everything else about it.
	for i, f := range findings {
		if f.KnownExploited == inventoryv1alpha1.KnownExploitedNotListed {
			require.Equal(t, f, got[i], "%s in %s", f.VulnerabilityID, f.Package.Name)
		}
	}
}

func TestWithoutHoldKeepsAFindingOpenThatNothingReachesOrNames(t *testing.T) {
	// Nothing reaches or names the libraries. The load check settles nothing, so the finding that the catalog held
	// stays open, with its note.
	ev := brotliEvidence(digestOf(nameInstalled), false)
	findings := findingsOf(t, ev, exploitedMatch(libsID, libsName))

	got, err := withoutHold(defaultSteps(t), inputsOf(t, ev), findings)

	require.NoError(t, err)
	target := targetIn(t, got, libsID)
	require.Equal(t, underInvestigation, target.Status)
	require.Nil(t, target.Rule)
	require.Equal(t, []inventoryv1alpha1.StatusNote{{
		Rule: loadCheckRule, Text: "nothing in the image reaches or names its libraries",
	}}, target.StatusNotes)
	require.Nil(t, target.Justification)
}

func TestWithoutHoldKeepsAFindingOpenThatSomethingReaches(t *testing.T) {
	ev := brotliEvidence(digestOf(nameLinked), true, cliPath)
	findings := findingsOf(t, ev, exploitedMatch(libsID, libsName), exploitedMatch(cliID, cliName))

	got, err := withoutHold(defaultSteps(t), inputsOf(t, ev), findings)

	require.NoError(t, err)
	library := targetIn(t, got, libsID)
	require.Equal(t, underInvestigation, library.Status)
	require.Equal(t, []inventoryv1alpha1.StatusNote{{Rule: loadCheckRule, Text: "reached by " + cliPath}},
		library.StatusNotes)
	// The command package owns an executable, which no rule settles, and the load check has no note of.
	command := targetIn(t, got, cliID)
	require.Equal(t, underInvestigation, command.Status)
	require.Nil(t, command.Rule)
	require.Nil(t, command.StatusNotes)
}

func TestWithoutHoldAppliesTheGuardOfThePlaybook(t *testing.T) {
	// Packages account for half of the ELF files, so the guard holds the finding open, though a later layer
	// deleted the files of the library package.
	ev := removedEvidence(digestOf("guarded"))
	ev.ELF = imagecontents.ELFSummary{Total: 8, Owned: 4}
	findings := findingsOf(t, ev, exploitedMatch(libsID, libsName))

	got, err := withoutHold(defaultSteps(t), inputsOf(t, ev), findings)

	require.NoError(t, err)
	require.Equal(t, underInvestigation, got[0].Status)
	require.Equal(t, guardRule, ptr.Deref(got[0].Rule, ""))

	// The rules that count are the playbook's: with a guard that holds nothing, the rule for a package that is
	// gone settles the finding.
	looser := defaultRules(t)
	for _, rule := range looser {
		if rule.Name == guardRule {
			rule.Spec.Condition = "contents.coverage < 0"
		}
	}
	steps := stepsOf(t, looser...)
	loose := rulesFindings(t, steps, ev, exploitedMatch(libsID, libsName))
	got, err = withoutHold(steps, inputsOf(t, ev), loose)
	require.NoError(t, err)
	require.Equal(t, notAffected, got[0].Status)
}

// rulesFindings returns what the steps make of the matches of a manifest, as a sheet holds it.
func rulesFindings(t testing.TB, steps []*engine.Compiled, ev imagecontents.Manifest,
	matches ...sdkevidence.Match) []inventoryv1alpha1.Finding {
	t.Helper()
	return rules.Findings(engine.Evaluate(steps, inputsOf(t, ev), matches).Findings)
}

func TestTheRebuildGivesBackEveryFindingOfTheRules(t *testing.T) {
	// Each fix state, with and without versions, known to be exploited or not, and a package that the SBOM
	// doesn't name: whatever the rules read from a finding, the rebuilt match carries.
	ev := brotliEvidence(digestOf("rebuild"), false)
	matches := make([]sdkevidence.Match, 0, 6)
	for i, fix := range []string{grypeFixed, grypeNotFixed, grypeWontFix, grypeUnknown, ""} {
		var versions []string
		if fix == grypeFixed {
			versions = []string{laterFixedVersion, fixedVersion}
		}
		matches = append(matches, sdkevidence.Match{
			VulnerabilityID: "CVE-2021-000" + strconv.Itoa(i+1), PackageID: libsID, Severity: grypeHigh, FixState: fix,
			FixedVersions: versions, KnownExploited: i%2 == 0, PackageName: libsName, PackageVersion: version,
			PackageType: typeAPK, CVSS: []sdkevidence.CVSS{{Version: "3.1", Vector: "CVSS:3.1/AV:N"}},
		})
	}
	matches = append(matches, sdkevidence.Match{
		VulnerabilityID: "CVE-2021-0009", PackageID: "pkg-not-in-the-sbom", Severity: "Low", FixState: grypeFixed,
		FixedVersions: []string{"2.0"}, PackageName: "ghost", PackageType: "deb",
	})
	steps, inputs := defaultSteps(t), inputsOf(t, ev)
	for _, f := range findingsOf(t, ev, matches...) {
		rebuilt, ok := rules.Matches([]inventoryv1alpha1.Finding{f})
		require.True(t, ok)
		again := rules.Findings(engine.Evaluate(steps, inputs, rebuilt).Findings)
		require.Equal(t, []inventoryv1alpha1.Finding{f}, again, "%s in %s", f.VulnerabilityID, f.Package.Name)
	}
}

func TestWithoutHoldStopsWhenARebuildDoesNotGiveBackTheSheet(t *testing.T) {
	// The sheet says a finding is not affected, as not loadable, and the evidence says that /usr/bin/brotli
	// reaches the library. The rebuild lost an input, or the sheet came from other rules, such as older ones that
	// settled on loading. Either way the second column would be wrong, and nobody would see it.
	ev := brotliEvidence(digestOf(nameLinked), true, cliPath)
	findings := findingsOf(t, ev, exploitedMatch(libsID, libsName), otherMatches()[0])
	i := indexOf(t, findings, fixedCVE, libsID)
	require.Equal(t, underInvestigation, findings[i].Status)
	findings[i].Status = notAffected
	findings[i].Justification = ptr.To(inventoryv1alpha1.VEXJustificationVulnerableCodeNotInExecutePath)

	_, err := withoutHold(defaultSteps(t), inputsOf(t, ev), findings)

	require.Error(t, err)
	require.ErrorContains(t, err, fixedCVE)
	require.ErrorContains(t, err, libsName)
	require.ErrorContains(t, err, answerNotAffected)
	require.ErrorContains(t, err, answerUnderInvestigation)
}

func TestWithoutHoldChecksTheFindingsTheCatalogHeldToo(t *testing.T) {
	// A finding that the catalog held is rebuilt as known to be exploited, and must come back as it is on the
	// sheet.
	ev := brotliEvidence(digestOf(nameLinked), false)
	findings := findingsOf(t, ev, exploitedMatch(libsID, libsName))
	findings[0].Rule, findings[0].Reason = nil, nil // the sheet says something else than the rules make of its inputs

	_, err := withoutHold(defaultSteps(t), inputsOf(t, ev), findings)

	require.ErrorContains(t, err, cve)
}

func TestWithoutHoldStopsWhenARebuildDoesNotGiveBackAWholeFinding(t *testing.T) {
	// The rules decide by none of the fixed versions that the totals read. The totals of the second column are
	// made of the rebuilt findings, so a rebuild that gives them back different would make them wrong with nobody
	// seeing it.
	ev := brotliEvidence(digestOf(nameLinked), true, cliPath)
	findings := findingsOf(t, ev, exploitedMatch(libsID, libsName), otherMatches()[0])
	findings[indexOf(t, findings, fixedCVE, libsID)].FixedVersions = []string{laterFixedVersion, fixedVersion}

	_, err := withoutHold(defaultSteps(t), inputsOf(t, ev), findings)

	require.Error(t, err)
	// The message names the finding, and says what each side holds of it.
	require.ErrorContains(t, err, fixedCVE)
	require.ErrorContains(t, err, libsName)
	require.ErrorContains(t, err, libsID)
	rebuilt, sheet, found := strings.Cut(err.Error(), ", and the sheet has ")
	require.True(t, found, err.Error())
	require.Contains(t, rebuilt, `"fixedVersions":["`+fixedVersion+`","`+laterFixedVersion+`"]`)
	require.Contains(t, sheet, `"fixedVersions":["`+laterFixedVersion+`","`+fixedVersion+`"]`)
}

// A finding with a value that this version doesn't know, as a newer hub may write, says nothing that the
// rules can read: the tool can't rebuild it, and says which finding it is.
func TestWithoutHoldStopsAtAFindingThatTheRulesCantEvaluateAgain(t *testing.T) {
	for what, change := range map[string]func(*inventoryv1alpha1.Finding){
		"a severity that the rules don't know":  func(f *inventoryv1alpha1.Finding) { f.Severity = "Catastrophic" },
		"a fix state that the rules don't know": func(f *inventoryv1alpha1.Finding) { f.FixState = "Deferred" },
		"a package ID that was changed to show": func(f *inventoryv1alpha1.Finding) { f.Package.ID = "unknown" },
	} {
		t.Run(what, func(t *testing.T) {
			ev := brotliEvidence(digestOf(nameLinked), true, cliPath)
			findings := findingsOf(t, ev, exploitedMatch(libsID, libsName), otherMatches()[0])
			change(&findings[indexOf(t, findings, fixedCVE, libsID)])

			_, err := withoutHold(defaultSteps(t), inputsOf(t, ev), findings)

			require.ErrorContains(t, err, fixedCVE)
			require.ErrorContains(t, err, libsName)
			require.ErrorContains(t, err, "can't evaluate again")
		})
	}
}

func TestWithoutHoldTakesAMissingListForAnEmptyOne(t *testing.T) {
	// A missing list and an empty one count as equal, so that neither side's choice between them can make the check
	// fail. The test gives the sheet an empty list where the rules make none, the one direction that it can reach:
	// the rules make no empty list today, so the other way round can't be built from them.
	ev := brotliEvidence(digestOf(nameLinked), true, cliPath)
	findings := findingsOf(t, ev, exploitedMatch(libsID, libsName), otherMatches()[0])
	target := &findings[indexOf(t, findings, cve, libsID)]
	require.Nil(t, target.FixedVersions, "the rules make no list for a finding without a fix")
	require.Empty(t, target.Conditions)
	target.FixedVersions, target.Conditions = []string{}, []inventoryv1alpha1.FindingCondition{}

	_, err := withoutHold(defaultSteps(t), inputsOf(t, ev), findings)

	require.NoError(t, err)
}

// ---- the totals ----

func TestTallyCountsByStatusSeverityFixStateAndRule(t *testing.T) {
	const critical, high = inventoryv1alpha1.SeverityCritical, inventoryv1alpha1.SeverityHigh
	const low = inventoryv1alpha1.SeverityLow
	const fixedState, notFixed = inventoryv1alpha1.FixStateFixed, inventoryv1alpha1.FixStateNotFixed
	const wontFix, unknown = inventoryv1alpha1.FixStateWontFix, inventoryv1alpha1.FixStateUnknown
	finding := func(s inventoryv1alpha1.VEXStatus, severity inventoryv1alpha1.Severity, f inventoryv1alpha1.FixState,
		rule ...string) inventoryv1alpha1.Finding {
		found := inventoryv1alpha1.Finding{Status: s, Severity: severity, FixState: f}
		if len(rule) > 0 {
			found.Rule = &rule[0]
		}
		return found
	}
	got := tally([]inventoryv1alpha1.Finding{
		finding(underInvestigation, critical, fixedState), finding(underInvestigation, high, fixedState, guardRule),
		finding(underInvestigation, high, notFixed), finding(underInvestigation, critical, unknown, knownExploitedRule),
		finding(notAffected, low, wontFix, removedRule), finding(notAffected, high, fixedState, removedRule),
	})

	require.Equal(t, 6, got.total)
	require.Equal(t, map[inventoryv1alpha1.VEXStatus]int{underInvestigation: 4, notAffected: 2}, got.status)
	require.Equal(t, map[inventoryv1alpha1.Severity]int{critical: 2, high: 3, low: 1}, got.severity)
	require.Equal(t, map[inventoryv1alpha1.FixState]int{fixedState: 3, notFixed: 1, unknown: 1, wontFix: 1}, got.fixState)
	// The residual, the findings that wait for an assessment, labelled by severity and by fix state.
	require.Equal(t, map[inventoryv1alpha1.Severity]int{critical: 2, high: 2}, got.statusBySeverity[underInvestigation])
	require.Equal(t, map[inventoryv1alpha1.FixState]int{fixedState: 2, notFixed: 1, unknown: 1},
		got.statusByFixState[underInvestigation])
	require.Equal(t, 1, got.statusByFixState[notAffected][wontFix])
	// What decided each status: no rule is the empty one.
	require.Equal(t, map[string]int{"": 2, guardRule: 1, knownExploitedRule: 1}, got.statusByRule[underInvestigation])
	require.Equal(t, map[string]int{removedRule: 2}, got.statusByRule[notAffected])
}

func TestTallyOfNothingIsZero(t *testing.T) {
	got := tally(nil)

	require.Zero(t, got.total)
	require.Zero(t, got.status[underInvestigation])
	require.Zero(t, got.statusBySeverity[underInvestigation][inventoryv1alpha1.SeverityHigh])
}

func TestSizesAreCountedAgainstTheTrigger(t *testing.T) {
	require.Equal(t, "0%", against(0))
	require.Equal(t, "50%", against(256*1024))
	require.Equal(t, "99%", against(512*1024-1), "rounded down: a size under the trigger never says 100%")
	require.Equal(t, "100%", against(512*1024), "a size at the trigger is not over it")
	require.Equal(t, "100% OVER", against(512*1024+1))
	require.Equal(t, "250% OVER", against(1280*1024))
}

func TestSizesOfASheetThatCannotBeEncodedAreADash(t *testing.T) {
	// A sheet that can't be encoded has no size to put against the trigger. Its row says so with a dash, and not
	// "0 B (0%)", which reads as a sheet of nothing.
	ev := brotliEvidence(digestOf(nameLinked), true, cliPath)
	sheet := &inventoryv1alpha1.ImageVerdicts{}
	// The encoding of an object fails on a managed-fields entry that holds invalid JSON.
	sheet.ManagedFields = []metav1.ManagedFieldsEntry{{FieldsV1: &metav1.FieldsV1{Raw: []byte("{")}}}
	_, err := json.Marshal(sheet)
	require.Error(t, err, "the sheet of this test can't be encoded")
	measured := []measurement{{c: testCase{Name: nameLinked}, data: caseData{manifests: []manifestData{{
		platform: arm64, digest: ev.Digest, sheet: sheet,
		info: evidenceInfo{CompressedBytes: 2048, UncompressedBytes: 9000},
	}}}}}
	var out bytes.Buffer

	printSizes(&out, measured)

	// CASE, PLATFORM, EVIDENCE COMPRESSED, EVIDENCE AS BASE64, EVIDENCE DECODED, SHEET, PACKAGES, FINDINGS, LEFT OUT
	cells := fields(row(t, out.String(), "sizes", nameLinked))
	require.Len(t, cells, 9, out.String())
	require.Equal(t, "-", cells[5], "the sheet")
	require.Equal(t, "2048 B (0%)", cells[2], "the sizes that can be told are still there")
	require.Equal(t, "9000 B", cells[4])
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
	evidence evidence.Store
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
	// The cluster runs the default playbook with the default rules, as the install applies them.
	require.NoError(t, api.Create(context.Background(), defaultPlaybook(t)))
	for _, rule := range defaultRules(t) {
		require.NoError(t, api.Create(context.Background(), rule))
	}
	return &world{
		t: t, api: api,
		inv:      inventory.NewCRDStore(api, nil, noName),
		evidence: evidence.NewCRDStore(api, nil, noName),
		verdicts: inventory.NewCRDVerdictsStore(api, noName),
	}
}

const (
	scannerVersion = "0.2.0"
	databaseAt     = "v6.1.10+2026-10-30T06:23:28Z"
)

// plant stores what a scan of the case's image and a match of its packages leave behind: the image's
// ImageInventory with its facts, the evidence of its one platform manifest, and the sheet that the default
// playbook's rules make of the matches. The manifest of the evidence is the image itself, as for an image that
// is no index. The scan ends seven seconds after the inventory first saw the image.
func (w *world) plant(caseName string, ev imagecontents.Manifest, matches ...sdkevidence.Match) {
	w.t.Helper()
	ctx := context.Background()
	w.observe(caseName, ev.Digest)
	scanned := w.firstSeen(ev.Digest).Add(7 * time.Second)

	w.putEvidence(scanned, ev)
	kept, omitted, counts := rules.Sheet(findingsOf(w.t, ev, matches...))
	require.NoError(w.t, w.verdicts.Put(ctx, ev.Digest, inventoryv1alpha1.ImageVerdictsStatus{
		Playbook: ptr.To(playbookName), FindingsVersion: ptr.To(databaseAt),
		Findings: kept, OmittedFindings: ptr.To(omitted), Counts: &counts,
	}))
	// The facts come last, as the runner writes them, so that whoever sees them can rely on the rest.
	w.setFacts(ev.Digest, scannedFacts(ev, scanned))
}

// putEvidence stores what a scan that finished at the time scanned found in the manifest ev, as the scanner's
// evidence, the way the runner stores it.
func (w *world) putEvidence(scanned time.Time, ev imagecontents.Manifest) {
	w.t.Helper()
	e, err := sdkevidence.New(imagecontents.Type, subjects.Manifest(ev.Digest), ev,
		sdkevidence.WithPlatform(ev.Platform), sdkevidence.WithCoverage(ev.Completeness()),
		sdkevidence.WithTime(scanned), sdkevidence.WithSource("/clusters/local/collectors/scanner"))
	require.NoError(w.t, err)
	require.NoError(w.t, w.evidence.Put(context.Background(), scannerSource, scannerVersion, e))
}

// setFacts writes the facts of a digest, which has an ImageInventory.
func (w *world) setFacts(digest string, facts *inventoryv1alpha1.ImageFacts) {
	w.t.Helper()
	found, err := w.inv.SetFacts(context.Background(), digest, facts)
	require.NoError(w.t, err)
	require.True(w.t, found, "the digest has an ImageInventory")
}

// scannedFacts returns the facts of a scan that finished at the time scanned and found the manifest ev.
func scannedFacts(ev imagecontents.Manifest, scanned time.Time) *inventoryv1alpha1.ImageFacts {
	return &inventoryv1alpha1.ImageFacts{
		Manifests: []inventoryv1alpha1.ManifestFact{{Platform: ev.Platform, Digest: ev.Digest}},
		Evidence: []inventoryv1alpha1.EvidenceFact{{
			Source: scannerSource, Type: imagecontents.Type, CollectorVersion: scannerVersion,
			Time: ptr.To(metav1.NewTime(scanned)), Coverage: ptr.To(ev.Completeness()),
		}},
	}
}

// observe makes the ImageInventory of a digest, as the spoke's presence does when a pod runs it.
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

func (w *world) plantRemoved() {
	ev := removedEvidence(digestOf(nameRemoved))
	w.plant(nameRemoved, ev, append(otherMatches(), exploitedMatch(libsID, libsName))...)
}

func (w *world) plantNoPackages(caseName string) {
	w.plant(caseName, imagecontents.Manifest{
		Platform: arm64, Digest: digestOf(caseName), SBOM: sbomOf(), ELF: imagecontents.ELFSummary{Total: 1},
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
	w.plantRemoved()
	w.plantNoPackages(nameScratch)
	w.plantNoPackages(nameStatic)
	path := writeCases(t, false,
		caseOf(nameInstalled, answerUnderInvestigation, answerUnderInvestigation),
		caseOf(nameLinked, answerUnderInvestigation, answerUnderInvestigation),
		caseOf(nameRemoved, answerUnderInvestigation, answerNotAffected),
		caseOf(nameStatic, answerNotFound, answerNotFound),
		caseOf(nameScratch, answerNoPackage, answerNoPackage),
	)

	code, out := w.run(path)

	require.Equal(t, exitOK, code, out)
	require.Contains(t, out, "provisional", "while the known answers are not approved, the output says so")
	require.Contains(t, out, databaseAt, "the version of the findings of the sheets")
	require.Contains(t, out, "playbook: "+playbookName)
	require.Contains(t, out, cve)

	// CASE, PLATFORM, LIBRARY, then the expected and the actual answer and the check, as built and then
	// without the known-exploited hold, and the other Brotli findings.
	require.Equal(t, []string{nameInstalled, arm64, libsName, answerUnderInvestigation, answerUnderInvestigation, rowOK,
		answerUnderInvestigation, answerUnderInvestigation, rowOK, "-"},
		fields(row(t, out, answersSection, nameInstalled)), "nothing reaches the library, and the load check settles nothing")
	require.Equal(t, []string{nameLinked, arm64, libsName, answerUnderInvestigation, answerUnderInvestigation, rowOK,
		answerUnderInvestigation, answerUnderInvestigation, rowOK, "brotli:UnderInvestigation"},
		fields(row(t, out, answersSection, nameLinked)), "the command package's finding appears, and doesn't decide")
	require.Equal(t, []string{nameRemoved, arm64, libsName, answerUnderInvestigation, answerUnderInvestigation, rowOK,
		answerNotAffected, answerNotAffected, rowOK, "-"},
		fields(row(t, out, answersSection, nameRemoved)),
		"the files of the package are gone, which settles the finding without the hold")
	require.Equal(t, []string{nameStatic, arm64, "-", answerNotFound, answerNone, rowOK,
		answerNotFound, answerNone, rowOK, "-"}, fields(row(t, out, answersSection, nameStatic)))
	require.Equal(t, []string{nameScratch, arm64, "-", answerNoPackage, answerNone, rowOK,
		answerNoPackage, answerNone, rowOK, "-"}, fields(row(t, out, answersSection, nameScratch)))
	require.Contains(t, out, "as built: 5 of 5 as expected, 0 differ, 0 false not-affected")
	require.Contains(t, out, "without the hold: 5 of 5 as expected, 0 differ, 0 false not-affected")
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
	w.plantRemoved()
	// The known answer says that the finding stays open, as it would if the files of the package were in the
	// image. Without the hold, the rules settle it: they find the files gone.
	path := writeCases(t, false, caseOf(nameRemoved, answerUnderInvestigation, answerUnderInvestigation))

	code, out := w.run(path)

	require.Equal(t, exitFailure, code, out)
	line := row(t, out, answersSection, nameRemoved)
	require.Contains(t, line, "FALSE NOT-AFFECTED")
	require.Equal(t, 1, strings.Count(line, "FALSE NOT-AFFECTED"),
		"the column as built is fine, and only the second is not")
	require.Contains(t, out, "as built: 1 of 1 as expected, 0 differ, 0 false not-affected")
	require.Contains(t, out, "without the hold: 0 of 1 as expected, 0 differ, 1 false not-affected")
}

func TestRunCallsASettledFindingAsBuiltAFalseNotAffectedToo(t *testing.T) {
	w := newWorld(t)
	// The catalog doesn't list the vulnerability, so the rules as built settle it as not affected, as the files of
	// the package are gone. The known answer for the column as built is UnderInvestigation.
	unlisted := exploitedMatch(libsID, libsName)
	unlisted.KnownExploited = false
	w.plant(nameRemoved, removedEvidence(digestOf(nameRemoved)), unlisted)
	path := writeCases(t, false, caseOf(nameRemoved, answerUnderInvestigation, answerNotAffected))

	code, out := w.run(path)

	require.Equal(t, exitFailure, code, out)
	require.Contains(t, row(t, out, answersSection, nameRemoved), "FALSE NOT-AFFECTED")
	require.Contains(t, out, "as built: 0 of 1 as expected, 0 differ, 1 false not-affected")
}

func TestRunCountsADifferenceThatIsNotAFalseNotAffected(t *testing.T) {
	w := newWorld(t)
	w.plantLinked()
	// The known answer says that the finding is not affected without the hold, and the rules keep it open,
	// because /usr/bin/brotli reaches the library. The finding is more careful than the known answer. No exit
	// with 1.
	path := writeCases(t, false, caseOf(nameLinked, answerUnderInvestigation, answerNotAffected))

	code, out := w.run(path)

	require.Equal(t, exitOK, code, out)
	require.Contains(t, row(t, out, answersSection, nameLinked), "DIFFERS")
	require.Contains(t, out, "without the hold: 0 of 1 as expected, 1 differ, 0 false not-affected")
}

func TestRunReportsACaseWhoseSheetNeverComesAndExitsWithOne(t *testing.T) {
	w := newWorld(t)
	w.plantNoPackages(nameScratch)
	// The pod's image was seen, and the scan done, but the matcher never answered: there is no sheet.
	ev := brotliEvidence(digestOf(nameLinked), true, cliPath)
	w.observe(nameLinked, ev.Digest)
	w.putEvidence(time.Now(), ev)
	w.setFacts(ev.Digest, scannedFacts(ev, time.Now()))
	path := writeCases(t, false,
		caseOf(nameLinked, answerUnderInvestigation, answerUnderInvestigation),
		caseOf(nameScratch, answerNoPackage, answerNoPackage))

	code, out := w.run(path)

	require.Equal(t, exitFailure, code, "a measurement with a case missing is not a measurement")
	require.Regexp(t, `linked\s+no answer: timed out after 300ms, waiting for the sheet of linux/arm64`, out)
	require.Contains(t, row(t, out, answersSection, nameScratch), rowOK, "the other cases are still measured")
	require.Contains(t, out, "1 case without an answer")
}

func TestRunReportsAFailedScanWithItsReason(t *testing.T) {
	w := newWorld(t)
	w.observe(nameScratch, digestOf(nameScratch))
	w.setFacts(digestOf(nameScratch), &inventoryv1alpha1.ImageFacts{
		Failures: []inventoryv1alpha1.ScanFailure{{
			Source: scannerSource, Reason: inventoryv1alpha1.ScanFailureReasonNoMatchingPlatform, Time: ptr.To(metav1.Now()),
			Attempts: 1,
		}},
	})
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
	ev := imagecontents.Manifest{
		Platform: arm64, Digest: digestOf("scratch-platform-manifest"), SBOM: sbomOf(),
		ELF: imagecontents.ELFSummary{Total: 1},
	}
	w.observe(nameScratch, reported)
	scanned := w.firstSeen(reported).Add(3 * time.Second)
	ctx := context.Background()
	w.putEvidence(scanned, ev)
	require.NoError(t, w.verdicts.Put(ctx, ev.Digest, inventoryv1alpha1.ImageVerdictsStatus{
		Playbook: ptr.To(playbookName), FindingsVersion: ptr.To("v1"), Counts: &inventoryv1alpha1.FindingCounts{
			Affected: ptr.To(int32(0)), UnderInvestigation: ptr.To(int32(0)), NotAffected: ptr.To(int32(0)),
			Fixed: ptr.To(int32(0)),
		},
	}))
	w.setFacts(reported, scannedFacts(ev, scanned))
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
	// The image that was deployed has no package, so its answer is none, and not the UnderInvestigation of the
	// earlier one.
	require.Equal(t, []string{nameLinked, arm64, "-", answerNoPackage, answerNone, rowOK,
		answerNoPackage, answerNone, rowOK, "-"}, fields(row(t, out, answersSection, nameLinked)))
	require.GreaterOrEqual(t, looks, 3, "the tool waited for the data of the image that it deployed")
}

func TestRunStopsWhenTheRebuildOfASheetIsNotFaithful(t *testing.T) {
	w := newWorld(t)
	w.plantLinked()
	// A sheet that says not affected what the evidence says is reached: it was made by other rules than these.
	ctx := context.Background()
	sheet, err := w.verdicts.Get(ctx, digestOf(nameLinked))
	require.NoError(t, err)
	status := *sheet.Status.DeepCopy()
	i := indexOf(t, status.Findings, fixedCVE, libsID)
	status.Findings[i].Status = notAffected
	status.Findings[i].Justification = ptr.To(inventoryv1alpha1.VEXJustificationVulnerableCodeNotInExecutePath)
	require.NoError(t, w.verdicts.Put(ctx, digestOf(nameLinked), status))
	path := writeCases(t, false, caseOf(nameLinked, answerUnderInvestigation, answerUnderInvestigation))

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
	w.plantRemoved()
	// Another manifest in the cluster, which belongs to no case and counts for nothing.
	w.plant("not-a-case", brotliEvidence(digestOf("not-a-case"), false), otherMatches()...)
	path := writeCases(t, false,
		caseOf(nameInstalled, answerUnderInvestigation, answerUnderInvestigation),
		caseOf(nameLinked, answerUnderInvestigation, answerUnderInvestigation),
		caseOf(nameRemoved, answerUnderInvestigation, answerNotAffected))

	code, out := w.run(path)

	require.Equal(t, exitOK, code, out)
	// installed-not-linked and removed-files: the target, the fixed one in the library, the one in busybox. linked:
	// those three and the target in the command package. Ten findings in all, three manifests.
	require.Contains(t, out, "== findings: 10 in 3 manifests")
	require.Contains(t, out, "== findings of "+cve+": 4 in 3 manifests")
	// All four findings of the target are held open and Critical, and none has a known fix.
	require.Regexp(t, `UnderInvestigation\s+4\s+4\s+0\s+0`, sectionOf(t, out, "findings of "+cve))
	// What decided each status: the catalog holds four open, and no rule decides the one in busybox of each image,
	// nor the fixed one in the library where its files are there. Where the files of the package are gone, the
	// finding is settled as not affected.
	require.Regexp(t, `UnderInvestigation\s+known-exploited\s+4`, sectionOf(t, out, "findings: 10"))
	require.Regexp(t, `UnderInvestigation\s+-\s+5`, sectionOf(t, out, "findings: 10"))
	require.Regexp(t, `NotAffected\s+removed-in-later-layer\s+1`, sectionOf(t, out, "findings: 10"))
	// Without the hold the catalog's findings go to the other rules: the target in the removed files is settled,
	// and the other three stay open.
	without := sectionOf(t, out, "findings without the known-exploited hold")
	require.NotContains(t, without, knownExploitedRule)
	require.Regexp(t, `NotAffected\s+removed-in-later-layer\s+2`, without,
		"the fixed one in the library of the removed files, and the target")
	require.Regexp(t, `UnderInvestigation\s+-\s+8`, without, "no rule settles the others")
	// Each case has its own row of findings, by status: UnderInvestigation, Affected, NotAffected and Fixed. In the
	// third image the files of the library package are gone.
	const byCase = "findings of each case"
	require.Equal(t, []string{nameInstalled, "3", "3", "0", "0", "0"}, fields(row(t, out, byCase, nameInstalled)))
	require.Equal(t, []string{nameLinked, "4", "4", "0", "0", "0"}, fields(row(t, out, byCase, nameLinked)))
	require.Equal(t, []string{nameRemoved, "3", "2", "0", "1", "0"}, fields(row(t, out, byCase, nameRemoved)))
}

func TestRunReportsCompletenessSizesAndScansOfEveryCase(t *testing.T) {
	w := newWorld(t)
	w.plantLinked()
	path := writeCases(t, false, caseOf(nameLinked, answerUnderInvestigation, answerUnderInvestigation))

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

	// The scan took 7 seconds from the first sight of the digest, as the evidence says.
	require.Equal(t, []string{nameLinked, arm64, "7s"}, fields(row(t, out, "scans", nameLinked)))
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

// kubeconfigOf writes a kubeconfig whose current context, named contextName, is of a cluster at server, and
// returns its path. No test calls the cluster.
func kubeconfigOf(t *testing.T, contextName, server string) string {
	t.Helper()
	kubeconfig := "apiVersion: v1\nkind: Config\ncurrent-context: " + contextName + "\n" +
		"clusters:\n- name: test\n  cluster:\n    server: " + server + "\n" +
		"contexts:\n- name: " + contextName + "\n  context:\n    cluster: test\n    user: test\n" +
		"users:\n- name: test\n  user:\n    token: not-a-token\n"
	path := filepath.Join(t.TempDir(), "kubeconfig")
	require.NoError(t, os.WriteFile(path, []byte(kubeconfig), 0o600))
	return path
}

// The tool deploys workloads and pushes images, so its own guard keeps it to a local kind cluster that
// KUBECONFIG names: never the default kubeconfig of a developer, nor another cluster on a loopback address,
// such as a tunnel to a remote one. It refuses before it builds, copies or pushes anything.
func TestRunRunsOnlyOnTheLocalKindClusterThatKUBECONFIGNames(t *testing.T) {
	for what, tc := range map[string]struct {
		kubeconfig func(t *testing.T) string
		refusal    string
	}{
		"without KUBECONFIG": {
			kubeconfig: func(*testing.T) string { return "" },
			refusal:    "KUBECONFIG is not set",
		},
		"a context that is not a kind cluster's": {
			kubeconfig: func(t *testing.T) string { return kubeconfigOf(t, "dev", "https://127.0.0.1:1") },
			refusal:    "doesn't start with kind-",
		},
		"a kind cluster that is not on a loopback address": {
			kubeconfig: func(t *testing.T) string {
				return kubeconfigOf(t, "kind-vexplain-test-e2e", "https://203.0.113.7:6443")
			},
			refusal: "not on a loopback address",
		},
	} {
		t.Run(what, func(t *testing.T) {
			t.Setenv("KUBECONFIG", tc.kubeconfig(t))
			var prepared atomic.Bool
			env := environment{
				connect: connectToLocalCluster,
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
			require.Contains(t, out.String(), tc.refusal)
			require.False(t, prepared.Load(), "no image is built, copied or pushed")
		})
	}
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
