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

// Package rules is the hub's deterministic layer. For one platform manifest it turns the matches of
// the vulnerability database into findings, and the findings into the sheet that the spokes read.
//
// A finding is one vulnerability in one package of one image (decision 0025). A rule settles it from
// the scan's evidence about that package, and what it settles covers that package only. Anything
// short of a rule's full evidence leaves the finding at NeedsAssessment: a finding that is wrongly
// settled as not affected is the worst error the operator can make, because nobody reviews what a
// rule settles. Evidence that is missing, unreadable or contradictory is short of full evidence.
//
// The text of a finding comes from images and from databases, which a crafted image can influence,
// and kubectl prints the strings of a status as they are. So every string that Evaluate writes into a
// finding is made printable first, and where the schema requires text that the source doesn't have, the
// finding says "unknown". The rules read neither of these: they decide by the package ID as the match
// gives it, and by the evidence.
//
// The package is pure. It reads nothing but its arguments, and keeps nothing between calls.
package rules

import (
	"cmp"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"k8s.io/utils/ptr"

	inventoryv1alpha1 "github.com/bedag/vexplain/api/inventory/v1alpha1"
	"github.com/bedag/vexplain/internal/matchapi"
	"github.com/bedag/vexplain/internal/scan/result"
)

// The limits of the schema of a finding and of a sheet.
const (
	// maxFindings is the most findings that a sheet lists, as the schema allows.
	maxFindings = 2048
	// maxSheetBytes is the most JSON that the findings of a sheet add up to. A sheet is one object,
	// which must stay below etcd's limit for a request, so its findings may take 1 MiB of it.
	maxSheetBytes = 1 << 20

	// The most characters of an ID, which is a vulnerability's or a package's, of a package name, of a
	// version, which is a package's or a fix's, and of a package type. The schema counts characters.
	maxIDLength      = 64
	maxNameLength    = 253
	maxVersionLength = 128
	maxTypeLength    = 32
	// maxReasonBytes is the most bytes of a reason. A byte count is never over the schema's count of
	// characters, so a reason that fits one fits the other.
	maxReasonBytes = 256
	// maxFixedVersions is the most fixed versions that a finding lists.
	maxFixedVersions = 8
)

// placeholder is what a finding says where the schema requires text and the match or the SBOM has
// none. It claims nothing about the vulnerability or the package.
const placeholder = "unknown"

// reasonIncompleteLibraries is the reason of a load check that the evidence of a package's libraries
// can't support, because it lacks a library or has a count that can't be true.
const reasonIncompleteLibraries = "the library evidence is incomplete"

// reasonUnreached is the reason of a load check that finds no file that reaches or names a library of
// the package, and no preload. It is a hint and no proof that nothing loads the libraries: loadCheck
// lays out what the check can't see.
const reasonUnreached = "nothing in the image reaches or names its libraries"

// Settings are the settings of the rules.
type Settings struct {
	// MinCompletenessPercent is the share of an image's ELF files that packages must account for
	// before any rule may settle a finding in it as not affected. At 0, the guard holds nothing back.
	MinCompletenessPercent int32
}

// Evaluate turns the matches of one platform manifest into findings, each scoped to its package. It
// is pure: the same input always gives the same output, whatever the order of the matches, and it
// changes neither the evidence nor the matches.
//
// Matches of one vulnerability in one package make one finding. For each finding, the first of these
// rules that applies decides it:
//
//  1. A vulnerability that is known to be exploited is Tracked, whatever else holds: it is patched,
//     not argued about.
//  2. When packages account for too few of the image's ELF files, the finding is NeedsAssessment,
//     because no rule may then settle it as not affected.
//  3. When the package database lists files of the package and none is left in the final filesystem,
//     the finding is Suppressed: the package is not there.
//  4. For a package whose ELF files are all shared libraries, the load check keeps the finding open,
//     and gives as the reason what reaches or names the libraries, or that nothing does. It settles
//     nothing (decision 0028).
//
// Any other finding is NeedsAssessment with no rule. The rules of 3 and 4 need the package's facts,
// and the package's entry in the SBOM that the facts are keyed by: for a package the evidence lacks,
// or describes twice, or whose SBOM can't be read, they never apply.
//
// Every string that a finding takes from a match, from the SBOM or from a path of the evidence is made
// printable first: each character that Go doesn't call printable, such as an escape character, a line
// break or a right-to-left override, becomes U+FFFD. The cuts to the schema's limits follow, so they
// hold for what the finding shows. An empty vulnerability ID, package ID, package name or package type
// becomes "unknown", so that no finding is one that the API server refuses. The rules read neither:
// they decide by the package ID as the match gives it, and by the evidence.
//
// The findings come sorted by vulnerability ID, then by package ID, as the matches give them.
func Evaluate(ev result.Manifest, matches []matchapi.Match, s Settings) []inventoryv1alpha1.Finding {
	e := newEvidence(ev, s)
	candidates := mergeMatches(matches)
	findings := make([]inventoryv1alpha1.Finding, 0, len(candidates))
	for _, c := range candidates {
		findings = append(findings, e.finding(c))
	}
	return findings
}

// evidence is what Evaluate knows of a manifest, indexed by package ID.
type evidence struct {
	// completeness is the share of the ELF files that packages own, and minCompleteness the least
	// that the guard accepts.
	completeness, minCompleteness int32
	// preloads is true when the image loads libraries that no ELF file asks for.
	preloads bool
	// sbom holds the packages that the SBOM names, once each.
	sbom map[string]sbomArtifact
	// facts holds the facts of the packages in sbom that have one set of facts. The facts are keyed by
	// the package's ID in the SBOM, so facts for an ID that the SBOM doesn't name can't be tied to a
	// package, and no rule uses them.
	facts map[string]result.PackageFacts
	// libraries holds the libraries of each package, in the order of their paths.
	libraries map[string][]result.Library
}

// newEvidence indexes the evidence of a manifest by package ID. It changes nothing in it.
func newEvidence(ev result.Manifest, s Settings) *evidence {
	e := &evidence{
		completeness:    ev.Completeness(),
		minCompleteness: s.MinCompletenessPercent,
		preloads:        ev.Preload.LDPreload || ev.Preload.LDAudit || ev.Preload.EtcLdSoPreload,
		sbom:            readSBOM(ev.SBOM),
		facts:           unique(ev.Packages, func(f result.PackageFacts) string { return f.ID }),
		libraries:       map[string][]result.Library{},
	}
	for id := range e.facts {
		if _, named := e.sbom[id]; !named {
			delete(e.facts, id)
		}
	}

	byPath := slices.Clone(ev.Libraries)
	slices.SortStableFunc(byPath, func(a, b result.Library) int { return strings.Compare(a.Path, b.Path) })
	for _, lib := range byPath {
		if lib.PackageID != "" {
			e.libraries[lib.PackageID] = append(e.libraries[lib.PackageID], lib)
		}
	}
	return e
}

// sbomArtifact is what the rules read of a package in Syft's JSON.
type sbomArtifact struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Version string `json:"version"`
	Type    string `json:"type"`
}

// readSBOM returns the packages that Syft's JSON names, by ID. JSON that can't be read names none, so
// that every finding then takes its package from its match, and no rule settles one.
func readSBOM(raw json.RawMessage) map[string]sbomArtifact {
	var doc struct {
		Artifacts []sbomArtifact `json:"artifacts"`
	}
	if json.Unmarshal(raw, &doc) != nil {
		return nil
	}
	return unique(doc.Artifacts, func(a sbomArtifact) string { return a.ID })
}

// unique indexes items by their keys. A key that more than one item has gets no entry: evidence that
// says two things about one package settles nothing. An item with an empty key names no package, and
// is left out.
func unique[T any](items []T, key func(T) string) map[string]T {
	index := make(map[string]T, len(items))
	repeated := map[string]bool{}
	for _, item := range items {
		k := key(item)
		if k == "" {
			continue
		}
		if _, seen := index[k]; seen {
			repeated[k] = true
		}
		index[k] = item
	}
	for k := range repeated {
		delete(index, k)
	}
	return index
}

// candidate is a finding before the rules decide it: the matches of one vulnerability in one package,
// merged.
type candidate struct {
	vulnerabilityID, packageID string
	// name, version and kind describe the package as its match does, which counts only for a package
	// that the SBOM doesn't name.
	name, version, kind string
	knownExploited      bool
	severity            inventoryv1alpha1.Severity
	fixState            inventoryv1alpha1.FixState
	fixedVersions       []string
}

// mergeMatches returns one candidate for each vulnerability and package that the matches name, sorted
// by vulnerability ID, then package ID. Grype can report one vulnerability for one package through
// several of its matchers, and each match may say something else about it. The candidate has:
//   - the known exploited flag, when any match says so
//   - the most severe severity
//   - the fix state of the match that knows most: fixed, then won't fix, then not fixed, then unknown
//   - the sorted union of the fixed versions
//
// The result doesn't depend on the order of the matches, because the matches are sorted first, down
// to the fields that describe the package, and the candidate takes those from the first of them.
func mergeMatches(matches []matchapi.Match) []candidate {
	sorted := slices.Clone(matches)
	slices.SortFunc(sorted, func(a, b matchapi.Match) int {
		return cmp.Or(
			strings.Compare(a.VulnerabilityID, b.VulnerabilityID),
			strings.Compare(a.PackageID, b.PackageID),
			strings.Compare(a.PackageName, b.PackageName),
			strings.Compare(a.PackageVersion, b.PackageVersion),
			strings.Compare(a.PackageType, b.PackageType),
		)
	})

	merged := make([]candidate, 0, len(sorted))
	for _, m := range sorted {
		last := len(merged) - 1
		if last < 0 || merged[last].vulnerabilityID != m.VulnerabilityID || merged[last].packageID != m.PackageID {
			merged = append(merged, candidate{
				vulnerabilityID: m.VulnerabilityID, packageID: m.PackageID,
				name: m.PackageName, version: m.PackageVersion, kind: m.PackageType,
				severity: inventoryv1alpha1.SeverityUnknown, fixState: inventoryv1alpha1.FixStateUnknown,
			})
			last++
		}
		merged[last].add(m)
	}
	for i := range merged {
		slices.Sort(merged[i].fixedVersions)
		merged[i].fixedVersions = slices.Compact(merged[i].fixedVersions)
	}
	return merged
}

// add merges a match into the candidate. The candidate's fixed versions are sorted and made unique
// once all matches are in.
func (c *candidate) add(m matchapi.Match) {
	c.knownExploited = c.knownExploited || m.KnownExploited
	if s := severityOf(m.Severity); severityRank(s) < severityRank(c.severity) {
		c.severity = s
	}
	if f := fixStateOf(m.FixState); fixStateRank(f) < fixStateRank(c.fixState) {
		c.fixState = f
	}
	// The fixed versions are made printable here, so that the sorted union is of what the finding shows.
	for _, v := range m.FixedVersions {
		c.fixedVersions = append(c.fixedVersions, printable(v))
	}
}

// severities lists the severities from the most severe down.
var severities = []inventoryv1alpha1.Severity{
	inventoryv1alpha1.SeverityCritical,
	inventoryv1alpha1.SeverityHigh,
	inventoryv1alpha1.SeverityMedium,
	inventoryv1alpha1.SeverityLow,
	inventoryv1alpha1.SeverityNegligible,
	inventoryv1alpha1.SeverityUnknown,
}

// severityOf maps the severity that Grype writes, whatever its case. Any other value is unknown.
func severityOf(grype string) inventoryv1alpha1.Severity {
	for _, s := range severities {
		if strings.EqualFold(grype, string(s)) {
			return s
		}
	}
	return inventoryv1alpha1.SeverityUnknown
}

// severityRank is the place of a severity in severities: the lower, the more severe. A severity that
// the list doesn't have comes after all that it has.
func severityRank(s inventoryv1alpha1.Severity) int {
	if i := slices.Index(severities, s); i >= 0 {
		return i
	}
	return len(severities)
}

// fixStateOf maps the fix state that Grype writes. An empty state is a real value, and not a missing
// one: Grype writes it for a match that says nothing of a fix, such as an NVD entry. It is unknown,
// like any other state that the schema doesn't name.
func fixStateOf(grype string) inventoryv1alpha1.FixState {
	switch grype {
	case "fixed":
		return inventoryv1alpha1.FixStateFixed
	case "not-fixed":
		return inventoryv1alpha1.FixStateNotFixed
	case "wont-fix":
		return inventoryv1alpha1.FixStateWontFix
	}
	return inventoryv1alpha1.FixStateUnknown
}

// fixStateRank orders the fix states by which one stands when the matches of a finding disagree: the
// lower, the more is known.
func fixStateRank(f inventoryv1alpha1.FixState) int {
	switch f {
	case inventoryv1alpha1.FixStateFixed:
		return 0
	case inventoryv1alpha1.FixStateWontFix:
		return 1
	case inventoryv1alpha1.FixStateNotFixed:
		return 2
	}
	return 3
}

// finding is the finding that the rules make of a candidate, cut to fit the schema. It shares no
// memory with the evidence or the matches.
func (e *evidence) finding(c candidate) inventoryv1alpha1.Finding {
	d := e.decide(c)
	f := inventoryv1alpha1.Finding{
		VulnerabilityID: required(c.vulnerabilityID, maxIDLength),
		Package:         e.packageReference(c),
		Outcome:         d.outcome,
		Conditions:      d.conditions,
		Severity:        c.severity,
		FixState:        c.fixState,
		FixedVersions:   listFixedVersions(c.fixedVersions),
	}
	if d.rule != "" {
		f.Rule = ptr.To(d.rule)
	}
	if d.justification != "" {
		f.Justification = ptr.To(d.justification)
	}
	if reason := cutBytes(printable(d.reason), maxReasonBytes); reason != "" {
		f.Reason = ptr.To(reason)
	}
	return f
}

// packageReference names the package of a candidate: as the SBOM's entry does when the SBOM names it,
// and as the match does when it doesn't.
func (e *evidence) packageReference(c candidate) inventoryv1alpha1.PackageReference {
	name, version, kind := c.name, c.version, c.kind
	if p, named := e.sbom[c.packageID]; named {
		name, version, kind = p.Name, p.Version, p.Type
	}
	ref := inventoryv1alpha1.PackageReference{
		ID:   required(c.packageID, maxIDLength),
		Name: required(name, maxNameLength),
		Type: required(kind, maxTypeLength),
	}
	if version = cutChars(printable(version), maxVersionLength); version != "" {
		ref.Version = ptr.To(version)
	}
	return ref
}

// listFixedVersions returns the first fixed versions that a finding lists, each cut to its length.
// The versions are sorted already.
func listFixedVersions(versions []string) []string {
	versions = versions[:min(len(versions), maxFixedVersions)]
	if len(versions) == 0 {
		return nil
	}
	listed := make([]string, len(versions))
	for i, v := range versions {
		listed[i] = cutChars(v, maxVersionLength)
	}
	return listed
}

// printable returns s with each character that Go doesn't call printable replaced by U+FFFD. Go calls
// a character printable when it is a letter, a mark, a number, a punctuation mark or a symbol, or the
// ASCII space. Control characters, line breaks and the format characters that reverse the direction of
// text are not. Bytes that aren't valid UTF-8 become U+FFFD too, so the result is always valid UTF-8,
// and the cuts that follow can rely on it.
func printable(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsPrint(r) {
			return r
		}
		return utf8.RuneError
	}, s)
}

// required returns s for a string that the schema requires: made printable, the placeholder when
// nothing is left, and cut to at most n characters. The placeholder is shorter than every limit.
func required(s string, n int) string {
	if s = printable(s); s == "" {
		return placeholder
	}
	return cutChars(s, n)
}

// cutChars returns s cut to at most n characters, which is what the schema's maxLength counts.
func cutChars(s string, n int) string {
	if len(s) <= n { // no more bytes than n, so no more characters
		return s
	}
	count := 0
	for i := range s {
		if count == n {
			return s[:i]
		}
		count++
	}
	return s
}

// cutBytes returns s cut to at most n bytes, on the boundary of a character: a character that the
// cut would split is left out.
func cutBytes(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

// decision is what the rules made of a finding.
type decision struct {
	outcome inventoryv1alpha1.Outcome
	// rule is the rule that decided the outcome, that blocked a suppression, or that kept the finding open
	// with a hint. It is empty when none did.
	rule inventoryv1alpha1.Rule
	// justification is set exactly when the outcome is Suppressed.
	justification inventoryv1alpha1.Justification
	// conditions are what a suppression depends on. No rule sets any today.
	conditions []inventoryv1alpha1.FindingCondition
	reason     string
}

// decide applies the rules of Evaluate, in their order, to one candidate.
func (e *evidence) decide(c candidate) decision {
	if c.knownExploited {
		return decision{outcome: inventoryv1alpha1.OutcomeTracked, rule: inventoryv1alpha1.RuleKnownExploited}
	}
	if e.completeness < e.minCompleteness {
		return decision{
			outcome: inventoryv1alpha1.OutcomeNeedsAssessment,
			rule:    inventoryv1alpha1.RuleCompletenessGuard,
			reason:  fmt.Sprintf("completeness %d%% is below %d%%", e.completeness, e.minCompleteness),
		}
	}

	facts, known := e.facts[c.packageID]
	if !known {
		return decision{outcome: inventoryv1alpha1.OutcomeNeedsAssessment}
	}
	// The package database lists files of the package, and none is left. A package that isn't an OS
	// package lists no files, so this never applies to it. Syft lists only the files of an rpm package
	// that exist, so nor does it to an rpm package: the safe way for the rule to err.
	if facts.FilesListed > 0 && facts.FilesPresent == 0 {
		return decision{
			outcome:       inventoryv1alpha1.OutcomeSuppressed,
			rule:          inventoryv1alpha1.RuleRemovedInLaterLayer,
			justification: inventoryv1alpha1.JustificationComponentNotPresent,
		}
	}
	return e.loadCheck(c.packageID, facts)
}

// loadCheck records what reaches or names the libraries of a package, as the reason of a finding that it
// keeps open. The reason is a hint for whoever assesses the finding: the check settles nothing (decision
// 0028). Its evidence is the one that decision 0026 defines.
//
// It applies to a package whose ELF files are all shared libraries. A package that owns an executable
// can be run, and one that owns no library has none to load, so the check has nothing to say about
// either. For the others the reason says what reaches a library, what names one, that the image
// preloads libraries, that the evidence of the libraries is incomplete, or, where none of these holds,
// that nothing in the image reaches or names them.
//
// That last reason is no proof that nothing loads them. The check reads the files of the image, and
// can't see:
//   - a name that a program builds while it runs, such as the plug-ins that APR-util loads under a name
//     that it formats at run time
//   - a plug-in path: a library outside the dynamic linker's search path, which a program loads by a
//     path that it reads or builds
//   - an archive, such as a JAR or a ZIP, whose files name a library
//   - a name in an environment value, which the scan checks for LD_PRELOAD and LD_AUDIT only
//   - a name that comes from outside the image, such as one that a request gives a program
func (e *evidence) loadCheck(packageID string, facts result.PackageFacts) decision {
	open := decision{outcome: inventoryv1alpha1.OutcomeNeedsAssessment}
	if facts.SharedLibraries <= 0 || facts.OtherELFFiles != 0 {
		return open
	}

	open.rule = inventoryv1alpha1.RuleLoadCheck
	libraries := e.libraries[packageID]
	// Unless the evidence has an entry for each library that the package owns, it can't say what reaches
	// or names them all.
	if len(libraries) != facts.SharedLibraries {
		open.reason = reasonIncompleteLibraries
		return open
	}
	open.reason = cmp.Or(e.whatLoads(libraries), reasonUnreached)
	return open
}

// whatLoads returns the reason that something can load the libraries, or "" when the evidence shows
// nothing that can. libraries are those of one package, in the order of their paths.
//
// The reason names the first path, so that it is the same each time: a reaching file wins over a file
// that names a library, and that over preload. Of each kind it names the first path of the first
// library that has one. Where a count has no paths, which the scanner never writes, the reason gives
// the count: it is still evidence that something reaches or names a library, so the finding never says
// that nothing does.
func (e *evidence) whatLoads(libraries []result.Library) string {
	for _, lib := range libraries {
		if len(lib.ReachedBy) > 0 {
			return "reached by " + lib.ReachedBy[0]
		}
	}
	for _, lib := range libraries {
		if lib.ReachedCount > 0 {
			return fmt.Sprintf("reached by %d ELF files", lib.ReachedCount)
		}
	}
	for _, lib := range libraries {
		if len(lib.NameHits) > 0 {
			return "named in " + lib.NameHits[0]
		}
	}
	for _, lib := range libraries {
		if lib.NameHitCount > 0 {
			return fmt.Sprintf("named in %d files", lib.NameHitCount)
		}
	}
	if e.preloads {
		return "the image preloads libraries"
	}
	// What is left are counts that can't be true, such as a negative one. They prove nothing.
	for _, lib := range libraries {
		if lib.ReachedCount != 0 || lib.NameHitCount != 0 {
			return reasonIncompleteLibraries
		}
	}
	return ""
}

// Sheet orders the findings of a manifest, keeps as many of them as a sheet may hold, and counts
// them all.
//
// The order puts the findings that are open first: Tracked, then NeedsAssessment, then Suppressed. A
// vulnerability that is known to be exploited is patched, not argued about, so its findings come
// before every other, and are the last that a cut leaves out. Within an outcome come the most severe
// findings, from Critical down, then by vulnerability ID, then by package ID. An outcome that Sheet
// doesn't know goes just before Suppressed, and a severity that it doesn't know after Unknown, so
// that a cut never leaves out a finding that may need attention before a suppressed one.
//
// A sheet holds at most 2048 findings and 1 MiB of JSON, where each finding counts the length of its
// json.Marshal and one byte to separate it from the next. Sheet keeps findings in order until the
// next would break a limit. It stops there and never skips a finding to fit a later one, so what it
// leaves out is the end of the order: the Suppressed findings go first, then the least severe
// NeedsAssessment findings, and Tracked findings go only when they alone pass a limit.
//
// omitted is the number of findings that were left out, and counts covers every finding, those left
// out included. Sheet changes neither the findings nor their order in the argument, and returns a
// slice of its own.
func Sheet(findings []inventoryv1alpha1.Finding) (kept []inventoryv1alpha1.Finding, omitted int32, counts inventoryv1alpha1.FindingCounts) {
	ordered := slices.Clone(findings)
	slices.SortStableFunc(ordered, compareFindings)

	var suppressed, tracked, needsAssessment int32
	for _, f := range ordered {
		switch f.Outcome {
		case inventoryv1alpha1.OutcomeSuppressed:
			suppressed++
		case inventoryv1alpha1.OutcomeTracked:
			tracked++
		case inventoryv1alpha1.OutcomeNeedsAssessment:
			needsAssessment++
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
		Suppressed:      ptr.To(suppressed),
		Tracked:         ptr.To(tracked),
		NeedsAssessment: ptr.To(needsAssessment),
	}
}

// compareFindings is the order of a sheet.
func compareFindings(a, b inventoryv1alpha1.Finding) int {
	return cmp.Or(
		cmp.Compare(outcomeRank(a.Outcome), outcomeRank(b.Outcome)),
		cmp.Compare(severityRank(a.Severity), severityRank(b.Severity)),
		strings.Compare(a.VulnerabilityID, b.VulnerabilityID),
		strings.Compare(a.Package.ID, b.Package.ID),
	)
}

// outcomeRank is the place of an outcome in the order of a sheet. Tracked comes first, so that a cut
// leaves out the least severe findings that need an assessment before any finding of a vulnerability
// that is known to be exploited. An outcome that this code doesn't know comes before the suppressed
// ones, so that a cut leaves out a suppressed finding before it leaves out one that may need
// attention.
func outcomeRank(o inventoryv1alpha1.Outcome) int {
	switch o {
	case inventoryv1alpha1.OutcomeTracked:
		return 0
	case inventoryv1alpha1.OutcomeNeedsAssessment:
		return 1
	case inventoryv1alpha1.OutcomeSuppressed:
		return 3
	}
	return 2
}
