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

package spoke

import (
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math"
	"regexp"
	"slices"
	"strings"

	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/utils/ptr"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
	inventoryv1alpha1 "github.com/bedag/vexplain/api/inventory/v1alpha1"
	triagev1alpha1 "github.com/bedag/vexplain/api/triage/v1alpha1"
	"github.com/bedag/vexplain/internal/inventory"
	"github.com/bedag/vexplain/internal/settings"
	"github.com/bedag/vexplain/internal/text"
	"github.com/bedag/vexplain/internal/urgency"
	"github.com/bedag/vexplain/sdk/evidence"
)

// The limits of a report, which its schema sets, and the size that its status keeps below.
const (
	maxReportName     = 253
	maxReportImages   = 32
	maxReportOwners   = 48
	maxReportCoverage = 32
	// The bounds of decision 0038: the actions of a report, the IDs that an action lists, and its digests.
	maxReportActions = 256
	maxActionIDs     = 5
	maxActionDigests = 8
	// maxStatusBytes is the most JSON that a report's status takes. A report is one object, which must stay
	// below etcd's limit for a request, so its status may take 1 MiB of it, as a sheet's findings do.
	maxStatusBytes = 1 << 20

	maxVulnerabilityID = 64
	maxPackageName     = 253
	maxPackageVersion  = 128
	maxPackageType     = 32
	maxOwnerKey        = 317
	maxOwnerValue      = 256
)

var (
	// digestPattern is the pattern of the digests of a report, which the API checks.
	digestPattern = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
	// platformPattern is the pattern of the platform of an image in a report.
	platformPattern = regexp.MustCompile(`^[a-z0-9]+/[a-z0-9_]+(/[a-z0-9]+)?$`)
	// ownerKeyPattern is the pattern of the key of an owner value.
	ownerKeyPattern = regexp.MustCompile(`^([a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*/)?[A-Za-z0-9]([-A-Za-z0-9_.]*[A-Za-z0-9])?$`)
)

// RunningImage is an image that a workload runs, by its digest, and the platforms of the pods that run it, as
// os/architecture[/variant]. A pod that says no platform adds none.
type RunningImage struct {
	Digest    string
	Platforms []string
}

// ReportName is the name of a workload's report: the kind in lower case, a hyphen and the name of the workload, or the
// kind and a hash of the workload's API group, kind and name when that is no valid name or is longer than 253
// characters. A report lives in the namespace of its workload.
func ReportName(w evidence.PresenceWorkload) string {
	kind := strings.ToLower(w.Kind)
	if name := kind + "-" + w.Name; len(name) <= maxReportName && len(validation.IsDNS1123Subdomain(name)) == 0 {
		return name
	}
	sum := sha256.Sum256([]byte(w.APIGroup + "\x00" + w.Kind + "\x00" + w.Name))
	return kind + "-" + hex.EncodeToString(sum[:])
}

// WorkloadExposure is what the renderer knows of how far a workload can be reached: its SSVC exposure, which decides
// the urgency of each finding with the finding itself, and the reach that a report shows beside it (decision 0038).
type WorkloadExposure struct {
	// SSVC is the workload's SSVC exposure. Empty counts as Unknown.
	SSVC configv1alpha1.SSVCExposure
	// Reach is the workload's internal reach and whether an exposed workload reaches it, or nil when no evidence says
	// anything of the workload.
	Reach *triagev1alpha1.ReportReach
}

// Render builds the status of a workload's report. It is pure: it reads its arguments and nothing else.
//
// images are the images that the workload runs. sheets holds the sheets of the manifests, by manifest digest, and facts
// the facts of the images, by image digest; one that isn't there says that none exists yet. exposure is the workload's,
// and cfg gives the admin's overrides of the table.
//
//   - An image has one entry for each platform that its pods run on, in the order of its digest and platform: the
//     manifest that the facts name for the platform, with the state that the manifest's sheet has. A platform that
//     several manifests of different variants cover has an entry for each of them. At most 32 entries
//     are listed, and a digest that isn't a sha256 digest has none. The sheets of the entries past the 32 still feed the
//     actions and the summary. Only a sheet that says what it found, with counts and a findings version, counts: the
//     others leave the image Pending, and their findings out.
//   - Coverage comes from the sheet's evidence, which is per manifest. The facts keep the lowest coverage across
//     platforms, so they give it only where no sheet exists. Coverage never changes the state.
//   - The open findings are those of the sheets with the status Affected or UnderInvestigation, each once for a
//     vulnerability and a package, found in the images that the sheets of it belong to. Where the same finding is
//     Affected on one platform and UnderInvestigation on another, the Affected one stays.
//   - The actions group the open findings by package, installed version and next step (decision 0038), most urgent
//     first, then most severe, then by package. They are kept in that order as long as there are at most 256 and the
//     status stays below 1 MiB, and the summary counts the rest.
//   - The summary counts the open findings once for each vulnerability and package, and adds up the settled counts
//     of each sheet once, as the metrics count them. It also counts the entries that are Pending and those that are
//     Incomplete, past the 32 listed too, since their findings are missing from those counts.
//   - The reach is the exposure's, and absent without one.
//   - Each text that comes from image content is made printable, and cut to the schema's limit.
func Render(w evidence.PresenceWorkload, images []RunningImage, sheets map[string]*inventoryv1alpha1.ImageVerdicts,
	facts map[string]*inventoryv1alpha1.ImageFacts, exposure WorkloadExposure,
	cfg settings.Effective) triagev1alpha1.WorkloadReportStatus {
	return renderStatus(w, images, sheets, facts, exposure, cfg).status
}

// rendering is what renderStatus makes: the status, and what the metrics count beyond it.
type rendering struct {
	status triagev1alpha1.WorkloadReportStatus
	// open holds every finding that needs action, each once for a vulnerability and a package, before the report's
	// limits cut its actions: the metrics count what the report leaves out as well.
	open []candidate
	// counts adds up the counts of each sheet once, as the funnel counts them: a vulnerability that two platforms
	// share counts twice, since each manifest has its own sheet.
	counts sheetCounts
}

// sheetCounts adds up the counts of the sheets by status.
type sheetCounts struct{ affected, underInvestigation, notAffected, fixed int32 }

// renderStatus is Render, and also returns what the metrics count.
func renderStatus(w evidence.PresenceWorkload, images []RunningImage, sheets map[string]*inventoryv1alpha1.ImageVerdicts,
	facts map[string]*inventoryv1alpha1.ImageFacts, exposure WorkloadExposure, cfg settings.Effective) rendering {
	if exposure.SSVC == "" {
		exposure.SSVC = configv1alpha1.SSVCExposureUnknown
	}
	status := triagev1alpha1.WorkloadReportStatus{
		Exposure: ptr.To(triagev1alpha1.SSVCExposure(exposure.SSVC)),
		Owner:    ownerOf(w),
	}
	var used []usedSheet
	var waiting unsettled
	status.Images, used, waiting = reportImages(images, sheets, facts)
	var counts sheetCounts
	var candidates []candidate
	for _, u := range used {
		c := u.sheet.Status.Counts
		counts.affected += ptr.Deref(c.Affected, 0)
		counts.underInvestigation += ptr.Deref(c.UnderInvestigation, 0)
		counts.notAffected += ptr.Deref(c.NotAffected, 0)
		counts.fixed += ptr.Deref(c.Fixed, 0)
		for _, f := range u.sheet.Status.Findings {
			if open, ok := candidateOf(f, exposure.SSVC, cfg); ok {
				open.digests = u.digests
				candidates = append(candidates, open)
			}
		}
	}
	candidates = distinct(candidates)
	actions := actionsOf(candidates)
	status.Summary = summaryOf(candidates, actions, counts, waiting)
	status.Reach = exposure.Reach.DeepCopy()
	status.Actions = cutActions(status, actions)
	status.Summary.OmittedActions = ptr.To(int32(len(actions) - len(status.Actions)))
	return rendering{status: status, open: candidates, counts: counts}
}

// slot is one entry of a report's images: an image on a platform, which is empty when no pod says it.
type slot struct{ digest, platform string }

// slots lists the entries that a report has for the images, in the order of their digests and platforms. A digest that isn't a sha256 digest has none, and a platform that isn't one is left out, as if no pod said it.
func slots(images []RunningImage) []slot {
	ordered := slices.Clone(images)
	slices.SortFunc(ordered, func(a, b RunningImage) int { return strings.Compare(a.Digest, b.Digest) })
	var out []slot
	for _, image := range ordered {
		if !digestPattern.MatchString(image.Digest) {
			continue
		}
		platforms := slices.DeleteFunc(slices.Clone(image.Platforms), func(p string) bool { return !platformPattern.MatchString(p) })
		slices.Sort(platforms)
		platforms = slices.Compact(platforms)
		if len(platforms) == 0 {
			platforms = []string{""}
		}
		for _, platform := range platforms {
			out = append(out, slot{image.Digest, platform})
		}
	}
	return out
}

// manifestsOf returns the digests of the manifests that the report of the images names, each once, from the facts of
// the images by digest: the sheets that Render needs.
func manifestsOf(images []RunningImage, facts map[string]*inventoryv1alpha1.ImageFacts) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range slots(images) {
		for _, manifest := range manifestsFor(facts[s.digest], s.platform) {
			if !seen[manifest] {
				seen[manifest] = true
				out = append(out, manifest)
			}
		}
	}
	return out
}

// digestsOf returns the digests of the images that a report can name, sorted, each once: the images that it has a label
// for, also those past the entries of its list.
func digestsOf(images []RunningImage) []string {
	var out []string
	for _, s := range slots(images) {
		if len(out) == 0 || out[len(out)-1] != s.digest {
			out = append(out, s.digest)
		}
	}
	return out
}

// usedSheet is a sheet that counts for a report, and the digests of the images that run its manifest, sorted.
type usedSheet struct {
	sheet   *inventoryv1alpha1.ImageVerdicts
	digests []string
}

// unsettled counts the entries of a report's images that have no verdict: those that are Pending, and those that are
// Incomplete.
type unsettled struct{ pending, incomplete int }

// reportImages returns the entries of the images, at most 32, the sheets that count, each once with the digests of the
// images that run it, and the entries that have no verdict. A sheet counts whether or not its image has an entry, and
// so does an entry without a verdict, so that a limit of the list hides neither a finding nor an image that the report
// can't speak for yet.
func reportImages(images []RunningImage, sheets map[string]*inventoryv1alpha1.ImageVerdicts,
	facts map[string]*inventoryv1alpha1.ImageFacts) ([]triagev1alpha1.ReportImage, []usedSheet, unsettled) {
	all := slots(images)
	entries := make([]triagev1alpha1.ReportImage, 0, min(len(all), maxReportImages))
	var used []usedSheet
	var waiting unsettled
	at := map[string]int{}
	for _, s := range all {
		manifests := manifestsFor(facts[s.digest], s.platform)
		if len(manifests) == 0 {
			// No manifest is known: the entry is Pending, and a pod's platform that no manifest covers has no sheet.
			manifests = []string{""}
		}
		for _, manifest := range manifests {
			entry := triagev1alpha1.ReportImage{Digest: s.digest, State: triagev1alpha1.ReportImageStatePending}
			if s.platform != "" {
				entry.Platform = ptr.To(s.platform)
			}
			var sheet *inventoryv1alpha1.ImageVerdicts
			if manifest != "" {
				entry.ManifestDigest = ptr.To(manifest)
				sheet = sheets[manifest]
			}
			entry.State = stateOf(sheet)
			if sheet != nil {
				entry.Coverage = coverageOf(sheetCoverage(sheet))
			} else {
				entry.Coverage = coverageOf(factsCoverage(facts[s.digest]))
			}
			switch entry.State {
			case triagev1alpha1.ReportImageStatePending:
				waiting.pending++
			case triagev1alpha1.ReportImageStateIncomplete:
				waiting.incomplete++
			}
			if entry.State != triagev1alpha1.ReportImageStatePending {
				// The slots come in the order of their digests, so the digests of a sheet stay sorted.
				if i, seen := at[manifest]; !seen {
					at[manifest] = len(used)
					used = append(used, usedSheet{sheet: sheet, digests: []string{s.digest}})
				} else if last := used[i].digests; last[len(last)-1] != s.digest {
					used[i].digests = append(used[i].digests, s.digest)
				}
			}
			if len(entries) < maxReportImages {
				entries = append(entries, entry)
			}
		}
	}
	return entries, used, waiting
}

// manifestsFor returns the digests of the manifests that the facts name for a platform, sorted by platform and each
// once: those listed under the platform itself or, where none is, those that cover it, by the rule that the hub's
// assessor applies (inventory.PlatformCovers). A node says no variant of its architecture, so an image listed under
// several variants of it has them all, which the report reads, rather than one that it guessed. For no platform, it is
// the image's only manifest, and none when it has several, since no pod says which of them runs.
func manifestsFor(facts *inventoryv1alpha1.ImageFacts, platform string) []string {
	if facts == nil {
		return nil
	}
	var out []string
	add := func(digest string) {
		if digestPattern.MatchString(digest) && !slices.Contains(out, digest) {
			out = append(out, digest)
		}
	}
	if platform == "" {
		for _, m := range facts.Manifests {
			add(m.Digest)
		}
		if len(out) != 1 {
			return nil
		}
		return out
	}
	for _, m := range facts.Manifests {
		if m.Platform == platform {
			add(m.Digest)
		}
	}
	if len(out) > 0 {
		return out
	}
	covering := slices.Clone(facts.Manifests)
	slices.SortStableFunc(covering, func(a, b inventoryv1alpha1.ManifestFact) int { return strings.Compare(a.Platform, b.Platform) })
	for _, m := range covering {
		if inventory.PlatformCovers(m.Platform, platform) {
			add(m.Digest)
		}
	}
	return out
}

// stateOf says how far a sheet's result goes: Pending until the sheet says what it found, and Incomplete when it left
// out more findings than the settled ones, which come last in its order, so that an open finding is missing.
func stateOf(sheet *inventoryv1alpha1.ImageVerdicts) triagev1alpha1.ReportImageState {
	if sheet == nil || sheet.Status.Counts == nil || sheet.Status.FindingsVersion == nil {
		return triagev1alpha1.ReportImageStatePending
	}
	settled := ptr.Deref(sheet.Status.Counts.NotAffected, 0) + ptr.Deref(sheet.Status.Counts.Fixed, 0)
	if ptr.Deref(sheet.Status.OmittedFindings, 0) > settled {
		return triagev1alpha1.ReportImageStateIncomplete
	}
	return triagev1alpha1.ReportImageStateReady
}

// sourceCoverage is the coverage of one source and type before it is bounded.
type sourceCoverage struct {
	source, eventType string
	coverage          int32
}

func sheetCoverage(sheet *inventoryv1alpha1.ImageVerdicts) []sourceCoverage {
	var out []sourceCoverage
	for _, e := range sheet.Status.Evidence {
		if e.Coverage != nil {
			out = append(out, sourceCoverage{e.Source, e.Type, *e.Coverage})
		}
	}
	return out
}

func factsCoverage(facts *inventoryv1alpha1.ImageFacts) []sourceCoverage {
	var out []sourceCoverage
	if facts == nil {
		return nil
	}
	for _, e := range facts.Evidence {
		if e.Coverage != nil {
			out = append(out, sourceCoverage{e.Source, e.Type, *e.Coverage})
		}
	}
	return out
}

// coverageOf lists the coverage by source and type, sorted, with the lowest where one source and type repeat, and
// within the schema's bounds.
func coverageOf(in []sourceCoverage) []triagev1alpha1.ReportCoverage {
	lowest := map[[2]string]int32{}
	for _, c := range in {
		key := [2]string{c.source, c.eventType}
		if known, ok := lowest[key]; !ok || c.coverage < known {
			lowest[key] = c.coverage
		}
	}
	var out []triagev1alpha1.ReportCoverage
	for key, coverage := range lowest {
		out = append(out, triagev1alpha1.ReportCoverage{Source: text.CutChars(key[0], 44), Type: text.CutChars(key[1], 253),
			Coverage: ptr.To(min(max(coverage, 0), 100))})
	}
	slices.SortFunc(out, func(a, b triagev1alpha1.ReportCoverage) int {
		return cmp.Or(strings.Compare(a.Source, b.Source), strings.Compare(a.Type, b.Type))
	})
	if len(out) > maxReportCoverage {
		out = out[:maxReportCoverage]
	}
	return out
}

// The review states that the series count an open finding by: a rule concluded its status, or no one vouches for it.
const (
	reviewRuleSettled = "RuleSettled"
	reviewOpen        = "Open"
)

// candidate is one finding that needs action in a workload, once for a vulnerability and a package: what the actions
// group, and what the metrics count.
type candidate struct {
	id     string
	pkg    triagev1alpha1.ReportPackage
	status inventoryv1alpha1.VEXStatus
	// reviewState is reviewRuleSettled or reviewOpen.
	reviewState string
	urgency     triagev1alpha1.SSVCOutcome
	step        triagev1alpha1.NextStep
	// fixes are the versions that fix the vulnerability, as the sheet lists them, untouched: an update names one only
	// where it can name it exactly.
	fixes     []string
	severity  triagev1alpha1.Severity
	exploited bool
	// digests are the digests of the images that the finding was found in, sorted.
	digests []string
}

// candidateOf makes the candidate of a sheet's finding, and reports false for a finding that needs no action. Its texts
// are made printable and cut to the schema's limits.
func candidateOf(f inventoryv1alpha1.Finding, exposure configv1alpha1.SSVCExposure, cfg settings.Effective) (candidate, bool) {
	switch f.Status {
	case inventoryv1alpha1.VEXStatusAffected, inventoryv1alpha1.VEXStatusUnderInvestigation:
	default:
		return candidate{}, false
	}
	out := candidate{
		id: text.Required(f.VulnerabilityID, maxVulnerabilityID),
		pkg: triagev1alpha1.ReportPackage{
			Name:    text.Required(f.Package.Name, maxPackageName),
			Version: optional(ptr.Deref(f.Package.Version, ""), maxPackageVersion),
			Type:    text.Required(f.Package.Type, maxPackageType),
		},
		status:      f.Status,
		reviewState: reviewOpen,
		urgency:     triagev1alpha1.SSVCOutcome(urgency.Decide(urgency.FromFinding(f, exposure), cfg.Urgency.Overrides)),
		step:        urgency.NextStep(f),
		severity:    severityOf(f.Severity),
		exploited:   f.KnownExploited == inventoryv1alpha1.KnownExploitedListed,
	}
	out.fixes = slices.Clone(f.FixedVersions)
	if f.Status == inventoryv1alpha1.VEXStatusAffected && ptr.Deref(f.Rule, "") != "" {
		out.reviewState = reviewRuleSettled
	}
	return out, true
}

// optional returns s made printable and cut to n characters, or nil when nothing is left.
func optional(s string, n int) *string {
	if s = text.CutChars(text.Printable(s), n); s == "" {
		return nil
	}
	return &s
}

// severityOf maps a sheet's severity to the report's, and a value that this version doesn't know to Unknown, which
// the schema takes.
func severityOf(s inventoryv1alpha1.Severity) triagev1alpha1.Severity {
	for _, known := range severities {
		if string(known) == string(s) {
			return known
		}
	}
	return triagev1alpha1.SeverityUnknown
}

// severities lists the severities from the most severe down.
var severities = []triagev1alpha1.Severity{
	triagev1alpha1.SeverityCritical, triagev1alpha1.SeverityHigh, triagev1alpha1.SeverityMedium,
	triagev1alpha1.SeverityLow, triagev1alpha1.SeverityNegligible, triagev1alpha1.SeverityUnknown,
}

// urgencies lists the outcomes from the most urgent down.
var urgencies = []triagev1alpha1.SSVCOutcome{
	triagev1alpha1.SSVCOutcomeImmediate, triagev1alpha1.SSVCOutcomeOutOfCycle, triagev1alpha1.SSVCOutcomeScheduled,
	triagev1alpha1.SSVCOutcomeDefer,
}

// rank is the place of a value in a list: the lower, the earlier. A value that the list lacks comes first among
// urgencies, which err towards urgency, and last among severities, as rules.Sheet puts them.
func rank[T comparable](list []T, v T, unknown int) int {
	if i := slices.Index(list, v); i >= 0 {
		return i
	}
	return unknown
}

// distinct keeps one candidate for each vulnerability and package, with the digests of every image that it was found
// in. Of several, an Affected one stays.
func distinct(candidates []candidate) []candidate {
	type key struct{ id, name, version, kind string }
	at := map[key]int{}
	var out []candidate
	for _, c := range candidates {
		k := key{c.id, c.pkg.Name, ptr.Deref(c.pkg.Version, ""), c.pkg.Type}
		i, seen := at[k]
		switch {
		case !seen:
			at[k] = len(out)
			out = append(out, c)
			continue
		case out[i].status != inventoryv1alpha1.VEXStatusAffected && c.status == inventoryv1alpha1.VEXStatusAffected:
			c.digests, out[i] = out[i].digests, c
		}
		out[i].digests = union(out[i].digests, c.digests)
	}
	return out
}

// union returns the sorted digests of two sorted lists, each once.
func union(a, b []string) []string {
	return slices.Compact(slices.Sorted(slices.Values(slices.Concat(a, b))))
}

// steps lists the next steps in the order that a report gives the actions of one package.
var steps = []triagev1alpha1.NextStep{triagev1alpha1.NextStepUpdate, triagev1alpha1.NextStepMitigate, triagev1alpha1.NextStepInvestigate}

// compareCandidates is the order of the IDs of an action: the most urgent first, then the most severe, then by ID.
func compareCandidates(a, b candidate) int {
	return cmp.Or(
		cmp.Compare(rank(urgencies, a.urgency, -1), rank(urgencies, b.urgency, -1)),
		cmp.Compare(rank(severities, a.severity, len(severities)), rank(severities, b.severity, len(severities))),
		strings.Compare(a.id, b.id),
	)
}

// compareActions is the order of a report: the most urgent first, then the most severe, then by package name, version,
// type and step, so that the order is total and the same on every render.
func compareActions(a, b triagev1alpha1.ReportAction) int {
	return cmp.Or(
		cmp.Compare(rank(urgencies, a.Urgency, -1), rank(urgencies, b.Urgency, -1)),
		cmp.Compare(rank(severities, a.Severity, len(severities)), rank(severities, b.Severity, len(severities))),
		strings.Compare(a.Package.Name, b.Package.Name),
		strings.Compare(ptr.Deref(a.Package.Version, ""), ptr.Deref(b.Package.Version, "")),
		strings.Compare(a.Package.Type, b.Package.Type),
		cmp.Compare(rank(steps, a.Step, len(steps)), rank(steps, b.Step, len(steps))),
	)
}

// actionsOf groups the candidates by package, installed version and next step, as decision 0038 has it, in the order of
// a report. Each candidate is in exactly one action, so that the actions miss no open finding. An action takes the
// highest severity and urgency of its candidates, is known exploited when one of them is, counts them all, and lists the
// IDs of the first 5 and the first 8 digests of the images that they were found in. An Update names its target only
// where updateTarget finds one.
func actionsOf(candidates []candidate) []triagev1alpha1.ReportAction {
	type key struct {
		step                triagev1alpha1.NextStep
		name, version, kind string
	}
	groups := map[key][]candidate{}
	var keys []key
	for _, c := range candidates {
		k := key{c.step, c.pkg.Name, ptr.Deref(c.pkg.Version, ""), c.pkg.Type}
		if _, seen := groups[k]; !seen {
			keys = append(keys, k)
		}
		groups[k] = append(groups[k], c)
	}
	actions := make([]triagev1alpha1.ReportAction, 0, len(keys))
	for _, k := range keys {
		group := groups[k]
		slices.SortFunc(group, compareCandidates)
		action := triagev1alpha1.ReportAction{
			Step:            k.step,
			Package:         *group[0].pkg.DeepCopy(),
			Severity:        triagev1alpha1.SeverityUnknown,
			Urgency:         group[0].urgency,
			KnownExploited:  triagev1alpha1.KnownExploitedNotListed,
			Vulnerabilities: int32(min(len(group), math.MaxInt32)),
		}
		var digests []string
		for i, c := range group {
			if rank(severities, c.severity, len(severities)) < rank(severities, action.Severity, len(severities)) {
				action.Severity = c.severity
			}
			if c.exploited {
				action.KnownExploited = triagev1alpha1.KnownExploitedListed
			}
			if i < maxActionIDs {
				action.VulnerabilityIDs = append(action.VulnerabilityIDs, c.id)
			}
			digests = union(digests, c.digests)
		}
		if k.step == triagev1alpha1.NextStepUpdate {
			if target := updateTarget(k.kind, group); target != "" {
				action.FixedVersion = ptr.To(target)
			}
		}
		action.Digests = digests[:min(len(digests), maxActionDigests)]
		actions = append(actions, action)
	}
	slices.SortFunc(actions, compareActions)
	return actions
}

// plainVersion is the form of a fixed version whose order is plain (decision 0038): numbers separated by dots, and at
// most one release suffix, -rN, -N or .elN, which only some package types order after the numbers (releaseSuffixes).
// Epochs, tildes, pre-releases, letters and a leading v are outside it, since package managers order them each in
// their own way.
var plainVersion = regexp.MustCompile(`^([0-9]+(?:\.[0-9]+)*)(?:(-r|-|\.el)([0-9]+))?$`)

// releaseSuffixes lists, by package type, the release suffixes that its package manager orders after the plain
// numbers that they follow (decision 0038): -rN as Alpine writes a release, -N as Debian and RPM write a numeric
// revision, and RPM's .elN. Every other type takes plain dotted numbers only: npm, Go modules, Cargo and RubyGems read
// -N as a pre-release, which comes before the plain numbers, and an unknown type may do the same.
var releaseSuffixes = map[string][]string{
	packageTypeAPK: {"-r"},
	packageTypeDeb: {"-"},
	packageTypeRPM: {"-", ".el"},
}

// The package types whose release suffixes an update's target can carry, as the scanner names them.
const (
	packageTypeAPK = "apk"
	packageTypeDeb = "deb"
	packageTypeRPM = "rpm"
)

// updateTarget returns the version that an Update of a package of the type goes to, or "" where no target is
// unambiguous, since a wrong target is worse than none and the sheets keep each vulnerability's fixed versions
// (decision 0038). It names one only when each candidate names exactly one fixed version, and either all name the same
// one, or each is a plain version whose release, if any, is a suffix that the type orders after the numbers, and all
// releases are of one kind: then the highest, its numbers compared one by one and the release last. Two versions that
// compare equal but are spelt apart, as 1.02 and 1.2, name none, and so does a version that the field can't hold
// exactly.
func updateTarget(pkgType string, group []candidate) string {
	versions := make([]string, 0, len(group))
	for _, c := range group {
		if len(c.fixes) != 1 {
			return ""
		}
		versions = append(versions, c.fixes[0])
	}
	exact := func(v string) string {
		if ptr.Deref(optional(v, maxPackageVersion), "") != v {
			return ""
		}
		return v
	}
	if len(slices.Compact(slices.Sorted(slices.Values(versions)))) == 1 {
		return exact(versions[0])
	}
	parsed := make([]parsedVersion, 0, len(versions))
	kind := ""
	for _, v := range versions {
		p, ok := parseVersion(v)
		switch {
		case !ok:
			return ""
		case p.kind == "":
		case !slices.Contains(releaseSuffixes[pkgType], p.kind), kind != "" && p.kind != kind:
			// A release that the type orders otherwise, or releases of two kinds, have no order that is plain.
			return ""
		}
		kind = cmp.Or(kind, p.kind)
		parsed = append(parsed, p)
	}
	highest := parsed[0]
	for _, p := range parsed[1:] {
		if compareParsed(p, highest) > 0 {
			highest = p
		}
	}
	for _, p := range parsed {
		if p.text != highest.text && compareParsed(p, highest) == 0 {
			return ""
		}
	}
	return exact(highest.text)
}

// parsedVersion is a plain version: its numbers, and the kind and number of its release, which are empty without one.
type parsedVersion struct {
	text    string
	numbers []string
	kind    string
	release string
}

// parseVersion reads a plain version, and reports false for any other.
func parseVersion(v string) (parsedVersion, bool) {
	m := plainVersion.FindStringSubmatch(v)
	if m == nil {
		return parsedVersion{}, false
	}
	return parsedVersion{text: v, numbers: strings.Split(m[1], "."), kind: m[2], release: m[3]}, true
}

// compareParsed orders two plain versions: by their numbers one by one, a version that goes on past the other's last
// number being the higher, as package managers have it, then by their releases, none being the lowest.
func compareParsed(a, b parsedVersion) int {
	for i := range min(len(a.numbers), len(b.numbers)) {
		if c := compareNumbers(a.numbers[i], b.numbers[i]); c != 0 {
			return c
		}
	}
	if c := cmp.Compare(len(a.numbers), len(b.numbers)); c != 0 {
		return c
	}
	switch {
	case a.release == "" || b.release == "":
		return cmp.Compare(len(a.release), len(b.release))
	default:
		return compareNumbers(a.release, b.release)
	}
}

// compareNumbers orders two runs of digits by the numbers that they spell, however long.
func compareNumbers(x, y string) int {
	x, y = strings.TrimLeft(x, "0"), strings.TrimLeft(y, "0")
	return cmp.Or(cmp.Compare(len(x), len(y)), strings.Compare(x, y))
}

// summaryOf counts what a report's summary says: the open findings by status, urgency, severity and exploitation, each
// once for a vulnerability and a package as the candidates have them; the settled findings as the sheets count them,
// once for each manifest; the actions by step; and the entries of the images that have no verdict, which add nothing to
// the other counts, so that a report whose images aren't settled never reads as clean (decision 0038). It leaves
// omittedActions to the cut.
func summaryOf(candidates []candidate, actions []triagev1alpha1.ReportAction, counts sheetCounts,
	waiting unsettled) *triagev1alpha1.ReportSummary {
	var affected, unclear, critical, exploited int32
	var highest *triagev1alpha1.SSVCOutcome
	for _, c := range candidates {
		if c.status == inventoryv1alpha1.VEXStatusAffected {
			affected++
		} else {
			unclear++
		}
		if c.severity == triagev1alpha1.SeverityCritical {
			critical++
		}
		if c.exploited {
			exploited++
		}
		if highest == nil || rank(urgencies, c.urgency, -1) < rank(urgencies, *highest, -1) {
			highest = ptr.To(c.urgency)
		}
	}
	bySteps := map[triagev1alpha1.NextStep]int32{}
	for _, a := range actions {
		bySteps[a.Step]++
	}
	return &triagev1alpha1.ReportSummary{
		Affected: ptr.To(affected), UnderInvestigation: ptr.To(unclear),
		NotAffected: ptr.To(counts.notAffected), Fixed: ptr.To(counts.fixed),
		Actions: ptr.To(int32(len(actions))), Updates: ptr.To(bySteps[triagev1alpha1.NextStepUpdate]),
		Mitigations: ptr.To(bySteps[triagev1alpha1.NextStepMitigate]), Investigations: ptr.To(bySteps[triagev1alpha1.NextStepInvestigate]),
		OmittedActions: ptr.To(int32(0)), HighestUrgency: highest, Critical: ptr.To(critical), KnownExploited: ptr.To(exploited),
		Pending: ptr.To(int32(min(waiting.pending, math.MaxInt32))), Incomplete: ptr.To(int32(min(waiting.incomplete, math.MaxInt32))),
	}
}

// cutActions keeps the actions in order while there are at most 256 and the status stays below 1 MiB, each action
// counting the length of its JSON and one byte to separate it from the next. It stops at the first that doesn't fit,
// and never skips one to fit a later one, so that what it leaves out is the end of the order. The status holds
// everything but the actions already, and omittedActions at its widest.
func cutActions(status triagev1alpha1.WorkloadReportStatus, ordered []triagev1alpha1.ReportAction) []triagev1alpha1.ReportAction {
	if status.Summary != nil {
		status.Summary = status.Summary.DeepCopy()
		status.Summary.OmittedActions = ptr.To(int32(math.MaxInt32))
	}
	rest, err := json.Marshal(status)
	if err != nil {
		return nil
	}
	size := len(rest) + len(`,"actions":[]`)
	n := 0
	for n < len(ordered) && n < maxReportActions {
		encoded, err := json.Marshal(ordered[n])
		if err != nil || size+len(encoded)+1 > maxStatusBytes {
			break
		}
		size += len(encoded) + 1
		n++
	}
	return slices.Clone(ordered[:n])
}

// ownerOf lists the owner values of a workload: the allowlisted labels and annotations that presence gives, each from
// where it was copied, sorted by source and key. A value is made printable and cut to 256 characters, and at most 48
// are kept.
func ownerOf(w evidence.PresenceWorkload) []triagev1alpha1.OwnerValue {
	var out []triagev1alpha1.OwnerValue
	for _, from := range []struct {
		source triagev1alpha1.OwnerSource
		values []evidence.KeyValue
	}{
		{triagev1alpha1.OwnerSourceNamespaceLabel, w.NamespaceLabels},
		{triagev1alpha1.OwnerSourceNamespaceAnnotation, w.NamespaceAnnotations},
		{triagev1alpha1.OwnerSourceWorkloadLabel, w.Labels},
	} {
		values := slices.SortedFunc(slices.Values(from.values), func(a, b evidence.KeyValue) int {
			return strings.Compare(a.Key, b.Key)
		})
		last := ""
		for i, v := range values {
			if (i > 0 && v.Key == last) || len(v.Key) > maxOwnerKey || !ownerKeyPattern.MatchString(v.Key) {
				continue
			}
			last = v.Key
			out = append(out, triagev1alpha1.OwnerValue{Source: from.source, Key: v.Key,
				Value: ptr.To(text.CutChars(text.Printable(v.Value), maxOwnerValue))})
		}
	}
	if len(out) > maxReportOwners {
		out = out[:maxReportOwners]
	}
	return out
}
