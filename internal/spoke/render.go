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
	"github.com/bedag/vexplain/internal/settings"
	"github.com/bedag/vexplain/internal/text"
	"github.com/bedag/vexplain/internal/urgency"
	"github.com/bedag/vexplain/sdk/evidence"
)

// The limits of a report, which its schema sets, and the size that its status keeps below.
const (
	maxReportName     = 253
	maxReportImages   = 32
	maxReportFindings = 1000
	maxReportOwners   = 48
	maxReportCoverage = 32
	maxStatusNotes    = 4
	// maxStatusBytes is the most JSON that a report's status takes. A report is one object, which must stay
	// below etcd's limit for a request, so its status may take 1 MiB of it, as a sheet's findings do.
	maxStatusBytes = 1 << 20

	maxVulnerabilityID = 64
	maxPackageName     = 253
	maxPackageVersion  = 128
	maxPackageType     = 32
	maxReason          = 256
	maxNoteText        = 256
	maxNoteRule        = 63
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

// Render builds the status of a workload's report. It is pure: it reads its arguments and nothing else.
//
// images are the images that the workload runs. sheets holds the sheets of the manifests, by manifest digest, and facts
// the facts of the images, by image digest; one that isn't there says that none exists yet. exposure is the workload's,
// which decides the urgency of each finding with the finding itself, and cfg gives the admin's overrides of the table.
//
//   - An image has one entry for each platform that its pods run on, in the order of its digest and platform: the
//     manifest that the facts name for the platform, with the state that the manifest's sheet has. At most 32 entries
//     are listed, and a digest that isn't a sha256 digest has none. The sheets of the entries past the 32 still feed the
//     counts and the findings. Only a sheet that says what it found, with counts
//     and a findings version, counts: the others leave the image Pending, and their findings and counts out.
//   - Coverage comes from the sheet's evidence, which is per manifest. The facts keep the lowest coverage across
//     platforms, so they give it only where no sheet exists. Coverage never changes the state.
//   - The findings are those of the sheets with the status Affected or UnderInvestigation, each once for a
//     vulnerability and a package, most urgent first, then most severe, then by ID. They are kept in that order as long
//     as there are at most 1000 and the status stays below 1 MiB. omitted counts the rest. Where the same finding is
//     Affected on one platform and UnderInvestigation on another, the Affected one stays.
//   - counts adds up the counts of each sheet once. A vulnerability that two platforms share counts twice, since each
//     manifest has its own sheet.
//   - Each text that comes from image content is made printable, and cut to the schema's limit.
func Render(w evidence.PresenceWorkload, images []RunningImage, sheets map[string]*inventoryv1alpha1.ImageVerdicts,
	facts map[string]*inventoryv1alpha1.ImageFacts, exposure configv1alpha1.SSVCExposure,
	cfg settings.Effective) triagev1alpha1.WorkloadReportStatus {
	status, _ := renderStatus(w, images, sheets, facts, exposure, cfg)
	return status
}

// renderStatus is Render, and also returns every finding that needs action, each once for a vulnerability and a
// package, before the report's limits cut the list: the metrics count what the report leaves out as well.
func renderStatus(w evidence.PresenceWorkload, images []RunningImage, sheets map[string]*inventoryv1alpha1.ImageVerdicts,
	facts map[string]*inventoryv1alpha1.ImageFacts, exposure configv1alpha1.SSVCExposure,
	cfg settings.Effective) (triagev1alpha1.WorkloadReportStatus, []triagev1alpha1.ReportFinding) {
	if exposure == "" {
		exposure = configv1alpha1.SSVCExposureUnknown
	}
	status := triagev1alpha1.WorkloadReportStatus{
		Exposure: ptr.To(triagev1alpha1.SSVCExposure(exposure)),
		Owner:    ownerOf(w),
	}
	var used []*inventoryv1alpha1.ImageVerdicts
	status.Images, used = reportImages(images, sheets, facts)
	counts := triagev1alpha1.ReportCounts{
		Affected: ptr.To(int32(0)), UnderInvestigation: ptr.To(int32(0)), NotAffected: ptr.To(int32(0)), Fixed: ptr.To(int32(0)),
	}
	var candidates []triagev1alpha1.ReportFinding
	for _, sheet := range used {
		counts.Affected = ptr.To(*counts.Affected + ptr.Deref(sheet.Status.Counts.Affected, 0))
		counts.UnderInvestigation = ptr.To(*counts.UnderInvestigation + ptr.Deref(sheet.Status.Counts.UnderInvestigation, 0))
		counts.NotAffected = ptr.To(*counts.NotAffected + ptr.Deref(sheet.Status.Counts.NotAffected, 0))
		counts.Fixed = ptr.To(*counts.Fixed + ptr.Deref(sheet.Status.Counts.Fixed, 0))
		for _, f := range sheet.Status.Findings {
			if finding, ok := reportFinding(f, exposure, cfg); ok {
				candidates = append(candidates, finding)
			}
		}
	}
	status.Counts = &counts
	candidates = distinct(candidates)
	open := slices.Clone(candidates)
	slices.SortStableFunc(candidates, compareFindings)
	status.Findings = cutFindings(status, candidates)
	status.Omitted = ptr.To(int32(len(candidates) - len(status.Findings)))
	return status, open
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
		if manifest := manifestFor(facts[s.digest], s.platform); manifest != "" && !seen[manifest] {
			seen[manifest] = true
			out = append(out, manifest)
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

// reportImages returns the entries of the images, at most 32, and the sheets that count, each once. A sheet counts
// whether or not its image has an entry, so that a limit of the list hides no finding.
func reportImages(images []RunningImage, sheets map[string]*inventoryv1alpha1.ImageVerdicts,
	facts map[string]*inventoryv1alpha1.ImageFacts) ([]triagev1alpha1.ReportImage, []*inventoryv1alpha1.ImageVerdicts) {
	all := slots(images)
	entries := make([]triagev1alpha1.ReportImage, 0, min(len(all), maxReportImages))
	var used []*inventoryv1alpha1.ImageVerdicts
	counted := map[string]bool{}
	for _, s := range all {
		entry := triagev1alpha1.ReportImage{Digest: s.digest, State: triagev1alpha1.ReportImageStatePending}
		if s.platform != "" {
			entry.Platform = ptr.To(s.platform)
		}
		manifest := manifestFor(facts[s.digest], s.platform)
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
		if entry.State != triagev1alpha1.ReportImageStatePending && !counted[manifest] {
			counted[manifest] = true
			used = append(used, sheet)
		}
		if len(entries) < maxReportImages {
			entries = append(entries, entry)
		}
	}
	return entries, used
}

// manifestFor returns the digest of the manifest that the facts name for a platform: the one listed under it, or
// under it without its variant. For no platform, it is the image's only manifest, and none when it has several, since
// no pod says which of them runs.
func manifestFor(facts *inventoryv1alpha1.ImageFacts, platform string) string {
	if facts == nil {
		return ""
	}
	valid := func(digest string) bool { return digestPattern.MatchString(digest) }
	if platform == "" {
		distinct := map[string]bool{}
		for _, m := range facts.Manifests {
			if valid(m.Digest) {
				distinct[m.Digest] = true
			}
		}
		if len(distinct) != 1 {
			return ""
		}
		for digest := range distinct {
			return digest
		}
	}
	base := platform
	if parts := strings.Split(platform, "/"); len(parts) == 3 {
		base = parts[0] + "/" + parts[1]
	}
	for _, want := range []string{platform, base} {
		for _, m := range facts.Manifests {
			if m.Platform == want && valid(m.Digest) {
				return m.Digest
			}
		}
	}
	return ""
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

// reportFinding makes the report's finding of a sheet's, and reports false for a finding that needs no action.
func reportFinding(f inventoryv1alpha1.Finding, exposure configv1alpha1.SSVCExposure,
	cfg settings.Effective) (triagev1alpha1.ReportFinding, bool) {
	var status triagev1alpha1.VEXStatus
	switch f.Status {
	case inventoryv1alpha1.VEXStatusAffected:
		status = triagev1alpha1.VEXStatusAffected
	case inventoryv1alpha1.VEXStatusUnderInvestigation:
		status = triagev1alpha1.VEXStatusUnderInvestigation
	default:
		return triagev1alpha1.ReportFinding{}, false
	}
	out := triagev1alpha1.ReportFinding{
		VulnerabilityID: text.Required(f.VulnerabilityID, maxVulnerabilityID),
		Package: triagev1alpha1.ReportPackage{
			Name:    text.Required(f.Package.Name, maxPackageName),
			Version: optional(ptr.Deref(f.Package.Version, ""), maxPackageVersion),
			Type:    text.Required(f.Package.Type, maxPackageType),
		},
		Status: status,
		Urgency: triagev1alpha1.SSVCOutcome(urgency.Decide(urgency.FromFinding(f, exposure),
			cfg.Urgency.Overrides)),
		NextStep:    urgency.NextStep(f),
		ReviewState: triagev1alpha1.ReviewStateOpen,
		Reason:      optional(ptr.Deref(f.Reason, ""), maxReason),
		Severity:    severityOf(f.Severity),
	}
	if len(f.FixedVersions) > 0 {
		out.FixedVersion = optional(f.FixedVersions[0], maxPackageVersion)
	}
	if status == triagev1alpha1.VEXStatusAffected && ptr.Deref(f.Rule, "") != "" {
		out.ReviewState = triagev1alpha1.ReviewStateRuleSettled
	}
	for _, note := range f.StatusNotes[:min(len(f.StatusNotes), maxStatusNotes)] {
		out.StatusNotes = append(out.StatusNotes, triagev1alpha1.ReportStatusNote{
			Rule: text.Required(note.Rule, maxNoteRule),
			Text: text.Required(note.Text, maxNoteText),
		})
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

// compareFindings is the order of a report: the most urgent first, then the most severe, then by ID, package, version and
// type, so that the order is total and the same on every render.
func compareFindings(a, b triagev1alpha1.ReportFinding) int {
	return cmp.Or(
		cmp.Compare(rank(urgencies, a.Urgency, -1), rank(urgencies, b.Urgency, -1)),
		cmp.Compare(rank(severities, a.Severity, len(severities)), rank(severities, b.Severity, len(severities))),
		strings.Compare(a.VulnerabilityID, b.VulnerabilityID),
		strings.Compare(a.Package.Name, b.Package.Name),
		strings.Compare(ptr.Deref(a.Package.Version, ""), ptr.Deref(b.Package.Version, "")),
		strings.Compare(a.Package.Type, b.Package.Type),
	)
}

// distinct keeps one finding for each vulnerability and package. Of several, an Affected one stays.
func distinct(findings []triagev1alpha1.ReportFinding) []triagev1alpha1.ReportFinding {
	type key struct{ id, name, version, kind string }
	at := map[key]int{}
	var out []triagev1alpha1.ReportFinding
	for _, f := range findings {
		k := key{f.VulnerabilityID, f.Package.Name, ptr.Deref(f.Package.Version, ""), f.Package.Type}
		i, seen := at[k]
		switch {
		case !seen:
			at[k] = len(out)
			out = append(out, f)
		case out[i].Status != triagev1alpha1.VEXStatusAffected && f.Status == triagev1alpha1.VEXStatusAffected:
			out[i] = f
		}
	}
	return out
}

// cutFindings keeps the findings in order while there are at most 1000 and the status stays below 1 MiB, each finding
// counting the length of its JSON and one byte to separate it from the next. It stops at the first that doesn't fit,
// and never skips one to fit a later one, so that what it leaves out is the end of the order. The status holds
// everything but the findings already, and omitted at its widest.
func cutFindings(status triagev1alpha1.WorkloadReportStatus, ordered []triagev1alpha1.ReportFinding) []triagev1alpha1.ReportFinding {
	status.Omitted = ptr.To(int32(math.MaxInt32))
	rest, err := json.Marshal(status)
	if err != nil {
		return nil
	}
	size := len(rest) + len(`,"findings":[]`)
	n := 0
	for n < len(ordered) && n < maxReportFindings {
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
