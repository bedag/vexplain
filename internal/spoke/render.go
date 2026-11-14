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
	sdkworkloads "github.com/bedag/vexplain/sdk/workloads"
)

// The limits of a report, which its schema sets, and the size that its status keeps below.
const (
	maxReportName      = 253
	maxReportImages    = 32
	maxReportOwners    = 48
	maxImageManifests  = 8
	maxImageContainers = 32
	maxContainerName   = 63
	maxImageRef        = 512
	// The bounds of decisions 0038 and 0042: the actions of a report, the IDs that an action lists, and its title.
	maxReportActions = 256
	maxActionIDs     = 5
	maxActionTitle   = 256
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
	// platformPattern is the pattern of a platform that a pod says, as os/architecture[/variant].
	platformPattern = regexp.MustCompile(`^[a-z0-9]+/[a-z0-9_]+(/[a-z0-9]+)?$`)
	// ownerKeyPattern is the pattern of the key of an owner value.
	ownerKeyPattern = regexp.MustCompile(`^([a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*/)?[A-Za-z0-9]([-A-Za-z0-9_.]*[A-Za-z0-9])?$`)
)

// RunningImage is an image that a workload runs, by its digest, and the platforms of the pods that run it, as
// os/architecture[/variant]. A pod that says no platform adds none.
type RunningImage struct {
	Digest    string
	Platforms []string
	// Containers are the containers of the workload's pods that run the image, each once, sorted by name.
	Containers []sdkworkloads.ContainerRef
	// Kind is the digestKind of the image's presence: RepoDigest, ImageID, or Reference for an image that has no
	// digest.
	Kind string
	// Ref is the reference of an image of the kind Reference, as its containers name it, and empty for the others.
	Ref string
}

// unscannable reports whether no registry can serve the image for a scan, so that no verdict will come for it: an image
// ID, or an image that has no digest.
func (image RunningImage) unscannable() bool {
	return image.Kind == evidence.DigestKindImageID || image.Kind == evidence.DigestKindReference
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

// Render builds the status of a workload's ResourceReport. It is pure: it reads its arguments and nothing else.
//
// images are the images that the workload runs, and playbooks the names of the playbooks whose results the report
// holds (playbooksFor). sheets holds the sheets of the manifests, by manifest digest, each the sheets of the playbooks
// that have one, and facts the facts of the images, by image digest; one that isn't there says that none exists yet.
// exposure is the workload's, and cfg gives the admin's overrides of the table.
//
//   - An image has one entry, in the order of the digests: the manifests that the facts name for the platforms that its
//     pods run on, the first 8, and the names of the containers that run it, the first 32. A manifest listed under the
//     platform itself is read alone, since it is the one that runs: the manifests that only cover the platform, naming
//     no variant where it names one or a variant where it names none, aren't read with it. At most 32 entries are
//     listed, and a digest that isn't a sha256 digest has none. The images past the 32 still feed the actions and the
//     summary.
//   - An image ID, or an image that has no digest, only a reference, can't be scanned, so it is Unscannable, and no
//     sheet of it is read. The other images fail closed: an image is Pending until each of the playbooks has a sheet of
//     each of its manifests that says what it found, with counts and a findings version, and while a platform of its
//     pods has no manifest, or the report holds no playbook; else Incomplete where such a sheet left out more findings
//     than the settled ones; and else Ready. Each playbook is read from its own sheets alone, and a sheet that doesn't
//     say what it found adds no finding.
//   - The open findings are those of the sheets with the status Affected or UnderInvestigation, each once for a
//     playbook, an image, a vulnerability and a package, which actions merge only within one image (decision 0042).
//     Where the same finding is Affected on one platform and UnderInvestigation on another, the Affected one stays.
//     Where sheets give it apart otherwise, it takes the more urgent urgency and the more severe severity of them, is
//     known exploited where one says so, and has the fixed versions of all.
//   - The actions group the open findings by playbook, image, package, installed version and next step (decisions 0038
//     and 0042), most urgent first, then most severe, then by package. Each names its playbook as its requirement, and
//     the locations of the containers that run its image. They are kept in that order as long as there are at most 256
//     and the status stays below 1 MiB, and the summary counts the rest.
//   - The summary counts the actions by step, the critical ones and those known to be exploited, and the images that are
//     Pending and those that are Unscannable, past the 32 listed too, since their findings are missing from the actions.
//   - The reach is the exposure's, and absent without one.
//   - Each text that comes from image content or from presence is made printable, and cut to the schema's limit.
func Render(w evidence.PresenceWorkload, images []RunningImage, playbooks []string,
	sheets map[string][]inventoryv1alpha1.ImageVerdicts, facts map[string]*inventoryv1alpha1.ImageFacts,
	exposure WorkloadExposure, cfg settings.Effective) triagev1alpha1.ResourceReportStatus {
	return renderStatus(w, images, playbooks, sheets, facts, exposure, cfg).status
}

// rendering is what renderStatus makes: the status, and what the metrics count beyond it.
type rendering struct {
	status triagev1alpha1.ResourceReportStatus
	// open holds every finding that needs action, each once for a playbook, an image, a vulnerability and a package,
	// before the report's limits cut its actions: the metrics count what the report leaves out as well.
	open []candidate
	// counts adds up the counts of each sheet once, as the funnel counts them: a vulnerability that two platforms
	// share counts twice, since each manifest has its own sheet, and so does one that two playbooks judge.
	counts sheetCounts
	// cases are the cases of the worklist: every open finding of each sheet, in each image that runs its manifest, with
	// the verdict and urgency that the sheet gives it.
	cases []openCase
	// playbooks holds what the report counts for each playbook that it holds results of or has an action of, before
	// its limits cut its actions.
	playbooks map[string]inventory.Tally
}

// sheetCounts adds up the counts of the sheets by status.
type sheetCounts struct{ affected, underInvestigation, notAffected, fixed int32 }

// renderStatus is Render, and also returns what the metrics count.
func renderStatus(w evidence.PresenceWorkload, images []RunningImage, playbooks []string,
	sheets map[string][]inventoryv1alpha1.ImageVerdicts, facts map[string]*inventoryv1alpha1.ImageFacts,
	exposure WorkloadExposure, cfg settings.Effective) rendering {
	if exposure.SSVC == "" {
		exposure.SSVC = configv1alpha1.SSVCExposureUnknown
	}
	status := triagev1alpha1.ResourceReportStatus{
		Exposure: ptr.To(triagev1alpha1.SSVCExposure(exposure.SSVC)),
		Owner:    ownerOf(w),
	}
	var used []usedSheet
	var waiting unsettled
	status.Images, used, waiting = reportImages(images, playbooks, sheets, facts)
	var r rendering
	for _, u := range used {
		c := u.sheet.Status.Counts
		r.counts.affected += ptr.Deref(c.Affected, 0)
		r.counts.underInvestigation += ptr.Deref(c.UnderInvestigation, 0)
		r.counts.notAffected += ptr.Deref(c.NotAffected, 0)
		r.counts.fixed += ptr.Deref(c.Fixed, 0)
		for _, f := range u.sheet.Status.Findings {
			open, ok := candidateOf(f, exposure.SSVC, cfg)
			if !ok {
				continue
			}
			open.playbook = u.sheet.Spec.Playbook
			for _, digest := range u.digests {
				open.digest = digest
				r.open = append(r.open, open)
				r.cases = append(r.cases, openCase{open.id, digest, string(open.status), string(open.urgency)})
			}
		}
	}
	r.open = distinct(r.open)
	locations := map[string][]string{}
	for _, image := range images {
		locations[image.Digest] = locationsOf(w.Kind, image.Containers)
	}
	actions := actionsOf(r.open, locations)
	r.playbooks = playbookCountsOf(used, actions)
	status.Summary = summaryOf(actions, waiting)
	status.Reach = exposure.Reach.DeepCopy()
	status.Actions = cutActions(status, actions)
	status.Summary.OmittedActions = ptr.To(int32(len(actions) - len(status.Actions)))
	r.status = status
	return r
}

// sortedImages returns the images that a report can name, in the order of their digests: those whose digest is a
// sha256 digest, as presence keys every image.
func sortedImages(images []RunningImage) []RunningImage {
	out := slices.DeleteFunc(slices.Clone(images), func(image RunningImage) bool { return !digestPattern.MatchString(image.Digest) })
	slices.SortFunc(out, func(a, b RunningImage) int { return strings.Compare(a.Digest, b.Digest) })
	return out
}

// imageManifests returns the digests of the manifests that the facts name for the platforms of an image's pods, each
// once, in the order of the platforms, and whether each platform has one. A platform that isn't one is left out, as if
// no pod said it, and an image whose pods say none is read on the empty platform.
func imageManifests(image RunningImage, facts *inventoryv1alpha1.ImageFacts) (manifests []string, complete bool) {
	platforms := slices.DeleteFunc(slices.Clone(image.Platforms), func(p string) bool { return !platformPattern.MatchString(p) })
	slices.Sort(platforms)
	platforms = slices.Compact(platforms)
	if len(platforms) == 0 {
		platforms = []string{""}
	}
	complete = true
	for _, platform := range platforms {
		found := manifestsFor(facts, platform)
		if len(found) == 0 {
			complete = false
		}
		for _, manifest := range found {
			if !slices.Contains(manifests, manifest) {
				manifests = append(manifests, manifest)
			}
		}
	}
	return manifests, complete
}

// manifestsOf returns the digests of the manifests whose sheets the report of the images reads, each once, from the
// facts of the images by digest: the sheets that Render needs.
func manifestsOf(images []RunningImage, facts map[string]*inventoryv1alpha1.ImageFacts) []string {
	var out []string
	for _, image := range sortedImages(images) {
		if image.unscannable() {
			continue
		}
		manifests, _ := imageManifests(image, facts[image.Digest])
		for _, manifest := range manifests {
			if !slices.Contains(out, manifest) {
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
	for _, image := range sortedImages(images) {
		if len(out) == 0 || out[len(out)-1] != image.Digest {
			out = append(out, image.Digest)
		}
	}
	return out
}

// usedSheet is a sheet that counts for a report, and the digests of the images that run its manifest, sorted.
type usedSheet struct {
	sheet   *inventoryv1alpha1.ImageVerdicts
	digests []string
}

// unsettled counts the images of a report that have no verdict: those that are Pending, and those that are
// Unscannable.
type unsettled struct{ pending, unscannable int }

// reportImages returns the entries of the images, at most 32, the sheets that count, each once with the digests of the
// images that run its manifest, and the images that have no verdict. A sheet counts whether or not its image has an
// entry, and so does an image without a verdict, so that a limit of the list hides neither a finding nor an image that
// the report can't speak for yet.
func reportImages(images []RunningImage, playbooks []string, sheets map[string][]inventoryv1alpha1.ImageVerdicts,
	facts map[string]*inventoryv1alpha1.ImageFacts) ([]triagev1alpha1.ResourceImage, []usedSheet, unsettled) {
	ordered := sortedImages(images)
	entries := make([]triagev1alpha1.ResourceImage, 0, min(len(ordered), maxReportImages))
	var used []usedSheet
	var waiting unsettled
	type sheetKey struct{ manifest, playbook string }
	at := map[sheetKey]int{}
	for _, image := range ordered {
		entry := triagev1alpha1.ResourceImage{Digest: ptr.To(image.Digest), State: triagev1alpha1.ResourceImageStateReady,
			Containers: containerNames(image.Containers)}
		manifests, complete := imageManifests(image, facts[image.Digest])
		switch {
		case image.unscannable():
			entry.State = triagev1alpha1.ResourceImageStateUnscannable
			if image.Kind == evidence.DigestKindReference {
				// Its digest is the hash of its reference, which no registry knows. A reference cut to fit would name
				// another image.
				entry.Digest = nil
				if ref := optional(image.Ref, maxImageRef); ptr.Deref(ref, "") == image.Ref {
					entry.Ref = ref
				}
			}
			manifests = nil
		case !complete || len(playbooks) == 0:
			entry.State = triagev1alpha1.ResourceImageStatePending
		}
		entry.ManifestDigests = manifests[:min(len(manifests), maxImageManifests)]
		for _, manifest := range manifests {
			for _, playbook := range playbooks {
				sheet := playbookSheet(sheets[manifest], playbook)
				state := stateOf(sheet)
				entry.State = worse(entry.State, state)
				if state == triagev1alpha1.ResourceImageStatePending {
					continue
				}
				// The images come in the order of their digests, so the digests of a sheet stay sorted.
				key := sheetKey{manifest, playbook}
				if i, seen := at[key]; !seen {
					at[key] = len(used)
					used = append(used, usedSheet{sheet: sheet, digests: []string{image.Digest}})
				} else if last := used[i].digests; last[len(last)-1] != image.Digest {
					used[i].digests = append(used[i].digests, image.Digest)
				}
			}
		}
		switch entry.State {
		case triagev1alpha1.ResourceImageStatePending:
			waiting.pending++
		case triagev1alpha1.ResourceImageStateUnscannable:
			waiting.unscannable++
		}
		if len(entries) < maxReportImages {
			entries = append(entries, entry)
		}
	}
	return entries, used, waiting
}

// containerNames returns the names of the containers, made printable and cut to the schema's limit, sorted and each
// once, the first 32.
func containerNames(containers []sdkworkloads.ContainerRef) []string {
	var out []string
	for _, c := range containers {
		out = append(out, text.CutChars(text.Printable(c.Name), maxContainerName))
	}
	slices.Sort(out)
	out = slices.Compact(out)
	return out[:min(len(out), maxImageContainers)]
}

// playbookSheet returns, of the sheets of a manifest, the one of the playbook, or nil when it has none.
func playbookSheet(sheets []inventoryv1alpha1.ImageVerdicts, playbook string) *inventoryv1alpha1.ImageVerdicts {
	i := slices.IndexFunc(sheets, func(sheet inventoryv1alpha1.ImageVerdicts) bool { return sheet.Spec.Playbook == playbook })
	if i < 0 {
		return nil
	}
	return &sheets[i]
}

// worse returns, of the states of two results for an image, the one that says less of the image: Pending, then
// Incomplete, then Ready.
func worse(a, b triagev1alpha1.ResourceImageState) triagev1alpha1.ResourceImageState {
	order := []triagev1alpha1.ResourceImageState{triagev1alpha1.ResourceImageStatePending,
		triagev1alpha1.ResourceImageStateIncomplete, triagev1alpha1.ResourceImageStateReady}
	if slices.Index(order, b) < slices.Index(order, a) {
		return b
	}
	return a
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
func stateOf(sheet *inventoryv1alpha1.ImageVerdicts) triagev1alpha1.ResourceImageState {
	if sheet == nil || sheet.Status.Counts == nil || sheet.Status.FindingsVersion == nil {
		return triagev1alpha1.ResourceImageStatePending
	}
	settled := ptr.Deref(sheet.Status.Counts.NotAffected, 0) + ptr.Deref(sheet.Status.Counts.Fixed, 0)
	if ptr.Deref(sheet.Status.OmittedFindings, 0) > settled {
		return triagev1alpha1.ResourceImageStateIncomplete
	}
	return triagev1alpha1.ResourceImageStateReady
}

// The review states that the series count an open finding by: a rule concluded its status, or no one vouches for it.
const (
	reviewRuleSettled = "RuleSettled"
	reviewOpen        = "Open"
)

// candidate is one finding that needs action in a workload, once for a playbook, an image, a vulnerability and a
// package: what the actions group, and what the metrics count.
type candidate struct {
	// playbook is the playbook whose sheet gives the finding, and digest the image that it was found in.
	playbook, digest string
	id               string
	pkg              triagev1alpha1.ReportPackage
	status           inventoryv1alpha1.VEXStatus
	// reviewState is reviewRuleSettled or reviewOpen.
	reviewState string
	urgency     triagev1alpha1.SSVCOutcome
	step        triagev1alpha1.ResourceStep
	// updateTarget is the version that an update of the package goes to, as the sheet names it, untouched: an update
	// names it only where it can name it exactly. It is empty where the sheet names none.
	updateTarget string
	severity     triagev1alpha1.Severity
	exploited    bool
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
	out.updateTarget = ptr.Deref(f.UpdateTarget, "")
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

// distinct keeps one candidate for each playbook, image, vulnerability and package. Several are merged into one: those
// that the sheets of an image's platforms give. Candidates of two images or two playbooks are never merged (decision
// 0042).
func distinct(candidates []candidate) []candidate {
	type key struct{ playbook, digest, id, name, version, kind string }
	at := map[key]int{}
	var out []candidate
	for _, c := range candidates {
		k := key{c.playbook, c.digest, c.id, c.pkg.Name, ptr.Deref(c.pkg.Version, ""), c.pkg.Type}
		if i, seen := at[k]; seen {
			out[i] = merged(out[i], c)
			continue
		}
		at[k] = len(out)
		out = append(out, c)
	}
	return out
}

// merged is the one candidate of two that two sheets of an image give for the same vulnerability and package. Sheets give
// one apart when their matches ran on two versions of the database, or for two variants of the image, so the merge takes
// the safe side, whichever sheet comes first (decision 0038): the Affected one where only one is, with its review state
// and step; the more urgent urgency and the more severe severity; known exploited where either is; and the update
// target, only where both name the same one, since two versions can't be ordered without their scheme.
func merged(kept, other candidate) candidate {
	if kept.status != inventoryv1alpha1.VEXStatusAffected && other.status == inventoryv1alpha1.VEXStatusAffected {
		kept, other = other, kept
	}
	if rank(urgencies, other.urgency, -1) < rank(urgencies, kept.urgency, -1) {
		kept.urgency = other.urgency
	}
	if rank(severities, other.severity, len(severities)) < rank(severities, kept.severity, len(severities)) {
		kept.severity = other.severity
	}
	kept.exploited = kept.exploited || other.exploited
	if kept.updateTarget != other.updateTarget {
		kept.updateTarget = ""
	}
	return kept
}

// steps lists the next steps in the order that a report gives the actions of one package.
var steps = []triagev1alpha1.ResourceStep{triagev1alpha1.ResourceStepUpdate, triagev1alpha1.ResourceStepMitigate,
	triagev1alpha1.ResourceStepInvestigate}

// compareCandidates is the order of the IDs of an action: the most urgent first, then the most severe, then by ID.
func compareCandidates(a, b candidate) int {
	return cmp.Or(
		cmp.Compare(rank(urgencies, a.urgency, -1), rank(urgencies, b.urgency, -1)),
		cmp.Compare(rank(severities, a.severity, len(severities)), rank(severities, b.severity, len(severities))),
		strings.Compare(a.id, b.id),
	)
}

// compareActions is the order of a report: the most urgent first, then the most severe, then by package name, version,
// type and step, image and playbook, so that the order is total and the same on every render.
func compareActions(a, b triagev1alpha1.ResourceAction) int {
	return cmp.Or(
		cmp.Compare(rank(urgencies, ptr.Deref(a.Urgency, ""), -1), rank(urgencies, ptr.Deref(b.Urgency, ""), -1)),
		cmp.Compare(rank(severities, a.Severity, len(severities)), rank(severities, b.Severity, len(severities))),
		strings.Compare(a.Package.Name, b.Package.Name),
		strings.Compare(ptr.Deref(a.Package.Version, ""), ptr.Deref(b.Package.Version, "")),
		strings.Compare(a.Package.Type, b.Package.Type),
		cmp.Compare(rank(steps, a.Step, len(steps)), rank(steps, b.Step, len(steps))),
		strings.Compare(ptr.Deref(a.Digest, ""), ptr.Deref(b.Digest, "")),
		strings.Compare(a.Requirement.Playbook, b.Requirement.Playbook),
	)
}

// actionsOf groups the candidates by playbook, image, package, installed version and next step, as decisions 0038 and
// 0042 have it, in the order of a report. Each candidate is in exactly one action, so that the actions miss no open
// finding. An action names its playbook as its requirement, and the locations of the image by its digest. It takes the
// highest severity and urgency of its candidates, is known exploited when one of them is, counts them all, and lists the
// IDs of the first 5. An Update names its target only where every finding of the action carries the same one.
func actionsOf(candidates []candidate, locations map[string][]string) []triagev1alpha1.ResourceAction {
	type key struct {
		playbook, digest    string
		step                triagev1alpha1.ResourceStep
		name, version, kind string
	}
	groups := map[key][]candidate{}
	var keys []key
	for _, c := range candidates {
		k := key{c.playbook, c.digest, c.step, c.pkg.Name, ptr.Deref(c.pkg.Version, ""), c.pkg.Type}
		if _, seen := groups[k]; !seen {
			keys = append(keys, k)
		}
		groups[k] = append(groups[k], c)
	}
	actions := make([]triagev1alpha1.ResourceAction, 0, len(keys))
	for _, k := range keys {
		group := groups[k]
		slices.SortFunc(group, compareCandidates)
		action := triagev1alpha1.ResourceAction{
			Step:            k.step,
			Locations:       slices.Clone(locations[k.digest]),
			Severity:        triagev1alpha1.SeverityUnknown,
			Urgency:         ptr.To(group[0].urgency),
			Requirement:     triagev1alpha1.ResourceRequirement{Playbook: k.playbook},
			Package:         group[0].pkg.DeepCopy(),
			Vulnerabilities: ptr.To(int32(min(len(group), math.MaxInt32))),
			KnownExploited:  ptr.To(triagev1alpha1.KnownExploitedNotListed),
			Digest:          ptr.To(k.digest),
		}
		for i, c := range group {
			if rank(severities, c.severity, len(severities)) < rank(severities, action.Severity, len(severities)) {
				action.Severity = c.severity
			}
			if c.exploited {
				action.KnownExploited = ptr.To(triagev1alpha1.KnownExploitedListed)
			}
			if i < maxActionIDs {
				action.VulnerabilityIDs = append(action.VulnerabilityIDs, c.id)
			}
		}
		if k.step == triagev1alpha1.ResourceStepUpdate {
			if target := updateTargetOf(group); target != "" {
				action.FixedVersion = ptr.To(target)
			}
		}
		action.Title = titleOf(action)
		actions = append(actions, action)
	}
	slices.SortFunc(actions, compareActions)
	return actions
}

// titleOf says what an action of a package asks for, in a short sentence cut to the schema's limit: its step and the
// package's name, and the version that an Update goes to where it names one.
func titleOf(action triagev1alpha1.ResourceAction) string {
	title := string(action.Step) + " " + action.Package.Name
	if action.FixedVersion != nil {
		title += " to " + *action.FixedVersion
	}
	return text.CutChars(title, maxActionTitle)
}

// updateTargetOf returns the version that an Update goes to, or "" where no target is certain. The collector orders the
// versions in the scheme of the package's ecosystem, so the target is the one that the findings carry, and it is named
// only where every finding of the action carries the same one and the field can hold it exactly: a wrong target is worse
// than none, and two targets can't be ordered here (decision 0038).
func updateTargetOf(group []candidate) string {
	target := group[0].updateTarget
	for _, c := range group[1:] {
		if c.updateTarget != target {
			return ""
		}
	}
	if ptr.Deref(optional(target, maxPackageVersion), "") != target {
		return ""
	}
	return target
}

// summaryOf counts what a report's summary says: the actions by step, the critical ones and those known to be exploited,
// their highest severity and urgency, and the images that have no verdict, which add nothing to the actions, so that a
// report whose images aren't settled never reads as clean (decision 0038). It leaves omittedActions to the cut.
func summaryOf(actions []triagev1alpha1.ResourceAction, waiting unsettled) *triagev1alpha1.ResourceSummary {
	var critical, exploited int32
	var severity *triagev1alpha1.Severity
	var highest *triagev1alpha1.SSVCOutcome
	bySteps := map[triagev1alpha1.ResourceStep]int32{}
	for _, a := range actions {
		bySteps[a.Step]++
		if a.Severity == triagev1alpha1.SeverityCritical {
			critical++
		}
		if ptr.Deref(a.KnownExploited, "") == triagev1alpha1.KnownExploitedListed {
			exploited++
		}
		if severity == nil || rank(severities, a.Severity, len(severities)) < rank(severities, *severity, len(severities)) {
			severity = ptr.To(a.Severity)
		}
		if a.Urgency != nil && (highest == nil || rank(urgencies, *a.Urgency, -1) < rank(urgencies, *highest, -1)) {
			highest = ptr.To(*a.Urgency)
		}
	}
	return &triagev1alpha1.ResourceSummary{
		Actions: ptr.To(int32(len(actions))), Updates: ptr.To(bySteps[triagev1alpha1.ResourceStepUpdate]),
		Changes: ptr.To(bySteps[triagev1alpha1.ResourceStepChange]), Mitigations: ptr.To(bySteps[triagev1alpha1.ResourceStepMitigate]),
		Investigations: ptr.To(bySteps[triagev1alpha1.ResourceStepInvestigate]), OmittedActions: ptr.To(int32(0)),
		HighestSeverity: severity, HighestUrgency: highest, Critical: ptr.To(critical), KnownExploited: ptr.To(exploited),
		PendingImages:     ptr.To(int32(min(waiting.pending, math.MaxInt32))),
		UnscannableImages: ptr.To(int32(min(waiting.unscannable, math.MaxInt32))),
	}
}

// cutActions keeps the actions in order while there are at most 256 and the status stays below 1 MiB, each action
// counting the length of its JSON and one byte to separate it from the next. It stops at the first that doesn't fit,
// and never skips one to fit a later one, so that what it leaves out is the end of the order. The status holds
// everything but the actions already, and omittedActions at its widest.
func cutActions(status triagev1alpha1.ResourceReportStatus, ordered []triagev1alpha1.ResourceAction) []triagev1alpha1.ResourceAction {
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
