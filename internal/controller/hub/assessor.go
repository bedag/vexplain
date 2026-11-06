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

// Package hub holds the hub's decisions (decision 0021): what evidence a spoke must collect about each
// image, and what the vulnerabilities in each platform manifest come to.
//
// The hub runs Playbooks (decision 0034), whose pipelines of Rules decide in CEL (decision 0033). The
// RuleReconciler compiles each Rule, and says whether its last evaluations had errors. The
// PlaybookReconciler says whether each Playbook can run. The Assessor asks a spoke, through
// tasks.Executor, for the evidence that the playbook of the images in presence needs, gets the findings
// of each platform manifest from the playbook's findings collector, has the engine evaluate the rules,
// and writes the manifest's sheet. The Janitor deletes the evidence and the sheets that no image refers
// to any more.
//
// The hub reaches a spoke only through tasks.Executor, the evidence store and the inventory stores. It
// imports no package of a spoke, so that a hub can run without one.
package hub

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"math"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/semaphore"
	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/utils/clock"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
	inventoryv1alpha1 "github.com/bedag/vexplain/api/inventory/v1alpha1"
	"github.com/bedag/vexplain/internal/evidence"
	"github.com/bedag/vexplain/internal/inventory"
	"github.com/bedag/vexplain/internal/rules"
	"github.com/bedag/vexplain/internal/rules/engine"
	"github.com/bedag/vexplain/internal/tasks"
	"github.com/bedag/vexplain/internal/text"
	sdkevidence "github.com/bedag/vexplain/sdk/evidence"
	subjects "github.com/bedag/vexplain/sdk/subject"
)

const (
	// maxRetryWait is the longest that an image whose evidence failed waits before it is asked for again.
	maxRetryWait = 24 * time.Hour
	// notPullableMessage says why an image ID gets no evidence.
	notPullableMessage = "the digest is an image ID, which no registry serves"
	// maxFindingsVersionLength is the most characters of the version of the findings that a sheet
	// records, and maxCollectorVersionLength of the version of a collector.
	maxFindingsVersionLength  = 128
	maxCollectorVersionLength = 128
	// reasonUncovered is why an image is asked for again whose presence lists a platform that no
	// manifest of its facts covers.
	reasonUncovered = "a platform runs it that no manifest of its facts covers"
	// assessWorkers is how many manifests the assessor assesses at once: as many as the matcher collector
	// matches at once by default, whose setting maxConcurrent defaults to 2. A match is the costly part.
	// Their evaluations share evidenceBudget.
	assessWorkers = 2
)

// errPassedABound is what the assessor returns for an evaluation in which a run of a rule passed a bound
// on time, so that the controller reconciles the manifest again, with its back-off.
var errPassedABound = errors.New("a rule's run passed a bound on time, as in a stalled process: the sheet holds " +
	"what the rules failed closed to, and is evaluated again from its findings")

// evidenceBudget is the most decoded evidence, in bytes, that the evaluations of the assessor hold at
// once: 8 MiB. An evaluation holds about 11 times the decoded size of its evidence: the data, the tree
// that encoding/json makes of it, and the tree of CEL values that the engine makes of that tree. So
// what the evaluations hold at once stays near 90 MiB, whatever the images, while the evidence of two
// of the largest images of the measurement still fits at once. An evaluation whose evidence is larger
// takes the whole budget, and so runs alone: one event's data is at most 16 MiB, the limit of a message
// of the collector API.
const evidenceBudget int64 = 8 << 20

// Assessor runs the playbook of the images in presence. Of the Playbooks whose subjects are presence,
// ch.bedag.vexplain.presence.v1alpha1, it runs the oldest, which covers every image of the
// ImageInventory objects: presence doesn't say which Collector reported an image. It is two controllers.
//
// The first reconciles each image, under the name of its ImageInventory, and asks a spoke for the
// evidence that the playbook's findings collector consumes, of the Collector that the playbook names for
// it, when the playbook is Ready. In this order, the first that applies decides:
//   - an image ID gets the failure NotPullable in the facts, once, and is never asked for: no registry
//     serves an image by its ID
//   - an image whose last attempt of that Collector failed is asked for again once its wait is over:
//     RetryBase after the first failure, doubled for each further failure in a row, a day at most
//   - an image whose facts name no manifest is asked for
//   - an image is asked for again when the evidence store lacks the evidence of a manifest that its facts
//     name, at the Collector's current version
//   - an image is asked for again when its presence lists a platform that no manifest of its facts
//     covers, such as one that started running it after its scan. A platform that is new since the
//     last such request is asked for at once. The scan of an image that doesn't offer the platform, as
//     an index may lack the one of a node, finds the same manifests every time, so a platform that the
//     last request was for already waits as a failure does: RetryBase after that request, doubled for
//     each further request for it in a row, a day at most
//
// The evidence store, and not the facts, says whether the evidence is there: the facts can name
// evidence that went since. Its metadata says so, from the cache, and from the API server when the
// cache has none. After each request, and each look that found the evidence current, the image is
// looked at again in RetryBase: a request can get lost, and evidence can go without an event that this
// controller watches. An image that waits for a platform that no manifest covers is looked at again in
// RetryBase too, or when its wait is over if that comes first.
//
// The second reconciles each platform manifest, under its subject, and writes its sheet. It gets the
// findings from the findings collector, with the evidence that it consumes, has the engine evaluate the
// playbook's rules with the evidence that the playbook names, and writes what rules.Sheet keeps of them,
// with what each piece of evidence was, the version of the findings, and the playbook. It asks for the
// findings again when that evidence changes, when the playbook names another findings collector, when
// the findings collector says that the subject changed, and after a start. When only a rule, the
// playbook or another piece of evidence changes, it evaluates the sheet's findings again without asking
// for them, unless the sheet can't stand in for a new match: it leaves findings out, which it can't
// reopen, shows a match that may not be the one that the rules saw (rules.Matches), or holds findings
// that were matched from other evidence than the store holds now. Then it asks again.
//
// A match that fails is no answer, and the controller tries it again. Until it succeeds, the sheet must
// not keep verdicts that rules which changed since made: when what the sheet rests on changed, it is
// evaluated again from its findings if it can stand in for a match, and deleted if it can't. After a
// start, the assessor doesn't know what a sheet rests on, which counts as a change.
//
// A playbook that isn't Ready still has its sheets evaluated: a missing Collector's evidence is absent,
// and a rule that is missing or not Ready can't be evaluated, which keeps every finding from NotAffected
// and Fixed. Only a Ready playbook asks for findings, and only a Ready playbook asks for evidence. A
// sheet that it can neither evaluate again nor match again is deleted: what its findings rested on is
// gone, and no sheet means no verdict yet. A sheet never outlives the evidence that its findings were
// matched from, nor the playbook: without either it is deleted too. A playbook in Conflict is never the
// one that runs, so it leaves the sheets alone.
//
// An evaluation decodes the evidence that the playbook names, and holds it, with what the engine makes
// of it, until the engine is done. So the evaluations of the assessor hold at most evidenceBudget of
// decoded evidence at once, by the size that the evidence store records, and a match runs outside the
// budget: it decodes the evidence that it consumes itself. Evidence larger than the budget is evaluated
// alone.
//
// The assessor remembers in memory what each sheet rested on, so that an event that changes nothing
// costs no evaluation. An evaluation in which a run of a rule passed a bound on time is written, but
// not remembered: the assessor evaluates the sheet's findings again, with the controller's back-off,
// until an evaluation is complete. After a restart it matches every manifest once, and writes only the
// sheets that changed. A sheet is written only when it changes (decision 0023): one whose findings,
// number left out, counts, evidence and playbook stay the same keeps the version of the findings that
// last changed it.
//
// The version that a Collector delivers its evidence at now is its status.version, which the deployer
// records from the collector's GetInfo: the assessor reads it from the Collector, and calls no
// collector for it.
//
// setup.Register builds it. Both controllers need a findings collector.
type Assessor struct {
	// Client reads the Playbooks, the Rules and the Collectors from the manager's cache.
	Client client.Client
	// Store keeps the ImageInventory objects: the presence of each image, and its facts.
	Store inventory.Store
	// Evidence keeps the evidence, and Facts writes the facts of the images.
	Evidence evidence.Store
	Facts    evidence.FactsWriter
	// Verdicts keeps the sheets.
	Verdicts inventory.VerdictsStore
	// Executor takes the requests to a spoke.
	Executor tasks.Executor
	// Findings is the findings collector of the playbooks.
	Findings Findings
	// Rules compiles the rules, and Evaluations counts the findings that a rule couldn't be evaluated
	// for.
	Rules       *Rules
	Evaluations *Evaluations
	// RetryBase is how long an image waits after the first failed attempt of a Collector, and how long
	// the assessor waits after a request before it looks at the image again. It must be positive.
	RetryBase time.Duration
	// Clock tells the time. Nil means the real clock.
	Clock clock.PassiveClock

	mu sync.Mutex
	// assessed holds what the last evaluation of each manifest rested on, by its digest.
	assessed map[string]assessment
	// sequence counts the changes of findings that Findings.Changed delivered. allChangedAt is the
	// sequence of the last change of every subject, and changedAt of the last change of each manifest.
	sequence     uint64
	allChangedAt uint64
	changedAt    map[string]uint64
	// uncoveredAsks holds, by the digest of an image and then by the Collector and the type of the
	// evidence, the last request that platforms which no manifest covered called for.
	uncoveredAsks map[string]map[string]uncoveredAsk

	// budget holds evidenceBudget, of which each evaluation takes the decoded size of its evidence while
	// it decodes and evaluates it. budgetOnce makes it on first use.
	budgetOnce sync.Once
	budget     *semaphore.Weighted
	// holding, when it isn't nil, learns when an evaluation of a manifest starts to hold its share of the
	// budget, and when it stops. The tests watch the budget through it.
	holding func(manifest string, holds bool)
}

// uncoveredAsk is a request for the evidence of an image that platforms which no manifest of its facts
// covered called for.
type uncoveredAsk struct {
	// platforms are the platforms that no manifest covered, sorted.
	platforms []string
	// asks counts the requests in a row for these platforms, or some of them, and at is when the last
	// was made.
	asks int32
	at   time.Time
}

// assessment is what the last evaluation of a manifest rested on.
type assessment struct {
	// basis says what the playbook, its steps and its evidence were.
	basis string
	// matched says which evidence the findings were last matched from, and matchedAt what the sequence
	// of changes was when that match began. matched is empty while the findings weren't matched since
	// the start.
	matched   string
	matchedAt uint64
}

// ---- the requests of evidence ----

// requestEvidence asks a spoke for the evidence of the image of the request, or records that it can't be
// pulled, as its facts and the evidence store call for. A name that isn't the name of an image is
// ignored, and so is an image without an object.
func (a *Assessor) requestEvidence(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	digest, ok := inventory.DigestForName(req.Name)
	if !ok {
		return ctrl.Result{}, nil
	}
	obj, err := a.Store.Get(ctx, digest)
	if err != nil {
		return ctrl.Result{}, err
	}
	if obj == nil {
		a.forgetImage(digest)
		return ctrl.Result{}, nil
	}
	playbook, check, err := a.playbook(ctx)
	if err != nil {
		return ctrl.Result{}, err
	}
	if playbook == nil || !check.ready() {
		// Nothing is collected for a playbook that can't run. A change of the playbook, of a rule or of
		// a Collector looks at every image again.
		return ctrl.Result{}, nil
	}
	wanted := a.consumed(playbook)
	switch ptr.Deref(obj.Status.DigestKind, "") {
	case inventoryv1alpha1.DigestKindImageID:
		for _, e := range wanted {
			if err := a.markNotPullable(ctx, digest, obj.Status.Facts, e.Collector); err != nil {
				return ctrl.Result{}, err
			}
		}
		return ctrl.Result{}, nil
	case inventoryv1alpha1.DigestKindRepoDigest:
		return a.ask(ctx, obj, wanted)
	}
	// Until the presence of the digest says what kind it is, nobody knows whether it can be pulled.
	return ctrl.Result{}, nil
}

// ask asks for each piece of the wanted evidence about the repository digest of obj that its facts and
// the evidence store say is missing or stale.
func (a *Assessor) ask(ctx context.Context, obj *inventoryv1alpha1.ImageInventory,
	wanted []configv1alpha1.PlaybookEvidence) (ctrl.Result, error) {
	log := logf.FromContext(ctx).WithValues("digest", obj.Spec.Digest)
	repositories := repositoriesOf(obj)
	// The image is looked at again when the first of its waits is over, and else in RetryBase.
	var look ctrl.Result
	again := func(after time.Duration) {
		if look.RequeueAfter == 0 || after < look.RequeueAfter {
			look.RequeueAfter = after
		}
	}
	for _, e := range wanted {
		why, wait, err := a.why(ctx, obj, e)
		switch {
		case err != nil:
			return ctrl.Result{}, err
		case wait > 0:
			again(wait)
			continue
		}
		again(a.RetryBase)
		if why == "" {
			continue
		}
		if len(repositories) == 0 {
			// A spoke can't pull the image without a repository. The presence that names one is an
			// event of its own.
			log.V(1).Info("Asked for no evidence: no repository to pull the image from")
			return ctrl.Result{}, nil
		}
		r := tasks.Request{Type: e.Type, Subject: subjects.Image(obj.Spec.Digest), Repositories: repositories}
		if err := a.Executor.Request(ctx, r); err != nil {
			return ctrl.Result{}, fmt.Errorf("ask for evidence of type %s about %s: %w", e.Type, obj.Spec.Digest, err)
		}
		if why == reasonUncovered {
			a.askedUncovered(obj.Spec.Digest, e, uncoveredPlatforms(obj))
		}
		log.V(1).Info("Asked for evidence", "type", e.Type, "collector", e.Collector, "because", why)
	}
	return look, nil
}

// why says why the image of obj is to be asked for the evidence e, and returns "" when it is current,
// or how long it waits before it is looked at again: after a failure, until it may be asked for again;
// after a request for platforms that no manifest covers, until then or for RetryBase, whichever is
// shorter, since the evidence of its manifests can go without an event in the day that this wait can
// reach, and a look finds that. The wait after a failure counts whatever version the facts name: they
// name the collector of the last success, which an image that fails under a new version keeps, and
// without the wait it would be asked for at every look.
func (a *Assessor) why(ctx context.Context, obj *inventoryv1alpha1.ImageInventory,
	e configv1alpha1.PlaybookEvidence) (string, time.Duration, error) {
	facts := obj.Status.Facts
	if failure := failureOf(facts, e.Collector); failure != nil {
		if wait := a.retryAfter(failure); wait > 0 {
			return "", wait, nil
		}
		return "its last attempt failed, and its wait is over", 0, nil
	}
	if facts == nil || len(facts.Manifests) == 0 {
		return "no manifest of it has evidence yet", 0, nil
	}
	current, err := a.collectorVersion(ctx, e.Collector)
	if err != nil {
		return "", 0, err
	}
	for _, manifest := range facts.Manifests {
		version, held, err := a.Evidence.Version(ctx, evidence.Key{Subject: subjects.Manifest(manifest.Digest), Type: e.Type, Source: e.Collector})
		switch {
		case err != nil:
			// A failed read is never mistaken for absent evidence.
			return "", 0, fmt.Errorf("look for the evidence of manifest %s: %w", manifest.Digest, err)
		case !held:
			return "the evidence of a manifest is gone", 0, nil
		case current != "" && version != current:
			return "another version of the collector delivered the evidence of a manifest", 0, nil
		}
	}
	uncovered := uncoveredPlatforms(obj)
	if len(uncovered) == 0 {
		return "", 0, nil
	}
	if wait := a.uncoveredWait(obj.Spec.Digest, e, uncovered); wait > 0 {
		return "", min(wait, a.RetryBase), nil
	}
	return reasonUncovered, 0, nil
}

// collectorVersion returns the version that the Collector of the name delivers its evidence at now: its
// status.version, which the deployer records from the collector's GetInfo. It returns "" when that
// isn't known, for a Collector without a version or one that is gone: evidence of any version is
// current then, and a playbook that names a Collector that is gone asks for nothing anyway.
func (a *Assessor) collectorVersion(ctx context.Context, name string) (string, error) {
	var c configv1alpha1.Collector
	if err := a.Client.Get(ctx, client.ObjectKey{Name: name}, &c); err != nil {
		if apierrors.IsNotFound(err) {
			return "", nil
		}
		return "", fmt.Errorf("read the version of Collector %s: %w", name, err)
	}
	return ptr.Deref(c.Status.Version, ""), nil
}

// uncoveredPlatforms returns the platforms that the presence of obj lists and that no manifest of its
// facts covers, sorted, each once. A manifest covers a platform of the same operating system and
// architecture, and of the same variant, or of any variant when either names none: a node says no
// variant of its architecture.
func uncoveredPlatforms(obj *inventoryv1alpha1.ImageInventory) []string {
	var manifests []string
	if obj.Status.Facts != nil {
		for _, manifest := range obj.Status.Facts.Manifests {
			manifests = append(manifests, manifest.Platform)
		}
	}
	var uncovered []string
	for _, entry := range obj.Status.Clusters {
		for _, running := range entry.Platforms {
			if !slices.ContainsFunc(manifests, func(manifest string) bool { return covers(manifest, running) }) {
				uncovered = append(uncovered, running)
			}
		}
	}
	slices.Sort(uncovered)
	return slices.Compact(uncovered)
}

// uncoveredWait returns how long the image of digest waits before it is asked for the evidence e again
// for the uncovered platforms, or zero or less when it may be asked for now: when one of them is new
// since the last request that uncovered platforms called for, or the wait after that request is over.
// The wait is the one after failed attempts, from the last request, with the requests for these
// platforms in a row as the attempts. The last request is kept while the image runs, also while its
// manifests cover every platform, so that a platform that its pods leave and come back to doesn't
// count as new each time.
func (a *Assessor) uncoveredWait(digest string, e configv1alpha1.PlaybookEvidence, uncovered []string) time.Duration {
	a.mu.Lock()
	defer a.mu.Unlock()
	last, ok := a.uncoveredAsks[digest][evidenceKey(e)]
	if !ok || !subset(uncovered, last.platforms) {
		return 0
	}
	return last.at.Add(retryWait(a.RetryBase, last.asks)).Sub(a.now())
}

// askedUncovered notes a request for the evidence e of the image of digest, which the uncovered
// platforms called for. A request for the platforms of the last one, or some of them, counts one more
// in a row; one for a new platform starts the count again.
func (a *Assessor) askedUncovered(digest string, e configv1alpha1.PlaybookEvidence, uncovered []string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.uncoveredAsks == nil {
		a.uncoveredAsks = map[string]map[string]uncoveredAsk{}
	}
	asks := a.uncoveredAsks[digest]
	if asks == nil {
		asks = map[string]uncoveredAsk{}
		a.uncoveredAsks[digest] = asks
	}
	next := uncoveredAsk{platforms: uncovered, asks: 1, at: a.now()}
	if last, ok := asks[evidenceKey(e)]; ok && subset(uncovered, last.platforms) && last.asks < math.MaxInt32 {
		next.asks = last.asks + 1
	}
	asks[evidenceKey(e)] = next
}

// forgetImage forgets what the assessor remembers of the requests for an image that runs nowhere any
// more.
func (a *Assessor) forgetImage(digest string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.uncoveredAsks, digest)
}

// evidenceKey names the evidence e by its Collector and its type, which a request asks for.
func evidenceKey(e configv1alpha1.PlaybookEvidence) string {
	return e.Collector + "/" + e.Type
}

// subset reports whether each of the sorted platforms is one of the sorted of.
func subset(platforms, of []string) bool {
	for _, platform := range platforms {
		if _, found := slices.BinarySearch(of, platform); !found {
			return false
		}
	}
	return true
}

// covers reports whether the manifest of a platform covers a platform that a pod runs on.
func covers(manifest, running string) bool {
	m, r := strings.SplitN(manifest, "/", 3), strings.SplitN(running, "/", 3)
	if len(m) < 2 || len(r) < 2 || m[0] != r[0] || m[1] != r[1] {
		return false
	}
	return len(m) == 2 || len(r) == 2 || m[2] == r[2]
}

// failureOf returns the failure that facts record of a Collector, or nil when they record none.
func failureOf(facts *inventoryv1alpha1.ImageFacts, collector string) *inventoryv1alpha1.ScanFailure {
	if facts == nil {
		return nil
	}
	i := slices.IndexFunc(facts.Failures, func(f inventoryv1alpha1.ScanFailure) bool { return f.Source == collector })
	if i < 0 {
		return nil
	}
	return &facts.Failures[i]
}

// retryAfter returns how long an image whose attempts failed has still to wait before it is asked for
// again, or a duration of zero or less when its wait is over. The wait runs from the last failure.
func (a *Assessor) retryAfter(failure *inventoryv1alpha1.ScanFailure) time.Duration {
	if failure.Time == nil {
		return 0
	}
	return failure.Time.Add(retryWait(a.RetryBase, failure.Attempts)).Sub(a.now())
}

// retryWait returns the wait after attempts failures in a row: base, doubled for each failure after
// the first, maxRetryWait at most.
func retryWait(base time.Duration, attempts int32) time.Duration {
	wait := base
	for failure := int32(1); failure < attempts && wait < maxRetryWait; failure++ {
		wait *= 2
	}
	return min(wait, maxRetryWait)
}

// markNotPullable records in the facts of digest, an image ID, that the Collector can't pull it, unless
// they say so already: the mark is made once, and keeps the time it was made. The facts hold the
// failures of 8 sources at most, and a mark that they can't hold is dropped: asking again changes
// nothing.
func (a *Assessor) markNotPullable(ctx context.Context, digest string, facts *inventoryv1alpha1.ImageFacts, collector string) error {
	if failure := failureOf(facts, collector); failure != nil && failure.Reason == inventoryv1alpha1.ScanFailureReasonNotPullable {
		return nil
	}
	log := logf.FromContext(ctx).WithValues("digest", digest, "collector", collector)
	err := a.Facts.Failed(ctx, digest, collector, string(inventoryv1alpha1.ScanFailureReasonNotPullable), notPullableMessage)
	switch {
	case errors.Is(err, evidence.ErrRefused):
		log.Info("Dropped the mark that an image ID can't be pulled, which the facts can't hold")
		return nil
	case err != nil:
		return fmt.Errorf("record that image ID %s can't be pulled: %w", digest, err)
	}
	log.Info("Recorded that an image ID can't be pulled, so its evidence is never asked for")
	return nil
}

// now returns the time of the assessor's clock.
func (a *Assessor) now() time.Time {
	if a.Clock == nil {
		return time.Now()
	}
	return a.Clock.Now()
}

// repositoriesOf returns the repositories that the presence of obj names, in every cluster: sorted,
// and each once.
func repositoriesOf(obj *inventoryv1alpha1.ImageInventory) []string {
	var repositories []string
	for _, entry := range obj.Status.Clusters {
		repositories = append(repositories, entry.Repositories...)
	}
	slices.Sort(repositories)
	return slices.Compact(repositories)
}

// ---- the playbook ----

// playbook returns the playbook that assesses the images in presence, with what a check of it found: the
// oldest of the Playbooks whose subjects are presence, whatever Collector delivers them, which is the
// one that no other puts in Conflict. It returns nil when there is none.
func (a *Assessor) playbook(ctx context.Context) (*configv1alpha1.Playbook, *playbookCheck, error) {
	var playbooks configv1alpha1.PlaybookList
	if err := a.Client.List(ctx, &playbooks); err != nil {
		return nil, nil, fmt.Errorf("list the Playbooks: %w", err)
	}
	var chosen *configv1alpha1.Playbook
	for i := range playbooks.Items {
		p := &playbooks.Items[i]
		if p.Spec.Subjects.Type == sdkevidence.TypePresence && (chosen == nil || older(p, chosen)) {
			chosen = p
		}
	}
	if chosen == nil {
		return nil, nil, nil
	}
	check, err := checkPlaybook(ctx, a.Client, a.Rules, chosen, playbooks.Items)
	if err != nil {
		return nil, nil, err
	}
	return chosen, check, nil
}

// consumed returns the evidence that the playbook names and that its findings collector consumes,
// sorted by name: the evidence that a match needs.
func (a *Assessor) consumed(playbook *configv1alpha1.Playbook) []configv1alpha1.PlaybookEvidence {
	consumable := a.Findings.Consumes(playbook.Spec.Findings.Collector)
	var consumed []configv1alpha1.PlaybookEvidence
	for _, e := range playbook.Spec.Evidence {
		if slices.Contains(consumable, e.Type) {
			consumed = append(consumed, e)
		}
	}
	slices.SortFunc(consumed, func(x, y configv1alpha1.PlaybookEvidence) int { return strings.Compare(x.Name, y.Name) })
	return consumed
}

// ---- the sheets ----

// assess keeps the sheet of the manifest of the request current, as Assessor describes. A name that
// isn't the subject of a manifest is ignored.
func (a *Assessor) assess(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	manifest, ok := manifestOf(req.Name)
	if !ok {
		return ctrl.Result{}, nil
	}
	log := logf.FromContext(ctx).WithValues("manifest", manifest)
	ctx = logf.IntoContext(ctx, log)
	playbook, check, err := a.playbook(ctx)
	if err != nil {
		return ctrl.Result{}, err
	}
	if playbook == nil {
		// No playbook assesses the image, so no rule stands behind a sheet of it.
		return ctrl.Result{}, a.deleteSheet(ctx, manifest)
	}
	// The evidence is read without its data, which only the match and the evaluation decode.
	var consumed *configv1alpha1.PlaybookEvidence
	var record *evidence.Encoded
	if all := a.consumed(playbook); len(all) > 0 {
		consumed = &all[0]
		if record, err = a.Evidence.GetEncoded(ctx, keyOf(manifest, *consumed)); err != nil {
			return ctrl.Result{}, err
		}
		if record == nil {
			// The janitor deletes a sheet before its evidence, and a match that was under way then may
			// have put it back. No list covers the sheets, so it would stay for good.
			return ctrl.Result{}, a.deleteSheet(ctx, manifest)
		}
	}
	pieces, err := a.evidenceOf(ctx, playbook, check, manifest, consumed, record)
	if err != nil {
		return ctrl.Result{}, err
	}
	sheet, err := a.Verdicts.Get(ctx, manifest)
	if err != nil {
		return ctrl.Result{}, err
	}

	basis := check.basis + "|" + basisOf(pieces)
	matchedKey := ""
	if record != nil {
		// A match rests on the findings collector and on the evidence that it consumed: a change of either
		// calls for a new one.
		matchedKey = fmt.Sprintf("%s|%s|%s|%d", playbook.Spec.Findings.Collector, record.CollectorVersion,
			record.EventID, record.Time.Unix())
	}
	canFind := check.ready() && consumed != nil
	last, sequence := a.last(manifest)
	stale := last.matched == "" || last.matched != matchedKey || a.changedSince(manifest, last.matchedAt) ||
		sheet == nil || sheet.Status.FindingsVersion == nil
	if last.basis == basis && (!stale || !canFind) {
		// Nothing that the sheet rests on changed, and either the findings are current, or no match can be
		// made until something changes.
		return ctrl.Result{}, nil
	}

	e := evaluation{
		manifest: manifest, playbook: playbook.Name, steps: check.steps, evidence: pieces, stored: sheet,
		next: assessment{basis: basis, matched: last.matched, matchedAt: last.matchedAt},
	}
	fromSheet, reusable := sheetMatches(sheet, consumed, record, record != nil && last.matched == matchedKey)
	switch {
	case (stale || !reusable) && canFind:
		// The match needs the data of the evidence that it consumes, so it decodes it outside the budget,
		// as two matches run at once. Evidence that can't be read is no answer, and changes nothing.
		decoded, err := record.Decode()
		if err != nil {
			return ctrl.Result{}, err
		}
		found, err := a.find(ctx, playbook.Spec.Findings.Collector, manifest, decoded)
		if err != nil {
			return ctrl.Result{}, a.unmatched(ctx, e, fromSheet, reusable, last.basis != basis, err)
		}
		e.next.matched, e.next.matchedAt = matchedKey, sequence
		return ctrl.Result{}, a.evaluate(ctx, e, found.Matches, &found.Version)
	case reusable:
		return ctrl.Result{}, a.evaluate(ctx, e, fromSheet, sheet.Status.FindingsVersion)
	default:
		// No match can be made, and the findings of the sheet can't be evaluated again: what they rested
		// on is gone, so the sheet says that there is no verdict.
		if sheet != nil {
			log.Info("Deleted a sheet that can neither be matched again nor evaluated again", "playbook", playbook.Name)
		}
		return ctrl.Result{}, a.deleteSheet(ctx, manifest)
	}
}

// find returns the findings of the manifest that the findings collector finds in record, the evidence
// that it consumes, with their version printable and cut to what a sheet records. Findings without a
// version are no answer.
func (a *Assessor) find(ctx context.Context, collector, manifest string, record *evidence.Record) (sdkevidence.Findings, error) {
	found, err := a.Findings.Find(ctx, collector, record.Event)
	if err != nil {
		return sdkevidence.Findings{}, fmt.Errorf("find the findings of manifest %s: %w", manifest, err)
	}
	found.Version = text.CutChars(text.Printable(found.Version), maxFindingsVersionLength)
	if found.Version == "" {
		return sdkevidence.Findings{}, fmt.Errorf("the findings of manifest %s name no version", manifest)
	}
	return found, nil
}

// evaluation is what an evaluation of the findings of a manifest takes besides the matches: the steps of
// the playbook, the evidence that it names, the stored sheet, and what the evaluation rests on.
type evaluation struct {
	manifest, playbook string
	steps              []*engine.Compiled
	evidence           []piece
	stored             *inventoryv1alpha1.ImageVerdicts
	next               assessment
}

// piece is a piece of the evidence that a playbook names: what a sheet records of it, from what the store
// says before the data is decoded, and its record, which is nil when the rules can't have it.
type piece struct {
	entry  inventoryv1alpha1.SheetEvidence
	record *evidence.Encoded
}

// weight returns how much of the budget the evaluation takes: the decoded size of its evidence, as the
// store records it, and the whole budget for evidence that is larger.
func (e evaluation) weight() int64 {
	var size int64
	for _, p := range e.evidence {
		if p.record != nil {
			size += p.record.Size
		}
	}
	return min(size, evidenceBudget)
}

// evaluate has the engine evaluate the steps on the matches, writes the sheet with the version of the
// findings, and remembers what the sheet rests on.
//
// An evaluation in which a run of a rule passed a bound on time is written all the same, since what the
// rules conclude then fails closed. But it isn't what the evidence gives, as a hint may lack its note and
// a rule that settles may not apply, so it doesn't stand for the sheet: the assessor remembers the match,
// and not what the sheet rests on, and returns errPassedABound, so that the controller reconciles the
// manifest again with its back-off, and the sheet's findings are evaluated again without a new match. The
// bounds are on wall time, and the stall that passed them is usually over by then.
func (a *Assessor) evaluate(ctx context.Context, e evaluation, matches []sdkevidence.Match, version *string) error {
	result, entries, err := a.evaluateWithin(ctx, e, matches)
	if err != nil {
		return err
	}
	if err := a.write(ctx, e.manifest, e.stored, sheetOf(e.playbook, entries, result, version)); err != nil {
		return err
	}
	a.Evaluations.Record(subjects.Manifest(e.manifest), result.NotEvaluated)
	if !result.Timely() {
		// No basis that assess computes is empty, so the next reconcile evaluates the sheet again.
		incomplete := e.next
		incomplete.basis = ""
		a.remember(e.manifest, incomplete)
		return fmt.Errorf("evaluate the findings of manifest %s: %w (findings by rule: %s)", e.manifest, errPassedABound,
			timedOut(result))
	}
	a.remember(e.manifest, e.next)
	return nil
}

// timedOut says, for each rule with a run that passed a bound on time, sorted by name, for how many
// findings.
func timedOut(result engine.Result) string {
	var parts []string
	for _, rule := range slices.Sorted(maps.Keys(result.TimedOut)) {
		if n := result.TimedOut[rule]; n > 0 {
			parts = append(parts, fmt.Sprintf("%s %d", rule, n))
		}
	}
	return strings.Join(parts, ", ")
}

// evaluateWithin decodes the evidence of e and has the engine evaluate the steps on the matches, while it
// holds as much of the budget as the evidence takes: it waits for that much, until ctx ends. It returns
// the result, and what the sheet records of the evidence as the rules read it. What it decodes is
// garbage once it returns.
func (a *Assessor) evaluateWithin(ctx context.Context, e evaluation, matches []sdkevidence.Match) (engine.Result,
	[]inventoryv1alpha1.SheetEvidence, error) {
	release, err := a.hold(ctx, e.manifest, e.weight())
	if err != nil {
		return engine.Result{}, nil, fmt.Errorf("wait to evaluate the findings of manifest %s: %w", e.manifest, err)
	}
	defer release()
	inputs, entries, err := inputsOf(ctx, e.evidence)
	if err != nil {
		return engine.Result{}, nil, err
	}
	return engine.Evaluate(e.steps, inputs, matches), entries, nil
}

// hold waits until the budget has weight to spare, or ctx ends, and takes it for an evaluation of manifest.
// It returns the function that gives it back. The budget hands out what it has in the order of the
// waits, so an evaluation that waits for the whole budget isn't passed by smaller ones.
func (a *Assessor) hold(ctx context.Context, manifest string, weight int64) (func(), error) {
	a.budgetOnce.Do(func() { a.budget = semaphore.NewWeighted(evidenceBudget) })
	if err := a.budget.Acquire(ctx, weight); err != nil {
		return nil, err
	}
	if a.holding != nil {
		a.holding(manifest, true)
	}
	return func() {
		if a.holding != nil {
			a.holding(manifest, false)
		}
		a.budget.Release(weight)
	}, nil
}

// unmatched handles a match that failed with err, and returns err, so that the controller tries the
// match again. The failure says nothing about the findings, but when what the sheet rests on changed
// since its last evaluation, changed says so, its verdicts may be those of rules that are gone. A sheet
// that can stand in for a match, as reusable says, is then evaluated again from its findings with the
// rules of now, and one that can't is deleted. A sheet whose basis didn't change stays as it is.
func (a *Assessor) unmatched(ctx context.Context, e evaluation, fromSheet []sdkevidence.Match, reusable, changed bool,
	err error) error {
	switch {
	case !changed:
		// The sheet holds what the rules of now made of its findings, which may only be older than the
		// source's.
	case reusable:
		if evaluateErr := a.evaluate(ctx, e, fromSheet, e.stored.Status.FindingsVersion); evaluateErr != nil {
			return errors.Join(err, evaluateErr)
		}
	default:
		if e.stored != nil {
			logf.FromContext(ctx).Info("Deleted a sheet whose match failed after what it rests on changed, and that can't be evaluated again",
				"playbook", e.playbook)
		}
		if deleteErr := a.deleteSheet(ctx, e.manifest); deleteErr != nil {
			return errors.Join(err, deleteErr)
		}
	}
	return err
}

// write writes status as the sheet of manifest, whose stored sheet is stored, or nil when it has none. A
// sheet whose findings and the rest stay the same keeps the version of the findings that last changed
// them, and so the store writes nothing.
func (a *Assessor) write(ctx context.Context, manifest string, stored *inventoryv1alpha1.ImageVerdicts,
	status inventoryv1alpha1.ImageVerdictsStatus) error {
	if stored != nil && stored.Status.FindingsVersion != nil {
		kept := status.DeepCopy()
		kept.FindingsVersion = stored.Status.FindingsVersion
		if equality.Semantic.DeepEqual(stored.Status, *kept) {
			return nil
		}
	}
	if err := a.Verdicts.Put(ctx, manifest, status); err != nil {
		return err
	}
	logf.FromContext(ctx).Info("Wrote the sheet of a manifest", "playbook", ptr.Deref(status.Playbook, ""),
		"findingsVersion", ptr.Deref(status.FindingsVersion, ""),
		"affected", *status.Counts.Affected, "underInvestigation", *status.Counts.UnderInvestigation,
		"notAffected", *status.Counts.NotAffected, "fixed", *status.Counts.Fixed, "omitted", *status.OmittedFindings)
	return nil
}

// evidenceOf returns the evidence that the playbook names, sorted by name, without decoding its data:
// what the sheet records of each piece, as the store says it, and its record. The evidence of a
// Collector that is missing, or that a rule takes with another type, is absent, as is evidence that the
// store doesn't hold. record is the evidence that the findings collector consumes, which the caller read
// already.
func (a *Assessor) evidenceOf(ctx context.Context, playbook *configv1alpha1.Playbook, check *playbookCheck, manifest string,
	consumed *configv1alpha1.PlaybookEvidence, record *evidence.Encoded) ([]piece, error) {
	named := slices.Clone(playbook.Spec.Evidence)
	slices.SortFunc(named, func(x, y configv1alpha1.PlaybookEvidence) int { return strings.Compare(x.Name, y.Name) })
	pieces := make([]piece, 0, len(named))
	for _, e := range named {
		p := piece{entry: inventoryv1alpha1.SheetEvidence{Name: e.Name, Source: e.Collector, Type: e.Type}}
		if !check.absent[e.Name] {
			p.record = record
			if consumed == nil || e.Name != consumed.Name {
				var err error
				if p.record, err = a.Evidence.GetEncoded(ctx, keyOf(manifest, e)); err != nil {
					return nil, err
				}
			}
			if p.record != nil {
				p.entry.Version = ptr.To(versionOf(p.record))
				p.entry.Time = ptr.To(metav1.NewTime(timeOf(p.record)))
				if p.record.Coverage != nil {
					p.entry.Coverage = ptr.To(*p.record.Coverage)
				}
			}
		}
		pieces = append(pieces, p)
	}
	return pieces, nil
}

// inputsOf decodes the evidence, and returns it as the rules read it, by name, with what the sheet
// records of each piece, in the order of the pieces. A record that can't be read is an error, and never
// absent evidence.
func inputsOf(ctx context.Context, pieces []piece) (map[string]engine.Input, []inventoryv1alpha1.SheetEvidence, error) {
	inputs := map[string]engine.Input{}
	entries := make([]inventoryv1alpha1.SheetEvidence, 0, len(pieces))
	for _, p := range pieces {
		entry := p.entry
		if p.record != nil {
			held, err := p.record.Decode()
			if err != nil {
				return nil, nil, err
			}
			var data any
			if err := json.Unmarshal(held.Event.Data(), &data); err != nil {
				// The store keeps JSON only. Evidence that isn't is missing, and settles nothing: the sheet
				// doesn't claim it.
				logf.FromContext(ctx).Info("Took evidence whose data isn't JSON for missing", "evidence", entry.Name)
				entry = inventoryv1alpha1.SheetEvidence{Name: entry.Name, Source: entry.Source, Type: entry.Type}
			} else {
				in := engine.Input{Present: true, Data: data, Time: held.Event.Time(), Source: held.Event.Source()}
				if coverage, ok := sdkevidence.Coverage(held.Event); ok {
					in.Coverage = ptr.To(coverage)
				}
				inputs[entry.Name] = in
			}
		}
		entries = append(entries, entry)
	}
	return inputs, entries, nil
}

// basisOf says what each piece of evidence that a sheet records was, so that a change of one shows.
func basisOf(pieces []piece) string {
	parts := make([]string, 0, len(pieces))
	for _, p := range pieces {
		e := p.entry
		if e.Version == nil {
			parts = append(parts, e.Name+":absent")
			continue
		}
		parts = append(parts, fmt.Sprintf("%s:%s@%d#%d", e.Name, *e.Version, e.Time.Unix(), ptr.Deref(e.Coverage, -1)))
	}
	return strings.Join(parts, ",")
}

// versionOf returns the version of the collector that delivered record as a sheet shows it: printable,
// and cut to the schema's limit. A collector reports its version itself.
func versionOf(record *evidence.Encoded) string {
	return text.Required(record.CollectorVersion, maxCollectorVersionLength)
}

// timeOf returns the time of the evidence of record as a sheet records it: to the second.
func timeOf(record *evidence.Encoded) time.Time {
	return record.Time.Truncate(time.Second)
}

// sheetMatches returns the matches that the findings of a sheet show, and whether the rules can evaluate
// them in place of a new match:
//   - the sheet has a verdict, leaves no finding out, and shows each match exactly, as rules.Matches
//     says
//   - its findings were matched from record, the evidence consumed, which the findings collector
//     consumes now: the assessor remembers that match, as known says, or the sheet's entry of the
//     evidence names record. Matches of other evidence could name packages that record lacks, or that
//     are other packages in it. A findings collector that consumes none of the playbook's evidence
//     vouches for no findings.
//
// A sheet's findings are evaluated again only with the evidence that they were matched from, so the
// sheet's entry of it names the evidence of the match, unless the rules couldn't have it.
func sheetMatches(sheet *inventoryv1alpha1.ImageVerdicts, consumed *configv1alpha1.PlaybookEvidence, record *evidence.Encoded,
	known bool) ([]sdkevidence.Match, bool) {
	if sheet == nil || sheet.Status.FindingsVersion == nil || sheet.Status.Counts == nil ||
		ptr.Deref(sheet.Status.OmittedFindings, 0) > 0 || consumed == nil || record == nil {
		return nil, false
	}
	if !known && !matchedFrom(sheet, *consumed, record) {
		return nil, false
	}
	return rules.Matches(sheet.Status.Findings)
}

// matchedFrom reports whether the sheet records the evidence e as record is: from its Collector, of its
// type, at the version of the collector that delivered it, and of its time.
func matchedFrom(sheet *inventoryv1alpha1.ImageVerdicts, e configv1alpha1.PlaybookEvidence, record *evidence.Encoded) bool {
	i := slices.IndexFunc(sheet.Status.Evidence, func(entry inventoryv1alpha1.SheetEvidence) bool { return entry.Name == e.Name })
	if i < 0 {
		return false
	}
	entry := sheet.Status.Evidence[i]
	return entry.Source == e.Collector && entry.Type == e.Type && entry.Version != nil && entry.Time != nil &&
		*entry.Version == versionOf(record) && entry.Time.Time.Equal(timeOf(record))
}

// sheetOf returns the sheet of what the engine made of the findings: what rules.Sheet keeps of them, with
// the evidence, the version of the findings and the playbook.
func sheetOf(playbook string, entries []inventoryv1alpha1.SheetEvidence, result engine.Result,
	version *string) inventoryv1alpha1.ImageVerdictsStatus {
	kept, omitted, counts := rules.Sheet(rules.Findings(result.Findings))
	return inventoryv1alpha1.ImageVerdictsStatus{
		Playbook:        ptr.To(playbook),
		FindingsVersion: version,
		Evidence:        entries,
		Findings:        kept,
		OmittedFindings: ptr.To(omitted),
		Counts:          &counts,
	}
}

// keyOf returns the key of the evidence e about a manifest.
func keyOf(manifest string, e configv1alpha1.PlaybookEvidence) evidence.Key {
	return evidence.Key{Subject: subjects.Manifest(manifest), Type: e.Type, Source: e.Collector}
}

// deleteSheet deletes the sheet of a manifest, and forgets what it rested on.
func (a *Assessor) deleteSheet(ctx context.Context, manifest string) error {
	if err := a.Verdicts.Delete(ctx, manifest); err != nil {
		return err
	}
	a.mu.Lock()
	delete(a.assessed, manifest)
	delete(a.changedAt, manifest)
	a.mu.Unlock()
	a.Evaluations.Forget(subjects.Manifest(manifest))
	return nil
}

// last returns what the last evaluation of a manifest rested on, nothing for a manifest that the
// assessor doesn't remember, and the sequence of the changes of findings now.
func (a *Assessor) last(manifest string) (assessment, uint64) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.assessed[manifest], a.sequence
}

// remember keeps what the evaluation of a manifest rested on, whose findings its sheet now holds.
func (a *Assessor) remember(manifest string, last assessment) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.assessed == nil {
		a.assessed = map[string]assessment{}
	}
	a.assessed[manifest] = last
}

// changed notes that the findings collector changed the findings of a subject, or of every subject for
// an empty one. A match that began before it is stale.
func (a *Assessor) changed(subject string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.sequence++
	if subject == "" {
		a.allChangedAt = a.sequence
		return
	}
	if manifest, ok := manifestOf(subject); ok {
		if a.changedAt == nil {
			a.changedAt = map[string]uint64{}
		}
		a.changedAt[manifest] = a.sequence
	}
}

// changedSince reports whether the findings collector changed the findings of a manifest since the
// sequence at.
func (a *Assessor) changedSince(manifest string, at uint64) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.allChangedAt > at || a.changedAt[manifest] > at
}

// changedQueue is the work queue of the assessor's controller of sheets, as Findings.Changed sees it: it
// notes each subject that it gets as changed before it hands it on, so that its match is stale, and
// hands on every manifest that has evidence for a request with an empty name, which stands for every
// subject.
type changedQueue struct {
	workqueue.TypedRateLimitingInterface[reconcile.Request]
	ctx      context.Context
	assessor *Assessor
}

func (q *changedQueue) Add(req reconcile.Request) {
	for _, r := range q.mark(req) {
		q.TypedRateLimitingInterface.Add(r)
	}
}

func (q *changedQueue) AddAfter(req reconcile.Request, d time.Duration) {
	for _, r := range q.mark(req) {
		q.TypedRateLimitingInterface.AddAfter(r, d)
	}
}

func (q *changedQueue) AddRateLimited(req reconcile.Request) {
	for _, r := range q.mark(req) {
		q.TypedRateLimitingInterface.AddRateLimited(r)
	}
}

// mark notes the subject of req as changed, and returns the requests of the manifests that it stands
// for.
func (q *changedQueue) mark(req reconcile.Request) []reconcile.Request {
	q.assessor.changed(req.Name)
	if req.Name != "" {
		return []reconcile.Request{req}
	}
	return q.assessor.everyManifest(q.ctx, nil)
}

// changes is the source of the subjects whose findings changed: Findings.Changed, through changedQueue.
func (a *Assessor) changes() source.Source {
	return source.Func(func(ctx context.Context, queue workqueue.TypedRateLimitingInterface[reconcile.Request]) error {
		return a.Findings.Changed().Start(ctx, &changedQueue{TypedRateLimitingInterface: queue, ctx: ctx, assessor: a})
	})
}

// everyManifest maps an event to every platform manifest that has evidence. It lists the subjects in the
// cache that the watch of the evidence keeps, and not from the API server: nothing maps an event twice,
// so a list that failed would lose it for good. The cache answers once it has synced, and fails only
// when ctx ends, as the manager stops.
func (a *Assessor) everyManifest(ctx context.Context, _ client.Object) []reconcile.Request {
	manifests, err := manifestsWithEvidence(ctx, a.Evidence)
	if err != nil {
		logf.FromContext(ctx).Error(err, "Could not list the evidence to assess every manifest again")
		return nil
	}
	requests := make([]reconcile.Request, 0, len(manifests))
	for _, manifest := range manifests {
		requests = append(requests, manifestRequest(manifest))
	}
	return requests
}

// everyImage maps an event to every image in presence, as the manager's cache lists them.
func (a *Assessor) everyImage(ctx context.Context, _ client.Object) []reconcile.Request {
	digests, err := a.Store.Digests(ctx)
	if err != nil {
		logf.FromContext(ctx).Error(err, "Could not list the images to look at every one again")
		return nil
	}
	requests := make([]reconcile.Request, 0, len(digests))
	for _, digest := range digests {
		requests = append(requests, reconcile.Request{NamespacedName: types.NamespacedName{Name: inventory.NameForDigest(digest)}})
	}
	return requests
}

// manifestsWithEvidence returns the digest of each platform manifest that has evidence in store.
func manifestsWithEvidence(ctx context.Context, store evidence.Store) ([]string, error) {
	all, err := store.Subjects(ctx)
	if err != nil {
		return nil, err
	}
	manifests := make([]string, 0, len(all))
	for _, subject := range all {
		if manifest, ok := manifestOf(subject); ok {
			manifests = append(manifests, manifest)
		}
	}
	return manifests, nil
}

// manifestOf returns the digest of the platform manifest that a subject names, and false for a subject
// that names none.
func manifestOf(subject string) (string, bool) {
	about, err := subjects.Parse(subject)
	if err != nil || about.Kind != subjects.KindManifest {
		return "", false
	}
	return about.Digest, true
}

// manifestRequest returns the request under which the assessor's controller of sheets reconciles a
// platform manifest: its subject, as the evidence store's Source names it.
func manifestRequest(manifest string) reconcile.Request {
	return reconcile.Request{NamespacedName: types.NamespacedName{Name: subjects.Manifest(manifest)}}
}

// ---- the controllers ----

// SetupRequestsWithManager sets up the controller of requests with the Manager. It refuses an assessor
// without a positive RetryBase, which would ask again at once after every failure, and one that can't
// tell what to ask for.
func (a *Assessor) SetupRequestsWithManager(mgr ctrl.Manager) error {
	if a.RetryBase <= 0 {
		return errors.New("the assessor needs a positive wait after a failed attempt")
	}
	if a.Findings == nil {
		return errors.New("the assessor needs a findings collector to ask for evidence")
	}
	every := handler.EnqueueRequestsFromMapFunc(a.everyImage)
	return ctrl.NewControllerManagedBy(mgr).
		Named("hub-evidence-requests").
		// Every event of an ImageInventory, through the store, the only door to them: a new image, a
		// change of its presence, and the facts that its evidence writes.
		WatchesRawSource(a.Store.Source()).
		// Every image, when the playbook, a rule or a Collector changes whether it can run.
		Watches(&configv1alpha1.Playbook{}, every, builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		Watches(&configv1alpha1.Rule{}, every, builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		Watches(&configv1alpha1.Collector{}, every, builder.WithPredicates(collectorChanged())).
		Complete(reconcile.Func(a.requestEvidence))
}

// SetupWithManager sets up the controller of sheets with the Manager.
func (a *Assessor) SetupWithManager(mgr ctrl.Manager) error {
	if a.Findings == nil {
		return errors.New("the assessor needs a findings collector to assess a manifest")
	}
	every := handler.EnqueueRequestsFromMapFunc(a.everyManifest)
	return ctrl.NewControllerManagedBy(mgr).
		Named("hub-assessor").
		WithOptions(controller.Options{MaxConcurrentReconciles: assessWorkers}).
		// A manifest whose evidence is created or deleted, through the store, the only door to it.
		WatchesRawSource(a.Evidence.Source()).
		// A manifest whose findings the findings collector changed, or every manifest.
		WatchesRawSource(a.changes()).
		// Every manifest, when the playbook, a rule or a Collector changes. The controllers' own status
		// writes don't change the generation.
		Watches(&configv1alpha1.Playbook{}, every, builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		Watches(&configv1alpha1.Rule{}, every, builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		Watches(&configv1alpha1.Collector{}, every, builder.WithPredicates(collectorChanged())).
		Complete(reconcile.Func(a.assess))
}
