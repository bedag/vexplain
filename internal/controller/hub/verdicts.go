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

// Package hub holds the hub's decisions (decision 0021): which image digests a spoke must scan, and
// what the vulnerabilities in each platform manifest come to.
//
// The Scheduler asks a spoke, through tasks.Executor, to scan the digests whose facts are missing
// or stale. The VerdictsReconciler matches the packages in the evidence of each manifest against the
// hub's vulnerability database, turns the matches into findings with the rules, and writes the
// manifest's sheet. The DatabasePoller notices when the database changes, and has every manifest
// matched again. The Janitor deletes the evidence and the sheets that no digest refers to any more.
//
// The hub reaches a spoke only through tasks.Executor and the inventory stores. It imports no
// package of a spoke, so that a hub can run without one.
package hub

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
	inventoryv1alpha1 "github.com/bedag/vexplain/api/inventory/v1alpha1"
	"github.com/bedag/vexplain/internal/inventory"
	"github.com/bedag/vexplain/internal/matchapi"
	"github.com/bedag/vexplain/internal/rules"
	"github.com/bedag/vexplain/internal/scan/result"
	"github.com/bedag/vexplain/internal/settings"
)

// Matcher matches the packages of an SBOM against the hub's vulnerability database (decision 0022).
// *matchapi.Client implements it.
type Matcher interface {
	// Match returns the matches of the packages of the SBOM. An error means that there is no answer,
	// and never that there are no matches.
	Match(ctx context.Context, sbom json.RawMessage) (matchapi.MatchResponse, error)
	// Database returns the version of the database that the matcher uses.
	Database(ctx context.Context) (matchapi.Database, error)
}

var _ Matcher = (*matchapi.Client)(nil)

// The verdicts controller reads and watches the OperatorConfig, which holds the settings of the
// rules.
// +kubebuilder:rbac:groups=config.vexplain.bedag.ch,resources=operatorconfigs,verbs=get;list;watch

// VerdictsReconciler keeps the sheet of each platform manifest current. It reconciles a manifest
// when its evidence comes or goes, when the matcher's database changes, and when the OperatorConfig
// changes. It matches the SBOM of the evidence, turns the matches into findings with rules.Evaluate,
// and writes what rules.Sheet keeps of them, with the version of the database and the scanner image
// of the evidence.
//
// A match is costly, and a sheet is written only when its findings change (decision 0023). So the
// reconciler remembers in memory what the last match of each manifest depended on: the database's
// version, the evidence, and the completeness that the rules demand. It matches again only when one
// of them has changed, or while the poller hasn't read the database's version yet. After a restart
// it matches every manifest once, and writes only the sheets whose findings changed. A sheet whose
// findings, number of findings left out and counts stay the same is left as it is: it keeps the
// version of the database that last changed them.
//
// A failed match writes nothing, and goes back to the controller, which tries again later. A
// manifest whose evidence is gone loses its sheet: a sheet never outlives its evidence.
type VerdictsReconciler struct {
	// Client reads the OperatorConfig from the manager's cache, and watches it.
	Client client.Client
	// Packages keeps the evidence of the manifests, and Verdicts their sheets.
	Packages inventory.PackagesStore
	Verdicts inventory.VerdictsStore
	// Matcher matches the SBOM of each manifest's evidence.
	Matcher Matcher
	// Database follows the version of the matcher's database, and enqueues every manifest when it
	// changes.
	Database *DatabasePoller

	mu sync.Mutex
	// matched holds what the last match of each manifest with a sheet depended on.
	matched map[string]matchInputs
}

// matchInputs are what the findings of a manifest depend on: the version of the database, the
// evidence, and the completeness that the rules demand. The content of a manifest can't change, and
// its evidence is written once, so the scanner image and the scan time tell its evidence: a scan
// that stores the evidence again, after the janitor deleted it with its sheet, has a later time.
type matchInputs struct {
	databaseVersion        string
	scannerImage           string
	scannedTime            time.Time
	minCompletenessPercent int32
}

// Reconcile keeps the sheet of the manifest of the request current: it deletes the sheet of
// evidence that is gone, and matches the evidence unless its last match had the same inputs. A name
// that isn't the name of a digest is ignored.
func (r *VerdictsReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	manifest, ok := inventory.DigestForName(req.Name)
	if !ok {
		return ctrl.Result{}, nil
	}
	evidence, info, err := r.Packages.Get(ctx, manifest)
	if err != nil {
		return ctrl.Result{}, err
	}
	if evidence == nil {
		// The janitor deletes the sheet before the evidence, but a match that was under way then may
		// have put the sheet back. No list covers the sheets, so it would stay for good.
		if err := r.Verdicts.Delete(ctx, manifest); err != nil {
			return ctrl.Result{}, err
		}
		r.forget(manifest)
		return ctrl.Result{}, nil
	}
	effective, err := settings.Load(ctx, r.Client)
	if err != nil {
		return ctrl.Result{}, err
	}
	inputs := matchInputs{
		databaseVersion:        r.Database.Version(),
		scannerImage:           info.ScannerImage,
		scannedTime:            info.ScannedTime,
		minCompletenessPercent: effective.Rules.MinCompletenessPercent,
	}
	// Before the poller has read the version of the database, no match is known to be current.
	if inputs.databaseVersion != "" && r.lastMatch(manifest) == inputs {
		return ctrl.Result{}, nil
	}
	return ctrl.Result{}, r.match(ctx, manifest, evidence, inputs)
}

// match matches the evidence of manifest, and writes the findings that the rules make of the
// matches into its sheet, unless the sheet holds them already.
func (r *VerdictsReconciler) match(ctx context.Context, manifest string, evidence *result.Manifest, inputs matchInputs) error {
	answer, err := r.Matcher.Match(ctx, evidence.SBOM)
	if err != nil {
		return fmt.Errorf("match the packages of manifest %s: %w", manifest, err)
	}
	findings := rules.Evaluate(*evidence, answer.Matches, rules.Settings{MinCompletenessPercent: inputs.minCompletenessPercent})
	kept, omitted, counts := rules.Sheet(findings)
	sheet := inventoryv1alpha1.ImageVerdictsStatus{
		DatabaseVersion: ptr.To(answer.DatabaseVersion),
		ScannerImage:    ptr.To(inputs.scannerImage),
		Findings:        kept,
		OmittedFindings: ptr.To(omitted),
		Counts:          &counts,
	}
	stored, err := r.Verdicts.Get(ctx, manifest)
	if err != nil {
		return err
	}
	// A sheet that doesn't say which database found its findings reads as no verdict yet, so it gets
	// the version.
	changed := stored == nil || stored.Status.DatabaseVersion == nil || !sameFindings(stored.Status, sheet)
	if !changed {
		// The sheet says which database found these findings, and which scanner's evidence they come
		// from. They stay as they are, and so the store writes nothing.
		sheet.DatabaseVersion, sheet.ScannerImage = stored.Status.DatabaseVersion, stored.Status.ScannerImage
	}
	if err := r.Verdicts.Put(ctx, manifest, sheet); err != nil {
		return err
	}
	inputs.databaseVersion = answer.DatabaseVersion
	r.remember(manifest, inputs)

	log := logf.FromContext(ctx).WithValues("manifest", manifest, "databaseVersion", answer.DatabaseVersion)
	if changed {
		log.Info("Wrote the findings of a manifest", "suppressed", *counts.Suppressed, "tracked", *counts.Tracked,
			"needsAssessment", *counts.NeedsAssessment, "omitted", omitted)
	} else {
		log.V(1).Info("Matched a manifest again, and its findings stay the same")
	}
	return nil
}

// sameFindings reports whether two sheets hold the same findings, leave out as many, and count the
// same, as the store compares them.
func sameFindings(a, b inventoryv1alpha1.ImageVerdictsStatus) bool {
	return equality.Semantic.DeepEqual(a.Findings, b.Findings) &&
		equality.Semantic.DeepEqual(a.OmittedFindings, b.OmittedFindings) &&
		equality.Semantic.DeepEqual(a.Counts, b.Counts)
}

// lastMatch returns what the last match of manifest depended on, or nothing for a manifest that it
// doesn't remember.
func (r *VerdictsReconciler) lastMatch(manifest string) matchInputs {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.matched[manifest]
}

// remember keeps what the match of manifest depended on, whose findings its sheet now holds.
func (r *VerdictsReconciler) remember(manifest string, inputs matchInputs) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.matched == nil {
		r.matched = map[string]matchInputs{}
	}
	r.matched[manifest] = inputs
}

// forget drops what the last match of manifest depended on: its evidence and its sheet are gone.
func (r *VerdictsReconciler) forget(manifest string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.matched, manifest)
}

// matchWorkers is how many manifests the verdicts controller matches at once: as many as the matcher
// serves at once by default, whose --max-concurrent defaults to 2 (defaultMaxConcurrent in
// cmd/matcher). A change of one calls for a change of the other. The reconciler keeps its memory
// under a lock, and the controller never reconciles one manifest twice at once.
const matchWorkers = 2

// SetupWithManager sets up the controller with the Manager.
func (r *VerdictsReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		Named("hub-verdicts").
		// After a change of the database every manifest is matched again, and with one worker the
		// matcher's second slot would sit idle.
		WithOptions(controller.Options{MaxConcurrentReconciles: matchWorkers}).
		// A manifest whose evidence is created or deleted, through the store, the only door to it.
		WatchesRawSource(r.Packages.Source()).
		// Every manifest, when the version of the matcher's database changes.
		WatchesRawSource(r.Database.Source()).
		// Every manifest, when the OperatorConfig changes. The settings of the rules are in its spec,
		// and the OperatorConfig controller's status writes don't change the generation.
		Watches(&configv1alpha1.OperatorConfig{}, handler.EnqueueRequestsFromMapFunc(r.everyManifest),
			builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		Complete(r)
}

// everyManifest maps a change of the OperatorConfig to every manifest that has evidence.
//
// It lists the manifests in the cache that the watch of the evidence keeps, and not from the API
// server. Nothing maps a change twice, so a list that failed would lose it for good, and a raised
// minimum would leave the suppressions of the laxer one standing. The cache answers once it has
// synced, without the API server, and fails only when ctx ends first: when the manager stops.
func (r *VerdictsReconciler) everyManifest(ctx context.Context, _ client.Object) []reconcile.Request {
	manifests, err := r.Packages.CachedDigests(ctx)
	if err != nil {
		logf.FromContext(ctx).Error(err, "Could not list the evidence to apply a change of the OperatorConfig")
		return nil
	}
	requests := make([]reconcile.Request, 0, len(manifests))
	for _, manifest := range manifests {
		requests = append(requests, requestFor(manifest))
	}
	return requests
}

// requestFor returns the request under which the hub reconciles a digest: the name of its objects.
func requestFor(digest string) reconcile.Request {
	return reconcile.Request{NamespacedName: types.NamespacedName{Name: inventory.NameForDigest(digest)}}
}
