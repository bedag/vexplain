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

package hub_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
	inventoryv1alpha1 "github.com/bedag/vexplain/api/inventory/v1alpha1"
	"github.com/bedag/vexplain/internal/controller/hub"
	"github.com/bedag/vexplain/internal/inventory"
	"github.com/bedag/vexplain/internal/matchapi"
	"github.com/bedag/vexplain/internal/scan/result"
)

// These tests cover the VerdictsReconciler: when it matches the evidence of a manifest, and what it
// writes into the manifest's sheet.

// verdictsFixture is a VerdictsReconciler over stores on a fake client, with a fake matcher, and the
// poller that reads the matcher's database for it.
type verdictsFixture struct {
	reconciler *hub.VerdictsReconciler
	client     client.Client
	packages   inventory.PackagesStore
	verdicts   inventory.VerdictsStore
	matcher    *fakeMatcher
	poller     *hub.DatabasePoller
}

// newVerdicts returns the fixture of a reconciler whose matcher's database is v1, and gives
// exampleMatch and otherMatch. The poller hasn't read the database yet. funcs act on the client.
func newVerdicts(t *testing.T, funcs interceptor.Funcs) *verdictsFixture {
	t.Helper()
	c := newClient(t, funcs)
	matcher := newFakeMatcher(exampleMatch, otherMatch)
	packages := inventory.NewCRDPackagesStore(c, nil, cluster)
	verdicts := inventory.NewCRDVerdictsStore(c, cluster)
	poller := &hub.DatabasePoller{Matcher: matcher, Packages: packages, Interval: time.Hour}
	return &verdictsFixture{
		reconciler: &hub.VerdictsReconciler{
			Client: c, Packages: packages, Verdicts: verdicts, Matcher: matcher, Database: poller,
		},
		client:   c,
		packages: packages,
		verdicts: verdicts,
		matcher:  matcher,
		poller:   poller,
	}
}

// readDatabase has the poller read the version of the matcher's database, as it does every interval.
func (f *verdictsFixture) readDatabase(t *testing.T) {
	t.Helper()
	hub.Poll(f.poller, t.Context())
}

// putEvidence stores the evidence m, made by scanner in a scan that finished at the time scanned.
func (f *verdictsFixture) putEvidence(t *testing.T, scanner string, scanned time.Time, m result.Manifest) {
	t.Helper()
	require.NoError(t, f.packages.Put(t.Context(), scanner, scanned, m))
}

// reconcile reconciles the manifest, which must succeed.
func (f *verdictsFixture) reconcile(t *testing.T, manifest string) {
	t.Helper()
	res, err := f.reconciler.Reconcile(t.Context(), requestFor(manifest))
	require.NoError(t, err)
	require.Equal(t, ctrl.Result{}, res)
}

// sheetOf reads the sheet of manifest, or nil when it has none.
func (f *verdictsFixture) sheetOf(t *testing.T, manifest string) *inventoryv1alpha1.ImageVerdicts {
	t.Helper()
	obj, err := f.verdicts.Get(t.Context(), manifest)
	require.NoError(t, err)
	return obj
}

// statusOf reads the status of the sheet of manifest, which must exist.
func (f *verdictsFixture) statusOf(t *testing.T, manifest string) *inventoryv1alpha1.ImageVerdictsStatus {
	t.Helper()
	obj := f.sheetOf(t, manifest)
	require.NotNil(t, obj, "the manifest has a sheet")
	return &obj.Status
}

func TestVerdictsWriteTheSheetThatTheRulesMakeOfNewEvidence(t *testing.T) {
	f := newVerdicts(t, interceptor.Funcs{})
	manifest := digestOf(101)
	f.readDatabase(t)
	f.putEvidence(t, scannerImage, t0, evidenceOf(manifest))

	f.reconcile(t, manifest)

	require.Equal(t, []json.RawMessage{sbomOf(manifest)}, f.matcher.matched(), "the SBOM of the evidence is matched")
	require.Equal(t, sheet(v1, scannerImage, counted{suppressed: 1, needsAssessment: 1}, otherReached, exampleNotLoadable),
		f.statusOf(t, manifest))
}

func TestVerdictsMatchNoMoreWhileTheSheetIsCurrent(t *testing.T) {
	f := newVerdicts(t, interceptor.Funcs{})
	manifest := digestOf(101)
	f.readDatabase(t)
	f.putEvidence(t, scannerImage, t0, evidenceOf(manifest))
	f.reconcile(t, manifest)

	f.reconcile(t, manifest)
	f.readDatabase(t) // The same version again.
	f.reconcile(t, manifest)

	require.Len(t, f.matcher.matched(), 1)
}

func TestVerdictsMatchEveryTimeUntilTheDatabaseVersionIsKnown(t *testing.T) {
	f := newVerdicts(t, interceptor.Funcs{})
	manifest := digestOf(101)
	f.putEvidence(t, scannerImage, t0, evidenceOf(manifest))

	f.reconcile(t, manifest)
	f.reconcile(t, manifest)
	require.Len(t, f.matcher.matched(), 2)

	// Once the poller has read the version, the match of that version is current.
	f.readDatabase(t)
	f.reconcile(t, manifest)
	require.Len(t, f.matcher.matched(), 2)
	require.Equal(t, sheet(v1, scannerImage, counted{suppressed: 1, needsAssessment: 1}, otherReached, exampleNotLoadable),
		f.statusOf(t, manifest))
}

// Until the poller has read the database's version, the controller matches against whatever database
// the matcher has. A manifest matched then against another version than the one the poller reads
// first is matched again; one matched against that version isn't.
func TestVerdictsMatchAgainAtTheFirstReadWhatAnotherVersionMatched(t *testing.T) {
	f := newVerdicts(t, interceptor.Funcs{})
	queue := workqueue.NewTypedRateLimitingQueue(workqueue.DefaultTypedControllerRateLimiter[reconcile.Request]())
	t.Cleanup(queue.ShutDown)
	require.NoError(t, f.poller.Source().Start(t.Context(), queue))
	stale, current := digestOf(101), digestOf(102)
	f.putEvidence(t, scannerImage, t0, evidenceOf(stale))
	f.putEvidence(t, scannerImage, t0, evidenceOf(current))
	f.reconcile(t, stale)
	f.matcher.set(v2, exploited(exampleMatch), otherMatch)
	f.reconcile(t, current)

	f.readDatabase(t)
	for _, req := range drain(queue) {
		res, err := f.reconciler.Reconcile(t.Context(), req)
		require.NoError(t, err)
		require.Equal(t, ctrl.Result{}, res)
	}

	require.Equal(t, []json.RawMessage{sbomOf(stale), sbomOf(current), sbomOf(stale)}, f.matcher.matched())
	for _, manifest := range []string{stale, current} {
		require.Equal(t, sheet(v2, scannerImage, counted{tracked: 1, needsAssessment: 1}, otherReached, exampleExploited),
			f.statusOf(t, manifest))
	}
}

// A failed match is no answer, and never an empty list of matches.
func TestVerdictsWriteNothingWhenTheMatcherFails(t *testing.T) {
	for _, failure := range []error{matchapi.ErrNotReady, matchapi.ErrUnavailable, errors.New("matcher: malformed response")} {
		t.Run(failure.Error(), func(t *testing.T) {
			f := newVerdicts(t, interceptor.Funcs{})
			matched, unmatched := digestOf(101), digestOf(102)
			f.readDatabase(t)
			f.putEvidence(t, scannerImage, t0, evidenceOf(matched))
			f.reconcile(t, matched)
			before := f.sheetOf(t, matched)
			// A new database, whose findings differ, can't be reached.
			f.matcher.set(v2, exploited(exampleMatch), otherMatch)
			f.readDatabase(t)
			f.matcher.failMatches(failure)
			f.putEvidence(t, scannerImage, t0, evidenceOf(unmatched))

			// The error goes back to the controller, which tries again later.
			_, err := f.reconciler.Reconcile(t.Context(), requestFor(matched))
			require.ErrorIs(t, err, failure)
			require.Equal(t, before, f.sheetOf(t, matched), "the sheet stays as it was")
			_, err = f.reconciler.Reconcile(t.Context(), requestFor(unmatched))
			require.ErrorIs(t, err, failure)
			require.Nil(t, f.sheetOf(t, unmatched), "a manifest without a sheet gets none")

			// The next try that gets an answer writes it.
			f.matcher.failMatches(nil)
			f.reconcile(t, matched)
			require.Equal(t, sheet(v2, scannerImage, counted{tracked: 1, needsAssessment: 1}, otherReached, exampleExploited),
				f.statusOf(t, matched))
		})
	}
}

func TestVerdictsMatchAgainForANewDatabaseAndWriteOnlyFindingsThatChanged(t *testing.T) {
	f := newVerdicts(t, interceptor.Funcs{})
	manifest := digestOf(101)
	f.readDatabase(t)
	f.putEvidence(t, scannerImage, t0, evidenceOf(manifest))
	f.reconcile(t, manifest)
	first := f.sheetOf(t, manifest)

	// A new database that finds the same: the sheet keeps the version that last changed its findings,
	// and isn't written at all.
	f.matcher.set(v2, exampleMatch, otherMatch)
	f.readDatabase(t)
	f.reconcile(t, manifest)
	require.Len(t, f.matcher.matched(), 2)
	require.Equal(t, first, f.sheetOf(t, manifest))

	// A new database whose findings differ: the sheet holds them, and the version that found them.
	f.matcher.set(v3, exploited(exampleMatch), otherMatch)
	f.readDatabase(t)
	f.reconcile(t, manifest)
	require.Len(t, f.matcher.matched(), 3)
	require.Equal(t, sheet(v3, scannerImage, counted{tracked: 1, needsAssessment: 1}, otherReached, exampleExploited),
		f.statusOf(t, manifest))
}

func TestVerdictsApplyTheMinimumCompletenessOfTheOperatorConfig(t *testing.T) {
	f := newVerdicts(t, interceptor.Funcs{})
	manifest := digestOf(101)
	f.readDatabase(t)
	f.putEvidence(t, scannerImage, t0, incompleteEvidenceOf(manifest))

	// Without an OperatorConfig the minimum is 90%, above the evidence's 75%: no rule may settle a
	// finding.
	f.reconcile(t, manifest)
	require.Equal(t, sheet(v1, scannerImage, counted{needsAssessment: 2}, otherGuarded, exampleGuarded), f.statusOf(t, manifest))

	// An admin lowers the minimum to the evidence's completeness. Nothing else changed, and the
	// manifest is matched again.
	require.NoError(t, f.client.Create(t.Context(), &configv1alpha1.OperatorConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "default"},
		Spec:       configv1alpha1.OperatorConfigSpec{Rules: &configv1alpha1.Rules{MinCompletenessPercent: ptr.To(int32(75))}},
	}))
	f.reconcile(t, manifest)
	require.Len(t, f.matcher.matched(), 2)
	require.Equal(t, sheet(v1, scannerImage, counted{suppressed: 1, needsAssessment: 1}, otherReached, exampleNotLoadable),
		f.statusOf(t, manifest))
}

// Without the minimum, the guard could let a rule settle a finding in evidence that packages don't
// account for: a false "not affected" is the worst error there is.
func TestVerdictsWriteNothingWhenTheOperatorConfigCantBeRead(t *testing.T) {
	f := newVerdicts(t, interceptor.Funcs{Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey,
		obj client.Object, opts ...client.GetOption) error {
		if _, ok := obj.(*configv1alpha1.OperatorConfig); ok {
			return errors.New("the API server is unavailable")
		}
		return c.Get(ctx, key, obj, opts...)
	}})
	manifest := digestOf(101)
	f.readDatabase(t)
	f.putEvidence(t, scannerImage, t0, incompleteEvidenceOf(manifest))

	_, err := f.reconciler.Reconcile(t.Context(), requestFor(manifest))

	require.ErrorContains(t, err, "the API server is unavailable")
	require.Nil(t, f.sheetOf(t, manifest))
}

func TestVerdictsDeleteTheSheetOfEvidenceThatIsGone(t *testing.T) {
	f := newVerdicts(t, interceptor.Funcs{})
	manifest := digestOf(101)
	f.readDatabase(t)
	f.putEvidence(t, scannerImage, t0, evidenceOf(manifest))
	f.reconcile(t, manifest)

	require.NoError(t, f.packages.Delete(t.Context(), manifest))
	f.reconcile(t, manifest)

	require.Nil(t, f.sheetOf(t, manifest))
	require.Len(t, f.matcher.matched(), 1, "there is nothing to match")

	// The manifest is forgotten: the same evidence, stored again, gets its sheet again.
	f.putEvidence(t, scannerImage, t0, evidenceOf(manifest))
	f.reconcile(t, manifest)
	require.Equal(t, sheet(v1, scannerImage, counted{suppressed: 1, needsAssessment: 1}, otherReached, exampleNotLoadable),
		f.statusOf(t, manifest))
}

// The janitor deletes a sheet and then its evidence. A scan can store the evidence again before the
// controller sees it gone: the controller then sees only evidence of a later scan.
func TestVerdictsMatchEvidenceThatALaterScanStoredAgain(t *testing.T) {
	f := newVerdicts(t, interceptor.Funcs{})
	manifest := digestOf(101)
	f.readDatabase(t)
	f.putEvidence(t, scannerImage, t0, evidenceOf(manifest))
	f.reconcile(t, manifest)

	require.NoError(t, f.verdicts.Delete(t.Context(), manifest))
	require.NoError(t, f.packages.Delete(t.Context(), manifest))
	f.putEvidence(t, scannerImage, t0.Add(25*time.Hour), evidenceOf(manifest))
	f.reconcile(t, manifest)

	require.Equal(t, sheet(v1, scannerImage, counted{suppressed: 1, needsAssessment: 1}, otherReached, exampleNotLoadable),
		f.statusOf(t, manifest))
}

func TestVerdictsMatchEvidenceThatAnotherScannerMade(t *testing.T) {
	t.Run("and keep the sheet when the findings are the same", func(t *testing.T) {
		f := newVerdicts(t, interceptor.Funcs{})
		manifest := digestOf(101)
		f.readDatabase(t)
		f.putEvidence(t, olderScanner, t0, evidenceOf(manifest))
		f.reconcile(t, manifest)
		first := f.sheetOf(t, manifest)

		f.putEvidence(t, scannerImage, t0.Add(time.Hour), evidenceOf(manifest))
		f.reconcile(t, manifest)

		require.Len(t, f.matcher.matched(), 2)
		// The sheet keeps the scanner image and the database version of the findings, and isn't written.
		require.Equal(t, first, f.sheetOf(t, manifest))
	})
	t.Run("and write the findings that differ", func(t *testing.T) {
		f := newVerdicts(t, interceptor.Funcs{})
		manifest := digestOf(101)
		f.readDatabase(t)
		f.putEvidence(t, olderScanner, t0, incompleteEvidenceOf(manifest))
		f.reconcile(t, manifest)

		f.putEvidence(t, scannerImage, t0.Add(time.Hour), evidenceOf(manifest))
		f.reconcile(t, manifest)

		require.Equal(t, sheet(v1, scannerImage, counted{suppressed: 1, needsAssessment: 1}, otherReached, exampleNotLoadable),
			f.statusOf(t, manifest))
	})
}

func TestVerdictsIgnoreANameThatNamesNoDigest(t *testing.T) {
	f := newVerdicts(t, interceptor.Funcs{})

	for _, name := range []string{"", "not-a-digest"} {
		res, err := f.reconciler.Reconcile(t.Context(), ctrl.Request{NamespacedName: types.NamespacedName{Name: name}})

		require.NoError(t, err)
		require.Equal(t, ctrl.Result{}, res)
	}
	require.Empty(t, f.matcher.matched())
}
