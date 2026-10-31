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
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	clocktesting "k8s.io/utils/clock/testing"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	inventoryv1alpha1 "github.com/bedag/vexplain/api/inventory/v1alpha1"
	"github.com/bedag/vexplain/internal/controller/hub"
	"github.com/bedag/vexplain/internal/inventory"
)

// These tests cover the Janitor: when it deletes the evidence and the sheet of a manifest that no
// digest refers to.

// grace is how long the evidence of a manifest must have been unreferenced before it is deleted.
const grace = 24 * time.Hour

// longAgo is when the evidence of a test was stored, unless the test is about that time: so long
// before t0 that only the grace that the janitor counts itself keeps the evidence.
var longAgo = t0.Add(-7 * grace)

// janitorFixture is a Janitor over stores on a fake client, with its clock.
type janitorFixture struct {
	janitor  *hub.Janitor
	client   client.Client
	store    inventory.Store
	packages inventory.PackagesStore
	verdicts inventory.VerdictsStore
	clock    *clocktesting.FakePassiveClock
}

// newJanitor returns the fixture of a janitor whose client acts with funcs.
func newJanitor(t *testing.T, funcs interceptor.Funcs) *janitorFixture {
	t.Helper()
	c := newClient(t, funcs)
	f := &janitorFixture{
		client:   c,
		store:    inventory.NewCRDStore(c, nil, cluster),
		packages: inventory.NewCRDPackagesStore(c, nil, cluster),
		verdicts: inventory.NewCRDVerdictsStore(c, cluster),
		clock:    clocktesting.NewFakePassiveClock(t0),
	}
	f.janitor = &hub.Janitor{Store: f.store, Packages: f.packages, Verdicts: f.verdicts,
		Interval: time.Hour, Grace: grace, Clock: f.clock}
	return f
}

// sweepAt runs one round of the janitor at the time now.
func (f *janitorFixture) sweepAt(t *testing.T, now time.Time) {
	t.Helper()
	f.clock.SetTime(now)
	hub.Sweep(f.janitor, t.Context())
}

// putEvidence stores the evidence of manifest, made by scanner in a scan that finished at the time
// scanned.
func (f *janitorFixture) putEvidence(t *testing.T, manifest, scanner string, scanned time.Time) {
	t.Helper()
	require.NoError(t, f.packages.Put(t.Context(), scanner, scanned, evidenceOf(manifest)))
}

// putEvidenceAndSheet stores the evidence of manifest, made by olderScanner in a scan that finished
// at the time scanned, and a sheet for it.
func (f *janitorFixture) putEvidenceAndSheet(t *testing.T, manifest string, scanned time.Time) {
	t.Helper()
	f.putEvidence(t, manifest, olderScanner, scanned)
	require.NoError(t, f.verdicts.Put(t.Context(), manifest,
		*sheet(v1, olderScanner, counted{needsAssessment: 2}, otherReached, exampleUnreached)))
}

// refer makes digest refer to the manifests: it runs in another cluster, and its facts name them.
func (f *janitorFixture) refer(t *testing.T, digest string, manifests ...string) {
	t.Helper()
	observe(t, f.store, digest, otherCluster, repository)
	setFacts(t, f.store, digest, scannedBy(olderScanner, manifests...))
}

// requireKept fails the test when the evidence or the sheet of manifest is gone.
func (f *janitorFixture) requireKept(t *testing.T, manifest string) {
	t.Helper()
	f.requireEvidence(t, manifest, true)
	sheet, err := f.verdicts.Get(t.Context(), manifest)
	require.NoError(t, err)
	require.NotNil(t, sheet, "the sheet is kept")
}

// requireRemoved fails the test unless the evidence and the sheet of manifest are gone.
func (f *janitorFixture) requireRemoved(t *testing.T, manifest string) {
	t.Helper()
	f.requireEvidence(t, manifest, false)
	sheet, err := f.verdicts.Get(t.Context(), manifest)
	require.NoError(t, err)
	require.Nil(t, sheet, "the sheet is deleted")
}

// requireEvidence fails the test unless the evidence of manifest exists as want says. It reads the
// object itself, so that evidence that the store can't read counts too.
func (f *janitorFixture) requireEvidence(t *testing.T, manifest string, want bool) {
	t.Helper()
	err := f.client.Get(t.Context(), client.ObjectKey{Name: inventory.NameForDigest(manifest)}, &inventoryv1alpha1.ImagePackages{})
	if want {
		require.NoError(t, err, "the evidence is kept")
	} else {
		require.True(t, apierrors.IsNotFound(err), "the evidence is deleted: %v", err)
	}
}

func TestJanitorDeletesEvidenceUnreferencedPastTheGraceTogetherWithItsSheet(t *testing.T) {
	f := newJanitor(t, interceptor.Funcs{})
	manifest := digestOf(101)
	f.putEvidenceAndSheet(t, manifest, longAgo)
	f.sweepAt(t, t0)

	f.sweepAt(t, t0.Add(grace))

	f.requireRemoved(t, manifest)
}

func TestJanitorKeepsEvidenceThatAnotherDigestStillRefersTo(t *testing.T) {
	f := newJanitor(t, interceptor.Funcs{})
	manifest := digestOf(101)
	f.putEvidenceAndSheet(t, manifest, longAgo)
	// Two digests share the manifest, such as two indexes of the same image. One of them goes.
	f.refer(t, digestOf(1), manifest)
	f.refer(t, digestOf(2), manifest, digestOf(102))
	forget(t, f.store, digestOf(1), otherCluster)

	for _, now := range []time.Time{t0, t0.Add(grace), t0.Add(2 * grace)} {
		f.sweepAt(t, now)
	}

	f.requireKept(t, manifest)
}

func TestJanitorKeepsEvidenceInsideTheGrace(t *testing.T) {
	f := newJanitor(t, interceptor.Funcs{})
	manifest := digestOf(101)
	f.putEvidenceAndSheet(t, manifest, longAgo)
	f.sweepAt(t, t0)

	f.sweepAt(t, t0.Add(grace-time.Second))

	f.requireKept(t, manifest)
}

func TestJanitorStartsTheGraceAgainWhenAReferenceComesAndGoes(t *testing.T) {
	f := newJanitor(t, interceptor.Funcs{})
	manifest := digestOf(101)
	f.putEvidenceAndSheet(t, manifest, longAgo)
	f.sweepAt(t, t0)
	f.refer(t, digestOf(1), manifest)
	f.sweepAt(t, t0.Add(grace/2))
	forget(t, f.store, digestOf(1), otherCluster)
	unreferencedAgain := t0.Add(grace * 3 / 4)
	f.sweepAt(t, unreferencedAgain)

	f.sweepAt(t, t0.Add(grace))
	f.requireKept(t, manifest)

	f.sweepAt(t, unreferencedAgain.Add(grace))
	f.requireRemoved(t, manifest)
}

// A scan by another scanner replaces the evidence of a manifest that no digest has referred to for
// almost the whole grace. The facts that refer to it come after the evidence: until they do, the new
// evidence must stay.
func TestJanitorKeepsEvidenceStoredAgainWithinTheGrace(t *testing.T) {
	f := newJanitor(t, interceptor.Funcs{})
	manifest := digestOf(101)
	f.putEvidenceAndSheet(t, manifest, longAgo)
	f.sweepAt(t, t0)
	replaced := t0.Add(grace - time.Minute)
	f.putEvidence(t, manifest, scannerImage, replaced)

	f.sweepAt(t, t0.Add(grace))
	f.requireKept(t, manifest)

	f.sweepAt(t, replaced.Add(grace))
	f.requireRemoved(t, manifest)
}

// A spoke can write the facts that refer to the manifest while the janitor is about to delete its
// evidence: the janitor looks for a reference once more, last.
func TestJanitorKeepsEvidenceThatADigestRefersToJustBeforeTheDelete(t *testing.T) {
	manifest := digestOf(101)
	var f *janitorFixture
	var referNow atomic.Bool
	f = newJanitor(t, interceptor.Funcs{Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey,
		obj client.Object, opts ...client.GetOption) error {
		if _, ok := obj.(*inventoryv1alpha1.ImagePackages); ok && referNow.CompareAndSwap(true, false) {
			f.refer(t, digestOf(1), manifest)
		}
		return c.Get(ctx, key, obj, opts...)
	}})
	f.putEvidenceAndSheet(t, manifest, longAgo)
	f.sweepAt(t, t0)

	referNow.Store(true)
	f.sweepAt(t, t0.Add(grace))

	require.False(t, referNow.Load(), "the janitor read the evidence")
	f.requireKept(t, manifest)
}

// A sheet never outlives its evidence: it goes first, and while it can't go, the evidence stays, so
// that the next round tries again.
func TestJanitorDeletesTheSheetBeforeTheEvidence(t *testing.T) {
	// The kinds of what the janitor deleted, in order.
	const sheetDeleted, evidenceDeleted = "sheet", "evidence"
	var deleted []string
	var sheetDeleteFails atomic.Bool
	f := newJanitor(t, interceptor.Funcs{Delete: func(ctx context.Context, c client.WithWatch, obj client.Object,
		opts ...client.DeleteOption) error {
		switch obj.(type) {
		case *inventoryv1alpha1.ImageVerdicts:
			deleted = append(deleted, sheetDeleted)
			if sheetDeleteFails.Load() {
				return errors.New("the API server is unavailable")
			}
		case *inventoryv1alpha1.ImagePackages:
			deleted = append(deleted, evidenceDeleted)
		}
		return c.Delete(ctx, obj, opts...)
	}})
	manifest := digestOf(101)
	f.putEvidenceAndSheet(t, manifest, longAgo)
	f.sweepAt(t, t0)

	sheetDeleteFails.Store(true)
	f.sweepAt(t, t0.Add(grace))
	require.Equal(t, []string{sheetDeleted}, deleted)
	f.requireKept(t, manifest)

	sheetDeleteFails.Store(false)
	f.sweepAt(t, t0.Add(grace+time.Hour))
	require.Equal(t, []string{sheetDeleted, sheetDeleted, evidenceDeleted}, deleted)
	f.requireRemoved(t, manifest)
}

func TestJanitorKeepsEvidenceWhoseReferencesItCantList(t *testing.T) {
	var failList atomic.Bool
	f := newJanitor(t, interceptor.Funcs{List: func(ctx context.Context, c client.WithWatch, list client.ObjectList,
		opts ...client.ListOption) error {
		if _, ok := list.(*inventoryv1alpha1.ImageInventoryList); ok && failList.Load() {
			return errors.New("the API server is unavailable")
		}
		return c.List(ctx, list, opts...)
	}})
	manifest := digestOf(101)
	f.putEvidenceAndSheet(t, manifest, longAgo)
	f.sweepAt(t, t0)

	failList.Store(true)
	f.sweepAt(t, t0.Add(grace))
	f.requireKept(t, manifest)

	failList.Store(false)
	f.sweepAt(t, t0.Add(grace+time.Hour))
	f.requireRemoved(t, manifest)
}

// Evidence in an encoding that this operator doesn't know may come from a newer one. The janitor
// can't tell when it was stored, and keeps it.
func TestJanitorKeepsEvidenceItCantRead(t *testing.T) {
	f := newJanitor(t, interceptor.Funcs{})
	manifest := digestOf(101)
	require.NoError(t, f.client.Create(t.Context(), &inventoryv1alpha1.ImagePackages{
		ObjectMeta: metav1.ObjectMeta{Name: inventory.NameForDigest(manifest)},
		Spec: inventoryv1alpha1.ImagePackagesSpec{
			ManifestDigest:    manifest,
			Platform:          linuxAMD64,
			ScannerImage:      scannerImage,
			ScannedTime:       ptr.To(metav1.NewTime(t0)),
			Encoding:          "ZstdJSON",
			Evidence:          []byte("not gzip"),
			UncompressedBytes: ptr.To(int64(64)),
		},
	}))

	f.sweepAt(t, t0)
	f.sweepAt(t, t0.Add(2*grace))

	f.requireEvidence(t, manifest, true)
}

// Evidence that goes, and comes back, as from a backup with its old scan time, is unreferenced only
// from the round that sees it again.
func TestJanitorGivesEvidenceThatComesBackAGraceOfItsOwn(t *testing.T) {
	f := newJanitor(t, interceptor.Funcs{})
	manifest := digestOf(101)
	f.putEvidenceAndSheet(t, manifest, longAgo)
	f.sweepAt(t, t0)
	require.NoError(t, f.packages.Delete(t.Context(), manifest))
	f.sweepAt(t, t0.Add(time.Hour))
	f.putEvidence(t, manifest, olderScanner, longAgo)
	back := t0.Add(2 * time.Hour)
	f.sweepAt(t, back)

	f.sweepAt(t, t0.Add(grace))
	f.requireKept(t, manifest)

	f.sweepAt(t, back.Add(grace))
	f.requireRemoved(t, manifest)
}

func TestJanitorRefusesANonPositiveIntervalOrGrace(t *testing.T) {
	for name, janitor := range map[string]*hub.Janitor{
		"no interval":      {Grace: grace},
		"a negative grace": {Interval: time.Hour, Grace: -grace},
		"no grace":         {Interval: time.Hour},
	} {
		t.Run(name, func(t *testing.T) {
			require.Error(t, janitor.Start(t.Context()))
		})
	}
}

func TestJanitorRunsUntilItsContextEnds(t *testing.T) {
	f := newJanitor(t, interceptor.Funcs{})
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- f.janitor.Start(ctx) }()

	cancel()

	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("the janitor did not stop when its context ended")
	}
}
