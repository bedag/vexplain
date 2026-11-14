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
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	inventoryv1alpha1 "github.com/bedag/vexplain/api/inventory/v1alpha1"
	"github.com/bedag/vexplain/internal/controller/hub"
	sdkevidence "github.com/bedag/vexplain/sdk/evidence"
	subjects "github.com/bedag/vexplain/sdk/subject"
)

// These tests cover the budget of decoded evidence: the evaluations of an assessor hold at most 8 MiB of decoded
// evidence at once, since one holds about 11 times its evidence, and two matches still run at once. They run the
// assessor's reconciles of manifests at once, and watch when each evaluation starts and stops holding its evidence.

// stillWaiting is how long a test watches for an evaluation that must not start.
const stillWaiting = 500 * time.Millisecond

// paddedEvidenceOf returns evidenceOf(manifest), whose data takes size bytes more once decoded: its SBOM holds a
// package whose name is a padding of one letter, which compresses to far less than a record holds, and which no
// match names.
func paddedEvidenceOf(manifest string, size int) scan {
	s := evidenceOf(manifest)
	s.sbom.Packages = append(s.sbom.Packages, sdkevidence.SBOMPackage{ID: "padding", Name: strings.Repeat("a", size), Type: deb})
	return s
}

// holding is one start or stop of an evaluation's hold on its evidence.
type holding struct {
	manifest string
	holds    bool
}

// holdings watches the evaluations of an assessor: it records each start and stop of their hold on their evidence,
// in order, and keeps each evaluation that starts from going on until the test lets it.
type holdings struct {
	t       *testing.T
	started chan string

	mu     sync.Mutex
	log    []holding
	inside map[string]bool
	most   int
	goOn   map[string]chan struct{}
}

// watchHoldings watches the evaluations of the assessor of f.
func watchHoldings(t *testing.T, f *assessorFixture) *holdings {
	t.Helper()
	h := &holdings{t: t, started: make(chan string, 16), inside: map[string]bool{}, goOn: map[string]chan struct{}{}}
	hub.WatchBudget(f.assessor, func(manifest string, holds bool) {
		h.mu.Lock()
		h.log = append(h.log, holding{manifest: manifest, holds: holds})
		if holds {
			h.inside[manifest] = true
			h.most = max(h.most, len(h.inside))
		} else {
			delete(h.inside, manifest)
		}
		goOn := h.gate(manifest)
		h.mu.Unlock()
		if holds {
			h.started <- manifest
			<-goOn
		}
	})
	return h
}

// gate returns the channel that lets the evaluation of manifest go on once it is closed. The caller holds the lock.
func (h *holdings) gate(manifest string) chan struct{} {
	if h.goOn[manifest] == nil {
		h.goOn[manifest] = make(chan struct{})
	}
	return h.goOn[manifest]
}

// next waits until an evaluation starts to hold its evidence, and returns its manifest.
func (h *holdings) next() string {
	h.t.Helper()
	select {
	case manifest := <-h.started:
		return manifest
	case <-time.After(reaction):
		require.FailNow(h.t, "an evaluation starts to hold its evidence")
		return ""
	}
}

// noneStarts checks that no evaluation starts to hold its evidence for a while.
func (h *holdings) noneStarts() {
	h.t.Helper()
	select {
	case manifest := <-h.started:
		require.FailNow(h.t, "an evaluation started while it had to wait", "manifest %s", manifest)
	case <-time.After(stillWaiting):
	}
}

// letGo lets the evaluation of manifest go on, and every later one of it.
func (h *holdings) letGo(manifest string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	close(h.gate(manifest))
}

// mostAtOnce returns the most evaluations that held their evidence at once.
func (h *holdings) mostAtOnce() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.most
}

// entries returns the starts and stops of the holds, in order.
func (h *holdings) entries() []holding {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]holding(nil), h.log...)
}

// assessing reconciles the manifest in the background with ctx, as the controller of sheets does, and returns the
// channel that gets its error.
func assessing(ctx context.Context, f *assessorFixture, manifest string) <-chan error {
	done := make(chan error, 1)
	go func() {
		_, err := hub.Assess(f.assessor, ctx, manifestRequest(manifest))
		done <- err
	}()
	return done
}

// requireDone waits until a reconcile that runs in the background returns, and returns its error.
func requireDone(t *testing.T, done <-chan error) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(reaction):
		require.FailNow(t, "the reconcile returns")
		return nil
	}
}

// scannedManifest stores the evidence s of a manifest of a new image, as a scan does, and returns the manifest.
func (f *assessorFixture) scannedManifest(t *testing.T, image int, s scan) string {
	t.Helper()
	f.scanned(t, digestOf(image), s.digest(), s)
	return s.digest()
}

func TestTheBudgetIsEightMebibytesOfDecodedEvidence(t *testing.T) {
	require.Equal(t, int64(8<<20), hub.EvidenceBudget)
}

func TestManifestsWhoseEvidenceExceedsTheBudgetTogetherNeverEvaluateAtOnce(t *testing.T) {
	f := newAssessor(t, interceptor.Funcs{}, nil)
	size := int(hub.EvidenceBudget) * 5 / 8
	first := f.scannedManifest(t, 1, paddedEvidenceOf(digestOf(101), size))
	second := f.scannedManifest(t, 2, paddedEvidenceOf(digestOf(102), size))
	h := watchHoldings(t, f)

	firstDone, secondDone := assessing(t.Context(), f, first), assessing(t.Context(), f, second)

	in := h.next()
	h.noneStarts()
	h.letGo(in)
	then := h.next()
	require.NotEqual(t, in, then)
	h.letGo(then)
	require.NoError(t, requireDone(t, firstDone))
	require.NoError(t, requireDone(t, secondDone))
	require.Equal(t, []holding{{in, true}, {in, false}, {then, true}, {then, false}}, h.entries())
	require.Equal(t, 1, h.mostAtOnce())
	require.NotNil(t, f.sheetOf(t, first))
	require.NotNil(t, f.sheetOf(t, second))
	require.Equal(t, 1, f.findings.found(first), "the matches ran outside the budget")
	require.Equal(t, 1, f.findings.found(second))
}

func TestManifestsWithinTheBudgetEvaluateAtOnce(t *testing.T) {
	f := newAssessor(t, interceptor.Funcs{}, nil)
	first := f.scannedManifest(t, 1, evidenceOf(digestOf(101)))
	second := f.scannedManifest(t, 2, evidenceOf(digestOf(102)))
	h := watchHoldings(t, f)

	firstDone, secondDone := assessing(t.Context(), f, first), assessing(t.Context(), f, second)

	one, other := h.next(), h.next()
	require.ElementsMatch(t, []string{first, second}, []string{one, other}, "both hold their evidence at once")
	h.letGo(one)
	h.letGo(other)
	require.NoError(t, requireDone(t, firstDone))
	require.NoError(t, requireDone(t, secondDone))
	require.Equal(t, 2, h.mostAtOnce())
}

// Evidence larger than the budget takes the whole budget: the evaluation waits until no other holds any, and no other
// starts while it holds.
func TestAManifestWhoseEvidenceExceedsTheBudgetEvaluatesAlone(t *testing.T) {
	for name, largeFirst := range map[string]bool{"the large one first": true, "the small one first": false} {
		t.Run(name, func(t *testing.T) {
			f := newAssessor(t, interceptor.Funcs{}, nil)
			large := f.scannedManifest(t, 1, paddedEvidenceOf(digestOf(101), int(hub.EvidenceBudget)+1<<20))
			small := f.scannedManifest(t, 2, evidenceOf(digestOf(102)))
			h := watchHoldings(t, f)
			before, after := small, large
			if largeFirst {
				before, after = large, small
			}

			beforeDone := assessing(t.Context(), f, before)
			require.Equal(t, before, h.next())
			afterDone := assessing(t.Context(), f, after)
			h.noneStarts()
			h.letGo(before)
			require.Equal(t, after, h.next())
			h.letGo(after)

			require.NoError(t, requireDone(t, beforeDone))
			require.NoError(t, requireDone(t, afterDone))
			require.Equal(t, 1, h.mostAtOnce())
			require.NotNil(t, f.sheetOf(t, large), "the large one was evaluated")
		})
	}
}

// A reconcile whose context ends while its evaluation waits for the budget returns at once, writes nothing, and
// leaves the budget as it was.
func TestACancelledContextEndsTheWaitForTheBudget(t *testing.T) {
	f := newAssessor(t, interceptor.Funcs{}, nil)
	large := f.scannedManifest(t, 1, paddedEvidenceOf(digestOf(101), int(hub.EvidenceBudget)+1<<20))
	small := f.scannedManifest(t, 2, evidenceOf(digestOf(102)))
	h := watchHoldings(t, f)
	largeDone := assessing(t.Context(), f, large)
	require.Equal(t, large, h.next())

	ctx, cancel := context.WithCancel(t.Context())
	smallDone := assessing(ctx, f, small)
	h.noneStarts()
	cancel()

	require.ErrorIs(t, requireDone(t, smallDone), context.Canceled)
	require.Nil(t, f.sheetOf(t, small), "nothing is written")
	require.Equal(t, []holding{{large, true}}, h.entries(), "the evaluation never started")
	h.letGo(large)
	require.NoError(t, requireDone(t, largeDone))

	h.letGo(small)
	require.NoError(t, requireDone(t, assessing(t.Context(), f, small)), "the budget is whole again")
	require.NotNil(t, f.sheetOf(t, small))
}

// An evaluation that fails while it holds its share of the budget gives the share back: here, evidence whose data can't
// be decoded any more, which only the evaluation of the sheet's findings decodes. Nothing is written.
func TestAnEvaluationThatFailsGivesItsShareOfTheBudgetBack(t *testing.T) {
	f := newAssessor(t, interceptor.Funcs{}, nil)
	broken := f.scannedManifest(t, 1, evidenceOf(digestOf(101)))
	large := f.scannedManifest(t, 2, paddedEvidenceOf(digestOf(102), int(hub.EvidenceBudget)+1<<20))
	f.assess(t, broken)
	before := f.sheetOf(t, broken)
	var list inventoryv1alpha1.EvidenceList
	require.NoError(t, f.client.List(t.Context(), &list))
	for i := range list.Items {
		if list.Items[i].Spec.Subject == subjects.Manifest(broken) {
			list.Items[i].Spec.Data = []byte("not gzip")
			require.NoError(t, f.client.Update(t.Context(), &list.Items[i])) // the fake client knows no schema
		}
	}
	tightenTheGuard(t, f.client)
	h := watchHoldings(t, f)
	h.letGo(broken)
	h.letGo(large)

	_, err := hub.Assess(f.assessor, t.Context(), manifestRequest(broken))

	require.Error(t, err)
	require.Equal(t, before, f.sheetOf(t, broken), "nothing is written")
	require.Equal(t, []holding{{broken, true}, {broken, false}}, h.entries())
	require.NoError(t, requireDone(t, assessing(t.Context(), f, large)), "the whole budget is free")
	require.NotNil(t, f.sheetOf(t, large))
}
