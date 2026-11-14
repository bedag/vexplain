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

package inventory_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	inventoryv1alpha1 "github.com/bedag/vexplain/api/inventory/v1alpha1"
	"github.com/bedag/vexplain/internal/inventory"
)

// These tests cover the VerdictsStore: the result sheets, one object per platform manifest and playbook,
// written only when they change.

// newVerdictsStore returns a VerdictsStore over a fake client, and the client. Its writes are
// labelled with clusterA.
func newVerdictsStore(t *testing.T, funcs interceptor.Funcs) (inventory.VerdictsStore, client.Client) {
	t.Helper()
	c := newClient(t, funcs)
	return inventory.NewCRDVerdictsStore(c, fixedCluster(clusterA)), c
}

// packageID is the ID in the SBOM of the package that the sheets of the tests are about.
const packageID = "pkg-1"

// libexample is the package of the findings of the sheets.
var libexample = inventoryv1alpha1.PackageReference{ID: packageID, Name: "libexample1", Version: ptr.To("1.2.3-1"), Type: "deb"}

// The playbooks of the sheets: the default one, and a stricter one that judges the same images.
const (
	defaultPlaybook = "container-cves"
	strictPlaybook  = "container-cves-strict"
)

// sheet returns the sheet of a match of the default playbook against the findings version: a finding that a
// rule settled, and one that no rule settled.
func sheet(findingsVersion string) inventoryv1alpha1.ImageVerdictsStatus {
	return inventoryv1alpha1.ImageVerdictsStatus{
		Playbook:        ptr.To(defaultPlaybook),
		FindingsVersion: ptr.To(findingsVersion),
		Evidence: []inventoryv1alpha1.SheetEvidence{{
			Name: "contents", Source: "scanner", Type: "ch.bedag.vexplain.scanner.image-contents.v1alpha1",
			// The API keeps a time in the local zone of whoever reads it, as metav1.Time decodes it.
			Version: ptr.To(scannerV1), Time: ptr.To(metav1.NewTime(time.Date(2026, 10, 30, 8, 0, 0, 0, time.UTC).Local())),
			Coverage: ptr.To(int32(100)),
		}},
		Findings: []inventoryv1alpha1.Finding{
			{
				VulnerabilityID: "CVE-2026-0001",
				Package:         libexample,
				Status:          inventoryv1alpha1.VEXStatusNotAffected,
				Rule:            ptr.To("removed-in-later-layer"),
				Justification:   ptr.To(inventoryv1alpha1.VEXJustificationComponentNotPresent),
				Conditions:      []inventoryv1alpha1.FindingCondition{inventoryv1alpha1.FindingConditionNoPreloadEnvironment},
				Severity:        inventoryv1alpha1.SeverityHigh,
				FixState:        inventoryv1alpha1.FixStateFixed,
				FixedVersions:   []string{"1.2.4-1"},
				KnownExploited:  inventoryv1alpha1.KnownExploitedNotListed,
			},
			{
				VulnerabilityID: "CVE-2026-0002",
				Package:         libexample,
				Status:          inventoryv1alpha1.VEXStatusUnderInvestigation,
				StatusNotes:     []inventoryv1alpha1.StatusNote{{Rule: "load-check", Text: "reached by /usr/bin/curl"}},
				Severity:        inventoryv1alpha1.SeverityMedium,
				FixState:        inventoryv1alpha1.FixStateNotFixed,
				KnownExploited:  inventoryv1alpha1.KnownExploitedNotListed,
			},
		},
		Counts: &inventoryv1alpha1.FindingCounts{
			Affected: ptr.To(int32(0)), UnderInvestigation: ptr.To(int32(1)), NotAffected: ptr.To(int32(1)), Fixed: ptr.To(int32(0)),
		},
	}
}

// The tests write the sheet of one platform manifest, manifestAMD64, under the default playbook, unless they
// say otherwise.

// storedSheet reads the sheet behind the store, straight from the client.
func storedSheet(t *testing.T, c client.Client) *inventoryv1alpha1.ImageVerdicts {
	t.Helper()
	obj := &inventoryv1alpha1.ImageVerdicts{}
	require.NoError(t, c.Get(t.Context(), client.ObjectKey{Name: inventory.SheetName(manifestAMD64, defaultPlaybook)}, obj))
	return obj
}

// requireNoSheet fails the test when the store holds the sheet of the playbook.
func requireNoSheet(t *testing.T, store inventory.VerdictsStore, playbook string) {
	t.Helper()
	got, err := store.Get(t.Context(), manifestAMD64, playbook)
	require.NoError(t, err)
	require.Nil(t, got)
}

// A sheet's name is its manifest's and its playbook's, and the name gives the manifest back.
func TestTheNameOfASheet(t *testing.T) {
	name := inventory.SheetName(manifestAMD64, defaultPlaybook)

	require.Equal(t, "sha256-1111111111111111111111111111111111111111111111111111111111111111.container-cves", name)
	manifest, ok := inventory.ManifestOfSheet(name)
	require.True(t, ok)
	require.Equal(t, manifestAMD64, manifest)
	for _, other := range []string{inventory.NameForDigest(manifestAMD64), inventory.NameForDigest(manifestAMD64) + ".",
		"not-a-digest." + defaultPlaybook} {
		_, ok := inventory.ManifestOfSheet(other)
		require.False(t, ok, "%q is no sheet's name", other)
	}
}

func TestVerdictsPutCreatesTheSheet(t *testing.T) {
	store, c := newVerdictsStore(t, interceptor.Funcs{})

	counts := verdictsCollectors.counted(t, clusterA, func() {
		require.NoError(t, store.Put(t.Context(), manifestAMD64, defaultPlaybook, sheet("v1")))
	})

	require.Equal(t, writeCounts{Create: 1, Update: 1, Sizes: 2}, counts, "the sheet is created, then its status written")
	got, err := store.Get(t.Context(), manifestAMD64, defaultPlaybook)
	require.NoError(t, err)
	require.NotNil(t, got)
	require.Equal(t, inventory.SheetName(manifestAMD64, defaultPlaybook), got.Name)
	require.Equal(t, inventoryv1alpha1.ImageVerdictsSpec{ManifestDigest: manifestAMD64, Playbook: defaultPlaybook}, got.Spec)
	// The labels name the playbook and the manifest, whose digest a label name holds all but the last hex digit of.
	require.Equal(t, map[string]string{
		"vexplain.bedag.ch/playbook": defaultPlaybook,
		"manifest.vexplain.bedag.ch/111111111111111111111111111111111111111111111111111111111111111": "",
	}, got.Labels)
	require.Equal(t, sheet("v1"), got.Status)
	require.Equal(t, storedSheet(t, c), got)
}

func TestVerdictsGetOfAnAbsentSheet(t *testing.T) {
	store, _ := newVerdictsStore(t, interceptor.Funcs{})
	require.NoError(t, store.Put(t.Context(), manifestAMD64, strictPlaybook, sheet("v1")))

	requireNoSheet(t, store, defaultPlaybook)
}

// sharesTheLabel is a manifest whose digest has the first 63 hex digits of manifestAMD64's, and so the label of its
// manifest.
const sharesTheLabel = "sha256:1111111111111111111111111111111111111111111111111111111111111112"

// Each playbook keeps a sheet of a manifest, and List returns those of the manifest, and of no other.
func TestVerdictsListReturnsTheSheetsOfAManifestByPlaybook(t *testing.T) {
	store, _ := newVerdictsStore(t, interceptor.Funcs{})
	require.NoError(t, store.Put(t.Context(), manifestAMD64, strictPlaybook, sheet("v2")))
	require.NoError(t, store.Put(t.Context(), manifestAMD64, defaultPlaybook, sheet("v1")))
	require.NoError(t, store.Put(t.Context(), manifestARM64, defaultPlaybook, sheet("v1")))
	require.NoError(t, store.Put(t.Context(), sharesTheLabel, defaultPlaybook, sheet("v1")))

	got, err := store.List(t.Context(), manifestAMD64)

	require.NoError(t, err)
	require.Len(t, got, 2)
	for i, playbook := range []string{defaultPlaybook, strictPlaybook} {
		require.Equal(t, inventoryv1alpha1.ImageVerdictsSpec{ManifestDigest: manifestAMD64, Playbook: playbook}, got[i].Spec,
			"the sheets in the order of their playbooks")
	}
	require.Equal(t, sheet("v1"), got[0].Status)
	require.Equal(t, sheet("v2"), got[1].Status)
	none, err := store.List(t.Context(), "sha256:3333333333333333333333333333333333333333333333333333333333333333")
	require.NoError(t, err)
	require.Empty(t, none)
}

// A sheet is written only when it changes, so a match that finds what the sheet holds writes
// nothing.
func TestVerdictsPutWritesOnlyAChange(t *testing.T) {
	store, c := newVerdictsStore(t, interceptor.Funcs{})
	require.NoError(t, store.Put(t.Context(), manifestAMD64, defaultPlaybook, sheet("v1")))
	version := storedSheet(t, c).ResourceVersion

	// The same sheet, with an empty list where the stored one has none: the same sheet all the same.
	same := sheet("v1")
	same.Findings[1].Conditions = []inventoryv1alpha1.FindingCondition{}
	counts := verdictsCollectors.counted(t, clusterA, func() {
		require.NoError(t, store.Put(t.Context(), manifestAMD64, defaultPlaybook, same))
	})
	require.Equal(t, writeCounts{}, counts)
	require.Equal(t, version, storedSheet(t, c).ResourceVersion, "nothing was written")

	// The known exploits now list the second vulnerability, which a rule holds open.
	changed := sheet("v2")
	changed.Findings[1].Rule = ptr.To("known-exploited")
	changed.Findings[1].Reason = ptr.To("known exploited")
	changed.Findings[1].KnownExploited = inventoryv1alpha1.KnownExploitedListed
	_, sum := verdictsCollectors.sizes(t, clusterA)
	counts = verdictsCollectors.counted(t, clusterA, func() {
		require.NoError(t, store.Put(t.Context(), manifestAMD64, defaultPlaybook, changed))
		require.NoError(t, store.Put(t.Context(), manifestAMD64, defaultPlaybook, changed))
	})
	require.Equal(t, writeCounts{Update: 1, Sizes: 1}, counts, "a change writes once")
	written := storedSheet(t, c)
	require.Equal(t, changed, written.Status)

	// The sample is the size of the whole sheet as json.Marshal writes it, status included.
	_, newSum := verdictsCollectors.sizes(t, clusterA)
	require.InDelta(t, float64(len(asJSON(t, written))), newSum-sum, 0, "the sample is the stored sheet")
}

// The store compares the whole status. A status that differs from the stored one in its findings
// version alone is another status, and is written: a caller that wants a sheet to keep the version
// that last changed its findings, as the assessor does, passes the stored version.
func TestVerdictsPutWritesAChangeOfTheFindingsVersionAlone(t *testing.T) {
	store, c := newVerdictsStore(t, interceptor.Funcs{})
	require.NoError(t, store.Put(t.Context(), manifestAMD64, defaultPlaybook, sheet("v1")))
	version := storedSheet(t, c).ResourceVersion

	counts := verdictsCollectors.counted(t, clusterA, func() {
		require.NoError(t, store.Put(t.Context(), manifestAMD64, defaultPlaybook, sheet("v2")))
	})

	require.Equal(t, writeCounts{Update: 1, Sizes: 1}, counts)
	written := storedSheet(t, c)
	require.NotEqual(t, version, written.ResourceVersion, "the status was written")
	require.Equal(t, sheet("v2"), written.Status)
}

// The store reads through a client that may read from a cache, and a cache can lag behind the
// writes. A write based on an old read meets a conflict, and the next round reads again.
func TestVerdictsPutRetriesAfterAConflict(t *testing.T) {
	armed := false
	store, c := newVerdictsStore(t, interceptor.Funcs{
		SubResourceUpdate: func(ctx context.Context, other client.Client, subResource string, obj client.Object,
			opts ...client.SubResourceUpdateOption) error {
			if armed {
				armed = false
				// Another write changes the sheet between this write's read and the write.
				written := storedSheet(t, other)
				written.Status = sheet("v2")
				require.NoError(t, other.Status().Update(ctx, written))
			}
			return other.SubResource(subResource).Update(ctx, obj, opts...)
		},
	})
	require.NoError(t, store.Put(t.Context(), manifestAMD64, defaultPlaybook, sheet("v1")))

	armed = true
	counts := verdictsCollectors.counted(t, clusterA, func() {
		require.NoError(t, store.Put(t.Context(), manifestAMD64, defaultPlaybook, sheet("v3")))
	})

	require.False(t, armed, "the conflict happened")
	require.Equal(t, sheet("v3"), storedSheet(t, c).Status)
	require.Equal(t, writeCounts{Update: 1, Sizes: 1}, counts, "a write that was refused is not counted")
}

// The sheet was deleted between this write's read and its status write. Put creates the sheet if
// needed, so the next round creates it again.
func TestVerdictsPutCreatesAgainASheetDeletedUnderItsWrite(t *testing.T) {
	armed := false
	store, c := newVerdictsStore(t, deleteUnderStatusWrite(t, &armed))
	require.NoError(t, store.Put(t.Context(), manifestAMD64, defaultPlaybook, sheet("v1")))

	armed = true
	counts := verdictsCollectors.counted(t, clusterA, func() {
		require.NoError(t, store.Put(t.Context(), manifestAMD64, defaultPlaybook, sheet("v2")))
	})

	require.False(t, armed, "the sheet was deleted under the write")
	require.Equal(t, sheet("v2"), storedSheet(t, c).Status)
	require.Equal(t, writeCounts{Create: 1, Update: 1, Sizes: 2}, counts, "created again, then written")
}

// The sheet was created between this write's read, which found none, and its create.
func TestVerdictsPutRetriesWhenTheSheetWasCreatedMeanwhile(t *testing.T) {
	armed := true
	store, c := newVerdictsStore(t, interceptor.Funcs{
		Create: func(ctx context.Context, other client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
			if armed {
				armed = false
				created, ok := obj.DeepCopyObject().(*inventoryv1alpha1.ImageVerdicts)
				require.True(t, ok)
				require.NoError(t, other.Create(ctx, created))
			}
			return other.Create(ctx, obj, opts...)
		},
	})

	counts := verdictsCollectors.counted(t, clusterA, func() {
		require.NoError(t, store.Put(t.Context(), manifestAMD64, defaultPlaybook, sheet("v1")))
	})

	require.False(t, armed, "the race happened")
	require.Equal(t, sheet("v1"), storedSheet(t, c).Status)
	require.Equal(t, writeCounts{Update: 1, Sizes: 1}, counts, "this store created nothing")
}

// Delete removes the sheet of one playbook, and leaves the others' sheets of the manifest.
func TestVerdictsDelete(t *testing.T) {
	store, _ := newVerdictsStore(t, interceptor.Funcs{})
	require.NoError(t, store.Put(t.Context(), manifestAMD64, defaultPlaybook, sheet("v1")))
	require.NoError(t, store.Put(t.Context(), manifestAMD64, strictPlaybook, sheet("v1")))

	counts := verdictsCollectors.counted(t, clusterA, func() {
		require.NoError(t, store.Delete(t.Context(), manifestAMD64, defaultPlaybook))
		require.NoError(t, store.Delete(t.Context(), manifestAMD64, defaultPlaybook), "an absent sheet is no error")
	})

	require.Equal(t, writeCounts{Delete: 1}, counts, "only the delete that removed a sheet counts")
	requireNoSheet(t, store, defaultPlaybook)
	kept, err := store.Get(t.Context(), manifestAMD64, strictPlaybook)
	require.NoError(t, err)
	require.NotNil(t, kept, "the other playbook's sheet stays")
}

func TestVerdictsDeleteReturnsAFailedDelete(t *testing.T) {
	errDelete := errors.New("delete failed")
	store, _ := newVerdictsStore(t, interceptor.Funcs{
		Delete: func(context.Context, client.WithWatch, client.Object, ...client.DeleteOption) error {
			return errDelete
		},
	})
	require.NoError(t, store.Put(t.Context(), manifestAMD64, defaultPlaybook, sheet("v1")))

	counts := verdictsCollectors.counted(t, clusterA, func() {
		require.ErrorIs(t, store.Delete(t.Context(), manifestAMD64, defaultPlaybook), errDelete, "only an absent sheet is no error")
	})

	require.Equal(t, writeCounts{}, counts)
}

func TestVerdictsReadErrorsAreReturned(t *testing.T) {
	errRead := errors.New("read failed")
	store, _ := newVerdictsStore(t, interceptor.Funcs{
		Get: func(context.Context, client.WithWatch, client.ObjectKey, client.Object, ...client.GetOption) error {
			return errRead
		},
		List: func(context.Context, client.WithWatch, client.ObjectList, ...client.ListOption) error {
			return errRead
		},
	})

	_, err := store.Get(t.Context(), manifestAMD64, defaultPlaybook)
	require.ErrorIs(t, err, errRead, "a failed read is not an absent sheet")
	_, err = store.List(t.Context(), manifestAMD64)
	require.ErrorIs(t, err, errRead, "a failed list is not a manifest without sheets")
	counts := verdictsCollectors.counted(t, clusterA, func() {
		require.ErrorIs(t, store.Put(t.Context(), manifestAMD64, defaultPlaybook, sheet("v1")), errRead)
	})
	require.Equal(t, writeCounts{}, counts, "nothing is written after a failed read")
}

func TestVerdictsEachVisitsEverySheetAndStopsAtTheFirstError(t *testing.T) {
	store, _ := newVerdictsStore(t, interceptor.Funcs{})
	require.NoError(t, store.Put(t.Context(), manifestAMD64, defaultPlaybook, sheet("v1")))
	require.NoError(t, store.Put(t.Context(), manifestAMD64, strictPlaybook, sheet("v1")))
	require.NoError(t, store.Put(t.Context(), manifestARM64, defaultPlaybook, sheet("v1")))

	var seen []string
	require.NoError(t, store.Each(t.Context(), func(s *inventoryv1alpha1.ImageVerdicts) error {
		seen = append(seen, s.Name)
		return nil
	}))
	require.ElementsMatch(t, []string{inventory.SheetName(manifestAMD64, defaultPlaybook),
		inventory.SheetName(manifestAMD64, strictPlaybook), inventory.SheetName(manifestARM64, defaultPlaybook)}, seen)

	stop := errors.New("stop")
	calls := 0
	require.ErrorIs(t, store.Each(t.Context(), func(*inventoryv1alpha1.ImageVerdicts) error { calls++; return stop }), stop)
	require.Equal(t, 1, calls)
}
