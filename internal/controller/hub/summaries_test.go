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
	"math"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	inventoryv1alpha1 "github.com/bedag/vexplain/api/inventory/v1alpha1"
	"github.com/bedag/vexplain/internal/controller/hub"
	"github.com/bedag/vexplain/internal/evidence"
	"github.com/bedag/vexplain/internal/inventory"
	subjects "github.com/bedag/vexplain/sdk/subject"
	"github.com/bedag/vexplain/sdk/workloads"
)

// These tests cover the summary of an image (decision 0039): what it says of the image's sheets, facts and
// clusters' entries, how the hub writes it while the spokes write their entries, and that it follows each of them
// as it changes, so that it never goes stale.

// The workloads that run the images of these tests: Deployments.
const (
	appsGroup  = "apps"
	deployment = "Deployment"
)

// ---- what the summary says ----

// verdictWith returns the sheet of manifest with a verdict whose summary counts open and fixable findings.
func verdictWith(manifest string, open, fixable int32) *inventoryv1alpha1.ImageVerdicts {
	return &inventoryv1alpha1.ImageVerdicts{
		ObjectMeta: metav1.ObjectMeta{Name: inventory.SheetName(manifest, playbookName)},
		Spec:       inventoryv1alpha1.ImageVerdictsSpec{ManifestDigest: manifest, Playbook: playbookName},
		Status: inventoryv1alpha1.ImageVerdictsStatus{
			Playbook:        ptr.To(playbookName),
			FindingsVersion: ptr.To(v1),
			OmittedFindings: ptr.To(int32(0)),
			Counts: &inventoryv1alpha1.FindingCounts{
				Affected: ptr.To(int32(0)), UnderInvestigation: ptr.To(open), NotAffected: ptr.To(int32(0)), Fixed: ptr.To(int32(0)),
			},
			Summary: &inventoryv1alpha1.SheetSummary{
				Open: ptr.To(open), Fixable: ptr.To(fixable), Held: ptr.To(int32(0)), Settled: ptr.To(int32(0)), Omitted: ptr.To(int32(0)),
			},
		},
	}
}

// noVerdict returns the sheet of manifest without a verdict: it says nothing of the findings yet.
func noVerdict(manifest string) *inventoryv1alpha1.ImageVerdicts {
	sheet := verdictWith(manifest, 0, 0)
	sheet.Status = inventoryv1alpha1.ImageVerdictsStatus{Playbook: ptr.To(playbookName)}
	return sheet
}

// sheetsOf returns the sheets by the digests of their manifests.
func sheetsOf(sheets ...*inventoryv1alpha1.ImageVerdicts) map[string]*inventoryv1alpha1.ImageVerdicts {
	byManifest := map[string]*inventoryv1alpha1.ImageVerdicts{}
	for _, sheet := range sheets {
		byManifest[sheet.Spec.ManifestDigest] = sheet
	}
	return byManifest
}

// imageWith returns the ImageInventory of digest with the entries.
func imageWith(digest string, entries ...inventoryv1alpha1.ClusterPresence) *inventoryv1alpha1.ImageInventory {
	return &inventoryv1alpha1.ImageInventory{
		ObjectMeta: metav1.ObjectMeta{Name: inventory.NameForDigest(digest)},
		Spec:       inventoryv1alpha1.ImageInventorySpec{Digest: digest},
		Status:     inventoryv1alpha1.ImageInventoryStatus{DigestKind: ptr.To(inventoryv1alpha1.DigestKindRepoDigest), Clusters: entries},
	}
}

// entryOf returns the entry of a cluster in which so many workloads in so many namespaces run the image, pulled from
// the repositories.
func entryOf(cluster string, workloadCount, namespaceCount int32, repositories ...string) inventoryv1alpha1.ClusterPresence {
	return inventoryv1alpha1.ClusterPresence{
		Cluster: cluster, ClusterID: cluster + "-id", WorkloadCount: ptr.To(workloadCount), NamespaceCount: ptr.To(namespaceCount),
		Repositories: repositories, FirstSeenTime: ptr.To(metav1.NewTime(t0)),
	}
}

// withFailure returns facts with the failure of the source for the reason, after what facts held.
func withFailure(facts *inventoryv1alpha1.ImageFacts, source string, reason inventoryv1alpha1.ScanFailureReason) *inventoryv1alpha1.ImageFacts {
	if facts == nil {
		facts = &inventoryv1alpha1.ImageFacts{}
	}
	facts.Failures = append(facts.Failures, inventoryv1alpha1.ScanFailure{
		Source: source, Reason: reason, Time: ptr.To(metav1.NewTime(t0)), Attempts: 1,
	})
	return facts
}

func TestTheSummaryOfAnImageOverTwoManifestsAndTwoClusters(t *testing.T) {
	amd64, arm64 := digestOf(201), digestOf(202)
	image := imageWith(digestOf(1),
		entryOf(localCluster, 1, 1, repository, mirror),
		entryOf(otherCluster, 3, 2, mirror))
	image.Status.Facts = scannedBy(scannerVersion, amd64, arm64)

	got := hub.SummaryOf(image, sheetsOf(verdictWith(amd64, 5, 2), verdictWith(arm64, 3, 3)))

	require.Equal(t, inventoryv1alpha1.ImageSummary{
		Image:      ptr.To(repository),
		Workloads:  ptr.To(int32(4)),
		Namespaces: ptr.To(int32(3)),
		ScanState:  inventoryv1alpha1.ScanStateScanned,
		// The most that a sheet counts, each: the platforms of an image almost always share their findings.
		Open:    ptr.To(int32(5)),
		Fixable: ptr.To(int32(3)),
	}, got)
}

func TestTheScanStateAndTheFindingsOfAnImage(t *testing.T) {
	amd64, arm64 := digestOf(201), digestOf(202)
	underTwoPlatforms := scannedBy(scannerVersion, amd64)
	underTwoPlatforms.Manifests = append(underTwoPlatforms.Manifests,
		inventoryv1alpha1.ManifestFact{Platform: linuxARM64 + "/v8", Digest: amd64})
	cases := []struct {
		name          string
		facts         *inventoryv1alpha1.ImageFacts
		sheets        map[string]*inventoryv1alpha1.ImageVerdicts
		want          inventoryv1alpha1.ScanState
		open, fixable *int32
	}{
		{name: "not scanned yet", want: inventoryv1alpha1.ScanStatePending},
		{name: "scanned, without a sheet yet", facts: scannedBy(scannerVersion, amd64),
			want: inventoryv1alpha1.ScanStatePending},
		{name: "with a sheet that has no verdict yet", facts: scannedBy(scannerVersion, amd64), sheets: sheetsOf(noVerdict(amd64)),
			want: inventoryv1alpha1.ScanStatePending},
		{name: "a manifest of two without a sheet", facts: scannedBy(scannerVersion, amd64, arm64), sheets: sheetsOf(verdictWith(amd64, 4, 1)),
			want: inventoryv1alpha1.ScanStatePending, open: ptr.To(int32(4)), fixable: ptr.To(int32(1))},
		{name: "a failure before any success", facts: withFailure(nil, scanner, inventoryv1alpha1.ScanFailureReasonUnauthorized),
			want: inventoryv1alpha1.ScanState(inventoryv1alpha1.ScanFailureReasonUnauthorized)},
		{name: "an image ID, which no registry serves", facts: withFailure(nil, scanner, inventoryv1alpha1.ScanFailureReasonNotPullable),
			want: inventoryv1alpha1.ScanState(inventoryv1alpha1.ScanFailureReasonNotPullable)},
		{name: "failures of two sources, the first by name",
			facts: withFailure(withFailure(nil, "scanner-b", inventoryv1alpha1.ScanFailureReasonTimedOut), scanner, "RateLimited"),
			want:  "RateLimited"},
		{name: "a failure after a success, while a manifest has no sheet",
			facts:  withFailure(scannedBy(scannerVersion, amd64, arm64), scanner, inventoryv1alpha1.ScanFailureReasonPullFailed),
			sheets: sheetsOf(verdictWith(amd64, 4, 1)),
			want:   inventoryv1alpha1.ScanState(inventoryv1alpha1.ScanFailureReasonPullFailed), open: ptr.To(int32(4)), fixable: ptr.To(int32(1))},
		{name: "a failure after a success, while every manifest has its verdict",
			facts:  withFailure(scannedBy(scannerVersion, amd64), scanner, inventoryv1alpha1.ScanFailureReasonPullFailed),
			sheets: sheetsOf(verdictWith(amd64, 0, 0)),
			want:   inventoryv1alpha1.ScanStateScanned, open: ptr.To(int32(0)), fixable: ptr.To(int32(0))},
		{name: "one manifest under two platforms, with its verdict", facts: underTwoPlatforms, sheets: sheetsOf(verdictWith(amd64, 2, 1)),
			want: inventoryv1alpha1.ScanStateScanned, open: ptr.To(int32(2)), fixable: ptr.To(int32(1))},
		{name: "the sheet of a manifest that the facts don't name", facts: scannedBy(scannerVersion, amd64), sheets: sheetsOf(verdictWith(arm64, 9, 9)),
			want: inventoryv1alpha1.ScanStatePending},
		// A reason shares its form with the scan states, so a collector can spell one of them. The failure still shows
		// as a failure, and never as a scan that waits or one that is complete.
		{name: "a failure whose reason is spelt Pending", facts: withFailure(nil, scanner, "Pending"),
			want: inventoryv1alpha1.ScanState(inventoryv1alpha1.ScanFailureReasonInternal)},
		{name: "a failure whose reason is spelt Scanned, while a manifest has no sheet",
			facts: withFailure(scannedBy(scannerVersion, amd64), scanner, "Scanned"),
			want:  inventoryv1alpha1.ScanState(inventoryv1alpha1.ScanFailureReasonInternal)},
		{name: "a failure whose reason is spelt Scanned, while every manifest has its verdict",
			facts:  withFailure(scannedBy(scannerVersion, amd64), scanner, "Scanned"),
			sheets: sheetsOf(verdictWith(amd64, 2, 1)),
			want:   inventoryv1alpha1.ScanStateScanned, open: ptr.To(int32(2)), fixable: ptr.To(int32(1))},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			image := imageWith(digestOf(1), entryOf(localCluster, 1, 1, repository))
			image.Status.Facts = tc.facts

			got := hub.SummaryOf(image, tc.sheets)

			require.Equal(t, tc.want, got.ScanState)
			require.Equal(t, tc.open, got.Open, "open")
			require.Equal(t, tc.fixable, got.Fixable, "fixable")
		})
	}
}

func TestTheSummaryOfAnImageIDHasNoName(t *testing.T) {
	image := imageWith(digestOf(1), entryOf(localCluster, 1, 1))

	got := hub.SummaryOf(image, nil)

	require.Nil(t, got.Image, "no repository names it")
	require.Equal(t, ptr.To(int32(1)), got.Workloads)
}

// The counts of 256 clusters can add up to more than the field holds. The sum stops at the most that it holds.
func TestTheSummaryOfAnImageStopsItsCountsAtTheMostThatTheyHold(t *testing.T) {
	image := imageWith(digestOf(1),
		entryOf(localCluster, math.MaxInt32, math.MaxInt32, repository),
		entryOf(otherCluster, 1, 1, repository))

	got := hub.SummaryOf(image, nil)

	require.Equal(t, ptr.To(int32(math.MaxInt32)), got.Workloads)
	require.Equal(t, ptr.To(int32(math.MaxInt32)), got.Namespaces)
}

// ---- how the summary is written ----

// summariesFixture is the controller of the summaries over a fake client, with what it counts of the writes of the
// summary.
type summariesFixture struct {
	client    client.Client
	store     inventory.Store
	verdicts  inventory.VerdictsStore
	summaries *hub.Summaries
	patches   int
	// cached, when it isn't nil, is the summary that a read of an ImageInventory shows, as a cache that hasn't seen
	// the last write of the summary yet would.
	cached *inventoryv1alpha1.ImageSummary
}

func newSummaries(t *testing.T, funcs interceptor.Funcs) *summariesFixture {
	t.Helper()
	f := &summariesFixture{}
	get := funcs.Get
	funcs.Get = func(ctx context.Context, c client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
		var err error
		if get != nil {
			err = get(ctx, c, key, obj, opts...)
		} else {
			err = c.Get(ctx, key, obj, opts...)
		}
		if image, ok := obj.(*inventoryv1alpha1.ImageInventory); ok && err == nil && f.cached != nil {
			image.Status.Summary = f.cached.DeepCopy()
		}
		return err
	}
	funcs.SubResourcePatch = func(ctx context.Context, c client.Client, subResource string, obj client.Object, patch client.Patch,
		opts ...client.SubResourcePatchOption) error {
		if _, ok := obj.(*inventoryv1alpha1.ImageInventory); ok {
			f.patches++
		}
		return c.SubResource(subResource).Patch(ctx, obj, patch, opts...)
	}
	f.client = newClient(t, funcs)
	f.store = inventory.NewCRDStore(f.client, nil, cluster)
	f.verdicts = inventory.NewCRDVerdictsStore(f.client, cluster)
	f.summaries = &hub.Summaries{Store: f.store, Verdicts: f.verdicts}
	return f
}

// reconcile has the controller look at the image of digest.
func (f *summariesFixture) reconcile(t *testing.T, digest string) {
	t.Helper()
	res, err := f.summaries.Reconcile(t.Context(), imageRequest(digest))
	require.NoError(t, err)
	require.Equal(t, ctrl.Result{}, res)
}

// summaryOf reads the summary of digest as the client stores it, past what a cache shows.
func (f *summariesFixture) summaryOf(t *testing.T, digest string) *inventoryv1alpha1.ImageSummary {
	t.Helper()
	cached := f.cached
	f.cached = nil
	defer func() { f.cached = cached }()
	var image inventoryv1alpha1.ImageInventory
	require.NoError(t, f.client.Get(t.Context(), client.ObjectKey{Name: inventory.NameForDigest(digest)}, &image))
	return image.Status.Summary
}

// runHere reports, as the spoke of this cluster does, that so many workloads in one namespace run digest.
func (f *summariesFixture) runHere(t *testing.T, digest string, workloadCount int) {
	t.Helper()
	observation := inventory.Observation{
		Cluster: localCluster, ClusterID: localCluster + "-id", DigestKind: inventoryv1alpha1.DigestKindRepoDigest,
		Repositories: []string{repository}, NamespaceCount: 1,
	}
	for i := range workloadCount {
		observation.Workloads = append(observation.Workloads, workloads.WorkloadRef{
			APIGroup: appsGroup, Kind: deployment, Namespace: "team-a", Name: "web-" + string(rune('a'+i)),
		})
	}
	require.NoError(t, f.store.Observe(t.Context(), digest, observation))
}

// putSheet writes the sheet of a manifest.
func (f *summariesFixture) putSheet(t *testing.T, sheet *inventoryv1alpha1.ImageVerdicts) {
	t.Helper()
	require.NoError(t, f.verdicts.Put(t.Context(), sheet.Spec.ManifestDigest, sheet.Spec.Playbook, sheet.Status))
}

// scannedImage is an image that runs two workloads in this cluster, and whose one manifest has a sheet with a
// verdict.
func (f *summariesFixture) scannedImage(t *testing.T, digest, manifest string) inventoryv1alpha1.ImageSummary {
	t.Helper()
	f.runHere(t, digest, 2)
	setFacts(t, f.store, digest, scannedBy(scannerVersion, manifest))
	f.putSheet(t, verdictWith(manifest, 3, 1))
	return inventoryv1alpha1.ImageSummary{
		Image: ptr.To(repository), Workloads: ptr.To(int32(2)), Namespaces: ptr.To(int32(1)),
		ScanState: inventoryv1alpha1.ScanStateScanned, Open: ptr.To(int32(3)), Fixable: ptr.To(int32(1)),
	}
}

func TestTheSummariesWriteTheSummaryOfAnImageAndNothingWhileItHoldsIt(t *testing.T) {
	f := newSummaries(t, interceptor.Funcs{})
	digest, manifest := digestOf(1), digestOf(101)
	want := f.scannedImage(t, digest, manifest)

	f.reconcile(t, digest)

	require.Equal(t, &want, f.summaryOf(t, digest))
	require.Equal(t, 1, f.patches)

	f.reconcile(t, digest)
	require.Equal(t, 1, f.patches, "the object holds the summary already")
}

// The controller writes the summary, and an event of the cache comes only after the write is in the cache. Until
// then, a read of the cache shows the summary from before the write, and a change of the summary alone delivers no
// event (inventory.Store's Source). So when what the summary reads goes back to what it was before the write, the
// summary that the cache shows is the one to write, and the stored one isn't: the controller writes it all the same.
func TestTheSummariesWriteAgainWhatTheirOwnWriteChangedWhileTheCacheShowsTheSummaryBeforeIt(t *testing.T) {
	f := newSummaries(t, interceptor.Funcs{})
	digest, manifest := digestOf(1), digestOf(101)
	twoWorkloads := f.scannedImage(t, digest, manifest)
	f.reconcile(t, digest)
	require.Equal(t, &twoWorkloads, f.summaryOf(t, digest))

	// A third workload starts, and the controller writes the summary of three.
	f.runHere(t, digest, 3)
	f.reconcile(t, digest)
	require.Equal(t, ptr.To(int32(3)), f.summaryOf(t, digest).Workloads)

	// The third workload stops again before the cache shows the summary of three.
	f.runHere(t, digest, 2)
	f.cached = &twoWorkloads
	f.reconcile(t, digest)

	require.Equal(t, &twoWorkloads, f.summaryOf(t, digest), "the summary of three, which the cache didn't show, is replaced")
}

// A digest whose object is deleted and created again, as when it stops running everywhere and starts again, has a new
// object without a summary, whatever the controller last wrote for the digest.
func TestTheSummariesWriteTheSummaryOfANewObjectOfTheSameDigest(t *testing.T) {
	f := newSummaries(t, interceptor.Funcs{})
	digest, manifest := digestOf(1), digestOf(101)
	f.putSheet(t, verdictWith(manifest, 3, 1))
	first := f.createImage(t, digest, "first", manifest)
	f.reconcile(t, digest)
	want := inventoryv1alpha1.ImageSummary{
		Image: ptr.To(repository), Workloads: ptr.To(int32(2)), Namespaces: ptr.To(int32(1)),
		ScanState: inventoryv1alpha1.ScanStateScanned, Open: ptr.To(int32(3)), Fixable: ptr.To(int32(1)),
	}
	require.Equal(t, &want, f.summaryOf(t, digest))

	require.NoError(t, f.client.Delete(t.Context(), first))
	f.createImage(t, digest, "again", manifest)
	require.Nil(t, f.summaryOf(t, digest))

	f.reconcile(t, digest)

	require.Equal(t, &want, f.summaryOf(t, digest), "the new object gets the summary")
}

// createImage creates the ImageInventory of digest with the UID, in which two workloads of this cluster run the image,
// and whose facts name the manifest.
func (f *summariesFixture) createImage(t *testing.T, digest string, uid types.UID, manifest string) *inventoryv1alpha1.ImageInventory {
	t.Helper()
	image := imageWith(digest)
	image.UID = uid
	require.NoError(t, f.client.Create(t.Context(), image))
	image.Status = *imageWith(digest, entryOf(localCluster, 2, 1, repository)).Status.DeepCopy()
	image.Status.Facts = scannedBy(scannerVersion, manifest)
	require.NoError(t, f.client.Status().Update(t.Context(), image))
	require.Equal(t, uid, image.UID)
	return image
}

// Observe creates an object, and writes its entry in a second call. An object without an entry is one of those
// moments, and gets no summary: the write of the entry is an event of its own.
func TestTheSummariesLeaveAnObjectWithoutEntriesAlone(t *testing.T) {
	f := newSummaries(t, interceptor.Funcs{})
	digest := digestOf(1)
	require.NoError(t, f.client.Create(t.Context(), imageWith(digest)))

	f.reconcile(t, digest)

	require.Zero(t, f.patches)
	require.Nil(t, f.summaryOf(t, digest))
}

func TestTheSummariesOfAnImageThatIsGoneWriteNothing(t *testing.T) {
	f := newSummaries(t, interceptor.Funcs{})

	f.reconcile(t, digestOf(1))

	require.Zero(t, f.patches)
}

// Each playbook that judges a manifest keeps a sheet of it, and the summary takes the worse: the one with the most open
// findings, with its fixable ones.
func TestTheSummaryOfAnImageTakesTheWorseSheetOfAManifest(t *testing.T) {
	f := newSummaries(t, interceptor.Funcs{})
	digest, manifest := digestOf(1), digestOf(101)
	f.runHere(t, digest, 1)
	setFacts(t, f.store, digest, scannedBy(scannerVersion, manifest))
	f.putSheet(t, verdictWith(manifest, 2, 2))
	stricter := verdictWith(manifest, 5, 1)
	stricter.Name, stricter.Spec.Playbook = inventory.SheetName(manifest, strictPlaybook), strictPlaybook
	f.putSheet(t, stricter)

	f.reconcile(t, digest)

	summary := f.summaryOf(t, digest)
	require.NotNil(t, summary)
	require.Equal(t, inventoryv1alpha1.ScanStateScanned, summary.ScanState)
	require.Equal(t, ptr.To(int32(5)), summary.Open)
	require.Equal(t, ptr.To(int32(1)), summary.Fixable, "the fixable findings of the worse sheet")
}

// A sheet that can't be read is never taken for one that is absent: the controller tries again, and writes nothing
// meanwhile.
func TestTheSummariesTryAgainWhenASheetCannotBeRead(t *testing.T) {
	broken := errors.New("the API server is away")
	f := newSummaries(t, interceptor.Funcs{
		List: func(ctx context.Context, c client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
			if _, ok := list.(*inventoryv1alpha1.ImageVerdictsList); ok {
				return broken
			}
			return c.List(ctx, list, opts...)
		},
	})
	digest, manifest := digestOf(1), digestOf(101)
	f.runHere(t, digest, 1)
	setFacts(t, f.store, digest, scannedBy(scannerVersion, manifest))

	_, err := f.summaries.Reconcile(t.Context(), imageRequest(digest))

	require.ErrorIs(t, err, broken)
	require.Zero(t, f.patches)
}

// A sheet's event maps to the images whose facts name its manifest, which are the summaries that read it.
func TestTheEventOfASheetMapsToTheImagesWhoseFactsNameItsManifest(t *testing.T) {
	f := newSummaries(t, interceptor.Funcs{})
	shared, own := digestOf(101), digestOf(102)
	for _, image := range []struct {
		digest    string
		manifests []string
	}{{digestOf(1), []string{shared}}, {digestOf(2), []string{shared, own}}, {digestOf(3), []string{own}}} {
		f.runHere(t, image.digest, 1)
		setFacts(t, f.store, image.digest, scannedBy(scannerVersion, image.manifests...))
	}

	got := hub.SheetChanged(f.summaries, t.Context(), verdictWith(shared, 1, 1))

	require.ElementsMatch(t, []ctrl.Request{imageRequest(digestOf(1)), imageRequest(digestOf(2))}, got)
	require.Empty(t, hub.SheetChanged(f.summaries, t.Context(), &metav1.PartialObjectMetadata{
		ObjectMeta: metav1.ObjectMeta{Name: "not-a-digest"},
	}), "a sheet whose name is no digest's")
}

// ---- with the manager ----

// imageSummaryOf returns a function that reads the summary of the image of digest.
func imageSummaryOf(digest string) func(g Gomega) *inventoryv1alpha1.ImageSummary {
	return func(g Gomega) *inventoryv1alpha1.ImageSummary {
		var image inventoryv1alpha1.ImageInventory
		g.Expect(lookup(digest, &image)()).To(Succeed())
		return image.Status.Summary
	}
}

var _ = Describe("The summaries of the images", func() {
	It("summarize an image from its sheets, its facts and the entries of every cluster, and follow each as it changes", func() {
		findings.set(v1, exampleMatch, otherMatch, goneMatch)
		namespace, digest, manifest := newNamespace(), newDigest(), newDigest()
		store := inventory.NewCRDStore(k8sClient, nil, cluster)

		By("summarizing a running image once the sheet of its manifest has a verdict")
		runAndScan(namespace, "app-0", digest, evidenceOf(manifest))
		Eventually(imageSummaryOf(digest), reaction, poll).Should(Equal(&inventoryv1alpha1.ImageSummary{
			Image: ptr.To(repository), Workloads: ptr.To(int32(0)), Namespaces: ptr.To(int32(1)),
			ScanState: inventoryv1alpha1.ScanStateScanned, Open: ptr.To(int32(2)), Fixable: ptr.To(int32(1)),
		}))

		By("adding the workloads and the namespaces of another cluster, and keeping the first repository by name")
		Expect(store.Observe(ctx, digest, inventory.Observation{
			Cluster: otherCluster, ClusterID: otherCluster + "-id", DigestKind: inventoryv1alpha1.DigestKindRepoDigest,
			Repositories: []string{mirror}, NamespaceCount: 2, Workloads: []workloads.WorkloadRef{
				{APIGroup: appsGroup, Kind: deployment, Namespace: "team-a", Name: "web"},
				{APIGroup: appsGroup, Kind: deployment, Namespace: "team-b", Name: "web"},
			},
		})).To(Succeed())
		Eventually(imageSummaryOf(digest), reaction, poll).Should(And(
			HaveField("Workloads", HaveValue(Equal(int32(2)))),
			HaveField("Namespaces", HaveValue(Equal(int32(3)))),
			HaveField("Image", HaveValue(Equal(repository)))))

		By("following its sheet when the findings change")
		findings.setFor(manifest, otherMatch)
		findings.change(subjects.Manifest(manifest))
		Eventually(statusOf(manifest), reaction, poll).Should(HaveField("Summary", HaveField("Open", HaveValue(Equal(int32(1))))))
		Eventually(imageSummaryOf(digest), reaction, poll).Should(And(
			HaveField("Open", HaveValue(Equal(int32(1)))),
			HaveField("Fixable", HaveValue(Equal(int32(1))))))

		By("following an image that stops running in a cluster")
		forget(GinkgoT(), store, digest, otherCluster)
		Eventually(imageSummaryOf(digest), reaction, poll).Should(And(
			HaveField("Workloads", HaveValue(Equal(int32(0)))),
			HaveField("Namespaces", HaveValue(Equal(int32(1))))))
	})

	It("show why the scan of an image failed, until a scan succeeds and the failure clears", func() {
		findings.set(v1, exampleMatch, otherMatch, goneMatch)
		namespace, digest, manifest := newNamespace(), newDigest(), newDigest()
		runWorkload(namespace, "app-0", digest)
		asked := expectRequest(digest, 0)

		By("showing the reason of the failure")
		facts := evidence.NewFactsWriter(inventory.NewCRDStore(k8sClient, nil, cluster))
		Expect(facts.Failed(ctx, digest, scanner, 0, string(inventoryv1alpha1.ScanFailureReasonUnauthorized),
			"the registry wants credentials")).To(Succeed())
		Eventually(imageSummaryOf(digest), reaction, poll).Should(HaveField("ScanState",
			Equal(inventoryv1alpha1.ScanState(inventoryv1alpha1.ScanFailureReasonUnauthorized))))

		By("showing Scanned once a scan has succeeded and the sheet of its manifest has a verdict")
		answerWithScan(digest, expectRequest(digest, asked), evidenceOf(manifest))
		Eventually(imageSummaryOf(digest), reaction, poll).Should(And(
			HaveField("ScanState", Equal(inventoryv1alpha1.ScanStateScanned)),
			HaveField("Open", HaveValue(Equal(int32(2))))))
	})

	// A summary that said Scanned without the open findings of a sheet would break its schema, so the hub would try to
	// write it again and again. A failure whose reason is spelt Scanned shows as Internal, and its summary is written.
	It("show a failure whose reason is spelt as a scan state as Internal", func() {
		namespace, digest := newNamespace(), newDigest()
		runWorkload(namespace, "app-0", digest)
		expectRequest(digest, 0)

		facts := evidence.NewFactsWriter(inventory.NewCRDStore(k8sClient, nil, cluster))
		Expect(facts.Failed(ctx, digest, scanner, 0, string(inventoryv1alpha1.ScanStateScanned), "the collector says Scanned")).To(Succeed())

		Eventually(imageSummaryOf(digest), reaction, poll).Should(And(
			HaveField("ScanState", Equal(inventoryv1alpha1.ScanState(inventoryv1alpha1.ScanFailureReasonInternal))),
			HaveField("Open", BeNil())))
	})
})
