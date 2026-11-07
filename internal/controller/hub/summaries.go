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

package hub

import (
	"cmp"
	"context"
	"math"
	"slices"
	"sync"

	"k8s.io/apimachinery/pkg/api/equality"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	inventoryv1alpha1 "github.com/bedag/vexplain/api/inventory/v1alpha1"
	"github.com/bedag/vexplain/internal/inventory"
)

// Summaries writes the summary of each image, which the list columns of its ImageInventory read (decision 0039): the
// image's name, its workloads and namespaces over every cluster, its scan state, and the most open and fixable findings
// that a sheet of its manifests counts. It is a controller that reconciles each image, under the name of its
// ImageInventory, whenever something that the summary reads changes, so that no summary goes stale:
//   - the object, through the store's Source: the entry of a cluster, as when the image stops running in one, and the
//     facts, as when a failure clears or a scan names other manifests
//   - a sheet of the image's manifests, as when its findings change. A sheet is up to 1 MiB, so the controller watches
//     the metadata of the sheets only, maps each to the images whose facts name its manifest, and reads the sheets of
//     an image when it summarizes it.
//
// It writes the summary alone, with Store.SetSummary, so that it never undoes the entry that a spoke writes meanwhile,
// nor the facts, and a write of either that meets it keeps the summary. An entry written between the controller's read
// and its write leaves the summary of the object before it, and the entry's own event has the image summarized again.
//
// It writes only a summary that the object doesn't hold yet. The cache shows a write of the controller only once its
// event comes, and a change of the summary alone delivers no event (Store.Source), so the cache can show a summary
// that a write has replaced since. The controller therefore remembers the summary that it last wrote to each object,
// by the object's UID: that is the summary that the object holds, since nothing else writes it. For an object that it
// wrote nothing to, as after a start, the cache tells, which holds every summary written before.
//
// An object without an entry gets no summary: Observe creates the object, and writes the entry in a second call, which
// is an event of its own.
//
// It is hub code: it reaches the images through inventory.Store and the sheets through inventory.VerdictsStore, and no
// spoke, so a hub runs it without one.
type Summaries struct {
	// Store keeps the ImageInventory objects: it reads them, follows them through its Source, finds the images of a
	// manifest, and writes their summaries.
	Store inventory.Store
	// Verdicts keeps the sheets.
	Verdicts inventory.VerdictsStore

	mu sync.Mutex
	// written holds, by digest, the summary that the controller last wrote, and the UID of the object that it wrote it
	// to.
	written map[string]writtenSummary
}

// writtenSummary is a summary that the controller wrote, and the UID of the object that it wrote it to.
type writtenSummary struct {
	uid     types.UID
	summary inventoryv1alpha1.ImageSummary
}

// The controller watches the metadata of the sheets. It reads and writes the ImageInventory objects and reads the
// sheets through the stores, which hold the rights for that.
// +kubebuilder:rbac:groups=inventory.vexplain.bedag.ch,resources=imageverdicts,verbs=list;watch

// Reconcile writes the summary of the image of the request, when its object doesn't hold it. A name that isn't the name
// of an image is ignored, and so is an image without an object.
func (s *Summaries) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	digest, ok := inventory.DigestForName(req.Name)
	if !ok {
		return ctrl.Result{}, nil
	}
	obj, err := s.Store.Get(ctx, digest)
	if err != nil {
		return ctrl.Result{}, err
	}
	if obj == nil {
		s.forget(digest)
		return ctrl.Result{}, nil
	}
	if len(obj.Status.Clusters) == 0 {
		return ctrl.Result{}, nil
	}
	sheets, err := s.sheetsOf(ctx, obj.Status.Facts)
	if err != nil {
		return ctrl.Result{}, err
	}
	summary := summaryOf(obj, sheets)
	if s.holds(digest, obj, summary) {
		return ctrl.Result{}, nil
	}
	found, err := s.Store.SetSummary(ctx, digest, summary)
	if err != nil {
		return ctrl.Result{}, err
	}
	if !found {
		// The image went away since the read.
		s.forget(digest)
		return ctrl.Result{}, nil
	}
	s.remember(digest, obj.UID, summary)
	logf.FromContext(ctx).V(1).Info("Wrote the summary of an image", "digest", digest, "scanState", summary.ScanState,
		"workloads", *summary.Workloads, "open", ptr.Deref(summary.Open, -1))
	return ctrl.Result{}, nil
}

// sheetsOf reads the sheets of the manifests that facts name, by manifest digest. A manifest without a sheet has
// none in the map. A sheet that can't be read is an error, and never one that is absent.
func (s *Summaries) sheetsOf(ctx context.Context, facts *inventoryv1alpha1.ImageFacts) (map[string]*inventoryv1alpha1.ImageVerdicts, error) {
	sheets := map[string]*inventoryv1alpha1.ImageVerdicts{}
	for _, manifest := range manifestDigestsOf(facts) {
		sheet, err := s.Verdicts.Get(ctx, manifest)
		if err != nil {
			return nil, err
		}
		if sheet != nil {
			sheets[manifest] = sheet
		}
	}
	return sheets, nil
}

// holds reports whether the object holds the summary already: the summary that the controller last wrote to it, or,
// when the controller wrote none to it, the summary that the object shows.
func (s *Summaries) holds(digest string, obj *inventoryv1alpha1.ImageInventory, summary inventoryv1alpha1.ImageSummary) bool {
	s.mu.Lock()
	written, ok := s.written[digest]
	s.mu.Unlock()
	if ok && written.uid == obj.UID {
		return equality.Semantic.DeepEqual(written.summary, summary)
	}
	return obj.Status.Summary != nil && equality.Semantic.DeepEqual(*obj.Status.Summary, summary)
}

// remember notes the summary that the controller wrote to the object of digest with the UID.
func (s *Summaries) remember(digest string, uid types.UID, summary inventoryv1alpha1.ImageSummary) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.written == nil {
		s.written = map[string]writtenSummary{}
	}
	s.written[digest] = writtenSummary{uid: uid, summary: summary}
}

// forget forgets what the controller wrote to the object of an image that has none any more.
func (s *Summaries) forget(digest string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.written, digest)
}

// sheetChanged maps an event of a sheet to the images whose facts name its manifest, whose summaries read it. The
// store lists them through the index of the manager's cache.
func (s *Summaries) sheetChanged(ctx context.Context, obj client.Object) []reconcile.Request {
	manifest, ok := inventory.DigestForName(obj.GetName())
	if !ok {
		return nil
	}
	digests, err := s.Store.ManifestReferences(ctx, manifest)
	if err != nil {
		logf.FromContext(ctx).Error(err, "Could not find the images of a sheet's manifest, so their summaries wait for their next change",
			"manifest", manifest)
		return nil
	}
	requests := make([]reconcile.Request, 0, len(digests))
	for _, digest := range digests {
		requests = append(requests, reconcile.Request{NamespacedName: types.NamespacedName{Name: inventory.NameForDigest(digest)}})
	}
	return requests
}

// summaryOf returns the summary of the image of obj, with sheets, the sheets of its manifests by manifest digest:
//   - its name, the first repository of the entries of the clusters, sorted
//   - its workloads and namespaces, added up over the entries, and the most that the summary holds
//   - its scan state: Scanned when every manifest that the facts name has a sheet with a verdict, else the reason of
//     the failure that the facts hold, the first by the collector's name, and Pending otherwise
//   - its open and fixable findings, the most that a sheet with a verdict counts of each: the platforms of an image
//     almost always share their findings, so a sum would count a vulnerability once for each platform. They are
//     absent while no sheet has a verdict.
func summaryOf(obj *inventoryv1alpha1.ImageInventory, sheets map[string]*inventoryv1alpha1.ImageVerdicts) inventoryv1alpha1.ImageSummary {
	summary := inventoryv1alpha1.ImageSummary{ScanState: inventoryv1alpha1.ScanStatePending}
	// A repository that the schema let through empty would name nothing.
	if repositories := slices.DeleteFunc(repositoriesOf(obj), func(r string) bool { return r == "" }); len(repositories) > 0 {
		summary.Image = ptr.To(repositories[0])
	}
	var workloads, namespaces int64
	for _, entry := range obj.Status.Clusters {
		workloads += int64(ptr.Deref(entry.WorkloadCount, 0))
		namespaces += int64(ptr.Deref(entry.NamespaceCount, 0))
	}
	summary.Workloads, summary.Namespaces = ptr.To(atMostInt32(workloads)), ptr.To(atMostInt32(namespaces))

	facts := obj.Status.Facts
	manifests := manifestDigestsOf(facts)
	verdicts := 0
	for _, manifest := range manifests {
		counted := verdictOf(sheets[manifest])
		if counted == nil {
			continue
		}
		verdicts++
		summary.Open = ptr.To(max(ptr.Deref(summary.Open, 0), ptr.Deref(counted.Open, 0)))
		summary.Fixable = ptr.To(max(ptr.Deref(summary.Fixable, 0), ptr.Deref(counted.Fixable, 0)))
	}
	switch {
	case len(manifests) > 0 && verdicts == len(manifests):
		summary.ScanState = inventoryv1alpha1.ScanStateScanned
	case facts != nil && len(facts.Failures) > 0:
		first := slices.MinFunc(facts.Failures, func(a, b inventoryv1alpha1.ScanFailure) int { return cmp.Compare(a.Source, b.Source) })
		summary.ScanState = inventoryv1alpha1.ScanState(first.Reason)
	}
	return summary
}

// verdictOf returns the summary of a sheet that holds a verdict, and nil for a sheet without one: a sheet without
// counts, a version of its findings or a summary says nothing of the findings yet.
func verdictOf(sheet *inventoryv1alpha1.ImageVerdicts) *inventoryv1alpha1.SheetSummary {
	if sheet == nil || sheet.Status.Counts == nil || sheet.Status.FindingsVersion == nil {
		return nil
	}
	return sheet.Status.Summary
}

// manifestDigestsOf returns the digests of the manifests that facts name, sorted, each once: an index can list one
// manifest under two platforms.
func manifestDigestsOf(facts *inventoryv1alpha1.ImageFacts) []string {
	if facts == nil {
		return nil
	}
	digests := make([]string, 0, len(facts.Manifests))
	for _, manifest := range facts.Manifests {
		digests = append(digests, manifest.Digest)
	}
	slices.Sort(digests)
	return slices.Compact(digests)
}

// atMostInt32 returns n, or the largest int32 when n is larger.
func atMostInt32(n int64) int32 {
	return int32(min(n, math.MaxInt32))
}

// SetupWithManager sets up the controller of the summaries with the Manager.
func (s *Summaries) SetupWithManager(mgr ctrl.Manager) error {
	sheets := &metav1.PartialObjectMetadata{}
	sheets.SetGroupVersionKind(inventoryv1alpha1.GroupVersion.WithKind("ImageVerdicts"))
	return ctrl.NewControllerManagedBy(mgr).
		Named("hub-image-summaries").
		// Every event of an ImageInventory, through the store, the only door to them, but a change of its summary
		// alone: the entries of the clusters and the facts.
		WatchesRawSource(s.Store.Source()).
		// The sheets of the manifests of the images, through their metadata.
		Watches(sheets, handler.EnqueueRequestsFromMapFunc(s.sheetChanged)).
		Complete(s)
}
