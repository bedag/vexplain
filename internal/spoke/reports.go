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
	"context"
	"fmt"
	"maps"
	"strings"
	"sync"

	"github.com/go-logr/logr"
	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
	inventoryv1alpha1 "github.com/bedag/vexplain/api/inventory/v1alpha1"
	triagev1alpha1 "github.com/bedag/vexplain/api/triage/v1alpha1"
	"github.com/bedag/vexplain/internal/inventory"
	"github.com/bedag/vexplain/internal/metrics"
	"github.com/bedag/vexplain/internal/settings"
	"github.com/bedag/vexplain/sdk/evidence"
)

// digestLabel starts the label that a report carries for each image digest it holds: the key is followed by the first 63
// hex digits of the digest, which a label name can hold, and the value is empty.
const digestLabel = "digest.vexplain.bedag.ch/"

// sweepName is the name of the request that has every report looked at again.
const sweepName = "sweep"

// Reports renders a WorkloadReport for each workload that runs in the spoke's cluster, in the workload's namespace
// (design 5.5). A report holds the images of the workload with how far the result for each goes, the findings that need
// action with their urgency and next step, and the workload's exposure. Render builds its status. Reports reads the
// workloads from Presence, the facts of their images from the inventory store and the sheets from the verdicts store,
// and writes only reports of its own.
//
//   - A report is written only when it differs from what the API server holds: its metadata first, when its labels or
//     its owner reference changed, then its status. The workload owns it through its UID, so that Kubernetes deletes it
//     with the workload, and the renderer deletes it when the workload leaves presence.
//   - Until presence KnowsWhatRuns, it writes and deletes nothing: after a start, presence names the workloads of a
//     collector only from its first snapshot, so a workload that only a collector yet to send one names would have its
//     report deleted, and written again.
//   - Until every collector that streams exposure to the spoke has sent its first snapshot since the start (Presence's
//     exposureKnown), a report keeps the exposure in its status, so that its findings keep their urgency. A new report
//     has Unknown then.
//   - It looks at a workload's report whenever presence changes an image that the workload runs, whenever the facts of
//     such an image change, and whenever one of its sheets does. It watches the metadata of the sheets only, since a
//     sheet is up to 1 MiB, and reads a sheet when it renders. Presence's changes include those of exposure and of the
//     collectors that stream it. An OperatorConfig change, which can change the table's overrides, has every report
//     looked at again, and so does a change that lets presence know what runs.
//   - The reports are watched through their metadata, and read from the API server when rendered: a report is up to
//     1 MiB too.
type Reports struct {
	client   client.Client
	api      client.Reader
	cache    client.Reader
	mapper   meta.RESTMapper
	presence *Presence
	store    inventory.Store
	verdicts inventory.VerdictsStore
	log      logr.Logger
	series   *ReportsCollector

	mu    sync.Mutex
	queue workqueue.TypedRateLimitingInterface[reconcile.Request]
}

// The renderer lists and watches the reports through their metadata, creates, patches and deletes them and writes their
// status, and watches the sheets through their metadata. It owns reports by their workloads' UIDs and needs no right on
// the workloads.
// +kubebuilder:rbac:groups=triage.vexplain.bedag.ch,resources=workloadreports,verbs=get;list;watch;create;patch;delete
// +kubebuilder:rbac:groups=triage.vexplain.bedag.ch,resources=workloadreports/status,verbs=update
// +kubebuilder:rbac:groups=inventory.vexplain.bedag.ch,resources=imageverdicts,verbs=list;watch

// NewReports returns the renderer of the reports, which works through the manager's clients. It reads what runs from
// presence, the facts of the images from store and the sheets from verdicts. It sets itself up to be told of each image
// that presence changes.
func NewReports(mgr ctrl.Manager, presence *Presence, store inventory.Store, verdicts inventory.VerdictsStore) *Reports {
	r := &Reports{
		client:   mgr.GetClient(),
		api:      mgr.GetAPIReader(),
		cache:    mgr.GetCache(),
		mapper:   mgr.GetRESTMapper(),
		presence: presence,
		store:    store,
		verdicts: verdicts,
		log:      ctrl.Log.WithName("spoke-reports"),
		series:   NewReportsCollector(),
	}
	metrics.SetSource("workload-reports", r.series)
	presence.mu.Lock()
	presence.changed = func(digest string) { r.add(requestFor(digest)) }
	presence.stirred = func() { r.add(sweepRequest()) }
	presence.mu.Unlock()
	return r
}

// add puts a request in the controller's queue, or drops it before the queue exists: the sweep at the start covers it.
func (r *Reports) add(req reconcile.Request) {
	r.mu.Lock()
	queue := r.queue
	r.mu.Unlock()
	if queue != nil {
		queue.Add(req)
	}
}

// SetupWithManager sets up the controller, named spoke-reports. Its requests have a namespace when they name a report,
// and none when they name the ImageInventory of an image, or the sweep.
func (r *Reports) SetupWithManager(mgr ctrl.Manager) error {
	sheets := &metav1.PartialObjectMetadata{}
	sheets.SetGroupVersionKind(inventoryv1alpha1.GroupVersion.WithKind("ImageVerdicts"))
	sweep := handler.EnqueueRequestsFromMapFunc(func(context.Context, client.Object) []reconcile.Request {
		return []reconcile.Request{sweepRequest()}
	})
	return ctrl.NewControllerManagedBy(mgr).
		Named("spoke-reports").
		For(&triagev1alpha1.WorkloadReport{}, builder.OnlyMetadata).
		WatchesRawSource(r.store.Source()).
		Watches(sheets, handler.EnqueueRequestsFromMapFunc(r.sheetChanged)).
		Watches(&configv1alpha1.OperatorConfig{}, sweep).
		WatchesRawSource(source.Func(func(ctx context.Context, queue workqueue.TypedRateLimitingInterface[reconcile.Request]) error {
			r.mu.Lock()
			r.queue = queue
			r.mu.Unlock()
			// Whatever happened before the queue existed has every report looked at.
			queue.Add(sweepRequest())
			return nil
		})).
		Complete(r)
}

func sweepRequest() reconcile.Request {
	return reconcile.Request{NamespacedName: types.NamespacedName{Name: sweepName}}
}

// sheetChanged maps a sheet to the images whose facts name its manifest.
func (r *Reports) sheetChanged(ctx context.Context, obj client.Object) []reconcile.Request {
	manifest, ok := inventory.DigestForName(obj.GetName())
	if !ok {
		return nil
	}
	digests, err := r.store.ManifestReferences(ctx, manifest)
	if err != nil {
		r.log.Error(err, "Could not find the images of a sheet's manifest, so their reports wait for the next change")
		return nil
	}
	requests := make([]reconcile.Request, 0, len(digests))
	for _, digest := range digests {
		requests = append(requests, requestFor(digest))
	}
	return requests
}

// Reconcile looks at a report, at the reports of an image, or at every report, by the request.
func (r *Reports) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	known, err := r.presence.KnowsWhatRuns(ctx)
	if err != nil || !known {
		return ctrl.Result{}, err
	}
	switch {
	case req.Namespace != "":
		return ctrl.Result{}, r.render(ctx, req.NamespacedName)
	case req.Name == sweepName:
		return ctrl.Result{}, r.sweep(ctx)
	}
	return ctrl.Result{}, r.imageChanged(ctx, req.Name)
}

// sweep has every report looked at: that of each workload that runs, and each that exists, since a report whose
// workload is gone is deleted.
func (r *Reports) sweep(ctx context.Context) error {
	for _, name := range r.presence.RunningReports() {
		r.add(reconcile.Request{NamespacedName: name})
	}
	existing, err := r.existing(ctx)
	if err != nil {
		return err
	}
	for _, obj := range existing {
		r.add(reconcile.Request{NamespacedName: client.ObjectKeyFromObject(&obj)})
	}
	return nil
}

// imageChanged has the reports looked at that the image of an ImageInventory can change: those of the workloads that run
// it, and those that hold its digest, whose workloads may have left it.
func (r *Reports) imageChanged(ctx context.Context, name string) error {
	digest, ok := inventory.DigestForName(name)
	if !ok {
		return nil
	}
	for _, w := range r.presence.Workloads(digest) {
		r.add(reconcile.Request{NamespacedName: types.NamespacedName{Namespace: w.Namespace, Name: ReportName(w)}})
	}
	existing, err := r.existing(ctx, client.HasLabels{digestLabelOf(digest)})
	if err != nil {
		return err
	}
	for _, obj := range existing {
		r.add(reconcile.Request{NamespacedName: client.ObjectKeyFromObject(&obj)})
	}
	return nil
}

// existing lists the metadata of the reports that exist, from the cache that the controller watches them through.
func (r *Reports) existing(ctx context.Context, options ...client.ListOption) ([]metav1.PartialObjectMetadata, error) {
	var list metav1.PartialObjectMetadataList
	list.SetGroupVersionKind(triagev1alpha1.GroupVersion.WithKind("WorkloadReportList"))
	if err := r.cache.List(ctx, &list, options...); err != nil {
		return nil, fmt.Errorf("list the WorkloadReports: %w", err)
	}
	return list.Items, nil
}

// digestLabelOf is the label key of a digest on a report.
func digestLabelOf(digest string) string {
	return digestLabel + strings.TrimPrefix(digest, "sha256:")[:63]
}

// render writes the report of the namespace and name to what Render makes of its workload, or deletes it when no
// workload that runs has it.
func (r *Reports) render(ctx context.Context, key types.NamespacedName) error {
	current, err := r.current(ctx, key)
	if err != nil {
		return err
	}
	running, runs := r.presence.Running(key.Namespace, key.Name)
	if !runs {
		r.series.delete(key)
		return r.delete(ctx, current)
	}
	cfg, err := settings.Load(ctx, r.client)
	if err != nil {
		return err
	}
	exposureKnown, err := r.presence.exposureKnown(ctx)
	if err != nil {
		return err
	}
	exposure := configv1alpha1.SSVCExposureUnknown
	if exposureKnown {
		exposure = r.presence.exposure.Of(running.Workload)
	} else if current != nil && current.Status.Exposure != nil {
		exposure = configv1alpha1.SSVCExposure(*current.Status.Exposure)
	}
	facts := map[string]*inventoryv1alpha1.ImageFacts{}
	for _, image := range running.Images {
		obj, err := r.store.Get(ctx, image.Digest)
		if err != nil {
			return err
		}
		if obj != nil {
			facts[image.Digest] = obj.Status.Facts
		}
	}
	sheets := map[string]*inventoryv1alpha1.ImageVerdicts{}
	for _, manifest := range manifestsOf(running.Images, facts) {
		sheet, err := r.verdicts.Get(ctx, manifest)
		if err != nil {
			return err
		}
		if sheet != nil {
			sheets[manifest] = sheet
		}
	}
	status := Render(running.Workload, running.Images, sheets, facts, exposure, cfg)
	series := seriesOf(cfg.ClusterName, running.Workload.Name, status, findingDigests(running.Images, sheets, facts))
	return r.write(ctx, current, key, running.Workload, running.Images, status, series)
}

// current reads the report from the API server, or returns nil when there is none.
func (r *Reports) current(ctx context.Context, key types.NamespacedName) (*triagev1alpha1.WorkloadReport, error) {
	var report triagev1alpha1.WorkloadReport
	if err := r.api.Get(ctx, key, &report); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read WorkloadReport %s: %w", key, err)
	}
	return &report, nil
}

// delete removes a report that no workload has, and the one that is already gone. It checks the UID, so that a report that
// a new workload made in the meantime stays.
func (r *Reports) delete(ctx context.Context, report *triagev1alpha1.WorkloadReport) error {
	if report == nil {
		return nil
	}
	r.series.delete(client.ObjectKeyFromObject(report))
	err := r.client.Delete(ctx, report, client.Preconditions{UID: &report.UID})
	if err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("delete WorkloadReport %s/%s: %w", report.Namespace, report.Name, err)
	}
	return nil
}

// write makes the report what the workload and the status say, and writes only what differs: the report itself when it
// is new or has another workload, its labels and owner reference, then its status.
func (r *Reports) write(ctx context.Context, current *triagev1alpha1.WorkloadReport, key types.NamespacedName,
	w evidence.PresenceWorkload, images []RunningImage, status triagev1alpha1.WorkloadReportStatus,
	series reportSeries) error {
	spec := triagev1alpha1.WorkloadReportSpec{Workload: triagev1alpha1.WorkloadReference{Kind: w.Kind, Name: w.Name}}
	if w.APIGroup != "" {
		spec.Workload.APIGroup = ptr.To(w.APIGroup)
	}
	if current != nil && !equality.Semantic.DeepEqual(current.Spec, spec) {
		// The spec never changes: a report of another workload with the same name is replaced.
		if err := r.delete(ctx, current); err != nil {
			return err
		}
		current = nil
	}
	owner, err := r.ownerOf(w)
	if err != nil {
		return err
	}
	labels := map[string]string{}
	for _, digest := range digestsOf(images) {
		labels[digestLabelOf(digest)] = ""
	}
	if current == nil {
		current = &triagev1alpha1.WorkloadReport{
			ObjectMeta: metav1.ObjectMeta{Namespace: key.Namespace, Name: key.Name, Labels: labels, OwnerReferences: owner},
			Spec:       spec,
		}
		if err := r.client.Create(ctx, current); err != nil {
			if apierrors.IsNotFound(err) {
				return nil // the namespace is gone, and with it the workload
			}
			return fmt.Errorf("create WorkloadReport %s: %w", key, err)
		}
	} else if patch, changed := metadataPatch(current, labels, owner); changed {
		if err := r.client.Patch(ctx, current, patch); err != nil {
			return fmt.Errorf("patch WorkloadReport %s: %w", key, err)
		}
	}
	if !equality.Semantic.DeepEqual(current.Status, status) {
		current.Status = status
		if err := r.client.Status().Update(ctx, current); err != nil {
			return fmt.Errorf("write status of WorkloadReport %s: %w", key, err)
		}
	}
	// The series follow every report that the renderer looks at, written or found as it should be.
	r.series.set(key, series)
	return nil
}

// metadataPatch sets the report's digest labels to labels, and its owner reference to owner, and leaves every other label
// and owner reference as it is. It reports whether anything changes.
func metadataPatch(report *triagev1alpha1.WorkloadReport, labels map[string]string,
	owner []metav1.OwnerReference) (client.Patch, bool) {
	before := report.DeepCopy()
	merged := map[string]string{}
	for k, v := range report.Labels {
		if !strings.HasPrefix(k, digestLabel) {
			merged[k] = v
		}
	}
	maps.Copy(merged, labels)
	if len(merged) == 0 {
		merged = nil
	}
	report.Labels = merged
	for _, o := range owner {
		if !hasOwner(report.OwnerReferences, o) {
			report.OwnerReferences = append(report.OwnerReferences, o)
		}
	}
	return client.MergeFrom(before), !equality.Semantic.DeepEqual(before.ObjectMeta, report.ObjectMeta)
}

// hasOwner reports whether the references hold the owner's UID.
func hasOwner(refs []metav1.OwnerReference, owner metav1.OwnerReference) bool {
	for _, ref := range refs {
		if ref.UID == owner.UID {
			return true
		}
	}
	return false
}

// ownerOf returns the owner reference to the workload, by its UID and with the API version that its kind has in the
// cluster, or none when the workload has no UID, or its kind is unknown to the cluster. A reference to a kind that the
// cluster doesn't know would never resolve, so it can't help Kubernetes delete the report.
func (r *Reports) ownerOf(w evidence.PresenceWorkload) ([]metav1.OwnerReference, error) {
	if w.UID == "" {
		return nil, nil
	}
	mapping, err := r.mapper.RESTMapping(schema.GroupKind{Group: w.APIGroup, Kind: w.Kind})
	if err != nil {
		if meta.IsNoMatchError(err) {
			r.log.Info("The cluster doesn't know the kind of a workload, so its report has no owner reference", "kind", w.Kind)
			return nil, nil
		}
		return nil, fmt.Errorf("find the version of kind %s: %w", w.Kind, err)
	}
	return []metav1.OwnerReference{{
		APIVersion: mapping.GroupVersionKind.GroupVersion().String(), Kind: w.Kind, Name: w.Name, UID: types.UID(w.UID),
	}}, nil
}
