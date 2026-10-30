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

// Package inventory holds the pod inventory: the spoke's Workloads collector, which turns the
// image digests that running pods report into this cluster's entries in the ImageInventory
// objects. It reads, writes and watches those objects only through inventory.Store.
package inventory

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"sync"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/workqueue"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
	inventoryv1alpha1 "github.com/bedag/vexplain/api/inventory/v1alpha1"
	"github.com/bedag/vexplain/internal/collector"
	"github.com/bedag/vexplain/internal/inventory"
	"github.com/bedag/vexplain/internal/metrics"
	"github.com/bedag/vexplain/internal/scope"
	"github.com/bedag/vexplain/internal/settings"
	"github.com/bedag/vexplain/internal/workloads"
)

// The two kinds of controller that workloads.ResolveOwner looks through. When one of them appears
// or changes its own controller, the top-level workload of its pods changes.
var (
	replicaSetKind = appsv1.SchemeGroupVersion.WithKind("ReplicaSet").GroupKind()
	jobKind        = batchv1.SchemeGroupVersion.WithKind("Job").GroupKind()
)

// errInvalidScope marks a scope in the OperatorConfig that doesn't parse.
var errInvalidScope = errors.New("the scope of the OperatorConfig is invalid")

// PodInventoryReconciler reconciles the image digests that pods report, one digest at a time.
// A request is named after the ImageInventory of its digest, inventory.NameForDigest(digest). The
// reconciler writes this cluster's entry in that object, through Store, and nothing else.
type PodInventoryReconciler struct {
	// Client reads pods, namespaces, ReplicaSets, Jobs and the OperatorConfig. The manager's
	// client reads them from its cache. It never touches the ImageInventory objects: only Store
	// does.
	Client client.Client
	// APIReader reads the cluster ID, once, from the API server. A direct read doesn't depend on
	// what the cache holds.
	APIReader client.Reader
	// Store is the only door to the ImageInventory objects: the reconciler writes, lists and
	// watches them through it.
	Store inventory.Store
	// Registry is where the reconciler reports the health of the Workloads collector.
	Registry *collector.Registry
	// OperatorNamespace is the namespace the operator runs in, the only one in which a pod that
	// carries workloads.TaskLabel is a task pod. It must be the namespace that the pod index was
	// built for, with workloads.PodDigestIndexer.
	OperatorNamespace string

	// clusterID is this cluster's ID once it has been read, guarded by mu.
	mu        sync.Mutex
	clusterID string
}

// The pod inventory only reads the workloads it analyses: pods and their namespaces, and the
// ReplicaSets and Jobs that ResolveOwner looks through. It caches the ReplicaSets and the Jobs as
// metadata, and a metadata informer lists and watches like any other. The namespaces include
// kube-system, whose UID is the cluster ID.
// +kubebuilder:rbac:groups="",resources=pods;namespaces,verbs=get;list;watch
// +kubebuilder:rbac:groups=apps,resources=replicasets,verbs=get;list;watch
// +kubebuilder:rbac:groups=batch,resources=jobs,verbs=get;list;watch

// It reads the cluster name and the scope from the OperatorConfig. The store, through which it
// reaches the ImageInventory objects, carries the markers for those.
// +kubebuilder:rbac:groups=config.vexplain.bedag.ch,resources=operatorconfigs,verbs=get;list;watch

// Reconcile sets this cluster's entry for the digest of the request from the pods in scope that
// run it, or removes the entry when there are none, and reports the outcome to the registry as
// the health of the Workloads collector. A name that isn't the name of a digest is ignored.
func (r *PodInventoryReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	digest, ok := inventory.DigestForName(req.Name)
	if !ok {
		return ctrl.Result{}, nil
	}
	if err := r.reconcileDigest(ctx, digest); err != nil {
		r.Registry.ReportFailure(configv1alpha1.CollectorTypeWorkloads, err)
		if errors.Is(err, errInvalidScope) {
			// A retry would fail the same way. Only a change of the OperatorConfig fixes the scope,
			// and that change enqueues every digest again.
			return ctrl.Result{}, reconcile.TerminalError(err)
		}
		return ctrl.Result{}, err
	}
	r.Registry.ReportSuccess(configv1alpha1.CollectorTypeWorkloads)
	return ctrl.Result{}, nil
}

// reconcileDigest writes or removes this cluster's entry for digest.
func (r *PodInventoryReconciler) reconcileDigest(ctx context.Context, digest string) error {
	effective, err := settings.Load(ctx, r.Client)
	if err != nil {
		return err
	}
	clusterID, err := r.thisClusterID(ctx)
	if err != nil {
		return err
	}
	matcher, err := scope.New(effective.Scope)
	if err != nil {
		return fmt.Errorf("%w: %w", errInvalidScope, err)
	}

	observation, err := r.observe(ctx, digest, matcher)
	if err != nil {
		return err
	}
	if observation == nil {
		// Forget also removes an entry under a former name of this cluster, by its ID.
		return r.Store.Forget(ctx, digest, effective.ClusterName, clusterID)
	}
	observation.Cluster, observation.ClusterID = effective.ClusterName, clusterID
	return r.Store.Observe(ctx, digest, *observation)
}

// observe returns where digest runs in this cluster, from the pods in scope that report it, with
// neither the cluster's name nor its ID. It returns nil when no pod in scope runs digest.
func (r *PodInventoryReconciler) observe(ctx context.Context, digest string,
	matcher *scope.Matcher) (*inventory.Observation, error) {
	var pods corev1.PodList
	// Every pod counts, whatever its phase, so that the image of a finished Job doesn't come and
	// go. The pods are only read, so the cache needn't copy them.
	if err := r.Client.List(ctx, &pods, client.MatchingFields{workloads.PodDigestIndex: digest},
		client.UnsafeDisableDeepCopy); err != nil {
		return nil, fmt.Errorf("list the pods that run %s: %w", digest, err)
	}

	namespaceLabels := make(map[string]map[string]string)
	inScope := make(map[string]bool) // the namespaces of the pods in scope
	owners := make(map[workloads.WorkloadRef]bool)
	repositories := make(map[string]bool)
	for i := range pods.Items {
		pod := &pods.Items[i]
		labels, read := namespaceLabels[pod.Namespace]
		if !read {
			var namespace corev1.Namespace
			if err := r.Client.Get(ctx, client.ObjectKey{Name: pod.Namespace}, &namespace); err != nil {
				// Never match without the labels: a namespace that a label excludes would be analysed.
				return nil, fmt.Errorf("read namespace %q of pod %q: %w", pod.Namespace, pod.Name, err)
			}
			labels = namespace.Labels
			namespaceLabels[pod.Namespace] = labels
		}
		if !matcher.Matches(labels, pod.Labels) {
			continue
		}

		owner, err := workloads.ResolveOwner(ctx, r.Client, pod)
		if err != nil {
			return nil, err
		}
		inScope[pod.Namespace] = true
		owners[owner] = true
		images, _ := workloads.PodImages(pod)
		for _, image := range images {
			// An image ID has no repository, and an empty one must not be recorded.
			if image.Digest == digest && !image.IsImageID() {
				repositories[image.Repository] = true
			}
		}
	}
	if len(inScope) == 0 {
		return nil, nil
	}

	observation := &inventory.Observation{
		DigestKind:     inventoryv1alpha1.DigestKindImageID,
		NamespaceCount: int32(len(inScope)),
		// The store sorts both lists, and keeps the first 100 workloads.
		Workloads:    slices.Collect(maps.Keys(owners)),
		Repositories: slices.Collect(maps.Keys(repositories)),
	}
	if len(observation.Repositories) > 0 {
		observation.DigestKind = inventoryv1alpha1.DigestKindRepoDigest
	}
	return observation, nil
}

// thisClusterID returns the ID of this cluster. It reads the ID once, and keeps it: it is the UID
// of kube-system, which doesn't change while the cluster lives. A failed read is tried again on the
// next call.
func (r *PodInventoryReconciler) thisClusterID(ctx context.Context) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.clusterID == "" {
		id, err := settings.ClusterID(ctx, r.APIReader)
		if err != nil {
			return "", err
		}
		r.clusterID = id
	}
	return r.clusterID, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *PodInventoryReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		Named("podinventory").
		// An ImageInventory is reconciled under its own name, for every event of it and with no
		// filter, as For would do. That covers an object deleted or changed by hand: the pods put it
		// back as they say. It covers the objects that exist when the operator starts, which the
		// first list delivers as created. And it covers the reconciler's own writes: a write costs
		// one more reconcile, whose Observe finds nothing to change and writes nothing, so it never
		// loops. The objects are watched through the store, the only door to them.
		WatchesRawSource(r.Store.Source()).
		Watches(&corev1.Pod{}, &podEventHandler{
			EventHandler:      handler.EnqueueRequestsFromMapFunc(r.digestsOfPod),
			reader:            r.Client,
			operatorNamespace: r.OperatorNamespace,
		}).
		// The scope reads the labels of a namespace, and nothing else of it.
		Watches(&corev1.Namespace{}, handler.EnqueueRequestsFromMapFunc(r.digestsInNamespace),
			builder.WithPredicates(predicate.LabelChangedPredicate{})).
		// The cluster name and the scope live in the spec. The OperatorConfig controller's status
		// writes don't change the generation.
		Watches(&configv1alpha1.OperatorConfig{}, handler.EnqueueRequestsFromMapFunc(r.everyDigest),
			builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		// A pod can reach the cache before its ReplicaSet or Job, and then resolves to that
		// controller. These watches put it right when the controller arrives. ResolveOwner reads
		// them as metadata, so they are cached as metadata.
		Watches(&appsv1.ReplicaSet{}, handler.EnqueueRequestsFromMapFunc(r.digestsOfPodsControlledBy(replicaSetKind)),
			builder.OnlyMetadata, builder.WithPredicates(controllerChanged)).
		Watches(&batchv1.Job{}, handler.EnqueueRequestsFromMapFunc(r.digestsOfPodsControlledBy(jobKind)),
			builder.OnlyMetadata, builder.WithPredicates(controllerChanged)).
		Complete(r)
}

// controllerChanged lets through the events of a ReplicaSet or a Job that can change the top-level
// workload of its pods: its creation, its deletion, and an update of its controller reference.
// ResolveOwner reads nothing else of it, and a ReplicaSet's status changes with every pod it runs.
var controllerChanged = predicate.Funcs{
	UpdateFunc: func(e event.UpdateEvent) bool {
		return !equality.Semantic.DeepEqual(
			metav1.GetControllerOfNoCopy(e.ObjectOld), metav1.GetControllerOfNoCopy(e.ObjectNew))
	},
}

// podEventHandler enqueues the digests of a pod, through the map function it embeds, which maps
// both the old and the new pod of an update. It also counts and logs the containers that it skips
// because their imageID is not a digest. A task pod of the operator is neither enqueued nor counted.
type podEventHandler struct {
	handler.EventHandler
	// reader reads the cluster name, the label of the counter.
	reader client.Reader
	// operatorNamespace is the namespace in which a pod that carries workloads.TaskLabel is a task
	// pod.
	operatorNamespace string
}

func (h *podEventHandler) Create(ctx context.Context, e event.CreateEvent,
	q workqueue.TypedRateLimitingInterface[reconcile.Request]) {
	h.countUnparsable(ctx, nil, e.Object)
	h.EventHandler.Create(ctx, e, q)
}

func (h *podEventHandler) Update(ctx context.Context, e event.UpdateEvent,
	q workqueue.TypedRateLimitingInterface[reconcile.Request]) {
	h.countUnparsable(ctx, e.ObjectOld, e.ObjectNew)
	h.EventHandler.Update(ctx, e, q)
}

// countUnparsable counts and logs the containers of pod whose imageID is set but isn't a digest,
// unless they were so in old already: old is the pod before an update, or nil for a new pod. A pod
// changes often, and the counter counts the containers it skips, not the changes of their pods.
//
// A task pod is skipped: the inventory never counts one, so it isn't a container that the
// inventory skips. A pod that carries the task label outside the operator's namespace is counted.
func (h *podEventHandler) countUnparsable(ctx context.Context, old, pod client.Object) {
	current, ok := pod.(*corev1.Pod)
	if !ok || workloads.IsTaskPod(current, h.operatorNamespace) {
		return
	}
	_, unparsable := workloads.PodImages(current)
	if previous, ok := old.(*corev1.Pod); ok {
		_, before := workloads.PodImages(previous)
		unparsable = slices.DeleteFunc(unparsable, func(name string) bool { return slices.Contains(before, name) })
	}
	if len(unparsable) == 0 {
		return
	}

	log := logf.FromContext(ctx)
	for _, container := range unparsable {
		log.Info("Skipped a container whose imageID is not a digest",
			"namespace", current.Namespace, "pod", current.Name, "container", container)
	}
	effective, err := settings.Load(ctx, h.reader)
	if err != nil {
		log.Error(err, "Could not count the skipped containers: the cluster name, the label of the counter, can't be read")
		return
	}
	metrics.UnparsableImageIDsTotal.WithLabelValues(effective.ClusterName).Add(float64(len(unparsable)))
}

// digestsOfPod maps a pod to the digests that it reports.
func (r *PodInventoryReconciler) digestsOfPod(_ context.Context, obj client.Object) []reconcile.Request {
	pod, ok := obj.(*corev1.Pod)
	if !ok {
		return nil
	}
	return r.requestsFor([]*corev1.Pod{pod})
}

// digestsInNamespace maps a namespace to the digests of all its pods. A change of its labels can
// move them into the scope or out of it.
func (r *PodInventoryReconciler) digestsInNamespace(ctx context.Context, namespace client.Object) []reconcile.Request {
	var pods corev1.PodList
	if err := r.Client.List(ctx, &pods, client.InNamespace(namespace.GetName()), client.UnsafeDisableDeepCopy); err != nil {
		logf.FromContext(ctx).Error(err, "Could not list the pods of a namespace whose labels changed",
			"namespace", namespace.GetName())
		return nil
	}
	return r.requestsFor(itemsOf(&pods))
}

// everyDigest maps the OperatorConfig to every digest: those that pods report, and those that have
// an object. A new cluster name or scope can change the entry of each of them, and an object whose
// pods are gone may still hold an entry of this cluster.
func (r *PodInventoryReconciler) everyDigest(ctx context.Context, _ client.Object) []reconcile.Request {
	log := logf.FromContext(ctx)
	var pods corev1.PodList
	if err := r.Client.List(ctx, &pods, client.UnsafeDisableDeepCopy); err != nil {
		log.Error(err, "Could not list the pods to apply a change of the OperatorConfig")
	}
	requests := r.requestsFor(itemsOf(&pods))

	digests, err := r.Store.Digests(ctx)
	if err != nil {
		log.Error(err, "Could not list the digests of the inventory to apply a change of the OperatorConfig")
	}
	for _, digest := range digests {
		requests = append(requests, requestFor(digest))
	}
	return requests
}

// digestsOfPodsControlledBy returns a map function for a ReplicaSet or a Job, of the kind
// controllerKind. It maps the object to the digests of the pods it controls. A pod is matched by
// the kind and the name in its controller reference, not by UID, the way ResolveOwner reads it.
func (r *PodInventoryReconciler) digestsOfPodsControlledBy(controllerKind schema.GroupKind) handler.MapFunc {
	return func(ctx context.Context, controller client.Object) []reconcile.Request {
		var pods corev1.PodList
		if err := r.Client.List(ctx, &pods, client.InNamespace(controller.GetNamespace()),
			client.UnsafeDisableDeepCopy); err != nil {
			logf.FromContext(ctx).Error(err, "Could not list the pods of a controller that changed",
				"kind", controllerKind.Kind, "namespace", controller.GetNamespace(), "name", controller.GetName())
			return nil
		}
		controlled := slices.DeleteFunc(itemsOf(&pods), func(pod *corev1.Pod) bool {
			ref := metav1.GetControllerOfNoCopy(pod)
			return ref == nil || ref.Name != controller.GetName() ||
				schema.FromAPIVersionAndKind(ref.APIVersion, ref.Kind).GroupKind() != controllerKind
		})
		return r.requestsFor(controlled)
	}
}

// itemsOf returns the pods of a list, without copying them.
func itemsOf(list *corev1.PodList) []*corev1.Pod {
	pods := make([]*corev1.Pod, 0, len(list.Items))
	for i := range list.Items {
		pods = append(pods, &list.Items[i])
	}
	return pods
}

// requestsFor returns a request for each digest that the pods report: the keys of the pod index,
// which has none for a task pod. The handler that enqueues them drops the duplicates.
func (r *PodInventoryReconciler) requestsFor(pods []*corev1.Pod) []reconcile.Request {
	index := workloads.PodDigestIndexer(r.OperatorNamespace)
	var requests []reconcile.Request
	for _, pod := range pods {
		for _, digest := range index(pod) {
			requests = append(requests, requestFor(digest))
		}
	}
	return requests
}

// requestFor returns the request of a digest, named after its ImageInventory.
func requestFor(digest string) reconcile.Request {
	return reconcile.Request{NamespacedName: types.NamespacedName{Name: inventory.NameForDigest(digest)}}
}
