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
	"fmt"
	"slices"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	dto "github.com/prometheus/client_model/go"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
	inventoryv1alpha1 "github.com/bedag/vexplain/api/inventory/v1alpha1"
	"github.com/bedag/vexplain/internal/inventory"
	"github.com/bedag/vexplain/internal/settings"
	"github.com/bedag/vexplain/internal/workloads"
)

// The fixtures of the specs of this suite: the objects they create, as a kubelet or a workload
// controller would, and the readers of what the pod inventory makes of them. The specs read the
// ImageInventory objects through the API, to see what the store has written, and write them
// through the store, or by hand where a spec plays another writer.

const (
	// repository is where the images of the specs come from.
	repository = "artifacts.example/team-a/app"
	// scannerImage is the image of the scanner that the specs of the scan kinds say produced their
	// data.
	scannerImage = "scanner.example/vexplain-scanner:1.0"
	// unknownValue is a value that no enum of the API has, in this version or in a later one.
	unknownValue = "Guess"
	// containerName is the name of the one container of every pod.
	containerName = "app"
	// localCluster is the cluster name when no OperatorConfig sets one, and renamedCluster the one
	// that the rename spec sets.
	localCluster   = "local"
	renamedCluster = "kind-a"
	// clusterLabel is the label of the operator's metrics that holds the cluster name.
	clusterLabel = "cluster"

	// reaction bounds how long the pod inventory takes to follow a change: a pod, a namespace label,
	// the OperatorConfig or an object deleted by hand. startup bounds the first reaction of a spec,
	// which may also wait for the manager to start.
	reaction = 10 * time.Second
	startup  = 30 * time.Second
	poll     = 100 * time.Millisecond
	// quiet is how long a spec watches for something that must not happen.
	quiet = 2 * time.Second
)

// The kinds of the workloads in the specs.
var (
	podKind        = corev1.SchemeGroupVersion.WithKind("Pod")
	replicaSetKind = appsv1.SchemeGroupVersion.WithKind("ReplicaSet")
	deploymentKind = appsv1.SchemeGroupVersion.WithKind("Deployment")
	jobKind        = batchv1.SchemeGroupVersion.WithKind("Job")
	cronJobKind    = batchv1.SchemeGroupVersion.WithKind("CronJob")
)

// --- the objects of the specs ---

// namespaceCount and digestCount number the namespaces and the digests that the specs create. The
// envtest API server is new for every run, so the numbers are unique.
var namespaceCount, digestCount int

// newNamespace creates a namespace and returns its name once the manager's cache holds it, so that
// the pod inventory reads its labels at the first reconcile of a pod in it. Names sort in the order
// of creation. envtest runs no namespace controller, so a deleted namespace would stay in
// Terminating: every spec creates its own and leaves it.
func newNamespace() string {
	GinkgoHelper()
	namespaceCount++
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf("inventory-%03d", namespaceCount)}}
	Expect(k8sClient.Create(ctx, ns)).To(Succeed())
	Eventually(func() error {
		return k8sManager.GetClient().Get(ctx, client.ObjectKeyFromObject(ns), &corev1.Namespace{})
	}, startup, poll).Should(Succeed())
	return ns.Name
}

// newDigest returns a digest that no other spec uses. After the spec, it waits until the digest has
// no ImageInventory, so that the next spec starts without it.
func newDigest() string {
	GinkgoHelper()
	digest := newManifestDigest()
	DeferCleanup(func() {
		Eventually(lookup(digest), reaction, poll).Should(Satisfy(apierrors.IsNotFound))
	})
	return digest
}

// newManifestDigest returns a digest that no other spec uses, for a platform manifest. No spec
// creates an ImageInventory for it, so there is nothing to wait for. It counts with newDigest.
func newManifestDigest() string {
	digestCount++
	return fmt.Sprintf("sha256:%064x", digestCount)
}

// chars returns a string of n characters. The specs of a schema limit write a value of exactly that
// length, which the schema admits, and one that is a character longer, which it refuses.
func chars(n int) string {
	return strings.Repeat("a", n)
}

// repoDigest is the imageID that a container runtime reports for an image pulled from repository.
func repoDigest(digest string) string {
	return repository + "@" + digest
}

// containerStatus is the status of a container named name whose runtime reports imageID.
func containerStatus(name, imageID string) corev1.ContainerStatus {
	return corev1.ContainerStatus{Name: name, Image: repository + ":1.0", ImageID: imageID}
}

// running is the status of a running pod whose container reports imageID.
func running(imageID string) corev1.PodStatus {
	return corev1.PodStatus{
		Phase:             corev1.PodRunning,
		ContainerStatuses: []corev1.ContainerStatus{containerStatus(containerName, imageID)},
	}
}

// controlledBy is an owner reference that makes the object of the kind gvk named name the
// controller. The UID is made up: nothing in envtest checks it, and the pod inventory finds a
// controller by kind and name.
func controlledBy(gvk schema.GroupVersionKind, name string) *metav1.OwnerReference {
	return &metav1.OwnerReference{
		APIVersion: gvk.GroupVersion().String(),
		Kind:       gvk.Kind,
		Name:       name,
		UID:        types.UID("uid-" + name),
		Controller: ptr.To(true),
	}
}

// newPod is a pod with one container that runs image, controlled by owner unless that is nil.
func newPod(namespace, name, image string, owner *metav1.OwnerReference) *corev1.Pod {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name},
		Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: containerName, Image: image}}},
	}
	if owner != nil {
		pod.OwnerReferences = []metav1.OwnerReference{*owner}
	}
	return pod
}

// newTaskPod is a pod that carries the task label with the value scan, as the scan pods of the
// operator do, and that runs an image by tag. Whether it is a task pod depends on its namespace.
func newTaskPod(namespace, name string) *corev1.Pod {
	pod := newPod(namespace, name, repository+":1.0", nil)
	pod.Labels = map[string]string{workloads.TaskLabel: "scan"}
	return pod
}

// start creates pod and writes status as a kubelet would, and deletes the pod after the spec.
func start(pod *corev1.Pod, status corev1.PodStatus) {
	GinkgoHelper()
	Expect(k8sClient.Create(ctx, pod)).To(Succeed())
	DeferCleanup(deletePod, pod)
	pod.Status = status
	Expect(k8sClient.Status().Update(ctx, pod)).To(Succeed())
}

// createPod creates a pod that runs an image of repository by tag, with status, and returns it.
func createPod(namespace, name string, owner *metav1.OwnerReference, status corev1.PodStatus) *corev1.Pod {
	GinkgoHelper()
	pod := newPod(namespace, name, repository+":1.0", owner)
	start(pod, status)
	return pod
}

// deletePod deletes a pod at once. With a grace period, it would wait for a kubelet that envtest
// doesn't run.
func deletePod(pod *corev1.Pod) {
	GinkgoHelper()
	Expect(client.IgnoreNotFound(k8sClient.Delete(ctx, pod, client.GracePeriodSeconds(0)))).To(Succeed())
}

// replicaSet is a ReplicaSet controlled by owner unless that is nil. Nothing runs it in envtest:
// it is there for the pod inventory to read.
func replicaSet(namespace, name string, owner *metav1.OwnerReference) client.Object {
	labels := map[string]string{"app": name}
	rs := &appsv1.ReplicaSet{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name},
		Spec: appsv1.ReplicaSetSpec{
			Selector: &metav1.LabelSelector{MatchLabels: labels},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: labels},
				Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: containerName, Image: repository}}},
			},
		},
	}
	if owner != nil {
		rs.OwnerReferences = []metav1.OwnerReference{*owner}
	}
	return rs
}

// job is a Job controlled by owner unless that is nil. Nothing runs it in envtest.
func job(namespace, name string, owner *metav1.OwnerReference) client.Object {
	j := &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name},
		Spec: batchv1.JobSpec{Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{
			RestartPolicy: corev1.RestartPolicyNever,
			Containers:    []corev1.Container{{Name: containerName, Image: repository}},
		}}},
	}
	if owner != nil {
		j.OwnerReferences = []metav1.OwnerReference{*owner}
	}
	return j
}

// createObject creates obj and returns it.
func createObject(obj client.Object) client.Object {
	GinkgoHelper()
	Expect(k8sClient.Create(ctx, obj)).To(Succeed())
	return obj
}

// unparsableScope is a scope that the CRD schema accepts, because it takes any operator, and that
// only the label selector parser rejects.
func unparsableScope() *configv1alpha1.Scope {
	return &configv1alpha1.Scope{
		IncludeNamespaces: &metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{
			{Key: "team", Operator: "Bogus", Values: []string{"team-a"}},
		}},
	}
}

// configure creates the OperatorConfig with spec, and waits until the manager's cache holds it, so
// that the pod inventory reads it from then on. After the spec, it deletes the object and waits
// until the cache has dropped it, so that the next spec runs on the defaults.
func configure(spec configv1alpha1.OperatorConfigSpec) {
	GinkgoHelper()
	obj := &configv1alpha1.OperatorConfig{ObjectMeta: metav1.ObjectMeta{Name: settings.ConfigName}, Spec: spec}
	Expect(k8sClient.Create(ctx, obj)).To(Succeed())
	cached := func() error {
		return k8sManager.GetClient().Get(ctx, client.ObjectKeyFromObject(obj), &configv1alpha1.OperatorConfig{})
	}
	DeferCleanup(func() {
		Expect(client.IgnoreNotFound(k8sClient.Delete(ctx, obj))).To(Succeed())
		Eventually(cached, reaction, poll).Should(Satisfy(apierrors.IsNotFound))
	})
	Eventually(cached, reaction, poll).Should(Succeed())
}

// --- reading the results ---

// kubeSystemUID is the ID of the cluster: the UID of its kube-system namespace.
func kubeSystemUID() string {
	GinkgoHelper()
	var namespace corev1.Namespace
	Expect(k8sClient.Get(ctx, client.ObjectKey{Name: metav1.NamespaceSystem}, &namespace)).To(Succeed())
	return string(namespace.UID)
}

// workloadRef is the reference to the workload of the kind gvk named name. The core group, the
// group of a bare pod, has no apiGroup.
func workloadRef(gvk schema.GroupVersionKind, namespace, name string) inventoryv1alpha1.WorkloadReference {
	ref := inventoryv1alpha1.WorkloadReference{Kind: gvk.Kind, Namespace: namespace, Name: name}
	if gvk.Group != "" {
		ref.APIGroup = ptr.To(gvk.Group)
	}
	return ref
}

// refs lists workload references, in the order the store sorts them: by namespace, kind and name.
func refs(references ...inventoryv1alpha1.WorkloadReference) []inventoryv1alpha1.WorkloadReference {
	return references
}

// localEntry is the entry of this cluster under its default name, without the time it was first
// seen. An entry without repositories has none, not an empty one.
func localEntry(namespaces, workloadCount int32, listed []inventoryv1alpha1.WorkloadReference,
	repositories ...string) inventoryv1alpha1.ClusterPresence {
	GinkgoHelper()
	return inventoryv1alpha1.ClusterPresence{
		Cluster:        localCluster,
		ClusterID:      kubeSystemUID(),
		NamespaceCount: ptr.To(namespaces),
		WorkloadCount:  ptr.To(workloadCount),
		Workloads:      listed,
		Repositories:   repositories,
	}
}

// lookup reads the ImageInventory of digest, for a spec that waits for it to be gone.
func lookup(digest string) func() error {
	return func() error {
		key := client.ObjectKey{Name: inventory.NameForDigest(digest)}
		return k8sClient.Get(ctx, key, &inventoryv1alpha1.ImageInventory{})
	}
}

// stored returns the ImageInventory of digest. It reads through k8sClient, a direct client, so it
// never sees a stale cache.
func stored(g Gomega, digest string) *inventoryv1alpha1.ImageInventory {
	GinkgoHelper()
	var obj inventoryv1alpha1.ImageInventory
	g.Expect(k8sClient.Get(ctx, client.ObjectKey{Name: inventory.NameForDigest(digest)}, &obj)).To(Succeed())
	return &obj
}

// withoutTimes checks that every entry has the time it was first seen, which no spec can know, and
// returns the entries without it.
func withoutTimes(g Gomega, entries []inventoryv1alpha1.ClusterPresence) []inventoryv1alpha1.ClusterPresence {
	GinkgoHelper()
	entries = slices.Clone(entries)
	for i := range entries {
		g.Expect(entries[i].FirstSeenTime).NotTo(BeNil())
		entries[i].FirstSeenTime = nil
	}
	return entries
}

// expectInventory waits until the ImageInventory of digest has the kind and exactly the entries,
// and returns it.
func expectInventory(digest string, within time.Duration, kind inventoryv1alpha1.DigestKind,
	entries ...inventoryv1alpha1.ClusterPresence) *inventoryv1alpha1.ImageInventory {
	GinkgoHelper()
	var obj *inventoryv1alpha1.ImageInventory
	Eventually(func(g Gomega) {
		obj = stored(g, digest)
		g.Expect(obj.Spec.Digest).To(Equal(digest))
		g.Expect(obj.Status.DigestKind).To(HaveValue(Equal(kind)))
		g.Expect(withoutTimes(g, obj.Status.Clusters)).To(Equal(entries))
	}, within, poll).Should(Succeed())
	return obj
}

// inventoryNames lists the names of the ImageInventory objects.
func inventoryNames() []string {
	GinkgoHelper()
	var list inventoryv1alpha1.ImageInventoryList
	Expect(k8sClient.List(ctx, &list)).To(Succeed())
	names := make([]string, 0, len(list.Items))
	for _, obj := range list.Items {
		names = append(names, obj.Name)
	}
	return names
}

// gaugeOnlyFor passes when the gauge of running images has a single series, for cluster, and its
// value is the number of ImageInventory objects with an entry for this cluster's ID.
func gaugeOnlyFor(cluster string) func(g Gomega) {
	GinkgoHelper()
	id := kubeSystemUID()
	return func(g Gomega) {
		var list inventoryv1alpha1.ImageInventoryList
		g.Expect(k8sClient.List(ctx, &list)).To(Succeed())
		running := 0
		for _, obj := range list.Items {
			if slices.ContainsFunc(obj.Status.Clusters, func(entry inventoryv1alpha1.ClusterPresence) bool {
				return entry.ClusterID == id
			}) {
				running++
			}
		}
		g.Expect(served(g, "vexplain_images_running", dto.MetricType_GAUGE)).To(
			Equal(map[string]float64{cluster: float64(running)}))
	}
}

// unparsableImageIDs returns the counter of the containers that were skipped because their imageID
// is not a digest, for the default cluster name, as the manager's metrics endpoint serves it.
func unparsableImageIDs(g Gomega) float64 {
	GinkgoHelper()
	return served(g, "vexplain_unparsable_image_ids_total", dto.MetricType_COUNTER)[localCluster]
}

// served returns the series of the metric named name, of the type kind, as the manager's metrics
// endpoint serves them: the value by cluster name. It gathers them from the registry, because a
// read through WithLabelValues would create the series it looks for.
func served(g Gomega, name string, kind dto.MetricType) map[string]float64 {
	GinkgoHelper()
	families, err := ctrlmetrics.Registry.Gather()
	g.Expect(err).NotTo(HaveOccurred())
	series := make(map[string]float64)
	for _, family := range families {
		if family.GetName() != name {
			continue
		}
		g.Expect(family.GetType()).To(Equal(kind))
		for _, metric := range family.GetMetric() {
			g.Expect(metric.GetLabel()).To(HaveExactElements(HaveField("GetName()", clusterLabel)))
			value := metric.GetGauge().GetValue()
			if kind == dto.MetricType_COUNTER {
				value = metric.GetCounter().GetValue()
			}
			series[metric.GetLabel()[0].GetValue()] = value
		}
	}
	return series
}
