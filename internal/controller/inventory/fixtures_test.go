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
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
	inventoryv1alpha1 "github.com/bedag/vexplain/api/inventory/v1alpha1"
	"github.com/bedag/vexplain/internal/inventory"
	"github.com/bedag/vexplain/internal/settings"
	"github.com/bedag/vexplain/sdk/workloads"
)

// The fixtures of the specs of this suite: the objects they write, as the spoke and the scanning spoke
// would, and the readers of what the API server and the manager keep of them. The specs read the
// ImageInventory objects through the API, to see what was written, and write the entries of
// presence through the store, as the spoke's presence does. No presence collector streams to the
// manager of the suite, so its presence never writes an entry itself.

const (
	// repository is where the images of the specs come from.
	repository = "artifacts.example/team-a/app"
	// scannerImage is the image of the scanner that the specs of the scan kinds say produced their
	// data.
	scannerImage = "scanner.example/vexplain-scanner:1.0"
	// unknownValue is a value that no enum of the API has, in this version or in a later one.
	unknownValue = "Guess"
	// localCluster is the cluster name when no OperatorConfig sets one, and renamedCluster the one
	// that the rename spec sets.
	localCluster   = "local"
	renamedCluster = "kind-a"
	// clusterLabel is the label of the operator's metrics that holds the cluster name.
	clusterLabel = "cluster"

	// reaction bounds how long the manager takes to follow a change, and poll is how often a spec
	// looks.
	reaction = 10 * time.Second
	poll     = 100 * time.Millisecond
)

// --- the objects of the specs ---

// digestCount numbers the digests that the specs use. The envtest API server is new for every run,
// so the numbers are unique.
var digestCount int

// newDigest returns a digest that no other spec uses. After the spec, it deletes the digest's
// ImageInventory, if the spec wrote one, so that the next spec starts without it.
func newDigest() string {
	GinkgoHelper()
	digest := newManifestDigest()
	DeferCleanup(func() {
		Expect(client.IgnoreNotFound(k8sClient.Delete(ctx, &inventoryv1alpha1.ImageInventory{
			ObjectMeta: metav1.ObjectMeta{Name: inventory.NameForDigest(digest)},
		}))).To(Succeed())
	})
	return digest
}

// newManifestDigest returns a digest that no other spec uses, for a platform manifest. No spec
// writes an ImageInventory for it. It counts with newDigest.
func newManifestDigest() string {
	digestCount++
	return fmt.Sprintf("sha256:%064x", digestCount)
}

// chars returns a string of n characters. The specs of a schema limit write a value of exactly that
// length, which the schema admits, and one that is a character longer, which it refuses.
func chars(n int) string {
	return strings.Repeat("a", n)
}

// storeOf returns a store of the cluster, which writes through the API server, without a cache.
func storeOf(cluster string) inventory.Store {
	return inventory.NewCRDStore(k8sClient, nil, func() string { return cluster })
}

// observeHere writes this cluster's entry for digest, as the spoke's presence does when a bare pod
// in team-a runs it, pulled from repository.
func observeHere(digest string) {
	GinkgoHelper()
	Expect(storeOf(localCluster).Observe(ctx, digest, inventory.Observation{
		Cluster:        localCluster,
		ClusterID:      kubeSystemUID(),
		DigestKind:     inventoryv1alpha1.DigestKindRepoDigest,
		Repositories:   []string{repository},
		NamespaceCount: 1,
		Workloads:      []workloads.WorkloadRef{{Kind: "Pod", Namespace: "team-a", Name: "p", UID: "uid-p"}},
	})).To(Succeed())
}

// configure creates the OperatorConfig with spec, and waits until the manager's cache holds it.
// After the spec, it deletes the object and waits until the cache has dropped it, so that the next
// spec runs on the defaults.
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

// stored returns the ImageInventory of digest. It reads through k8sClient, a direct client, so it
// never sees a stale cache.
func stored(g Gomega, digest string) *inventoryv1alpha1.ImageInventory {
	GinkgoHelper()
	var obj inventoryv1alpha1.ImageInventory
	g.Expect(k8sClient.Get(ctx, client.ObjectKey{Name: inventory.NameForDigest(digest)}, &obj)).To(Succeed())
	return &obj
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
			series[metric.GetLabel()[0].GetValue()] = metric.GetGauge().GetValue()
		}
	}
	return series
}
