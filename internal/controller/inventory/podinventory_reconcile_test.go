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
	"errors"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
	inventoryv1alpha1 "github.com/bedag/vexplain/api/inventory/v1alpha1"
	"github.com/bedag/vexplain/internal/collector"
	inventorycontroller "github.com/bedag/vexplain/internal/controller/inventory"
	"github.com/bedag/vexplain/internal/inventory"
	"github.com/bedag/vexplain/internal/settings"
	"github.com/bedag/vexplain/internal/workloads"
)

// These specs call Reconcile directly, against a fake client, for the paths that envtest cannot
// reach on demand: a request that names no digest, which the CRD's name rule keeps out of the API
// server, a namespace that can't be read, and a scope that doesn't parse, checked as
// controller-runtime sees the error.
var _ = Describe("PodInventoryReconciler.Reconcile", func() {
	const podNamespace = "team-a"

	var (
		digest   = "sha256:" + strings.Repeat("e", 64)
		request  = ctrl.Request{NamespacedName: types.NamespacedName{Name: inventory.NameForDigest(digest)}}
		registry *collector.Registry
	)

	BeforeEach(func() {
		registry = collector.NewRegistry()
	})

	// reconcilerFor returns a reconciler over a fake client that holds kube-system, a pod in the
	// namespace team-a that runs digest, and objs. It returns the client too.
	reconcilerFor := func(objs ...client.Object) (*inventorycontroller.PodInventoryReconciler, client.Client) {
		pod := newPod(podNamespace, "p", repository+":1.0", nil)
		pod.Status = running(repoDigest(digest))
		kubeSystem := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: metav1.NamespaceSystem, UID: "uid-kube-system"}}
		fakeClient := fake.NewClientBuilder().
			WithScheme(k8sClient.Scheme()).
			WithObjects(append(objs, pod, kubeSystem)...).
			WithIndex(&corev1.Pod{}, workloads.PodDigestIndex, workloads.IndexPodDigests).
			WithStatusSubresource(&inventoryv1alpha1.ImageInventory{}).
			Build()
		return &inventorycontroller.PodInventoryReconciler{
			Client:    fakeClient,
			APIReader: fakeClient,
			// Reconcile is called directly, so nothing starts the store's Source: no cache.
			Store:    inventory.NewCRDStore(fakeClient, nil),
			Registry: registry,
		}, fakeClient
	}

	// objects lists the ImageInventory objects that c holds.
	objects := func(c client.Client) []inventoryv1alpha1.ImageInventory {
		GinkgoHelper()
		var list inventoryv1alpha1.ImageInventoryList
		Expect(c.List(ctx, &list)).To(Succeed())
		return list.Items
	}

	It("ignores a name that is not the name of a digest, and reports nothing", func() {
		reconciler, c := reconcilerFor(&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: podNamespace}})

		result, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Name: "web"}})

		Expect(err).NotTo(HaveOccurred())
		Expect(result).To(Equal(ctrl.Result{}))
		_, _, known := registry.Health(configv1alpha1.CollectorTypeWorkloads)
		Expect(known).To(BeFalse(), "only the reconcile of a digest is a run of the collector")
		Expect(objects(c)).To(BeEmpty())
	})

	It("fails, records nothing, and is retried when it can't read the namespace of a pod", func() {
		reconciler, c := reconcilerFor() // The fake client has no namespace team-a.

		_, err := reconciler.Reconcile(ctx, request)

		Expect(err).To(MatchError(ContainSubstring(`read namespace "` + podNamespace + `"`)))
		Expect(errors.Is(err, reconcile.TerminalError(nil))).To(BeFalse(), "the request is retried")
		_, lastErr, _ := registry.Health(configv1alpha1.CollectorTypeWorkloads)
		Expect(lastErr).To(MatchError(err))
		Expect(objects(c)).To(BeEmpty(), "a pod is never matched without the labels of its namespace")
	})

	It("is not retried for a scope that doesn't parse, and reports the cause", func() {
		reconciler, c := reconcilerFor(
			&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: podNamespace}},
			&configv1alpha1.OperatorConfig{
				ObjectMeta: metav1.ObjectMeta{Name: settings.ConfigName},
				Spec:       configv1alpha1.OperatorConfigSpec{Scope: unparsableScope()},
			},
		)

		_, err := reconciler.Reconcile(ctx, request)

		Expect(errors.Is(err, reconcile.TerminalError(nil))).To(BeTrue(),
			"only a change of the OperatorConfig fixes it, and that change enqueues every digest again")
		_, lastErr, _ := registry.Health(configv1alpha1.CollectorTypeWorkloads)
		Expect(lastErr).To(MatchError(HavePrefix("the scope of the OperatorConfig is invalid: includeNamespaces: ")),
			"the Collector shows the cause, without the mark that tells controller-runtime not to retry")
		Expect(objects(c)).To(BeEmpty())
	})
})
