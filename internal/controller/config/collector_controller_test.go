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

package config_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	eventsv1 "k8s.io/api/events/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/tools/events"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/yaml"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
	"github.com/bedag/vexplain/internal/collector"
	configcontroller "github.com/bedag/vexplain/internal/controller/config"
)

const (
	// workloadsName is the name of the default Collector, and the only name the API accepts for
	// a Collector of type Workloads. scannerName is the same for the type Scanner.
	workloadsName = "workloads"
	scannerName   = "scanner"
	// unhealthyReason is the reason of the event that reports a failing collector.
	unhealthyReason = "CollectorUnhealthy"
	// unknownType is a collector type that no version of the operator knows.
	unknownType = "NoSuchCollector"
	// typeField, workloadsField and scannerField are the names of the fields of a raw spec, and
	// workloadsType and scannerType the values of its type.
	typeField      = "type"
	workloadsField = "workloads"
	scannerField   = "scanner"
	workloadsType  = "Workloads"
	scannerType    = "Scanner"
)

// workloadsSpec is the spec of the default Collector.
var workloadsSpec = configv1alpha1.CollectorSpec{
	Type:      configv1alpha1.CollectorTypeWorkloads,
	Workloads: &configv1alpha1.WorkloadsCollectorSpec{},
}

// scannerSpec is the spec of the default Scanner Collector as the API server stores it. The
// operator asks for scanner: {}, and the schema fills in the four settings.
var scannerSpec = configv1alpha1.CollectorSpec{
	Type: configv1alpha1.CollectorTypeScanner,
	Scanner: &configv1alpha1.ScannerCollectorSpec{
		MaxConcurrentScans:   ptr.To[int32](2),
		ScanTimeoutSeconds:   ptr.To[int32](1800),
		MemoryLimitMebibytes: ptr.To[int32](2048),
		WorkspaceMebibytes:   ptr.To[int32](10240),
	},
}

// These specs run against the manager that the suite starts through setup.Register, so the
// controller under test is the production one, and so is the start-up that creates the default
// Collectors. The registry is the one the controller reads, and a spec reports health into it as a
// collector would.
//
// The registry has no reset, so the specs are ordered: the defaults come first, because the
// manager creates the object at the start of the suite, and the health goes from nothing reported
// through success and failure to success again.
var _ = Describe("Collector", Ordered, func() {
	const (
		timeout  = 30 * time.Second
		interval = 100 * time.Millisecond
	)

	key := client.ObjectKey{Name: workloadsName}

	// deleteCollector removes the Collector named name, and waits until it is gone.
	deleteCollector := func(name string) {
		GinkgoHelper()
		Expect(client.IgnoreNotFound(k8sClient.Delete(ctx, &configv1alpha1.Collector{
			ObjectMeta: metav1.ObjectMeta{Name: name},
		}))).To(Succeed())
		Eventually(func() error {
			return k8sClient.Get(ctx, client.ObjectKey{Name: name}, &configv1alpha1.Collector{})
		}, timeout, interval).Should(Satisfy(apierrors.IsNotFound))
	}
	// deleteDefault removes the default Collector of the Workloads, and waits until it is gone.
	deleteDefault := func() {
		GinkgoHelper()
		deleteCollector(workloadsName)
	}

	// rawCollector builds a Collector from raw spec content. A Go struct can't say a spec without
	// a type, or a type that no version knows, as the API server should see it.
	rawCollector := func(name string, spec map[string]any) *unstructured.Unstructured {
		obj := &unstructured.Unstructured{Object: map[string]any{"spec": spec}}
		obj.SetGroupVersionKind(configv1alpha1.GroupVersion.WithKind("Collector"))
		obj.SetName(name)
		return obj
	}

	// readyCollector returns the default Collector with its Ready condition. It fails, so that an
	// Eventually retries, until the controller has set the condition for the current generation.
	readyCollector := func(g Gomega) (configv1alpha1.Collector, *metav1.Condition) {
		GinkgoHelper()
		var got configv1alpha1.Collector
		g.Expect(k8sClient.Get(ctx, key, &got)).To(Succeed())
		ready := meta.FindStatusCondition(got.Status.Conditions, configv1alpha1.ConditionReady)
		g.Expect(ready).NotTo(BeNil())
		g.Expect(ready.ObservedGeneration).To(Equal(got.Generation))
		return got, ready
	}

	// unhealthyEvents lists the CollectorUnhealthy events about the default Collector. It reads
	// through k8sClient, a direct client, so that it never sees a stale cache. The events API files
	// the events of a cluster-scoped object in the namespace default.
	unhealthyEvents := func(g Gomega) []eventsv1.Event {
		GinkgoHelper()
		var list eventsv1.EventList
		g.Expect(k8sClient.List(ctx, &list,
			client.InNamespace(metav1.NamespaceDefault),
			client.MatchingFields{"regarding.name": workloadsName, "reason": unhealthyReason},
		)).To(Succeed())
		return list.Items
	}

	Describe("the defaults", func() {
		It("are created by the manager when it starts", func() {
			// Nothing else creates the object before this spec: it is the first one, and the
			// manager's start-up runs EnsureDefaults through setup.Register.
			Eventually(func(g Gomega) {
				var got configv1alpha1.Collector
				g.Expect(k8sClient.Get(ctx, key, &got)).To(Succeed())
				g.Expect(got.Spec).To(Equal(workloadsSpec))
			}, timeout, interval).Should(Succeed())
		})

		It("include the Scanner, whose four settings the API server fills in", func() {
			// The manager's start-up asks for scanner: {}, so every value in the object is a default of
			// the schema.
			Eventually(func(g Gomega) {
				var got configv1alpha1.Collector
				g.Expect(k8sClient.Get(ctx, client.ObjectKey{Name: scannerName}, &got)).To(Succeed())
				g.Expect(got.Spec).To(Equal(scannerSpec))
			}, timeout, interval).Should(Succeed())
		})

		It("are created on an empty cluster", func() {
			deleteDefault()

			Expect(collector.EnsureDefaults(ctx, k8sClient)).To(Succeed())

			var got configv1alpha1.Collector
			Expect(k8sClient.Get(ctx, key, &got)).To(Succeed())
			Expect(got.Spec).To(Equal(workloadsSpec))
		})

		It("leave an existing workloads Collector untouched", func() {
			var existing configv1alpha1.Collector
			Expect(k8sClient.Get(ctx, key, &existing)).To(Succeed())
			patch := client.MergeFrom(existing.DeepCopy())
			existing.Labels = map[string]string{"custom": "label"}
			Expect(k8sClient.Patch(ctx, &existing, patch)).To(Succeed())

			Expect(collector.EnsureDefaults(ctx, k8sClient)).To(Succeed())

			var got configv1alpha1.Collector
			Expect(k8sClient.Get(ctx, key, &got)).To(Succeed())
			Expect(got.UID).To(Equal(existing.UID))
			Expect(got.Labels).To(HaveKeyWithValue("custom", "label"))
		})
	})

	Describe("validation by the API server", func() {
		DescribeTable("rejects",
			func(name string, spec map[string]any, message string) {
				err := k8sClient.Create(ctx, rawCollector(name, spec))

				Expect(err).To(Satisfy(apierrors.IsInvalid))
				Expect(err).To(MatchError(ContainSubstring(message)))
			},
			Entry("type Workloads without workloads: {}",
				workloadsName, map[string]any{typeField: workloadsType},
				"workloads must be set exactly when type is Workloads"),
			Entry("a Collector named foo of type Workloads",
				"foo", map[string]any{typeField: workloadsType, workloadsField: map[string]any{}},
				"a Collector is named after its type"),
			Entry("type Scanner without scanner: {}",
				scannerName, map[string]any{typeField: scannerType},
				"scanner must be set exactly when type is Scanner"),
			Entry("type Scanner with workloads: {}",
				scannerName, map[string]any{
					typeField: scannerType, scannerField: map[string]any{}, workloadsField: map[string]any{}},
				"workloads must be set exactly when type is Workloads"),
			Entry("type Workloads with scanner: {}",
				workloadsName, map[string]any{
					typeField: workloadsType, workloadsField: map[string]any{}, scannerField: map[string]any{}},
				"scanner must be set exactly when type is Scanner"),
			Entry("a type that no version knows",
				workloadsName, map[string]any{typeField: unknownType},
				`spec.type: Unsupported value: "`+unknownType+`"`),
			Entry("a spec without a type",
				workloadsName, map[string]any{},
				"spec.type: Required value"),
		)

		DescribeTable("rejects a Scanner setting outside its bounds",
			func(setting string, value int64) {
				spec := map[string]any{typeField: scannerType, scannerField: map[string]any{setting: value}}
				err := k8sClient.Create(ctx, rawCollector(scannerName, spec))

				Expect(err).To(Satisfy(apierrors.IsInvalid))
				Expect(err).To(MatchError(ContainSubstring("spec.scanner." + setting)))
			},
			Entry("maxConcurrentScans of 0", "maxConcurrentScans", int64(0)),
			Entry("maxConcurrentScans of 33", "maxConcurrentScans", int64(33)),
			Entry("scanTimeoutSeconds of 59", "scanTimeoutSeconds", int64(59)),
			Entry("scanTimeoutSeconds of 21601", "scanTimeoutSeconds", int64(21601)),
			Entry("memoryLimitMebibytes of 255", "memoryLimitMebibytes", int64(255)),
			Entry("memoryLimitMebibytes of 65537", "memoryLimitMebibytes", int64(65537)),
			Entry("workspaceMebibytes of 1023", "workspaceMebibytes", int64(1023)),
			Entry("workspaceMebibytes of 1048577", "workspaceMebibytes", int64(1048577)),
		)

		It("accepts every Scanner setting at its lowest and at its highest value", func() {
			for _, scanner := range []map[string]any{
				{"maxConcurrentScans": int64(1), "scanTimeoutSeconds": int64(60),
					"memoryLimitMebibytes": int64(256), "workspaceMebibytes": int64(1024)},
				{"maxConcurrentScans": int64(32), "scanTimeoutSeconds": int64(21600),
					"memoryLimitMebibytes": int64(65536), "workspaceMebibytes": int64(1048576)},
			} {
				deleteCollector(scannerName)

				Expect(k8sClient.Create(ctx, rawCollector(scannerName,
					map[string]any{typeField: scannerType, scannerField: scanner}))).To(Succeed())
			}
		})

		It("accepts the Scanner sample, which holds the defaults", func() {
			data, err := os.ReadFile(filepath.Join("..", "..", "..", "config", "samples",
				"config_v1alpha1_collector_scanner.yaml"))
			Expect(err).NotTo(HaveOccurred())
			sample := &configv1alpha1.Collector{}
			Expect(yaml.UnmarshalStrict(data, sample)).To(Succeed())
			deleteCollector(scannerName)

			Expect(k8sClient.Create(ctx, sample)).To(Succeed())

			Expect(sample.Name).To(Equal(scannerName))
			Expect(sample.Spec).To(Equal(scannerSpec))
		})

		It("accepts the sample, which is the default Collector", func() {
			data, err := os.ReadFile(filepath.Join("..", "..", "..", "config", "samples",
				"config_v1alpha1_collector.yaml"))
			Expect(err).NotTo(HaveOccurred())
			sample := &configv1alpha1.Collector{}
			Expect(yaml.UnmarshalStrict(data, sample)).To(Succeed())
			deleteDefault()

			Expect(k8sClient.Create(ctx, sample)).To(Succeed())

			Expect(sample.Name).To(Equal(workloadsName))
			Expect(sample.Spec).To(Equal(workloadsSpec))
		})
	})

	Describe("health", func() {
		var succeededAt *metav1.Time

		It("is Unknown with reason NoData until the collector reports", func() {
			Eventually(func(g Gomega) {
				got, ready := readyCollector(g)
				g.Expect(ready.Status).To(Equal(metav1.ConditionUnknown))
				g.Expect(ready.Reason).To(Equal("NoData"))
				g.Expect(got.Status.LastSuccessTime).To(BeNil())
			}, timeout, interval).Should(Succeed())
		})

		It("is True with reason Healthy, and has a last success time, after a success", func() {
			// The API keeps whole seconds.
			before := time.Now().Truncate(time.Second)
			collectorRegistry.ReportSuccess(configv1alpha1.CollectorTypeWorkloads)

			Eventually(func(g Gomega) {
				got, ready := readyCollector(g)
				g.Expect(ready.Status).To(Equal(metav1.ConditionTrue))
				g.Expect(ready.Reason).To(Equal("Healthy"))
				g.Expect(got.Status.LastSuccessTime).NotTo(BeNil())
				g.Expect(got.Status.LastSuccessTime.Time).To(BeTemporally(">=", before))
				g.Expect(got.Status.LastSuccessTime.Time).To(BeTemporally("<=", time.Now()))
				succeededAt = got.Status.LastSuccessTime
			}, timeout, interval).Should(Succeed())
		})

		It("is False with reason CollectorFailing, and records one event, after a failure", func() {
			failure := errors.New("pods cannot be listed")
			collectorRegistry.ReportFailure(configv1alpha1.CollectorTypeWorkloads, failure)

			By("setting the condition, with the error as its message, and keeping the last success")
			Eventually(func(g Gomega) {
				got, ready := readyCollector(g)
				g.Expect(ready.Status).To(Equal(metav1.ConditionFalse))
				g.Expect(ready.Reason).To(Equal("CollectorFailing"))
				g.Expect(ready.Message).To(Equal(failure.Error()))
				g.Expect(got.Status.LastSuccessTime).NotTo(BeNil())
				g.Expect(got.Status.LastSuccessTime.Time).To(BeTemporally("==", succeededAt.Time))
			}, timeout, interval).Should(Succeed())

			By("recording a Warning event in the namespace default")
			Eventually(unhealthyEvents, timeout, interval).Should(HaveLen(1))
			event := unhealthyEvents(Default)[0]
			Expect(event.Namespace).To(Equal(metav1.NamespaceDefault))
			Expect(event.Type).To(Equal(corev1.EventTypeWarning))
			Expect(event.Regarding).To(And(
				HaveField("Kind", "Collector"),
				HaveField("Name", workloadsName),
			))
			Expect(event.Note).To(Equal(failure.Error()))

			By("recording no further event, however often the controller resyncs")
			// The resync is one second, so these seconds hold several.
			Consistently(unhealthyEvents, 5*time.Second, 500*time.Millisecond).Should(HaveLen(1))
			Expect(unhealthyEvents(Default)[0].Series).To(BeNil(), "the event was recorded once")
		})

		It("is True again, with a later success time, when the collector succeeds again", func() {
			collectorRegistry.ReportSuccess(configv1alpha1.CollectorTypeWorkloads)

			Eventually(func(g Gomega) {
				got, ready := readyCollector(g)
				g.Expect(ready.Status).To(Equal(metav1.ConditionTrue))
				g.Expect(ready.Reason).To(Equal("Healthy"))
				g.Expect(got.Status.LastSuccessTime).NotTo(BeNil())
				g.Expect(got.Status.LastSuccessTime.Time).To(BeTemporally(">", succeededAt.Time))
			}, timeout, interval).Should(Succeed())
			Expect(unhealthyEvents(Default)).To(HaveLen(1), "recovering records no event")
		})
	})
})

// These specs call Reconcile directly, against a fake client, for the paths that envtest cannot
// reach on demand: a second reconcile of an unchanged object, a type that the CRD does not admit,
// failed status writes, and what the controller does to the events.
var _ = Describe("CollectorReconciler.Reconcile", func() {
	const (
		resync = 45 * time.Second
		// maxMessageBytes is the longest condition message and event note that the controller
		// writes. The events API takes a note of 1 kB at most.
		maxMessageBytes = 1024
	)

	var (
		groupResource = configv1alpha1.GroupVersion.WithResource("collectors").GroupResource()
		request       = ctrl.Request{NamespacedName: client.ObjectKey{Name: workloadsName}}
		registry      *collector.Registry
		recorder      *events.FakeRecorder
		statusWrites  int
	)

	BeforeEach(func() {
		registry = collector.NewRegistry()
		recorder = events.NewFakeRecorder(10)
		statusWrites = 0
	})

	// newObject is a Collector of type Workloads with a generation that is not 0.
	newObject := func() *configv1alpha1.Collector {
		return &configv1alpha1.Collector{
			ObjectMeta: metav1.ObjectMeta{Name: workloadsName, Generation: 3},
			Spec:       workloadsSpec,
		}
	}

	// reconcilerFor returns a reconciler over a fake client that holds objs. Every status write
	// counts in statusWrites, and fails with updateErr when that is set.
	reconcilerFor := func(updateErr error, objs ...client.Object) *configcontroller.CollectorReconciler {
		fakeClient := fake.NewClientBuilder().
			WithScheme(k8sClient.Scheme()).
			WithObjects(objs...).
			WithStatusSubresource(&configv1alpha1.Collector{}).
			WithInterceptorFuncs(interceptor.Funcs{
				SubResourceUpdate: func(ctx context.Context, c client.Client, subResource string,
					obj client.Object, opts ...client.SubResourceUpdateOption) error {
					statusWrites++
					if updateErr != nil {
						return updateErr
					}
					return c.SubResource(subResource).Update(ctx, obj, opts...)
				},
			}).Build()
		return &configcontroller.CollectorReconciler{
			Client:   fakeClient,
			Scheme:   fakeClient.Scheme(),
			Registry: registry,
			Recorder: recorder,
			Resync:   resync,
		}
	}

	// reconcile runs one reconcile of the request, which must not fail, and expects the next one
	// to come after the resync.
	reconcile := func(reconciler *configcontroller.CollectorReconciler) {
		GinkgoHelper()
		result, err := reconciler.Reconcile(ctx, request)
		Expect(err).NotTo(HaveOccurred())
		Expect(result).To(Equal(ctrl.Result{RequeueAfter: resync}))
	}

	// stored returns the Collector as the reconciler's client holds it.
	stored := func(reconciler *configcontroller.CollectorReconciler) configv1alpha1.Collector {
		GinkgoHelper()
		var got configv1alpha1.Collector
		Expect(reconciler.Get(ctx, request.NamespacedName, &got)).To(Succeed())
		return got
	}

	readyOf := func(obj configv1alpha1.Collector) *metav1.Condition {
		GinkgoHelper()
		ready := meta.FindStatusCondition(obj.Status.Conditions, configv1alpha1.ConditionReady)
		Expect(ready).NotTo(BeNil())
		return ready
	}

	// recordedEvents returns the events that the reconciler recorded since the last call, as
	// "<type> <reason> <note>".
	recordedEvents := func() []string {
		var got []string
		for {
			select {
			case event := <-recorder.Events:
				got = append(got, event)
			default:
				return got
			}
		}
	}

	It("writes the condition once, and writes nothing when it reconciles the object again", func() {
		reconciler := reconcilerFor(nil, newObject())

		reconcile(reconciler)
		reconcile(reconciler)

		Expect(statusWrites).To(Equal(1))
		ready := readyOf(stored(reconciler))
		Expect(ready).To(HaveField("Status", metav1.ConditionUnknown))
		Expect(ready).To(HaveField("Reason", "NoData"))
		Expect(ready).To(HaveField("ObservedGeneration", int64(3)))
		Expect(recordedEvents()).To(BeEmpty())
	})

	It("moves observedGeneration with the generation of the object", func() {
		reconciler := reconcilerFor(nil, newObject())
		reconcile(reconciler)
		edited := stored(reconciler)
		edited.Generation = 4
		Expect(reconciler.Update(ctx, &edited)).To(Succeed())

		reconcile(reconciler)

		Expect(statusWrites).To(Equal(2))
		Expect(readyOf(stored(reconciler))).To(HaveField("ObservedGeneration", int64(4)))
	})

	It("writes the time of a success once, and writes nothing while the report is unchanged", func() {
		reconciler := reconcilerFor(nil, newObject())
		reconcile(reconciler)
		registry.ReportSuccess(configv1alpha1.CollectorTypeWorkloads)

		// The registry holds the time to the nanosecond and the API keeps whole seconds. A second
		// reconcile that compared the two would find a difference and write again.
		reconcile(reconciler)
		reconcile(reconciler)

		Expect(statusWrites).To(Equal(2), "one write for NoData, one for the success")
		got := stored(reconciler)
		Expect(readyOf(got)).To(HaveField("Reason", "Healthy"))
		Expect(got.Status.LastSuccessTime).NotTo(BeNil())
		Expect(recordedEvents()).To(BeEmpty())
	})

	It("starts from NoData again after a restart, whatever condition it finds", func() {
		stale := newObject()
		stale.Status.Conditions = []metav1.Condition{{
			Type:               configv1alpha1.ConditionReady,
			Status:             metav1.ConditionFalse,
			Reason:             "CollectorFailing",
			Message:            "pods cannot be listed",
			ObservedGeneration: 3,
			LastTransitionTime: metav1.Now(),
		}}
		reconciler := reconcilerFor(nil, stale)

		reconcile(reconciler)

		got := stored(reconciler)
		Expect(readyOf(got)).To(HaveField("Status", metav1.ConditionUnknown))
		Expect(readyOf(got)).To(HaveField("Reason", "NoData"))
		Expect(recordedEvents()).To(BeEmpty(), "leaving False is not a failure")
	})

	// A restart empties the registry, so the status is the only place that still has the time of
	// a success from before. A success is the only thing that replaces it.
	Describe("the last success time that an earlier run of the operator stored", func() {
		var (
			earlier    metav1.Time
			reconciler *configcontroller.CollectorReconciler
		)

		BeforeEach(func() {
			earlier = metav1.NewTime(time.Now().Add(-time.Hour).Truncate(time.Second))
			previous := newObject()
			previous.Status.LastSuccessTime = &earlier
			reconciler = reconcilerFor(nil, previous)
		})

		// lastSuccessTime returns the time that the status of the Collector holds.
		lastSuccessTime := func() time.Time {
			GinkgoHelper()
			got := stored(reconciler)
			Expect(got.Status.LastSuccessTime).NotTo(BeNil())
			return got.Status.LastSuccessTime.Time
		}

		It("stays while the collector has not reported", func() {
			reconcile(reconciler)

			Expect(readyOf(stored(reconciler))).To(HaveField("Reason", "NoData"))
			Expect(lastSuccessTime()).To(BeTemporally("==", earlier.Time))
		})

		// The registry knows the type from its first report on. A failure is no success, though,
		// so the status still holds the last success there was.
		It("stays when the first report is a failure", func() {
			registry.ReportFailure(configv1alpha1.CollectorTypeWorkloads, errors.New("pods cannot be listed"))

			reconcile(reconciler)

			Expect(readyOf(stored(reconciler))).To(HaveField("Reason", "CollectorFailing"))
			Expect(lastSuccessTime()).To(BeTemporally("==", earlier.Time))
		})

		It("gives way to the first success", func() {
			reconcile(reconciler)
			registry.ReportSuccess(configv1alpha1.CollectorTypeWorkloads)

			reconcile(reconciler)

			reported, _, _ := registry.Health(configv1alpha1.CollectorTypeWorkloads)
			Expect(readyOf(stored(reconciler))).To(HaveField("Reason", "Healthy"))
			// The API keeps whole seconds.
			Expect(lastSuccessTime()).To(BeTemporally("==", reported.Truncate(time.Second)))
		})
	})

	It("records one event for the transition to False, and none while it stays False", func() {
		reconciler := reconcilerFor(nil, newObject())
		registry.ReportFailure(configv1alpha1.CollectorTypeWorkloads, errors.New("first error"))

		reconcile(reconciler)
		reconcile(reconciler)

		Expect(readyOf(stored(reconciler))).To(HaveField("Reason", "CollectorFailing"))
		Expect(recordedEvents()).To(ConsistOf("Warning " + unhealthyReason + " first error"))

		By("changing the message when another error follows, without another event")
		registry.ReportFailure(configv1alpha1.CollectorTypeWorkloads, errors.New("second error"))
		reconcile(reconciler)

		Expect(readyOf(stored(reconciler))).To(HaveField("Message", "second error"))
		Expect(statusWrites).To(Equal(2))
		Expect(recordedEvents()).To(BeEmpty())
	})

	It("records an event again for a failure that follows a success", func() {
		reconciler := reconcilerFor(nil, newObject())
		registry.ReportFailure(configv1alpha1.CollectorTypeWorkloads, errors.New("first error"))
		reconcile(reconciler)
		Expect(recordedEvents()).To(HaveLen(1))
		registry.ReportSuccess(configv1alpha1.CollectorTypeWorkloads)
		reconcile(reconciler)
		Expect(recordedEvents()).To(BeEmpty())

		registry.ReportFailure(configv1alpha1.CollectorTypeWorkloads, errors.New("second error"))
		reconcile(reconciler)

		Expect(recordedEvents()).To(ConsistOf("Warning " + unhealthyReason + " second error"))
	})

	It("is False with reason UnknownValue for a type it does not know, and records an event", func() {
		unknown := newObject()
		unknown.Spec = configv1alpha1.CollectorSpec{Type: unknownType}
		reconciler := reconcilerFor(nil, unknown)

		reconcile(reconciler)
		reconcile(reconciler)

		ready := readyOf(stored(reconciler))
		Expect(ready).To(HaveField("Status", metav1.ConditionFalse))
		Expect(ready).To(HaveField("Reason", "UnknownValue"))
		Expect(ready.Message).To(ContainSubstring(`"` + unknownType + `"`))
		Expect(statusWrites).To(Equal(1))
		Expect(recordedEvents()).To(ConsistOf(HavePrefix("Warning " + unhealthyReason + " ")))
	})

	// The scanner Collector exists from the start, so the controller must know its type: a type of
	// this version is no UnknownValue, whatever the scanner has or has not reported.
	It("knows the Scanner type: NoData until the scanner reports, and Healthy after its success", func() {
		scannerRequest := ctrl.Request{NamespacedName: client.ObjectKey{Name: scannerName}}
		reconciler := reconcilerFor(nil, &configv1alpha1.Collector{
			ObjectMeta: metav1.ObjectMeta{Name: scannerName, Generation: 1},
			Spec:       scannerSpec,
		})
		scannerReady := func() *metav1.Condition {
			GinkgoHelper()
			_, err := reconciler.Reconcile(ctx, scannerRequest)
			Expect(err).NotTo(HaveOccurred())
			var got configv1alpha1.Collector
			Expect(reconciler.Get(ctx, scannerRequest.NamespacedName, &got)).To(Succeed())
			return readyOf(got)
		}

		Expect(scannerReady()).To(And(HaveField("Status", metav1.ConditionUnknown), HaveField("Reason", "NoData")))
		Expect(recordedEvents()).To(BeEmpty())

		registry.ReportSuccess(configv1alpha1.CollectorTypeScanner)

		Expect(scannerReady()).To(And(HaveField("Status", metav1.ConditionTrue), HaveField("Reason", "Healthy")))
		Expect(recordedEvents()).To(BeEmpty())
	})

	It("caps a long error, so that the condition and the event stay within their limits", func() {
		reconciler := reconcilerFor(nil, newObject())
		// 2000 bytes of two-byte characters, so that the cap falls inside a character.
		registry.ReportFailure(configv1alpha1.CollectorTypeWorkloads, errors.New(strings.Repeat("é", 1000)))

		reconcile(reconciler)

		message := readyOf(stored(reconciler)).Message
		Expect(len(message)).To(BeNumerically("<=", maxMessageBytes))
		Expect(utf8.ValidString(message)).To(BeTrue())
		Expect(message).To(And(HavePrefix("éé"), HaveSuffix("...")))
		Expect(recordedEvents()).To(ConsistOf("Warning " + unhealthyReason + " " + message))
	})

	It("does nothing for an object that is gone, and does not requeue", func() {
		result, err := reconcilerFor(nil).Reconcile(ctx, request)

		Expect(err).NotTo(HaveOccurred())
		Expect(result).To(Equal(ctrl.Result{}))
		Expect(statusWrites).To(BeZero())
	})

	It("is not an error when the object is deleted between the read and the status write", func() {
		registry.ReportFailure(configv1alpha1.CollectorTypeWorkloads, errors.New("first error"))
		gone := apierrors.NewNotFound(groupResource, workloadsName)

		result, err := reconcilerFor(gone, newObject()).Reconcile(ctx, request)

		Expect(err).NotTo(HaveOccurred())
		Expect(result).To(Equal(ctrl.Result{}))
		Expect(recordedEvents()).To(BeEmpty(), "a Collector that is gone has nothing to be unhealthy")
	})

	It("returns a failed status write, so that the request is retried, and records no event", func() {
		registry.ReportFailure(configv1alpha1.CollectorTypeWorkloads, errors.New("first error"))
		conflict := apierrors.NewConflict(groupResource, workloadsName, errors.New("the object was modified"))

		_, err := reconcilerFor(conflict, newObject()).Reconcile(ctx, request)

		Expect(err).To(MatchError(conflict))
		Expect(recordedEvents()).To(BeEmpty(), "the event follows the status it announces, and the retry records it")
	})
})
