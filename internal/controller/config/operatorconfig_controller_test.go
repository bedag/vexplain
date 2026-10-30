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

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/yaml"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
	configcontroller "github.com/bedag/vexplain/internal/controller/config"
	"github.com/bedag/vexplain/internal/scope"
	"github.com/bedag/vexplain/internal/settings"
)

// badSelector is a selector that the CRD schema accepts and a label selector cannot parse: the
// schema types the operator as a plain string.
func badSelector() *metav1.LabelSelector {
	return &metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{
		{Key: "team", Operator: "Bogus", Values: []string{"team-a"}},
	}}
}

// These specs run against the manager that the suite starts through setup.Register, so the
// controller under test is the production one.
var _ = Describe("OperatorConfig", func() {
	const (
		// singletonName is the only name the CRD accepts.
		singletonName = "default"
		timeout       = 30 * time.Second
		interval      = 100 * time.Millisecond
	)

	singleton := client.ObjectKey{Name: singletonName}

	// The singleton is cluster-scoped, so every spec shares it. Each spec starts without it.
	AfterEach(func() {
		Expect(client.IgnoreNotFound(k8sClient.Delete(ctx, &configv1alpha1.OperatorConfig{
			ObjectMeta: metav1.ObjectMeta{Name: singletonName},
		}))).To(Succeed())
		Eventually(func() error {
			return k8sClient.Get(ctx, singleton, &configv1alpha1.OperatorConfig{})
		}, timeout, interval).Should(Satisfy(apierrors.IsNotFound))
	})

	createSingleton := func(spec configv1alpha1.OperatorConfigSpec) {
		GinkgoHelper()
		Expect(k8sClient.Create(ctx, &configv1alpha1.OperatorConfig{
			ObjectMeta: metav1.ObjectMeta{Name: singletonName},
			Spec:       spec,
		})).To(Succeed())
	}

	// rawConfig builds an OperatorConfig from raw spec content. A Go struct would drop an empty
	// selector map (omitempty), and some specs need exactly that on the wire.
	rawConfig := func(name string, spec map[string]any) *unstructured.Unstructured {
		obj := &unstructured.Unstructured{Object: map[string]any{"spec": spec}}
		obj.SetGroupVersionKind(configv1alpha1.GroupVersion.WithKind("OperatorConfig"))
		obj.SetName(name)
		return obj
	}

	// readyOnceCurrent returns the Ready condition of the singleton. It fails, so that an
	// Eventually retries, until the controller has set the condition for the current generation.
	readyOnceCurrent := func(g Gomega) *metav1.Condition {
		GinkgoHelper()
		var got configv1alpha1.OperatorConfig
		g.Expect(k8sClient.Get(ctx, singleton, &got)).To(Succeed())
		ready := meta.FindStatusCondition(got.Status.Conditions, configv1alpha1.ConditionReady)
		g.Expect(ready).NotTo(BeNil())
		g.Expect(ready.ObservedGeneration).To(Equal(got.Generation))
		return ready
	}

	expectReady := func() {
		GinkgoHelper()
		Eventually(func(g Gomega) {
			ready := readyOnceCurrent(g)
			g.Expect(ready.Status).To(Equal(metav1.ConditionTrue))
			g.Expect(ready.Reason).To(Equal(configv1alpha1.ReasonValid))
		}, timeout, interval).Should(Succeed())
	}

	// expectInvalid waits for Ready=False with reason Invalid, and for a message that names the
	// field at fault. The message is the error of scope.New, which stops at the first selector it
	// refuses, so there is one field to name.
	expectInvalid := func(field string) {
		GinkgoHelper()
		Eventually(func(g Gomega) {
			ready := readyOnceCurrent(g)
			g.Expect(ready.Status).To(Equal(metav1.ConditionFalse))
			g.Expect(ready.Reason).To(Equal(configv1alpha1.ReasonInvalid))
			g.Expect(ready.Message).To(ContainSubstring(field))
		}, timeout, interval).Should(Succeed())
	}

	Describe("validation by the API server", func() {
		It("rejects an object that is not named default", func() {
			err := k8sClient.Create(ctx, &configv1alpha1.OperatorConfig{
				ObjectMeta: metav1.ObjectMeta{Name: "other"},
			})

			Expect(err).To(Satisfy(apierrors.IsInvalid))
			Expect(err).To(MatchError(ContainSubstring("singleton named 'default'")))
		})

		DescribeTable("rejects an empty exclude selector",
			func(field string, selector map[string]any) {
				selectors := map[string]any{field: selector}
				err := k8sClient.Create(ctx, rawConfig(singletonName, map[string]any{"scope": selectors}))

				Expect(err).To(Satisfy(apierrors.IsInvalid))
				Expect(err).To(MatchError(ContainSubstring(field + " must not be empty")))
			},
			Entry("excludeNamespaces: {}",
				"excludeNamespaces", map[string]any{}),
			Entry("excludeNamespaces with an empty matchLabels",
				"excludeNamespaces", map[string]any{"matchLabels": map[string]any{}}),
			Entry("excludeNamespaces with an empty matchExpressions",
				"excludeNamespaces", map[string]any{"matchExpressions": []any{}}),
			Entry("excludePods: {}",
				"excludePods", map[string]any{}),
			Entry("excludePods with an empty matchLabels",
				"excludePods", map[string]any{"matchLabels": map[string]any{}}),
			Entry("excludePods with an empty matchExpressions",
				"excludePods", map[string]any{"matchExpressions": []any{}}),
		)

		DescribeTable("rejects the cluster name",
			func(name string) {
				err := k8sClient.Create(ctx, &configv1alpha1.OperatorConfig{
					ObjectMeta: metav1.ObjectMeta{Name: singletonName},
					Spec:       configv1alpha1.OperatorConfigSpec{ClusterName: ptr.To(name)},
				})

				Expect(err).To(Satisfy(apierrors.IsInvalid))
				Expect(err).To(MatchError(ContainSubstring("spec.clusterName")))
			},
			Entry("with an uppercase letter", "Cluster-A"),
			Entry("that starts with a dash", "-cluster-a"),
			Entry("that ends with a dash", "cluster-a-"),
			Entry("with an underscore", "cluster_a"),
			Entry("that is empty", ""),
			Entry("that is 64 characters long", strings.Repeat("a", 64)),
		)
	})

	Describe("the rules", func() {
		// rulesWith returns a spec whose rules ask for the minimum completeness percent.
		rulesWith := func(percent int32) configv1alpha1.OperatorConfigSpec {
			return configv1alpha1.OperatorConfigSpec{Rules: &configv1alpha1.Rules{MinCompletenessPercent: ptr.To(percent)}}
		}

		DescribeTable("reject a minimum completeness outside 0 to 100",
			func(percent int32) {
				err := k8sClient.Create(ctx, &configv1alpha1.OperatorConfig{
					ObjectMeta: metav1.ObjectMeta{Name: singletonName},
					Spec:       rulesWith(percent),
				})

				Expect(err).To(Satisfy(apierrors.IsInvalid))
				Expect(err).To(MatchError(ContainSubstring("spec.rules.minCompletenessPercent")))
			},
			Entry("of 101", int32(101)),
			Entry("of -1", int32(-1)),
		)

		DescribeTable("keep a minimum completeness at either end of the range",
			func(percent int32) {
				createSingleton(rulesWith(percent))

				var got configv1alpha1.OperatorConfig
				Expect(k8sClient.Get(ctx, singleton, &got)).To(Succeed())
				// A threshold of 0 is stored as 0: only an absent one gets the default.
				Expect(got.Spec.Rules.MinCompletenessPercent).To(HaveValue(Equal(percent)))
			},
			Entry("of 0", int32(0)),
			Entry("of 100", int32(100)),
		)

		It("fill in the default of 90 for rules: {}, which is the default that settings.Load uses", func() {
			createSingleton(configv1alpha1.OperatorConfigSpec{Rules: &configv1alpha1.Rules{}})

			var got configv1alpha1.OperatorConfig
			Expect(k8sClient.Get(ctx, singleton, &got)).To(Succeed())
			Expect(got.Spec.Rules.MinCompletenessPercent).To(HaveValue(Equal(int32(90))))

			// The default in the Go code stands in when there is no object, and it must be the one that
			// the API server applies.
			Expect(got.Spec.Rules.MinCompletenessPercent).To(HaveValue(Equal(settings.DefaultMinCompletenessPercent)))
			effective, err := settings.Load(ctx, k8sClient)
			Expect(err).NotTo(HaveOccurred())
			Expect(effective.Rules.MinCompletenessPercent).To(Equal(int32(90)))
		})

		It("read the minimum completeness of the stored object through settings.Load", func() {
			createSingleton(rulesWith(55))

			effective, err := settings.Load(ctx, k8sClient)

			Expect(err).NotTo(HaveOccurred())
			Expect(effective.Rules.MinCompletenessPercent).To(Equal(int32(55)))
		})
	})

	Describe("the Ready condition", func() {
		It("defaults clusterName and is Ready for an empty spec", func() {
			createSingleton(configv1alpha1.OperatorConfigSpec{})

			var got configv1alpha1.OperatorConfig
			Expect(k8sClient.Get(ctx, singleton, &got)).To(Succeed())
			Expect(got.Spec.ClusterName).To(HaveValue(Equal("local")))

			expectReady()
		})

		It("is Ready for the sample", func() {
			data, err := os.ReadFile(filepath.Join("..", "..", "..", "config", "samples",
				"config_v1alpha1_operatorconfig.yaml"))
			Expect(err).NotTo(HaveOccurred())
			sample := &configv1alpha1.OperatorConfig{}
			Expect(yaml.UnmarshalStrict(data, sample)).To(Succeed())

			Expect(k8sClient.Create(ctx, sample)).To(Succeed())

			expectReady()
		})

		It("is Ready for a cluster name of 63 characters, the longest allowed", func() {
			createSingleton(configv1alpha1.OperatorConfigSpec{ClusterName: ptr.To(strings.Repeat("a", 63))})

			expectReady()
		})

		It("is Ready for a scope whose selectors are valid", func() {
			createSingleton(configv1alpha1.OperatorConfigSpec{
				ClusterName: ptr.To("cluster-a"),
				Scope: &configv1alpha1.Scope{
					IncludeNamespaces: &metav1.LabelSelector{MatchLabels: map[string]string{"team": "team-a"}},
					ExcludeNamespaces: &metav1.LabelSelector{MatchLabels: map[string]string{"vexplain": "off"}},
					IncludePods: &metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{
						{Key: "tier", Operator: metav1.LabelSelectorOpIn, Values: []string{"web", "api"}},
					}},
					ExcludePods: &metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{
						{Key: "debug", Operator: metav1.LabelSelectorOpExists},
					}},
				},
			})

			expectReady()
		})

		It("is Ready for empty include selectors, which match everything", func() {
			createSingleton(configv1alpha1.OperatorConfigSpec{Scope: &configv1alpha1.Scope{
				IncludeNamespaces: &metav1.LabelSelector{},
				IncludePods:       &metav1.LabelSelector{},
			}})

			expectReady()
		})

		It("is False with reason Invalid for a selector with an unknown operator", func() {
			createSingleton(configv1alpha1.OperatorConfigSpec{Scope: &configv1alpha1.Scope{
				IncludeNamespaces: badSelector(),
			}})

			Eventually(func(g Gomega) {
				ready := readyOnceCurrent(g)
				g.Expect(ready.Status).To(Equal(metav1.ConditionFalse))
				g.Expect(ready.Reason).To(Equal(configv1alpha1.ReasonInvalid))
				g.Expect(ready.Message).To(And(
					ContainSubstring("includeNamespaces"),
					ContainSubstring(`"Bogus" is not a valid label selector operator`),
				))
			}, timeout, interval).Should(Succeed())
		})

		DescribeTable("is False with reason Invalid, and names the selector at fault",
			func(selectors *configv1alpha1.Scope, field string) {
				createSingleton(configv1alpha1.OperatorConfigSpec{Scope: selectors})

				expectInvalid(field)
			},
			Entry("includeNamespaces",
				&configv1alpha1.Scope{IncludeNamespaces: badSelector()},
				"includeNamespaces"),
			Entry("excludeNamespaces",
				&configv1alpha1.Scope{ExcludeNamespaces: badSelector()},
				"excludeNamespaces"),
			Entry("includePods, whose matchLabels key is not a label key",
				&configv1alpha1.Scope{IncludePods: &metav1.LabelSelector{
					MatchLabels: map[string]string{"not a label key": "x"},
				}},
				"includePods"),
			Entry("excludePods, where Exists comes with values",
				&configv1alpha1.Scope{ExcludePods: &metav1.LabelSelector{
					MatchExpressions: []metav1.LabelSelectorRequirement{
						{Key: "debug", Operator: metav1.LabelSelectorOpExists, Values: []string{"true"}},
					},
				}},
				"excludePods"),
		)

		It("returns to True when the selector is fixed", func() {
			createSingleton(configv1alpha1.OperatorConfigSpec{Scope: &configv1alpha1.Scope{
				IncludeNamespaces: badSelector(),
			}})
			expectInvalid("includeNamespaces")

			var got configv1alpha1.OperatorConfig
			Expect(k8sClient.Get(ctx, singleton, &got)).To(Succeed())
			patch := client.MergeFrom(got.DeepCopy())
			got.Spec.Scope = nil
			Expect(k8sClient.Patch(ctx, &got, patch)).To(Succeed())

			expectReady()
		})
	})
})

// These specs call Reconcile directly, against a fake client, for the paths that envtest cannot
// reach on demand: a second reconcile of an unchanged object, a failed status write, and a scope
// that the CRD schema rejects.
var _ = Describe("OperatorConfigReconciler.Reconcile", func() {
	var (
		groupResource = configv1alpha1.GroupVersion.WithResource("operatorconfigs").GroupResource()
		request       = ctrl.Request{NamespacedName: client.ObjectKey{Name: "default"}}
		statusWrites  int
	)

	BeforeEach(func() {
		statusWrites = 0
	})

	// newObject is an OperatorConfig with a spec that is valid and a generation that is not 0.
	newObject := func() *configv1alpha1.OperatorConfig {
		return &configv1alpha1.OperatorConfig{ObjectMeta: metav1.ObjectMeta{Name: "default", Generation: 3}}
	}

	// reconcilerFor returns a reconciler over a fake client that holds objs. Every status write
	// counts in statusWrites, and fails with updateErr when that is set.
	reconcilerFor := func(updateErr error, objs ...client.Object) *configcontroller.OperatorConfigReconciler {
		fakeClient := fake.NewClientBuilder().
			WithScheme(k8sClient.Scheme()).
			WithObjects(objs...).
			WithStatusSubresource(&configv1alpha1.OperatorConfig{}).
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
		return &configcontroller.OperatorConfigReconciler{Client: fakeClient, Scheme: fakeClient.Scheme()}
	}

	It("writes the condition once, and writes nothing when it reconciles the object again", func() {
		reconciler := reconcilerFor(nil, newObject())

		for range 2 {
			_, err := reconciler.Reconcile(ctx, request)
			Expect(err).NotTo(HaveOccurred())
		}

		Expect(statusWrites).To(Equal(1))
		var got configv1alpha1.OperatorConfig
		Expect(reconciler.Get(ctx, request.NamespacedName, &got)).To(Succeed())
		ready := meta.FindStatusCondition(got.Status.Conditions, configv1alpha1.ConditionReady)
		Expect(ready).To(HaveField("Status", metav1.ConditionTrue))
		Expect(ready).To(HaveField("ObservedGeneration", int64(3)))
	})

	It("does nothing for an object that is gone", func() {
		_, err := reconcilerFor(nil).Reconcile(ctx, request)

		Expect(err).NotTo(HaveOccurred())
		Expect(statusWrites).To(BeZero())
	})

	It("is not an error when the object is deleted between the read and the status write", func() {
		gone := apierrors.NewNotFound(groupResource, "default")

		_, err := reconcilerFor(gone, newObject()).Reconcile(ctx, request)

		Expect(err).NotTo(HaveOccurred())
	})

	It("returns a failed status write, so that the request is retried", func() {
		conflict := apierrors.NewConflict(groupResource, "default", errors.New("the object was modified"))

		_, err := reconcilerFor(conflict, newObject()).Reconcile(ctx, request)

		Expect(err).To(MatchError(conflict))
	})

	// The reconciler checks the scope with scope.New, which the pod inventory builds its matcher
	// with. So the condition can't say Valid for a scope that the inventory refuses, and its
	// message is the refusal. An empty exclude can only get here from a client that skips the CRD
	// schema, which envtest does not do, so the objects come from the fake client.
	DescribeTable("is False with reason Invalid, and has the error of scope.New as its message",
		func(selectors *configv1alpha1.Scope) {
			_, refused := scope.New(selectors)
			Expect(refused).To(HaveOccurred(), "scope.New must refuse the fixture")
			object := newObject()
			object.Spec.Scope = selectors
			reconciler := reconcilerFor(nil, object)

			_, err := reconciler.Reconcile(ctx, request)

			Expect(err).NotTo(HaveOccurred())
			var got configv1alpha1.OperatorConfig
			Expect(reconciler.Get(ctx, request.NamespacedName, &got)).To(Succeed())
			ready := meta.FindStatusCondition(got.Status.Conditions, configv1alpha1.ConditionReady)
			Expect(ready).To(HaveField("Status", metav1.ConditionFalse))
			Expect(ready).To(HaveField("Reason", configv1alpha1.ReasonInvalid))
			Expect(ready).To(HaveField("Message", refused.Error()))
		},
		Entry("an empty excludeNamespaces",
			&configv1alpha1.Scope{ExcludeNamespaces: &metav1.LabelSelector{}}),
		Entry("an empty excludePods",
			&configv1alpha1.Scope{ExcludePods: &metav1.LabelSelector{}}),
		Entry("an unparsable selector",
			&configv1alpha1.Scope{IncludeNamespaces: badSelector()}),
		// scope.New stops at the first selector it refuses, and so does the message.
		Entry("two selectors at fault",
			&configv1alpha1.Scope{IncludePods: badSelector(), ExcludeNamespaces: &metav1.LabelSelector{}}),
	)
})
