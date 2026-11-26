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
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
)

// These specs check the schema of the Spoke against the API server. Its name is the cluster's name, so the name is
// checked too.
var _ = Describe("Spoke API", func() {
	// spokeNamed returns a Spoke that the schema accepts.
	spokeNamed := func(name string) *configv1alpha1.Spoke {
		return &configv1alpha1.Spoke{
			ObjectMeta: metav1.ObjectMeta{Name: name},
			Spec: configv1alpha1.SpokeSpec{
				CredentialsSecretRef: configv1alpha1.SecretReference{Name: "spoke-credentials"},
			},
		}
	}

	It("refuses a Spoke without credentialsSecretRef", func() {
		err := k8sClient.Create(ctx, rawObject("Spoke", apiName("cluster-a"), map[string]any{}))

		Expect(err).To(refusedWith("spec.credentialsSecretRef"))
	})

	It("accepts a Spoke with labels", func() {
		obj := spokeNamed(apiName("cluster-a"))
		obj.Spec.Labels = map[string]configv1alpha1.LabelValue{"example.com/env": "stage", "region": ""}

		Expect(k8sClient.Create(ctx, obj)).To(Succeed())
		DeferCleanup(func() { Expect(client.IgnoreNotFound(k8sClient.Delete(ctx, obj))).To(Succeed()) })
	})

	DescribeTable("refuses a label that OperatorConfig.clusterLabels refuses, with",
		func(labels map[string]configv1alpha1.LabelValue, message string) {
			obj := spokeNamed(apiName("cluster-a"))
			obj.Spec.Labels = labels

			Expect(k8sClient.Create(ctx, obj)).To(refusedWith("spec.labels", message))
		},
		Entry("a key that is no label key", map[string]configv1alpha1.LabelValue{"env name": "v"}, "every key must be a valid label key"),
		Entry("a value that is no label value", map[string]configv1alpha1.LabelValue{"env": "-a"}, "every value must be a valid label value"),
		Entry("33 labels", func() map[string]configv1alpha1.LabelValue {
			labels := map[string]configv1alpha1.LabelValue{}
			for i := range 33 {
				labels["k"+strings.Repeat("a", i)] = "v"
			}
			return labels
		}(), "Too many"),
	)

	DescribeTable("refuses a name that is no cluster name, with",
		func(name string) {
			Expect(k8sClient.Create(ctx, spokeNamed(name))).To(Not(Succeed()))
		},
		Entry("64 characters", strings.Repeat("a", 64)),
		Entry("a dot", "cluster.a"),
	)

	It("accepts a name of 63 characters", func() {
		obj := spokeNamed(strings.Repeat("a", 63))

		Expect(k8sClient.Create(ctx, obj)).To(Succeed())
		DeferCleanup(func() { Expect(client.IgnoreNotFound(k8sClient.Delete(ctx, obj))).To(Succeed()) })
	})

	Describe("status.clusterID", func() {
		patchID := func(obj *configv1alpha1.Spoke, id *string) error {
			base := obj.DeepCopy()
			obj.Status.ClusterID = id
			return k8sClient.Status().Patch(ctx, obj, client.MergeFrom(base))
		}

		It("may be set and cleared, but not changed to another value", func() {
			obj := spokeNamed(apiName("cluster-a"))
			createObject(obj)

			Expect(patchID(obj, ptr.To("id-a"))).To(Succeed())
			Expect(patchID(obj, ptr.To("id-b"))).To(refusedWith("clusterID"))
			Expect(patchID(obj, ptr.To("id-a"))).To(Succeed())
			Expect(patchID(obj, nil)).To(Succeed())
			Expect(patchID(obj, ptr.To("id-b"))).To(Succeed())
		})
	})
})
