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
	"os"
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/yaml"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
)

// These specs check the schema of the CollectorRuntimeConfig against the API server. Its templates
// are patches for objects that Kubernetes owns the schema of, so the kind keeps them as they are.
var _ = Describe("CollectorRuntimeConfig API", func() {
	It("accepts an empty spec, which is what the default config is", func() {
		createObject(&configv1alpha1.CollectorRuntimeConfig{ObjectMeta: metav1.ObjectMeta{Name: apiName("runtime")}})
	})

	It("keeps the templates as they are, whatever fields they hold", func() {
		deployment := `{"metadata":{"labels":{"team":"team-a"}},"spec":{"replicas":1,"template":{"spec":{` +
			`"nodeSelector":{"kubernetes.io/os":"linux"},` +
			`"containers":[{"name":"collector","imagePullPolicy":"Always","resources":{"limits":{"memory":"256Mi"}}}]}}}}`
		serviceAccount := `{"metadata":{"annotations":{"iam.example/role":"collector"}}}`
		obj := &configv1alpha1.CollectorRuntimeConfig{
			ObjectMeta: metav1.ObjectMeta{Name: apiName("runtime")},
			Spec: configv1alpha1.CollectorRuntimeConfigSpec{
				DeploymentTemplate:     &runtime.RawExtension{Raw: []byte(deployment)},
				ServiceAccountTemplate: &runtime.RawExtension{Raw: []byte(serviceAccount)},
			},
		}
		createObject(obj)

		var got configv1alpha1.CollectorRuntimeConfig
		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(obj), &got)).To(Succeed())
		Expect(got.Spec.DeploymentTemplate).NotTo(BeNil())
		Expect(got.Spec.DeploymentTemplate.Raw).To(MatchJSON(deployment))
		Expect(got.Spec.ServiceAccountTemplate).NotTo(BeNil())
		Expect(got.Spec.ServiceAccountTemplate.Raw).To(MatchJSON(serviceAccount))
	})

	It("keeps a field that no version of Kubernetes knows", func() {
		template := `{"spec":{"fieldOfALaterVersion":{"nested":[1,2,3]}}}`
		obj := &configv1alpha1.CollectorRuntimeConfig{
			ObjectMeta: metav1.ObjectMeta{Name: apiName("runtime")},
			Spec: configv1alpha1.CollectorRuntimeConfigSpec{
				DeploymentTemplate: &runtime.RawExtension{Raw: []byte(template)},
			},
		}
		createObject(obj)

		var got configv1alpha1.CollectorRuntimeConfig
		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(obj), &got)).To(Succeed())
		Expect(got.Spec.DeploymentTemplate.Raw).To(MatchJSON(template))
	})

	It("has no status", func() {
		obj := &configv1alpha1.CollectorRuntimeConfig{ObjectMeta: metav1.ObjectMeta{Name: apiName("runtime")}}
		createObject(obj)

		// A kind without a status subresource has no status endpoint to write to.
		err := k8sClient.SubResource("status").Update(ctx, obj)

		Expect(err).To(Satisfy(apierrors.IsNotFound))
	})

	It("accepts the sample", func() {
		data, err := os.ReadFile(filepath.Join("..", "..", "..", "config", "samples",
			"config_v1alpha1_collectorruntimeconfig.yaml"))
		Expect(err).NotTo(HaveOccurred())
		sample := &configv1alpha1.CollectorRuntimeConfig{}
		Expect(yaml.UnmarshalStrict(data, sample)).To(Succeed())

		createObject(sample)

		Expect(sample.Spec.DeploymentTemplate).NotTo(BeNil())
	})
})
