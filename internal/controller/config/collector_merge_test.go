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
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
	"github.com/bedag/vexplain/internal/collector/certs"
)

// owningTeam is the team that someone other than the deployer names in an annotation of a collector's service
// account.
const owningTeam = "team-b"

// These specs check how a CollectorRuntimeConfig shapes what the deployer makes for a collector: its templates are
// merged onto the defaults as strategic merge patches, and the deployer then sets the fields of the collector's
// contract again, which no template changes.
var _ = Describe("Shaping a collector with a runtime config", func() {
	// newRuntimeConfig creates a runtime config of a name of its own with the templates, each unless it is empty, and
	// deletes it when the spec ends. It returns the name.
	newRuntimeConfig := func(deployment, serviceAccount string) string {
		GinkgoHelper()
		config := &configv1alpha1.CollectorRuntimeConfig{ObjectMeta: metav1.ObjectMeta{Name: apiName("runtime")}}
		if deployment != "" {
			config.Spec.DeploymentTemplate = &runtime.RawExtension{Raw: []byte(deployment)}
		}
		if serviceAccount != "" {
			config.Spec.ServiceAccountTemplate = &runtime.RawExtension{Raw: []byte(serviceAccount)}
		}
		createObject(config)
		return config.Name
	}
	// setTemplate changes the deployment template of the runtime config.
	setTemplate := func(name, deployment string) {
		GinkgoHelper()
		Eventually(func() error {
			var config configv1alpha1.CollectorRuntimeConfig
			if err := k8sClient.Get(ctx, client.ObjectKey{Name: name}, &config); err != nil {
				return err
			}
			config.Spec.DeploymentTemplate = &runtime.RawExtension{Raw: []byte(deployment)}
			return k8sClient.Update(ctx, &config)
		}, deployTimeout, deployPoll).Should(Succeed())
	}
	// shapedBy returns the spec of a Collector that the runtime config shapes.
	shapedBy := func(config string) configv1alpha1.CollectorSpec {
		spec := helloSpec("")
		spec.RuntimeConfigRef = &configv1alpha1.RuntimeConfigReference{Name: config}
		return spec
	}
	// collectorContainer returns the container named collector of a Deployment.
	collectorContainer := func(d *appsv1.Deployment) corev1.Container {
		GinkgoHelper()
		for _, c := range d.Spec.Template.Spec.Containers {
			if c.Name == collectorContainer {
				return c
			}
		}
		Fail("the Deployment has no container named collector")
		return corev1.Container{}
	}
	// expectContract checks the fields of the contract that the deployer sets again after the template.
	expectContract := func(name string, d *appsv1.Deployment) {
		GinkgoHelper()
		container := collectorContainer(d)
		Expect(container.Image).To(Equal(examplePackage))
		Expect(container.Env).To(ContainElements(
			corev1.EnvVar{Name: "VEXPLAIN_COLLECTOR_NAME", Value: name},
			corev1.EnvVar{Name: listenVariable, Value: grpcListen},
			corev1.EnvVar{Name: "VEXPLAIN_HEALTH_LISTEN", Value: ":8081"},
			corev1.EnvVar{Name: "VEXPLAIN_TLS_DIR", Value: tlsDir},
		))
		Expect(container.Ports).To(ContainElements(
			And(HaveField("Name", "grpc"), HaveField("ContainerPort", int32(9443))),
			And(HaveField("Name", "http"), HaveField("ContainerPort", int32(8081))),
		))
		Expect(container.VolumeMounts).To(ContainElement(And(HaveField("MountPath", tlsDir), HaveField("SubPath", BeEmpty()))))
		Expect(d.Spec.Template.Spec.Volumes).To(ContainElement(
			HaveField("VolumeSource.Secret.SecretName", certs.SecretName(name))))
	}

	It("gives a collector that no runtime config shapes no proxy variable", func() {
		name := newCollector(helloSpec(""))

		for _, env := range collectorContainer(deploymentOf(name)).Env {
			Expect(env.Name).NotTo(BeElementOf("HTTPS_PROXY", "HTTP_PROXY", "NO_PROXY", "https_proxy", "http_proxy", "no_proxy"))
		}
	})

	It("applies what a template sets, and follows a change of it", func() {
		config := newRuntimeConfig(`{
			"metadata": {"labels": {"team": "team-a"}},
			"spec": {"template": {
				"metadata": {"labels": {"team": "team-a"}},
				"spec": {
					"nodeSelector": {"kubernetes.io/os": "linux"},
					"containers": [{
						"name": "collector",
						"imagePullPolicy": "Always",
						"resources": {"limits": {"cpu": "500m"}},
						"env": [
							{"name": "HTTPS_PROXY", "value": "http://proxy-b.example:3128"},
							{"name": "NO_PROXY", "valueFrom": {"secretKeyRef": {"name": "proxy-settings", "key": "no-proxy"}}}
						]
					}]
				}
			}}
		}`, `{"metadata": {"labels": {"team": "team-a"}, "annotations": {"iam.example/role": "collector"}}}`)
		name := newCollector(shapedBy(config))

		d := deploymentOf(name)
		Expect(d.Labels).To(HaveKeyWithValue("team", "team-a"))
		Expect(d.Spec.Template.Labels).To(And(HaveKeyWithValue("team", "team-a"), HaveKeyWithValue(collectorLabel, name)))
		Expect(d.Spec.Template.Spec.NodeSelector).To(Equal(map[string]string{"kubernetes.io/os": "linux"}))
		container := collectorContainer(d)
		Expect(container.ImagePullPolicy).To(Equal(corev1.PullAlways))
		Expect(container.Resources.Limits.Cpu().Equal(resource.MustParse("500m"))).To(BeTrue(), "the CPU limit")
		Expect(container.Resources.Requests.Memory().Equal(resource.MustParse("64Mi"))).To(BeTrue(), "the default requests stay")
		Expect(container.Env).To(ContainElements(
			corev1.EnvVar{Name: "HTTPS_PROXY", Value: "http://proxy-b.example:3128"},
			corev1.EnvVar{Name: "NO_PROXY", ValueFrom: &corev1.EnvVarSource{SecretKeyRef: &corev1.SecretKeySelector{
				LocalObjectReference: corev1.LocalObjectReference{Name: "proxy-settings"}, Key: "no-proxy",
			}}},
		), "a runtime config sets a proxy, from a value or from a Secret")
		Expect(container.SecurityContext).NotTo(BeNil(), "what the template leaves alone keeps its default")
		Expect(container.SecurityContext.ReadOnlyRootFilesystem).To(HaveValue(BeTrue()))
		expectContract(name, d)

		var account corev1.ServiceAccount
		Expect(k8sClient.Get(ctx, client.ObjectKey{Namespace: operatorNamespace, Name: certs.ServiceName(name)}, &account)).To(Succeed())
		Expect(account.Labels).To(And(HaveKeyWithValue("team", "team-a"), HaveKeyWithValue(collectorLabel, name)))
		Expect(account.Annotations).To(HaveKeyWithValue("iam.example/role", "collector"))

		By("following the template once it no longer sets the node selector, nor the Deployment's label")
		setTemplate(config, `{"spec": {"template": {"spec": {"containers": [{"name": "collector", "imagePullPolicy": "Always"}]}}}}`)
		Eventually(func(g Gomega) map[string]string {
			return deploymentOf(name).Spec.Template.Spec.NodeSelector
		}, deployTimeout, deployPoll).Should(BeEmpty())
		Eventually(func(g Gomega) map[string]string {
			return deploymentOf(name).Labels
		}, deployTimeout, deployPoll).ShouldNot(HaveKey("team"))
		Expect(deploymentOf(name).Labels).To(HaveKeyWithValue(collectorLabel, name))
	})

	// A cloud identity that a template gives the service account must go once the template no longer gives it, or the
	// collector keeps a role that the admin took away. What others set stays.
	It("takes away from the service account what a template no longer sets, and leaves what others set", func() {
		const owner = "team.example/owner"
		config := newRuntimeConfig("", `{"metadata": {"annotations": {"iam.example/role": "collector", "iam.example/audience": "sts"}}}`)
		name := newCollector(shapedBy(config))
		key := client.ObjectKey{Namespace: operatorNamespace, Name: certs.ServiceName(name)}
		Eventually(func(g Gomega) map[string]string {
			var account corev1.ServiceAccount
			g.Expect(k8sClient.Get(ctx, key, &account)).To(Succeed())
			return account.Annotations
		}, deployTimeout, deployPoll).Should(And(HaveKey("iam.example/role"), HaveKey("iam.example/audience")))
		Eventually(func() error {
			var account corev1.ServiceAccount
			if err := k8sClient.Get(ctx, key, &account); err != nil {
				return err
			}
			account.Annotations[owner] = owningTeam
			return k8sClient.Update(ctx, &account)
		}, deployTimeout, deployPoll).Should(Succeed())

		Eventually(func() error {
			var obj configv1alpha1.CollectorRuntimeConfig
			if err := k8sClient.Get(ctx, client.ObjectKey{Name: config}, &obj); err != nil {
				return err
			}
			obj.Spec.ServiceAccountTemplate = &runtime.RawExtension{Raw: []byte(`{"metadata": {"annotations": {"iam.example/audience": "sts"}}}`)}
			return k8sClient.Update(ctx, &obj)
		}, deployTimeout, deployPoll).Should(Succeed())

		Eventually(func(g Gomega) map[string]string {
			var account corev1.ServiceAccount
			g.Expect(k8sClient.Get(ctx, key, &account)).To(Succeed())
			return account.Annotations
		}, deployTimeout, deployPoll).Should(And(
			Not(HaveKey("iam.example/role")),
			HaveKeyWithValue("iam.example/audience", "sts"),
			HaveKeyWithValue(owner, owningTeam),
		))
	})

	It("sets the image, the TLS volume and its mount, the ports and the contract's environment again after a template", func() {
		config := newRuntimeConfig(`{"spec": {"template": {"spec": {
			"containers": [{
				"name": "collector",
				"image": "artifacts.example/other:6.6.6",
				"env": [{"name": "VEXPLAIN_LISTEN", "value": ":1234"}],
				"ports": [{"containerPort": 9443, "$patch": "delete"}],
				"volumeMounts": [{"mountPath": "/run/vexplain/tls", "$patch": "delete"}]
			}],
			"volumes": [{"name": "vexplain-tls", "$patch": "delete"}]
		}}}}`, "")

		name := newCollector(shapedBy(config))

		d := deploymentOf(name)
		expectContract(name, d)
		var listens []corev1.EnvVar
		for _, env := range collectorContainer(d).Env {
			if env.Name == listenVariable {
				listens = append(listens, env)
			}
		}
		Expect(listens).To(ConsistOf(corev1.EnvVar{Name: listenVariable, Value: grpcListen}), "the template's :1234 is gone")
	})

	It("lets a template's own seccomp profile win, at the pod and at the container", func() {
		config := newRuntimeConfig(`{"spec": {"template": {"spec": {
			"securityContext": {"seccompProfile": {"type": "Localhost", "localhostProfile": "profiles/pod.json"}},
			"containers": [{"name": "collector", "securityContext": {"seccompProfile": {"type": "Localhost", "localhostProfile": "profiles/container.json"}}}]
		}}}}`, "")

		name := newCollector(shapedBy(config))

		d := deploymentOf(name)
		Expect(d.Spec.Template.Spec.SecurityContext.SeccompProfile).To(Equal(&corev1.SeccompProfile{
			Type: corev1.SeccompProfileTypeLocalhost, LocalhostProfile: ptr.To("profiles/pod.json")}))
		container := collectorContainer(d)
		Expect(container.SecurityContext.SeccompProfile).To(Equal(&corev1.SeccompProfile{
			Type: corev1.SeccompProfileTypeLocalhost, LocalhostProfile: ptr.To("profiles/container.json")}))
		Expect(container.SecurityContext.ReadOnlyRootFilesystem).To(HaveValue(BeTrue()), "the rest of the default stays")
	})

	It("gives the Deployment the default container back when a template takes the container named collector away", func() {
		config := newRuntimeConfig(`{"spec": {"template": {"spec": {"containers": [{"name": "collector", "$patch": "delete"}]}}}}`, "")

		name := newCollector(shapedBy(config))

		d := deploymentOf(name)
		expectContract(name, d)
		container := collectorContainer(d)
		Expect(container.ImagePullPolicy).To(Equal(corev1.PullIfNotPresent))
		Expect(container.SecurityContext).NotTo(BeNil())
		Expect(container.SecurityContext.ReadOnlyRootFilesystem).To(HaveValue(BeTrue()))
		Expect(container.SecurityContext.AllowPrivilegeEscalation).To(HaveValue(BeFalse()))
		Expect(container.ReadinessProbe).NotTo(BeNil())
		Expect(container.LivenessProbe).NotTo(BeNil())
		Expect(container.Resources.Requests.Cpu().Equal(resource.MustParse("10m"))).To(BeTrue())
	})

	DescribeTable("is RuntimeConfigInvalid for a template that doesn't decode, or that the API server refuses, and leaves what it deployed as it was",
		func(deployment, serviceAccount, says string) {
			config := newRuntimeConfig("", "")
			name := newCollector(shapedBy(config))
			expectReady(name, metav1.ConditionUnknown, configv1alpha1.ReasonProgressing)
			deployed := deploymentOf(name)

			Eventually(func() error {
				var obj configv1alpha1.CollectorRuntimeConfig
				if err := k8sClient.Get(ctx, client.ObjectKey{Name: config}, &obj); err != nil {
					return err
				}
				if deployment != "" {
					obj.Spec.DeploymentTemplate = &runtime.RawExtension{Raw: []byte(deployment)}
				}
				if serviceAccount != "" {
					obj.Spec.ServiceAccountTemplate = &runtime.RawExtension{Raw: []byte(serviceAccount)}
				}
				return k8sClient.Update(ctx, &obj)
			}, deployTimeout, deployPoll).Should(Succeed())

			_, ready := expectReady(name, metav1.ConditionFalse, configv1alpha1.ReasonRuntimeConfigInvalid)
			Expect(ready.Message).To(ContainSubstring(says))
			Expect(deploymentOf(name).ResourceVersion).To(Equal(deployed.ResourceVersion))
			Eventually(unhealthyEvents(name), deployTimeout, deployPoll).Should(HaveLen(1))

			By("deploying again once the template decodes")
			setTemplate(config, `{"spec": {"replicas": 1}}`)
			if serviceAccount != "" {
				Eventually(func() error {
					var obj configv1alpha1.CollectorRuntimeConfig
					if err := k8sClient.Get(ctx, client.ObjectKey{Name: config}, &obj); err != nil {
						return err
					}
					obj.Spec.ServiceAccountTemplate = nil
					return k8sClient.Update(ctx, &obj)
				}, deployTimeout, deployPoll).Should(Succeed())
			}
			expectReady(name, metav1.ConditionUnknown, configv1alpha1.ReasonProgressing)
		},
		Entry("a replica count that is no number", `{"spec": {"replicas": "one"}}`, "", "replicas"),
		Entry("a field that a Deployment doesn't have", `{"spec": {"template": {"spec": {"nodeSelectr": {}}}}}`, "", "nodeSelectr"),
		Entry("a list where a Deployment has an object", `{"spec": {"template": {"spec": {"containers": {"name": "collector"}}}}}`, "",
			"deployment template"),
		Entry("a service account template that sets more than labels and annotations", "",
			`{"metadata": {"name": "another"}}`, "service account template"),
		Entry("a CPU limit below zero, which the API server refuses",
			`{"spec": {"template": {"spec": {"containers": [{"name": "collector", "resources": {"limits": {"cpu": "-1"}}}]}}}}`, "",
			"must be greater than or equal to 0"),
	)

	It("is RuntimeConfigInvalid while the runtime config that a Collector names doesn't exist, and deploys it once it does", func() {
		missing := apiName("runtime")
		name := newCollector(shapedBy(missing))

		_, ready := expectReady(name, metav1.ConditionFalse, configv1alpha1.ReasonRuntimeConfigInvalid)
		Expect(ready.Message).To(ContainSubstring(missing))
		notDeployed(name)

		createObject(&configv1alpha1.CollectorRuntimeConfig{ObjectMeta: metav1.ObjectMeta{Name: missing}})
		deploymentOf(name)
		expectReady(name, metav1.ConditionUnknown, configv1alpha1.ReasonProgressing)
	})

	// A Collector that names no runtime config is shaped by the one named default.
	It("applies a change of the default runtime config to a Collector that names none", func() {
		name := newCollector(helloSpec(""))
		deploymentOf(name)
		Eventually(func() error {
			var config configv1alpha1.CollectorRuntimeConfig
			if err := k8sClient.Get(ctx, client.ObjectKey{Name: defaultRuntimeConfig}, &config); err != nil {
				return err
			}
			config.Spec.DeploymentTemplate = &runtime.RawExtension{
				Raw: []byte(`{"spec": {"template": {"spec": {"priorityClassName": "collectors"}}}}`),
			}
			return k8sClient.Update(ctx, &config)
		}, deployTimeout, deployPoll).Should(Succeed())
		DeferCleanup(func() {
			Eventually(func() error {
				var config configv1alpha1.CollectorRuntimeConfig
				if err := k8sClient.Get(ctx, client.ObjectKey{Name: defaultRuntimeConfig}, &config); err != nil {
					return err
				}
				config.Spec = configv1alpha1.CollectorRuntimeConfigSpec{}
				return k8sClient.Update(ctx, &config)
			}, deployTimeout, deployPoll).Should(Succeed())
		})

		Eventually(func() string {
			return deploymentOf(name).Spec.Template.Spec.PriorityClassName
		}, deployTimeout, deployPoll).Should(Equal("collectors"))
	})
})
