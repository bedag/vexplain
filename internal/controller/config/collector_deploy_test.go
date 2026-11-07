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
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gstruct"
	"github.com/onsi/gomega/types"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
	"github.com/bedag/vexplain/internal/collector/certs"
	configcontroller "github.com/bedag/vexplain/internal/controller/config"
)

// These specs check what the deployer makes for a Collector, through the manager that the suite starts: the objects
// of the collector's contract and their hardened defaults. envtest runs no controller of Deployments, so no pod runs.
var _ = Describe("Deploying a collector", func() {
	It("keeps a TLS Secret, a service account, a Service and a Deployment for the Collector, labelled and owned by it", func() {
		name := newCollector(helloSpec(""))
		var collector configv1alpha1.Collector
		Eventually(func(g Gomega) []string {
			g.Expect(k8sClient.Get(ctx, client.ObjectKey{Name: name}, &collector)).To(Succeed())
			return collector.Finalizers
		}, deployTimeout, deployPoll).Should(ContainElement(evidenceFinalizer), "the finalizer that deletes its evidence")
		inOperatorNamespace := func(objectName string) client.ObjectKey {
			return client.ObjectKey{Namespace: operatorNamespace, Name: objectName}
		}

		By("keeping its TLS Secret")
		var secret corev1.Secret
		Eventually(func(g Gomega) {
			g.Expect(k8sClient.Get(ctx, inOperatorNamespace(certs.SecretName(name)), &secret)).To(Succeed())
			g.Expect(secret.Labels).To(HaveKeyWithValue(collectorLabel, name))
			g.Expect(metav1.GetControllerOf(&secret)).NotTo(BeNil())
		}, deployTimeout, deployPoll).Should(Succeed())
		expectOwnedBy(&secret, &collector)
		Expect(secret.Type).To(Equal(corev1.SecretTypeTLS))
		Expect(secret.Data).To(HaveKey(corev1.TLSCertKey))

		By("keeping its service account")
		var account corev1.ServiceAccount
		Eventually(func() error {
			return k8sClient.Get(ctx, inOperatorNamespace(certs.ServiceName(name)), &account)
		}, deployTimeout, deployPoll).Should(Succeed())
		expectOwnedBy(&account, &collector)

		By("keeping its Service, on port 9443 for gRPC and on port 8081 for HTTP")
		var service corev1.Service
		Eventually(func() error {
			return k8sClient.Get(ctx, inOperatorNamespace(certs.ServiceName(name)), &service)
		}, deployTimeout, deployPoll).Should(Succeed())
		expectOwnedBy(&service, &collector)
		Expect(service.Spec.Selector).To(Equal(map[string]string{collectorLabel: name}))
		Expect(service.Spec.Ports).To(ConsistOf(
			And(HaveField("Name", "grpc"), HaveField("Port", int32(9443)), HaveField("TargetPort", intstr.FromString("grpc"))),
			And(HaveField("Name", "http"), HaveField("Port", int32(8081)), HaveField("TargetPort", intstr.FromString("http"))),
		))

		By("running it in a Deployment of one replica")
		d := deploymentOf(name)
		expectOwnedBy(d, &collector)
		Expect(d.Spec.Replicas).To(HaveValue(Equal(int32(1))))
		Expect(d.Spec.Selector.MatchLabels).To(Equal(map[string]string{collectorLabel: name}))
		Expect(d.Spec.Template.Labels).To(HaveKeyWithValue(collectorLabel, name))
		pod := d.Spec.Template.Spec
		Expect(pod.ServiceAccountName).To(Equal(certs.ServiceName(name)))
		Expect(pod.Containers).To(HaveLen(1))
		container := pod.Containers[0]
		Expect(container.Name).To(Equal("collector"))
		Expect(container.Image).To(Equal(examplePackage))

		By("giving it the environment of the contract, and no proxy variable: the operator passes none of its own")
		Expect(container.Env).To(ConsistOf(
			corev1.EnvVar{Name: "VEXPLAIN_COLLECTOR_NAME", Value: name},
			gstruct.MatchFields(gstruct.IgnoreExtras, gstruct.Fields{
				"Name":      Equal("POD_NAMESPACE"),
				"ValueFrom": HaveField("FieldRef.FieldPath", "metadata.namespace"),
			}),
			corev1.EnvVar{Name: listenVariable, Value: grpcListen},
			corev1.EnvVar{Name: "VEXPLAIN_HEALTH_LISTEN", Value: ":8081"},
			corev1.EnvVar{Name: "VEXPLAIN_TLS_DIR", Value: tlsDir},
		))
		Expect(container.Ports).To(ConsistOf(
			And(HaveField("Name", "grpc"), HaveField("ContainerPort", int32(9443))),
			And(HaveField("Name", "http"), HaveField("ContainerPort", int32(8081))),
		))

		By("mounting its TLS Secret as a directory, so that the kubelet updates the files of a renewed certificate")
		Expect(container.VolumeMounts).To(ConsistOf(
			And(HaveField("MountPath", tlsDir), HaveField("ReadOnly", true), HaveField("SubPath", BeEmpty())),
		))
		Expect(pod.Volumes).To(ConsistOf(And(
			HaveField("Name", container.VolumeMounts[0].Name),
			HaveField("VolumeSource.Secret.SecretName", certs.SecretName(name)),
		)))

		By("probing its readiness and its liveness on port 8081")
		Expect(container.ReadinessProbe).To(HaveField("ProbeHandler.HTTPGet", And(
			HaveField("Path", "/readyz"), HaveField("Port", intstr.FromString("http")))))
		Expect(container.LivenessProbe).To(HaveField("ProbeHandler.HTTPGet", And(
			HaveField("Path", "/healthz"), HaveField("Port", intstr.FromString("http")))))

		By("hardening it by default")
		Expect(pod.SecurityContext).NotTo(BeNil())
		Expect(pod.SecurityContext.RunAsNonRoot).To(HaveValue(BeTrue()))
		Expect(pod.SecurityContext.SeccompProfile).To(HaveField("Type", corev1.SeccompProfileTypeRuntimeDefault))
		Expect(container.SecurityContext).NotTo(BeNil())
		Expect(container.SecurityContext.SeccompProfile).To(HaveField("Type", corev1.SeccompProfileTypeRuntimeDefault),
			"the profile at the container too, as strict policies ask")
		Expect(container.SecurityContext.AllowPrivilegeEscalation).To(HaveValue(BeFalse()))
		Expect(container.SecurityContext.ReadOnlyRootFilesystem).To(HaveValue(BeTrue()))
		Expect(container.SecurityContext.Capabilities).To(HaveField("Drop", ConsistOf(corev1.Capability("ALL"))))
		Expect(container.ImagePullPolicy).To(Equal(corev1.PullIfNotPresent))
		Expect(container.Resources.Requests.Cpu().Equal(resource.MustParse("10m"))).To(BeTrue(), "a CPU request of 10m")
		Expect(container.Resources.Requests.Memory().Equal(resource.MustParse("64Mi"))).To(BeTrue(), "a memory request of 64Mi")
		Expect(container.Resources.Limits).To(BeEmpty(), "no limits, which a runtime config sets")

		By("waiting for the Deployment, which no controller of envtest makes available")
		expectReady(name, metav1.ConditionUnknown, configv1alpha1.ReasonProgressing)
	})

	// The deployer checks each collector at every resync, and writes what it keeps when it differs from what it wants.
	// What the API server fills in, or another controller adds, must be no difference, or the deployer and the API
	// server would change the object back and forth.
	It("leaves what it keeps as it is while nothing changes", func() {
		name := newCollector(helloSpec(""))
		expectReady(name, metav1.ConditionUnknown, configv1alpha1.ReasonProgressing)
		key := client.ObjectKey{Namespace: operatorNamespace, Name: certs.ServiceName(name)}
		versions := func(g Gomega) []string {
			var d appsv1.Deployment
			var service corev1.Service
			var account corev1.ServiceAccount
			var secret corev1.Secret
			g.Expect(k8sClient.Get(ctx, key, &d)).To(Succeed())
			g.Expect(k8sClient.Get(ctx, key, &service)).To(Succeed())
			g.Expect(k8sClient.Get(ctx, key, &account)).To(Succeed())
			g.Expect(k8sClient.Get(ctx, client.ObjectKey{Namespace: operatorNamespace, Name: certs.SecretName(name)},
				&secret)).To(Succeed())
			return []string{d.ResourceVersion, service.ResourceVersion, account.ResourceVersion, secret.ResourceVersion}
		}
		written := versions(Default)

		// The suite's deployer checks each collector every second.
		Consistently(versions, 4*time.Second, 500*time.Millisecond).Should(Equal(written))
	})

	// A write that changes nothing still costs a call of the API server, and of each webhook that it calls, at every
	// resync. So the deployer writes the spec of a Deployment only when it differs from what the API server holds,
	// whose defaults fill in what the deployer leaves out.
	It("writes the spec of a Deployment only when what it wants differs from what the API server holds", func() {
		name := newCollector(helloSpec(""))
		live := deploymentOf(name)
		var collector configv1alpha1.Collector
		Expect(k8sClient.Get(ctx, client.ObjectKey{Name: name}, &collector)).To(Succeed())
		desired := configcontroller.DefaultDeployment(&collector, operatorNamespace)

		Expect(configcontroller.WritesSpec(desired, live)).To(BeFalse(), "the API server's defaults are no difference")

		changed := desired.DeepCopy()
		changed.Spec.Template.Spec.NodeSelector = nil
		changed.Spec.Template.Spec.PriorityClassName = "collectors"
		Expect(configcontroller.WritesSpec(changed, live)).To(BeTrue(), "the deployer wants something else")
		edited := live.DeepCopy()
		edited.Spec.Template.Spec.Containers[0].Image = "artifacts.example/other:6.6.6"
		Expect(configcontroller.WritesSpec(desired, edited)).To(BeTrue(), "someone changed what the deployer sets")
		withoutHash := live.DeepCopy()
		delete(withoutHash.Annotations, "vexplain.bedag.ch/spec-hash")
		Expect(configcontroller.WritesSpec(desired, withoutHash)).To(BeTrue(), "nothing says what the deployer wrote")
	})

	It("creates the default runtime config empty at its start, and never overwrites it", func() {
		key := client.ObjectKey{Name: defaultRuntimeConfig}
		Eventually(func(g Gomega) configv1alpha1.CollectorRuntimeConfigSpec {
			var config configv1alpha1.CollectorRuntimeConfig
			g.Expect(k8sClient.Get(ctx, key, &config)).To(Succeed())
			return config.Spec
		}, deployTimeout, deployPoll).Should(BeZero())

		By("leaving a default that an admin changed as it is")
		var config configv1alpha1.CollectorRuntimeConfig
		Expect(k8sClient.Get(ctx, key, &config)).To(Succeed())
		template := `{"metadata":{"annotations":{"iam.example/role":"collector"}}}`
		config.Spec.ServiceAccountTemplate = &runtime.RawExtension{Raw: []byte(template)}
		Expect(k8sClient.Update(ctx, &config)).To(Succeed())
		DeferCleanup(func() {
			var changed configv1alpha1.CollectorRuntimeConfig
			Expect(k8sClient.Get(ctx, key, &changed)).To(Succeed())
			changed.Spec = configv1alpha1.CollectorRuntimeConfigSpec{}
			Expect(k8sClient.Update(ctx, &changed)).To(Succeed())
		})

		Expect(configcontroller.EnsureDefaultRuntimeConfig(ctx, k8sClient)).To(Succeed())

		Expect(k8sClient.Get(ctx, key, &config)).To(Succeed())
		Expect(config.Spec.ServiceAccountTemplate).NotTo(BeNil())
		Expect(config.Spec.ServiceAccountTemplate.Raw).To(MatchJSON(template))

		By("creating it again, empty, when it is missing")
		Expect(k8sClient.Delete(ctx, &config)).To(Succeed())
		Expect(configcontroller.EnsureDefaultRuntimeConfig(ctx, k8sClient)).To(Succeed())
		var created configv1alpha1.CollectorRuntimeConfig
		Expect(k8sClient.Get(ctx, key, &created)).To(Succeed())
		Expect(created.Spec).To(BeZero())
	})
})

// expectOwnedBy checks that obj carries the label of the Collector, and the Collector as its controller, so that the
// garbage collector deletes it with the Collector.
func expectOwnedBy(obj client.Object, collector *configv1alpha1.Collector) {
	GinkgoHelper()
	Expect(obj.GetLabels()).To(HaveKeyWithValue(collectorLabel, collector.Name))
	Expect(metav1.GetControllerOf(obj)).To(ownerReferenceTo(collector))
}

// ownerReferenceTo matches an owner reference to the Collector.
func ownerReferenceTo(collector *configv1alpha1.Collector) types.GomegaMatcher {
	return gstruct.PointTo(And(
		HaveField("APIVersion", configv1alpha1.GroupVersion.String()),
		HaveField("Kind", "Collector"),
		HaveField("Name", collector.Name),
		HaveField("UID", collector.UID),
		HaveField("Controller", ptr.To(true)),
	))
}

// notDeployed checks, for a while, that the deployer keeps no Deployment for the Collector of the name.
func notDeployed(name string) {
	GinkgoHelper()
	Consistently(func() error {
		return k8sClient.Get(ctx, client.ObjectKey{Namespace: operatorNamespace, Name: certs.ServiceName(name)},
			&appsv1.Deployment{})
	}, 3*time.Second, 500*time.Millisecond).Should(Satisfy(apierrors.IsNotFound))
}
