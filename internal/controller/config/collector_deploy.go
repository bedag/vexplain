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

package config

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"maps"
	"slices"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
	"github.com/bedag/vexplain/internal/collector/certs"
	"github.com/bedag/vexplain/internal/evidence"
	"github.com/bedag/vexplain/internal/workloads"
)

// The deployer keeps, in the operator's namespace, a Deployment, a Service and a service account for each collector.
// It labels and owns the collector's TLS Secret, which the Authority writes, and reads it through the API reader,
// since the manager's cache holds only the Secrets of the LLM keys. It reads the pods of a collector too, whose status
// says which digest runs. Markers generate no bindings: config/rbac/manager_secrets_rolebinding.yaml binds the Role.
// +kubebuilder:rbac:groups=apps,resources=deployments,verbs=get;list;watch;create;update,namespace=vexplain-system
// +kubebuilder:rbac:groups="",resources=services;serviceaccounts,verbs=get;list;watch;create;update,namespace=vexplain-system
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;update,namespace=vexplain-system
// +kubebuilder:rbac:groups="",resources=pods,verbs=get;list;watch,namespace=vexplain-system

// The collector's contract: what the SDK's server expects of the Deployment that runs it, and what the operator
// expects of the collector.
const (
	// collectorContainer is the name of the container that runs the collector, which a template names to change it.
	collectorContainer = "collector"
	// grpcPort serves the collector API over mutual TLS, and healthPort serves /healthz, /readyz and /metrics in
	// plain HTTP, since the kubelet's probes can't present a client certificate.
	grpcPort   = 9443
	healthPort = 8081
	// grpcPortName and healthPortName name the ports of the container and of the Service.
	grpcPortName   = "grpc"
	healthPortName = "http"
	// tlsVolume is the volume of the collector's TLS Secret, which tlsDir mounts.
	tlsVolume = "vexplain-tls"
	tlsDir    = "/run/vexplain/tls"
	// specHashAnnotation holds the hash of the spec that the deployer last wrote into a Deployment, so that a change of
	// a template, which may take a field away, is written, and nothing is written while nothing changes.
	specHashAnnotation = "vexplain.bedag.ch/spec-hash"
)

// collectorLabels are the labels of what the deployer makes for a collector: the name of its Collector, under the
// same key as the evidence that the collector delivers. They select the collector's pods too.
func collectorLabels(collector string) map[string]string {
	return map[string]string{evidence.CollectorLabel: collector}
}

// contractEnv is the environment that the collector's contract sets: the collector's name, its namespace, where it
// listens and where it finds its TLS files, as the SDK's OptionsFromEnv reads them.
func contractEnv(collector string) []corev1.EnvVar {
	return []corev1.EnvVar{
		{Name: "VEXPLAIN_COLLECTOR_NAME", Value: collector},
		{Name: "POD_NAMESPACE", ValueFrom: &corev1.EnvVarSource{FieldRef: &corev1.ObjectFieldSelector{FieldPath: "metadata.namespace"}}},
		{Name: "VEXPLAIN_LISTEN", Value: fmt.Sprintf(":%d", grpcPort)},
		{Name: "VEXPLAIN_HEALTH_LISTEN", Value: fmt.Sprintf(":%d", healthPort)},
		{Name: "VEXPLAIN_TLS_DIR", Value: tlsDir},
	}
}

// contractPorts are the ports of the collector's container.
func contractPorts() []corev1.ContainerPort {
	return []corev1.ContainerPort{
		{Name: grpcPortName, ContainerPort: grpcPort, Protocol: corev1.ProtocolTCP},
		{Name: healthPortName, ContainerPort: healthPort, Protocol: corev1.ProtocolTCP},
	}
}

// tlsMount mounts the collector's TLS Secret as a directory. A mount with a subPath would never see a renewed
// certificate: the kubelet updates the files of a Secret only in a directory that it mounts whole.
func tlsMount() corev1.VolumeMount {
	return corev1.VolumeMount{Name: tlsVolume, MountPath: tlsDir, ReadOnly: true}
}

// defaultDeployment returns the Deployment that the deployer runs the collector of obj in before a runtime config
// shapes it: one replica, hardened, with the collector's contract, its probes and the manager's proxy variables.
func defaultDeployment(obj *configv1alpha1.Collector, namespace string, proxyEnv []corev1.EnvVar) *appsv1.Deployment {
	name := certs.ServiceName(obj.Name)
	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name, Labels: collectorLabels(obj.Name)},
		Spec: appsv1.DeploymentSpec{
			Replicas: ptr.To[int32](1),
			Selector: &metav1.LabelSelector{MatchLabels: collectorLabels(obj.Name)},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: collectorLabels(obj.Name)},
				Spec: corev1.PodSpec{
					ServiceAccountName: name,
					SecurityContext: &corev1.PodSecurityContext{
						RunAsNonRoot:   ptr.To(true),
						SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
					},
					Containers: []corev1.Container{{
						Name:            collectorContainer,
						Image:           obj.Spec.Package,
						ImagePullPolicy: corev1.PullIfNotPresent,
						Ports:           contractPorts(),
						Env:             append(contractEnv(obj.Name), proxyEnv...),
						VolumeMounts:    []corev1.VolumeMount{tlsMount()},
						ReadinessProbe:  httpProbe("/readyz"),
						LivenessProbe:   httpProbe("/healthz"),
						SecurityContext: &corev1.SecurityContext{
							AllowPrivilegeEscalation: ptr.To(false),
							ReadOnlyRootFilesystem:   ptr.To(true),
							Capabilities:             &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
						},
					}},
					Volumes: []corev1.Volume{tlsSecretVolume(obj.Name)},
				},
			},
		},
	}
}

// httpProbe probes path on the collector's HTTP port.
func httpProbe(path string) *corev1.Probe {
	return &corev1.Probe{ProbeHandler: corev1.ProbeHandler{
		HTTPGet: &corev1.HTTPGetAction{Path: path, Port: intstr.FromString(healthPortName)},
	}}
}

// tlsSecretVolume is the volume of the collector's TLS Secret.
func tlsSecretVolume(collector string) corev1.Volume {
	return corev1.Volume{Name: tlsVolume, VolumeSource: corev1.VolumeSource{
		Secret: &corev1.SecretVolumeSource{SecretName: certs.SecretName(collector)},
	}}
}

// setContract sets again what the collector's contract needs of d, whatever a template made of it: its name, its
// labels and its selector, by which the Service and the deployer find the collector's pods; and, of the container
// named collector, which it adds when a template took it away, the image of the package, the TLS volume and its
// mount, the ports and the contract's environment. The rest of the container and of the pod stays as the template
// shaped it.
func setContract(d *appsv1.Deployment, obj *configv1alpha1.Collector, namespace string) {
	d.Namespace, d.Name = namespace, certs.ServiceName(obj.Name)
	// The hash says what the deployer wrote, so no template sets it.
	delete(d.Annotations, specHashAnnotation)
	labels := collectorLabels(obj.Name)
	d.Labels = withEntries(d.Labels, labels)
	d.Spec.Selector = &metav1.LabelSelector{MatchLabels: labels}
	d.Spec.Template.Labels = withEntries(d.Spec.Template.Labels, labels)

	pod := &d.Spec.Template.Spec
	if containerOf(pod) == nil {
		pod.Containers = append(pod.Containers, corev1.Container{Name: collectorContainer})
	}
	container := containerOf(pod)
	container.Image = obj.Spec.Package

	ports := contractPorts()
	container.Ports = append(ports, slices.DeleteFunc(container.Ports, func(p corev1.ContainerPort) bool {
		return slices.ContainsFunc(ports, func(contract corev1.ContainerPort) bool {
			return p.Name == contract.Name || p.ContainerPort == contract.ContainerPort
		})
	})...)
	env := contractEnv(obj.Name)
	container.Env = append(env, slices.DeleteFunc(container.Env, func(e corev1.EnvVar) bool {
		return slices.ContainsFunc(env, func(contract corev1.EnvVar) bool { return e.Name == contract.Name })
	})...)
	mount := tlsMount()
	container.VolumeMounts = append(slices.DeleteFunc(container.VolumeMounts, func(m corev1.VolumeMount) bool {
		return m.Name == mount.Name || m.MountPath == mount.MountPath
	}), mount)
	volume := tlsSecretVolume(obj.Name)
	pod.Volumes = append(slices.DeleteFunc(pod.Volumes, func(v corev1.Volume) bool { return v.Name == volume.Name }), volume)
}

// withEntries returns m with the entries of add, which replace those of the same keys.
func withEntries(m, add map[string]string) map[string]string {
	if m == nil {
		m = make(map[string]string, len(add))
	}
	maps.Copy(m, add)
	return m
}

// applyServiceAccount creates or updates the collector's service account: the labels of the collector and the
// metadata of the runtime config's template. It adds the template's labels and annotations, and takes none away,
// so that what others set stays.
func (r *CollectorReconciler) applyServiceAccount(ctx context.Context, obj *configv1alpha1.Collector, shaped *shape) error {
	account := &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Namespace: r.OperatorNamespace, Name: certs.ServiceName(obj.Name)}}
	_, err := controllerutil.CreateOrUpdate(ctx, r.Client, account, func() error {
		account.Labels = withEntries(withEntries(account.Labels, shaped.accountLabels), collectorLabels(obj.Name))
		if len(shaped.accountAnnotations) > 0 {
			account.Annotations = withEntries(account.Annotations, shaped.accountAnnotations)
		}
		return controllerutil.SetControllerReference(obj, account, r.Scheme)
	})
	if err != nil {
		return fmt.Errorf("write the service account of collector %s: %w", obj.Name, err)
	}
	return nil
}

// applyService creates or updates the collector's Service, through which the operator reaches the collector API, on
// port 9443, and the collector's HTTP port, 8081.
func (r *CollectorReconciler) applyService(ctx context.Context, obj *configv1alpha1.Collector) error {
	service := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Namespace: r.OperatorNamespace, Name: certs.ServiceName(obj.Name)}}
	_, err := controllerutil.CreateOrUpdate(ctx, r.Client, service, func() error {
		service.Labels = withEntries(service.Labels, collectorLabels(obj.Name))
		service.Spec.Selector = collectorLabels(obj.Name)
		service.Spec.Ports = []corev1.ServicePort{
			{Name: grpcPortName, Protocol: corev1.ProtocolTCP, Port: grpcPort, TargetPort: intstr.FromString(grpcPortName)},
			{Name: healthPortName, Protocol: corev1.ProtocolTCP, Port: healthPort, TargetPort: intstr.FromString(healthPortName)},
		}
		return controllerutil.SetControllerReference(obj, service, r.Scheme)
	})
	if err != nil {
		return fmt.Errorf("write the Service of collector %s: %w", obj.Name, err)
	}
	return nil
}

// applyDeployment creates or updates the collector's Deployment from desired, and returns it as the API server
// holds it. It writes the spec only when specWanted says so, and otherwise nothing, since the API server fills in
// defaults that desired leaves out, and the live spec never equals desired. It adds the labels and annotations of
// desired, and takes none away, so that those of the Deployment controller stay.
func (r *CollectorReconciler) applyDeployment(ctx context.Context, obj *configv1alpha1.Collector,
	desired *appsv1.Deployment) (*appsv1.Deployment, error) {
	hash, err := specHash(&desired.Spec)
	if err != nil {
		return nil, err
	}
	live := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Namespace: desired.Namespace, Name: desired.Name}}
	_, err = controllerutil.CreateOrUpdate(ctx, r.Client, live, func() error {
		live.Labels = withEntries(live.Labels, desired.Labels)
		if len(desired.Annotations) > 0 {
			live.Annotations = withEntries(live.Annotations, desired.Annotations)
		}
		if specWanted(desired, hash, live) {
			live.Spec = *desired.Spec.DeepCopy()
			live.Annotations = withEntries(live.Annotations, map[string]string{specHashAnnotation: hash})
		}
		return controllerutil.SetControllerReference(obj, live, r.Scheme)
	})
	if err != nil {
		return nil, fmt.Errorf("write the Deployment of collector %s: %w", obj.Name, err)
	}
	return live, nil
}

// specWanted says whether the deployer writes the spec of desired, whose hash is hash, over live, the Deployment as
// the API server holds it: when desired changed since the deployer last wrote it, as the hash in live's annotation
// says, or when live no longer holds the collector's contract as desired sets it, as after a change by hand.
//
// The rest of live isn't compared: the API server fills in defaults that desired leaves out, such as the timings of a
// probe, and a comparison would find them different at every resync, and write the same spec again each time.
func specWanted(desired *appsv1.Deployment, hash string, live *appsv1.Deployment) bool {
	return live.Annotations[specHashAnnotation] != hash || !keepsContract(&desired.Spec.Template.Spec, &live.Spec.Template.Spec)
}

// keepsContract says whether the pod of live holds what the pod of desired sets of the collector's contract: the
// container named collector with its image, its environment, its ports and its mounts, and the volumes. A field that
// desired leaves empty, and the API server fills in, is no difference.
func keepsContract(desired, live *corev1.PodSpec) bool {
	want, have := containerOf(desired), containerOf(live)
	return want != nil && have != nil && want.Image == have.Image &&
		equality.Semantic.DeepDerivative(want.Env, have.Env) &&
		equality.Semantic.DeepDerivative(want.Ports, have.Ports) &&
		equality.Semantic.DeepDerivative(want.VolumeMounts, have.VolumeMounts) &&
		equality.Semantic.DeepDerivative(desired.Volumes, live.Volumes)
}

// containerOf returns the container named collector of pod, or nil.
func containerOf(pod *corev1.PodSpec) *corev1.Container {
	i := slices.IndexFunc(pod.Containers, func(c corev1.Container) bool { return c.Name == collectorContainer })
	if i < 0 {
		return nil
	}
	return &pod.Containers[i]
}

// specHash returns the hash of a Deployment's spec, as the deployer writes it.
func specHash(spec *appsv1.DeploymentSpec) (string, error) {
	raw, err := json.Marshal(spec)
	if err != nil {
		return "", fmt.Errorf("encode the spec of a Deployment: %w", err)
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

// ownSecret gives the collector's TLS Secret, which the Authority creates and renews, the collector's labels and the
// Collector as its controller, so that the garbage collector deletes it with the Collector. The Authority changes the
// data of a Secret only, so what this sets stays.
func (r *CollectorReconciler) ownSecret(ctx context.Context, obj *configv1alpha1.Collector) error {
	var secret corev1.Secret
	key := client.ObjectKey{Namespace: r.OperatorNamespace, Name: certs.SecretName(obj.Name)}
	if err := r.APIReader.Get(ctx, key, &secret); err != nil {
		return fmt.Errorf("read the TLS Secret of collector %s: %w", obj.Name, err)
	}
	before := secret.DeepCopy()
	secret.Labels = withEntries(secret.Labels, collectorLabels(obj.Name))
	if err := controllerutil.SetControllerReference(obj, &secret, r.Scheme); err != nil {
		return fmt.Errorf("own the TLS Secret of collector %s: %w", obj.Name, err)
	}
	if equality.Semantic.DeepEqual(before.ObjectMeta, secret.ObjectMeta) {
		return nil
	}
	if err := r.Update(ctx, &secret); err != nil {
		return fmt.Errorf("own the TLS Secret of collector %s: %w", obj.Name, err)
	}
	return nil
}

// available says whether the Deployment has rolled out, as kubectl's rollout status says it: the Deployment
// controller has seen its spec, and every replica runs it and is available, with no older one left. Before, the
// collector that answers may be an older one.
func available(d *appsv1.Deployment) bool {
	s := d.Status
	return s.ObservedGeneration >= d.Generation &&
		s.UpdatedReplicas >= ptr.Deref(d.Spec.Replicas, 1) &&
		s.Replicas <= s.UpdatedReplicas &&
		s.AvailableReplicas >= s.UpdatedReplicas
}

// runningDigest returns the digest that the collector's newest pod reports for the image of its container named
// collector, or nil when no pod reports one, such as before its container has started.
func (r *CollectorReconciler) runningDigest(ctx context.Context, obj *configv1alpha1.Collector) (*string, error) {
	var pods corev1.PodList
	if err := r.List(ctx, &pods, client.InNamespace(r.OperatorNamespace), client.MatchingLabels(collectorLabels(obj.Name))); err != nil {
		return nil, fmt.Errorf("list the pods of collector %s: %w", obj.Name, err)
	}
	var newest *corev1.Pod
	var digest string
	for i := range pods.Items {
		pod := &pods.Items[i]
		if !pod.DeletionTimestamp.IsZero() || (newest != nil && !pod.CreationTimestamp.After(newest.CreationTimestamp.Time)) {
			continue
		}
		for _, status := range pod.Status.ContainerStatuses {
			if ref, ok := workloads.DigestFromImageID(status.ImageID); ok && status.Name == collectorContainer {
				newest, digest = pod, ref.Digest
			}
		}
	}
	if newest == nil {
		return nil, nil
	}
	return &digest, nil
}
