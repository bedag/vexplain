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
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
	"github.com/bedag/vexplain/internal/collector/certs"
	"github.com/bedag/vexplain/internal/evidence"
	"github.com/bedag/vexplain/sdk/workloads"
)

// The deployer keeps, in the operator's namespace, a Deployment, a Service and a service account for each collector.
// It labels and owns the collector's TLS Secret, which the Authority writes, reads it through the API reader, since
// the manager's cache holds only the Secrets of the LLM keys, and deletes it with its Collector. It reads the pods of a
// collector too, whose status says which digest runs. Markers generate no bindings:
// config/rbac/manager_secrets_rolebinding.yaml binds the Role.
// +kubebuilder:rbac:groups=apps,resources=deployments,verbs=get;list;watch;create;update,namespace=vexplain-system
// +kubebuilder:rbac:groups="",resources=services;serviceaccounts,verbs=get;list;watch;create;update,namespace=vexplain-system
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;update;delete,namespace=vexplain-system
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
	// templateKeysAnnotation records the keys of the labels and the annotations that the deployer took from a runtime
	// config's template, as kubectl's last applied configuration records what it applied: a key that a later template
	// no longer sets goes, such as the annotation of a cloud identity that an admin took away, and a key that someone
	// else set stays.
	templateKeysAnnotation = "vexplain.bedag.ch/template-keys"
	// progressDeadlineExceeded is the reason of a Deployment's Progressing condition once its rollout has made no
	// progress within its progress deadline, and newReplicaSetAvailable its reason once the rollout has completed, as
	// the Deployment controller sets them. The latter stays until the next rollout.
	progressDeadlineExceeded = "ProgressDeadlineExceeded"
	newReplicaSetAvailable   = "NewReplicaSetAvailable"
)

// The default requests of the collector's container: what a collector needs to run idle. It gets no limits, since
// what a collector needs depends on what it does: a runtime config sets them.
var (
	defaultCPURequest    = resource.MustParse("10m")
	defaultMemoryRequest = resource.MustParse("64Mi")
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
// shapes it: one replica of the default container, running as the collector's service account, as non-root and with
// the RuntimeDefault seccomp profile.
func defaultDeployment(obj *configv1alpha1.Collector, namespace string) *appsv1.Deployment {
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
					Containers: []corev1.Container{defaultContainer(obj)},
					Volumes:    []corev1.Volume{tlsSecretVolume(obj.Name)},
				},
			},
		},
	}
}

// defaultContainer returns the container named collector before a runtime config shapes it: hardened, with the
// collector's contract, its probes, the default requests. It sets no proxy: a collector's runtime config does (decision 0037).
func defaultContainer(obj *configv1alpha1.Collector) corev1.Container {
	return corev1.Container{
		Name:            collectorContainer,
		Image:           obj.Spec.Package,
		ImagePullPolicy: corev1.PullIfNotPresent,
		Ports:           contractPorts(),
		Env:             contractEnv(obj.Name),
		VolumeMounts:    []corev1.VolumeMount{tlsMount()},
		ReadinessProbe:  httpProbe("/readyz"),
		LivenessProbe:   httpProbe("/healthz"),
		Resources: corev1.ResourceRequirements{Requests: corev1.ResourceList{
			corev1.ResourceCPU:    defaultCPURequest.DeepCopy(),
			corev1.ResourceMemory: defaultMemoryRequest.DeepCopy(),
		}},
		SecurityContext: &corev1.SecurityContext{
			AllowPrivilegeEscalation: ptr.To(false),
			ReadOnlyRootFilesystem:   ptr.To(true),
			Capabilities:             &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
			// Set at the pod as well: a strict Pod Security policy, Kyverno's for one, asks for the profile at both.
			SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
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
// named collector, the image of the package, the TLS volume and its mount, the ports and the contract's environment.
// A template that took the container away gets the default container back, hardened. The rest of the container and of
// the pod stays as the template shaped it.
func setContract(d *appsv1.Deployment, obj *configv1alpha1.Collector, namespace string) {
	d.Namespace, d.Name = namespace, certs.ServiceName(obj.Name)
	// These say what the deployer wrote, so no template sets them.
	delete(d.Annotations, specHashAnnotation)
	delete(d.Annotations, templateKeysAnnotation)
	labels := collectorLabels(obj.Name)
	d.Labels = withEntries(d.Labels, labels)
	d.Spec.Selector = &metav1.LabelSelector{MatchLabels: labels}
	d.Spec.Template.Labels = withEntries(d.Spec.Template.Labels, labels)

	pod := &d.Spec.Template.Spec
	if containerOf(pod) == nil {
		pod.Containers = append(pod.Containers, defaultContainer(obj))
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

// applyTemplateMetadata gives meta the labels and the annotations of a template, and takes away those that the
// deployer gave it from an earlier template and that this one no longer sets, as templateKeysAnnotation records them.
// What others set stays. The keys of the deployer's own labels and annotations are no template's.
func applyTemplateMetadata(meta *metav1.ObjectMeta, labels, annotations map[string]string) {
	labels, annotations = maps.Clone(labels), maps.Clone(annotations)
	delete(labels, evidence.CollectorLabel)
	delete(annotations, specHashAnnotation)
	delete(annotations, templateKeysAnnotation)
	var earlier templateKeys
	// A record that doesn't decode, which only a change by hand makes, takes nothing away.
	_ = json.Unmarshal([]byte(meta.Annotations[templateKeysAnnotation]), &earlier)
	for _, key := range earlier.Labels {
		if _, kept := labels[key]; !kept {
			delete(meta.Labels, key)
		}
	}
	for _, key := range earlier.Annotations {
		if _, kept := annotations[key]; !kept {
			delete(meta.Annotations, key)
		}
	}
	if len(labels) > 0 {
		meta.Labels = withEntries(meta.Labels, labels)
	}
	if len(annotations) > 0 {
		meta.Annotations = withEntries(meta.Annotations, annotations)
	}
	given := templateKeys{Labels: slices.Sorted(maps.Keys(labels)), Annotations: slices.Sorted(maps.Keys(annotations))}
	if len(given.Labels)+len(given.Annotations) == 0 {
		delete(meta.Annotations, templateKeysAnnotation)
		return
	}
	// Two lists of strings always encode.
	record, _ := json.Marshal(given)
	meta.Annotations = withEntries(meta.Annotations, map[string]string{templateKeysAnnotation: string(record)})
}

// templateKeys are the keys of the labels and the annotations that the deployer took from a template, each sorted.
type templateKeys struct {
	Labels      []string `json:"labels,omitempty"`
	Annotations []string `json:"annotations,omitempty"`
}

// applyServiceAccount creates or updates the collector's service account: the labels of the collector and the
// metadata of the runtime config's template.
func (r *CollectorReconciler) applyServiceAccount(ctx context.Context, obj *configv1alpha1.Collector, shaped *shape) error {
	account := &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Namespace: r.OperatorNamespace, Name: certs.ServiceName(obj.Name)}}
	_, err := controllerutil.CreateOrUpdate(ctx, r.Client, account, func() error {
		applyTemplateMetadata(&account.ObjectMeta, shaped.accountLabels, shaped.accountAnnotations)
		account.Labels = withEntries(account.Labels, collectorLabels(obj.Name))
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
// defaults that desired leaves out, and the live spec never equals desired. The labels and the annotations of desired
// are those of the template, and the collector's label, which applyTemplateMetadata applies, so that those of the
// Deployment controller stay.
func (r *CollectorReconciler) applyDeployment(ctx context.Context, obj *configv1alpha1.Collector,
	desired *appsv1.Deployment) (*appsv1.Deployment, error) {
	hash, err := specHash(&desired.Spec)
	if err != nil {
		return nil, err
	}
	live := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Namespace: desired.Namespace, Name: desired.Name}}
	_, err = controllerutil.CreateOrUpdate(ctx, r.Client, live, func() error {
		applyTemplateMetadata(&live.ObjectMeta, desired.Labels, desired.Annotations)
		live.Labels = withEntries(live.Labels, collectorLabels(obj.Name))
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

// rolloutOf says how far the rollout of the collector's Deployment has got, as kubectl's rollout status says it. It is
// in progress while the Deployment controller hasn't seen the spec, while fewer replicas run it than the Deployment
// wants, while an older one is left, and while a replica that runs it is still starting: the collector that answers
// may then be an older one, or none yet. failure says why the collector can't be reached, if it can't: the rollout
// exceeded its progress deadline, as a start that never finishes does, or a replica isn't available after the rollout
// completed, as when its container crash-loops or is killed for its memory. The SDK's server answers its health check
// with SERVING until it stops, so the Deployment is where such a failure shows.
func rolloutOf(d *appsv1.Deployment) (inProgress bool, failure error) {
	s := d.Status
	if s.ObservedGeneration < d.Generation {
		return true, nil
	}
	progress := ""
	for _, c := range s.Conditions {
		if c.Type != appsv1.DeploymentProgressing {
			continue
		}
		if progress = c.Reason; c.Reason == progressDeadlineExceeded {
			return false, fmt.Errorf("the rollout of the collector's Deployment exceeded its progress deadline: %s", c.Message)
		}
	}
	if s.UpdatedReplicas < ptr.Deref(d.Spec.Replicas, 1) || s.Replicas > s.UpdatedReplicas {
		return true, nil
	}
	if s.AvailableReplicas < s.UpdatedReplicas {
		if progress != newReplicaSetAvailable {
			return true, nil
		}
		return false, fmt.Errorf("the collector's Deployment has %d of %d replicas available", s.AvailableReplicas, s.UpdatedReplicas)
	}
	return false, nil
}

// runningDigest returns the digest that the collector's newest pod reports for the image of its container named
// collector, or nil when no pod reports one, such as before its container has started. A bare image ID, without a
// repository, is the digest of the image's configuration, which names no package, so it counts as none.
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
			if ref, ok := workloads.DigestFromImageID(status.ImageID); ok && !ref.IsImageID() && status.Name == collectorContainer {
				newest, digest = pod, ref.Digest
			}
		}
	}
	if newest == nil {
		return nil, nil
	}
	return &digest, nil
}
