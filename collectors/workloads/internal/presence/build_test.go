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

package presence

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/rand"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/bedag/vexplain/sdk/collector"
	"github.com/bedag/vexplain/sdk/evidence"
)

// buildFor builds the presence of the cluster as a Watch with the context sees it.
func buildFor(t *testing.T, c collector.Context) state {
	t.Helper()
	_, informers := startAPI(t)
	r, err := rulesOf(c)
	require.NoError(t, err)
	built, err := build(t.Context(), informers, r)
	require.NoError(t, err)
	return built
}

func TestADeploymentsImageListsTheDeploymentWithItsUIDAndItsPods(t *testing.T) {
	ns := newNamespace(t, nil, nil).Name
	d, rs := deployment(t, ns)
	digest := newDigest()
	owner := controlledBy(rs, "apps/v1", "ReplicaSet")
	pod{namespace: ns, name: "web-5d8f9-b", node: nodeARM64, owner: owner}.run(t, digest)
	pod{namespace: ns, name: "web-5d8f9-a", node: nodeAMD64, owner: owner}.run(t, digest)

	got := buildFor(t, contextFor("vexplain-system", everything, "")).images[digest]

	require.Equal(t, evidence.Presence{
		DigestKind:   evidence.DigestKindRepoDigest,
		Repositories: []string{repository},
		Workloads: []evidence.PresenceWorkload{{
			APIGroup: appsv1.GroupName, Kind: "Deployment", Namespace: ns, Name: web, UID: string(d.UID),
			Pods: []evidence.PresencePod{
				{Name: "web-5d8f9-a", Node: nodeAMD64, Platform: platformAMD64, Containers: appContainers},
				{Name: "web-5d8f9-b", Node: nodeARM64, Platform: platformARM64, Containers: appContainers},
			},
		}},
	}, got)
}

// A kubelet creates a mirror pod in the API server for each static pod of its node, and makes the node its
// controller. A node is no workload: each mirror pod is a workload of its own, of kind Pod.
func TestAMirrorPodIsItsOwnWorkload(t *testing.T) {
	c, _ := startAPI(t)
	ns := newNamespace(t, nil, nil).Name
	var node corev1.Node
	require.NoError(t, c.Get(t.Context(), client.ObjectKey{Name: nodeAMD64}, &node))
	digest := newDigest()
	mirror := pod{
		namespace: ns, name: "etcd-" + nodeAMD64, node: nodeAMD64,
		annotations: map[string]string{corev1.MirrorPodAnnotationKey: "4f5c8a"},
		owner:       controlledBy(&node, "v1", "Node"),
	}.run(t, digest)

	got := buildFor(t, contextFor("vexplain-system", everything, "")).images[digest]

	require.Equal(t, []evidence.PresenceWorkload{{
		Kind: "Pod", Namespace: ns, Name: mirror.Name, UID: string(mirror.UID),
		Pods: []evidence.PresencePod{{Name: mirror.Name, Node: nodeAMD64, Platform: platformAMD64, Containers: appContainers}},
	}}, got.Workloads)
}

// vexplain's own pods, such as its scan pods, run images too, and are no workloads of the cluster. The context names
// their label, which counts only in vexplain's namespace: anyone who can create pods can set a label, and would hide a
// workload with it otherwise.
func TestAScanPodInTheOperatorsNamespaceIsSkipped(t *testing.T) {
	operatorNamespace := newNamespace(t, nil, nil).Name
	elsewhere := newNamespace(t, nil, nil).Name
	scanned, labelled := newDigest(), newDigest()
	scanLabels := map[string]string{taskLabel: "scan"}
	pod{namespace: operatorNamespace, name: "scan-x2k4p", node: nodeAMD64, labels: scanLabels}.run(t, scanned)
	pod{namespace: elsewhere, name: appPod, node: nodeAMD64, labels: scanLabels}.run(t, labelled)

	got := buildFor(t, contextFor(operatorNamespace, everything, "")).images

	require.NotContains(t, got, scanned, "the scan pod runs in vexplain's namespace")
	require.Contains(t, got, labelled, "the label counts only in vexplain's namespace")
}

// The scope of the context narrows what the collector reports, as OperatorConfig's spec.scope says: a namespace that
// it excludes drops out, with its pods, and so does the image that no pod in scope runs any more.
func TestANamespaceThatTheScopeExcludesDropsOut(t *testing.T) {
	excluded := newNamespace(t, map[string]string{"vexplain": "off"}, nil).Name
	included := newNamespace(t, nil, nil).Name
	onlyExcluded, shared := newDigest(), newDigest()
	pod{namespace: excluded, name: appPod, node: nodeAMD64}.run(t, onlyExcluded)
	pod{namespace: excluded, name: otherAppPod, node: nodeAMD64}.run(t, shared)
	pod{namespace: included, name: otherAppPod, node: nodeAMD64}.run(t, shared)
	scope := json.RawMessage(`{"excludeNamespaces": {"matchLabels": {"vexplain": "off"}}}`)

	got := buildFor(t, contextFor("vexplain-system", scope, "")).images

	require.NotContains(t, got, onlyExcluded)
	require.Len(t, got[shared].Workloads, 1)
	require.Equal(t, included, got[shared].Workloads[0].Namespace)
}

// Owner attribution copies the labels and annotations that its allowlists name, and nothing else: an annotation can
// hold a contact's address. A workload's labels are those of its pods, which carry the labels of the workload's pod
// template: the collector reads no other kind of workload than pods, ReplicaSets and Jobs.
func TestAnAllowlistedNamespaceLabelIsCopiedAndAnotherLabelIsnt(t *testing.T) {
	ns := newNamespace(t,
		map[string]string{teamLabel: team, "tier": "frontend"},
		map[string]string{contactAnnotation: contact, "description": "kept out"},
	).Name
	digest := newDigest()
	pod{namespace: ns, name: appPod, node: nodeAMD64,
		labels: map[string]string{partOf: shop, appLabel: web}}.run(t, digest)
	attribution := `{"namespaceLabels": ["team"], "namespaceAnnotations": ["contact"],
		"workloadLabels": ["` + partOf + `", "` + costCenter + `"]}`

	got := buildFor(t, contextFor("vexplain-system", everything, attribution)).images[digest]

	require.Len(t, got.Workloads, 1)
	w := got.Workloads[0]
	require.Equal(t, []evidence.KeyValue{{Key: teamLabel, Value: team}}, w.NamespaceLabels)
	require.Equal(t, []evidence.KeyValue{{Key: contactAnnotation, Value: contact}},
		w.NamespaceAnnotations)
	require.Equal(t, []evidence.KeyValue{{Key: partOf, Value: shop}}, w.Labels, "a bare pod's labels are its own")
}

// Without allowlists nothing is copied.
func TestNothingIsCopiedWithoutAllowlists(t *testing.T) {
	ns := newNamespace(t, map[string]string{teamLabel: team},
		map[string]string{contactAnnotation: contact}).Name
	digest := newDigest()
	pod{namespace: ns, name: appPod, node: nodeAMD64, labels: map[string]string{teamLabel: team}}.run(t, digest)

	got := buildFor(t, contextFor("vexplain-system", everything, "")).images[digest]

	require.Len(t, got.Workloads, 1)
	require.Empty(t, got.Workloads[0].Labels)
	require.Empty(t, got.Workloads[0].NamespaceLabels)
	require.Empty(t, got.Workloads[0].NamespaceAnnotations)
}

// An image ID is the digest of an image's configuration, which no registry serves: it comes without a repository. A
// pod on a node whose labels say no platform is listed without one.
func TestAnImageIDHasNoRepository(t *testing.T) {
	ns := newNamespace(t, nil, nil).Name
	digest := newDigest()
	pod{namespace: ns, name: toolPod, node: nodeBare}.runReporting(t, "docker://"+digest)

	got := buildFor(t, contextFor("vexplain-system", everything, "")).images[digest]

	require.Equal(t, evidence.Presence{
		DigestKind: evidence.DigestKindImageID,
		Workloads: []evidence.PresenceWorkload{{
			Kind: "Pod", Namespace: ns, Name: toolPod, UID: got.Workloads[0].UID,
			Pods: []evidence.PresencePod{{Name: toolPod, Node: nodeBare, Containers: appContainers}},
		}},
	}, got)
	require.NotEmpty(t, got.Workloads[0].UID)
}

// A container whose image ID isn't a digest, or that has none yet, runs an image without a digest, which presence keeps
// as a Reference image. The collector counts such containers, by why, among the pods in scope: those that the scope
// leaves out, and vexplain's own, don't count. A pod that has ended and never got an image ID never will, and isn't
// waited for.
func TestTheContainersWithoutADigestAreCountedByWhy(t *testing.T) {
	token := rand.String(6)
	inScope := map[string]string{"run": token}
	operatorNamespace := newNamespace(t, inScope, nil).Name
	ns := newNamespace(t, inScope, nil).Name
	outside := newNamespace(t, nil, nil).Name
	pod{namespace: ns, name: taggedPod, node: nodeAMD64}.runReporting(t, byTag)
	pod{namespace: ns, name: "pending-0", node: nodeAMD64}.create(t)
	ended := pod{namespace: ns, name: "evicted-0", node: nodeAMD64}.create(t)
	ended.Status = corev1.PodStatus{Phase: corev1.PodFailed, Reason: "Evicted"}
	c, _ := startAPI(t)
	require.NoError(t, c.Status().Update(t.Context(), ended))
	cached(t, ended)
	pod{namespace: outside, name: taggedPod, node: nodeAMD64}.runReporting(t, byTag)
	pod{namespace: operatorNamespace, name: "scan-0", node: nodeAMD64,
		labels: map[string]string{taskLabel: "scan"}}.runReporting(t, byTag)
	scope := json.RawMessage(`{"includeNamespaces": {"matchLabels": {"run": "` + token + `"}}}`)

	got := buildFor(t, contextFor(operatorNamespace, scope, "")).withoutDigest

	require.Equal(t, map[string]int{reasonUnparsable: 1, reasonPending: 1}, got)
}

// Every pod counts, whatever its phase, so that the image of a finished Job doesn't come and go: the pod of a Job that
// a CronJob started is the CronJob's.
func TestThePodOfAFinishedJobCountsForItsCronJob(t *testing.T) {
	c, _ := startAPI(t)
	ns := newNamespace(t, nil, nil).Name
	cronJob := &metav1.OwnerReference{APIVersion: "batch/v1", Kind: "CronJob", Name: "nightly",
		UID: "uid-nightly", Controller: ptr.To(true)}
	job := &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "nightly-29000000", OwnerReferences: []metav1.OwnerReference{*cronJob}},
		Spec: batchv1.JobSpec{Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{
			RestartPolicy: corev1.RestartPolicyNever,
			Containers:    []corev1.Container{{Name: appContainer, Image: repository + ":1.0"}},
		}}},
	}
	require.NoError(t, c.Create(t.Context(), job))
	cached(t, job)
	digest := newDigest()
	finished := pod{namespace: ns, name: "nightly-29000000-x2k4p", node: nodeAMD64,
		owner: controlledBy(job, "batch/v1", "Job")}.run(t, digest)
	finished.Status.Phase = corev1.PodSucceeded
	require.NoError(t, c.Status().Update(t.Context(), finished))
	cached(t, finished)

	got := buildFor(t, contextFor("vexplain-system", everything, "")).images[digest]

	require.Len(t, got.Workloads, 1)
	require.Equal(t, evidence.PresenceWorkload{
		APIGroup: batchv1.GroupName, Kind: "CronJob", Namespace: ns, Name: "nightly", UID: "uid-nightly",
		Pods: []evidence.PresencePod{{Name: finished.Name, Node: nodeAMD64, Platform: platformAMD64, Containers: appContainers}},
	}, got.Workloads[0])
}

// workloadAttribution allowlists the two keys of the workloads' labels in the tests.
const workloadAttribution = `{"workloadLabels": ["` + partOf + `", "` + costCenter + `"]}`

// Owner attribution copies a workload's own labels. Kubernetes copies a Deployment's pod template's labels to its
// pods, and none of the Deployment's own, so a key set on the Deployment's object alone is copied from there.
func TestALabelOnTheDeploymentsObjectIsCopied(t *testing.T) {
	ns := newNamespace(t, nil, nil).Name
	d, rs := deployment(t, ns)
	labelled(t, d, map[string]string{partOf: shop})
	digest := newDigest()
	pod{namespace: ns, name: webPod, node: nodeAMD64, owner: controlledBy(rs, "apps/v1", "ReplicaSet")}.
		run(t, digest)

	got := buildFor(t, contextFor("vexplain-system", everything, workloadAttribution)).images[digest]

	require.Len(t, got.Workloads, 1)
	require.Equal(t, []evidence.KeyValue{{Key: partOf, Value: shop}}, got.Workloads[0].Labels)
}

// A key that a Deployment's pod template sets, and that its object doesn't, isn't the Deployment's label: it is not
// copied, though every pod of the Deployment carries it.
func TestALabelOnlyOnTheDeploymentsPodTemplateIsNotCopied(t *testing.T) {
	ns := newNamespace(t, nil, nil).Name
	_, rs := deployment(t, ns)
	digest := newDigest()
	pod{namespace: ns, name: webPod, node: nodeAMD64, owner: controlledBy(rs, "apps/v1", "ReplicaSet"),
		labels: map[string]string{costCenter: costCenterA}}.run(t, digest)

	got := buildFor(t, contextFor("vexplain-system", everything, workloadAttribution)).images[digest]

	require.Len(t, got.Workloads, 1)
	require.Empty(t, got.Workloads[0].Labels)
}

// A bare pod is a workload of its own, and its labels are its own.
func TestABarePodsLabelIsCopied(t *testing.T) {
	ns := newNamespace(t, nil, nil).Name
	digest := newDigest()
	pod{namespace: ns, name: "debug-0", node: nodeAMD64, labels: map[string]string{costCenter: costCenterA}}.run(t, digest)

	got := buildFor(t, contextFor("vexplain-system", everything, workloadAttribution)).images[digest]

	require.Len(t, got.Workloads, 1)
	require.Equal(t, []evidence.KeyValue{{Key: costCenter, Value: costCenterA}}, got.Workloads[0].Labels)
}

// A rollout that changes the pod template runs the pods of two ReplicaSets at once, with the template's labels of
// each. The Deployment's labels are its object's, whichever pods run, so they don't flip during the rollout.
func TestARolloutThatChangesThePodTemplateDoesntFlipTheLabels(t *testing.T) {
	ns := newNamespace(t, nil, nil).Name
	d, before := deployment(t, ns)
	labelled(t, d, map[string]string{partOf: shop})
	after := replicaSetOf(t, d, "7c9d8")
	digest := newDigest()
	attribution := contextFor("vexplain-system", everything, workloadAttribution)
	labelsWhile := func(step string) []evidence.KeyValue {
		t.Helper()
		got := buildFor(t, attribution).images[digest]
		require.Len(t, got.Workloads, 1, step)
		return got.Workloads[0].Labels
	}
	shopLabels := []evidence.KeyValue{{Key: partOf, Value: shop}}

	old := pod{namespace: ns, name: webPod, node: nodeAMD64,
		owner: controlledBy(before, "apps/v1", "ReplicaSet"), labels: map[string]string{partOf: "shop-v1"}}.run(t, digest)
	require.Equal(t, shopLabels, labelsWhile("before the rollout"))

	pod{namespace: ns, name: "web-7c9d8-a1b2c", node: nodeAMD64,
		owner: controlledBy(after, "apps/v1", "ReplicaSet"), labels: map[string]string{partOf: "shop-v2"}}.run(t, digest)
	require.Equal(t, shopLabels, labelsWhile("during the rollout"))

	deletePod(t, old)
	require.Equal(t, shopLabels, labelsWhile("after the rollout"))
}

// A Deployment deleted and created again under the same name is another object, whose labels aren't those of the
// first one's pods' owner: until those pods go, their workload has no labels.
func TestTheLabelsOfAnotherObjectOfTheWorkloadsNameAreNotCopied(t *testing.T) {
	c, _ := startAPI(t)
	ns := newNamespace(t, nil, nil).Name
	d, rs := deployment(t, ns)
	digest := newDigest()
	pod{namespace: ns, name: webPod, node: nodeAMD64, owner: controlledBy(rs, "apps/v1", "ReplicaSet")}.
		run(t, digest)
	require.NoError(t, c.Delete(t.Context(), d))
	again := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: d.Name, Labels: map[string]string{partOf: shop}},
		Spec:       d.Spec,
	}
	require.NoError(t, c.Create(t.Context(), again))
	cached(t, again)

	got := buildFor(t, contextFor("vexplain-system", everything, workloadAttribution)).images[digest]

	require.Len(t, got.Workloads, 1)
	require.Equal(t, string(d.UID), got.Workloads[0].UID)
	require.Empty(t, got.Workloads[0].Labels)
}

// containerPod creates a pod with the init containers and the containers, and writes the statuses that a kubelet
// would: the image ID of each container that has one in imageIDs, by container name. It returns the pod once the cache
// holds its status.
func containerPod(t *testing.T, ns, name string, init, containers []corev1.Container, imageIDs map[string]string) *corev1.Pod {
	t.Helper()
	c, _ := startAPI(t)
	created := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
		Spec:       corev1.PodSpec{NodeName: nodeAMD64, InitContainers: init, Containers: containers},
	}
	require.NoError(t, c.Create(t.Context(), created))
	created.Status.Phase = corev1.PodRunning
	for _, container := range init {
		created.Status.InitContainerStatuses = append(created.Status.InitContainerStatuses,
			corev1.ContainerStatus{Name: container.Name, ImageID: imageIDs[container.Name]})
	}
	for _, container := range containers {
		created.Status.ContainerStatuses = append(created.Status.ContainerStatuses,
			corev1.ContainerStatus{Name: container.Name, ImageID: imageIDs[container.Name]})
	}
	require.NoError(t, c.Status().Update(t.Context(), created))
	cached(t, created)
	return created
}

// Presence names the containers of each pod that run a digest, with their kind. A container that a mesh injected shows
// under its own name, and two containers of one digest are named under that digest.
func TestPresenceNamesTheContainersOfEachPodWithTheirKind(t *testing.T) {
	ns := newNamespace(t, nil, nil).Name
	always := corev1.ContainerRestartPolicyAlways
	shared, mesh, setup := newDigest(), newDigest(), newDigest()
	containerPod(t, ns, "web-0",
		[]corev1.Container{
			{Name: setupContainer, Image: repository + ":setup"},
			{Name: proxyContainer, Image: repository + ":mesh", RestartPolicy: &always},
		},
		[]corev1.Container{{Name: web, Image: repository + ":1.0"}, {Name: workerContainer, Image: repository + ":1.0"}},
		map[string]string{
			setupContainer: repository + "@" + setup, proxyContainer: repository + "@" + mesh,
			web: repository + "@" + shared, workerContainer: repository + "@" + shared,
		})

	got := buildFor(t, contextFor("vexplain-system", everything, "")).images

	require.Equal(t, []evidence.PresenceContainer{{Name: web, Kind: regularContainer}, {Name: workerContainer, Kind: regularContainer}},
		got[shared].Workloads[0].Pods[0].Containers)
	require.Equal(t, []evidence.PresenceContainer{{Name: proxyContainer, Kind: "Sidecar"}},
		got[mesh].Workloads[0].Pods[0].Containers)
	require.Equal(t, []evidence.PresenceContainer{{Name: setupContainer, Kind: "InitContainer"}},
		got[setup].Workloads[0].Pods[0].Containers)
}

// A container that reports no digest runs an image that presence keeps, by the SHA-256 of its reference, as a
// Reference image whose repositories hold the reference, so that the workload isn't left out. The same goes for an
// image ID that is no digest.
func TestAnImageWithoutADigestIsKeptAsAReference(t *testing.T) {
	ns := newNamespace(t, nil, nil).Name
	pending := repository + ":pending-" + rand.String(6)
	tagged := repository + ":tagged-" + rand.String(6)
	containerPod(t, ns, "web-0", nil,
		[]corev1.Container{{Name: "starting", Image: pending}, {Name: oddContainer, Image: tagged}},
		map[string]string{oddContainer: tagged})

	got := buildFor(t, contextFor("vexplain-system", everything, ""))

	for _, reference := range []struct{ image, container string }{{pending, "starting"}, {tagged, oddContainer}} {
		sum := sha256.Sum256([]byte(reference.image))
		presence, ok := got.images["sha256:"+hex.EncodeToString(sum[:])]
		require.True(t, ok, "presence names the image of %s", reference.container)
		require.Equal(t, evidence.DigestKindReference, presence.DigestKind)
		require.Equal(t, []string{reference.image}, presence.Repositories)
		require.Equal(t, []evidence.PresenceContainer{{Name: reference.container, Kind: regularContainer}},
			presence.Workloads[0].Pods[0].Containers)
	}
}

// A pod that runs more containers of one image than an event names stays in presence with its image, and names the
// first by name. The build says which pod it was.
func TestAPodWithMoreContainersThanAnEventNamesKeepsTheFirst(t *testing.T) {
	ns := newNamespace(t, nil, nil).Name
	digest := newDigest()
	containers := make([]corev1.Container, 0, maxContainersPerPod+3)
	ids := map[string]string{}
	for i := range maxContainersPerPod + 3 {
		name := fmt.Sprintf("c%02d", i)
		containers = append(containers, corev1.Container{Name: name, Image: repository + ":1.0"})
		ids[name] = repository + "@" + digest
	}
	many := containerPod(t, ns, "many-0", nil, containers, ids)
	// The pod would make every later Watch of the package log it.
	t.Cleanup(func() {
		c, _ := startAPI(t)
		assert.NoError(t, client.IgnoreNotFound(c.Delete(context.Background(), many, client.GracePeriodSeconds(0))))
	})

	built := buildFor(t, contextFor("vexplain-system", everything, ""))

	pod := built.images[digest].Workloads[0].Pods[0]
	require.Len(t, pod.Containers, maxContainersPerPod)
	require.Equal(t, "c00", pod.Containers[0].Name)
	require.Equal(t, fmt.Sprintf("c%02d", maxContainersPerPod-1), pod.Containers[maxContainersPerPod-1].Name)
	require.Contains(t, built.truncated, ns+"/many-0")
}
