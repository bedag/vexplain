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

package scan_test

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	inventoryv1alpha1 "github.com/bedag/vexplain/api/inventory/v1alpha1"
	"github.com/bedag/vexplain/internal/controller/scan"
	"github.com/bedag/vexplain/internal/inventory"
	"github.com/bedag/vexplain/internal/scan/result"
	"github.com/bedag/vexplain/internal/tasks"
	"github.com/bedag/vexplain/internal/workloads"
)

// The fixtures of the specs of this suite: the workloads whose images they scan, the scan pods that
// envtest doesn't run, and the readers of what the runner made of them. envtest runs no kubelet and
// no Job controller: a spec creates the pod of a scan Job, and writes its status, as they would.

const (
	// repository is where the images of the specs come from.
	repository = "artifacts.example/team-a/app"
	// scannerImageID is the imageID that a kubelet reports for the container of a scan pod.
	scannerImageID = "scanner.example/vexplain-scanner@" + scannerDigest
	scannerDigest  = "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"

	// reaction bounds how long the runner takes to follow a change. startup bounds the first reaction
	// of a spec, which may also wait for the manager to start.
	reaction = 10 * time.Second
	startup  = 30 * time.Second
	poll     = 100 * time.Millisecond
	// quiet is how long a spec watches for something that must not happen. It spans a few waits
	// for a free slot.
	quiet = 3 * time.Second
)

// cluster is the name of this cluster for the stores that the specs read through.
func cluster() string { return "local" }

// namespaceCount and digestCount number the namespaces and the digests that the specs create. The
// envtest API server is new for every run, so the numbers are unique.
var namespaceCount, digestCount int

// newNamespace creates a namespace for the workloads of a spec, and returns its name once the
// manager's cache holds it, so that the pod inventory reads its labels at the first reconcile of a
// pod in it. envtest runs no namespace controller, so the spec leaves it.
func newNamespace() string {
	GinkgoHelper()
	namespaceCount++
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf("team-%03d", namespaceCount)}}
	Expect(k8sClient.Create(ctx, ns)).To(Succeed())
	Eventually(func() error {
		return k8sManager.GetClient().Get(ctx, client.ObjectKeyFromObject(ns), &corev1.Namespace{})
	}, startup, poll).Should(Succeed())
	return ns.Name
}

// newDigest returns a digest that no other spec uses. After the spec, it waits until the digest has
// no ImageInventory, so that the next spec starts without it.
func newDigest() string {
	GinkgoHelper()
	digest := newManifestDigest()
	DeferCleanup(func() {
		Eventually(lookup(digest), reaction, poll).Should(Satisfy(apierrors.IsNotFound))
	})
	return digest
}

// newManifestDigest returns a digest that no other spec uses, for a platform manifest. It counts
// with newDigest.
func newManifestDigest() string {
	digestCount++
	return fmt.Sprintf("sha256:%064x", digestCount)
}

// digestLabelOf is the value of the digest label of the scan Jobs of digest.
func digestLabelOf(digest string) string {
	return strings.TrimPrefix(digest, "sha256:")[:63]
}

// runWorkload creates a pod named name that runs digest on node, pulled from repository with the
// pull secret regcred, and writes its status as a kubelet would. It deletes the pod after the spec.
func runWorkload(namespace, name, digest, node string) *corev1.Pod {
	GinkgoHelper()
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name},
		Spec: corev1.PodSpec{
			NodeName:         node,
			ImagePullSecrets: []corev1.LocalObjectReference{{Name: "regcred"}},
			Containers:       []corev1.Container{{Name: appContainer, Image: repository + ":1.0"}},
		},
	}
	Expect(k8sClient.Create(ctx, pod)).To(Succeed())
	DeferCleanup(deletePod, pod)
	pod.Status = corev1.PodStatus{Phase: corev1.PodRunning, ContainerStatuses: []corev1.ContainerStatus{{
		Name: appContainer, Image: repository + ":1.0", ImageID: repository + "@" + digest,
	}}}
	Expect(k8sClient.Status().Update(ctx, pod)).To(Succeed())
	return pod
}

// deletePod deletes a pod at once. With a grace period, it would wait for a kubelet that envtest
// doesn't run.
func deletePod(pod *corev1.Pod) {
	GinkgoHelper()
	Expect(client.IgnoreNotFound(k8sClient.Delete(ctx, pod, client.GracePeriodSeconds(0)))).To(Succeed())
}

// lookup reads the ImageInventory of digest, for a spec that waits for it, or for it to be gone.
func lookup(digest string) func() error {
	return func() error {
		key := client.ObjectKey{Name: inventory.NameForDigest(digest)}
		return k8sClient.Get(ctx, key, &inventoryv1alpha1.ImageInventory{})
	}
}

// expectPresence waits until the pod inventory has created the ImageInventory of digest: a digest
// that runs, and that the hub would ask to scan.
func expectPresence(digest string) {
	GinkgoHelper()
	Eventually(lookup(digest), startup, poll).Should(Succeed())
}

// requestScan asks for a scan of digest from repository, as the hub does. After the spec, it
// deletes the scan Jobs of the digest that are left.
func requestScan(digest string) {
	GinkgoHelper()
	Expect(queue.RequestScan(ctx, tasks.ScanRequest{Digest: digest, Repositories: []string{repository}})).To(Succeed())
	DeferCleanup(deleteScanJobs, digest)
}

// scanJobsOf lists the scan Jobs of digest. The digests of the specs differ in their last hex digit
// only, so the label, which holds the first 63, is the same for all of them: the annotation, which
// holds the whole digest, tells them apart, as it does for the runner.
func scanJobsOf(g Gomega, digest string) []batchv1.Job {
	GinkgoHelper()
	var list batchv1.JobList
	g.Expect(k8sClient.List(ctx, &list, client.InNamespace(operatorNamespace), client.MatchingLabels{
		workloads.TaskLabel: scanTask, scan.DigestLabel: digestLabelOf(digest),
	})).To(Succeed())
	return slices.DeleteFunc(list.Items, func(job batchv1.Job) bool { return job.Annotations[scan.DigestLabel] != digest })
}

// jobNamesOf returns a function that names the scan Jobs of digest, for a spec that watches them.
func jobNamesOf(digest string) func(g Gomega) []string {
	return func(g Gomega) []string {
		jobs := scanJobsOf(g, digest)
		names := make([]string, 0, len(jobs))
		for _, job := range jobs {
			names = append(names, job.Name)
		}
		return names
	}
}

// expectJob waits until digest has exactly one scan Job, and returns it.
func expectJob(digest string) *batchv1.Job {
	GinkgoHelper()
	var job batchv1.Job
	Eventually(func(g Gomega) {
		jobs := scanJobsOf(g, digest)
		g.Expect(jobs).To(HaveLen(1))
		job = jobs[0]
	}, startup, poll).Should(Succeed())
	return &job
}

// expectJobGone waits until digest has no scan Job.
func expectJobGone(digest string) {
	GinkgoHelper()
	Eventually(jobNamesOf(digest), reaction, poll).Should(BeEmpty())
}

// deleteScanJobs deletes the scan Jobs of digest. envtest runs no garbage collector, so their pods
// and Secrets stay, and no spec depends on them.
func deleteScanJobs(digest string) {
	GinkgoHelper()
	for _, job := range scanJobsOf(Default, digest) {
		Expect(client.IgnoreNotFound(k8sClient.Delete(ctx, &job,
			client.PropagationPolicy(metav1.DeletePropagationBackground)))).To(Succeed())
	}
}

// runScanPod creates the pod of a scan Job, as the Job controller would, makes it print log, and
// writes its status in phase, as a kubelet would. The kubelet reports the scanner image's digest for
// its container. It deletes the pod after the spec.
func runScanPod(job *batchv1.Job, phase corev1.PodPhase, log string) {
	GinkgoHelper()
	template := job.Spec.Template.DeepCopy()
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:   job.Namespace,
			Name:        job.Name + "-x2k4p",
			Labels:      template.Labels,
			Annotations: template.Annotations,
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion: "batch/v1", Kind: "Job", Name: job.Name, UID: job.UID, Controller: ptr.To(true),
			}},
		},
		Spec: template.Spec,
	}
	pod.Spec.NodeName = amd64Node
	Expect(k8sClient.Create(ctx, pod)).To(Succeed())
	DeferCleanup(deletePod, pod)
	scanLogs.set(pod.Name, log)
	pod.Status = corev1.PodStatus{Phase: phase, ContainerStatuses: []corev1.ContainerStatus{{
		Name: scannerContainer, Image: scannerImage, ImageID: scannerImageID,
	}}}
	Expect(k8sClient.Status().Update(ctx, pod)).To(Succeed())
}

// manifestOf is what a scan found in the platform manifest digest: one package, and four ELF files
// of which three belong to it.
func manifestOf(platform, digest string) result.Manifest {
	return result.Manifest{
		Platform: platform,
		Digest:   digest,
		SBOM:     json.RawMessage(`{"artifacts":[{"id":"pkg-1","name":"libexample1","version":"1.2.3-1","type":"deb"}]}`),
		Packages: []result.PackageFacts{{ID: "pkg-1", FilesListed: 2, FilesPresent: 2, SharedLibraries: 1}},
		ELF:      result.ELFSummary{Total: 4, Owned: 3},
	}
}

// resultLog returns the log of a scan of digest that found manifests.
func resultLog(digest string, manifests ...result.Manifest) string {
	GinkgoHelper()
	line, err := result.Encode(result.Result{Image: repository + "@" + digest, Manifests: manifests})
	Expect(err).NotTo(HaveOccurred())
	return "scanner: resolving the image\n" + line + "\n"
}

// errorLog returns the log of a scan that failed for reason.
func errorLog(reason result.ErrorReason) string {
	return "scanner: resolving the image\n" + result.EncodeError(reason) + "\n"
}

// factsOf reads the facts of the ImageInventory of digest.
func factsOf(g Gomega, digest string) *inventoryv1alpha1.ImageFacts {
	GinkgoHelper()
	var obj inventoryv1alpha1.ImageInventory
	g.Expect(k8sClient.Get(ctx, client.ObjectKey{Name: inventory.NameForDigest(digest)}, &obj)).To(Succeed())
	return obj.Status.Facts
}

// platformFacts are the facts of a platform whose manifest is manifestOf's.
func platformFacts(platform, manifestDigest string) inventoryv1alpha1.PlatformFacts {
	return inventoryv1alpha1.PlatformFacts{
		Platform:            platform,
		ManifestDigest:      manifestDigest,
		CompletenessPercent: ptr.To(int32(75)),
		ELFFiles:            ptr.To(int32(4)),
		Packages:            ptr.To(int32(1)),
	}
}
