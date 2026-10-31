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
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	ctrlconfig "sigs.k8s.io/controller-runtime/pkg/config"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
	inventoryv1alpha1 "github.com/bedag/vexplain/api/inventory/v1alpha1"
	"github.com/bedag/vexplain/internal/collector"
	"github.com/bedag/vexplain/internal/controller/scan"
	"github.com/bedag/vexplain/internal/inventory"
	"github.com/bedag/vexplain/internal/scan/result"
	"github.com/bedag/vexplain/internal/setup"
	"github.com/bedag/vexplain/internal/workloads"
)

// These specs run against the manager that the suite starts through setup.Register, so the runner
// under test is the production one, with the production watches, and the stores that it writes
// through. The specs ask for scans through the queue, as the hub does.
//
// Every spec uses digests and namespaces of its own. The scanner Collector and the health registry
// are shared: the spec that changes the Collector puts it back, and every spec deletes the scan Jobs
// it leaves, so that the next one finds every slot free.
var _ = Describe("Scan runner", func() {
	It("makes a Job and its Secret for a request, as the scan pods' constraints say", func() {
		ns, digest := newNamespace(), newDigest()
		runWorkload(ns, appPod, digest, arm64Node)
		expectPresence(digest)

		requestScan(digest)
		job := expectJob(digest)

		By("labelling the Job and its pods as scans of the digest, which the annotation names in full")
		labels := map[string]string{workloads.TaskLabel: scanTask, scan.DigestLabel: digestLabelOf(digest)}
		annotations := map[string]string{scan.DigestLabel: digest}
		Expect(job.Namespace).To(Equal(operatorNamespace))
		Expect(job.Labels).To(Equal(labels))
		Expect(job.Annotations).To(Equal(annotations))
		for key, value := range labels {
			Expect(job.Spec.Template.Labels).To(HaveKeyWithValue(key, value))
		}
		Expect(job.Spec.Template.Annotations).To(Equal(annotations))

		By("bounding how long the Job runs, and how long it stays")
		Expect(job.Spec.ActiveDeadlineSeconds).To(HaveValue(Equal(int64(1800))), "the Collector's scanTimeoutSeconds")
		Expect(job.Spec.BackoffLimit).To(HaveValue(BeZero()))
		Expect(job.Spec.TTLSecondsAfterFinished).To(HaveValue(Equal(int32(3600))))

		By("running one pod without access to the API, as the scanner's user")
		spec := job.Spec.Template.Spec
		Expect(spec.RestartPolicy).To(Equal(corev1.RestartPolicyNever))
		Expect(spec.AutomountServiceAccountToken).To(HaveValue(BeFalse()))
		Expect(spec.EnableServiceLinks).To(HaveValue(BeFalse()))
		Expect(spec.SecurityContext).NotTo(BeNil())
		Expect(spec.SecurityContext.RunAsNonRoot).To(HaveValue(BeTrue()))
		Expect(spec.SecurityContext.RunAsUser).To(HaveValue(Equal(int64(65532))))
		Expect(spec.SecurityContext.RunAsGroup).To(HaveValue(Equal(int64(65532))))
		Expect(spec.SecurityContext.FSGroup).To(HaveValue(Equal(int64(65532))), "the scanner's group reads the Secret")
		Expect(spec.SecurityContext.SeccompProfile).To(Equal(&corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault}))

		By("running the scanner on the image of the request, for the platform of its node")
		Expect(spec.Containers).To(HaveLen(1))
		container := spec.Containers[0]
		Expect(container.Name).To(Equal(scannerContainer))
		Expect(container.Image).To(Equal(scannerImage))
		Expect(container.ImagePullPolicy).To(Equal(corev1.PullIfNotPresent))
		Expect(container.Command).To(BeEmpty(), "the scanner image's entrypoint runs")
		Expect(container.Args).To(Equal([]string{
			"--image", repository + "@" + digest,
			"--platform", "linux/arm64",
			"--work", "/work",
			// Three quarters of the Collector's workspaceMebibytes, 10240: the rest is Syft's.
			"--max-bytes", "8053063680",
			"--registry-mirror", registryMirror,
		}))
		Expect(container.Env).To(Equal(append([]corev1.EnvVar{{Name: "DOCKER_CONFIG", Value: "/creds"}}, proxyEnv...)))
		Expect(container.Resources.Limits).To(HaveLen(1))
		Expect(container.Resources.Limits.Memory().String()).To(Equal("2Gi"), "the Collector's memoryLimitMebibytes")
		Expect(container.Resources.Requests).To(HaveLen(1))
		Expect(container.Resources.Requests.Memory().String()).To(Equal("2Gi"))
		Expect(container.SecurityContext).NotTo(BeNil())
		Expect(container.SecurityContext.AllowPrivilegeEscalation).To(HaveValue(BeFalse()))
		Expect(container.SecurityContext.ReadOnlyRootFilesystem).To(HaveValue(BeTrue()))
		Expect(container.SecurityContext.Capabilities).To(Equal(&corev1.Capabilities{Drop: []corev1.Capability{"ALL"}}))

		By("mounting the workspace, the credentials and a temporary directory")
		mounts := map[string]corev1.VolumeMount{}
		for _, mount := range container.VolumeMounts {
			mounts[mount.MountPath] = mount
		}
		Expect(mounts).To(HaveLen(3))
		volumes := map[string]corev1.VolumeSource{}
		for _, volume := range spec.Volumes {
			volumes[volume.Name] = volume.VolumeSource
		}
		Expect(volumes).To(HaveLen(3))
		work := volumes[mounts["/work"].Name]
		Expect(work.EmptyDir).NotTo(BeNil())
		Expect(work.EmptyDir.SizeLimit).NotTo(BeNil())
		Expect(work.EmptyDir.SizeLimit.String()).To(Equal("10Gi"), "the Collector's workspaceMebibytes")
		Expect(volumes[mounts["/tmp"].Name].EmptyDir).NotTo(BeNil())
		Expect(mounts["/creds"].ReadOnly).To(BeTrue())
		creds := volumes[mounts["/creds"].Name].Secret
		Expect(creds).NotTo(BeNil())
		Expect(creds.DefaultMode).To(HaveValue(Equal(int32(0o440))), "the scanner's group reads the Secret")

		By("putting the pod's credentials into an Opaque Secret that the Job owns")
		var secret corev1.Secret
		Eventually(func() error {
			return k8sClient.Get(ctx, client.ObjectKey{Namespace: operatorNamespace, Name: creds.SecretName}, &secret)
		}, reaction, poll).Should(Succeed())
		Expect(secret.Type).To(Equal(corev1.SecretTypeOpaque))
		Expect(secret.Data).To(Equal(map[string][]byte{"config.json": dockerConfig}))
		Expect(metav1.IsControlledBy(&secret, job)).To(BeTrue())
		Expect(secret.Labels).NotTo(HaveKey(configv1alpha1.LLMAPIKeyLabel))
		Expect(pullCredentials.callsFor(ns)).To(Equal([]credentialsCall{{namespace: ns, pod: appPod, repository: repository}}))
	})

	It("makes no second Job for a digest that is being scanned", func() {
		ns, digest := newNamespace(), newDigest()
		runWorkload(ns, appPod, digest, amd64Node)
		expectPresence(digest)
		requestScan(digest)
		job := expectJob(digest)

		requestScan(digest)

		Consistently(jobNamesOf(digest), quiet, poll).Should(Equal([]string{job.Name}))
	})

	It("runs no more Jobs at once than maxConcurrentScans, and starts the next when one finishes", func() {
		setMaxConcurrentScans(1)
		ns, first, second := newNamespace(), newDigest(), newDigest()
		runWorkload(ns, appPod, first, amd64Node)
		runWorkload(ns, "tool-0", second, amd64Node)
		expectPresence(first)
		expectPresence(second)

		requestScan(first)
		requestScan(second)

		By("running one Job, while the other request waits for its slot")
		var running *batchv1.Job
		waiting := second
		Eventually(func(g Gomega) {
			jobs := append(scanJobsOf(g, first), scanJobsOf(g, second)...)
			g.Expect(jobs).To(HaveLen(1))
			running = &jobs[0]
		}, startup, poll).Should(Succeed())
		if running.Annotations[scan.DigestLabel] == second {
			waiting = first
		}
		Consistently(jobNamesOf(waiting), quiet, poll).Should(BeEmpty())

		By("starting the waiting scan once the running one has finished")
		scanned := running.Annotations[scan.DigestLabel]
		runScanPod(running, corev1.PodSucceeded, resultLog(scanned, manifestOf("linux/amd64", newManifestDigest())))
		expectJobGone(scanned)
		expectJob(waiting)
	})

	It("stores the evidence and the facts of a successful scan, and deletes its Job", func() {
		ns, digest := newNamespace(), newDigest()
		runWorkload(ns, appPod, digest, amd64Node)
		runWorkload(ns, "app-1", digest, arm64Node)
		expectPresence(digest)
		before := time.Now().Truncate(time.Second)

		requestScan(digest)
		job := expectJob(digest)
		Expect(job.Spec.Template.Spec.Containers[0].Args).To(ContainElements("linux/amd64", "linux/arm64"),
			"the platforms of the nodes of both pods")
		manifests := []result.Manifest{
			manifestOf("linux/amd64", newManifestDigest()), manifestOf("linux/arm64/v8", newManifestDigest()),
		}
		runScanPod(job, corev1.PodSucceeded, resultLog(digest, manifests...))

		expectJobGone(digest)
		By("storing the evidence of both manifests")
		packages := inventory.NewCRDPackagesStore(k8sClient, nil, cluster)
		for _, manifest := range manifests {
			DeferCleanup(packages.Delete, ctx, manifest.Digest)
			stored, info, err := packages.Get(ctx, manifest.Digest)
			Expect(err).NotTo(HaveOccurred())
			Expect(stored).To(HaveValue(Equal(manifest)))
			Expect(info.Platform).To(Equal(manifest.Platform))
			Expect(info.ScannerImage).To(Equal(scannerImage))
		}
		By("recording the facts of the scan, with no failure")
		facts := factsOf(Default, digest)
		Expect(facts).NotTo(BeNil())
		Expect(facts.ScannerImage).To(HaveValue(Equal(scannerImage)))
		Expect(facts.ScannedTime).NotTo(BeNil())
		Expect(facts.ScannedTime.Time).To(BeTemporally(">=", before))
		Expect(facts.Failure).To(BeNil())
		Expect(facts.Platforms).To(Equal([]inventoryv1alpha1.PlatformFacts{
			platformFacts("linux/amd64", manifests[0].Digest), platformFacts("linux/arm64/v8", manifests[1].Digest),
		}))
		By("reporting the Scanner as healthy")
		lastSuccess, lastErr, known := registry.Health(configv1alpha1.CollectorTypeScanner)
		Expect(known).To(BeTrue())
		Expect(lastErr).NotTo(HaveOccurred())
		Expect(lastSuccess).To(BeTemporally(">=", before))
	})

	It("records the reason of an error line, keeps the earlier platforms, and deletes the Job", func() {
		ns, digest := newNamespace(), newDigest()
		runWorkload(ns, appPod, digest, amd64Node)
		expectPresence(digest)
		earlier := &inventoryv1alpha1.ImageFacts{
			ScannerImage: ptr.To("scanner.example/vexplain-scanner:0.9"),
			ScannedTime:  ptr.To(metav1.NewTime(time.Date(2026, time.October, 1, 12, 0, 0, 0, time.UTC))),
			Platforms:    []inventoryv1alpha1.PlatformFacts{platformFacts("linux/amd64", newManifestDigest())},
		}
		found, err := inventory.NewCRDStore(k8sClient, nil, cluster).SetFacts(ctx, digest, earlier)
		Expect(err).NotTo(HaveOccurred())
		Expect(found).To(BeTrue())

		requestScan(digest)
		runScanPod(expectJob(digest), corev1.PodFailed, errorLog(result.ErrorReasonUnauthorized))

		expectJobGone(digest)
		facts := factsOf(Default, digest)
		Expect(facts.Platforms).To(Equal(earlier.Platforms))
		Expect(facts.ScannerImage).To(Equal(earlier.ScannerImage), "the scanner of the last successful scan")
		Expect(facts.ScannedTime.Equal(earlier.ScannedTime)).To(BeTrue())
		Expect(facts.Failure).NotTo(BeNil())
		Expect(facts.Failure.Reason).To(Equal(inventoryv1alpha1.ScanFailureReasonUnauthorized))
		Expect(facts.Failure.Attempts).To(Equal(int32(1)))
		Expect(facts.Failure.Time).NotTo(BeNil())
		_, lastErr, _ := registry.Health(configv1alpha1.CollectorTypeScanner)
		Expect(lastErr).To(MatchError(ContainSubstring("Unauthorized")))
	})

	It("records TimedOut for a Job past its deadline, which left no log", func() {
		ns, digest := newNamespace(), newDigest()
		runWorkload(ns, appPod, digest, amd64Node)
		expectPresence(digest)
		requestScan(digest)
		job := expectJob(digest)

		By("failing the Job at its deadline, as the Job controller does, after it has removed its pod")
		now := metav1.Now()
		job.Status = batchv1.JobStatus{StartTime: &now, Conditions: []batchv1.JobCondition{
			{Type: batchv1.JobFailureTarget, Status: corev1.ConditionTrue, Reason: batchv1.JobReasonDeadlineExceeded,
				LastProbeTime: now, LastTransitionTime: now},
			{Type: batchv1.JobFailed, Status: corev1.ConditionTrue, Reason: batchv1.JobReasonDeadlineExceeded,
				LastProbeTime: now, LastTransitionTime: now},
		}}
		Expect(k8sClient.Status().Update(ctx, job)).To(Succeed())

		expectJobGone(digest)
		facts := factsOf(Default, digest)
		Expect(facts.Failure).NotTo(BeNil())
		Expect(facts.Failure.Reason).To(Equal(inventoryv1alpha1.ScanFailureReasonTimedOut))
		Expect(facts.Failure.Attempts).To(Equal(int32(1)))
	})

	It("records TooLarge for evidence that an ImagePackages can't hold", func() {
		ns, digest := newNamespace(), newDigest()
		runWorkload(ns, appPod, digest, amd64Node)
		expectPresence(digest)
		requestScan(digest)
		job := expectJob(digest)

		// Random bytes don't compress, so 1 MiB of them is more than an ImagePackages holds compressed.
		noise := make([]byte, 1<<20)
		_, err := rand.Read(noise)
		Expect(err).NotTo(HaveOccurred())
		large := manifestOf("linux/amd64", newManifestDigest())
		large.SBOM, err = json.Marshal(map[string]any{"artifacts": []any{}, "noise": base64.StdEncoding.EncodeToString(noise)})
		Expect(err).NotTo(HaveOccurred())
		runScanPod(job, corev1.PodSucceeded, resultLog(digest, large))

		expectJobGone(digest)
		facts := factsOf(Default, digest)
		Expect(facts.Failure).NotTo(BeNil())
		Expect(facts.Failure.Reason).To(Equal(inventoryv1alpha1.ScanFailureReasonTooLarge))
		Expect(facts.Failure.Attempts).To(Equal(int32(1)))
		Expect(facts.Platforms).To(BeEmpty())
		stored, _, err := inventory.NewCRDPackagesStore(k8sClient, nil, cluster).Get(ctx, large.Digest)
		Expect(err).NotTo(HaveOccurred())
		Expect(stored).To(BeNil())
	})

	It("writes no facts for a digest that went away during its scan, and deletes the Job", func() {
		ns, digest := newNamespace(), newDigest()
		pod := runWorkload(ns, appPod, digest, amd64Node)
		expectPresence(digest)
		requestScan(digest)
		job := expectJob(digest)

		By("stopping the only pod that runs the digest")
		deletePod(pod)
		Eventually(lookup(digest), reaction, poll).Should(Satisfy(apierrors.IsNotFound))

		manifest := manifestOf("linux/amd64", newManifestDigest())
		DeferCleanup(inventory.NewCRDPackagesStore(k8sClient, nil, cluster).Delete, ctx, manifest.Digest)
		runScanPod(job, corev1.PodSucceeded, resultLog(digest, manifest))

		expectJobGone(digest)
		Consistently(lookup(digest), quiet, poll).Should(Satisfy(apierrors.IsNotFound))
	})

	It("never inventories its scan pods", func() {
		ns, digest := newNamespace(), newDigest()
		runWorkload(ns, appPod, digest, amd64Node)
		expectPresence(digest)
		requestScan(digest)

		// The scan pod reports the digest of the scanner image, as any pod reports its images.
		runScanPod(expectJob(digest), corev1.PodRunning, "")

		Consistently(lookup(scannerDigest), quiet, poll).Should(Satisfy(apierrors.IsNotFound))
	})

	// Without a scanner image nothing can scan, and the Scanner says so from the start. The manager
	// is built through setup.Register, as cmd/main.go builds it, but it isn't started: the report
	// comes before any reconcile.
	It("reports at start that no scanner image is configured", func() {
		mgr, err := ctrl.NewManager(k8sManager.GetConfig(), ctrl.Options{
			Scheme:  k8sManager.GetScheme(),
			Cache:   setup.CacheOptions(operatorNamespace),
			Client:  setup.ClientOptions(),
			Metrics: metricsserver.Options{BindAddress: "0"},
			// The suite's manager has controllers of the same names.
			Controller: ctrlconfig.Controller{SkipNameValidation: ptr.To(true)},
		})
		Expect(err).NotTo(HaveOccurred())
		unconfigured := collector.NewRegistry()

		Expect(setup.Register(mgr, setup.Options{OperatorNamespace: operatorNamespace, CollectorRegistry: unconfigured})).To(Succeed())

		_, lastErr, known := unconfigured.Health(configv1alpha1.CollectorTypeScanner)
		Expect(known).To(BeTrue())
		Expect(lastErr).To(MatchError("no scanner image is configured"))
	})
})

// setMaxConcurrentScans sets maxConcurrentScans in the scanner Collector, and waits until the
// manager's cache holds the change. After the spec, it puts the default back.
func setMaxConcurrentScans(n int32) {
	GinkgoHelper()
	set := func(value int32) {
		GinkgoHelper()
		// The Collector controller writes the status meanwhile, so a write may find the object
		// changed, and is tried again on what is there now.
		Eventually(func() error {
			var scanner configv1alpha1.Collector
			if err := k8sClient.Get(ctx, client.ObjectKey{Name: scannerCollector}, &scanner); err != nil {
				return err
			}
			scanner.Spec.Scanner.MaxConcurrentScans = ptr.To(value)
			return k8sClient.Update(ctx, &scanner)
		}, startup, poll).Should(Succeed())
		Eventually(func(g Gomega) {
			var cached configv1alpha1.Collector
			g.Expect(k8sManager.GetClient().Get(ctx, client.ObjectKey{Name: scannerCollector}, &cached)).To(Succeed())
			g.Expect(cached.Spec.Scanner.MaxConcurrentScans).To(HaveValue(Equal(value)))
		}, reaction, poll).Should(Succeed())
	}
	set(n)
	DeferCleanup(set, int32(2))
}
