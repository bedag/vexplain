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

package hub_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
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
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	inventoryv1alpha1 "github.com/bedag/vexplain/api/inventory/v1alpha1"
	"github.com/bedag/vexplain/internal/inventory"
	"github.com/bedag/vexplain/internal/matchapi"
	"github.com/bedag/vexplain/internal/scan/result"
	"github.com/bedag/vexplain/internal/setup"
	"github.com/bedag/vexplain/internal/testenv"
	"github.com/bedag/vexplain/internal/workloads"
)

// These specs use Ginkgo (BDD-style Go testing framework). Refer to http://onsi.github.io/ginkgo/
// to learn more about Ginkgo.
//
// They run the hub with the spoke, as one manager wired by setup.Register, as cmd/main.go wires
// it, against an API server: the whole way from a running image to the sheet of its manifest. The
// manager reaches the matcher by its URL, as in production, and the matcher is a fake on HTTP.

const (
	// operatorNamespace is the namespace the manager runs in, where the scan Jobs run.
	operatorNamespace = "vexplain-system"
	// amd64Node is the node that the workloads of the specs run on.
	amd64Node = "node-amd64"

	// The intervals of the scheduler's second looks, the poller and the janitor, and the janitor's
	// grace, are short, so that a spec sees each of them act within seconds.
	scanRetryBase   = 2 * time.Second
	pollInterval    = 500 * time.Millisecond
	janitorInterval = time.Second
	janitorGrace    = 2 * time.Second

	// reaction bounds how long the manager takes to follow a change, and startup its first reaction
	// in a spec, which may wait for the manager to start. quiet is how long a spec watches for
	// something that must not happen: several polls of the matcher.
	reaction = 15 * time.Second
	startup  = 30 * time.Second
	poll     = 100 * time.Millisecond
	quiet    = 2 * time.Second

	// digestAnnotation is where the scan runner names the digest of a scan Job.
	digestAnnotation = "vexplain.bedag.ch/digest"
)

var (
	ctx = context.Background()
	// k8sClient reads and writes through the API server, without a cache.
	k8sClient client.Client
	// k8sManager runs the hub and the spoke, wired by setup.Register.
	k8sManager ctrl.Manager
	// matcher is the matcher that the manager reaches by its URL.
	matcher *matcherServer
	// scanLogs holds the logs of the scan pods that the specs run.
	scanLogs *podLogs
)

func TestHub(t *testing.T) {
	RegisterFailHandler(Fail)

	RunSpecs(t, "Hub Suite")
}

var _ = BeforeSuite(func() {
	logf.SetLogger(zap.New(zap.WriteTo(GinkgoWriter), zap.UseDevMode(true)))

	matcher = newMatcherServer(v1, exampleMatch, otherMatch)
	// Registered first, so that it runs last: after the manager has stopped.
	DeferCleanup(matcher.Close)
	scanLogs = &podLogs{logs: map[string]string{}}
	env := testenv.Start(setup.Options{
		OperatorNamespace:   operatorNamespace,
		ScannerImage:        scannerImage,
		ScanLogs:            scanLogs,
		ScanCredentials:     anonymousPull{},
		MatcherURL:          matcher.URL,
		ScanRetryBase:       scanRetryBase,
		MatcherPollInterval: pollInterval,
		JanitorInterval:     janitorInterval,
		UnreferencedGrace:   janitorGrace,
	})
	k8sClient, k8sManager = env.Client, env.Manager

	By("creating the operator namespace, and a node")
	Expect(k8sClient.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: operatorNamespace}})).To(Succeed())
	Expect(k8sClient.Create(ctx, &corev1.Node{ObjectMeta: metav1.ObjectMeta{
		Name:   amd64Node,
		Labels: map[string]string{corev1.LabelOSStable: "linux", corev1.LabelArchStable: "amd64"},
	}})).To(Succeed())
})

// ---- the matcher ----

// matcherServer is the matcher on HTTP: its database gives the same matches for every SBOM. It counts
// the matches of each manifest, by the manifest that the source of the SBOM names.
type matcherServer struct {
	*httptest.Server
	mu        sync.Mutex
	version   string
	matches   []matchapi.Match
	matchesOf map[string]int
}

// newMatcherServer returns a running matcher whose database has the version, and gives the matches.
func newMatcherServer(version string, matches ...matchapi.Match) *matcherServer {
	s := &matcherServer{matchesOf: map[string]int{}}
	s.set(version, matches...)
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+matchapi.PathDatabase, s.database)
	mux.HandleFunc("POST "+matchapi.PathMatch, s.match)
	s.Server = httptest.NewServer(mux)
	return s
}

// set changes the database to one of version that gives the matches.
func (s *matcherServer) set(version string, matches ...matchapi.Match) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.version, s.matches = version, slices.Clone(matches)
}

// matched returns how often the matcher has matched the SBOM of manifest.
func (s *matcherServer) matched(manifest string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.matchesOf[manifest]
}

func (s *matcherServer) database(w http.ResponseWriter, _ *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	writeJSON(w, matchapi.Database{Version: s.version, Built: t0})
}

func (s *matcherServer) match(w http.ResponseWriter, r *http.Request) {
	var req matchapi.MatchRequest
	var sbom struct {
		Source struct {
			ID string `json:"id"`
		} `json:"source"`
	}
	if json.NewDecoder(r.Body).Decode(&req) != nil || json.Unmarshal(req.SBOM, &sbom) != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.matchesOf[sbom.Source.ID]++
	writeJSON(w, matchapi.MatchResponse{DatabaseVersion: s.version, Matches: append([]matchapi.Match{}, s.matches...)})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// ---- the scan pods ----

// podLogs is the log reader of the scan runner: the log of each scan pod, by name, as a spec sets it.
// envtest runs no kubelet, so there are no real logs.
type podLogs struct {
	mu   sync.Mutex
	logs map[string]string
}

func (l *podLogs) set(pod, log string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.logs[pod] = log
}

// ScanLog returns the log of the pod, or an empty log, as a pod that printed nothing has.
func (l *podLogs) ScanLog(_ context.Context, namespace, pod string) (string, error) {
	if namespace != operatorNamespace {
		return "", fmt.Errorf("no scan pod runs in namespace %q", namespace)
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.logs[pod], nil
}

// anonymousPull gives every scan the credentials of an anonymous pull.
type anonymousPull struct{}

func (anonymousPull) DockerConfig(context.Context, *corev1.Pod, string) ([]byte, error) {
	return []byte(`{"auths":{}}`), nil
}

// ---- workloads, digests and the inventory ----

// namespaceCount and digestCount number the namespaces and the digests of the specs. The API server
// is new for every run, so the numbers are unique.
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

// newDigest returns a digest that no other spec uses: of an image, or of a platform manifest.
func newDigest() string {
	digestCount++
	return digestOf(1000 + digestCount)
}

// runWorkload creates a pod named name that runs digest, pulled from repository, on the node, and
// writes its status as a kubelet would. It deletes the pod after the spec.
func runWorkload(namespace, name, digest string) *corev1.Pod {
	GinkgoHelper()
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name},
		Spec: corev1.PodSpec{
			NodeName:   amd64Node,
			Containers: []corev1.Container{{Name: "app", Image: repository + ":1.0"}},
		},
	}
	Expect(k8sClient.Create(ctx, pod)).To(Succeed())
	DeferCleanup(deletePod, pod)
	pod.Status = corev1.PodStatus{Phase: corev1.PodRunning, ContainerStatuses: []corev1.ContainerStatus{{
		Name: "app", Image: repository + ":1.0", ImageID: repository + "@" + digest,
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

// lookup returns a function that reads obj, the inventory object named after digest.
func lookup(digest string, obj client.Object) func() error {
	return func() error {
		return k8sClient.Get(ctx, client.ObjectKey{Name: inventory.NameForDigest(digest)}, obj)
	}
}

// manifestsOf returns a function that reads the manifests that the facts of digest name.
func manifestsOf(digest string) func(g Gomega) []string {
	return func(g Gomega) []string {
		var obj inventoryv1alpha1.ImageInventory
		g.Expect(lookup(digest, &obj)()).To(Succeed())
		var manifests []string
		if obj.Status.Facts != nil {
			for _, platform := range obj.Status.Facts.Platforms {
				manifests = append(manifests, platform.ManifestDigest)
			}
		}
		return manifests
	}
}

// statusOf returns a function that reads the status of the sheet of manifest, or nil while it has
// none.
func statusOf(manifest string) func(g Gomega) *inventoryv1alpha1.ImageVerdictsStatus {
	return func(g Gomega) *inventoryv1alpha1.ImageVerdictsStatus {
		var obj inventoryv1alpha1.ImageVerdicts
		err := lookup(manifest, &obj)()
		if apierrors.IsNotFound(err) {
			return nil
		}
		g.Expect(err).NotTo(HaveOccurred())
		return &obj.Status
	}
}

// ---- scans ----

// runAndScan runs a pod named name that runs digest, and has the spoke scan it, which finds the
// manifest m. It returns once the facts of digest name the manifest. The pod is deleted after the
// spec.
func runAndScan(namespace, name, digest string, m result.Manifest) *corev1.Pod {
	GinkgoHelper()
	pod := runWorkload(namespace, name, digest)
	runScanPod(expectScanJob(digest), resultLog(digest, m))
	Eventually(manifestsOf(digest), reaction, poll).Should(Equal([]string{m.Digest}))
	return pod
}

// expectScanJob waits until the scan runner has started a Job for digest, other than the Jobs named
// earlier, and returns it.
func expectScanJob(digest string, earlier ...string) *batchv1.Job {
	GinkgoHelper()
	var job batchv1.Job
	Eventually(func(g Gomega) {
		var list batchv1.JobList
		g.Expect(k8sClient.List(ctx, &list, client.InNamespace(operatorNamespace),
			client.MatchingLabels{workloads.TaskLabel: "scan"})).To(Succeed())
		jobs := slices.DeleteFunc(list.Items, func(j batchv1.Job) bool {
			return j.Annotations[digestAnnotation] != digest || slices.Contains(earlier, j.Name)
		})
		g.Expect(jobs).To(HaveLen(1))
		job = jobs[0]
	}, startup, poll).Should(Succeed())
	return &job
}

// runScanPod creates the pod of a scan Job, as the Job controller would, makes it print log, and
// writes the status of a pod that succeeded, as a kubelet would.
func runScanPod(job *batchv1.Job, log string) {
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
	pod.Status = corev1.PodStatus{Phase: corev1.PodSucceeded, ContainerStatuses: []corev1.ContainerStatus{{
		Name: "scanner", Image: scannerImage, ImageID: "scanner.example/vexplain-scanner@" + digestOf(999),
		State: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{
			ExitCode: 0, Reason: "Completed", ContainerID: "containerd://" + strings.Repeat("c", 64),
		}},
	}}}
	Expect(k8sClient.Status().Update(ctx, pod)).To(Succeed())
}

// resultLog returns the log of a scan of digest, pulled from repository, that found the manifests.
func resultLog(digest string, manifests ...result.Manifest) string {
	GinkgoHelper()
	line, err := result.Encode(result.Result{Image: repository + "@" + digest, Manifests: manifests})
	Expect(err).NotTo(HaveOccurred())
	return "scanner: resolving the image\n" + line + "\n"
}
