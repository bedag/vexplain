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
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	cloudevents "github.com/cloudevents/sdk-go/v2"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"
	"sigs.k8s.io/yaml"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
	inventoryv1alpha1 "github.com/bedag/vexplain/api/inventory/v1alpha1"
	"github.com/bedag/vexplain/internal/controller/scan"
	"github.com/bedag/vexplain/internal/evidence"
	"github.com/bedag/vexplain/internal/inventory"
	"github.com/bedag/vexplain/internal/scan/result"
	"github.com/bedag/vexplain/internal/setup"
	"github.com/bedag/vexplain/internal/tasks"
	"github.com/bedag/vexplain/internal/testenv"
	sdkevidence "github.com/bedag/vexplain/sdk/evidence"
	subjects "github.com/bedag/vexplain/sdk/subject"
	"github.com/bedag/vexplain/sdk/workloads"
)

// These specs use Ginkgo (BDD-style Go testing framework). Refer to http://onsi.github.io/ginkgo/
// to learn more about Ginkgo.
//
// They run the hub with the spoke, as one manager wired by setup.Register, as cmd/main.go wires
// it, against an API server: the whole way from a running image to the sheet of its manifest. The
// install's Collectors, the default rules of config/rules and the default playbook of
// config/playbooks are applied, as the install applies them. The findings come from a fake of the
// findings collector, and the spoke's scans from the scan runner, whose Jobs the specs run.

const (
	// operatorNamespace is the namespace the manager runs in, where the scan Jobs run.
	operatorNamespace = "vexplain-system"
	// amd64Node is the node that the workloads of the specs run on.
	amd64Node = "node-amd64"

	// The interval of the assessor's second looks at an image, of the janitor's rounds, and the
	// janitor's grace are short, so that a spec sees each of them act within seconds.
	retryInterval   = 2 * time.Second
	janitorInterval = time.Second
	janitorGrace    = 2 * time.Second

	// reaction bounds how long the manager takes to follow a change, and startup its first reaction
	// in a spec, which may wait for the manager to start. quiet is how long a spec watches for
	// something that must not happen.
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
	// findings is the findings collector that the manager asks.
	findings *fakeFindings
	// requests records what the hub asks the spoke for, and hands it on to the spoke's scan queue.
	requests *recordingExecutor
	// scanLogs holds the logs of the scan pods that the specs run.
	scanLogs *podLogs
)

func TestHub(t *testing.T) {
	RegisterFailHandler(Fail)

	RunSpecs(t, "Hub Suite")
}

var _ = BeforeSuite(func() {
	logf.SetLogger(zap.New(zap.WriteTo(GinkgoWriter), zap.UseDevMode(true)))

	findings = newFakeFindings(v1, exampleMatch, otherMatch, goneMatch)
	scanLogs = &podLogs{logs: map[string]string{}}
	queue := scan.NewQueue()
	requests = &recordingExecutor{next: queue}
	env := testenv.Start(setup.Options{
		OperatorNamespace: operatorNamespace,
		ScannerImage:      scannerImage,
		ScanQueue:         queue,
		Executor:          requests,
		ScanLogs:          scanLogs,
		ScanCredentials:   anonymousPull{},
		Findings:          findings,
		RetryBase:         retryInterval,
		JanitorInterval:   janitorInterval,
		UnreferencedGrace: janitorGrace,
	})
	k8sClient, k8sManager = env.Client, env.Manager

	By("creating the operator namespace, and a node")
	Expect(k8sClient.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: operatorNamespace}})).To(Succeed())
	Expect(k8sClient.Create(ctx, &corev1.Node{ObjectMeta: metav1.ObjectMeta{
		Name:   amd64Node,
		Labels: map[string]string{corev1.LabelOSStable: "linux", corev1.LabelArchStable: "amd64"},
	}})).To(Succeed())

	By("applying the install's Collectors, the default rules and the default playbook")
	for _, name := range []string{workloadsCollector, scanner, matcherCollector} {
		Expect(k8sClient.Create(ctx, collectorNamed(name))).To(Succeed())
	}
	for _, rule := range defaultRules() {
		Expect(k8sClient.Create(ctx, rule)).To(Succeed())
	}
	Expect(k8sClient.Create(ctx, defaultPlaybook())).To(Succeed())
	Eventually(readyOf(&configv1alpha1.Playbook{}, playbookName), startup, poll).Should(HaveField("Status", metav1.ConditionTrue))
})

// ---- the install ----

// collectorNamed returns a Collector of the install, as a manifest of config/collectors gives it. The
// operator runs no package of it: the spoke's scanner and the fake findings collector do its work.
func collectorNamed(name string) *configv1alpha1.Collector {
	return &configv1alpha1.Collector{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec:       configv1alpha1.CollectorSpec{Package: "artifacts.example/vexplain/" + name + ":0.1.0"},
	}
}

// repositoryRoot is the root of the repository, from the directory of this package.
var repositoryRoot = filepath.Join("..", "..", "..")

// readDefaultRules reads the default rules as config/rules ships them: every file that its
// kustomization lists, each a Rule.
func readDefaultRules() ([]*configv1alpha1.Rule, error) {
	dir := filepath.Join(repositoryRoot, "config", "rules")
	var kustomization struct {
		Resources []string `json:"resources"`
	}
	if err := readYAML(filepath.Join(dir, "kustomization.yaml"), &kustomization); err != nil {
		return nil, err
	}
	rules := make([]*configv1alpha1.Rule, 0, len(kustomization.Resources))
	for _, file := range kustomization.Resources {
		rule := &configv1alpha1.Rule{}
		if err := readYAML(filepath.Join(dir, file), rule); err != nil {
			return nil, err
		}
		rules = append(rules, rule)
	}
	return rules, nil
}

// readDefaultPlaybook reads the default playbook as config/playbooks ships it: the one file that its
// kustomization lists.
func readDefaultPlaybook() (*configv1alpha1.Playbook, error) {
	dir := filepath.Join(repositoryRoot, "config", "playbooks")
	var kustomization struct {
		Resources []string `json:"resources"`
	}
	if err := readYAML(filepath.Join(dir, "kustomization.yaml"), &kustomization); err != nil {
		return nil, err
	}
	if !slices.Equal(kustomization.Resources, []string{playbookName + ".yaml"}) {
		return nil, fmt.Errorf("config/playbooks lists %v, and not the default playbook alone", kustomization.Resources)
	}
	playbook := &configv1alpha1.Playbook{}
	if err := readYAML(filepath.Join(dir, kustomization.Resources[0]), playbook); err != nil {
		return nil, err
	}
	return playbook, nil
}

// defaultRules returns the default rules, as readDefaultRules reads them.
func defaultRules() []*configv1alpha1.Rule {
	GinkgoHelper()
	rules, err := readDefaultRules()
	Expect(err).NotTo(HaveOccurred())
	return rules
}

// defaultPlaybook returns the default playbook, as readDefaultPlaybook reads it.
func defaultPlaybook() *configv1alpha1.Playbook {
	GinkgoHelper()
	playbook, err := readDefaultPlaybook()
	Expect(err).NotTo(HaveOccurred())
	return playbook
}

// readYAML reads a YAML file into out, and refuses a field that out doesn't have.
func readYAML(path string, out any) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if err := yaml.UnmarshalStrict(raw, out); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	return nil
}

// readyOf returns a function that reads the Ready condition of the object of a kind with the name, or
// nil while it has none.
func readyOf(obj client.Object, name string) func(g Gomega) *metav1.Condition {
	return conditionOf(obj, name, configv1alpha1.ConditionReady)
}

// conditionOf returns a function that reads a condition of the object of a kind with the name, or nil
// while it has none.
func conditionOf(obj client.Object, name, conditionType string) func(g Gomega) *metav1.Condition {
	return func(g Gomega) *metav1.Condition {
		g.Expect(k8sClient.Get(ctx, client.ObjectKey{Name: name}, obj)).To(Succeed())
		var conditions []metav1.Condition
		switch o := obj.(type) {
		case *configv1alpha1.Playbook:
			conditions = o.Status.Conditions
		case *configv1alpha1.Rule:
			conditions = o.Status.Conditions
		default:
			Fail(fmt.Sprintf("no conditions of a %T", obj))
		}
		return meta.FindStatusCondition(conditions, conditionType)
	}
}

// update changes the object of a kind with the name with change, and writes it, trying again after a
// conflict.
func update[T client.Object](obj T, name string, change func(T)) {
	GinkgoHelper()
	Eventually(func(g Gomega) {
		g.Expect(k8sClient.Get(ctx, client.ObjectKey{Name: name}, obj)).To(Succeed())
		change(obj)
		g.Expect(k8sClient.Update(ctx, obj)).To(Succeed())
	}, reaction, poll).Should(Succeed())
}

// changeRule changes the spec of the rule with the name, and changes it back after the spec.
func changeRule(name string, change func(*configv1alpha1.RuleSpec)) {
	GinkgoHelper()
	var before configv1alpha1.RuleSpec
	update(&configv1alpha1.Rule{}, name, func(rule *configv1alpha1.Rule) {
		before = *rule.Spec.DeepCopy()
		change(&rule.Spec)
	})
	DeferCleanup(func() {
		update(&configv1alpha1.Rule{}, name, func(rule *configv1alpha1.Rule) { rule.Spec = *before.DeepCopy() })
	})
}

// ---- the findings collector ----

// fakeFindings is the findings collector of the default playbook, matcher: its database gives the same
// matches for every manifest, unless a spec gives a manifest matches of its own. It counts the findings
// that it was asked for, by manifest.
type fakeFindings struct {
	mu         sync.Mutex
	version    string
	matches    []sdkevidence.Match
	byManifest map[string][]sdkevidence.Match
	asked      map[string]int
	// queue is the queue that Changed delivers into, once the assessor has started it.
	queue workqueue.TypedRateLimitingInterface[reconcile.Request]
}

// newFakeFindings returns a findings collector whose database has the version, and gives the matches.
func newFakeFindings(version string, matches ...sdkevidence.Match) *fakeFindings {
	f := &fakeFindings{byManifest: map[string][]sdkevidence.Match{}, asked: map[string]int{}}
	f.set(version, matches...)
	return f
}

// set changes the database to one of version that gives the matches.
func (f *fakeFindings) set(version string, matches ...sdkevidence.Match) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.version, f.matches = version, slices.Clone(matches)
}

// setFor has the database give the matches for the manifest, and what it gives every other one for it
// again after the spec.
func (f *fakeFindings) setFor(manifest string, matches ...sdkevidence.Match) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.byManifest[manifest] = slices.Clone(matches)
	DeferCleanup(func() {
		f.mu.Lock()
		defer f.mu.Unlock()
		delete(f.byManifest, manifest)
	})
}

// found returns how often the findings of manifest were asked for.
func (f *fakeFindings) found(manifest string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.asked[manifest]
}

// foundOf returns a function that tells how often the findings of manifest were asked for.
func (f *fakeFindings) foundOf(manifest string) func() int {
	return func() int { return f.found(manifest) }
}

// Find answers as a findings collector does: for the scanner's evidence about a manifest, the matches
// of its database.
func (f *fakeFindings) Find(_ context.Context, collector string, input cloudevents.Event) (sdkevidence.Findings, error) {
	if collector != matcherCollector || input.Type() != result.EvidenceType {
		return sdkevidence.Findings{}, errors.New("no findings collector here matches that")
	}
	about, err := subjects.Parse(input.Subject())
	if err != nil || about.Kind != subjects.KindManifest {
		return sdkevidence.Findings{}, errors.New("the evidence is about no manifest")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.asked[about.Digest]++
	matches, own := f.byManifest[about.Digest]
	if !own {
		matches = f.matches
	}
	return sdkevidence.Findings{Version: f.version, Matches: slices.Clone(matches)}, nil
}

// Changed is the source through which a spec says what to match again.
func (f *fakeFindings) Changed() source.Source {
	return source.Func(func(_ context.Context, queue workqueue.TypedRateLimitingInterface[reconcile.Request]) error {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.queue = queue
		return nil
	})
}

// Consumes says that the matcher consumes the scanner's evidence.
func (f *fakeFindings) Consumes(collector string) []string {
	if collector != matcherCollector {
		return nil
	}
	return []string{result.EvidenceType}
}

// change says, as a findings collector does when its database changes, that the subjects are to be
// matched again: with none, every subject.
func (f *fakeFindings) change(named ...string) {
	GinkgoHelper()
	var queue workqueue.TypedRateLimitingInterface[reconcile.Request]
	Eventually(func() bool {
		f.mu.Lock()
		defer f.mu.Unlock()
		queue = f.queue
		return queue != nil
	}, startup, poll).Should(BeTrue(), "the assessor has started")
	if len(named) == 0 {
		queue.Add(reconcile.Request{})
		return
	}
	for _, subject := range named {
		queue.Add(reconcile.Request{NamespacedName: types.NamespacedName{Name: subject}})
	}
}

// ---- the requests ----

// recordingExecutor records what the hub asks a spoke for, and hands it on.
type recordingExecutor struct {
	next tasks.Executor
	mu   sync.Mutex
	log  []tasks.Request
}

func (e *recordingExecutor) Request(ctx context.Context, r tasks.Request) error {
	e.mu.Lock()
	e.log = append(e.log, tasks.Request{Type: r.Type, Subject: r.Subject, Repositories: slices.Clone(r.Repositories)})
	e.mu.Unlock()
	return e.next.Request(ctx, r)
}

// taken returns what the hub asked for, in order.
func (e *recordingExecutor) taken() []tasks.Request {
	e.mu.Lock()
	defer e.mu.Unlock()
	return slices.Clone(e.log)
}

// of returns a function that tells how often the hub asked for evidence about the image of digest.
func (e *recordingExecutor) of(digest string) func() int {
	return func() int {
		e.mu.Lock()
		defer e.mu.Unlock()
		n := 0
		for _, r := range e.log {
			if r.Subject == subjects.Image(digest) {
				n++
			}
		}
		return n
	}
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
			for _, manifest := range obj.Status.Facts.Manifests {
				manifests = append(manifests, manifest.Digest)
			}
		}
		return manifests
	}
}

// evidenceStore returns a store that reads the evidence from the API server.
func evidenceStore() evidence.Store {
	return evidence.NewCRDStore(k8sClient, nil, cluster)
}

// recordOf returns a function that reads the scanner's record about manifest, or nil while there is
// none.
func recordOf(manifest string) func(g Gomega) *evidence.Record {
	return func(g Gomega) *evidence.Record {
		record, err := evidenceStore().Get(ctx, evidence.Key{
			Subject: subjects.Manifest(manifest), Type: result.EvidenceType, Source: scanner,
		})
		g.Expect(err).NotTo(HaveOccurred())
		return record
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

// contentsOf returns what a sheet records of the scanner's evidence about manifest, as it is stored
// now.
func contentsOf(manifest string) inventoryv1alpha1.SheetEvidence {
	GinkgoHelper()
	record := recordOf(manifest)(Default)
	Expect(record).NotTo(BeNil())
	return sheetEvidenceOf(record)
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

// storeEvidence stores what a scan by the scanner image found in m, and the facts of the image of
// digest that name it, as the spoke does after a scan. The image must have an ImageInventory.
func storeEvidence(digest string, m result.Manifest) {
	GinkgoHelper()
	e := scanEventOf(time.Now(), m)
	Expect(evidenceStore().Put(ctx, scanner, scannerImage, e)).To(Succeed())
	facts := evidence.NewFactsWriter(inventory.NewCRDStore(k8sClient, nil, cluster))
	Expect(facts.Succeeded(ctx, digest, scanner, scannerImage, []cloudevents.Event{e})).To(Succeed())
}
