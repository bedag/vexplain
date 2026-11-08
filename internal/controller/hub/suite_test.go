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
	"sync"
	"testing"
	"time"

	cloudevents "github.com/cloudevents/sdk-go/v2"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/workqueue"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"
	"sigs.k8s.io/yaml"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
	inventoryv1alpha1 "github.com/bedag/vexplain/api/inventory/v1alpha1"
	"github.com/bedag/vexplain/internal/evidence"
	"github.com/bedag/vexplain/internal/inventory"
	"github.com/bedag/vexplain/internal/setup"
	"github.com/bedag/vexplain/internal/tasks"
	"github.com/bedag/vexplain/internal/testenv"
	"github.com/bedag/vexplain/internal/testenv/imagecontents"
	sdkevidence "github.com/bedag/vexplain/sdk/evidence"
	subjects "github.com/bedag/vexplain/sdk/subject"
)

// These specs use Ginkgo (BDD-style Go testing framework). Refer to http://onsi.github.io/ginkgo/
// to learn more about Ginkgo.
//
// They run the hub as one manager wired by setup.Register, as cmd/main.go wires it, against an API
// server: the way from a running image to the sheet of its manifest. The install's Collectors, the
// default rules of config/rules and the default playbook of config/playbooks are applied, as the
// install applies them, and each Collector's status holds the capabilities that its collector would
// answer, which say what types it produces. A Collector that produces the subjects of a playbook for
// virtual machines is installed too. The findings come from a fake of the findings collector. The hub's requests
// for evidence go to the specs, which answer them as the spoke's executor does once the scanner
// collector has scanned an image: they store its evidence, each manifest's SBOM and contents, and the
// facts that name it. The executor and the scanner have tests of their own.

const (
	// operatorNamespace is the namespace the manager runs in.
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
)

var (
	ctx = context.Background()
	// k8sClient reads and writes through the API server, without a cache.
	k8sClient client.Client
	// k8sManager runs the hub and the spoke, wired by setup.Register.
	k8sManager ctrl.Manager
	// findings is the findings collector that the manager asks.
	findings *fakeFindings
	// requests records what the hub asks the spoke for.
	requests *recordingExecutor
)

func TestHub(t *testing.T) {
	RegisterFailHandler(Fail)

	RunSpecs(t, "Hub Suite")
}

var _ = BeforeSuite(func() {
	logf.SetLogger(zap.New(zap.WriteTo(GinkgoWriter), zap.UseDevMode(true)))

	findings = newFakeFindings(v1, exampleMatch, otherMatch, goneMatch)
	requests = &recordingExecutor{}
	env := testenv.Start(setup.Options{
		OperatorNamespace: operatorNamespace,
		Executor:          requests,
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

	By("applying the install's Collectors with their capabilities, the default rules and the default playbook")
	for _, name := range []string{workloadsCollector, scanner, vulnerabilitiesCollector, vmCollector} {
		install(GinkgoT(), k8sClient, name)
	}
	for _, rule := range defaultRules() {
		Expect(k8sClient.Create(ctx, rule)).To(Succeed())
	}
	Expect(k8sClient.Create(ctx, defaultPlaybook())).To(Succeed())
	Eventually(readyOf(&configv1alpha1.Playbook{}, playbookName), startup, poll).Should(HaveField("Status", metav1.ConditionTrue))
})

// ---- the install ----

// collectorNamed returns a Collector of the install, as a manifest of config/collectors gives it. The
// operator runs no package of it, so nothing answers GetCapabilities: the specs record the capabilities,
// answer the hub's requests for the scanner's evidence, and the fake findings collector does the
// vulnerabilities collector's work.
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

// fakeFindings is the findings collector of the default playbook, vulnerabilities collector: its database gives the same
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

// Find answers as a findings collector does: for the SBOM of a manifest, the matches of its database.
func (f *fakeFindings) Find(_ context.Context, collector string, input cloudevents.Event) (sdkevidence.Findings, error) {
	if collector != vulnerabilitiesCollector || input.Type() != sdkevidence.TypeSBOM {
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

// Consumes says that the vulnerabilities collector consumes the SBOM of a manifest.
func (f *fakeFindings) Consumes(_ context.Context, collector string) ([]string, error) {
	if collector != vulnerabilitiesCollector {
		return nil, nil
	}
	return []string{sdkevidence.TypeSBOM}, nil
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

// recordingExecutor records what the hub asks a spoke for, and hands it on to next, when it has one.
type recordingExecutor struct {
	next tasks.Executor
	mu   sync.Mutex
	log  []tasks.Request
}

func (e *recordingExecutor) Request(ctx context.Context, r tasks.Request) error {
	e.mu.Lock()
	e.log = append(e.log, tasks.Request{Type: r.Type, Subject: r.Subject, Repositories: slices.Clone(r.Repositories)})
	e.mu.Unlock()
	if e.next == nil {
		return nil
	}
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

// ---- workloads, digests and the inventory ----

// namespaceCount and digestCount number the namespaces and the digests of the specs. The API server
// is new for every run, so the numbers are unique.
var namespaceCount, digestCount int

// newNamespace creates a namespace for the workloads of a spec, and returns its name once the
// manager's cache holds it. envtest runs no namespace controller, so the spec leaves it.
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

// workload is a workload of the specs: its pod, and the digest that the pod runs.
type workload struct {
	pod    *corev1.Pod
	digest string
}

// runWorkload creates a pod named name that runs digest, pulled from repository, on the node, and
// writes its status as a kubelet would. It writes this cluster's entry for digest, with the node's
// platform, as the spoke's presence does once a presence collector reports the pod: no presence
// collector streams to the manager of the suite. It stops the workload after the spec.
func runWorkload(namespace, name, digest string) *workload {
	GinkgoHelper()
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name},
		Spec: corev1.PodSpec{
			NodeName:   amd64Node,
			Containers: []corev1.Container{{Name: "app", Image: repository + ":1.0"}},
		},
	}
	Expect(k8sClient.Create(ctx, pod)).To(Succeed())
	w := &workload{pod: pod, digest: digest}
	DeferCleanup(stopWorkload, w)
	pod.Status = corev1.PodStatus{Phase: corev1.PodRunning, ContainerStatuses: []corev1.ContainerStatus{{
		Name: "app", Image: repository + ":1.0", ImageID: repository + "@" + digest,
	}}}
	Expect(k8sClient.Status().Update(ctx, pod)).To(Succeed())
	observeOn(GinkgoT(), inventory.NewCRDStore(k8sClient, nil, cluster), digest, localCluster, []string{linuxAMD64},
		repository)
	return w
}

// stopWorkload deletes the pod of a workload, and forgets this cluster's entry for its digest, as the
// spoke's presence does once no pod runs it.
func stopWorkload(w *workload) {
	GinkgoHelper()
	deletePod(w.pod)
	forget(GinkgoT(), inventory.NewCRDStore(k8sClient, nil, cluster), w.digest, localCluster)
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

// scanTypes are the types of the scanner's evidence about a manifest, sorted: its SBOM and its contents,
// which one scan delivers.
var scanTypes = []string{sdkevidence.TypeSBOM, imagecontents.Type}

// recordOf returns a function that reads the scanner's record of the type about manifest, or nil while
// there is none.
func recordOf(manifest, eventType string) func(g Gomega) *evidence.Record {
	return func(g Gomega) *evidence.Record {
		record, err := evidenceStore().Get(ctx, evidence.Key{
			Subject: subjects.Manifest(manifest), Type: eventType, Source: scanner,
		})
		g.Expect(err).NotTo(HaveOccurred())
		return record
	}
}

// heldOf returns a function that tells the types of the scanner's evidence about manifest that the store
// holds, sorted.
func heldOf(manifest string) func(g Gomega) []string {
	return func(g Gomega) []string {
		var held []string
		for _, eventType := range scanTypes {
			if recordOf(manifest, eventType)(g) != nil {
				held = append(held, eventType)
			}
		}
		return held
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

// restedOn returns what a sheet records of the scanner's evidence about manifest, as it is stored now: its
// contents and its SBOM, in the order of their names.
func restedOn(manifest string) []inventoryv1alpha1.SheetEvidence {
	GinkgoHelper()
	contentsRecord, sbomRecord := recordOf(manifest, imagecontents.Type)(Default), recordOf(manifest, sdkevidence.TypeSBOM)(Default)
	Expect(contentsRecord).NotTo(BeNil())
	Expect(sbomRecord).NotTo(BeNil())
	return []inventoryv1alpha1.SheetEvidence{sheetEvidenceOf(contents, contentsRecord), sheetEvidenceOf(sbomName, sbomRecord)}
}

// ---- scans ----

// runAndScan runs a workload of a pod named name that runs digest, and has the spoke answer the hub's
// request for its evidence with a scan that found s in a manifest. It returns once the facts of digest
// name the manifest. The workload stops after the spec.
func runAndScan(namespace, name, digest string, s scan) *workload {
	GinkgoHelper()
	w := runWorkload(namespace, name, digest)
	answerWithScan(digest, expectRequest(digest, 0), s)
	return w
}

// expectRequest waits until the hub has asked for the SBOM of the image of digest, which the findings
// collector consumes, more often than before, and returns how often it has.
func expectRequest(digest string, before int) int {
	GinkgoHelper()
	Eventually(requests.of(digest), startup, poll).Should(BeNumerically(">", before))
	Expect(requests.taken()).To(ContainElement(tasks.Request{
		Type: sdkevidence.TypeSBOM, Subject: subjects.Image(digest), Repositories: []string{repository},
	}))
	return requests.of(digest)()
}

// answerWithScan answers the hub's request for the evidence of the image of digest, the asked-th, as
// the spoke's executor does once the scanner found s in a manifest: it stores the scanner's evidence, the
// SBOM and the contents of one answer, and the facts, and returns once the facts name the manifest.
func answerWithScan(digest string, asked int, s scan) {
	GinkgoHelper()
	Expect(asked).To(BeNumerically(">", 0), "the hub asked for the evidence")
	storeEvidence(digest, s)
	Eventually(manifestsOf(digest), reaction, poll).Should(Equal([]string{s.digest()}))
}

// storeEvidence stores what a scan by the scanner of scannerVersion found in a manifest, s, and the facts
// of the image of digest that name it, as the spoke's executor does with what the scanner returns: the
// SBOM and the contents of the manifest. The image must have an ImageInventory.
func storeEvidence(digest string, s scan) {
	GinkgoHelper()
	events := scanEventsOf(time.Now(), s)
	for _, e := range events {
		Expect(evidenceStore().Put(ctx, scanner, scannerVersion, e)).To(Succeed())
	}
	facts := evidence.NewFactsWriter(inventory.NewCRDStore(k8sClient, nil, cluster))
	Expect(facts.Succeeded(ctx, digest, scanner, scannerVersion, events)).To(Succeed())
}
