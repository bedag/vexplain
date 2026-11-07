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
	"errors"
	"fmt"
	"math"
	"strings"
	"testing"
	"time"

	cloudevents "github.com/cloudevents/sdk-go/v2"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/require"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	clocktesting "k8s.io/utils/clock/testing"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
	inventoryv1alpha1 "github.com/bedag/vexplain/api/inventory/v1alpha1"
	"github.com/bedag/vexplain/internal/controller/hub"
	"github.com/bedag/vexplain/internal/evidence"
	"github.com/bedag/vexplain/internal/inventory"
	"github.com/bedag/vexplain/internal/tasks"
	"github.com/bedag/vexplain/internal/testenv/imagecontents"
	sdkevidence "github.com/bedag/vexplain/sdk/evidence"
	subjects "github.com/bedag/vexplain/sdk/subject"
)

// ---- the assessor, on the manager of the suite ----

// manyMatches returns n matches of vulnerabilities in the package that a later layer removed: findings
// that the default rules settle as not affected, which a sheet leaves out first.
func manyMatches(n int) []sdkevidence.Match {
	matches := make([]sdkevidence.Match, 0, n)
	for i := range n {
		m := goneMatch
		m.VulnerabilityID = fmt.Sprintf("CVE-2026-%05d", 10000+i)
		matches = append(matches, m)
	}
	return matches
}

// withUnknownPackage returns m with one more package, removed in a later layer, whose ID in the SBOM is
// "unknown": the text that a finding shows for a match that names no package.
func withUnknownPackage(m imagecontents.Manifest) imagecontents.Manifest {
	m.SBOM = json.RawMessage(strings.Replace(string(m.SBOM), "]",
		`,{"id":"unknown","name":"libunknown","version":"1.0","type":"deb"}]`, 1))
	m.Packages = append(m.Packages, imagecontents.PackageFacts{ID: "unknown", FilesListed: 2})
	return m
}

// lowerTheGuard changes the completeness guard so that it holds findings below 89%, which changes no
// sheet of the suite's evidence, and changes it back after the spec.
func lowerTheGuard() {
	GinkgoHelper()
	changeRule(guardRule, func(spec *configv1alpha1.RuleSpec) { spec.Condition = "contents.coverage < 89" })
}

var _ = Describe("The assessor", func() {
	It("evaluates a sheet again from its findings when a rule changes, without asking for them again", func() {
		findings.set(v1, exampleMatch, otherMatch, goneMatch)
		digest, manifest := newDigest(), newDigest()
		runAndScan(newNamespace(), "app-0", digest, incompleteEvidenceOf(manifest))
		Eventually(statusOf(manifest), reaction, poll).Should(Equal(
			sheet(v1, contentsOf(manifest), counted{underInvestigation: 3}, otherGuarded, exampleGuarded, goneGuarded)))
		found := findings.found(manifest)

		By("lowering the minimum of the completeness guard to the completeness of the evidence")
		changeRule(guardRule, func(spec *configv1alpha1.RuleSpec) {
			spec.Condition = "contents.coverage < 75"
			spec.Reason = ptr.To("'completeness ' + string(contents.coverage) + '% is below 75%'")
		})

		Eventually(statusOf(manifest), reaction, poll).Should(Equal(
			sheet(v1, contentsOf(manifest), counted{underInvestigation: 2, notAffected: 1}, otherReached, exampleUnreached, goneSettled)))
		Expect(findings.found(manifest)).To(Equal(found), "the findings were not asked for again")
	})

	It("asks for the findings again when a rule changes and the sheet leaves findings out, which it can't reopen", func() {
		digest, manifest := newDigest(), newDigest()
		findings.setFor(manifest, manyMatches(2100)...)
		runAndScan(newNamespace(), "app-0", digest, evidenceOf(manifest))
		Eventually(statusOf(manifest), reaction, poll).Should(And(
			HaveField("OmittedFindings", HaveValue(Equal(int32(52)))),
			HaveField("Counts.NotAffected", HaveValue(Equal(int32(2100))))))
		found := findings.found(manifest)

		lowerTheGuard()

		Eventually(findings.foundOf(manifest), reaction, poll).Should(BeNumerically(">", found))
	})

	// A finding shows "unknown" for a match that names no package. Evaluated again from what it shows, it
	// would name the package of the evidence whose ID is "unknown", which a later layer removed, and be
	// settled as not affected.
	It("asks for the findings again when a rule changes and a finding shows a package ID that was changed to show it", func() {
		digest, manifest := newDigest(), newDigest()
		nameless := goneMatch
		nameless.PackageID = ""
		findings.setFor(manifest, nameless, exampleMatch)
		runAndScan(newNamespace(), "app-0", digest, withUnknownPackage(evidenceOf(manifest)))
		shown := And(HaveField("Package.ID", "unknown"), HaveField("Status", inventoryv1alpha1.VEXStatusUnderInvestigation))
		Eventually(statusOf(manifest), reaction, poll).Should(HaveField("Findings", ContainElement(shown)))
		found := findings.found(manifest)

		lowerTheGuard()

		Eventually(findings.foundOf(manifest), reaction, poll).Should(BeNumerically(">", found))
		Consistently(statusOf(manifest), quiet, poll).Should(And(
			HaveField("Findings", ContainElement(shown)),
			HaveField("Counts.NotAffected", HaveValue(BeZero()))), "the finding is never settled by the package it shows")
	})

	It("asks for the findings of every manifest again when the findings collector says that every subject changed", func() {
		findings.set(v1, exampleMatch, otherMatch, goneMatch)
		namespace := newNamespace()
		first, firstManifest, second, secondManifest := newDigest(), newDigest(), newDigest(), newDigest()
		runAndScan(namespace, "app-0", first, evidenceOf(firstManifest))
		runAndScan(namespace, "app-1", second, evidenceOf(secondManifest))
		for _, manifest := range []string{firstManifest, secondManifest} {
			Eventually(statusOf(manifest), reaction, poll).ShouldNot(BeNil())
		}
		before := map[string]int{firstManifest: findings.found(firstManifest), secondManifest: findings.found(secondManifest)}

		findings.change()

		for manifest, found := range before {
			Eventually(findings.foundOf(manifest), reaction, poll).Should(BeNumerically(">", found))
		}
	})

	It("asks for the findings of a manifest again when the findings collector names it, and of no other", func() {
		findings.set(v1, exampleMatch, otherMatch, goneMatch)
		namespace := newNamespace()
		first, firstManifest, second, secondManifest := newDigest(), newDigest(), newDigest(), newDigest()
		runAndScan(namespace, "app-0", first, evidenceOf(firstManifest))
		runAndScan(namespace, "app-1", second, evidenceOf(secondManifest))
		for _, manifest := range []string{firstManifest, secondManifest} {
			Eventually(statusOf(manifest), reaction, poll).ShouldNot(BeNil())
		}
		foundFirst, foundSecond := findings.found(firstManifest), findings.found(secondManifest)

		findings.change(subjects.Manifest(firstManifest))

		Eventually(findings.foundOf(firstManifest), reaction, poll).Should(BeNumerically(">", foundFirst))
		Consistently(findings.foundOf(secondManifest), quiet, poll).Should(Equal(foundSecond))
	})

	// The spoke's presence lists the platforms of the pods that run an image. A list without a platform
	// that no manifest covers asks for nothing more.
	It("asks for an image's evidence again when presence lists a platform that no manifest of its facts covers", func() {
		digest, manifest := newDigest(), newDigest()
		store := inventory.NewCRDStore(k8sClient, nil, cluster)
		// The image runs in another cluster only.
		observe := func(platforms ...string) {
			GinkgoHelper()
			Expect(store.Observe(ctx, digest, inventory.Observation{
				Cluster: otherCluster, ClusterID: otherCluster + "-id", DigestKind: inventoryv1alpha1.DigestKindRepoDigest,
				Repositories: []string{repository}, Platforms: platforms, NamespaceCount: 1,
			})).To(Succeed())
		}
		observe()
		DeferCleanup(func() { Expect(store.Forget(ctx, digest, otherCluster, otherCluster+"-id")).To(Succeed()) })
		storeEvidence(digest, evidenceOf(manifest))
		Eventually(manifestsOf(digest), reaction, poll).Should(Equal([]string{manifest}))
		asked := requests.of(digest)
		before := asked()

		By("asking for nothing while presence lists no platform")
		Consistently(asked, 2*retryInterval, poll).Should(Equal(before))

		By("asking for nothing while presence lists the platform of the manifest")
		observe(linuxAMD64)
		Consistently(asked, 2*retryInterval, poll).Should(Equal(before))

		By("asking again once presence lists a platform that the facts don't")
		observe(linuxAMD64, linuxARM64)
		Eventually(asked, reaction, poll).Should(BeNumerically(">", before))
	})
})

// ---- the assessor, on a fake client ----

// retryBase is how long an image waits after the first failed attempt of a collector.
const retryBase = time.Hour

// nopExecutor takes every request and does nothing.
type nopExecutor struct{}

func (nopExecutor) Request(context.Context, tasks.Request) error { return nil }

// assessorFixture is an Assessor over stores on a fake client that holds the install: the Collectors,
// the default rules and the default playbook.
type assessorFixture struct {
	assessor *hub.Assessor
	client   client.Client
	store    inventory.Store
	evidence evidence.Store
	verdicts inventory.VerdictsStore
	executor *recordingExecutor
	findings *fakeFindings
	clock    *clocktesting.FakePassiveClock
}

// newAssessor returns the fixture of an assessor whose client acts with funcs, and whose evidence
// store reads through the cache informers when it isn't nil.
func newAssessor(t *testing.T, funcs interceptor.Funcs, informers cache.Cache) *assessorFixture {
	t.Helper()
	c := newClient(t, funcs)
	for _, name := range []string{workloadsCollector, scanner, matcherCollector} {
		require.NoError(t, c.Create(t.Context(), collectorNamed(name)))
	}
	// The deployer records the version that the scanner's GetInfo answers, which its evidence is current at.
	var scannerCollector configv1alpha1.Collector
	require.NoError(t, c.Get(t.Context(), client.ObjectKey{Name: scanner}, &scannerCollector))
	scannerCollector.Status.Version = ptr.To(scannerVersion)
	require.NoError(t, c.Status().Update(t.Context(), &scannerCollector))
	for _, rule := range unitRules(t) {
		require.NoError(t, c.Create(t.Context(), rule))
	}
	require.NoError(t, c.Create(t.Context(), unitPlaybook(t)))
	f := &assessorFixture{
		client:   c,
		store:    inventory.NewCRDStore(c, nil, cluster),
		evidence: evidence.NewCRDStore(c, informers, cluster),
		verdicts: inventory.NewCRDVerdictsStore(c, cluster),
		executor: &recordingExecutor{next: nopExecutor{}},
		findings: newFakeFindings(v1, exampleMatch, otherMatch, goneMatch),
		clock:    clocktesting.NewFakePassiveClock(t0),
	}
	f.assessor = &hub.Assessor{
		Client:      c,
		Store:       f.store,
		Evidence:    f.evidence,
		Facts:       evidence.NewFactsWriter(f.store),
		Verdicts:    f.verdicts,
		Executor:    f.executor,
		Findings:    f.findings,
		Rules:       hub.NewRules(),
		Evaluations: hub.NewEvaluations(),
		RetryBase:   retryBase,
		Clock:       f.clock,
	}
	return f
}

// unitRules are the default rules, as config/rules ships them.
func unitRules(t *testing.T) []*configv1alpha1.Rule {
	t.Helper()
	rules, err := readDefaultRules()
	require.NoError(t, err)
	return rules
}

// unitPlaybook is the default playbook, as config/playbooks ships it.
func unitPlaybook(t *testing.T) *configv1alpha1.Playbook {
	t.Helper()
	playbook, err := readDefaultPlaybook()
	require.NoError(t, err)
	return playbook
}

// restart replaces the assessor with a new one over the same stores and collectors, as a new process of
// the operator does: it remembers nothing of what it did before.
func (f *assessorFixture) restart() {
	old := f.assessor
	f.assessor = &hub.Assessor{
		Client: old.Client, Store: old.Store, Evidence: old.Evidence, Facts: old.Facts, Verdicts: old.Verdicts,
		Executor: old.Executor, Findings: old.Findings, Rules: hub.NewRules(), Evaluations: hub.NewEvaluations(),
		RetryBase: old.RetryBase, Clock: old.Clock,
	}
}

// request reconciles the image of digest, as the assessor's controller of requests does.
func (f *assessorFixture) request(t *testing.T, digest string) (ctrl.Result, error) {
	t.Helper()
	return hub.RequestEvidence(f.assessor, t.Context(), imageRequest(digest))
}

// assess reconciles the manifest, as the assessor's controller of sheets does, which must succeed.
func (f *assessorFixture) assess(t *testing.T, manifest string) {
	t.Helper()
	_, err := hub.Assess(f.assessor, t.Context(), manifestRequest(manifest))
	require.NoError(t, err)
}

// asked returns the requests that the executor took, in order.
func (f *assessorFixture) asked() []tasks.Request {
	return f.executor.taken()
}

// scannerRequest is the request of the scanner's evidence about the image of digest.
func scannerRequest(digest string, repositories ...string) tasks.Request {
	return tasks.Request{Type: imagecontents.Type, Subject: subjects.Image(digest), Repositories: repositories}
}

// storeScans stores the scanner's evidence of the manifests at the version, as a scan does before it writes its
// facts.
func (f *assessorFixture) storeScans(t *testing.T, version string, manifests ...string) {
	t.Helper()
	for _, manifest := range manifests {
		putScan(t, f.evidence, version, t0, evidenceOf(manifest))
	}
}

// sheetOf reads the sheet of manifest, or nil when it has none.
func (f *assessorFixture) sheetOf(t *testing.T, manifest string) *inventoryv1alpha1.ImageVerdicts {
	t.Helper()
	obj, err := f.verdicts.Get(t.Context(), manifest)
	require.NoError(t, err)
	return obj
}

// laggingCache is a cache of informers that hasn't seen any evidence yet, as right after it was
// stored. Any call but a read panics on the nil cache.Cache inside.
type laggingCache struct {
	cache.Cache
}

func (laggingCache) Get(_ context.Context, key client.ObjectKey, _ client.Object, _ ...client.GetOption) error {
	return apierrors.NewNotFound(schema.GroupResource{Group: inventoryv1alpha1.GroupVersion.Group, Resource: "evidences"}, key.Name)
}

func (laggingCache) List(context.Context, client.ObjectList, ...client.ListOption) error {
	return nil
}

func TestTheAssessorAsksForTheEvidenceOfARepositoryDigestWithoutFacts(t *testing.T) {
	f := newAssessor(t, interceptor.Funcs{}, nil)
	digest := digestOf(1)
	observe(t, f.store, digest, localCluster, repository)
	observe(t, f.store, digest, otherCluster, mirror, repository)

	res, err := f.request(t, digest)

	require.NoError(t, err)
	// The type that the findings collector consumes, of the Collector that the playbook names for it.
	// Every repository that a cluster pulled the digest from, once, so that the spoke can pull the image
	// from the one that its pod used.
	require.Equal(t, []tasks.Request{scannerRequest(digest, repository, mirror)}, f.asked())
	// A request can get lost before the evidence answers it, so the image is looked at again.
	require.Equal(t, ctrl.Result{RequeueAfter: retryBase}, res)
}

func TestTheAssessorAsksForNothingWhileTheEvidenceIsCurrent(t *testing.T) {
	f := newAssessor(t, interceptor.Funcs{}, nil)
	digest := digestOf(1)
	observe(t, f.store, digest, localCluster, repository)
	setFacts(t, f.store, digest, scannedBy(scannerVersion, digestOf(101), digestOf(102)))
	f.storeScans(t, scannerVersion, digestOf(101), digestOf(102))

	res, err := f.request(t, digest)

	require.NoError(t, err)
	require.Empty(t, f.asked())
	// Evidence can go without an event that the assessor watches for the image, so it looks again.
	require.Equal(t, ctrl.Result{RequeueAfter: retryBase}, res)
}

// The evidence store, and not the facts, says whether the evidence is there at the current version of
// its collector.
func TestTheAssessorAsksAgainForEvidenceThatTheStoreLacks(t *testing.T) {
	for name, store := range map[string]func(t *testing.T, f *assessorFixture){
		"a manifest that the facts name has none": func(t *testing.T, f *assessorFixture) {
			f.storeScans(t, scannerVersion, digestOf(101))
		},
		"the store holds another version of the collector's": func(t *testing.T, f *assessorFixture) {
			f.storeScans(t, scannerVersion, digestOf(101))
			f.storeScans(t, olderScanner, digestOf(102))
		},
		// A record written before records named their version reads as held at no version, which is
		// none of a collector's.
		"a record doesn't say its version": func(t *testing.T, f *assessorFixture) {
			f.storeScans(t, scannerVersion, digestOf(101), digestOf(102))
			var list inventoryv1alpha1.EvidenceList
			require.NoError(t, f.client.List(t.Context(), &list))
			unversioned := list.Items[0]
			delete(unversioned.Annotations, evidence.CollectorVersionAnnotation)
			require.NoError(t, f.client.Update(t.Context(), &unversioned))
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := newAssessor(t, interceptor.Funcs{}, nil)
			digest := digestOf(1)
			observe(t, f.store, digest, localCluster, repository)
			setFacts(t, f.store, digest, scannedBy(scannerVersion, digestOf(101), digestOf(102)))
			store(t, f)

			res, err := f.request(t, digest)

			require.NoError(t, err)
			require.Equal(t, []tasks.Request{scannerRequest(digest, repository)}, f.asked())
			require.Equal(t, ctrl.Result{RequeueAfter: retryBase}, res)
		})
	}
}

// The facts of a scan can reach the assessor before its cache has seen the evidence, which the scan
// stored first. The API server then says whether the evidence is there.
func TestTheAssessorAsksForNothingWhenOnlyItsCacheHasNotSeenTheEvidence(t *testing.T) {
	f := newAssessor(t, interceptor.Funcs{}, laggingCache{})
	digest := digestOf(1)
	observe(t, f.store, digest, localCluster, repository)
	setFacts(t, f.store, digest, scannedBy(scannerVersion, digestOf(101)))
	f.storeScans(t, scannerVersion, digestOf(101))

	res, err := f.request(t, digest)

	require.NoError(t, err)
	require.Empty(t, f.asked())
	require.Equal(t, ctrl.Result{RequeueAfter: retryBase}, res)
}

// A read that fails says nothing of the evidence: the assessor asks for nothing, and tries again.
func TestTheAssessorReturnsAFailedReadOfTheEvidence(t *testing.T) {
	errRead := errors.New("the API server is unavailable")
	f := newAssessor(t, interceptor.Funcs{
		Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
			if _, ok := obj.(*metav1.PartialObjectMetadata); ok {
				return errRead
			}
			return c.Get(ctx, key, obj, opts...)
		},
	}, nil)
	digest := digestOf(1)
	observe(t, f.store, digest, localCluster, repository)
	setFacts(t, f.store, digest, scannedBy(scannerVersion, digestOf(101)))

	_, err := f.request(t, digest)

	require.ErrorIs(t, err, errRead)
	require.Empty(t, f.asked())
}

// Whether a manifest has evidence comes from the metadata of the evidence. Evidence whose data the
// store can't read, as from a newer operator, is there all the same, and asks for nothing.
func TestTheAssessorCountsEvidenceThatTheStoreCantReadAsPresent(t *testing.T) {
	f := newAssessor(t, interceptor.Funcs{}, nil)
	digest := digestOf(1)
	observe(t, f.store, digest, localCluster, repository)
	setFacts(t, f.store, digest, scannedBy(scannerVersion, digestOf(101)))
	f.storeScans(t, scannerVersion, digestOf(101))
	var list inventoryv1alpha1.EvidenceList
	require.NoError(t, f.client.List(t.Context(), &list))
	require.Len(t, list.Items, 1)
	newer := list.Items[0]
	newer.Spec.Encoding = "ZstdJSON"
	require.NoError(t, f.client.Update(t.Context(), &newer)) // the fake client knows no schema
	_, err := f.evidence.ListBySubject(t.Context(), newer.Spec.Subject)
	require.Error(t, err, "the store can't read the evidence")

	res, err := f.request(t, digest)

	require.NoError(t, err)
	require.Empty(t, f.asked())
	require.Equal(t, ctrl.Result{RequeueAfter: retryBase}, res)
}

func TestTheAssessorWaitsOutTheBackoffOfFailedAttempts(t *testing.T) {
	tests := []struct {
		name string
		// lastSuccess is the scanner of the last successful scan, or "" for none.
		lastSuccess string
		attempts    int32
		wait        time.Duration
	}{
		{name: "one failure waits the base", lastSuccess: scannerVersion, attempts: 1, wait: time.Hour},
		{name: "two failures wait twice the base", lastSuccess: scannerVersion, attempts: 2, wait: 2 * time.Hour},
		{name: "each further failure doubles the wait", lastSuccess: scannerVersion, attempts: 5, wait: 16 * time.Hour},
		{name: "the wait is a day at most", lastSuccess: scannerVersion, attempts: 6, wait: 24 * time.Hour},
		{name: "any number of failures waits a day", lastSuccess: scannerVersion, attempts: math.MaxInt32, wait: 24 * time.Hour},
		{name: "an image that never succeeded waits too", attempts: 2, wait: 2 * time.Hour},
		// The facts name the scanner of the last success. An image that fails under a new scanner keeps
		// the old name, and must not be asked for at every look.
		{name: "a failure waits whatever scanner succeeded last", lastSuccess: olderScanner, attempts: 2, wait: 2 * time.Hour},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newAssessor(t, interceptor.Funcs{}, nil)
			digest := digestOf(1)
			observe(t, f.store, digest, localCluster, repository)
			setFacts(t, f.store, digest, failedAfter(tt.lastSuccess, tt.attempts, t0))

			f.clock.SetTime(t0.Add(tt.wait - time.Second))
			res, err := f.request(t, digest)
			require.NoError(t, err)
			require.Empty(t, f.asked(), "no request before the wait is over")
			require.Equal(t, ctrl.Result{RequeueAfter: time.Second}, res, "the image is looked at again when the wait is over")

			f.clock.SetTime(t0.Add(tt.wait))
			res, err = f.request(t, digest)
			require.NoError(t, err)
			require.Equal(t, []tasks.Request{scannerRequest(digest, repository)}, f.asked())
			require.Equal(t, ctrl.Result{RequeueAfter: retryBase}, res)
		})
	}
}

// The assessor asks for the scanner's evidence. Another collector's failure holds none of it back, and
// the scanner's waits out its own backoff, whatever another source's failure says.
func TestTheAssessorLooksAtTheFailureOfTheCollectorThatItAsksOnly(t *testing.T) {
	f := newAssessor(t, interceptor.Funcs{}, nil)
	digest, other := digestOf(1), digestOf(2)
	observe(t, f.store, digest, localCluster, repository)
	setFacts(t, f.store, digest, &inventoryv1alpha1.ImageFacts{Failures: []inventoryv1alpha1.ScanFailure{{
		Source: "provenance", Reason: inventoryv1alpha1.ScanFailureReasonNotFound, Time: ptr.To(metav1.NewTime(t0)), Attempts: 1,
	}}})
	observe(t, f.store, other, localCluster, repository)
	facts := failedAfter(scannerVersion, 2, t0)
	facts.Failures = append([]inventoryv1alpha1.ScanFailure{{
		Source: matcherCollector, Reason: inventoryv1alpha1.ScanFailureReasonNotFound,
		Time: ptr.To(metav1.NewTime(t0.Add(-48 * time.Hour))), Attempts: 1,
	}}, facts.Failures...)
	setFacts(t, f.store, other, facts)

	_, err := f.request(t, digest)
	require.NoError(t, err)
	res, err := f.request(t, other)
	require.NoError(t, err)

	require.Equal(t, []tasks.Request{scannerRequest(digest, repository)}, f.asked())
	require.Equal(t, ctrl.Result{RequeueAfter: 2 * time.Hour}, res, "the scanner's wait isn't over")
}

func TestTheAssessorMarksAnImageIDNotPullableOnceAndNeverAsksForIt(t *testing.T) {
	f := newAssessor(t, interceptor.Funcs{}, nil)
	digest := digestOf(1)
	observe(t, f.store, digest, localCluster) // No repository: an image ID.

	res, err := f.request(t, digest)

	require.NoError(t, err)
	require.Equal(t, ctrl.Result{}, res)
	marked := factsOf(t, f.store, digest)
	require.NotNil(t, marked)
	require.Len(t, marked.Failures, 1)
	failure := marked.Failures[0]
	require.Equal(t, scanner, failure.Source, "the mark is the scanner's, whose evidence the image can't get")
	require.Equal(t, inventoryv1alpha1.ScanFailureReasonNotPullable, failure.Reason)
	require.Equal(t, ptr.To("the digest is an image ID, which no registry serves"), failure.Message)
	require.Equal(t, int32(1), failure.Attempts)

	// Later looks change nothing: the failure keeps its time and its count, and the image is never
	// asked for.
	f.clock.SetTime(t0.Add(48 * time.Hour))
	res, err = f.request(t, digest)
	require.NoError(t, err)
	require.Equal(t, ctrl.Result{}, res)
	require.Equal(t, marked, factsOf(t, f.store, digest))
	require.Empty(t, f.asked())
}

// The facts keep the failures of at most 8 sources. A mark that they can't hold is dropped: asking
// again changes nothing.
func TestTheAssessorDropsAMarkThatTheFactsCantHold(t *testing.T) {
	f := newAssessor(t, interceptor.Funcs{}, nil)
	digest := digestOf(1)
	observe(t, f.store, digest, localCluster)
	facts := &inventoryv1alpha1.ImageFacts{}
	for i := range 8 {
		facts.Failures = append(facts.Failures, inventoryv1alpha1.ScanFailure{
			Source: fmt.Sprintf("source-%d", i), Reason: inventoryv1alpha1.ScanFailureReasonNotFound,
			Time: ptr.To(metav1.NewTime(t0)), Attempts: 1,
		})
	}
	setFacts(t, f.store, digest, facts)

	res, err := f.request(t, digest)

	require.NoError(t, err)
	require.Equal(t, ctrl.Result{}, res)
	require.Len(t, factsOf(t, f.store, digest).Failures, 8)
}

func TestTheAssessorDoesNothingForADigestWithoutAnObject(t *testing.T) {
	f := newAssessor(t, interceptor.Funcs{}, nil)

	for _, req := range []ctrl.Request{imageRequest(digestOf(1)), {}} {
		res, err := hub.RequestEvidence(f.assessor, t.Context(), req)

		require.NoError(t, err)
		require.Equal(t, ctrl.Result{}, res)
	}
	require.Empty(t, f.asked())
}

// The presence of a digest says what kind it is. Until it does, nobody knows whether it can be pulled,
// even with a repository. A spoke can't pull a repository digest without a repository either.
func TestTheAssessorAsksForNothingOfADigestOfUnknownKindOrWithoutARepository(t *testing.T) {
	for name, observation := range map[string]inventory.Observation{
		"of unknown kind": {Cluster: localCluster, ClusterID: localCluster + "-id", Repositories: []string{repository}},
		"without a repository": {
			Cluster: localCluster, ClusterID: localCluster + "-id", DigestKind: inventoryv1alpha1.DigestKindRepoDigest,
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := newAssessor(t, interceptor.Funcs{}, nil)
			digest := digestOf(1)
			require.NoError(t, f.store.Observe(t.Context(), digest, observation))

			_, err := f.request(t, digest)

			require.NoError(t, err)
			require.Empty(t, f.asked())
		})
	}
}

// Only a playbook that is Ready asks for evidence. One that isn't still has its sheets evaluated
// again, but nothing new is collected for it.
func TestTheAssessorAsksForNothingWithoutAReadyPlaybook(t *testing.T) {
	for name, change := range map[string]func(t *testing.T, c client.Client){
		"no playbook": func(t *testing.T, c client.Client) {
			require.NoError(t, c.Delete(t.Context(), &configv1alpha1.Playbook{ObjectMeta: metav1.ObjectMeta{Name: playbookName}}))
		},
		"a rule of the pipeline is missing": func(t *testing.T, c client.Client) {
			require.NoError(t, c.Delete(t.Context(), &configv1alpha1.Rule{ObjectMeta: metav1.ObjectMeta{Name: guardRule}}))
		},
		"the findings collector is missing": func(t *testing.T, c client.Client) {
			require.NoError(t, c.Delete(t.Context(), collectorNamed(matcherCollector)))
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := newAssessor(t, interceptor.Funcs{}, nil)
			change(t, f.client)
			digest := digestOf(1)
			observe(t, f.store, digest, localCluster, repository)

			_, err := f.request(t, digest)

			require.NoError(t, err)
			require.Empty(t, f.asked())
		})
	}
}

func TestTheAssessorReturnsTheErrorOfARequestThatFails(t *testing.T) {
	f := newAssessor(t, interceptor.Funcs{}, nil)
	errSpoke := errors.New("the spoke is unreachable")
	f.assessor.Executor = failingExecutor{errSpoke}
	digest := digestOf(1)
	observe(t, f.store, digest, localCluster, repository)

	_, err := f.request(t, digest)

	require.ErrorIs(t, err, errSpoke)
}

// failingExecutor refuses every request with its error.
type failingExecutor struct{ err error }

func (e failingExecutor) Request(context.Context, tasks.Request) error { return e.err }

// A platform that starts running an image after its scan has no manifest in the facts. The assessor
// asks for the image again, so that the spoke collects the evidence of that platform too. A node
// doesn't say the variant of its architecture, so a platform without a variant is covered by a
// manifest of any variant of it.
func TestTheAssessorAsksAgainForAPlatformThatNoManifestCovers(t *testing.T) {
	for _, tc := range []struct {
		name      string
		manifests []inventoryv1alpha1.ManifestFact
		running   []string
		asks      bool
	}{
		{"no platform is known", []inventoryv1alpha1.ManifestFact{{Platform: linuxAMD64, Digest: digestOf(101)}}, nil, false},
		{"the platform of the manifest", []inventoryv1alpha1.ManifestFact{{Platform: linuxAMD64, Digest: digestOf(101)}}, []string{linuxAMD64}, false},
		{"a platform that no manifest has", []inventoryv1alpha1.ManifestFact{{Platform: linuxAMD64, Digest: digestOf(101)}},
			[]string{linuxAMD64, linuxARM64}, true},
		{"a variant of the platform of the manifest", []inventoryv1alpha1.ManifestFact{{Platform: "linux/arm64/v8", Digest: digestOf(101)}},
			[]string{linuxARM64}, false},
		{"the platform of a manifest of a variant", []inventoryv1alpha1.ManifestFact{{Platform: linuxARM64, Digest: digestOf(101)}},
			[]string{"linux/arm64/v8"}, false},
		{"another variant of the platform", []inventoryv1alpha1.ManifestFact{{Platform: "linux/arm/v6", Digest: digestOf(101)}},
			[]string{"linux/arm/v7"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newAssessor(t, interceptor.Funcs{}, nil)
			digest := digestOf(1)
			observeOn(t, f.store, digest, localCluster, tc.running, repository)
			facts := scannedBy(scannerVersion)
			facts.Manifests = tc.manifests
			setFacts(t, f.store, digest, facts)
			f.storeScans(t, scannerVersion, digestOf(101))

			_, err := f.request(t, digest)

			require.NoError(t, err)
			if tc.asks {
				require.Equal(t, []tasks.Request{scannerRequest(digest, repository)}, f.asked())
			} else {
				require.Empty(t, f.asked())
			}
		})
	}
}

// An image doesn't offer every platform: an index may lack the one of a node, which then runs the image
// emulated, or offer another variant. Its scan finds the same manifests every time, and the platform
// stays uncovered. The assessor asks for it again after RetryBase, then after twice that, and so on, a
// day at most, and asks at once for a platform that is new since its last request.
func TestTheAssessorBacksOffAPlatformThatStaysUncovered(t *testing.T) {
	f := newAssessor(t, interceptor.Funcs{}, nil)
	digest, manifest := digestOf(1), digestOf(101)
	observeOn(t, f.store, digest, localCluster, []string{linuxAMD64, linuxARM64}, repository)
	setFacts(t, f.store, digest, scannedBy(scannerVersion, manifest))
	f.storeScans(t, scannerVersion, manifest)
	asks := func() int { return len(f.asked()) }

	res, err := f.request(t, digest)
	require.NoError(t, err)
	require.Equal(t, 1, asks(), "a platform that no manifest covers is asked for at once")
	require.Equal(t, ctrl.Result{RequeueAfter: retryBase}, res)

	now := t0
	for i, wait := range []time.Duration{time.Hour, 2 * time.Hour, 4 * time.Hour, 8 * time.Hour, 16 * time.Hour,
		24 * time.Hour, 24 * time.Hour} {
		// The scan finds the same manifest again.
		setFacts(t, f.store, digest, scannedBy(scannerVersion, manifest))

		f.clock.SetTime(now.Add(wait - time.Second))
		res, err = f.request(t, digest)
		require.NoError(t, err)
		require.Equal(t, i+1, asks(), "no request before the wait of %s is over", wait)
		require.Equal(t, ctrl.Result{RequeueAfter: time.Second}, res, "the image is looked at again when the wait is over")

		now = now.Add(wait)
		f.clock.SetTime(now)
		_, err = f.request(t, digest)
		require.NoError(t, err)
		require.Equal(t, i+2, asks(), "a request once the wait of %s is over", wait)
	}

	// The pods leave the platform, and come back to it.
	observeOn(t, f.store, digest, localCluster, []string{linuxAMD64}, repository)
	_, err = f.request(t, digest)
	require.NoError(t, err)
	observeOn(t, f.store, digest, localCluster, []string{linuxAMD64, linuxARM64}, repository)
	_, err = f.request(t, digest)
	require.NoError(t, err)
	require.Equal(t, 8, asks(), "a platform that the pods come back to isn't new")

	observeOn(t, f.store, digest, localCluster, []string{linuxAMD64, linuxARM64, "linux/s390x"}, repository)
	_, err = f.request(t, digest)
	require.NoError(t, err)
	require.Equal(t, 9, asks(), "a platform that is new since the last request is asked for at once")
}

// The wait of an uncovered platform reaches a day, and the evidence of the image's manifests can go
// without an event that the assessor watches meanwhile. So an image that waits for an uncovered platform
// is looked at again in RetryBase at the latest, as after any request, and asked for at once when its
// evidence is gone.
func TestTheAssessorLooksAtAnImageThatWaitsForAnUncoveredPlatformAgainInRetryBase(t *testing.T) {
	f := newAssessor(t, interceptor.Funcs{}, nil)
	digest, manifest := digestOf(1), digestOf(101)
	observeOn(t, f.store, digest, localCluster, []string{linuxAMD64, linuxARM64}, repository)
	setFacts(t, f.store, digest, scannedBy(scannerVersion, manifest))
	f.storeScans(t, scannerVersion, manifest)

	// Two requests for the platform in a row: the next may come two RetryBases after the second.
	_, err := f.request(t, digest)
	require.NoError(t, err)
	f.clock.SetTime(t0.Add(retryBase))
	_, err = f.request(t, digest)
	require.NoError(t, err)
	require.Len(t, f.asked(), 2)

	f.clock.SetTime(t0.Add(retryBase + time.Minute))
	res, err := f.request(t, digest)
	require.NoError(t, err)
	require.Len(t, f.asked(), 2, "the wait isn't over")
	require.Equal(t, ctrl.Result{RequeueAfter: retryBase}, res,
		"the image is looked at again in RetryBase, before its wait of two RetryBases is over")

	require.NoError(t, f.evidence.DeleteSubject(t.Context(), subjects.Manifest(manifest)))
	f.clock.SetTime(t0.Add(2*retryBase + time.Minute))
	res, err = f.request(t, digest)
	require.NoError(t, err)
	require.Len(t, f.asked(), 3, "the evidence of its manifest is gone, which is asked for at once")
	require.Equal(t, ctrl.Result{RequeueAfter: retryBase}, res)
}

// An assessor without a positive base would ask again at once after every failure.
func TestTheAssessorRefusesToStartWithoutARetryBase(t *testing.T) {
	for name, assessor := range map[string]*hub.Assessor{
		"no retry base":         {},
		"a negative retry base": {RetryBase: -time.Hour},
	} {
		t.Run(name, func(t *testing.T) {
			require.Error(t, assessor.SetupRequestsWithManager(nil))
		})
	}
}

// ---- sheets, on a fake client ----

// scanned stores the evidence of manifest, and the facts of digest that name it, as a scan does.
func (f *assessorFixture) scanned(t *testing.T, digest, manifest string, m imagecontents.Manifest) {
	t.Helper()
	observe(t, f.store, digest, localCluster, repository)
	putScan(t, f.evidence, scannerVersion, t0, m)
	setFacts(t, f.store, digest, scannedBy(scannerVersion, manifest))
}

func TestTheAssessorWritesTheSheetThatThePlaybooksRulesMakeOfTheFindings(t *testing.T) {
	f := newAssessor(t, interceptor.Funcs{}, nil)
	digest, manifest := digestOf(1), digestOf(101)
	f.scanned(t, digest, manifest, evidenceOf(manifest))

	f.assess(t, manifest)

	record, err := f.evidence.Get(t.Context(), evidence.Key{Subject: subjects.Manifest(manifest), Type: imagecontents.Type, Source: scanner})
	require.NoError(t, err)
	require.Equal(t, sheet(v1, sheetEvidenceOf(record), counted{underInvestigation: 2, notAffected: 1},
		otherReached, exampleUnreached, goneSettled), &f.sheetOf(t, manifest).Status)
	require.Equal(t, 1, f.findings.found(manifest))
}

// A sheet is written only when it changes. A match that finds what the sheet holds leaves it as it is:
// the sheet keeps the version of the findings that last changed it.
func TestTheAssessorKeepsAnUnchangedSheetAsItIs(t *testing.T) {
	f := newAssessor(t, interceptor.Funcs{}, nil)
	digest, manifest := digestOf(1), digestOf(101)
	f.scanned(t, digest, manifest, evidenceOf(manifest))
	f.assess(t, manifest)
	before := f.sheetOf(t, manifest)

	f.findings.set(v2, exampleMatch, otherMatch, goneMatch)
	hub.MarkChanged(f.assessor, "")
	f.assess(t, manifest)

	require.Equal(t, 2, f.findings.found(manifest), "the manifest was matched again")
	require.Equal(t, before, f.sheetOf(t, manifest), "nothing was written")
}

// A failed match is no answer, and never an empty list of matches: the sheet stays, and the controller
// tries again.
func TestTheAssessorKeepsTheSheetWhenTheFindingsCollectorFails(t *testing.T) {
	f := newAssessor(t, interceptor.Funcs{}, nil)
	digest, manifest := digestOf(1), digestOf(101)
	f.scanned(t, digest, manifest, evidenceOf(manifest))
	f.assess(t, manifest)
	before := f.sheetOf(t, manifest)
	errMatch := errors.New("the matcher is unavailable")
	f.assessor.Findings = failingFindings{fakeFindings: f.findings, err: errMatch}
	hub.MarkChanged(f.assessor, "")

	_, err := hub.Assess(f.assessor, t.Context(), manifestRequest(manifest))

	require.ErrorIs(t, err, errMatch)
	require.Equal(t, before, f.sheetOf(t, manifest))
}

// failingFindings is a findings collector whose every match fails with its error.
type failingFindings struct {
	*fakeFindings
	err error
}

func (f failingFindings) Find(context.Context, string, cloudevents.Event) (sdkevidence.Findings, error) {
	return sdkevidence.Findings{}, f.err
}

// changeUnitRule changes the spec of the rule of the name on the fake client, which counts no
// generations: it counts one more, as the API server does for a change of the spec.
func changeUnitRule(t *testing.T, c client.Client, name string, change func(*configv1alpha1.RuleSpec)) {
	t.Helper()
	var rule configv1alpha1.Rule
	require.NoError(t, c.Get(t.Context(), client.ObjectKey{Name: name}, &rule))
	change(&rule.Spec)
	rule.Generation++
	require.NoError(t, c.Update(t.Context(), &rule)) // the fake client knows no schema
}

// tightenTheGuard has the completeness guard hold every finding of evidence that covers 100%.
func tightenTheGuard(t *testing.T, c client.Client) {
	t.Helper()
	changeUnitRule(t, c, guardRule, func(spec *configv1alpha1.RuleSpec) {
		spec.Condition = "contents.coverage < 101"
		spec.Reason = ptr.To("'completeness ' + string(contents.coverage) + '% is below 101%'")
	})
}

// A match that fails is no answer, but the rules that the sheet's verdicts rest on may be gone: a rule
// that changed, or one that changed while the operator was down. The sheet is evaluated again from its
// findings with the rules of now, so that a finding that they hold isn't left settled for as long as the
// findings collector fails. The match is tried again.
func TestTheAssessorEvaluatesTheSheetAgainWhenAMatchFailsAfterARuleChanged(t *testing.T) {
	for name, restart := range map[string]bool{"while it runs": false, "after a restart": true} {
		t.Run(name, func(t *testing.T) {
			f := newAssessor(t, interceptor.Funcs{}, nil)
			digest, manifest := digestOf(1), digestOf(101)
			f.scanned(t, digest, manifest, evidenceOf(manifest))
			f.assess(t, manifest)
			require.Equal(t, ptr.To(int32(1)), f.sheetOf(t, manifest).Status.Counts.NotAffected)

			tightenTheGuard(t, f.client)
			errMatch := errors.New("the matcher is unavailable")
			f.assessor.Findings = failingFindings{fakeFindings: f.findings, err: errMatch}
			if restart {
				f.restart()
			} else {
				hub.MarkChanged(f.assessor, "")
			}
			_, err := hub.Assess(f.assessor, t.Context(), manifestRequest(manifest))

			require.ErrorIs(t, err, errMatch, "the match is tried again")
			status := f.sheetOf(t, manifest).Status
			require.Equal(t, ptr.To(int32(0)), status.Counts.NotAffected)
			require.Equal(t, ptr.To(int32(3)), status.Counts.UnderInvestigation)
			require.Equal(t, ptr.To(v1), status.FindingsVersion, "the findings are those of the last match")
			for _, finding := range status.Findings {
				require.Equal(t, ptr.To(guardRule), finding.Rule)
			}
		})
	}
}

// A sheet that can't be evaluated again from its findings, as one that leaves findings out, or one whose
// findings were matched from other evidence, is deleted when a match fails after what it rested on
// changed: its verdicts rest on what is gone, and no sheet means no verdict yet.
func TestTheAssessorDeletesTheSheetWhenAMatchFailsAndItCantBeEvaluatedAgain(t *testing.T) {
	for _, tc := range []struct {
		name    string
		matches []sdkevidence.Match
		change  func(t *testing.T, f *assessorFixture, manifest string)
	}{
		{"the sheet leaves findings out", manyMatches(2100), func(t *testing.T, f *assessorFixture, _ string) {
			tightenTheGuard(t, f.client)
			hub.MarkChanged(f.assessor, "")
		}},
		{"the evidence changed", []sdkevidence.Match{exampleMatch, otherMatch, goneMatch}, func(t *testing.T, f *assessorFixture, manifest string) {
			putScan(t, f.evidence, olderScanner, t0.Add(time.Hour), evidenceOf(manifest))
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newAssessor(t, interceptor.Funcs{}, nil)
			digest, manifest := digestOf(1), digestOf(101)
			f.findings.set(v1, tc.matches...)
			f.scanned(t, digest, manifest, evidenceOf(manifest))
			f.assess(t, manifest)
			require.NotNil(t, f.sheetOf(t, manifest))

			tc.change(t, f, manifest)
			errMatch := errors.New("the matcher is unavailable")
			f.assessor.Findings = failingFindings{fakeFindings: f.findings, err: errMatch}
			_, err := hub.Assess(f.assessor, t.Context(), manifestRequest(manifest))

			require.ErrorIs(t, err, errMatch, "the match is tried again")
			require.Nil(t, f.sheetOf(t, manifest))
		})
	}
}

// renamedFindings is the findings collector of the fixture, standing for the Collector of another name.
type renamedFindings struct {
	*fakeFindings
	name string
}

func (f renamedFindings) Find(ctx context.Context, collector string, input cloudevents.Event) (sdkevidence.Findings, error) {
	if collector != f.name {
		return sdkevidence.Findings{}, errors.New("no findings collector here matches that")
	}
	return f.fakeFindings.Find(ctx, matcherCollector, input)
}

func (f renamedFindings) Consumes(ctx context.Context, collector string) ([]string, error) {
	if collector != f.name {
		return nil, nil
	}
	return f.fakeFindings.Consumes(ctx, matcherCollector)
}

// The findings of a sheet are those of the findings collector that matched them. A playbook that names
// another one has the manifest matched again, and not the old collector's findings evaluated again.
func TestTheAssessorMatchesAgainWhenThePlaybookNamesAnotherFindingsCollector(t *testing.T) {
	f := newAssessor(t, interceptor.Funcs{}, nil)
	digest, manifest := digestOf(1), digestOf(101)
	f.scanned(t, digest, manifest, evidenceOf(manifest))
	f.assess(t, manifest)
	require.Equal(t, 1, f.findings.found(manifest))

	const other = "other-matcher"
	require.NoError(t, f.client.Create(t.Context(), collectorNamed(other)))
	var playbook configv1alpha1.Playbook
	require.NoError(t, f.client.Get(t.Context(), client.ObjectKey{Name: playbookName}, &playbook))
	playbook.Spec.Findings.Collector = other
	playbook.Generation++
	require.NoError(t, f.client.Update(t.Context(), &playbook)) // the fake client knows no schema
	f.assessor.Findings = renamedFindings{fakeFindings: f.findings, name: other}
	f.assess(t, manifest)

	require.Equal(t, 2, f.findings.found(manifest), "the other findings collector matched the manifest")
}

// The version of a collector is what the collector reports. The sheet shows it printable.
func TestTheAssessorShowsTheVersionOfACollectorPrintable(t *testing.T) {
	f := newAssessor(t, interceptor.Funcs{}, nil)
	digest, manifest := digestOf(1), digestOf(101)
	const version = "scanner:1.0\x1b[31m\u202e"
	observe(t, f.store, digest, localCluster, repository)
	putScan(t, f.evidence, version, t0, evidenceOf(manifest))
	setFacts(t, f.store, digest, scannedBy(version, manifest))

	f.assess(t, manifest)

	require.Equal(t, ptr.To("scanner:1.0\uFFFD[31m\uFFFD"), f.sheetOf(t, manifest).Status.Evidence[0].Version)
}

// A sheet never outlives the evidence that its findings were matched from, nor a playbook that
// assesses it.
func TestTheAssessorDeletesTheSheetOfAManifestThatNothingAssesses(t *testing.T) {
	for name, gone := range map[string]func(t *testing.T, f *assessorFixture, manifest string){
		"the evidence is gone": func(t *testing.T, f *assessorFixture, manifest string) {
			require.NoError(t, f.evidence.DeleteSubject(t.Context(), subjects.Manifest(manifest)))
		},
		"no playbook assesses it": func(t *testing.T, f *assessorFixture, _ string) {
			require.NoError(t, f.client.Delete(t.Context(), &configv1alpha1.Playbook{ObjectMeta: metav1.ObjectMeta{Name: playbookName}}))
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := newAssessor(t, interceptor.Funcs{}, nil)
			digest, manifest := digestOf(1), digestOf(101)
			f.scanned(t, digest, manifest, evidenceOf(manifest))
			f.assess(t, manifest)
			require.NotNil(t, f.sheetOf(t, manifest))

			gone(t, f, manifest)
			f.assess(t, manifest)

			require.Nil(t, f.sheetOf(t, manifest))
		})
	}
}

// A playbook that isn't Ready can't match. A sheet that leaves findings out can't be evaluated again
// from them, and neither can findings with other evidence than they were matched from: they could name
// packages that it lacks, or that are other packages in it. Such a sheet's findings rested on what is
// now gone, so the sheet says that there is no verdict.
func TestTheAssessorDeletesASheetThatItCanNeitherMatchNorEvaluateAgain(t *testing.T) {
	for _, tc := range []struct {
		name    string
		matches []sdkevidence.Match
		change  func(t *testing.T, f *assessorFixture, manifest string)
	}{
		{"the sheet leaves findings out", manyMatches(2100), func(t *testing.T, f *assessorFixture, _ string) {
			require.NoError(t, f.client.Delete(t.Context(), &configv1alpha1.Rule{ObjectMeta: metav1.ObjectMeta{Name: loadCheckRule}}))
		}},
		{"the evidence changed since the match", []sdkevidence.Match{exampleMatch, otherMatch, goneMatch},
			func(t *testing.T, f *assessorFixture, manifest string) {
				require.NoError(t, f.client.Delete(t.Context(), collectorNamed(matcherCollector)))
				putScan(t, f.evidence, olderScanner, t0.Add(time.Hour), evidenceOf(manifest))
			}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newAssessor(t, interceptor.Funcs{}, nil)
			digest, manifest := digestOf(1), digestOf(101)
			f.findings.set(v1, tc.matches...)
			f.scanned(t, digest, manifest, evidenceOf(manifest))
			f.assess(t, manifest)
			require.NotNil(t, f.sheetOf(t, manifest))

			tc.change(t, f, manifest)
			f.assess(t, manifest)

			require.Nil(t, f.sheetOf(t, manifest))
			require.Equal(t, 1, f.findings.found(manifest), "a playbook that isn't Ready matches nothing")
		})
	}
}

// A rule that is missing, or isn't Ready, can't be evaluated, and might hold: it keeps every finding from
// NotAffected and Fixed, and the sheet says which rule and why.
func TestTheAssessorHoldsTheFindingsOfASheetOpenWhenARuleIsMissingOrNotReady(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(t *testing.T, c client.Client)
		reason string
	}{
		{"missing", func(t *testing.T, c client.Client) {
			require.NoError(t, c.Delete(t.Context(), &configv1alpha1.Rule{ObjectMeta: metav1.ObjectMeta{Name: guardRule}}))
		}, "could not be evaluated: the rule is missing"},
		{"not Ready", func(t *testing.T, c client.Client) {
			changeUnitRule(t, c, guardRule, func(spec *configv1alpha1.RuleSpec) {
				spec.Condition = "contents.coverage <" // doesn't compile
			})
		}, "could not be evaluated: the rule isn't Ready"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newAssessor(t, interceptor.Funcs{}, nil)
			digest, manifest := digestOf(1), digestOf(101)
			f.scanned(t, digest, manifest, evidenceOf(manifest))
			f.assess(t, manifest)
			require.Equal(t, ptr.To(int32(1)), f.sheetOf(t, manifest).Status.Counts.NotAffected)

			tc.change(t, f.client)
			f.assess(t, manifest)

			status := f.sheetOf(t, manifest).Status
			require.Equal(t, ptr.To(int32(0)), status.Counts.NotAffected)
			require.Equal(t, ptr.To(int32(3)), status.Counts.UnderInvestigation)
			for _, finding := range status.Findings {
				require.Equal(t, ptr.To(guardRule), finding.Rule)
				require.Equal(t, ptr.To(tc.reason), finding.Reason)
			}
			require.Equal(t, 1, f.findings.found(manifest), "the sheet was evaluated again from its findings")
		})
	}
}
