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

package worker_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clocktesting "k8s.io/utils/clock/testing"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
	inventoryv1alpha1 "github.com/bedag/vexplain/api/inventory/v1alpha1"
	triagev1alpha1 "github.com/bedag/vexplain/api/triage/v1alpha1"
	"github.com/bedag/vexplain/internal/agent/casefile"
	"github.com/bedag/vexplain/internal/agent/cases"
	"github.com/bedag/vexplain/internal/agent/profile"
	"github.com/bedag/vexplain/internal/agent/worker"
	"github.com/bedag/vexplain/internal/controller/hub"
	"github.com/bedag/vexplain/internal/inventory"
	"github.com/bedag/vexplain/internal/settings"
	"github.com/bedag/vexplain/sdk/workloads"
)

const (
	playbook = "container-cves"
	// team and investigation name the investigation that queues the specs' cases.
	team          = "team-a"
	investigation = "most-urgent"
	workerA       = "vexplain-agent-a"
	workerB       = "vexplain-agent-b"
	// within bounds how long a worker, or the agent with a scripted model, takes to react in these tests.
	within = 10 * time.Second
	often  = 10 * time.Millisecond
	quiet  = 300 * time.Millisecond
)

// start is when the specs' clock starts: a whole second, which a status's times hold exactly.
var start = time.Date(2026, 11, 20, 10, 0, 0, 0, time.UTC)

// fixture is an API server's fake with the sheets and the Assessments of the queued cases, and a clock that the specs
// move.
type fixture struct {
	api      client.WithWatch
	clock    *clocktesting.FakeClock
	verdicts inventory.VerdictsStore
	store    inventory.Store
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	scheme := runtime.NewScheme()
	require.NoError(t, configv1alpha1.AddToScheme(scheme))
	require.NoError(t, inventoryv1alpha1.AddToScheme(scheme))
	require.NoError(t, triagev1alpha1.AddToScheme(scheme))
	api := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(&triagev1alpha1.Assessment{},
		&inventoryv1alpha1.ImageVerdicts{}, &inventoryv1alpha1.ImageInventory{}).Build()
	local := func() string { return "cluster-a" }
	return &fixture{api: api, clock: clocktesting.NewFakeClock(start), verdicts: inventory.NewCRDVerdictsStore(api, local),
		store: inventory.NewCRDStore(api, nil, local)}
}

// queue writes the sheet of a case of the vulnerability in a manifest of its own, creates its Assessment and queues it
// at the urgency rank for an investigation of the trigger, and returns the Assessment's name.
func (f *fixture) queue(t *testing.T, cve string, rank int32, trigger triagev1alpha1.InvestigationTriggerType) string {
	t.Helper()
	ctx := t.Context()
	sum := sha256.Sum256([]byte(cve))
	digest := "sha256:" + hex.EncodeToString(sum[:])
	require.NoError(t, f.verdicts.Put(ctx, digest, playbook, inventoryv1alpha1.ImageVerdictsStatus{
		Playbook: ptr.To(playbook), FindingsVersion: ptr.To("v1"), Findings: []inventoryv1alpha1.Finding{{
			VulnerabilityID: cve,
			Package: inventoryv1alpha1.PackageReference{ID: "pkg-1", Name: "libexample1", Version: ptr.To("1.0-1"),
				Type: "deb"},
			Status: inventoryv1alpha1.VEXStatusUnderInvestigation, Severity: inventoryv1alpha1.SeverityHigh,
			FixState: inventoryv1alpha1.FixStateNotFixed, KnownExploited: inventoryv1alpha1.KnownExploitedNotListed,
		}},
	}))
	a := &triagev1alpha1.Assessment{ObjectMeta: metav1.ObjectMeta{Name: cases.Name(cve, digest)},
		Spec: triagev1alpha1.AssessmentSpec{Subject: triagev1alpha1.AssessmentSubject{
			Type: triagev1alpha1.SubjectTypeContainerImage, ContainerImage: &triagev1alpha1.ContainerImageSubject{Digest: digest}},
			VulnerabilityID: cve}}
	require.NoError(t, f.api.Create(ctx, a))
	a.Status.Queue = &triagev1alpha1.AssessmentQueue{Playbook: playbook,
		InvestigationRef: &triagev1alpha1.InvestigationReference{Namespace: team, Name: investigation, UID: "uid-" + types.UID(investigation)},
		Requests: []triagev1alpha1.QueueRequest{{InvestigationRef: triagev1alpha1.InvestigationReference{Namespace: team,
			Name: investigation, UID: "uid-" + types.UID(investigation)}, Trigger: trigger}},
		Order: triagev1alpha1.QueueOrder{UrgencyRank: ptr.To(rank), KnownExploited: triagev1alpha1.KnownExploitedNotListed,
			Resources: ptr.To(int32(1))},
		QueuedTime: ptr.To(metav1.NewTime(f.clock.Now()))}
	meta.SetStatusCondition(&a.Status.Conditions, metav1.Condition{Type: configv1alpha1.ConditionReady,
		Status: metav1.ConditionFalse, Reason: triagev1alpha1.ReasonQueued, Message: "The case waits for the agent."})
	require.NoError(t, f.api.Status().Update(ctx, a))
	f.clock.Step(time.Second) // the next case comes later
	return a.Name
}

// get returns the Assessment of the name as the API server has it.
func (f *fixture) get(t *testing.T, name string) *triagev1alpha1.Assessment {
	t.Helper()
	a := &triagev1alpha1.Assessment{}
	require.NoError(t, f.api.Get(t.Context(), client.ObjectKey{Name: name}, a))
	return a
}

// update changes the status of the Assessment of the name, as the hub or another worker would.
func (f *fixture) update(t *testing.T, name string, change func(*triagev1alpha1.AssessmentStatus)) {
	t.Helper()
	a := f.get(t, name)
	change(&a.Status)
	require.NoError(t, f.api.Status().Update(t.Context(), a))
}

// stale returns a client whose lists of Assessments show them as they are now, as a cache that lags behind would.
func (f *fixture) stale(t *testing.T) client.Client {
	t.Helper()
	var then triagev1alpha1.AssessmentList
	require.NoError(t, f.api.List(t.Context(), &then))
	return interceptor.NewClient(f.api, interceptor.Funcs{
		List: func(ctx context.Context, c client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
			if l, ok := list.(*triagev1alpha1.AssessmentList); ok {
				then.DeepCopyInto(l)
				return nil
			}
			return c.List(ctx, list, opts...)
		},
	})
}

// loop returns a loop of the worker of the name, which judges with judge, one case at a time over all workers.
func (f *fixture) loop(name string, judge worker.Judge) *worker.Loop {
	return &worker.Loop{Client: f.api, APIReader: f.api, Verdicts: f.verdicts, Store: f.store, Name: name,
		Limit: func() int { return 1 }, Judge: judge, Clock: f.clock}
}

// run starts the loop, and stops it after the test, waiting for it.
func run(t *testing.T, l *worker.Loop) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- l.Start(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			require.NoError(t, err)
		case <-time.After(within):
			t.Error("the loop didn't stop")
		}
	})
}

// judgements records which worker judges which case, and holds each judgement until its context ends, unless
// release is closed.
type judgements struct {
	mu      sync.Mutex
	by      map[string][]string
	started chan string
	release chan struct{}
}

func newJudgements() *judgements {
	return &judgements{by: map[string][]string{}, started: make(chan string, 10), release: make(chan struct{})}
}

func (j *judgements) judge(ctx context.Context, c cases.Case, _ cases.Request, _ int) worker.Result {
	name := cases.Name(c.VulnerabilityID, c.ManifestDigest)
	j.mu.Lock()
	j.by[name] = append(j.by[name], worker.Claimant(ctx))
	j.mu.Unlock()
	j.started <- name
	select {
	case <-ctx.Done():
		return worker.Wait
	case <-j.release:
		return worker.Done
	}
}

// next returns the case of the next judgement that starts.
func (j *judgements) next(t *testing.T) string {
	t.Helper()
	select {
	case name := <-j.started:
		return name
	case <-time.After(within):
		t.Fatal("no judgement started")
		return ""
	}
}

// workers returns the workers that judged the case.
func (j *judgements) workers(name string) []string {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.by[name]
}

func readyReason(a *triagev1alpha1.Assessment) string {
	if c := meta.FindStatusCondition(a.Status.Conditions, configv1alpha1.ConditionReady); c != nil {
		return c.Reason
	}
	return ""
}

// The most urgent tier goes first; within a tier, a case that a person asked for, through an investigation that runs
// Once; then the first come.
func TestTheFirstCaseInOrderIsClaimed(t *testing.T) {
	f := newFixture(t)
	scheduled := f.queue(t, "CVE-2026-0003", 3, triagev1alpha1.InvestigationTriggerContinuous)
	early := f.queue(t, "CVE-2026-0002", 2, triagev1alpha1.InvestigationTriggerContinuous)
	asked := f.queue(t, "CVE-2026-0012", 2, triagev1alpha1.InvestigationTriggerOnce)
	late := f.queue(t, "CVE-2026-0022", 2, triagev1alpha1.InvestigationTriggerContinuous)
	immediate := f.queue(t, "CVE-2026-0001", 1, triagev1alpha1.InvestigationTriggerContinuous)
	j := newJudgements()
	run(t, f.loop(workerA, j.judge))

	require.Equal(t, immediate, j.next(t))
	a := f.get(t, immediate)
	require.NotNil(t, a.Status.Claim)
	require.Equal(t, workerA, a.Status.Claim.Worker)
	require.Equal(t, start.Add(5*time.Second+worker.DefaultLease), a.Status.Claim.LeaseEndTime.UTC())
	require.Equal(t, triagev1alpha1.ReasonJudging, readyReason(a))

	close(j.release)
	require.Equal(t, []string{asked, early, late, scheduled}, []string{j.next(t), j.next(t), j.next(t), j.next(t)})
	require.Equal(t, []string{workerA}, j.workers(immediate))
}

// Two workers that claim the same case from a cache that shows it waiting: one wins, and the other claims the next.
func TestOneOfTwoClaimsWins(t *testing.T) {
	f := newFixture(t)
	first := f.queue(t, "CVE-2026-0001", 1, triagev1alpha1.InvestigationTriggerContinuous)
	second := f.queue(t, "CVE-2026-0002", 2, triagev1alpha1.InvestigationTriggerContinuous)
	j := newJudgements()
	a, b := f.loop(workerA, j.judge), f.loop(workerB, j.judge)
	a.Client, b.Client = f.stale(t), f.stale(t)

	run(t, a)
	require.Equal(t, first, j.next(t))
	run(t, b)
	require.Equal(t, second, j.next(t))

	require.Equal(t, []string{workerA}, j.workers(first), "judged once")
	require.Equal(t, []string{workerB}, j.workers(second))
	require.Equal(t, workerB, f.get(t, second).Status.Claim.Worker)
}

// The limit counts the cases that every worker judges, as the claims show them.
func TestTheLimitHoldsAcrossWorkers(t *testing.T) {
	f := newFixture(t)
	busy := f.queue(t, "CVE-2026-0001", 1, triagev1alpha1.InvestigationTriggerContinuous)
	f.queue(t, "CVE-2026-0002", 2, triagev1alpha1.InvestigationTriggerContinuous)
	f.update(t, busy, func(s *triagev1alpha1.AssessmentStatus) {
		s.Claim = &triagev1alpha1.QueueClaim{Worker: workerB, LeaseEndTime: ptr.To(metav1.NewTime(start.Add(time.Hour)))}
	})
	j := newJudgements()
	run(t, f.loop(workerA, j.judge))

	require.Never(t, func() bool { return len(j.started) > 0 }, quiet, often, "nothing is claimed")
}

// While no case can start, because the agent is switched off or the default profile's ModelConfig isn't Ready, a
// worker claims nothing: claiming each waiting case only for the judge to hand it back would write every Assessment
// twice each RetryDelay. Once cases can start again, they are claimed.
func TestNothingIsClaimedWhileNoCaseCanStart(t *testing.T) {
	setModel := func(t *testing.T, f *fixture, status metav1.ConditionStatus) {
		t.Helper()
		var model configv1alpha1.ModelConfig
		require.NoError(t, f.api.Get(t.Context(), client.ObjectKey{Name: profile.DefaultName}, &model))
		meta.SetStatusCondition(&model.Status.Conditions, metav1.Condition{Type: configv1alpha1.ConditionReady,
			Status: status, Reason: "Probed", ObservedGeneration: model.Generation})
		require.NoError(t, f.api.Update(t.Context(), &model))
	}
	switchTo := func(t *testing.T, f *fixture, state configv1alpha1.AgentState) {
		t.Helper()
		cfg := &configv1alpha1.OperatorConfig{ObjectMeta: metav1.ObjectMeta{Name: settings.ConfigName}}
		_, err := controllerutil.CreateOrUpdate(t.Context(), f.api, cfg, func() error {
			cfg.Spec.Agent = &configv1alpha1.AgentSettings{State: ptr.To(state)}
			return nil
		})
		require.NoError(t, err)
	}
	for _, tc := range []struct {
		name        string
		stop, start func(*testing.T, *fixture)
	}{
		{"switched off",
			func(t *testing.T, f *fixture) { switchTo(t, f, configv1alpha1.AgentStateDisabled) },
			func(t *testing.T, f *fixture) { switchTo(t, f, configv1alpha1.AgentStateEnabled) }},
		{"the default profile's ModelConfig isn't Ready",
			func(t *testing.T, f *fixture) { setModel(t, f, metav1.ConditionFalse) },
			func(t *testing.T, f *fixture) { setModel(t, f, metav1.ConditionTrue) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			require.NoError(t, f.api.Create(t.Context(), &configv1alpha1.AgentProfile{
				ObjectMeta: metav1.ObjectMeta{Name: profile.DefaultName},
				Spec:       configv1alpha1.AgentProfileSpec{ModelRef: configv1alpha1.ModelConfigReference{Name: profile.DefaultName}}}))
			require.NoError(t, f.api.Create(t.Context(), &configv1alpha1.ModelConfig{
				ObjectMeta: metav1.ObjectMeta{Name: profile.DefaultName},
				Spec: configv1alpha1.ModelConfigSpec{Endpoint: "https://llm.example/v1", Model: "model-a",
					APIKeySecretRef: configv1alpha1.SecretKeyRef{Name: "llm-api-key", Key: "api-key"}}}))
			setModel(t, f, metav1.ConditionTrue)
			tc.stop(t, f)
			for i := range 5 {
				f.queue(t, fmt.Sprintf("CVE-2026-%04d", i+1), 1, triagev1alpha1.InvestigationTriggerContinuous)
			}
			var writes atomic.Int32
			j := newJudgements()
			l := f.loop(workerA, j.judge)
			l.Client = interceptor.NewClient(f.api, interceptor.Funcs{
				SubResourceUpdate: func(ctx context.Context, c client.Client, sub string, obj client.Object,
					opts ...client.SubResourceUpdateOption) error {
					writes.Add(1)
					return c.SubResource(sub).Update(ctx, obj, opts...)
				},
			})
			l.CanStart = (&worker.Agent{Client: f.api}).CanStart
			run(t, l)

			for range 3 {
				require.Never(t, func() bool { return writes.Load() > 0 || len(j.started) > 0 }, quiet, often,
					"nothing is claimed, and nothing written")
				f.clock.Step(cases.DefaultRetryDelay)
			}
			tc.start(t, f)
			f.clock.Step(time.Second)

			j.next(t)
			require.Positive(t, writes.Load())
		})
	}
}

// A judgement that takes long renews its lease, every Renew, Lease ahead.
func TestTheLeaseIsRenewed(t *testing.T) {
	f := newFixture(t)
	name := f.queue(t, "CVE-2026-0001", 1, triagev1alpha1.InvestigationTriggerContinuous)
	j := newJudgements()
	run(t, f.loop(workerA, j.judge))
	j.next(t)
	claimed := f.clock.Now()

	for i := 1; i <= 3; i++ {
		f.clock.Step(worker.DefaultRenew)
		want := claimed.Add(time.Duration(i)*worker.DefaultRenew + worker.DefaultLease)
		require.Eventually(t, func() bool { return f.get(t, name).Status.Claim.LeaseEndTime.Time.Equal(want) }, within, often,
			"renewal %d", i)
	}
}

// A renewal that conflicts with a write of the hub reads the case again, and keeps its claim.
func TestAConflictOnRenewalKeepsTheClaim(t *testing.T) {
	f := newFixture(t)
	name := f.queue(t, "CVE-2026-0001", 1, triagev1alpha1.InvestigationTriggerContinuous)
	var conflicted atomic.Bool
	l := f.loop(workerA, nil)
	j := newJudgements()
	l.Judge = j.judge
	l.Client = interceptor.NewClient(f.api, interceptor.Funcs{
		SubResourceUpdate: func(ctx context.Context, c client.Client, sub string, obj client.Object,
			opts ...client.SubResourceUpdateOption) error {
			a, ok := obj.(*triagev1alpha1.Assessment)
			// The renewal read the case; the hub adds a request before it writes.
			if ok && a.Status.Claim != nil && a.Status.Claim.LeaseEndTime.After(start.Add(worker.DefaultLease+5*time.Second)) &&
				conflicted.CompareAndSwap(false, true) {
				f.update(t, name, func(s *triagev1alpha1.AssessmentStatus) {
					s.Queue.Requests = append(s.Queue.Requests, triagev1alpha1.QueueRequest{
						InvestigationRef: triagev1alpha1.InvestigationReference{Namespace: team, Name: "another", UID: "uid-another"},
						Trigger:          triagev1alpha1.InvestigationTriggerContinuous})
				})
			}
			return c.SubResource(sub).Update(ctx, obj, opts...)
		},
	})
	run(t, l)
	j.next(t)
	claimed := f.clock.Now()

	f.clock.Step(worker.DefaultRenew)

	want := claimed.Add(worker.DefaultRenew + worker.DefaultLease)
	require.Eventually(t, func() bool { return f.get(t, name).Status.Claim.LeaseEndTime.Time.Equal(want) }, within, often)
	require.True(t, conflicted.Load())
	a := f.get(t, name)
	require.Equal(t, workerA, a.Status.Claim.Worker)
	require.Len(t, a.Status.Queue.Requests, 2, "the hub's write stands")
	require.Equal(t, triagev1alpha1.ReasonJudging, readyReason(a), "the judgement goes on")
}

// Once the claim names another worker, as after a lease that ran out, the judgement stops, and its worker leaves the
// other's claim alone.
func TestAClaimByAnotherWorkerStopsTheJudge(t *testing.T) {
	f := newFixture(t)
	name := f.queue(t, "CVE-2026-0001", 1, triagev1alpha1.InvestigationTriggerContinuous)
	ended := make(chan struct{})
	run(t, f.loop(workerA, func(ctx context.Context, _ cases.Case, _ cases.Request, _ int) worker.Result {
		<-ctx.Done()
		close(ended)
		return worker.Wait
	}))
	require.Eventually(t, func() bool { return f.get(t, name).Status.Claim != nil }, within, often)

	f.update(t, name, func(s *triagev1alpha1.AssessmentStatus) {
		s.Claim = &triagev1alpha1.QueueClaim{Worker: workerB, LeaseEndTime: ptr.To(metav1.NewTime(start.Add(time.Hour)))}
	})
	f.clock.Step(worker.DefaultRenew)

	select {
	case <-ended:
	case <-time.After(within):
		t.Fatal("the judge's context didn't end")
	}
	require.Never(t, func() bool { c := f.get(t, name).Status.Claim; return c == nil || c.Worker != workerB }, quiet, often,
		"the other worker keeps its claim")
}

// A judgement that failed after spending tokens counts a failure and a miss; one that failed before counts a miss.
// Each waits RetryDelay, doubled for each miss in a row.
func TestAFailedJudgementBacksOff(t *testing.T) {
	f := newFixture(t)
	name := f.queue(t, "CVE-2026-0001", 1, triagev1alpha1.InvestigationTriggerContinuous)
	results := make(chan worker.Result, 3)
	seen := make(chan int, 3)
	for _, r := range []worker.Result{worker.Failed, worker.Failed, worker.Retry} {
		results <- r
	}
	run(t, f.loop(workerA, func(_ context.Context, _ cases.Case, _ cases.Request, failures int) worker.Result {
		seen <- failures
		return <-results
	}))
	waited := func(failures, misses int32, wait time.Duration) func() bool {
		return func() bool {
			a := f.get(t, name)
			q := a.Status.Queue
			return a.Status.Claim == nil && readyReason(a) == triagev1alpha1.ReasonQueued &&
				ptr.Deref(q.Failures, 0) == failures && ptr.Deref(q.Misses, 0) == misses &&
				q.NotBefore != nil && q.NotBefore.Time.Equal(f.clock.Now().Add(wait))
		}
	}

	require.Eventually(t, waited(1, 1, 10*time.Second), within, often)
	require.Equal(t, 0, <-seen)
	f.clock.Step(10 * time.Second)
	require.Eventually(t, waited(2, 2, 20*time.Second), within, often)
	require.Equal(t, 1, <-seen)
	f.clock.Step(20 * time.Second)
	require.Eventually(t, waited(2, 3, 40*time.Second), within, often, "a retry counts a miss only")
	require.Equal(t, 2, <-seen)
}

// A case whose sheet holds it no more leaves the queue withdrawn, unjudged.
func TestACaseWhoseSheetIsGoneIsWithdrawn(t *testing.T) {
	f := newFixture(t)
	name := f.queue(t, "CVE-2026-0001", 1, triagev1alpha1.InvestigationTriggerContinuous)
	a := f.get(t, name)
	require.NoError(t, f.verdicts.Delete(t.Context(), a.Spec.Subject.ContainerImage.Digest, playbook))
	j := newJudgements()
	run(t, f.loop(workerA, j.judge))

	require.Eventually(t, func() bool { return readyReason(f.get(t, name)) == triagev1alpha1.ReasonWithdrawn }, within, often)
	a = f.get(t, name)
	require.Nil(t, a.Status.Queue)
	require.Nil(t, a.Status.Claim)
	require.Empty(t, j.started, "not judged")
}

// A worker rebuilds a case without the exposure rules, which only the hub runs: it lays over the case where the hub
// found that it runs, as the Assessment's queue holds it, so that the case file shows the rules' exposure. A case queued
// without it is rebuilt as it was before.
func TestTheCaseFileTakesRunsInFromTheQueue(t *testing.T) {
	f := newFixture(t)
	with := f.queue(t, "CVE-2026-0001", 1, triagev1alpha1.InvestigationTriggerContinuous)
	shop := "workload/cluster-a/team-a/Deployment.apps/shop"
	f.update(t, with, func(s *triagev1alpha1.AssessmentStatus) {
		s.Queue.RunsIn = &triagev1alpha1.QueueRunsIn{HighestExposure: ptr.To(triagev1alpha1.SSVCExposureControlled),
			HighestUrgency: ptr.To(triagev1alpha1.SSVCOutcomeScheduled), UrgentWorkloads: ptr.To(int32(0)),
			Exposure: []triagev1alpha1.ExposureGroup{{Exposure: triagev1alpha1.SSVCExposureControlled,
				Rules: []string{"exposed-not-published"}, Workloads: ptr.To(int32(1)), First: []string{shop}}}}
	})
	without := f.queue(t, "CVE-2026-0002", 2, triagev1alpha1.InvestigationTriggerContinuous)
	seen := make(chan cases.Case, 2)
	run(t, f.loop(workerA, func(_ context.Context, c cases.Case, _ cases.Request, _ int) worker.Result {
		seen <- c
		return worker.Done
	}))
	next := func() cases.Case {
		t.Helper()
		select {
		case c := <-seen:
			return c
		case <-time.After(within):
			t.Fatal("no case was judged")
			return cases.Case{}
		}
	}

	c := next()
	require.Equal(t, with, cases.Name(c.VulnerabilityID, c.ManifestDigest))
	file, err := casefile.Build(c, nil, nil, 64000)
	require.NoError(t, err)
	require.Contains(t, string(file.JSON), `"highestExposure":"Controlled","highestUrgency":"Scheduled",`+
		`"exposure":[{"exposure":"Controlled","rules":["exposed-not-published"],"workloads":1,"first":["`+shop+`"]}]`)
	require.Contains(t, string(file.JSON), `"workloadsByExposure":{"Controlled":1}`)

	c = next()
	require.Equal(t, without, cases.Name(c.VulnerabilityID, c.ManifestDigest))
	require.Equal(t, cases.Impact{WorkloadsByExposure: map[configv1alpha1.SSVCExposure]int32{}}, c.Impact,
		"rebuilt from the inventory, which knows no workload of it")
}

// A worker can't read the Spokes, whose labels say which clusters a playbook's match selects: it counts the workloads of
// the clusters that the hub queued the case with, and no other's.
func TestTheWorkerSelectsTheQueuedClusters(t *testing.T) {
	const remoteCluster = "cluster-b"
	f := newFixture(t)
	name := f.queue(t, "CVE-2026-0001", 1, triagev1alpha1.InvestigationTriggerContinuous)
	manifest := f.get(t, name).Spec.Subject.ContainerImage.Digest
	for cluster, apps := range map[string][]string{localCluster: {"shop", "cart"}, remoteCluster: {"batch"}} {
		refs := make([]workloads.WorkloadRef, 0, len(apps))
		for _, app := range apps {
			refs = append(refs, workloads.WorkloadRef{Kind: "Deployment", Namespace: team, Name: app})
		}
		require.NoError(t, f.store.Observe(t.Context(), manifest, inventory.Observation{Cluster: cluster,
			ClusterID: cluster + "-id", DigestKind: inventoryv1alpha1.DigestKindRepoDigest,
			Repositories: []string{"artifacts.example/team-a/app"}, NamespaceCount: 1, Workloads: refs}))
	}
	_, err := f.store.SetFacts(t.Context(), manifest, &inventoryv1alpha1.ImageFacts{
		Manifests: []inventoryv1alpha1.ManifestFact{{Platform: "linux/amd64", Digest: manifest}}})
	require.NoError(t, err)
	f.update(t, name, func(s *triagev1alpha1.AssessmentStatus) {
		s.Queue.RunsIn = &triagev1alpha1.QueueRunsIn{Clusters: []string{remoteCluster}}
	})
	seen := make(chan cases.Case, 1)
	run(t, f.loop(workerA, func(_ context.Context, c cases.Case, _ cases.Request, _ int) worker.Result {
		seen <- c
		return worker.Done
	}))

	select {
	case c := <-seen:
		require.Equal(t, []string{remoteCluster}, c.Impact.ClusterNames)
		require.Equal(t, int32(1), c.Impact.Resources, "the workloads of the queued cluster alone")
	case <-time.After(within):
		t.Fatal("no case was judged")
	}
}

// A worker whose renewal failed stops the judgement once its next renewal would come no sooner than the end of the
// last lease that it wrote, as a leader whose renewal deadline passed steps down: a next renewal that hung for its
// whole timeout would leave the judgement running into the sweep's grace, which is there for clocks that differ.
func TestALeaseThatCantBeRenewedStopsTheJudge(t *testing.T) {
	f := newFixture(t)
	name := f.queue(t, "CVE-2026-0001", 1, triagev1alpha1.InvestigationTriggerContinuous)
	var failing atomic.Bool
	refused := func() error { return apierrors.NewServiceUnavailable("the API server is away") }
	l := f.loop(workerA, nil)
	l.APIReader = interceptor.NewClient(f.api, interceptor.Funcs{
		Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
			if failing.Load() {
				return refused()
			}
			return c.Get(ctx, key, obj, opts...)
		},
	})
	l.Client = interceptor.NewClient(f.api, interceptor.Funcs{
		SubResourceUpdate: func(ctx context.Context, c client.Client, sub string, obj client.Object,
			opts ...client.SubResourceUpdateOption) error {
			if failing.Load() {
				return refused()
			}
			return c.SubResource(sub).Update(ctx, obj, opts...)
		},
	})
	ended := make(chan struct{})
	started := make(chan struct{})
	l.Judge = func(ctx context.Context, _ cases.Case, _ cases.Request, _ int) worker.Result {
		close(started)
		<-ctx.Done()
		close(ended)
		return worker.Wait
	}
	run(t, l)
	<-started
	claimed := f.get(t, name)
	failing.Store(true)

	f.clock.Step(worker.DefaultRenew) // a renewal fails, and the next comes well before the lease ends
	select {
	case <-ended:
		t.Fatal("the judge stopped while a renewal could still go through in time")
	case <-time.After(quiet):
	}
	f.clock.Step(worker.DefaultRenew) // another fails, and the next would come as the lease ends

	select {
	case <-ended:
	case <-time.After(within):
		t.Fatal("the judge's context didn't end")
	}
	require.True(t, f.clock.Now().Before(claimed.Status.Claim.LeaseEndTime.Time), "it stops before its lease ends")
	require.Equal(t, claimed, f.get(t, name), "nothing is written")
}

// A renewal whose call to the API server hangs gives up after its timeout, which is shorter than the sweep's grace:
// so the judge stops once its lease ended, before the sweep can hand the case to another worker.
func TestARenewalThatHangsGivesUpInTime(t *testing.T) {
	f := newFixture(t)
	f.queue(t, "CVE-2026-0001", 1, triagev1alpha1.InvestigationTriggerContinuous)
	l := f.loop(workerA, nil)
	l.RenewTimeout = 50 * time.Millisecond
	// The renewals read under the judge's context, which names the worker; the hand-back after it doesn't.
	l.APIReader = interceptor.NewClient(f.api, interceptor.Funcs{
		Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
			if worker.Claimant(ctx) != "" {
				<-ctx.Done()
				return ctx.Err()
			}
			return c.Get(ctx, key, obj, opts...)
		},
	})
	ended := make(chan struct{})
	started := make(chan struct{})
	l.Judge = func(ctx context.Context, _ cases.Case, _ cases.Request, _ int) worker.Result {
		close(started)
		<-ctx.Done()
		close(ended)
		return worker.Wait
	}
	run(t, l)
	<-started

	f.clock.Step(worker.DefaultLease) // a renewal starts, and hangs past the lease's end
	select {
	case <-ended:
	case <-time.After(within):
		t.Fatal("the judge's context didn't end while its renewal hung")
	}
}

// A case that no investigation wants any more while it is judged leaves the queue withdrawn when it is handed back,
// and with its outcome when it ends.
func TestACaseInProgressThatNobodyWantsLeavesTheQueue(t *testing.T) {
	for _, result := range []worker.Result{worker.Retry, worker.Done} {
		t.Run(map[worker.Result]string{worker.Retry: "handed back", worker.Done: "done"}[result], func(t *testing.T) {
			f := newFixture(t)
			name := f.queue(t, "CVE-2026-0001", 1, triagev1alpha1.InvestigationTriggerContinuous)
			started, finish := make(chan struct{}), make(chan struct{})
			run(t, f.loop(workerA, func(ctx context.Context, _ cases.Case, _ cases.Request, _ int) worker.Result {
				close(started)
				<-finish
				if result == worker.Done {
					// The Assessment holds the case's outcome already, which the judge marks so.
					f.update(t, name, func(s *triagev1alpha1.AssessmentStatus) {
						s.NoVerdict = &triagev1alpha1.AssessmentNoVerdict{Summary: "Judged before."}
						meta.SetStatusCondition(&s.Conditions, metav1.Condition{Type: configv1alpha1.ConditionReady,
							Status: metav1.ConditionTrue, Reason: triagev1alpha1.ReasonJudged, Message: "Judged before."})
					})
				}
				return result
			}))
			<-started

			(&hub.APIQueue{Client: f.api, APIReader: f.api}).Keep(types.NamespacedName{Namespace: team, Name: investigation}, nil)
			a := f.get(t, name)
			require.Empty(t, a.Status.Queue.Requests)
			require.NotNil(t, a.Status.Claim, "the case in progress finishes")
			close(finish)

			want := map[worker.Result]string{worker.Retry: triagev1alpha1.ReasonWithdrawn, worker.Done: triagev1alpha1.ReasonJudged}[result]
			require.Eventually(t, func() bool { return f.get(t, name).Status.Queue == nil }, within, often)
			a = f.get(t, name)
			require.Nil(t, a.Status.Claim)
			require.Equal(t, want, readyReason(a))
			if result == worker.Done {
				require.NotNil(t, a.Status.NoVerdict, "the outcome stands")
			}
		})
	}
}
