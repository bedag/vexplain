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
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clocktesting "k8s.io/utils/clock/testing"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
	inventoryv1alpha1 "github.com/bedag/vexplain/api/inventory/v1alpha1"
	triagev1alpha1 "github.com/bedag/vexplain/api/triage/v1alpha1"
	"github.com/bedag/vexplain/internal/agent/cases"
	"github.com/bedag/vexplain/internal/controller/hub"
)

// queueStart is when the queue's clock starts: a whole second, which a status's times hold exactly.
var queueStart = time.Date(2026, 11, 20, 10, 0, 0, 0, time.UTC)

// The case that the queue's tests queue, as the agent's tests judge one: its manifest, its vulnerability and its
// playbook, and the investigation that wants it.
const (
	judgedManifest = "sha256:4242424242424242424242424242424242424242424242424242424242424242"
	judgedCVE      = "CVE-2026-0042"
	judgedPlaybook = "agent-cves"
)

var judgedInvestigation = types.NamespacedName{Namespace: "team-c", Name: "judged"}

// readyReason returns the reason of the Ready condition, or "".
func readyReason(list []metav1.Condition) string {
	if c := meta.FindStatusCondition(list, configv1alpha1.ConditionReady); c != nil {
		return c.Reason
	}
	return ""
}

var (
	firstInvestigation  = types.NamespacedName{Namespace: judgedInvestigation.Namespace, Name: "most-urgent"}
	secondInvestigation = types.NamespacedName{Namespace: "team-e", Name: "weekly"}
)

// queueFixture is the hub's queue on an API server's fake, with a clock that the specs move.
type queueFixture struct {
	api   client.Client
	clock *clocktesting.FakeClock
	queue *hub.APIQueue
}

func newQueueFixture(t *testing.T) *queueFixture {
	t.Helper()
	scheme := runtime.NewScheme()
	require.NoError(t, triagev1alpha1.AddToScheme(scheme))
	api := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(&triagev1alpha1.Assessment{},
		&triagev1alpha1.Investigation{}).Build()
	clock := clocktesting.NewFakeClock(queueStart)
	return &queueFixture{api: api, clock: clock, queue: &hub.APIQueue{Client: api, APIReader: api, Clock: clock}}
}

// queuedCase returns a case of the vulnerability, whose Assessment it creates, as an investigation does before it
// queues a case.
func (f *queueFixture) queuedCase(t *testing.T, cve string) cases.Case {
	t.Helper()
	c := cases.Case{ManifestDigest: judgedManifest, VulnerabilityID: cve,
		Findings: []inventoryv1alpha1.Finding{{VulnerabilityID: cve, KnownExploited: inventoryv1alpha1.KnownExploitedListed,
			EPSSPermille: ptr.To(int32(950))}},
		Impact: cases.Impact{Resources: 13, HighestUrgency: configv1alpha1.SSVCOutcomeImmediate}}
	require.NoError(t, f.api.Create(t.Context(), &triagev1alpha1.Assessment{
		ObjectMeta: metav1.ObjectMeta{Name: cases.Name(cve, judgedManifest)},
		Spec: triagev1alpha1.AssessmentSpec{Subject: triagev1alpha1.AssessmentSubject{
			Type: triagev1alpha1.SubjectTypeContainerImage, ContainerImage: &triagev1alpha1.ContainerImageSubject{Digest: judgedManifest}},
			VulnerabilityID: cve}}))
	return c
}

// uidOf returns the uid that the fixture's investigation of the key has: the fake API server sets none.
func uidOf(key types.NamespacedName) types.UID {
	return types.UID("uid-" + key.Namespace + "-" + key.Name)
}

// refOf returns the reference to the investigation of the key, with its uid.
func refOf(key types.NamespacedName) triagev1alpha1.InvestigationReference {
	return triagev1alpha1.InvestigationReference{Namespace: key.Namespace, Name: key.Name, UID: uidOf(key)}
}

// investigation creates the investigation of the key, so that the sweep finds it.
func (f *queueFixture) investigation(t *testing.T, key types.NamespacedName) {
	t.Helper()
	require.NoError(t, f.api.Create(t.Context(), &triagev1alpha1.Investigation{
		ObjectMeta: metav1.ObjectMeta{Namespace: key.Namespace, Name: key.Name, UID: uidOf(key)},
		Spec: triagev1alpha1.InvestigationSpec{PlaybookRef: triagev1alpha1.PlaybookReference{Name: judgedPlaybook},
			Agent: triagev1alpha1.InvestigationAgent{MaxCases: 10}}}))
}

// request returns the investigation's request with the trigger.
func request(key types.NamespacedName, trigger triagev1alpha1.InvestigationTriggerType) cases.Request {
	return cases.Request{Investigation: key, InvestigationUID: uidOf(key), Playbook: judgedPlaybook, Trigger: trigger}
}

// get returns the case's Assessment as the API server has it.
func (f *queueFixture) get(t *testing.T, c cases.Case) *triagev1alpha1.Assessment {
	t.Helper()
	a := &triagev1alpha1.Assessment{}
	require.NoError(t, f.api.Get(t.Context(), client.ObjectKey{Name: cases.Name(c.VulnerabilityID, c.ManifestDigest)}, a))
	return a
}

// claim writes a claim of a worker on the case, whose lease ends at the time.
func (f *queueFixture) claim(t *testing.T, c cases.Case, leaseEnd time.Time) {
	t.Helper()
	a := f.get(t, c)
	a.Status.Claim = &triagev1alpha1.QueueClaim{Worker: "vexplain-agent-a", LeaseEndTime: ptr.To(metav1.NewTime(leaseEnd))}
	meta.SetStatusCondition(&a.Status.Conditions, metav1.Condition{Type: configv1alpha1.ConditionReady,
		Status: metav1.ConditionFalse, Reason: triagev1alpha1.ReasonJudging, Message: "The agent judges the case."})
	require.NoError(t, f.api.Status().Update(t.Context(), a))
}

func TestAddQueuesOnceAndChargesTheFirst(t *testing.T) {
	f := newQueueFixture(t)
	c := f.queuedCase(t, judgedCVE)

	require.True(t, f.queue.Add(c, request(firstInvestigation, triagev1alpha1.InvestigationTriggerContinuous)))
	require.False(t, f.queue.Add(c, request(secondInvestigation, triagev1alpha1.InvestigationTriggerOnce)), "queued once")

	a := f.get(t, c)
	q := a.Status.Queue
	require.NotNil(t, q)
	first := refOf(firstInvestigation)
	require.Equal(t, &first, q.InvestigationRef, "charged to the first, with its uid")
	require.Nil(t, a.Status.InvestigationRef, "no judgement is made yet")
	require.Equal(t, []triagev1alpha1.QueueRequest{
		{InvestigationRef: first, Trigger: triagev1alpha1.InvestigationTriggerContinuous},
		{InvestigationRef: refOf(secondInvestigation), Trigger: triagev1alpha1.InvestigationTriggerOnce}},
		q.Requests)
	require.Equal(t, judgedPlaybook, q.Playbook)
	require.Equal(t, triagev1alpha1.QueueOrder{UrgencyRank: ptr.To(int32(1)), KnownExploited: triagev1alpha1.KnownExploitedListed,
		EPSSPermille: ptr.To(int32(950)), Resources: ptr.To(int32(13))}, q.Order)
	require.True(t, q.QueuedTime.Time.Equal(queueStart))
	require.Equal(t, triagev1alpha1.ReasonQueued, readyReason(a.Status.Conditions))
	require.Nil(t, a.Status.Claim)
}

// The queue writes where the case runs, as the exposure rules decided it, into the case's Assessment, and writes it again
// whenever an investigation hands the case over with another exposure: the worker's case file takes it from there.
func TestTheQueuedAssessmentHoldsRunsIn(t *testing.T) {
	f := newQueueFixture(t)
	c := f.queuedCase(t, judgedCVE)
	c.Impact.HighestExposure, c.Impact.UrgentResources = configv1alpha1.SSVCExposureControlled, 0
	c.Impact.HighestUrgency = configv1alpha1.SSVCOutcomeScheduled
	c.Impact.Exposure = []cases.ExposureGroup{{Exposure: configv1alpha1.SSVCExposureControlled,
		Rules: []string{"exposed-not-published"}, Workloads: 13,
		First: []string{"workload/cluster-a/team-a/Deployment.apps/shop"}}}

	require.True(t, f.queue.Add(c, request(firstInvestigation, triagev1alpha1.InvestigationTriggerContinuous)))

	runsIn := f.get(t, c).Status.Queue.RunsIn
	require.NotNil(t, runsIn)
	require.Equal(t, ptr.To(triagev1alpha1.SSVCExposureControlled), runsIn.HighestExposure)
	require.Equal(t, cases.RunsInOf(c), runsIn)

	c.Impact.HighestExposure, c.Impact.UrgentResources = configv1alpha1.SSVCExposureOpen, 13
	c.Impact.HighestUrgency = configv1alpha1.SSVCOutcomeImmediate
	c.Impact.Exposure[0].Exposure, c.Impact.Exposure[0].Rules = configv1alpha1.SSVCExposureOpen, []string{"published-or-unchecked"}
	require.False(t, f.queue.Add(c, request(firstInvestigation, triagev1alpha1.InvestigationTriggerContinuous)))

	runsIn = f.get(t, c).Status.Queue.RunsIn
	require.NotNil(t, runsIn)
	require.Equal(t, ptr.To(triagev1alpha1.SSVCExposureOpen), runsIn.HighestExposure,
		"the case is handed over again with the exposure of now")
	require.Equal(t, cases.RunsInOf(c), runsIn)
}

// An investigation hands a case over as the queue holds it: the views of every playbook that selects the case, combined.
// So the queue writes the order and where the case runs as each request hands them over, whichever playbook's
// investigation it comes from, and the case-file playbook stays the one that added the case.
func TestEachRequestWritesTheCaseAsItHandsItOver(t *testing.T) {
	f := newQueueFixture(t)
	c := f.queuedCase(t, judgedCVE)
	runsIn := func(exposure configv1alpha1.SSVCExposure, resources int32, clusters ...string) cases.Case {
		combined := c
		combined.Impact.HighestExposure, combined.Impact.Resources, combined.Clusters = exposure, resources, clusters
		return combined
	}
	fromOther := request(secondInvestigation, triagev1alpha1.InvestigationTriggerContinuous)

	added := runsIn(configv1alpha1.SSVCExposureUnknown, 5, otherCluster)
	require.True(t, f.queue.Add(added, request(firstInvestigation, triagev1alpha1.InvestigationTriggerContinuous)))
	q := f.get(t, c).Status.Queue
	require.Equal(t, judgedPlaybook, q.Playbook, "the case file's playbook")
	require.Equal(t, cases.OrderOf(added), q.Order)
	require.Equal(t, cases.RunsInOf(added), q.RunsIn)

	both := runsIn(configv1alpha1.SSVCExposureOpen, 21, localCluster, otherCluster)
	require.False(t, f.queue.Add(both, fromOther))
	q = f.get(t, c).Status.Queue
	require.Equal(t, cases.OrderOf(both), q.Order, "another investigation's request writes the order")
	require.Equal(t, cases.RunsInOf(both), q.RunsIn, "and where the case runs, with the clusters")
	require.Len(t, q.Requests, 2)
}

func TestKeepWithdrawsACaseThatNoOneWants(t *testing.T) {
	f := newQueueFixture(t)
	c := f.queuedCase(t, judgedCVE)
	f.queue.Add(c, request(firstInvestigation, triagev1alpha1.InvestigationTriggerOnce))
	f.queue.Add(c, request(secondInvestigation, triagev1alpha1.InvestigationTriggerOnce))

	f.queue.Keep(firstInvestigation, nil)
	a := f.get(t, c)
	require.Len(t, a.Status.Queue.Requests, 1, "the other investigation still wants it")
	require.Equal(t, triagev1alpha1.ReasonQueued, readyReason(a.Status.Conditions))

	f.queue.Keep(secondInvestigation, nil)
	a = f.get(t, c)
	require.Equal(t, triagev1alpha1.ReasonWithdrawn, readyReason(a.Status.Conditions))
	require.Nil(t, a.Status.Queue)
}

func TestKeepLeavesACaseInProgress(t *testing.T) {
	f := newQueueFixture(t)
	c := f.queuedCase(t, judgedCVE)
	f.queue.Add(c, request(firstInvestigation, triagev1alpha1.InvestigationTriggerOnce))
	f.claim(t, c, queueStart.Add(time.Minute))

	f.queue.Keep(firstInvestigation, nil)

	a := f.get(t, c)
	require.NotNil(t, a.Status.Claim, "the case in progress finishes")
	require.NotNil(t, a.Status.Queue)
	require.Empty(t, a.Status.Queue.Requests)
	require.Equal(t, triagev1alpha1.ReasonJudging, readyReason(a.Status.Conditions))
}

func TestPendingCountsQueuedAndJudging(t *testing.T) {
	f := newQueueFixture(t)
	waiting, judging := f.queuedCase(t, "CVE-2026-0001"), f.queuedCase(t, "CVE-2026-0002")
	f.queue.Add(waiting, request(firstInvestigation, triagev1alpha1.InvestigationTriggerOnce))
	f.queue.Add(judging, request(firstInvestigation, triagev1alpha1.InvestigationTriggerOnce))
	f.queue.Add(judging, request(secondInvestigation, triagev1alpha1.InvestigationTriggerOnce))
	f.claim(t, judging, queueStart.Add(time.Minute))

	queued, inProgress := f.queue.Pending(firstInvestigation, uidOf(firstInvestigation))
	require.Equal(t, [2]int{1, 1}, [2]int{queued, inProgress})
	queued, inProgress = f.queue.Pending(secondInvestigation, uidOf(secondInvestigation))
	require.Equal(t, [2]int{0, 1}, [2]int{queued, inProgress})
	queued, inProgress = f.queue.Pending(types.NamespacedName{Namespace: "team-c", Name: "other"}, "")
	require.Zero(t, queued+inProgress)
}

// A worker whose lease ended more than 30 seconds ago is taken for dead: its case waits again, and counts a failure,
// since the worker may have spent tokens on it.
func TestALapsedLeaseGoesBack(t *testing.T) {
	f := newQueueFixture(t)
	f.investigation(t, firstInvestigation)
	c := f.queuedCase(t, judgedCVE)
	f.queue.Add(c, request(firstInvestigation, triagev1alpha1.InvestigationTriggerOnce))
	f.claim(t, c, queueStart.Add(-31*time.Second))

	f.queue.Sweep(t.Context())

	a := f.get(t, c)
	require.Nil(t, a.Status.Claim)
	require.Equal(t, triagev1alpha1.ReasonQueued, readyReason(a.Status.Conditions))
	require.Equal(t, ptr.To(int32(1)), a.Status.Queue.Failures)
	require.Equal(t, ptr.To(int32(1)), a.Status.Queue.Misses)
	require.True(t, a.Status.Queue.NotBefore.Time.Equal(queueStart.Add(10*time.Second)))
}

func TestALiveLeaseIsLeftAlone(t *testing.T) {
	f := newQueueFixture(t)
	f.investigation(t, firstInvestigation)
	c := f.queuedCase(t, judgedCVE)
	f.queue.Add(c, request(firstInvestigation, triagev1alpha1.InvestigationTriggerOnce))
	f.claim(t, c, queueStart.Add(-29*time.Second))
	before := f.get(t, c)

	f.queue.Sweep(t.Context())

	require.Equal(t, before, f.get(t, c))
}

// A request of an investigation that is gone is removed, and a waiting case that no request is left on is withdrawn.
func TestARequestOfAGoneInvestigationIsRemoved(t *testing.T) {
	f := newQueueFixture(t)
	f.investigation(t, firstInvestigation)
	both, gone := f.queuedCase(t, "CVE-2026-0001"), f.queuedCase(t, "CVE-2026-0002")
	f.queue.Add(both, request(firstInvestigation, triagev1alpha1.InvestigationTriggerOnce))
	f.queue.Add(both, request(secondInvestigation, triagev1alpha1.InvestigationTriggerOnce))
	f.queue.Add(gone, request(secondInvestigation, triagev1alpha1.InvestigationTriggerOnce))

	f.queue.Sweep(t.Context())

	a := f.get(t, both)
	require.Equal(t, []triagev1alpha1.QueueRequest{{InvestigationRef: refOf(firstInvestigation),
		Trigger: triagev1alpha1.InvestigationTriggerOnce}}, a.Status.Queue.Requests)
	a = f.get(t, gone)
	require.Nil(t, a.Status.Queue)
	require.Equal(t, triagev1alpha1.ReasonWithdrawn, readyReason(a.Status.Conditions))
}

// A case held without a queue, as an install before the queue in the API left it, is withdrawn.
func TestAHeldCaseWithoutAQueueIsWithdrawn(t *testing.T) {
	f := newQueueFixture(t)
	c := f.queuedCase(t, judgedCVE)
	a := f.get(t, c)
	meta.SetStatusCondition(&a.Status.Conditions, metav1.Condition{Type: configv1alpha1.ConditionReady,
		Status: metav1.ConditionFalse, Reason: triagev1alpha1.ReasonJudging, Message: "Left by an earlier install."})
	require.NoError(t, f.api.Status().Update(t.Context(), a))

	f.queue.Sweep(t.Context())

	require.Equal(t, triagev1alpha1.ReasonWithdrawn, readyReason(f.get(t, c).Status.Conditions))
}

// A case queued again that leaves the queue unjudged keeps the charge of its earlier judgement, whose usage it holds.
func TestAWithdrawnRequeueKeepsTheChargeOfTheJudgement(t *testing.T) {
	f := newQueueFixture(t)
	c := f.queuedCase(t, judgedCVE)
	a := f.get(t, c)
	judgedRef := refOf(firstInvestigation)
	judged := &judgedRef
	a.Status.InvestigationRef = judged
	require.NoError(t, f.api.Status().Update(t.Context(), a))

	require.True(t, f.queue.Add(c, request(secondInvestigation, triagev1alpha1.InvestigationTriggerOnce)))
	require.Equal(t, uidOf(secondInvestigation), f.get(t, c).Status.Queue.InvestigationRef.UID)
	f.queue.Keep(secondInvestigation, nil)

	a = f.get(t, c)
	require.Equal(t, triagev1alpha1.ReasonWithdrawn, readyReason(a.Status.Conditions))
	require.Equal(t, judged, a.Status.InvestigationRef, "the judgement's charge stands")
}

// A request of an earlier object of the same namespace and name gives way to the current object's. A case that waits
// unclaimed is charged to the current object from then on, and judged with its guidance: the earlier object is gone,
// and its judgement never began.
func TestARequestOfAnEarlierObjectGivesWay(t *testing.T) {
	f := newQueueFixture(t)
	c := f.queuedCase(t, judgedCVE)
	earlier := request(firstInvestigation, triagev1alpha1.InvestigationTriggerOnce)
	earlier.InvestigationUID = earlierUID
	require.True(t, f.queue.Add(c, earlier))

	require.True(t, f.queue.Add(c, request(firstInvestigation, triagev1alpha1.InvestigationTriggerContinuous)),
		"the current object takes the charge over")

	a := f.get(t, c)
	require.Equal(t, []triagev1alpha1.QueueRequest{{InvestigationRef: refOf(firstInvestigation),
		Trigger: triagev1alpha1.InvestigationTriggerContinuous}}, a.Status.Queue.Requests)
	require.Equal(t, refOf(firstInvestigation), *a.Status.Queue.InvestigationRef)
	require.False(t, f.queue.Add(c, request(firstInvestigation, triagev1alpha1.InvestigationTriggerContinuous)),
		"and is charged once")
}

// A held case charges the investigation when it is queued again only where an earlier object of its name charged it,
// and it waits unclaimed: one that the queue lost is queued again as it was charged.
func TestAHeldCaseChargesTheInvestigationOnlyWhereItTakesItOver(t *testing.T) {
	inv := &triagev1alpha1.Investigation{ObjectMeta: metav1.ObjectMeta{Namespace: firstInvestigation.Namespace,
		Name: firstInvestigation.Name, UID: uidOf(firstInvestigation)}}
	queued := func(uid types.UID, claimed bool) *triagev1alpha1.Assessment {
		a := &triagev1alpha1.Assessment{}
		a.Status.Queue = &triagev1alpha1.AssessmentQueue{InvestigationRef: &triagev1alpha1.InvestigationReference{
			Namespace: inv.Namespace, Name: inv.Name, UID: uid}}
		if claimed {
			a.Status.Claim = &triagev1alpha1.QueueClaim{Worker: "vexplain-agent-a"}
		}
		return a
	}
	require.True(t, hub.ChargedToAnEarlier(queued(earlierUID, false), inv))
	require.False(t, hub.ChargedToAnEarlier(queued(earlierUID, true), inv), "a judgement under way keeps its charge")
	require.False(t, hub.ChargedToAnEarlier(queued(inv.UID, false), inv), "charged to this object already")
	require.False(t, hub.ChargedToAnEarlier(&triagev1alpha1.Assessment{}, inv), "a held case that the queue lost")
}

// A judgement under way stays charged to the object that it began for.
func TestAJudgementUnderWayStaysChargedToTheEarlierObject(t *testing.T) {
	f := newQueueFixture(t)
	c := f.queuedCase(t, judgedCVE)
	earlier := request(firstInvestigation, triagev1alpha1.InvestigationTriggerOnce)
	earlier.InvestigationUID = earlierUID
	require.True(t, f.queue.Add(c, earlier))
	f.claim(t, c, time.Now().Add(time.Minute))

	require.False(t, f.queue.Add(c, request(firstInvestigation, triagev1alpha1.InvestigationTriggerContinuous)))

	a := f.get(t, c)
	require.Equal(t, []triagev1alpha1.QueueRequest{{InvestigationRef: refOf(firstInvestigation),
		Trigger: triagev1alpha1.InvestigationTriggerContinuous}}, a.Status.Queue.Requests)
	require.Equal(t, types.UID(earlierUID), a.Status.Queue.InvestigationRef.UID)
}

// Pending counts the requests of the object that the uid names, not those of an earlier one.
func TestPendingLeavesOutTheRequestsOfAnEarlierObject(t *testing.T) {
	f := newQueueFixture(t)
	c := f.queuedCase(t, judgedCVE)
	earlier := request(firstInvestigation, triagev1alpha1.InvestigationTriggerOnce)
	earlier.InvestigationUID = earlierUID
	f.queue.Add(c, earlier)

	queued, inProgress := f.queue.Pending(firstInvestigation, uidOf(firstInvestigation))
	require.Zero(t, queued+inProgress)
	queued, inProgress = f.queue.Pending(firstInvestigation, earlierUID)
	require.Equal(t, 1, queued+inProgress)
}

// A request of an object that the cache doesn't hold is removed: the investigation of its namespace and name is
// another object now.
func TestARequestOfAnEarlierObjectIsSweptAway(t *testing.T) {
	f := newQueueFixture(t)
	f.investigation(t, firstInvestigation)
	c := f.queuedCase(t, judgedCVE)
	earlier := request(firstInvestigation, triagev1alpha1.InvestigationTriggerOnce)
	earlier.InvestigationUID = earlierUID
	f.queue.Add(c, earlier)

	f.queue.Sweep(t.Context())

	a := f.get(t, c)
	require.Nil(t, a.Status.Queue)
	require.Equal(t, triagev1alpha1.ReasonWithdrawn, readyReason(a.Status.Conditions))
}
