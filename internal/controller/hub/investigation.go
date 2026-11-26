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

package hub

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/robfig/cron/v3"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/events"
	"k8s.io/client-go/util/retry"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/utils/clock"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
	inventoryv1alpha1 "github.com/bedag/vexplain/api/inventory/v1alpha1"
	triagev1alpha1 "github.com/bedag/vexplain/api/triage/v1alpha1"
	"github.com/bedag/vexplain/internal/agent/cases"
	"github.com/bedag/vexplain/internal/collectorclient"
	"github.com/bedag/vexplain/internal/conditions"
	"github.com/bedag/vexplain/internal/evidence"
	"github.com/bedag/vexplain/internal/exposure"
	"github.com/bedag/vexplain/internal/inventory"
	"github.com/bedag/vexplain/internal/rules/engine"
	"github.com/bedag/vexplain/internal/schedule"
	"github.com/bedag/vexplain/internal/settings"
	"github.com/bedag/vexplain/internal/text"
	"github.com/bedag/vexplain/internal/urgency"
)

// The limits of an investigation's status.
const (
	// DefaultInvestigationDebounce is how long the controller waits after a change of what investigations read, so
	// that the changes within it come to one reconcile of each investigation.
	DefaultInvestigationDebounce = 30 * time.Second
	// maxResults is the most results that an investigation lists, and maxResultsBytes the most JSON that they add up
	// to, which keeps the status well below what the API server stores for an object.
	maxResults      = 20
	maxResultsBytes = 512 << 10
	// maxResultReasonLength is the most characters of a result's reason.
	maxResultReasonLength = 256
	// impactRefresh is how often an investigation is reconciled at least, so that its impact follows the inventory.
	impactRefresh = 5 * time.Minute
	// viewWait is how often an investigation looks again whether the view of exposure has read the store after a
	// start: before, a workload's exposure that the view hasn't read yet would be missing.
	viewWait = 2 * time.Second
	// overTheCap is the reason of a case that the cap leaves out.
	overTheCap = "over the cap"
	// The reasons of the events of a run.
	reasonRunStarted      = "RunStarted"
	reasonRunFinished     = "RunFinished"
	reasonTickSkipped     = "TickSkipped"
	reasonJudgedElsewhere = "JudgedElsewhere"
	// namedElsewhere is the most cases that the event JudgedElsewhere names.
	namedElsewhere = 5
)

// notes is what a reconcile tells besides the status: events, which are recorded once the status is written, except
// that a skipped tick changes no status, when to come back, and how many cases the queue took and the reconcile
// charged.
type notes struct {
	events      [][2]string // reason and message
	tickSkipped bool
	requeue     time.Duration
	charged     int32
}

// sentenceEnd ends the first sentence of a summary.
var sentenceEnd = regexp.MustCompile(`[.!?]\s`)

// InvestigationReconciler answers an Investigation (decision 0051): it selects the cases of the investigation's
// playbook, from the sheets and the hub's inventory, and shows in the status where they run, whom to contact, and how
// urgent they are, without the agent. While the agent is switched on, it creates the Assessment of each selected case
// without a fresh verdict, the most urgent first and up to the cap, and queues it for the agent (decision 0052).
//
// It is hub code: it reads the sheets, the inventory and the evidence through their stores.
type InvestigationReconciler struct {
	client.Client
	// APIReader reads an investigation past the cache, to keep the charges of a reconcile that failed after the queue
	// took cases.
	APIReader client.Reader
	// Store finds where a manifest runs, Verdicts holds the sheets of the playbooks, and Evidence the data that a case
	// file holds, whose hashes say whether a verdict is fresh.
	Store    inventory.Store
	Verdicts inventory.VerdictsStore
	Evidence evidence.Store
	// View is the hub's view of exposure, from which the exposure rules of the investigation's playbook decide the
	// exposure of each workload that runs a case's image, Rules compiles them, and Evaluations counts the workloads that
	// they couldn't be evaluated for. Without a View, the cases count the workloads by the exposure that the inventory
	// holds, as the spokes decide it; with one, Rules and Evaluations are needed too.
	View        *exposure.View
	Rules       *Rules
	Evaluations *Evaluations
	// Queue is the agent's queue: the Assessments' status, in production.
	Queue cases.Queue
	// Recorder records the CapReached event.
	Recorder events.EventRecorder
	// Debounce is how long the controller waits after a change of a sheet, an Assessment or the OperatorConfig before
	// it reconciles the investigations that it concerns. Zero means DefaultInvestigationDebounce.
	Debounce time.Duration
	// Clock tells the time of the schedules and the age of verdicts. Nil means the real clock.
	Clock clock.Clock
}

// The controller writes the status of the investigations, creates the Assessments and writes their status. It reads
// the Playbooks, the Rules, the Collectors, the OperatorConfig and the metadata of the sheets, which other controllers
// of the hub read too.
// +kubebuilder:rbac:groups=triage.vexplain.bedag.ch,resources=investigations,verbs=get;list;watch
// +kubebuilder:rbac:groups=triage.vexplain.bedag.ch,resources=investigations/status,verbs=update
// +kubebuilder:rbac:groups=triage.vexplain.bedag.ch,resources=assessments,verbs=get;list;watch;create
// +kubebuilder:rbac:groups=triage.vexplain.bedag.ch,resources=assessments/status,verbs=update
// +kubebuilder:rbac:groups=events.k8s.io,resources=events,verbs=create;patch

// judgement is what an investigation shows of one selected case: its result and status, which are the sheet's, and
// the agent's fresh verdict and the review of its statement beside them.
type judgement struct {
	c       cases.Case
	result  triagev1alpha1.InvestigationResultType
	status  inventoryv1alpha1.VEXStatus
	verdict *triagev1alpha1.VEXStatus
	review  *triagev1alpha1.ReviewState
	reason  string
}

// run is what one reconcile of an investigation found.
type run struct {
	// wanted are the names of the cases that it wants judged: those without a fresh verdict, within the cap.
	wanted []string
	// elsewhere are the names of the cases whose reused verdict was judged for another investigation, or for none, and
	// earlier how many of them were judged for an earlier object of this investigation's name.
	elsewhere           []string
	earlier             int
	selected            []judgement
	skipped, overTheCap int
	toJudge, reused     int
	judged              int
	charged             int32
}

// Reconcile selects the investigation's cases, queues those to judge, and writes the status. An investigation that
// can't run, for want of its playbook, of the playbook's agent section or of conditions that compile, is Stalled and
// keeps what its status showed. One whose agent is switched off shows its impact, and is Stalled. Until the view of
// exposure has read the store, it waits, and changes nothing.
//
// It returns the errors of reading and writing, so that the request is retried.
func (r *InvestigationReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var inv triagev1alpha1.Investigation
	if err := r.Get(ctx, req.NamespacedName, &inv); err != nil {
		if apierrors.IsNotFound(err) {
			// A deleted investigation wants no case judged any more.
			r.Queue.Keep(req.NamespacedName, nil)
		}
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if r.View != nil && !r.View.Synced() {
		return ctrl.Result{RequeueAfter: viewWait}, nil
	}
	status := *inv.Status.DeepCopy()
	// A run of a Once investigation starts again with each change of its spec.
	if triggerOf(&inv).Type == triagev1alpha1.InvestigationTriggerOnce && status.ObservedGeneration != nil &&
		*status.ObservedGeneration != inv.Generation {
		status.StartTime, status.CompletionTime = nil, nil
	}
	var n notes
	ready, progress, err := r.judge(ctx, &inv, &status, &n)
	if err != nil {
		return ctrl.Result{}, errors.Join(err, r.keepCharges(ctx, req.NamespacedName, inv.UID, &inv.Status, &status, n.charged))
	}
	// The impact follows the inventory, which no watch brings: every investigation is reconciled again within
	// impactRefresh.
	result := ctrl.Result{RequeueAfter: impactRefresh}
	if n.requeue > 0 {
		result.RequeueAfter = min(n.requeue, impactRefresh)
	}
	if n.tickSkipped {
		r.Recorder.Eventf(&inv, nil, corev1.EventTypeNormal, reasonTickSkipped, eventActionReconcile,
			"%s", "The schedule's tick came while the last run still goes, so it is skipped.")
	}
	ready.ObservedGeneration = inv.Generation
	ready.Message = message(ready.Message)
	wasCapped := readyReason(inv.Status.Conditions) == triagev1alpha1.ReasonCapReached
	conditions.SetReady(&status.Conditions, ready, progress)
	conditions.Observe(&status.ObservedGeneration, inv.Generation)
	if equality.Semantic.DeepEqual(status, inv.Status) {
		return result, nil
	}
	before := inv.Status
	inv.Status = status
	if err := r.Status().Update(ctx, &inv); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(errors.Join(err, r.keepCharges(ctx, req.NamespacedName, inv.UID, &before, &status,
			n.charged)))
	}
	for _, e := range n.events {
		r.Recorder.Eventf(&inv, nil, corev1.EventTypeNormal, e[0], eventActionReconcile, "%s", e[1])
	}
	logf.FromContext(ctx).V(1).Info("Wrote the status of the Investigation", "reason", ready.Reason, "message", ready.Message)
	if ready.Reason == triagev1alpha1.ReasonCapReached && !wasCapped {
		r.Recorder.Eventf(&inv, nil, corev1.EventTypeNormal, triagev1alpha1.ReasonCapReached, eventActionReconcile,
			"%s", ready.Message)
	}
	return result, nil
}

// keepCharges adds delta, the charges of the cases that the queue took in a reconcile that then failed, to the
// investigation's counter as the API server has it. The next reconcile finds those cases held and doesn't charge them,
// so without this it would spend their room again. from is the status that the reconcile started from, and status
// the one it made: when the reconcile started a run on the status that the API server still has, the charges are that
// run's, so its times are kept with them. An object of the key with another uid than uid is another investigation,
// which these charges aren't of.
func (r *InvestigationReconciler) keepCharges(ctx context.Context, key types.NamespacedName, uid types.UID,
	from, status *triagev1alpha1.InvestigationStatus, delta int32) error {
	if delta == 0 {
		return nil
	}
	err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		var inv triagev1alpha1.Investigation
		if err := r.APIReader.Get(ctx, key, &inv); err != nil {
			return err
		}
		if inv.UID != uid {
			return nil
		}
		if equality.Semantic.DeepEqual(inv.Status.StartTime, from.StartTime) &&
			!equality.Semantic.DeepEqual(from.StartTime, status.StartTime) {
			inv.Status.StartTime, inv.Status.CompletionTime = status.StartTime, status.CompletionTime
			inv.Status.LastScheduleTime = status.LastScheduleTime
			if inv.Status.Cases != nil {
				inv.Status.Cases.Charged = ptr.To(int32(0))
			}
		}
		if inv.Status.Cases == nil {
			// The next reconcile counts the rest.
			zero := func() *int32 { return ptr.To(int32(0)) }
			inv.Status.Cases = &triagev1alpha1.InvestigationCases{Total: zero(), Queued: zero(), InProgress: zero(),
				Charged: zero(), Judged: zero(), Reused: zero(), OverTheCap: zero(), JudgedElsewhere: zero(), NotSelected: zero()}
		}
		inv.Status.Cases.Charged = ptr.To(ptr.Deref(inv.Status.Cases.Charged, 0) + delta)
		return r.Status().Update(ctx, &inv)
	})
	if client.IgnoreNotFound(err) != nil {
		return fmt.Errorf("keep the charges of the %d cases that the queue took: %w", delta, err)
	}
	return nil
}

// triggerOf returns the investigation's trigger, Once by default.
func triggerOf(inv *triagev1alpha1.Investigation) triagev1alpha1.InvestigationTrigger {
	return ptr.Deref(inv.Spec.Trigger, triagev1alpha1.InvestigationTrigger{Type: triagev1alpha1.InvestigationTriggerOnce})
}

// now returns the time of the reconciler's clock.
func (r *InvestigationReconciler) now() metav1.Time {
	if r.Clock == nil {
		return metav1.Now()
	}
	return metav1.NewTime(r.Clock.Now())
}

// startRun starts a run when the trigger says so, and writes its times: a Once or Continuous investigation starts one
// when it has none, and a Schedule one at each tick, unless a run still goes, which skips the tick and leaves
// lastScheduleTime as it was. The next tick of a schedule that a run skipped comes as soon as the run is over.
func (r *InvestigationReconciler) startRun(inv *triagev1alpha1.Investigation, status *triagev1alpha1.InvestigationStatus,
	trigger triagev1alpha1.InvestigationTrigger, sched cron.Schedule, pending int, n *notes) {
	now := r.now()
	start := func(why string) {
		status.StartTime, status.CompletionTime = ptr.To(now), nil
		if status.Cases != nil {
			status.Cases.Charged = ptr.To(int32(0))
		}
		n.events = append(n.events, [2]string{reasonRunStarted, why})
	}
	if trigger.Type != triagev1alpha1.InvestigationTriggerSchedule {
		if status.StartTime == nil {
			start("The investigation started its run.")
		}
		return
	}
	ref := inv.CreationTimestamp.Time
	if status.LastScheduleTime != nil {
		ref = status.LastScheduleTime.Time
	}
	switch next := sched.Next(ref); {
	case next.After(now.Time):
		n.requeue = next.Sub(now.Time)
	case pending > 0:
		n.tickSkipped, n.requeue = true, DefaultInvestigationDebounce
	default:
		start("The schedule's tick started a run.")
		status.LastScheduleTime = ptr.To(now)
		n.requeue = sched.Next(now.Time).Sub(now.Time)
	}
}

// judge fills status with what the investigation selects, queues the cases to judge, and returns the Ready condition
// and the progress that go with it.
func (r *InvestigationReconciler) judge(ctx context.Context, inv *triagev1alpha1.Investigation,
	status *triagev1alpha1.InvestigationStatus, n *notes) (metav1.Condition, conditions.Progress, error) {
	key := client.ObjectKeyFromObject(inv)
	stall := func(reason, format string, args ...any) (metav1.Condition, conditions.Progress, error) {
		return metav1.Condition{Status: metav1.ConditionFalse, Reason: reason, Message: fmt.Sprintf(format, args...)},
			conditions.Stalled, nil
	}
	// An investigation that can't select its cases wants none judged.
	stalled := func(reason, format string, args ...any) (metav1.Condition, conditions.Progress, error) {
		r.Queue.Keep(key, nil)
		return stall(reason, format, args...)
	}
	// One stored before spec.agent existed reads back without it: with a cap of 0, it would skip every case.
	if inv.Spec.Agent.MaxCases < 1 {
		return stalled(triagev1alpha1.ReasonAgentSettingsMissing, "%s", "The investigation predates spec.agent: apply "+
			"it again with spec.agent, whose maxCases is required. It judges nothing until then.")
	}
	var playbook configv1alpha1.Playbook
	if err := r.Get(ctx, client.ObjectKey{Name: inv.Spec.PlaybookRef.Name}, &playbook); err != nil {
		if apierrors.IsNotFound(err) {
			return stalled(triagev1alpha1.ReasonPlaybookNotFound, "The Playbook %q doesn't exist.", inv.Spec.PlaybookRef.Name)
		}
		return metav1.Condition{}, conditions.None, err
	}
	agent := playbook.Spec.Agent
	if agent == nil {
		return stalled(triagev1alpha1.ReasonAgentNotAllowed,
			"The Playbook %q has no agent section, so none of its cases may go to the agent.", playbook.Name)
	}
	playbookConditions, err := compileConditions(agent.MatchConditions, func(c configv1alpha1.MatchCondition) engine.Condition {
		return engine.Condition{Name: c.Name, Expression: c.Expression}
	})
	if err != nil {
		return stalled(triagev1alpha1.ReasonInvalidCondition, "The Playbook %q: spec.agent.matchConditions: %v", playbook.Name, err)
	}
	investigationConditions, err := compileConditions(inv.Spec.MatchConditions, func(c triagev1alpha1.MatchCondition) engine.Condition {
		return engine.Condition{Name: c.Name, Expression: c.Expression}
	})
	if err != nil {
		return stalled(triagev1alpha1.ReasonInvalidCondition, "spec.matchConditions: %v", err)
	}
	cfg, err := settings.Load(ctx, r.Client)
	if err != nil {
		return metav1.Condition{}, conditions.None, err
	}
	trigger := triggerOf(inv)
	var sched cron.Schedule
	if trigger.Type == triagev1alpha1.InvestigationTriggerSchedule {
		if sched, err = schedule.Parse(ptr.Deref(trigger.Schedule, "")); err != nil {
			return stalled(triagev1alpha1.ReasonInvalidSchedule, "spec.trigger.schedule: %v", err)
		}
	}
	selected, skipped, err := r.selectCases(ctx, &playbook, cases.Selection{
		Playbook: playbook.Name, Vulnerabilities: inv.Spec.Vulnerabilities, SkipNotRunning: true,
		PlaybookConditions: playbookConditions, Conditions: investigationConditions, Overrides: cfg.Urgency.Overrides,
		Exposures: r.caseExposures(),
	})
	if err != nil {
		return metav1.Condition{}, conditions.None, err
	}
	slices.SortFunc(selected, cases.Compare)

	agentOn := cfg.AgentState == configv1alpha1.AgentStateEnabled
	enabled := ptr.Deref(inv.Spec.State, triagev1alpha1.InvestigationStateEnabled) != triagev1alpha1.InvestigationStateDisabled
	on := agentOn && enabled
	waiting, working := r.Queue.Pending(key, inv.UID)
	if on {
		r.startRun(inv, status, trigger, sched, waiting+working, n)
	}
	var charged int32
	if status.Cases != nil {
		charged = ptr.Deref(status.Cases.Charged, 0)
	}
	// Between the runs of a Once or Schedule investigation, nothing new is queued. While a run is open, the cases that
	// it holds stay with the queue, the agent switched on or off; new ones are handed over only while it is on.
	open := enabled && status.StartTime != nil &&
		(trigger.Type == triagev1alpha1.InvestigationTriggerContinuous || status.CompletionTime == nil)
	running := agentOn && open
	done, err := r.take(ctx, inv, &playbook, selected, open, running, status.StartTime, charged)
	n.charged = done.charged - charged
	if err != nil {
		return metav1.Condition{}, conditions.None, err
	}
	done.skipped = len(skipped)
	// A condition that fails, as on a field that the findings lack, skips cases as surely as one that doesn't hold, and
	// the Ready condition says so.
	failing, firstFailure := 0, ""
	for _, k := range skipped {
		if k.Failed {
			failing++
			firstFailure = cmp.Or(firstFailure, k.Reason)
		}
	}
	// The investigation keeps the cases that it would hand over, or has: a disabled one keeps none.
	if !enabled {
		done.wanted = nil
	}
	r.Queue.Keep(key, done.wanted)
	queued, inProgress := r.Queue.Pending(key, inv.UID)
	if running && trigger.Type != triagev1alpha1.InvestigationTriggerContinuous && done.toJudge == 0 && queued+inProgress == 0 {
		status.CompletionTime = ptr.To(r.now())
		n.events = append(n.events, [2]string{reasonRunFinished, "Every selected case is judged, reused or skipped."})
	}
	var wasElsewhere int32
	if status.Cases != nil {
		wasElsewhere = ptr.Deref(status.Cases.JudgedElsewhere, 0)
	}
	show(status, done, queued, inProgress)
	if e, changed := judgedElsewhereEvent(inv, done.elsewhere, done.earlier, wasElsewhere, running); changed {
		n.events = append(n.events, e)
	}
	if status.Usage, err = r.spent(ctx, inv, status.StartTime); err != nil {
		return metav1.Condition{}, conditions.None, err
	}

	ready, progress := readyOf(inv, done, len(selected), agentOn, enabled, queued+inProgress)
	if failing > 0 {
		ready.Message += fmt.Sprintf(" %d cases are skipped because a condition failed on them, the first so: %s.", failing,
			firstFailure)
	}
	return ready, progress, nil
}

// judgedElsewhereEvent returns the event JudgedElsewhere, which names up to namedElsewhere of the cases judged
// elsewhere, and whether to record it: when their count changed from was, and is above 0. Its advice follows the
// policy. Under IfJudgedElsewhere or Always a case counts as judged elsewhere only where the run couldn't hand it over:
// while the run hands cases over, running, that is for want of room, so it advises raising maxCases. Otherwise the run
// is closed, the investigation disabled or the agent off: room isn't what keeps the cases, so it advises nothing, though
// a changed spec of a Once investigation, a higher cap among them, starts a new run.
// Under IfStale, only an investigation with guidance gets the hint to judge them with it. Its first sentence says how
// many of the cases, earlier, were judged for an earlier object of the investigation's name.
func judgedElsewhereEvent(inv *triagev1alpha1.Investigation, elsewhere []string, earlier int, was int32, running bool) ([2]string,
	bool) {
	count := len(elsewhere)
	if count == 0 || int32(count) == was {
		return [2]string{}, false
	}
	hint := ""
	switch ptr.Deref(inv.Spec.Agent.JudgePolicy, triagev1alpha1.InvestigationJudgeIfStale) {
	case triagev1alpha1.InvestigationJudgeIfJudgedElsewhere, triagev1alpha1.InvestigationJudgeAlways:
		if running {
			hint = " Raise spec.agent.maxCases to judge them for this investigation: the cap had no room for them."
		}
	default:
		if ptr.Deref(inv.Spec.Agent.Guidance, "") != "" {
			hint = " Set spec.agent.judgePolicy to IfJudgedElsewhere to judge them with this investigation's guidance."
		}
	}
	first := fmt.Sprintf("%d selected cases reuse a verdict that was judged for another investigation, or for none.", count)
	switch {
	case earlier == count:
		first = fmt.Sprintf("%d selected cases reuse a verdict that was judged for an earlier %s.", count, inv.Name)
	case earlier > 0:
		first = fmt.Sprintf("%d selected cases reuse a verdict that was judged for another investigation, or for none; "+
			"%d of them for an earlier %s.", count, earlier, inv.Name)
	}
	return [2]string{reasonJudgedElsewhere, message(fmt.Sprintf("%s%s They include: %s.", first, hint,
		strings.Join(elsewhere[:min(count, namedElsewhere)], ", ")))}, true
}

// readyOf returns the Ready condition of an investigation's run, and the progress that goes with it.
func readyOf(inv *triagev1alpha1.Investigation, done run, selected int, agentOn, enabled bool, pending int) (metav1.Condition,
	conditions.Progress) {
	switch {
	case !agentOn:
		// The cases that wait stay in the queue, as design 5.11 says, for when the agent is switched on again.
		return metav1.Condition{Status: metav1.ConditionFalse, Reason: triagev1alpha1.ReasonAgentDisabled,
			Message: fmt.Sprintf("The agent is switched off in the OperatorConfig: the status shows where the %d selected "+
				"cases run, and none is judged.", selected)}, conditions.Stalled
	case !enabled:
		return metav1.Condition{Status: metav1.ConditionFalse, Reason: triagev1alpha1.ReasonDisabled,
			Message: "The investigation is disabled: it judges nothing new, and its status stays current."}, conditions.None
	case pending > 0:
		return metav1.Condition{Status: metav1.ConditionFalse, Reason: triagev1alpha1.ReasonJudging,
				Message: fmt.Sprintf("%d of %d cases have a verdict.", done.reused+done.judged, done.reused+done.judged+done.toJudge)},
			conditions.Reconciling
	case done.overTheCap > 0:
		return metav1.Condition{Status: metav1.ConditionTrue, Reason: triagev1alpha1.ReasonCapReached,
				Message: fmt.Sprintf("%d selected cases are over the cap of %d.", done.overTheCap, inv.Spec.Agent.MaxCases)},
			conditions.None
	}
	return metav1.Condition{Status: metav1.ConditionTrue, Reason: triagev1alpha1.ReasonJudged,
		Message: fmt.Sprintf("%d cases selected, %d with a fresh verdict, %d left to the agent.", selected, done.reused+done.judged,
			done.toJudge)}, conditions.None
}

// selectCases selects the cases of the playbook as sel says, counting the workloads of the clusters that the playbook's
// match selects only, by the labels of each cluster (design of remote spokes 5.8).
func (r *InvestigationReconciler) selectCases(ctx context.Context, playbook *configv1alpha1.Playbook, sel cases.Selection) (
	[]cases.Case, []cases.Skipped, error) {
	clusterLabels, err := settings.ClusterLabels(ctx, r.Client)
	if err != nil {
		return nil, nil, err
	}
	sel.Clusters = matchingClusters(playbook, clusterLabels)
	return cases.Select(ctx, r.Verdicts, r.Store, sel)
}

// caseExposures returns how the cases of one reconcile decide the exposure of their workloads: with the exposure rules
// of their playbook over the view, which count what they couldn't be evaluated for in Evaluations, and nil without a
// View.
func (r *InvestigationReconciler) caseExposures() cases.Exposures {
	if r.View == nil {
		return nil
	}
	return exposure.NewCaseExposures(r.View, r.playbookExposure,
		func(manifest, playbook string, notEvaluated map[string]int) {
			r.Evaluations.Record(ExposureEvaluations(manifest, playbook), notEvaluated)
		})
}

// playbookExposure returns what the cases read of the playbook of the name to decide the exposure of workloads, as the
// check of the playbook finds it, which the assessor runs too: its exposure rules, the type of each piece of its
// evidence, the producers whose evidence the rules read, by the cluster whose workloads they produce it for, how long
// the evidence of each counts, those of them that are sources, whose evidence is about entry points, and the evidence
// that it takes as optional.
//
// A workload's evidence comes from the collectors of its own cluster (design of remote spokes 5.7): the local
// Collectors produce for the hub's own cluster, and the collectors that a Spoke lists, with the maxAge that it mirrors,
// for the Spoke's cluster. An image's evidence comes from the local Collectors only (decision 0066). A source answers
// about entry points, which the hub asks it about whatever cluster runs the workload, so it counts for every cluster,
// under "".
//
// A Collector counts as a producer only while the capabilities that it recorded declare the type, and, unless it is a
// source of the type, with the scope Hub: the records of another scope, such as those left from before a downgrade,
// are nothing that a stream keeps current. A pinned Collector that doesn't count in a cluster, as one absent for the
// check, makes the piece's input missing there, as the finding rules get it, unless it counts as a source. A piece
// that a rule takes with another type has no producers.
func (r *InvestigationReconciler) playbookExposure(ctx context.Context, name string) (exposure.PlaybookExposure, error) {
	var playbook configv1alpha1.Playbook
	if err := r.Get(ctx, client.ObjectKey{Name: name}, &playbook); err != nil {
		return exposure.PlaybookExposure{}, err
	}
	check, err := checkPlaybook(ctx, r.Client, r.Rules, &playbook)
	if err != nil {
		return exposure.PlaybookExposure{}, err
	}
	cfg, err := settings.Load(ctx, r.Client)
	if err != nil {
		return exposure.PlaybookExposure{}, err
	}
	pe := exposure.PlaybookExposure{Steps: check.exposureSteps, Types: map[string]string{}, Optional: map[string]bool{},
		Producers: map[string]map[string][]string{}, MaxAges: map[[3]string]time.Duration{},
		Absent: map[string]map[string]bool{}}
	for _, e := range playbook.Spec.Evidence {
		pe.Types[e.Name], pe.Optional[e.Name] = e.Type, optional(e)
		if check.absent[e.Name] {
			continue
		}
		producers, absent := map[string][]string{}, map[string]bool{}
		// count notes the Collector of p as a producer of the piece for the cluster, or for every cluster as a source,
		// where it counts, and else notes a pin of it as absent in the cluster.
		count := func(cluster string, p producer, c *configv1alpha1.Collector, source bool) {
			key := cluster
			if source {
				key = ""
			}
			switch {
			case !p.absent && countsForExposure(c, e.Type, source):
				producers[key] = append(producers[key], p.collector)
				pe.MaxAges[[3]string{key, p.collector, e.Type}] = collectorclient.MaxAge(c, e.Type)
			case len(e.Collectors) > 0 && !slices.Contains(producers[""], p.collector):
				absent[cluster] = true
			}
		}
		for _, p := range check.producers[e.Name] {
			var c configv1alpha1.Collector
			if err := r.Get(ctx, client.ObjectKey{Name: p.collector}, &c); client.IgnoreNotFound(err) != nil {
				return exposure.PlaybookExposure{}, err
			}
			operation, _, _ := collectorclient.EntryPointSource(&c, e.Type)
			count(cfg.ClusterName, p, &c, operation != "")
		}
		if check.workloadEvidence[e.Name] {
			for cluster, listed := range check.remote {
				for _, p := range producersOf(listed, e.Type, e.Collectors) {
					var c configv1alpha1.Collector
					if i := slices.IndexFunc(listed, func(o configv1alpha1.Collector) bool { return o.Name == p.collector }); i >= 0 {
						c = listed[i]
					}
					// The hub asks a remote collector nothing, so none is a source.
					count(cluster, p, &c, false)
				}
			}
		}
		pe.Producers[e.Name], pe.Absent[e.Name] = producers, absent
	}
	return pe, nil
}

// countsForExposure reports whether the capabilities that the Collector recorded declare the type, with the scope Hub
// unless the Collector is a source of it, whose answers the hub asks for.
func countsForExposure(c *configv1alpha1.Collector, eventType string, source bool) bool {
	return c.Status.Capabilities != nil && slices.ContainsFunc(c.Status.Capabilities.Produces,
		func(p configv1alpha1.ProducedType) bool {
			return p.Type == eventType && (source || p.Scope == configv1alpha1.EvidenceScopeHub)
		})
}

// compileConditions compiles a list of match conditions.
func compileConditions[T any](list []T, conditionOf func(T) engine.Condition) (*engine.Conditions, error) {
	conds := make([]engine.Condition, 0, len(list))
	for _, c := range list {
		conds = append(conds, conditionOf(c))
	}
	return engine.CompileConditions(conds)
}

// take goes through the selected cases, the most urgent first: it reuses a fresh verdict that the judgePolicy takes, and
// hands the others to the agent while the cap has room, and leaves the rest over the cap. The cap is the counter in the status, charged, which
// counts each hand-off in this run, and in the life of a Continuous investigation: room is maxCases less charged, and
// each case that Queue.Add takes uses one, a stale case that was judged before included. A case that waits for the agent
// or is with it, held, keeps its place, and the others are judged, reused and skipped counts for the status only. While
// the investigation runs, it creates the Assessment of each case it hands over, and records the playbook in each
// Assessment it hands over or reuses. It hands a held case over again at each reconcile, whatever the room, and
// doesn't charge it again: the queue takes its current place in the tiers, and a restart of either side leaves it
// queued. A held case that an earlier object of the investigation's name charged, and that waits unclaimed, is taken
// over and charged once, whatever the room: the cap may be passed by such cases.
//
// The counter is written with the status of the same reconcile. It returns what it did up to an error too, so that a
// reconcile that fails after Queue.Add took cases keeps their charge. A crash between Queue.Add and the write still
// loses the charge of the cases that the reconcile added, so it under-charges by them. So does a cache that doesn't
// show yet that an earlier object charged a held case, which Queue.Add takes over from what the API server holds.
func (r *InvestigationReconciler) take(ctx context.Context, inv *triagev1alpha1.Investigation,
	playbook *configv1alpha1.Playbook, selected []cases.Case, open, running bool, start *metav1.Time, charged int32) (run,
	error) {
	done := run{selected: make([]judgement, 0, len(selected)), charged: charged}
	memo := map[string]map[string][]string{}
	policy := ptr.Deref(inv.Spec.Agent.JudgePolicy, triagev1alpha1.InvestigationJudgeIfStale)
	oldest := r.now().Add(-time.Duration(ptr.Deref(inv.Spec.Agent.VerdictMaxAgeSeconds, 0)) * time.Second)
	// An investigation that judges verdicts again past an age takes no older outcome from the agent.
	var judgedAfter time.Time
	if inv.Spec.Agent.VerdictMaxAgeSeconds != nil {
		judgedAfter = oldest
	}
	room := max(0, inv.Spec.Agent.MaxCases-charged)
	for _, c := range selected {
		a, err := r.assessmentOf(ctx, c)
		if err != nil {
			return done, err
		}
		fresh, err := r.fresh(ctx, a, c, playbook, memo)
		if err != nil {
			return done, err
		}
		// A verdict without a time can't be shown to be young enough.
		if fresh && inv.Spec.Agent.VerdictMaxAgeSeconds != nil && (a.Status.JudgedTime == nil || a.Status.JudgedTime.Time.Before(oldest)) {
			fresh = false
		}
		after := judgedAfter
		// A verdict that the policy declines is judged again only where the run hands its case over. Otherwise it still
		// shows, with its verdict.
		if fresh && !reuses(policy, a, inv, start) && handsOver(a, open, running, room) {
			// The agent must not take the verdict that is there as the answer. A second past it asks for a newer one, and
			// stays the same at each reconcile until that lands, which the queue keeps as the later judgedAfter.
			fresh, after = false, ptr.Deref(a.Status.JudgedTime, metav1.Time{}).Add(time.Second)
		}
		if judgedIn(a, start) {
			done.judged++
		}
		j := judgement{c: c, status: sheetStatus(c.Findings)}
		// held says the case waits for the agent or is with it already. A withdrawn case, which no investigation wanted
		// any more, is held by none.
		held := a != nil && !fresh && isHeld(a)
		switch {
		case fresh:
			if !judgedIn(a, start) {
				done.reused++
			}
			if !judgedFor(a, inv) {
				done.elsewhere = append(done.elsewhere, a.Name)
				if judgedForAnEarlier(a, inv) {
					done.earlier++
				}
			}
			// The verdict shows beside the sheet's status, which holds its Affected or UnderInvestigation, and its
			// NotAffected or Fixed only once a person accepted its statement.
			if v := a.Status.Verdict; v != nil {
				j.verdict, j.review, j.reason = &v.Status, sheetReview(c.Findings, a.Name, v.Status), firstSentence(v.Summary)
			} else {
				j.result, j.reason = triagev1alpha1.InvestigationResultError, firstSentence(a.Status.NoVerdict.Summary)
			}
			if running {
				if _, err := r.record(ctx, a, playbook.Name, false); err != nil {
					return done, err
				}
			}
		case held:
			// A case that waits or is with the agent was charged when it was handed over. It is handed over again
			// whatever the room and the agent's switch, while the run is open: the queue takes its current place in
			// the tiers.
			done.toJudge++
			done.wanted = append(done.wanted, cases.Name(c.VulnerabilityID, c.ManifestDigest))
			if open {
				if err := r.queueHeld(ctx, inv, a, c, playbook.Name, after, &room, &done); err != nil {
					return done, err
				}
			}
		case room > 0:
			done.toJudge++
			done.wanted = append(done.wanted, cases.Name(c.VulnerabilityID, c.ManifestDigest))
			if !running {
				room-- // what a run would hand over
				break
			}
			added, err := r.queue(ctx, inv, a, c, playbook.Name, after)
			if err != nil {
				return done, err
			}
			if added {
				room--
				done.charged++
			}
		default:
			done.overTheCap++
			j.result, j.reason = triagev1alpha1.InvestigationResultSkip, overTheCap
		}
		if j.result == "" {
			j.result = resultOf(j.status)
		}
		done.selected = append(done.selected, j)
	}
	return done, nil
}

// judgedIn reports whether the Assessment recorded its verdict, or no verdict, at or after the start of the run, whoever
// queued the case.
func judgedIn(a *triagev1alpha1.Assessment, start *metav1.Time) bool {
	return a != nil && start != nil && a.Status.JudgedTime != nil && !a.Status.JudgedTime.Before(start)
}

// handsOver reports whether an open run hands the case of the Assessment over: held already, or with room while the
// agent is on.
func handsOver(a *triagev1alpha1.Assessment, open, running bool, room int32) bool {
	return open && (isHeld(a) || room > 0 && running)
}

// queueHeld queues a held case again, and charges the investigation where the case waits unclaimed, charged to an
// earlier object of its name: this one takes the charge over, out of room. One that the queue lost is queued again,
// charged as it was.
func (r *InvestigationReconciler) queueHeld(ctx context.Context, inv *triagev1alpha1.Investigation,
	a *triagev1alpha1.Assessment, c cases.Case, playbook string, after time.Time, room *int32, done *run) error {
	earlier := chargedToAnEarlier(a, inv)
	added, err := r.queue(ctx, inv, a, c, playbook, after)
	if err == nil && added && earlier {
		*room--
		done.charged++
	}
	return err
}

// chargedToAnEarlier reports whether the Assessment's case waits unclaimed, charged to an earlier object of the
// investigation's namespace and name, so that queueing it again charges the investigation.
func chargedToAnEarlier(a *triagev1alpha1.Assessment, inv *triagev1alpha1.Investigation) bool {
	q := a.Status.Queue
	return q != nil && a.Status.Claim == nil && q.InvestigationRef != nil && q.InvestigationRef.Namespace == inv.Namespace &&
		q.InvestigationRef.Name == inv.Name && q.InvestigationRef.UID != inv.UID
}

// judgedFor reports whether the Assessment's outcome was judged for the investigation: its investigationRef names its
// namespace, name and uid, so that an investigation recreated under the same name doesn't take the earlier object's
// outcomes as its own.
func judgedFor(a *triagev1alpha1.Assessment, inv *triagev1alpha1.Investigation) bool {
	c := a.Status.InvestigationRef
	return c != nil && c.Namespace == inv.Namespace && c.Name == inv.Name && c.UID == inv.UID
}

// judgedForAnEarlier reports whether the Assessment's outcome was judged for an earlier object of the investigation's
// namespace and name: another uid.
func judgedForAnEarlier(a *triagev1alpha1.Assessment, inv *triagev1alpha1.Investigation) bool {
	c := a.Status.InvestigationRef
	return c != nil && c.Namespace == inv.Namespace && c.Name == inv.Name && c.UID != inv.UID
}

// reuses reports whether the judgePolicy takes the Assessment's fresh verdict: IfStale any, IfJudgedElsewhere one judged
// for the investigation, and Always one judged for it in this run. A policy that this version doesn't know takes any,
// as IfStale does, since the CRD's enum stops it at admission.
func reuses(policy triagev1alpha1.InvestigationJudgePolicy, a *triagev1alpha1.Assessment,
	inv *triagev1alpha1.Investigation, start *metav1.Time) bool {
	switch policy {
	case triagev1alpha1.InvestigationJudgeIfJudgedElsewhere:
		return judgedFor(a, inv)
	case triagev1alpha1.InvestigationJudgeAlways:
		return judgedFor(a, inv) && judgedIn(a, start)
	}
	return true
}

// spent sums the tokens of the judgements charged to the investigation at or after the start of its run, from the
// cache. It is nil before the run starts.
func (r *InvestigationReconciler) spent(ctx context.Context, inv *triagev1alpha1.Investigation,
	start *metav1.Time) (*triagev1alpha1.InvestigationUsage, error) {
	if start == nil {
		return nil, nil
	}
	var list triagev1alpha1.AssessmentList
	if err := r.List(ctx, &list); err != nil {
		return nil, fmt.Errorf("list the Assessments to sum the tokens of %s: %w", client.ObjectKeyFromObject(inv), err)
	}
	var prompt, completion int64
	for i := range list.Items {
		a := &list.Items[i]
		if !judgedFor(a, inv) || !judgedIn(a, start) || a.Status.Usage == nil {
			continue
		}
		prompt += ptr.Deref(a.Status.Usage.PromptTokens, 0)
		completion += ptr.Deref(a.Status.Usage.CompletionTokens, 0)
	}
	return &triagev1alpha1.InvestigationUsage{PromptTokens: ptr.To(prompt), CompletionTokens: ptr.To(completion)}, nil
}

// assessmentOf returns the Assessment of the case, or nil when there is none.
func (r *InvestigationReconciler) assessmentOf(ctx context.Context, c cases.Case) (*triagev1alpha1.Assessment, error) {
	a := &triagev1alpha1.Assessment{}
	err := r.Get(ctx, client.ObjectKey{Name: cases.Name(c.VulnerabilityID, c.ManifestDigest)}, a)
	if apierrors.IsNotFound(err) {
		return nil, nil
	}
	return a, err
}

// fresh reports whether the Assessment holds a verdict, or a no-verdict, on the case's current inputs: its inputHash is
// that of the case's findings and of the data of its case file, which comes from the Assessment's case-file playbook,
// or from the investigation's when that playbook is gone or has no sheet of the manifest.
func (r *InvestigationReconciler) fresh(ctx context.Context, a *triagev1alpha1.Assessment, c cases.Case,
	playbook *configv1alpha1.Playbook, memo map[string]map[string][]string) (bool, error) {
	if a == nil || (a.Status.Verdict == nil && a.Status.NoVerdict == nil) || a.Status.InputHash == nil {
		return false, nil
	}
	var hashes map[string][]string
	if name := ptr.Deref(a.Status.CaseFilePlaybook, playbook.Name); name != playbook.Name {
		var other configv1alpha1.Playbook
		switch err := r.Get(ctx, client.ObjectKey{Name: name}, &other); {
		case err == nil && other.Spec.Agent != nil:
			if hashes, err = r.caseFileHashes(ctx, c.ManifestDigest, &other, memo); err != nil {
				return false, err
			}
		case client.IgnoreNotFound(err) != nil:
			return false, err
		}
	}
	if hashes == nil {
		var err error
		if hashes, err = r.caseFileHashes(ctx, c.ManifestDigest, playbook, memo); err != nil || hashes == nil {
			return false, err
		}
	}
	return *a.Status.InputHash == cases.InputHash(c.Findings, hashes), nil
}

// caseFileHashes returns the hashes of the data of the case file's evidence of the manifest under the playbook, and nil
// when the playbook has no sheet of the manifest. memo keeps what a reconcile read, by manifest and playbook, so that it
// reads each sheet and its evidence once.
func (r *InvestigationReconciler) caseFileHashes(ctx context.Context, manifest string, playbook *configv1alpha1.Playbook,
	memo map[string]map[string][]string) (map[string][]string, error) {
	key := manifest + "/" + playbook.Name
	if hashes, seen := memo[key]; seen {
		return hashes, nil
	}
	sheet, err := r.Verdicts.Get(ctx, manifest, playbook.Name)
	if err != nil {
		return nil, err
	}
	var hashes map[string][]string
	if sheet != nil {
		if hashes, err = cases.EvidenceHashes(ctx, r.Evidence, sheet, playbook.Spec.Agent.Evidence); err != nil {
			return nil, err
		}
	}
	memo[key] = hashes
	return hashes, nil
}

// queue creates the case's Assessment when it has none, records the playbook in it, and queues the case as asQueued has
// it, with the Assessment's case-file playbook. It reports whether the queue took the case. asQueued runs before the
// record, which marks the case Queued: an error after the mark would leave a case queued that the queue never took,
// nor charged against maxCases.
func (r *InvestigationReconciler) queue(ctx context.Context, inv *triagev1alpha1.Investigation,
	a *triagev1alpha1.Assessment, c cases.Case, playbook string, judgedAfter time.Time) (bool, error) {
	if a == nil {
		a = &triagev1alpha1.Assessment{
			ObjectMeta: metav1.ObjectMeta{
				Name:   cases.Name(c.VulnerabilityID, c.ManifestDigest),
				Labels: cases.Labels(c.VulnerabilityID, c.ManifestDigest),
			},
			Spec: triagev1alpha1.AssessmentSpec{
				Subject: triagev1alpha1.AssessmentSubject{
					Type:           triagev1alpha1.SubjectTypeContainerImage,
					ContainerImage: &triagev1alpha1.ContainerImageSubject{Digest: c.ManifestDigest},
				},
				VulnerabilityID: c.VulnerabilityID,
			},
		}
		// Another investigation may have created it since the cache was read: the next reconcile reads it.
		if err := r.Create(ctx, a); err != nil {
			return false, fmt.Errorf("create the Assessment %q: %w", a.Name, err)
		}
	}
	queued, err := r.asQueued(ctx, a, c, playbook)
	if err != nil {
		return false, err
	}
	caseFile, err := r.record(ctx, a, playbook, true)
	if err != nil {
		return false, err
	}
	trigger := ptr.Deref(inv.Spec.Trigger, triagev1alpha1.InvestigationTrigger{Type: triagev1alpha1.InvestigationTriggerOnce})
	return r.Queue.Add(queued, cases.Request{Investigation: client.ObjectKeyFromObject(inv), InvestigationUID: inv.UID,
		Playbook: caseFile, Trigger: trigger.Type, JudgedAfter: judgedAfter}), nil
}

// asQueued returns the case as the agent's queue holds it, whichever playbook's investigation hands it over: of the
// views of the playbooks that select it, the most urgent, by the queue's tiers and then by the playbooks' names, with
// the union of their matching clusters, or none, which counts every cluster's, when one of them has no cluster
// selector. Several playbooks' results add up, and the most cautious counts (decision 0043). The playbooks are those
// that the Assessment names, of which c is the view of playbook, whose investigation hands the case over: the others are
// read as viewOf says, so that one that stops selecting the case stops shaping its place in the queue, at the next
// hand-over, and none freezes it.
func (r *InvestigationReconciler) asQueued(ctx context.Context, a *triagev1alpha1.Assessment, c cases.Case,
	playbook string) (cases.Case, error) {
	views := map[string]cases.Case{playbook: c}
	if others := slices.DeleteFunc(slices.Clone(a.Status.Playbooks), func(name string) bool { return name == playbook }); len(others) > 0 {
		cfg, err := settings.Load(ctx, r.Client)
		if err != nil {
			return cases.Case{}, err
		}
		clusterLabels, err := settings.ClusterLabels(ctx, r.Client)
		if err != nil {
			return cases.Case{}, err
		}
		for _, name := range others {
			view, err := r.viewOf(ctx, name, c, cfg.Urgency.Overrides, clusterLabels)
			if err != nil {
				return cases.Case{}, err
			}
			if view != nil {
				views[name] = *view
			}
		}
	}
	var queued cases.Case
	var clusters []string
	every := false
	for i, name := range slices.Sorted(maps.Keys(views)) {
		view := views[name]
		if i == 0 || cases.CompareTiers(cases.TiersOf(view), cases.TiersOf(queued)) < 0 {
			queued = view
		}
		every = every || view.Clusters == nil
		clusters = append(clusters, view.Clusters...)
	}
	queued.Clusters = nil
	if !every {
		slices.Sort(clusters)
		queued.Clusters = slices.Compact(clusters)
	}
	return queued, nil
}

// viewOf returns the case c as the playbook of the name selects it, from its own sheet of c's manifest, its matching
// clusters and its exposure rules, or nil where it doesn't: the playbook or its sheet is gone, the sheet holds no
// finding of c's vulnerability, or the case runs in no cluster that the playbook's match selects.
func (r *InvestigationReconciler) viewOf(ctx context.Context, name string, c cases.Case,
	overrides []configv1alpha1.UrgencyOverride, clusterLabels map[string]map[string]string) (*cases.Case, error) {
	var playbook configv1alpha1.Playbook
	if err := r.Get(ctx, client.ObjectKey{Name: name}, &playbook); err != nil {
		return nil, client.IgnoreNotFound(err)
	}
	sheet, err := r.Verdicts.Get(ctx, c.ManifestDigest, name)
	if err != nil || sheet == nil {
		return nil, err
	}
	selected, _, err := cases.SelectIn(ctx, sheet, r.Store, cases.Selection{Playbook: name,
		Vulnerabilities: []string{c.VulnerabilityID}, SkipNotRunning: true, Overrides: overrides, Exposures: r.caseExposures(),
		Clusters: matchingClusters(&playbook, clusterLabels)})
	if err != nil {
		return nil, err
	}
	i := slices.IndexFunc(selected, func(k cases.Case) bool { return k.VulnerabilityID == c.VulnerabilityID })
	if i < 0 {
		return nil, nil
	}
	return &selected[i], nil
}

// isHeld reports whether the case of the Assessment waits for the agent, Queued, or is with it, Judging.
func isHeld(a *triagev1alpha1.Assessment) bool {
	ready := meta.FindStatusCondition(a.Status.Conditions, configv1alpha1.ConditionReady)
	return ready != nil && ready.Status == metav1.ConditionFalse &&
		(ready.Reason == triagev1alpha1.ReasonQueued || ready.Reason == triagev1alpha1.ReasonJudging)
}

// record writes into the Assessment's status that the playbook's investigation selected it: its case-file playbook, the
// first that did, and the playbook in its list, and, for a case that is queued, the condition Queued unless it is held
// already. So a stale verdict, or a withdrawn case, that is queued again is held too. It returns the case-file
// playbook. A write that a newer version of the Assessment conflicts with is an error, and the reconcile is retried.
func (r *InvestigationReconciler) record(ctx context.Context, a *triagev1alpha1.Assessment, playbook string,
	queued bool) (string, error) {
	before := a.Status.DeepCopy()
	if a.Status.CaseFilePlaybook == nil {
		a.Status.CaseFilePlaybook = ptr.To(playbook)
	}
	if !slices.Contains(a.Status.Playbooks, playbook) {
		a.Status.Playbooks = append(a.Status.Playbooks, playbook)
	}
	if queued && !isHeld(a) {
		conditions.SetReady(&a.Status.Conditions, metav1.Condition{
			Status: metav1.ConditionFalse, Reason: triagev1alpha1.ReasonQueued,
			Message: "The case waits for the agent.", ObservedGeneration: a.Generation,
		}, conditions.Reconciling)
		conditions.Observe(&a.Status.ObservedGeneration, a.Generation)
	}
	if equality.Semantic.DeepEqual(*before, a.Status) {
		return *a.Status.CaseFilePlaybook, nil
	}
	if err := r.Status().Update(ctx, a); err != nil {
		return "", fmt.Errorf("record the playbook %q in the Assessment %q: %w", playbook, a.Name, err)
	}
	return *a.Status.CaseFilePlaybook, nil
}

// show writes what the run found into the status: the impact, the progress, the summary and the first results.
func show(status *triagev1alpha1.InvestigationStatus, done run, queued, inProgress int) {
	summary := map[triagev1alpha1.InvestigationResultType]int32{}
	type subject struct{ resources, namespaces, urgent int32 }
	subjects := map[string]subject{}
	clusters := map[string]bool{}
	for _, j := range done.selected {
		summary[j.result]++
		s := subjects[j.c.ManifestDigest]
		subjects[j.c.ManifestDigest] = subject{resources: j.c.Impact.Resources, namespaces: j.c.Impact.Namespaces,
			urgent: max(s.urgent, j.c.Impact.UrgentResources)}
		for _, name := range j.c.Impact.ClusterNames {
			clusters[name] = true
		}
	}
	// A subject's workloads are urgent where one of its cases is: the more exposed a workload, the more urgent each
	// case, so the case with the most urgent workloads counts them all.
	var impact subject
	for _, s := range subjects {
		impact.resources += s.resources
		impact.namespaces += s.namespaces
		impact.urgent += s.urgent
	}
	status.Impact = &triagev1alpha1.InvestigationImpact{
		Subjects: ptr.To(int32(len(subjects))), Resources: ptr.To(impact.resources), Namespaces: ptr.To(impact.namespaces),
		Clusters: ptr.To(int32(len(clusters))), UrgentResources: ptr.To(impact.urgent),
	}
	status.Cases = &triagev1alpha1.InvestigationCases{
		Total: ptr.To(int32(len(done.selected))), Queued: ptr.To(int32(queued)),
		InProgress: ptr.To(int32(inProgress)), Charged: ptr.To(done.charged), Judged: ptr.To(int32(done.judged)), Reused: ptr.To(int32(done.reused)),
		OverTheCap: ptr.To(int32(done.overTheCap)), JudgedElsewhere: ptr.To(int32(len(done.elsewhere))),
		NotSelected: ptr.To(int32(done.skipped)),
	}
	status.Summary = &triagev1alpha1.InvestigationSummary{
		Fail: ptr.To(summary[triagev1alpha1.InvestigationResultFail]), Pass: ptr.To(summary[triagev1alpha1.InvestigationResultPass]),
		Warn: ptr.To(summary[triagev1alpha1.InvestigationResultWarn]), Error: ptr.To(summary[triagev1alpha1.InvestigationResultError]),
		Skip: ptr.To(summary[triagev1alpha1.InvestigationResultSkip]),
	}
	status.Results = nil
	size := 0
	for _, j := range done.selected[:min(len(done.selected), maxResults)] {
		result := resultFor(j)
		// A result marshals: it holds strings, numbers and lists of them.
		raw, _ := json.Marshal(result)
		if size += len(raw); size > maxResultsBytes {
			break
		}
		status.Results = append(status.Results, result)
	}
	status.Omitted = ptr.To(int32(len(done.selected) - len(status.Results)))
}

// resultFor returns the result of a judged case: the case in the shape of an action.
func resultFor(j judgement) triagev1alpha1.InvestigationResult {
	c := j.c
	subject := c.ManifestDigest
	if len(c.Subject.Repositories) > 0 {
		subject = c.Subject.Repositories[0] + "@" + subject
	}
	result := triagev1alpha1.InvestigationResult{
		Subject: subject, VulnerabilityID: c.VulnerabilityID, Result: j.result,
		Severity: triagev1alpha1.Severity(highestSeverity(c.Findings)), Resources: ptr.To(c.Impact.Resources),
	}
	if j.status != "" {
		result.Status = ptr.To(triagev1alpha1.VEXStatus(j.status))
		result.Step = stepOf(c.Findings, j.status)
	}
	result.Verdict, result.Review = j.verdict, j.review
	if c.Impact.HighestUrgency != "" {
		result.Urgency = ptr.To(triagev1alpha1.SSVCOutcome(c.Impact.HighestUrgency))
	}
	if c.Impact.HighestExposure != "" {
		result.Exposure = ptr.To(triagev1alpha1.SSVCExposure(c.Impact.HighestExposure))
	}
	if j.reason != "" {
		result.Reason = ptr.To(j.reason)
	}
	for _, o := range c.Impact.Owners {
		owners := triagev1alpha1.NamespaceOwners{Cluster: o.Cluster, Namespace: o.Namespace}
		for _, v := range o.Owner {
			owners.Values = append(owners.Values, triagev1alpha1.OwnerValue{
				Source: triagev1alpha1.OwnerSource(v.Source), Key: v.Key, Value: v.Value,
			})
		}
		result.Owners = append(result.Owners, owners)
	}
	return result
}

// sheetReview returns where the review of the statement of the Assessment's verdict stands, as the sheet's findings show
// it, or nil when they show none.
func sheetReview(findings []inventoryv1alpha1.Finding, assessment string, verdict triagev1alpha1.VEXStatus) *triagev1alpha1.ReviewState {
	for _, f := range findings {
		if a := f.Agent; a != nil && a.Assessment == assessment && string(a.Status) == string(verdict) && a.Review != nil {
			return ptr.To(triagev1alpha1.ReviewState(*a.Review))
		}
	}
	return nil
}

// sheetStatus returns the most cautious status of the findings, as the most cautious wins between rules: Affected,
// then UnderInvestigation, then Fixed, then NotAffected.
func sheetStatus(findings []inventoryv1alpha1.Finding) inventoryv1alpha1.VEXStatus {
	order := []inventoryv1alpha1.VEXStatus{inventoryv1alpha1.VEXStatusAffected, inventoryv1alpha1.VEXStatusUnderInvestigation,
		inventoryv1alpha1.VEXStatusFixed, inventoryv1alpha1.VEXStatusNotAffected}
	rank := func(s inventoryv1alpha1.VEXStatus) int {
		if i := slices.Index(order, s); i >= 0 {
			return i
		}
		return 1 // a status that this version doesn't know is open
	}
	most := inventoryv1alpha1.VEXStatusNotAffected
	for _, f := range findings {
		if rank(f.Status) < rank(most) {
			most = f.Status
		}
	}
	return most
}

// resultOf returns OpenReports' result of a status: fail for Affected, pass for NotAffected and Fixed, and warn for
// UnderInvestigation and a status that this version doesn't know.
func resultOf(status inventoryv1alpha1.VEXStatus) triagev1alpha1.InvestigationResultType {
	switch status {
	case inventoryv1alpha1.VEXStatusAffected:
		return triagev1alpha1.InvestigationResultFail
	case inventoryv1alpha1.VEXStatusNotAffected, inventoryv1alpha1.VEXStatusFixed:
		return triagev1alpha1.InvestigationResultPass
	}
	return triagev1alpha1.InvestigationResultWarn
}

// stepOf returns what the owners do about the case at the status: Update when every package has a fix, or else the
// step of a package without one, and nil for a settled case.
func stepOf(findings []inventoryv1alpha1.Finding, status inventoryv1alpha1.VEXStatus) *triagev1alpha1.ResourceStep {
	step := triagev1alpha1.ResourceStepUpdate
	for _, f := range findings {
		f.Status = status
		switch s := urgency.NextStep(f); s {
		case "":
			return nil
		case triagev1alpha1.ResourceStepUpdate:
		default:
			step = s
		}
	}
	return &step
}

// highestSeverity returns the highest severity of the findings.
func highestSeverity(findings []inventoryv1alpha1.Finding) inventoryv1alpha1.Severity {
	most := inventoryv1alpha1.SeverityUnknown
	for _, f := range findings {
		if i := slices.Index(severityOrder, f.Severity); i >= 0 && i < slices.Index(severityOrder, most) {
			most = f.Severity
		}
	}
	return most
}

// severityOrder lists the severities from the most severe down.
var severityOrder = []inventoryv1alpha1.Severity{inventoryv1alpha1.SeverityCritical, inventoryv1alpha1.SeverityHigh,
	inventoryv1alpha1.SeverityMedium, inventoryv1alpha1.SeverityLow, inventoryv1alpha1.SeverityNegligible,
	inventoryv1alpha1.SeverityUnknown}

// firstSentence returns the first sentence of a summary, at most maxResultReasonLength characters.
func firstSentence(summary string) string {
	summary = strings.TrimSpace(summary)
	if loc := sentenceEnd.FindStringIndex(summary); loc != nil {
		summary = summary[:loc[0]+1]
	}
	return text.CutChars(summary, maxResultReasonLength)
}

// readyReason returns the reason of the Ready condition, or "" when there is none.
func readyReason(list []metav1.Condition) string {
	if ready := meta.FindStatusCondition(list, configv1alpha1.ConditionReady); ready != nil {
		return ready.Reason
	}
	return ""
}

// investigationsOf returns a map of an object to the investigations whose playbook it concerns, by the names that
// playbooks gives of it; nil names every investigation.
func (r *InvestigationReconciler) investigationsOf(playbooks func(client.Object) []string) handler.MapFunc {
	return func(ctx context.Context, obj client.Object) []reconcile.Request {
		names := playbooks(obj)
		var list triagev1alpha1.InvestigationList
		if err := r.List(ctx, &list); err != nil {
			logf.FromContext(ctx).Error(err, "Could not list the Investigations that a change concerns; they wait for their next change")
			return nil
		}
		var requests []reconcile.Request
		for _, inv := range list.Items {
			if names == nil || slices.Contains(names, inv.Spec.PlaybookRef.Name) {
				requests = append(requests, reconcile.Request{NamespacedName: types.NamespacedName{Namespace: inv.Namespace, Name: inv.Name}})
			}
		}
		return requests
	}
}

// debounced enqueues the requests that mapFn maps an event to after a pause: the queue keeps one request that waits, so
// the events within the pause come to one reconcile.
func debounced(pause time.Duration, mapFn handler.MapFunc) handler.EventHandler {
	add := func(ctx context.Context, obj client.Object, q workqueue.TypedRateLimitingInterface[reconcile.Request]) {
		for _, req := range mapFn(ctx, obj) {
			q.AddAfter(req, pause)
		}
	}
	return handler.Funcs{
		CreateFunc: func(ctx context.Context, e event.CreateEvent, q workqueue.TypedRateLimitingInterface[reconcile.Request]) {
			add(ctx, e.Object, q)
		},
		UpdateFunc: func(ctx context.Context, e event.UpdateEvent, q workqueue.TypedRateLimitingInterface[reconcile.Request]) {
			add(ctx, e.ObjectNew, q)
		},
		DeleteFunc: func(ctx context.Context, e event.DeleteEvent, q workqueue.TypedRateLimitingInterface[reconcile.Request]) {
			add(ctx, e.Object, q)
		},
		GenericFunc: func(ctx context.Context, e event.GenericEvent, q workqueue.TypedRateLimitingInterface[reconcile.Request]) {
			add(ctx, e.Object, q)
		},
	}
}

// SetupWithManager sets up the controller with the Manager.
func (r *InvestigationReconciler) SetupWithManager(mgr ctrl.Manager) error {
	pause := r.Debounce
	if pause == 0 {
		pause = DefaultInvestigationDebounce
	}
	sheets := &metav1.PartialObjectMetadata{}
	sheets.SetGroupVersionKind(inventoryv1alpha1.GroupVersion.WithKind("ImageVerdicts"))
	return ctrl.NewControllerManagedBy(mgr).
		Named("hub-investigation").
		// The controller's own status writes start no reconcile.
		For(&triagev1alpha1.Investigation{}, builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		// A playbook that comes, goes or changes, at once.
		Watches(&configv1alpha1.Playbook{}, handler.EnqueueRequestsFromMapFunc(r.investigationsOf(func(obj client.Object) []string {
			return []string{obj.GetName()}
		})), builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		// A sheet, through its metadata, whose name ends in its playbook's.
		Watches(sheets, debounced(pause, r.investigationsOf(func(obj client.Object) []string {
			_, playbook, _ := strings.Cut(obj.GetName(), ".")
			return []string{playbook}
		}))).
		// An Assessment of a playbook's case, as when the agent judged it.
		Watches(&triagev1alpha1.Assessment{}, debounced(pause, r.investigationsOf(func(obj client.Object) []string {
			a, ok := obj.(*triagev1alpha1.Assessment)
			if !ok {
				return []string{}
			}
			return append(slices.Clone(a.Status.Playbooks), ptr.Deref(a.Status.CaseFilePlaybook, ""))
		}))).
		// The switch of the agent, and the urgency's table, for every investigation.
		Watches(&configv1alpha1.OperatorConfig{}, debounced(pause, r.investigationsOf(func(client.Object) []string { return nil })),
			builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		Complete(r)
}
