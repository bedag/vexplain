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

package config

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/robfig/cron/v3"
	"google.golang.org/grpc/status"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/clock"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/event"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
	"github.com/bedag/vexplain/internal/text"
	collectorv1alpha1 "github.com/bedag/vexplain/sdk/api/collector/v1alpha1"
)

const (
	// maxRunNowLength is how many characters of a run-now value status.lastHandledRunNow holds.
	maxRunNowLength = 128
	// maxFailureLength is how many characters of why a fire failed status.schedules holds.
	maxFailureLength = 1024
	// pendingEvents is how many of the scheduler's requests to reconcile a Collector wait for the deployer before the
	// next one waits too.
	pendingEvents = 64
)

// cronParser parses the five fields of a standard cron expression, minute, hour, day of month, month and day of week,
// as Kubernetes' CronJob does, and no descriptor such as @daily.
var cronParser = cron.NewParser(cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow)

// parseCron parses a schedule's cron expression, which runs in UTC. It refuses a time zone, as TZ= or CRON_TZ=, which
// the parser would take otherwise: schedules run in UTC, and Kubernetes refuses a time zone in a CronJob's schedule in
// the same way.
func parseCron(expression string) (cron.Schedule, error) {
	if strings.Contains(expression, "TZ") {
		return nil, errors.New("it names a time zone, and schedules run in UTC")
	}
	return cronParser.Parse(expression)
}

// Firer fires a schedule of a collector, as collectorclient.Pool does.
type Firer interface {
	Fire(ctx context.Context, collector string, req *collectorv1alpha1.FireRequest) error
}

// Scheduler runs the schedules of the collectors (design 5.2, decision 0040). For each Collector that is Ready for its
// generation, it fires each schedule that the Collector's status lists at the times of its cron expression, in UTC,
// and fires every schedule once for each new value of the Collector's run-now annotation. A fire calls the collector's
// Fire, with the Collector's settings and the context of the cluster.
//
//   - The times of a schedule count from when the scheduler starts to run it, after a start of the operator or a
//     change of its cron expression: a time that passed before is never caught up on. A time that comes while the
//     Collector isn't Ready is skipped, and so is one that comes while the schedule still fires, as a CronJob with the
//     concurrency policy Forbid skips a run while the last one runs.
//   - A run-now value that status.lastHandledRunNow doesn't record fires each schedule once, as soon as the Collector
//     is Ready. The value is handled once each schedule's fire for it has succeeded, and at once for a Collector without
//     schedules. A schedule whose fire for the value failed fires for it again once the retry delay has passed, and the
//     schedules that took it don't. The scheduler remembers which schedules took a value, or fire for it, so it fires
//     none twice for it, however often the deployer syncs before the status records the value.
//   - The schedules of a Collector that is gone, or being deleted, stop, and a fire of it that still runs records
//     nothing.
//
// The scheduler writes no status: the deployer alone writes a Collector's status. The scheduler keeps the last fire of
// each schedule, and the run-now value that it handled last, in memory, and asks the deployer to reconcile the
// Collector, through Events, whenever they change; the deployer writes them into the status. A restart forgets them,
// and the status keeps what was written. A value whose fires succeeded just before a restart, and that the status
// doesn't record yet, fires again after it.
//
// It is a manager.Runnable, which the manager runs on its leader only, as it runs every runnable that doesn't say
// otherwise: two replicas would fire each schedule twice.
type Scheduler struct {
	firer          Firer
	clusterContext func(context.Context) (*collectorv1alpha1.Context, error)
	retry          time.Duration
	clock          clock.Clock
	// events carries the requests to reconcile a Collector, and wake tells the goroutine of Start that a Sync, or the
	// end of a fire, changed what is due.
	events chan event.GenericEvent
	wake   chan struct{}
	// fires counts the fires that run.
	fires sync.WaitGroup

	// mu guards entries, and what each holds.
	mu      sync.Mutex
	entries map[string]*entry
}

// entry is what the scheduler knows of a Collector.
type entry struct {
	// name is the Collector's name, and uid tells it from a Collector of the same name that was created after it.
	name string
	uid  types.UID
	// ready says whether the Collector is Ready for its generation, and settings are its spec.settings, which each fire
	// carries.
	ready    bool
	settings []byte
	// runNow is the run-now value of its annotation, "" for none, recorded the one that its status records, and handled
	// the one that this process handled last.
	runNow, recorded, handled string
	// slots are the schedules that its status lists, by name, and those that it listed before, whose fires may still
	// run.
	slots map[string]*slot
}

// slot is a schedule of a Collector, as the scheduler runs it.
type slot struct {
	name string
	// listed says whether the Collector's status lists the schedule. One that it no longer lists doesn't fire, and is
	// kept for its fire that may still run, and for the run-now values that it took.
	listed bool
	// expression is its cron expression, times the times that it gives, and next the next of them, or zero for none.
	expression string
	times      cron.Schedule
	next       time.Time
	// firing says whether a fire of it runs.
	firing bool
	// took is the run-now value that it last fired for with success, and failed the one whose fire failed last, which
	// fires again at retryAt.
	took, failed string
	retryAt      time.Time
	// last is the last fire of it that this process made, or nil.
	last *fire
}

// fire is what came of a fire: when it was made, in whole seconds, as the status holds a time, and why it failed, or
// "" when the collector took it.
type fire struct {
	at      time.Time
	failure string
}

// NewScheduler returns a scheduler that fires through firer, the deployer's pool, with the context of the cluster that
// clusterContext builds, as collectorclient.ClusterContext does. A schedule whose fire for run now failed fires again
// after retry. The scheduler tells the time by clk.
func NewScheduler(firer Firer, clusterContext func(context.Context) (*collectorv1alpha1.Context, error),
	retry time.Duration, clk clock.Clock) *Scheduler {
	return &Scheduler{
		firer:          firer,
		clusterContext: clusterContext,
		retry:          retry,
		clock:          clk,
		events:         make(chan event.GenericEvent, pendingEvents),
		wake:           make(chan struct{}, 1),
		entries:        map[string]*entry{},
	}
}

// Sync takes what the Collector c says now: whether it is Ready for its generation, its settings, the schedules that
// its status lists, its run-now annotation, and the run-now value that its status records. The deployer calls it after
// each reconcile. A Collector that is being deleted is forgotten.
func (s *Scheduler) Sync(c *configv1alpha1.Collector) {
	if !c.DeletionTimestamp.IsZero() {
		s.Forget(c.Name)
		return
	}
	s.mu.Lock()
	e := s.entries[c.Name]
	if e == nil || e.uid != c.UID {
		e = &entry{name: c.Name, uid: c.UID, slots: map[string]*slot{}}
		s.entries[c.Name] = e
	}
	e.ready = readyForGeneration(c)
	e.settings = nil
	if c.Spec.Settings != nil {
		e.settings = slices.Clone(c.Spec.Settings.Raw)
	}
	e.runNow, e.recorded = runNowOf(c), ptr.Deref(c.Status.LastHandledRunNow, "")
	e.list(c.Status.Schedules, s.clock.Now())
	s.mu.Unlock()
	s.signal()
}

// Forget stops the schedules of the collector, whose Collector is gone. A fire of it that still runs records nothing.
func (s *Scheduler) Forget(collector string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.entries, collector)
}

// Events returns the scheduler's requests to reconcile a Collector whose last fires, or the run-now value that the
// scheduler handled last, changed, so that the deployer writes them into its status.
func (s *Scheduler) Events() <-chan event.GenericEvent {
	return s.events
}

// Start runs the schedules until ctx ends, and then returns once the fires that run have ended. It fires what is due,
// and waits until the next time that comes, or until a Sync or the end of a fire changes what is due.
func (s *Scheduler) Start(ctx context.Context) error {
	ctx = logf.IntoContext(ctx, logf.FromContext(ctx).WithName("collector-schedules"))
	defer s.fires.Wait()
	for {
		if !s.await(ctx, s.round(ctx)) {
			return nil
		}
	}
}

// await waits until next, unless it is zero, until a Sync or the end of a fire changes what is due, or until ctx ends,
// and says whether the scheduler goes on.
func (s *Scheduler) await(ctx context.Context, next time.Time) bool {
	var due <-chan time.Time
	if !next.IsZero() {
		timer := s.clock.NewTimer(next.Sub(s.clock.Now()))
		defer timer.Stop()
		// The clock may pass next before the timer is made, as when it jumps, and the timer would then wait for a later
		// time: what is due is fired at once.
		if !s.clock.Now().Before(next) {
			return ctx.Err() == nil
		}
		due = timer.C()
	}
	select {
	case <-ctx.Done():
		return false
	case <-s.wake:
	case <-due:
	}
	return true
}

// round fires what is due at the time of the clock, and returns the next time that comes, or zero for none: a
// schedule's time, or when a fire for run now that failed may fire again.
func (s *Scheduler) round(ctx context.Context) time.Time {
	s.mu.Lock()
	now := s.clock.Now()
	var next time.Time
	var handled []string
	for _, e := range s.entries {
		next = earliest(next, s.fireTimes(ctx, e, now))
		if !e.ready || !e.pending() {
			continue
		}
		next = earliest(next, s.fireRunNow(ctx, e, now))
		if e.settle() {
			handled = append(handled, e.name)
		}
	}
	s.mu.Unlock()
	for _, name := range handled {
		s.notify(ctx, name)
	}
	return next
}

// fireTimes fires each schedule of e whose time has come, while e is Ready, and returns the next time of its
// schedules. A schedule's next time follows from now, so that a round that comes late fires once.
func (s *Scheduler) fireTimes(ctx context.Context, e *entry, now time.Time) time.Time {
	var next time.Time
	for _, sl := range e.slots {
		if !sl.listed {
			continue
		}
		if !sl.next.IsZero() && !now.Before(sl.next) {
			sl.next = sl.times.Next(now.UTC())
			if e.ready && !sl.firing {
				s.start(ctx, e, sl, "", now)
			}
		}
		next = earliest(next, sl.next)
	}
	return next
}

// fireRunNow fires each schedule of e for its run-now value that hasn't taken it, doesn't fire, and whose fire for it
// didn't fail within the retry delay, and returns when the next of those may fire again.
func (s *Scheduler) fireRunNow(ctx context.Context, e *entry, now time.Time) time.Time {
	var next time.Time
	for _, sl := range e.slots {
		switch {
		case !sl.listed || sl.took == e.runNow || sl.firing:
		case sl.failed == e.runNow && now.Before(sl.retryAt):
			next = earliest(next, sl.retryAt)
		default:
			s.start(ctx, e, sl, e.runNow, now)
		}
	}
	return next
}

// start fires the schedule of e in a goroutine of its own: for the run-now value runNow, or at its time when runNow is
// "".
func (s *Scheduler) start(ctx context.Context, e *entry, sl *slot, runNow string, now time.Time) {
	sl.firing = true
	request := &collectorv1alpha1.FireRequest{Schedule: sl.name, Settings: e.settings}
	s.fires.Go(func() {
		err := s.fire(ctx, e.name, request)
		s.finish(ctx, e, sl, runNow, now, err)
	})
}

// fire calls the collector's Fire with the request, and the context of the cluster.
func (s *Scheduler) fire(ctx context.Context, collector string, request *collectorv1alpha1.FireRequest) error {
	clusterContext, err := s.clusterContext(ctx)
	if err != nil {
		return fmt.Errorf("build the context of the collectors: %w", err)
	}
	request.Context = clusterContext
	return s.firer.Fire(ctx, collector, request)
}

// finish records what came of a fire of the schedule of e made at: for the run-now value runNow, or at its time when
// runNow is "". It asks the deployer to write it into the Collector's status, unless the scheduler has forgotten the
// Collector since.
func (s *Scheduler) finish(ctx context.Context, e *entry, sl *slot, runNow string, at time.Time, err error) {
	s.mu.Lock()
	current := s.entries[e.name] == e
	sl.firing = false
	sl.last = &fire{at: at.Truncate(time.Second), failure: failureOf(err)}
	switch {
	case runNow == "":
	case err == nil:
		sl.took = runNow
	default:
		sl.failed, sl.retryAt = runNow, s.clock.Now().Add(s.retry)
	}
	e.settle()
	s.mu.Unlock()
	s.signal()
	if !current {
		return
	}
	// A failure's message is the collector's text, which the status shows: the log line gives the code of the call.
	log := logf.FromContext(ctx).WithValues("collector", e.name, "schedule", sl.name)
	if err != nil {
		log.Info("A fire of the collector's schedule failed; the status of its Collector says why",
			"code", status.Code(err).String())
	} else {
		log.V(1).Info("Fired the collector's schedule")
	}
	s.notify(ctx, e.name)
}

// notify asks the deployer to reconcile the Collector of the name, so that it writes what the scheduler recorded into
// its status.
func (s *Scheduler) notify(ctx context.Context, collector string) {
	select {
	case s.events <- event.GenericEvent{Object: &configv1alpha1.Collector{ObjectMeta: metav1.ObjectMeta{Name: collector}}}:
	case <-ctx.Done():
	}
}

// signal wakes the goroutine of Start, without waiting.
func (s *Scheduler) signal() {
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

// fired returns what the scheduler recorded of the fires of the Collector c since this process started: the last fire
// of each schedule, by name, and the run-now value that it handled last, or "" for none.
func (s *Scheduler) fired(c *configv1alpha1.Collector) (map[string]fire, string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e := s.entries[c.Name]
	if e == nil || e.uid != c.UID {
		return nil, ""
	}
	fires := make(map[string]fire, len(e.slots))
	for name, sl := range e.slots {
		if sl.last != nil {
			fires[name] = *sl.last
		}
	}
	return fires, e.handled
}

// list takes the schedules that the Collector's status lists. A schedule that is new, listed again, or whose cron
// expression changed counts its times from now. One that the status no longer lists stops.
func (e *entry) list(schedules []configv1alpha1.ScheduleStatus, now time.Time) {
	listed := make(map[string]bool, len(schedules))
	for _, listing := range schedules {
		listed[listing.Name] = true
		sl := e.slots[listing.Name]
		if sl == nil {
			sl = &slot{name: listing.Name}
			e.slots[listing.Name] = sl
		}
		if sl.listed && sl.expression == listing.Schedule {
			continue
		}
		times, err := parseCron(listing.Schedule)
		if err != nil {
			// The deployer lists no schedule that it can't run, so this one is no schedule of the Collector.
			sl.listed = false
			continue
		}
		// A time that never comes, as for the 30th of February, is zero.
		sl.listed, sl.expression, sl.times, sl.next = true, listing.Schedule, times, times.Next(now.UTC())
	}
	for name, sl := range e.slots {
		if !listed[name] {
			sl.listed = false
		}
	}
}

// pending says whether the Collector asks for a run now that it hasn't had: a run-now value that neither its status
// records, nor this process handled.
func (e *entry) pending() bool {
	return e.runNow != "" && e.runNow != e.recorded && e.runNow != e.handled
}

// settle notes the run-now value of a pending run now as handled once each schedule that the status lists has taken
// it, which a Collector without schedules has at once, and says whether it did.
func (e *entry) settle() bool {
	if !e.pending() {
		return false
	}
	for _, sl := range e.slots {
		if sl.listed && sl.took != e.runNow {
			return false
		}
	}
	e.handled = e.runNow
	return true
}

// readyForGeneration says whether the Collector c is Ready for its generation: the deployer found its collector
// healthy, and its spec, its triggers among it, valid.
func readyForGeneration(c *configv1alpha1.Collector) bool {
	ready := meta.FindStatusCondition(c.Status.Conditions, configv1alpha1.ConditionReady)
	return ready != nil && ready.Status == metav1.ConditionTrue && ready.ObservedGeneration == c.Generation
}

// runNowOf returns the run-now value of the Collector c, as its status records one: the first characters of its
// annotation, as many as the status holds. It returns "" when the annotation is absent or empty, which asks for
// nothing.
func runNowOf(c *configv1alpha1.Collector) string {
	return text.CutChars(c.Annotations[configv1alpha1.AnnotationRunNow], maxRunNowLength)
}

// failureOf returns what the status says of the error of a fire: printable, and cut to what the status holds, or ""
// for none.
func failureOf(err error) string {
	if err == nil {
		return ""
	}
	return text.Required(err.Error(), maxFailureLength)
}

// earliest returns the earlier of a and b, where zero stands for none.
func earliest(a, b time.Time) time.Time {
	if a.IsZero() || (!b.IsZero() && b.Before(a)) {
		return b
	}
	return a
}

// --- what the deployer records of the schedules ---

// effectiveSchedules returns the schedules that the operator runs for a collector: those that it declares, in their
// order, each with the cron expression that spec.triggers sets for it, if it sets one. It refuses, for TriggersInvalid,
// a trigger that names no schedule that the collector declares, and a cron expression that the operator can't run, and
// names the trigger or the schedule.
func effectiveSchedules(declared []configv1alpha1.CollectorSchedule, triggers []configv1alpha1.CollectorTrigger) (
	[]configv1alpha1.CollectorSchedule, *refusal) {
	named := func(name string) func(configv1alpha1.CollectorSchedule) bool {
		return func(s configv1alpha1.CollectorSchedule) bool { return s.Name == name }
	}
	for _, trigger := range triggers {
		if !slices.ContainsFunc(declared, named(trigger.Name)) {
			return nil, refuse(configv1alpha1.ReasonTriggersInvalid,
				"spec.triggers names %s, and the collector declares no schedule of that name.", quote(trigger.Name))
		}
	}
	effective := make([]configv1alpha1.CollectorSchedule, 0, len(declared))
	for _, declaration := range declared {
		expression, from := declaration.Cron, "the collector declares"
		i := slices.IndexFunc(triggers, func(t configv1alpha1.CollectorTrigger) bool { return t.Name == declaration.Name })
		if i >= 0 && triggers[i].Schedule != nil {
			expression, from = *triggers[i].Schedule, "spec.triggers sets"
		}
		if _, err := parseCron(expression); err != nil {
			return nil, refuse(configv1alpha1.ReasonTriggersInvalid,
				"The cron expression %s, which %s for the schedule %s, isn't five fields in UTC: %v.",
				quote(expression), from, quote(declaration.Name), err)
		}
		effective = append(effective, configv1alpha1.CollectorSchedule{Name: declaration.Name, Cron: expression})
	}
	return effective, nil
}

// scheduleStatuses returns the status of the schedules that run, each with the last fire that recorded holds for its
// name: a restart of the operator, whose scheduler has recorded nothing yet, keeps it.
func scheduleStatuses(schedules []configv1alpha1.CollectorSchedule, recorded []configv1alpha1.ScheduleStatus) []configv1alpha1.ScheduleStatus {
	statuses := make([]configv1alpha1.ScheduleStatus, 0, len(schedules))
	for _, running := range schedules {
		current := configv1alpha1.ScheduleStatus{Name: running.Name, Schedule: running.Cron}
		i := slices.IndexFunc(recorded, func(r configv1alpha1.ScheduleStatus) bool { return r.Name == running.Name })
		if i >= 0 {
			current.LastFireTime, current.LastFailure = recorded[i].LastFireTime, recorded[i].LastFailure
		}
		statuses = append(statuses, current)
	}
	return statuses
}

// recordFires writes into the status of obj what the deployer's scheduler recorded of its fires: the last fire of each
// schedule that the status lists, and the run-now value that it handled last.
func (r *CollectorReconciler) recordFires(obj *configv1alpha1.Collector) {
	fires, handled := r.Scheduler.fired(obj)
	for i := range obj.Status.Schedules {
		listed := &obj.Status.Schedules[i]
		last, ok := fires[listed.Name]
		if !ok {
			continue
		}
		at := metav1.NewTime(last.at)
		listed.LastFireTime, listed.LastFailure = &at, nil
		if last.failure != "" {
			listed.LastFailure = ptr.To(last.failure)
		}
	}
	if handled != "" {
		obj.Status.LastHandledRunNow = ptr.To(handled)
	}
}
