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

package config_test

import (
	"context"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clocktesting "k8s.io/utils/clock/testing"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
	configcontroller "github.com/bedag/vexplain/internal/controller/config"
	collectorv1alpha1 "github.com/bedag/vexplain/sdk/api/collector/v1alpha1"
)

// The cron expressions, run-now values and other values of the tests of the schedules.
const (
	// cronDailyAtSix fires at 06:00 in UTC, an hour that a clock in a time zone ahead of UTC shows as later.
	cronDailyAtSix   = "0 6 * * *"
	cronDailyAtEight = "0 8 * * *"
	// cronNeverDue names the 30th of February, which never comes.
	cronNeverDue = "0 0 30 2 *"
	runNowFirst  = "2026-11-08T07:00:00Z"
	runNowSecond = "2026-11-08T08:00:00Z"
	// scheduledCluster is the cluster that the context of each fire of the scheduler's tests names.
	scheduledCluster = "cluster-a"
	// scheduledSettings are the settings of the Collectors of the scheduler's tests.
	scheduledSettings = `{"greeting":"hello"}`
	// mirrorDown is why a collector refuses a fire in the tests.
	mirrorDown = "the database mirror can't be reached"
	// quotedRefresh is how a condition's message names the schedule refresh.
	quotedRefresh = `"` + scheduleRefresh + `"`
	// retryDelay is how long the scheduler of the tests waits before it fires a schedule again whose fire for run now
	// failed: the deployer's resync of the tests.
	retryDelay = 30 * time.Second
	// fireWait bounds how long a test waits for a fire that runs in a goroutine of the scheduler.
	fireWait = 5 * time.Second
	firePoll = 10 * time.Millisecond
)

var (
	// sixUTC is 06:00 in UTC on a day of the scheduler's tests, which halfPastFive comes half an hour before, as a
	// clock one hour ahead of UTC shows it: 06:30. The scheduler's clock shows each time of the tests in that zone.
	sixUTC       = time.Date(2026, time.November, 8, 6, 0, 0, 0, time.UTC)
	aheadOfUTC   = time.FixedZone("UTC+1", 60*60)
	halfPastFive = sixUTC.Add(-30 * time.Minute).In(aheadOfUTC)

	// refreshDaily and compactWeekly are schedules that a Collector's status lists.
	refreshDaily  = configv1alpha1.ScheduleStatus{Name: scheduleRefresh, Schedule: cronDailyAtSix}
	compactWeekly = configv1alpha1.ScheduleStatus{Name: scheduleCompact, Schedule: cronWeekly}
)

// --- the scheduler on its own ---

// firedCall is a fire that the tests' firer took: the collector, the schedule, and the settings and the cluster that
// the request carried.
type firedCall struct{ collector, schedule, settings, cluster string }

// testFirer is the firer of the scheduler's tests. It notes each fire as it comes, fails the fires of the schedules in
// failing, and, while held isn't nil, holds each fire until the test releases it.
type testFirer struct {
	mu      sync.Mutex
	calls   []firedCall
	failing map[string]error
	held    chan struct{}
}

func (f *testFirer) Fire(ctx context.Context, collector string, req *collectorv1alpha1.FireRequest) error {
	f.mu.Lock()
	f.calls = append(f.calls, firedCall{collector: collector, schedule: req.GetSchedule(),
		settings: string(req.GetSettings()), cluster: req.GetContext().GetCluster()})
	err, held := f.failing[req.GetSchedule()], f.held
	f.mu.Unlock()
	if held != nil {
		select {
		case <-held:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return err
}

// taken returns the fires that the firer took, in the order that they came.
func (f *testFirer) taken() []firedCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.calls)
}

// fired returns the schedules of the fires that the firer took, in the order that they came.
func (f *testFirer) fired() []string {
	calls := f.taken()
	schedules := make([]string, 0, len(calls))
	for _, call := range calls {
		schedules = append(schedules, call.schedule)
	}
	return schedules
}

// fail makes the fires of the schedule fail with err, or succeed again when err is nil.
func (f *testFirer) fail(schedule string, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.failing[schedule] = err
}

// hold holds each fire until the function that it returns releases them.
func (f *testFirer) hold() (release func()) {
	f.mu.Lock()
	defer f.mu.Unlock()
	held := make(chan struct{})
	f.held = held
	return func() {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.held = nil
		close(held)
	}
}

// schedulerEnv is a scheduler on a fake clock, with the tests' firer. A test moves the clock, and runs the scheduler's
// rounds itself, as its Start would at each time that comes.
type schedulerEnv struct {
	t         *testing.T
	clock     *clocktesting.FakeClock
	firer     *testFirer
	scheduler *configcontroller.Scheduler
}

func newSchedulerEnv(t *testing.T) *schedulerEnv {
	t.Helper()
	e := &schedulerEnv{
		t:     t,
		clock: clocktesting.NewFakeClock(halfPastFive),
		firer: &testFirer{failing: map[string]error{}},
	}
	clusterContext := func(context.Context) (*collectorv1alpha1.Context, error) {
		return &collectorv1alpha1.Context{Cluster: scheduledCluster}, nil
	}
	e.scheduler = configcontroller.NewScheduler(e.firer, clusterContext, retryDelay, e.clock)
	return e
}

// roundAt moves the scheduler's clock to at, which it shows in a time zone ahead of UTC, runs a round, and waits until
// the fires that the round started have ended.
func (e *schedulerEnv) roundAt(at time.Time) {
	e.t.Helper()
	e.clock.SetTime(at.In(aheadOfUTC))
	e.scheduler.Round(e.t.Context())
	e.scheduler.WaitFires()
}

// startRound moves the clock to at, and runs a round without waiting for its fires.
func (e *schedulerEnv) startRound(at time.Time) {
	e.t.Helper()
	e.clock.SetTime(at.In(aheadOfUTC))
	e.scheduler.Round(e.t.Context())
}

// waitFired waits until the firer has taken n fires.
func (e *schedulerEnv) waitFired(n int) {
	e.t.Helper()
	require.Eventually(e.t, func() bool { return len(e.firer.taken()) == n }, fireWait, firePoll,
		"the firer took %v", e.firer.fired())
}

// notified returns the names of the Collectors that the scheduler asked the deployer to reconcile since the last
// call, in order.
func (e *schedulerEnv) notified() []string {
	return drainEvents(e.scheduler.Events())
}

// handled returns the run-now value that the scheduler handled last for c.
func (e *schedulerEnv) handled(c *configv1alpha1.Collector) string {
	_, handled := e.scheduler.Fired(c)
	return handled
}

// lastFire returns the last fire of the schedule of c that the scheduler recorded, which must exist.
func (e *schedulerEnv) lastFire(c *configv1alpha1.Collector, schedule string) configcontroller.Fire {
	e.t.Helper()
	fires, _ := e.scheduler.Fired(c)
	last, ok := fires[schedule]
	require.True(e.t, ok, "the scheduler recorded no fire of %s", schedule)
	return last
}

// drainEvents returns the names of the Collectors of the events that wait in events, in order.
func drainEvents(events <-chan event.GenericEvent) []string {
	var names []string
	for {
		select {
		case e := <-events:
			names = append(names, e.Object.GetName())
		default:
			return names
		}
	}
}

// scheduledCollector returns a Collector that is Ready for its generation, with settings, and whose status lists the
// schedules, as the deployer records them.
func scheduledCollector(schedules ...configv1alpha1.ScheduleStatus) *configv1alpha1.Collector {
	c := &configv1alpha1.Collector{
		ObjectMeta: metav1.ObjectMeta{Name: graceCollector, UID: types.UID(graceCollector + "-uid-1"), Generation: 1},
		Spec: configv1alpha1.CollectorSpec{
			Package: examplePackage, Settings: &runtime.RawExtension{Raw: []byte(scheduledSettings)},
		},
		Status: configv1alpha1.CollectorStatus{Schedules: schedules},
	}
	setReady(c, metav1.ConditionTrue, 1)
	return c
}

// setReady sets the Ready condition of c, for the generation.
func setReady(c *configv1alpha1.Collector, ready metav1.ConditionStatus, generation int64) {
	reason := configv1alpha1.ReasonHealthy
	if ready != metav1.ConditionTrue {
		reason = configv1alpha1.ReasonProgressing
	}
	meta.SetStatusCondition(&c.Status.Conditions, metav1.Condition{Type: configv1alpha1.ConditionReady, Status: ready,
		Reason: reason, ObservedGeneration: generation})
}

// withRunNow sets the run-now annotation of c to value, and returns c.
func withRunNow(c *configv1alpha1.Collector, value string) *configv1alpha1.Collector {
	c.Annotations = map[string]string{configv1alpha1.AnnotationRunNow: value}
	return c
}

// A schedule fires at the times of its cron expression in UTC, whatever the time zone of the clock, with the
// Collector's settings and the context of the cluster. The scheduler records the fire, and asks the deployer to write
// it into the status.
func TestAScheduleFiresAtItsTimesInUTC(t *testing.T) {
	e := newSchedulerEnv(t)
	c := scheduledCollector(refreshDaily)
	e.scheduler.Sync(c)

	e.roundAt(sixUTC.Add(-time.Second))
	require.Empty(t, e.firer.fired(), "not before its time")

	e.roundAt(sixUTC)
	require.Equal(t, []firedCall{{collector: graceCollector, schedule: scheduleRefresh, settings: scheduledSettings,
		cluster: scheduledCluster}}, e.firer.taken())
	require.True(t, e.lastFire(c, scheduleRefresh).Time.Equal(sixUTC), "the fire's time")
	require.Empty(t, e.lastFire(c, scheduleRefresh).Failure, "the collector took the fire")
	require.Equal(t, []string{graceCollector}, e.notified())

	e.roundAt(sixUTC.Add(23 * time.Hour))
	require.Len(t, e.firer.fired(), 1, "once a day")
	e.roundAt(sixUTC.Add(24 * time.Hour))
	require.Len(t, e.firer.fired(), 2)
}

// The times of a schedule count from when the scheduler starts to run it: a time that passed before, as while the
// operator didn't run, or before its cron expression changed, is never caught up on. A round that comes late, as
// after the process was suspended, fires once, and not once for each time that passed.
func TestTheTimesOfAScheduleCountFromWhenItStartsToRun(t *testing.T) {
	e := newSchedulerEnv(t)
	e.clock.SetTime(sixUTC.Add(time.Hour).In(aheadOfUTC))
	c := scheduledCollector(refreshDaily)
	e.scheduler.Sync(c)

	e.roundAt(sixUTC.Add(time.Hour))
	require.Empty(t, e.firer.fired(), "today's time passed before the scheduler ran the schedule")

	e.clock.SetTime(sixUTC.Add(90 * time.Minute).In(aheadOfUTC))
	c.Status.Schedules[0].Schedule = cronDailyAtEight
	e.scheduler.Sync(c)
	e.roundAt(sixUTC.Add(2 * time.Hour))
	require.Equal(t, []string{scheduleRefresh}, e.firer.fired(), "the changed expression's next time")
	e.roundAt(sixUTC.Add(24 * time.Hour))
	require.Len(t, e.firer.fired(), 1, "the old expression's time is gone")

	e.roundAt(sixUTC.Add(4*24*time.Hour + 2*time.Hour))
	require.Len(t, e.firer.fired(), 2, "a late round fires once")
	e.roundAt(sixUTC.Add(4*24*time.Hour + 2*time.Hour + time.Minute))
	require.Len(t, e.firer.fired(), 2)
}

// Only a Collector that is Ready for its generation is fired: one that isn't Ready, or is Ready for an older
// generation, whose spec the deployer hasn't checked yet, isn't. A time that passes meanwhile is skipped, and becoming
// Ready doesn't catch up on it.
func TestAScheduleOfACollectorThatIsntReadyIsSkipped(t *testing.T) {
	e := newSchedulerEnv(t)
	c := scheduledCollector(refreshDaily)
	setReady(c, metav1.ConditionUnknown, 1)
	e.scheduler.Sync(c)
	e.roundAt(sixUTC)
	require.Empty(t, e.firer.fired(), "not Ready")

	setReady(c, metav1.ConditionTrue, 1)
	c.Generation = 2
	e.scheduler.Sync(c)
	e.roundAt(sixUTC.Add(24 * time.Hour))
	require.Empty(t, e.firer.fired(), "Ready for an older generation")

	setReady(c, metav1.ConditionTrue, 2)
	e.scheduler.Sync(c)
	e.roundAt(sixUTC.Add(24*time.Hour + time.Minute))
	require.Empty(t, e.firer.fired(), "the time that passed isn't caught up on")
	e.roundAt(sixUTC.Add(48 * time.Hour))
	require.Equal(t, []string{scheduleRefresh}, e.firer.fired())
}

// A cron expression that never comes due, such as one for the 30th of February, leaves the schedule to run now alone.
func TestAScheduleThatNeverComesDueFiresForRunNowAlone(t *testing.T) {
	e := newSchedulerEnv(t)
	c := scheduledCollector(configv1alpha1.ScheduleStatus{Name: scheduleRefresh, Schedule: cronNeverDue})
	e.scheduler.Sync(c)

	e.roundAt(sixUTC.Add(4 * 366 * 24 * time.Hour))
	require.Empty(t, e.firer.fired())

	e.scheduler.Sync(withRunNow(c, runNowFirst))
	e.roundAt(sixUTC.Add(4*366*24*time.Hour + time.Second))
	require.Equal(t, []string{scheduleRefresh}, e.firer.fired())
}

// A new value of the run-now annotation fires every schedule once, and is handled once each fire has succeeded. The
// same value fires nothing again, before or after the status records it, and a new value fires every schedule again.
func TestRunNowFiresEveryScheduleOnceForEachNewValue(t *testing.T) {
	e := newSchedulerEnv(t)
	c := withRunNow(scheduledCollector(compactWeekly, refreshDaily), runNowFirst)

	e.scheduler.Sync(c)
	e.roundAt(halfPastFive)

	require.ElementsMatch(t, []string{scheduleCompact, scheduleRefresh}, e.firer.fired())
	require.Equal(t, runNowFirst, e.handled(c))
	for _, schedule := range []string{scheduleCompact, scheduleRefresh} {
		require.True(t, e.lastFire(c, schedule).Time.Equal(halfPastFive), schedule)
	}
	require.NotEmpty(t, e.notified(), "the deployer writes the value into the status")

	e.scheduler.Sync(c)
	e.roundAt(halfPastFive.Add(time.Second))
	require.Len(t, e.firer.fired(), 2, "the same value, before the status records it")

	c.Status.LastHandledRunNow = ptr.To(runNowFirst)
	e.scheduler.Sync(c)
	e.roundAt(halfPastFive.Add(2 * time.Second))
	require.Len(t, e.firer.fired(), 2, "the same value, once the status records it")

	e.scheduler.Sync(withRunNow(c, runNowSecond))
	e.roundAt(halfPastFive.Add(3 * time.Second))
	require.ElementsMatch(t, []string{scheduleCompact, scheduleRefresh, scheduleCompact, scheduleRefresh}, e.firer.fired())
	require.Equal(t, runNowSecond, e.handled(c))
}

// Review Focus 5: run now while the collector isn't Ready waits, and fires once when it is Ready, never twice, however
// often the deployer syncs before the status records the value, and even when the Collector turns not Ready and
// Ready again meanwhile.
func TestRunNowWaitsUntilTheCollectorIsReadyAndThenFiresOnce(t *testing.T) {
	e := newSchedulerEnv(t)
	c := withRunNow(scheduledCollector(refreshDaily), runNowFirst)
	setReady(c, metav1.ConditionUnknown, 1)
	e.scheduler.Sync(c)
	e.roundAt(halfPastFive)
	require.Empty(t, e.firer.fired())
	require.Empty(t, e.handled(c))

	setReady(c, metav1.ConditionTrue, 1)
	for i := range 3 {
		e.scheduler.Sync(c)
		e.roundAt(halfPastFive.Add(time.Duration(i+1) * time.Second))
	}
	require.Equal(t, []string{scheduleRefresh}, e.firer.fired())
	require.Equal(t, runNowFirst, e.handled(c))

	setReady(c, metav1.ConditionFalse, 1)
	e.scheduler.Sync(c)
	e.roundAt(halfPastFive.Add(10 * time.Second))
	setReady(c, metav1.ConditionTrue, 1)
	e.scheduler.Sync(c)
	e.roundAt(halfPastFive.Add(11 * time.Second))
	require.Len(t, e.firer.fired(), 1, "never twice")
}

// A fire for run now that fails leaves the value unhandled, and the scheduler asks the deployer to write the failure.
// The schedule fires for the value again once the retry delay has passed, and only that schedule: the others took the
// value already.
func TestAFailedFireForRunNowIsTriedAgainForItsScheduleAloneAfterTheRetryDelay(t *testing.T) {
	e := newSchedulerEnv(t)
	c := withRunNow(scheduledCollector(compactWeekly, refreshDaily), runNowFirst)
	e.firer.fail(scheduleRefresh, status.Error(codes.Unavailable, mirrorDown))
	e.scheduler.Sync(c)
	e.roundAt(halfPastFive)

	require.Empty(t, e.handled(c), "a fire failed")
	require.Contains(t, e.lastFire(c, scheduleRefresh).Failure, mirrorDown)
	require.Empty(t, e.lastFire(c, scheduleCompact).Failure)
	require.NotEmpty(t, e.notified(), "the deployer writes the failure at once")

	e.scheduler.Sync(c)
	e.roundAt(halfPastFive.Add(retryDelay - time.Second))
	require.Len(t, e.firer.fired(), 2, "not before the retry delay")

	e.firer.fail(scheduleRefresh, nil)
	e.roundAt(halfPastFive.Add(retryDelay))
	require.Equal(t, scheduleRefresh, e.firer.fired()[2])
	require.Len(t, e.firer.fired(), 3, "the schedule that took the value isn't fired again")
	require.Equal(t, runNowFirst, e.handled(c))
	require.Empty(t, e.lastFire(c, scheduleRefresh).Failure, "the last fire succeeded")
}

// A Sync that comes while a fire for run now runs fires nothing more: the value is handled once the fire succeeds. A
// run now that comes while the schedule fires at its time waits until that fire has ended, and then fires once.
func TestASyncDuringAFireFiresTheScheduleNoMore(t *testing.T) {
	e := newSchedulerEnv(t)
	c := withRunNow(scheduledCollector(refreshDaily), runNowFirst)
	release := e.firer.hold()
	e.scheduler.Sync(c)
	e.startRound(halfPastFive)
	e.waitFired(1)

	e.scheduler.Sync(c)
	e.startRound(halfPastFive.Add(time.Second))
	require.Empty(t, e.handled(c), "the fire runs")
	release()
	e.scheduler.WaitFires()
	e.scheduler.Sync(c)
	e.roundAt(halfPastFive.Add(2 * time.Second))
	require.Len(t, e.firer.fired(), 1)
	require.Equal(t, runNowFirst, e.handled(c))

	release = e.firer.hold()
	e.startRound(sixUTC)
	e.waitFired(2)
	e.scheduler.Sync(withRunNow(c, runNowSecond))
	e.startRound(sixUTC.Add(time.Second))
	release()
	e.scheduler.WaitFires()
	require.Len(t, e.firer.fired(), 2, "the schedule fires one fire at a time")
	e.roundAt(sixUTC.Add(2 * time.Second))
	require.Len(t, e.firer.fired(), 3, "then run now fires")
	require.Equal(t, runNowSecond, e.handled(c))
}

// A Collector without schedules handles a run-now value at once, once it is Ready: there is nothing to fire.
func TestRunNowOfACollectorWithoutSchedulesIsHandledOnceItIsReady(t *testing.T) {
	e := newSchedulerEnv(t)
	c := withRunNow(scheduledCollector(), runNowFirst)
	setReady(c, metav1.ConditionFalse, 1)
	e.scheduler.Sync(c)
	e.roundAt(halfPastFive)
	require.Empty(t, e.handled(c))
	require.Empty(t, e.notified())

	setReady(c, metav1.ConditionTrue, 1)
	e.scheduler.Sync(c)
	e.roundAt(halfPastFive.Add(time.Second))
	require.Equal(t, runNowFirst, e.handled(c))
	require.Equal(t, []string{graceCollector}, e.notified())
	require.Empty(t, e.firer.fired())
}

// The status holds the first 128 characters of a run-now value, so the scheduler handles a longer value as those:
// it fires once, and a scheduler of a new process, which finds them in the status, fires nothing.
func TestALongRunNowValueIsHandledAsItsFirst128Characters(t *testing.T) {
	long := strings.Repeat("7", 200)
	e := newSchedulerEnv(t)
	c := withRunNow(scheduledCollector(refreshDaily), long)
	e.scheduler.Sync(c)
	e.roundAt(halfPastFive)
	require.Equal(t, long[:128], e.handled(c))

	c.Status.LastHandledRunNow = ptr.To(long[:128])
	restarted := newSchedulerEnv(t)
	restarted.scheduler.Sync(c)
	restarted.roundAt(halfPastFive.Add(time.Second))
	require.Empty(t, restarted.firer.fired())
}

// The schedules of a Collector that is gone, or being deleted, stop. A fire that still runs records nothing, and asks
// the deployer for nothing.
func TestTheSchedulesOfACollectorThatIsGoneStop(t *testing.T) {
	e := newSchedulerEnv(t)
	c := scheduledCollector(refreshDaily)
	e.scheduler.Sync(c)
	e.scheduler.Forget(graceCollector)
	e.roundAt(sixUTC)
	require.Empty(t, e.firer.fired(), "gone")

	e.scheduler.Sync(c)
	deleting := c.DeepCopy()
	deleting.DeletionTimestamp = &metav1.Time{Time: sixUTC}
	e.scheduler.Sync(deleting)
	e.roundAt(sixUTC.Add(24 * time.Hour))
	require.Empty(t, e.firer.fired(), "being deleted")

	e.scheduler.Sync(c)
	release := e.firer.hold()
	e.startRound(sixUTC.Add(48 * time.Hour))
	e.waitFired(1)
	e.scheduler.Forget(graceCollector)
	release()
	e.scheduler.WaitFires()
	require.Empty(t, e.notified())
	fires, handled := e.scheduler.Fired(c)
	require.Empty(t, fires)
	require.Empty(t, handled)
}

// A Collector created again under the name of one that is gone, which the deployer hasn't forgotten yet, has a UID of
// its own: it starts afresh, with nothing of the old one's fires.
func TestACollectorCreatedAgainStartsAfresh(t *testing.T) {
	e := newSchedulerEnv(t)
	old := withRunNow(scheduledCollector(refreshDaily), runNowFirst)
	e.scheduler.Sync(old)
	e.roundAt(halfPastFive)
	require.Equal(t, runNowFirst, e.handled(old))

	created := withRunNow(scheduledCollector(refreshDaily), runNowFirst)
	created.UID = types.UID(graceCollector + "-uid-2")
	fires, handled := e.scheduler.Fired(created)
	require.Empty(t, fires)
	require.Empty(t, handled)
	e.scheduler.Sync(created)
	e.roundAt(halfPastFive.Add(time.Second))
	require.Len(t, e.firer.fired(), 2, "its run-now value is new to it")
}

// Start fires each schedule at its time on the scheduler's clock, and a run now at once. Once its context ends, it
// returns when the fires that run have ended.
func TestTheSchedulerRunsTheSchedulesOnItsClock(t *testing.T) {
	e := newSchedulerEnv(t)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- e.scheduler.Start(ctx) }()

	// Before the Sync nothing is due, so the scheduler waits on no timer: once it does, it waits for the schedule's time.
	e.scheduler.Sync(scheduledCollector(refreshDaily))
	require.Eventually(t, e.clock.HasWaiters, fireWait, firePoll)
	e.clock.Step(30 * time.Minute)
	e.waitFired(1)

	release := e.firer.hold()
	e.scheduler.Sync(withRunNow(scheduledCollector(refreshDaily), runNowFirst))
	e.waitFired(2)
	cancel()
	release()
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(fireWait):
		t.Fatal("Start didn't return once its context ended")
	}
}

// --- the deployer with its scheduler ---

// The tests below reconcile the deployer themselves, as the tests of the grace do, and run the rounds of its scheduler
// on a clock of their own: the scheduler's events would have the deployer reconcile.

// helloSchedules are the schedules that the test's collector declares: a refresh every six hours, and a compaction
// once a week.
func helloSchedules() []*collectorv1alpha1.Schedule {
	return []*collectorv1alpha1.Schedule{{Name: scheduleRefresh, Cron: cronEverySixHours}, {Name: scheduleCompact, Cron: cronWeekly}}
}

// declare makes the test's collector declare the schedules.
func (e *graceEnv) declare(schedules ...*collectorv1alpha1.Schedule) {
	e.collector.answer(func(_ *collectorv1alpha1.GetInfoResponse, caps *collectorv1alpha1.GetCapabilitiesResponse) {
		caps.Schedules = schedules
	})
}

// setTriggers writes the triggers into the spec of the Collector.
func (e *graceEnv) setTriggers(triggers ...configv1alpha1.CollectorTrigger) {
	e.t.Helper()
	obj := e.collectorObject()
	obj.Spec.Triggers = triggers
	require.NoError(e.t, e.client.Update(e.t.Context(), obj))
}

// annotateRunNow sets the run-now annotation of the Collector to value.
func (e *graceEnv) annotateRunNow(value string) {
	e.t.Helper()
	obj := e.collectorObject()
	obj.Annotations = map[string]string{configv1alpha1.AnnotationRunNow: value}
	require.NoError(e.t, e.client.Update(e.t.Context(), obj))
}

// fireAt moves the clock of the deployer's scheduler to at, runs a round of it, waits for the fires that the round
// started, and reconciles the Collector, as the deployer does when the scheduler asks it to. It returns the Collector.
func (e *graceEnv) fireAt(r *configcontroller.CollectorReconciler, at time.Time) *configv1alpha1.Collector {
	e.t.Helper()
	e.scheduleClock.SetTime(at)
	r.Scheduler.Round(e.t.Context())
	r.Scheduler.WaitFires()
	drainEvents(r.Scheduler.Events())
	e.reconcile(r)
	return e.collectorObject()
}

// scheduleNamed returns the status of the schedule of the name, which must exist.
func scheduleNamed(t *testing.T, obj *configv1alpha1.Collector, name string) configv1alpha1.ScheduleStatus {
	t.Helper()
	i := slices.IndexFunc(obj.Status.Schedules, func(s configv1alpha1.ScheduleStatus) bool { return s.Name == name })
	require.GreaterOrEqual(t, i, 0, "the status lists no schedule %s", name)
	return obj.Status.Schedules[i]
}

// A trigger that names no schedule of the collector, or a schedule whose cron expression, as spec.triggers sets it or
// as the collector declares it, the operator can't run, makes the Collector TriggersInvalid: the message names the
// trigger or the schedule, and only a change of the spec or the package helps.
func TestTriggersThatNameNoScheduleOrACronExpressionThatDoesntParseAreTriggersInvalid(t *testing.T) {
	for name, tc := range map[string]struct {
		declared string
		triggers []configv1alpha1.CollectorTrigger
		says     []string
	}{
		"a trigger of a name that the collector doesn't declare": {cronEverySixHours,
			[]configv1alpha1.CollectorTrigger{{Name: "nightly"}}, []string{`"nightly"`}},
		"a cron expression of six fields": {cronEverySixHours,
			[]configv1alpha1.CollectorTrigger{{Name: scheduleRefresh, Schedule: ptr.To("0 */6 * * * *")}},
			[]string{quotedRefresh, "spec.triggers", "fields"}},
		"a time zone": {cronEverySixHours,
			[]configv1alpha1.CollectorTrigger{{Name: scheduleRefresh, Schedule: ptr.To("TZ=Europe/Zurich " + cronDailyAtSix)}},
			[]string{quotedRefresh, "time zone"}},
		"a descriptor": {cronEverySixHours,
			[]configv1alpha1.CollectorTrigger{{Name: scheduleRefresh, Schedule: ptr.To("@daily")}}, []string{quotedRefresh}},
		"a declared cron expression that doesn't parse": {"61 * * * *", nil, []string{quotedRefresh, "the collector declares"}},
	} {
		t.Run(name, func(t *testing.T) {
			e := newGraceEnv(t)
			e.declare(&collectorv1alpha1.Schedule{Name: scheduleRefresh, Cron: tc.declared})
			e.setTriggers(tc.triggers...)
			r := e.start()
			e.reconcile(r)
			e.makeAvailable()
			e.serve()

			ready := e.reconcile(r)

			require.Equal(t, metav1.ConditionFalse, ready.Status)
			require.Equal(t, configv1alpha1.ReasonTriggersInvalid, ready.Reason, ready.Message)
			for _, part := range tc.says {
				require.Contains(t, ready.Message, part)
			}
			obj := e.collectorObject()
			require.True(t, meta.IsStatusConditionTrue(obj.Status.Conditions, configv1alpha1.ConditionStalled))
			require.NotNil(t, obj.Status.Capabilities, "what the package declares is recorded")
			require.Empty(t, obj.Status.Schedules, "no schedule runs")
		})
	}
}

// The status lists the schedules that run: those that the collector declares, each with the cron expression that
// spec.triggers sets for it. A trigger can replace a declared expression that doesn't parse.
func TestTheStatusListsTheSchedulesWithTheCronExpressionsOfTheTriggers(t *testing.T) {
	e := newGraceEnv(t)
	e.declare(&collectorv1alpha1.Schedule{Name: scheduleRefresh, Cron: "61 * * * *"},
		&collectorv1alpha1.Schedule{Name: scheduleCompact, Cron: cronWeekly})
	e.setTriggers(configv1alpha1.CollectorTrigger{Name: scheduleRefresh, Schedule: ptr.To(cronHourly)},
		configv1alpha1.CollectorTrigger{Name: scheduleCompact})
	r := e.start()

	e.healthy(r)

	require.Equal(t, []configv1alpha1.ScheduleStatus{
		{Name: scheduleCompact, Schedule: cronWeekly}, {Name: scheduleRefresh, Schedule: cronHourly},
	}, e.collectorObject().Status.Schedules)
}

// A declared schedule fires at its time, and the status records when, and whether the collector took the fire. A
// restart of the operator leaves what the status recorded.
func TestAScheduleThatFiresAtItsTimeHasItsLastFireInTheStatus(t *testing.T) {
	e := newGraceEnv(t)
	e.declare(helloSchedules()...)
	r := e.start()
	e.healthy(r)
	sixPM := time.Date(2026, time.November, 1, 18, 0, 0, 0, time.UTC)

	e.fireAt(r, sixPM.Add(-time.Second))
	require.Empty(t, e.collector.fires(), "not before its time")
	obj := e.fireAt(r, sixPM)
	require.Equal(t, []string{scheduleRefresh}, e.collector.fires())
	refresh := scheduleNamed(t, obj, scheduleRefresh)
	require.NotNil(t, refresh.LastFireTime)
	require.True(t, refresh.LastFireTime.Time.Equal(sixPM))
	require.Nil(t, refresh.LastFailure)
	require.Nil(t, scheduleNamed(t, obj, scheduleCompact).LastFireTime, "the compaction's time hasn't come")

	e.collector.failFires(status.Error(codes.Unavailable, mirrorDown))
	obj = e.fireAt(r, sixPM.Add(6*time.Hour))
	refresh = scheduleNamed(t, obj, scheduleRefresh)
	require.True(t, refresh.LastFireTime.Time.Equal(sixPM.Add(6*time.Hour)))
	require.Contains(t, ptr.Deref(refresh.LastFailure, ""), mirrorDown)

	// The operator starts again, its new authority issues the collector's certificate again, and the collector loads it.
	e.collector.failFires(nil)
	second := e.start()
	e.reconcile(second)
	e.serve()
	require.Eventually(t, func() bool { return e.reconcile(second).Reason == configv1alpha1.ReasonHealthy }, 20*time.Second,
		100*time.Millisecond)
	require.Equal(t, refresh, scheduleNamed(t, e.collectorObject(), scheduleRefresh), "what the status recorded stays")
}

// Review Focus 5, through the deployer: run now while the collector isn't Ready waits, fires each schedule once when
// it is Ready, and the status records the value. Reconciles and rounds after that fire nothing more.
func TestRunNowWaitsUntilReadyFiresOnceAndIsRecorded(t *testing.T) {
	e := newGraceEnv(t)
	e.declare(helloSchedules()...)
	e.annotateRunNow(runNowFirst)
	r := e.start()
	require.Equal(t, configv1alpha1.ReasonProgressing, e.reconcile(r).Reason)
	e.fireAt(r, e.now)
	require.Empty(t, e.collector.fires(), "not Ready")

	e.makeAvailable()
	e.serve()
	require.Equal(t, configv1alpha1.ReasonHealthy, e.reconcile(r).Reason)
	obj := e.fireAt(r, e.now)

	require.ElementsMatch(t, []string{scheduleRefresh, scheduleCompact}, e.collector.fires())
	require.Equal(t, ptr.To(runNowFirst), obj.Status.LastHandledRunNow)
	for _, schedule := range obj.Status.Schedules {
		require.NotNil(t, schedule.LastFireTime, schedule.Name)
		require.Nil(t, schedule.LastFailure, schedule.Name)
	}
	for i := range 3 {
		e.fireAt(r, e.now.Add(time.Duration(i+1)*time.Second))
	}
	require.Len(t, e.collector.fires(), 2, "never twice")
}

// A fire for run now that fails leaves lastHandledRunNow unset, and the status says why. Once the retry delay has
// passed, the schedule fires again, and the status records the value.
func TestAFailedFireForRunNowLeavesTheValueUnhandledAndRecordsTheFailure(t *testing.T) {
	e := newGraceEnv(t)
	e.declare(&collectorv1alpha1.Schedule{Name: scheduleRefresh, Cron: cronEverySixHours})
	r := e.start()
	e.healthy(r)
	e.collector.failFires(status.Error(codes.Unavailable, mirrorDown))
	e.annotateRunNow(runNowFirst)
	e.reconcile(r)

	obj := e.fireAt(r, e.now)
	require.Nil(t, obj.Status.LastHandledRunNow)
	require.Contains(t, ptr.Deref(scheduleNamed(t, obj, scheduleRefresh).LastFailure, ""), mirrorDown)

	e.collector.failFires(nil)
	e.fireAt(r, e.now.Add(retryDelay-time.Second))
	require.Len(t, e.collector.fires(), 1, "not before the retry delay")
	obj = e.fireAt(r, e.now.Add(retryDelay))
	require.Len(t, e.collector.fires(), 2)
	require.Equal(t, ptr.To(runNowFirst), obj.Status.LastHandledRunNow)
	require.Nil(t, scheduleNamed(t, obj, scheduleRefresh).LastFailure, "the last fire succeeded")
}

// The deployer reconciles a Collector when its generation changes, and when its run-now annotation does, which changes
// no generation. Its own writes of the status change neither, and neither does another annotation.
func TestTheDeployerHearsOfANewRunNowValue(t *testing.T) {
	old := &configv1alpha1.Collector{ObjectMeta: metav1.ObjectMeta{Name: graceCollector, Generation: 1}}
	updated := func(change func(*configv1alpha1.Collector)) bool {
		changed := old.DeepCopy()
		change(changed)
		return configcontroller.CollectorChanged.Update(event.UpdateEvent{ObjectOld: old, ObjectNew: changed})
	}

	require.True(t, updated(func(c *configv1alpha1.Collector) {
		c.Annotations = map[string]string{configv1alpha1.AnnotationRunNow: runNowFirst}
	}))
	require.True(t, updated(func(c *configv1alpha1.Collector) { c.Generation = 2 }))
	require.False(t, updated(func(c *configv1alpha1.Collector) {
		c.Annotations = map[string]string{"example.com/note": runNowFirst}
	}))
	require.False(t, updated(func(c *configv1alpha1.Collector) { c.Status.LastHandledRunNow = ptr.To(runNowFirst) }))
}

// This spec runs against the suite's manager, wired as in production, whose scheduler's clock stands still: run now
// alone fires.
var _ = Describe("Running the schedules of a collector", func() {
	It("fires each schedule once for a new value of the run-now annotation, and records the value", func() {
		f := newFakeCollector()
		f.answer(func(_ *collectorv1alpha1.GetInfoResponse, caps *collectorv1alpha1.GetCapabilitiesResponse) {
			caps.Schedules = helloSchedules()
		})
		name := newCollector(helloSpec(""))
		serveFake(name, f)
		makeAvailable(name, runningDigest)
		expectReady(name, metav1.ConditionTrue, configv1alpha1.ReasonHealthy)

		Eventually(func() error {
			var obj configv1alpha1.Collector
			if err := k8sClient.Get(ctx, client.ObjectKey{Name: name}, &obj); err != nil {
				return err
			}
			obj.Annotations = map[string]string{configv1alpha1.AnnotationRunNow: runNowFirst}
			return k8sClient.Update(ctx, &obj)
		}, deployTimeout, deployPoll).Should(Succeed())

		Eventually(func(g Gomega) *string {
			got, _ := readyOf(name)(g)
			return got.Status.LastHandledRunNow
		}, deployTimeout, deployPoll).Should(HaveValue(Equal(runNowFirst)))
		Expect(f.fires()).To(ConsistOf(scheduleRefresh, scheduleCompact))
		got, _ := readyOf(name)(Default)
		Expect(got.Status.Schedules).To(HaveEach(HaveField("LastFireTime", Not(BeNil()))))

		By("firing nothing more for the same value")
		Consistently(f.fires, 2*time.Second, 250*time.Millisecond).Should(HaveLen(2))
	})
})
