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

// Package worker claims the cases of the agent's queue, which lives in the Assessments' status, and judges them
// (decision 0057). A worker claims a case with a lease, in one status update that carries the Assessment's
// resourceVersion, so that of two workers one wins. It renews the lease while it judges, and stops once the claim
// names another worker.
package worker

import (
	"cmp"
	"context"
	"fmt"
	"maps"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/retry"
	"k8s.io/utils/clock"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	triagev1alpha1 "github.com/bedag/vexplain/api/triage/v1alpha1"
	"github.com/bedag/vexplain/internal/agent/cases"
	"github.com/bedag/vexplain/internal/conditions"
	"github.com/bedag/vexplain/internal/inventory"
	"github.com/bedag/vexplain/internal/settings"
)

const (
	// DefaultLease is how long a claim lasts unless its worker renews it, and DefaultRenew how often the worker renews
	// it while it judges.
	DefaultLease = 60 * time.Second
	DefaultRenew = 20 * time.Second
	// DefaultRenewTimeout bounds a renewal, well within the 30 seconds of grace that the hub's sweep gives a lease
	// that ended: a renewal that hangs can't keep a judgement running once the sweep may hand its case to another
	// worker.
	DefaultRenewTimeout = 10 * time.Second
)

// Result is what a judge did with a case.
type Result int

const (
	// Done takes the case out of the queue.
	Done Result = iota
	// Wait hands the case back, with nothing written, such as one whose model isn't Ready, or one in progress when the
	// agent was switched off. It is tried again after RetryDelay.
	Wait
	// Retry hands back a case whose judgement failed before it spent tokens, such as at an endpoint that is down from
	// the first request. It is tried again after RetryDelay, doubled for each failure in a row, at most
	// cases.MaxBackoff.
	Retry
	// Failed hands back a case whose judgement failed after it spent tokens, or whose outcome couldn't be written, as
	// Retry does, and counts the failure.
	Failed
)

// Judge judges one case for a worker, and says what became of it. failures counts the judgements of the case that
// failed as Failed says, or whose worker stopped, since it came into the queue: a wait for another reason doesn't start
// it again. ctx ends when the worker stops, or once the case's claim names another worker. Claimant(ctx) is the name of
// the worker, which the judge's writes check the claim against.
type Judge func(ctx context.Context, c cases.Case, r cases.Request, failures int) Result

// Loop claims the cases of the queue, the first in order whose wait is over, while fewer cases are judged than its
// limit, and judges each with its Judge. It is a manager's runnable.
type Loop struct {
	// Client lists the Assessments from a cache, and writes their status. APIReader reads an Assessment past the cache
	// before the writes that follow a claim.
	Client    client.Client
	APIReader client.Reader
	// Verdicts and Store are what a case is rebuilt from: its sheet, and where its image runs.
	Verdicts inventory.VerdictsStore
	Store    inventory.Store
	// Name names the worker in the claims: its pod's name.
	Name string
	// Limit returns how many cases may be judged at once over all workers: the ModelConfig's maxConcurrentRequests. It
	// is read before each round of claims.
	Limit func() int
	// CanStart reports whether any case can start now, read before each round of claims: while it can't, the loop
	// claims nothing, rather than claim each waiting case for its judge to hand it straight back. Nil means always.
	CanStart func() bool
	Judge    Judge
	// Lease is how long a claim lasts, and Renew how often the worker renews it. Zero means DefaultLease and
	// DefaultRenew.
	Lease, Renew time.Duration
	// RenewTimeout bounds each renewal. Zero means DefaultRenewTimeout.
	RenewTimeout time.Duration
	// RetryDelay is how long a case that the judge handed back waits. Zero means cases.DefaultRetryDelay.
	RetryDelay time.Duration
	// Clock tells the time of the leases and of the waits. Nil means the real clock.
	Clock clock.WithTicker

	mu sync.Mutex
	// running holds the cases that this worker judges now, and wake tells the loop that one ended.
	running map[string]bool
	wake    chan struct{}
}

// poll is how often a loop looks at the queue without being woken: for a case whose wait ended, a case that another
// worker handed back, and a change of the limit.
const poll = time.Second

// writeTimeout bounds the writes that end a claim, the judge's outcome among them, which go ahead when the worker stops
// meanwhile, so that an outcome is written whole and the cases don't wait for their leases to run out.
const writeTimeout = 30 * time.Second

// A worker reads the queue, the cases' sheets and inventory and the OperatorConfig, and writes the Assessments' status.
// +kubebuilder:rbac:groups=triage.vexplain.bedag.ch,resources=assessments,verbs=get;list;watch
// +kubebuilder:rbac:groups=triage.vexplain.bedag.ch,resources=assessments/status,verbs=update
// +kubebuilder:rbac:groups=inventory.vexplain.bedag.ch,resources=imageverdicts,verbs=get;list
// +kubebuilder:rbac:groups=inventory.vexplain.bedag.ch,resources=imageinventories,verbs=get;list;watch
// +kubebuilder:rbac:groups=config.vexplain.bedag.ch,resources=operatorconfigs,verbs=get;list;watch

// NeedLeaderElection says that the loop runs on every replica of the workers: the claims, and not a leader, keep two
// workers from judging one case.
func (l *Loop) NeedLeaderElection() bool { return false }

// Start claims and judges cases until ctx is done, and then waits for the cases in progress, whose judge sees ctx end.
func (l *Loop) Start(ctx context.Context) error {
	l.mu.Lock()
	l.running, l.wake = map[string]bool{}, make(chan struct{}, 1)
	l.mu.Unlock()
	var running sync.WaitGroup
	defer running.Wait()
	ticker := l.clock().NewTicker(min(poll, l.retryDelay()))
	defer ticker.Stop()
	for {
		l.claim(ctx, &running)
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C():
		case <-l.wake:
		}
	}
}

// claim claims the waiting cases in order while fewer cases are judged than the limit, and judges each in a goroutine
// of running. A claim that another worker's write beat, as the conflict says, leaves the case to it.
func (l *Loop) claim(ctx context.Context, running *sync.WaitGroup) {
	if l.CanStart != nil && !l.CanStart() {
		return
	}
	log := logf.FromContext(ctx).WithValues("worker", l.Name)
	var list triagev1alpha1.AssessmentList
	// The objects are only read: a claim writes a copy.
	if err := l.Client.List(ctx, &list, client.UnsafeDisableDeepCopy); err != nil {
		log.Error(err, "Could not list the agent's queue")
		return
	}
	now := l.clock().Now()
	l.mu.Lock()
	mine := maps.Clone(l.running)
	l.mu.Unlock()
	// Cases that this worker claimed count, whether the cache shows their claims yet or not.
	judging := len(mine)
	var waiting []*triagev1alpha1.Assessment
	for i := range list.Items {
		a := &list.Items[i]
		switch q := a.Status.Queue; {
		case q == nil, mine[a.Name]:
		case a.Status.Claim != nil:
			judging++
		case q.NotBefore == nil || !q.NotBefore.After(now):
			waiting = append(waiting, a)
		}
	}
	slices.SortFunc(waiting, inOrder)
	limit := max(l.Limit(), 1)
	for _, a := range waiting {
		if judging >= limit {
			return
		}
		claimed := a.DeepCopy()
		claimed.Status.Claim = &triagev1alpha1.QueueClaim{Worker: l.Name,
			LeaseEndTime: ptr.To(metav1.NewTime(now.Add(l.lease()).Truncate(time.Second)))}
		cases.SetWaiting(claimed, triagev1alpha1.ReasonJudging, "The agent judges the case.", conditions.Reconciling)
		if err := l.Client.Status().Update(ctx, claimed); err != nil {
			if !apierrors.IsConflict(err) && !apierrors.IsNotFound(err) {
				log.Error(err, "Could not claim a case", "assessment", a.Name)
			}
			continue
		}
		judging++
		l.mu.Lock()
		l.running[a.Name] = true
		l.mu.Unlock()
		running.Go(func() { l.work(ctx, claimed) })
	}
}

// inOrder orders the waiting cases: by the tiers, then a case that a person asked for, through an investigation that
// runs Once, then the first come, and then by name.
func inOrder(a, b *triagev1alpha1.Assessment) int {
	asked := func(a *triagev1alpha1.Assessment) int {
		if once(a.Status.Queue) {
			return 0
		}
		return 1
	}
	return cmp.Or(cases.CompareTiers(cases.TiersOfOrder(a.Status.Queue.Order), cases.TiersOfOrder(b.Status.Queue.Order)),
		cmp.Compare(asked(a), asked(b)), timeOf(a.Status.Queue.QueuedTime).Compare(timeOf(b.Status.Queue.QueuedTime)),
		strings.Compare(a.Name, b.Name))
}

// once reports whether an investigation that runs Once requests the case.
func once(q *triagev1alpha1.AssessmentQueue) bool {
	return slices.ContainsFunc(q.Requests, func(r triagev1alpha1.QueueRequest) bool {
		return r.Trigger == triagev1alpha1.InvestigationTriggerOnce
	})
}

// work judges a claimed case, renewing its lease meanwhile, and ends the claim. A case that its sheet holds no more is
// withdrawn unjudged.
func (l *Loop) work(ctx context.Context, a *triagev1alpha1.Assessment) {
	defer func() {
		l.mu.Lock()
		delete(l.running, a.Name)
		l.mu.Unlock()
		select {
		case l.wake <- struct{}{}:
		default:
		}
	}()
	log := logf.FromContext(ctx).WithValues("worker", l.Name, "assessment", a.Name)
	c, err := l.caseOf(ctx, a)
	switch {
	case err != nil:
		log.Error(err, "Could not read the case; it waits in the queue")
		l.release(ctx, a.Name, Wait, false)
		return
	case c == nil:
		log.Info("The case's sheet holds it no more; it leaves the queue")
		l.release(ctx, a.Name, Done, true)
		return
	}
	judgeCtx, cancel := context.WithCancel(WithClaimant(ctx, l.Name))
	renewed := l.renew(judgeCtx, a.Name, a.Status.Claim.LeaseEndTime.Time, cancel)
	result := l.Judge(judgeCtx, *c, requestOf(a), int(ptr.Deref(a.Status.Queue.Failures, 0)))
	cancel()
	<-renewed
	l.release(ctx, a.Name, result, false)
}

// requestOf returns the request that the judge gets for the case: the investigation that the queue charged while it
// still wants the case, whose guidance the case gets, the playbook whose case file goes with it, the trigger Once when
// such an investigation wants it, and the latest JudgedAfter.
func requestOf(a *triagev1alpha1.Assessment) cases.Request {
	q := a.Status.Queue
	r := cases.Request{Playbook: q.Playbook, JudgedAfter: timeOf(q.JudgedAfter)}
	if c := q.InvestigationRef; c != nil && slices.ContainsFunc(q.Requests, func(req triagev1alpha1.QueueRequest) bool {
		return req.InvestigationRef == *c
	}) {
		r.Investigation, r.InvestigationUID = types.NamespacedName{Namespace: c.Namespace, Name: c.Name}, c.UID
	}
	switch {
	case once(q):
		r.Trigger = triagev1alpha1.InvestigationTriggerOnce
	case len(q.Requests) > 0:
		r.Trigger = q.Requests[0].Trigger
	}
	return r
}

// caseOf rebuilds the case from its sheet and the inventory, as selection does, but for an image that runs nowhere: of
// the playbook of its case file, or else of another playbook that selected it. Where it runs, by the exposure that the
// hub's exposure rules decided, comes from the Assessment's queue, as the hub last queued the case: the workers keep no
// view of exposure. So do the clusters whose workloads the case counts: the workers can't read the remote clusters'
// labels, which the playbook's match selects them by. It returns nil when no sheet holds the case any more.
func (l *Loop) caseOf(ctx context.Context, a *triagev1alpha1.Assessment) (*cases.Case, error) {
	image := a.Spec.Subject.ContainerImage
	if image == nil {
		return nil, nil
	}
	cfg, err := settings.Load(ctx, l.Client)
	if err != nil {
		return nil, err
	}
	var clusters []string
	if a.Status.Queue.RunsIn != nil {
		clusters = a.Status.Queue.RunsIn.Clusters
	}
	for _, playbook := range append([]string{a.Status.Queue.Playbook}, a.Status.Playbooks...) {
		sheet, err := l.Verdicts.Get(ctx, image.Digest, playbook)
		if err != nil || sheet == nil {
			if err != nil {
				return nil, err
			}
			continue
		}
		selected, _, err := cases.SelectIn(ctx, sheet, l.Store, cases.Selection{
			Playbook: playbook, Vulnerabilities: []string{a.Spec.VulnerabilityID}, Overrides: cfg.Urgency.Overrides,
			Clusters: clusters})
		if err != nil {
			return nil, err
		}
		for i := range selected {
			if selected[i].VulnerabilityID == a.Spec.VulnerabilityID && selected[i].ManifestDigest == image.Digest {
				selected[i].Impact.LayRunsIn(a.Status.Queue)
				return &selected[i], nil
			}
		}
	}
	return nil, nil
}

// renew renews the case's lease every Renew until ctx ends, and calls lost once the claim no longer names this
// worker, or the case is gone. A renewal that fails otherwise keeps the claim for the next one, unless the next would
// come no sooner than the end of the last lease that it wrote, leaseEnd at first: as a leader whose renewal deadline
// passed steps down, the worker stops then. Waiting for the next renewal, which may hang for RenewTimeout, would run
// into the sweep's grace, which is there for clocks that differ, after which the sweep may give the case to another
// worker. It returns a channel that is closed when it stops. Its ticker starts before it returns, so that a clock moved
// after the claim renews it.
func (l *Loop) renew(ctx context.Context, name string, leaseEnd time.Time, lost context.CancelFunc) <-chan struct{} {
	stopped := make(chan struct{})
	ticker := l.clock().NewTicker(l.renewEvery())
	go func() {
		defer close(stopped)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C():
			}
			held, end, err := l.extend(ctx, name)
			switch {
			case !held:
				lost()
				return
			case err == nil:
				leaseEnd = end
			case !l.clock().Now().Add(l.renewEvery()).Before(leaseEnd):
				logf.FromContext(ctx).Info("The lease of a case can't be renewed before it ends; its judgement stops",
					"worker", l.Name, "assessment", name)
				lost()
				return
			}
		}
	}()
	return stopped
}

// extend moves the lease's end Lease ahead, within RenewTimeout, and returns the end that it wrote. It reports held
// false once the claim doesn't name this worker, or the case is gone. A conflict reads the case again: only a claim of
// another worker ends the judgement.
func (l *Loop) extend(ctx context.Context, name string) (held bool, end time.Time, err error) {
	renewal, cancel := context.WithTimeout(ctx, cmp.Or(l.RenewTimeout, DefaultRenewTimeout))
	defer cancel()
	held = true
	err = retry.RetryOnConflict(retry.DefaultRetry, func() error {
		var a triagev1alpha1.Assessment
		if err := l.APIReader.Get(renewal, client.ObjectKey{Name: name}, &a); err != nil {
			return err
		}
		if held = a.Status.Claim != nil && a.Status.Claim.Worker == l.Name; !held {
			return nil
		}
		end = l.clock().Now().Add(l.lease()).Truncate(time.Second)
		a.Status.Claim.LeaseEndTime = ptr.To(metav1.NewTime(end))
		return l.Client.Status().Update(renewal, &a)
	})
	switch {
	case apierrors.IsNotFound(err):
		return false, end, nil
	case err != nil && ctx.Err() == nil:
		logf.FromContext(ctx).Error(err, "Could not renew the lease of a case", "worker", l.Name, "assessment", name)
	}
	return held, end, err
}

// release ends this worker's claim on the case, as the judge's result says, while the claim names this worker: a case
// that is done leaves the queue, and so does one that is gone, withdrawn, and one handed back that no investigation
// wants any more. Any other waits again. It writes when ctx ends meanwhile too, within writeTimeout.
func (l *Loop) release(ctx context.Context, name string, result Result, gone bool) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), writeTimeout)
	defer cancel()
	now := l.clock().Now()
	err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		var a triagev1alpha1.Assessment
		if err := l.APIReader.Get(ctx, client.ObjectKey{Name: name}, &a); err != nil {
			return err
		}
		// The judge's outcome cleared the claim, or another worker holds it now.
		if a.Status.Claim == nil || a.Status.Claim.Worker != l.Name {
			return nil
		}
		q := a.Status.Queue
		switch {
		case gone:
			cases.Withdraw(&a, "The case's sheet holds it no more.")
		case result == Done:
			a.Status.Queue, a.Status.Claim = nil, nil
		case len(q.Requests) == 0:
			cases.Withdraw(&a, "No investigation wants the case judged any more.")
		default:
			wait := l.retryDelay()
			if result == Retry || result == Failed {
				wait = cases.Miss(q, result == Failed, wait)
			}
			cases.Requeue(&a, now.Add(wait).Truncate(time.Second))
		}
		return l.Client.Status().Update(ctx, &a)
	})
	if client.IgnoreNotFound(err) != nil {
		logf.FromContext(ctx).Error(err, "Could not end the claim of a case; its lease runs out", "worker", l.Name,
			"assessment", name)
	}
}

func (l *Loop) clock() clock.WithTicker {
	if l.Clock == nil {
		return clock.RealClock{}
	}
	return l.Clock
}

func (l *Loop) lease() time.Duration      { return cmp.Or(l.Lease, DefaultLease) }
func (l *Loop) renewEvery() time.Duration { return cmp.Or(l.Renew, DefaultRenew) }
func (l *Loop) retryDelay() time.Duration { return cmp.Or(l.RetryDelay, cases.DefaultRetryDelay) }

// timeOf returns the time, and the zero time for none.
func timeOf(t *metav1.Time) time.Time {
	if t == nil {
		return time.Time{}
	}
	return t.Time
}

type claimantKey struct{}

// WithClaimant returns ctx with the name of the worker that judges a case under it.
func WithClaimant(ctx context.Context, name string) context.Context {
	return context.WithValue(ctx, claimantKey{}, name)
}

// Claimant returns the name of the worker that judges the case of ctx, and "" outside a worker.
func Claimant(ctx context.Context) string {
	name, _ := ctx.Value(claimantKey{}).(string)
	return name
}

// Name returns the name of this worker in its claims: POD_NAME, which the downward API sets to the pod's name, or else
// the host's name, which is a pod's name too.
func Name() (string, error) {
	if name := os.Getenv("POD_NAME"); name != "" {
		return name, nil
	}
	name, err := os.Hostname()
	if err != nil {
		return "", fmt.Errorf("name the agent's worker: %w", err)
	}
	return name, nil
}
