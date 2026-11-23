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
	"context"
	"slices"
	"time"

	"k8s.io/apimachinery/pkg/api/equality"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/util/retry"
	"k8s.io/utils/clock"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	triagev1alpha1 "github.com/bedag/vexplain/api/triage/v1alpha1"
	"github.com/bedag/vexplain/internal/agent/cases"
	"github.com/bedag/vexplain/internal/conditions"
)

const (
	// sweepInterval is how often the sweep looks at the queue.
	sweepInterval = 30 * time.Second
	// sweepDelay is how long the first sweep waits after the start, so that the investigations' reconciles at the start
	// have queued again the cases that an earlier version held without a queue: withdrawn first, such a case would be
	// charged again.
	sweepDelay = 90 * time.Second
	// leaseGrace is how long past its end a worker's lease is left to it, for clocks that differ, before the sweep
	// takes the worker for gone.
	leaseGrace = 30 * time.Second
	// notWanted is the message of a case that left the queue because no investigation wants it any more.
	notWanted = "No investigation wants the case judged any more."
)

// APIQueue is the agent's queue in the API (decision 0057): the Assessments whose status holds a queue. The
// investigations queue cases through it, as cases.Queue says, the workers claim them, and its sweep returns the cases
// of workers that are gone. It judges a case that two investigations want once, and charges it to the first.
type APIQueue struct {
	// Client reads the Assessments and the Investigations from the manager's cache, and writes the Assessments'
	// status. APIReader reads an Assessment past the cache before each write, which carries its resourceVersion.
	Client    client.Client
	APIReader client.Reader
	// Clock tells the time of the queue and of the leases. Nil means the real clock.
	Clock clock.Clock
	// RetryDelay is the first wait of a case whose worker's lease ran out. Zero means cases.DefaultRetryDelay.
	RetryDelay time.Duration
}

var _ cases.Queue = (*APIQueue)(nil)

// writeTimeout bounds the reads and writes of the queue that an investigation's reconcile asks for.
const writeTimeout = 30 * time.Second

// The queue reads the Assessments and the Investigations, and writes the Assessments' status.
// +kubebuilder:rbac:groups=triage.vexplain.bedag.ch,resources=assessments;investigations,verbs=get;list;watch
// +kubebuilder:rbac:groups=triage.vexplain.bedag.ch,resources=assessments/status,verbs=update

// Add writes the request into the case's Assessment, and reports whether it queued the case: one that isn't queued
// yet starts to wait, Queued, charged to the request's investigation in its queue, which the outcome takes. Either way,
// the case takes the later JudgedAfter, and its place in the tiers and where it runs as they are now, when it is new to
// the queue or the request's investigation is of the queue's playbook.
func (q *APIQueue) Add(c cases.Case, r cases.Request) bool {
	ctx, cancel := context.WithTimeout(context.Background(), writeTimeout)
	defer cancel()
	name := cases.Name(c.VulnerabilityID, c.ManifestDigest)
	// A status holds its times to the second.
	now := metav1.NewTime(q.now().Truncate(time.Second))
	ref := triagev1alpha1.InvestigationReference{Namespace: r.Investigation.Namespace, Name: r.Investigation.Name,
		UID: r.InvestigationUID}
	added := false
	err := q.update(ctx, name, func(a *triagev1alpha1.Assessment) {
		s := &a.Status
		added = s.Queue == nil
		// Where the case runs is the queue's playbook's: another playbook's investigation, which decides it with its own
		// exposure rules, would write the case in turn with it at each of its reconciles.
		decides := added || r.InvestigationPlaybook == s.Queue.Playbook
		if added {
			s.Queue = &triagev1alpha1.AssessmentQueue{Playbook: r.Playbook, QueuedTime: &now, InvestigationRef: ptr.To(ref)}
			cases.SetWaiting(a, triagev1alpha1.ReasonQueued, "The case waits for the agent.", conditions.Reconciling)
		}
		// An earlier object of the same namespace and name charged a case that waits unclaimed: that object is gone and
		// its judgement never began, so the current object takes the charge over, and the case gets its guidance. A
		// judgement under way stays charged to the object that it began for.
		if c := s.Queue.InvestigationRef; !added && s.Claim == nil && c != nil && c.Namespace == ref.Namespace &&
			c.Name == ref.Name && c.UID != ref.UID {
			s.Queue.InvestigationRef, added = ptr.To(ref), true
		}
		// A request of an earlier object of the same namespace and name gives way: a case has one request for each.
		request := triagev1alpha1.QueueRequest{InvestigationRef: ref, Trigger: r.Trigger}
		if i := slices.IndexFunc(s.Queue.Requests, requestOf(r.Investigation)); i >= 0 {
			s.Queue.Requests[i] = request
		} else {
			s.Queue.Requests = append(s.Queue.Requests, request)
		}
		if decides {
			s.Queue.Order, s.Queue.RunsIn = cases.OrderOf(c), cases.RunsInOf(c)
		}
		if after := r.JudgedAfter.Truncate(time.Second); !r.JudgedAfter.IsZero() &&
			(s.Queue.JudgedAfter == nil || after.After(s.Queue.JudgedAfter.Time)) {
			s.Queue.JudgedAfter = &metav1.Time{Time: after}
		}
	})
	if err != nil {
		logf.Log.Error(err, "Could not queue the case for the agent", "assessment", name)
		return false
	}
	return added
}

// Keep removes the investigation's requests from the queued cases that it doesn't name, and withdraws a waiting case
// that no request is left on. A case in progress finishes.
func (q *APIQueue) Keep(investigation types.NamespacedName, names []string) {
	ctx, cancel := context.WithTimeout(context.Background(), writeTimeout)
	defer cancel()
	queued, err := q.queued(ctx)
	if err != nil {
		logf.Log.Error(err, "Could not list the agent's queue")
		return
	}
	for i := range queued {
		a := &queued[i]
		if slices.Contains(names, a.Name) || !slices.ContainsFunc(a.Status.Queue.Requests, requestOf(investigation)) {
			continue
		}
		err := q.update(ctx, a.Name, func(obj *triagev1alpha1.Assessment) { drop(obj, requestOf(investigation)) })
		if client.IgnoreNotFound(err) != nil {
			logf.Log.Error(err, "Could not take an investigation's request off a case", "assessment", a.Name)
		}
	}
}

// Pending returns how many of the cases of the investigation of the uid wait in the queue, and how many a worker judges
// now, from the cache. The requests of an earlier object of its name aren't its own.
func (q *APIQueue) Pending(investigation types.NamespacedName, uid types.UID) (queued, inProgress int) {
	ctx, cancel := context.WithTimeout(context.Background(), writeTimeout)
	defer cancel()
	list, err := q.queued(ctx)
	if err != nil {
		logf.Log.Error(err, "Could not list the agent's queue")
		return 0, 0
	}
	for i := range list {
		switch a := &list[i]; {
		case !slices.ContainsFunc(a.Status.Queue.Requests, func(r triagev1alpha1.QueueRequest) bool {
			return requestOf(investigation)(r) && r.InvestigationRef.UID == uid
		}):
		case a.Status.Claim != nil:
			inProgress++
		default:
			queued++
		}
	}
	return queued, inProgress
}

// Sweeps runs Sweep sweepDelay after it starts, and then every sweepInterval, until ctx is done. It is a manager's
// runnable, on the leader.
func (q *APIQueue) Sweeps(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return nil
	case <-q.clock().After(sweepDelay):
	}
	wait.UntilWithContext(ctx, q.Sweep, sweepInterval)
	return nil
}

// Sweep looks at the Assessments in the cache, and writes past it:
//   - a case whose worker's lease ended more than leaseGrace ago waits again, and counts a failure, since the worker
//     may have spent tokens on it;
//   - the requests of investigations that are gone are removed, and a waiting case that no request is left on is
//     withdrawn;
//   - a case held without a queue, as an install before the queue in the API left it, is withdrawn.
func (q *APIQueue) Sweep(ctx context.Context) {
	log := logf.FromContext(ctx)
	var list triagev1alpha1.AssessmentList
	// The objects are only read, so a cache needn't copy them.
	if err := q.Client.List(ctx, &list, client.UnsafeDisableDeepCopy); err != nil {
		log.Error(err, "Could not list the Assessments to sweep the agent's queue")
		return
	}
	now := q.now()
	for i := range list.Items {
		a := &list.Items[i]
		var change func(*triagev1alpha1.Assessment)
		switch {
		case a.Status.Queue == nil && isHeld(a):
			change = func(obj *triagev1alpha1.Assessment) {
				if obj.Status.Queue == nil && isHeld(obj) {
					cases.Withdraw(obj, notWanted)
				}
			}
		case a.Status.Queue != nil:
			gone := q.gone(ctx, a.Status.Queue.Requests)
			if len(gone) == 0 && !lapsed(a, now) {
				continue
			}
			change = func(obj *triagev1alpha1.Assessment) {
				if lapsed(obj, now) {
					cases.Requeue(obj, now.Add(cases.Miss(obj.Status.Queue, true, q.retryDelay())).Truncate(time.Second))
				}
				drop(obj, func(r triagev1alpha1.QueueRequest) bool { return gone[r.InvestigationRef] })
			}
		default:
			continue
		}
		if err := q.update(ctx, a.Name, change); client.IgnoreNotFound(err) != nil {
			log.Error(err, "Could not sweep a case of the agent's queue", "assessment", a.Name)
		}
	}
}

// gone returns the investigations of the requests that the cache doesn't hold: none of that name, or one of another
// uid.
func (q *APIQueue) gone(ctx context.Context, requests []triagev1alpha1.QueueRequest) map[triagev1alpha1.InvestigationReference]bool {
	gone := map[triagev1alpha1.InvestigationReference]bool{}
	for _, r := range requests {
		ref := r.InvestigationRef
		var inv triagev1alpha1.Investigation
		err := q.Client.Get(ctx, types.NamespacedName{Namespace: ref.Namespace, Name: ref.Name}, &inv)
		if client.IgnoreNotFound(err) == nil && (err != nil || inv.UID != ref.UID) {
			gone[ref] = true
		}
	}
	return gone
}

// lapsed reports whether the case's claim is of a worker whose lease ended more than leaseGrace before now.
func lapsed(a *triagev1alpha1.Assessment, now time.Time) bool {
	c := a.Status.Claim
	return c != nil && c.LeaseEndTime != nil && now.After(c.LeaseEndTime.Add(leaseGrace))
}

// drop takes the requests that match off the case, and withdraws a waiting case that no request is left on.
func drop(a *triagev1alpha1.Assessment, match func(triagev1alpha1.QueueRequest) bool) {
	if a.Status.Queue == nil {
		return
	}
	a.Status.Queue.Requests = slices.DeleteFunc(a.Status.Queue.Requests, match)
	if len(a.Status.Queue.Requests) == 0 && a.Status.Claim == nil {
		cases.Withdraw(a, notWanted)
	}
}

// requestOf returns whether a request is the investigation's.
func requestOf(investigation types.NamespacedName) func(triagev1alpha1.QueueRequest) bool {
	return func(r triagev1alpha1.QueueRequest) bool {
		return r.InvestigationRef.Namespace == investigation.Namespace && r.InvestigationRef.Name == investigation.Name
	}
}

// queued returns the Assessments whose status holds a queue, from the cache, which they are only read from.
func (q *APIQueue) queued(ctx context.Context) ([]triagev1alpha1.Assessment, error) {
	var list triagev1alpha1.AssessmentList
	if err := q.Client.List(ctx, &list, client.UnsafeDisableDeepCopy); err != nil {
		return nil, err
	}
	return slices.DeleteFunc(list.Items, func(a triagev1alpha1.Assessment) bool { return a.Status.Queue == nil }), nil
}

// update changes the status of the Assessment of the name, read past the cache, and writes it when it changed, with
// the version that it read: a conflict reads it again, and changes it again.
func (q *APIQueue) update(ctx context.Context, name string, change func(*triagev1alpha1.Assessment)) error {
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		var a triagev1alpha1.Assessment
		if err := q.APIReader.Get(ctx, client.ObjectKey{Name: name}, &a); err != nil {
			return err
		}
		before := a.Status.DeepCopy()
		change(&a)
		if equality.Semantic.DeepEqual(*before, a.Status) {
			return nil
		}
		return q.Client.Status().Update(ctx, &a)
	})
}

func (q *APIQueue) clock() clock.Clock {
	if q.Clock == nil {
		return clock.RealClock{}
	}
	return q.Clock
}

func (q *APIQueue) now() time.Time { return q.clock().Now() }

func (q *APIQueue) retryDelay() time.Duration {
	if q.RetryDelay == 0 {
		return cases.DefaultRetryDelay
	}
	return q.RetryDelay
}
