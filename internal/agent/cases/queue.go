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

package cases

import (
	"slices"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
	triagev1alpha1 "github.com/bedag/vexplain/api/triage/v1alpha1"
	"github.com/bedag/vexplain/internal/conditions"
)

// What the agent's queue in the Assessments' status holds is written by the hub, which queues and sweeps, and by the
// workers, which claim and hand back: both write it with these.

const (
	// DefaultRetryDelay is how long a case that was handed back waits before it is tried again.
	DefaultRetryDelay = 10 * time.Second
	// MaxBackoff is the longest that a case whose judgement failed waits.
	MaxBackoff = 10 * time.Minute
)

// OrderOf returns the place of the case in the queue's tiers, as its Assessment holds it.
func OrderOf(c Case) triagev1alpha1.QueueOrder {
	t := TiersOf(c)
	o := triagev1alpha1.QueueOrder{UrgencyRank: ptr.To(t.UrgencyRank), KnownExploited: triagev1alpha1.KnownExploitedNotListed,
		Resources: ptr.To(t.Resources)}
	if t.KnownExploited {
		o.KnownExploited = triagev1alpha1.KnownExploitedListed
	}
	if t.EPSSPermille >= 0 {
		o.EPSSPermille = ptr.To(t.EPSSPermille)
	}
	return o
}

// maxClusters is how many clusters an Assessment's queue names: as many as the inventory holds for an image.
const maxClusters = 256

// RunsInOf returns how far the workloads that run the case's subject can be reached, and how urgent the case is there,
// as its Assessment's queue holds it for the workers, which can't decide exposure themselves, nor read which clusters a
// playbook's match selects: so it names the clusters whose workloads the case counts too.
func RunsInOf(c Case) *triagev1alpha1.QueueRunsIn {
	im := c.Impact
	r := &triagev1alpha1.QueueRunsIn{UrgentWorkloads: ptr.To(im.UrgentResources), Clusters: c.Clusters}
	// shortcut: past maxClusters, the queue names no cluster, and a worker counts every cluster's workloads, which errs
	// towards counting more; raise the cap with the inventory's when fleets grow past it.
	if len(c.Clusters) > maxClusters {
		r.Clusters = nil
	}
	if im.HighestExposure != "" {
		r.HighestExposure = ptr.To(triagev1alpha1.SSVCExposure(im.HighestExposure))
	}
	if im.HighestUrgency != "" {
		r.HighestUrgency = ptr.To(triagev1alpha1.SSVCOutcome(im.HighestUrgency))
	}
	for _, g := range im.Exposure {
		r.Exposure = append(r.Exposure, triagev1alpha1.ExposureGroup{Exposure: triagev1alpha1.SSVCExposure(g.Exposure),
			Rules: g.Rules, Missing: g.Missing, Workloads: ptr.To(g.Workloads), First: g.First})
	}
	return r
}

// LayRunsIn lays where an Assessment's queue q says that the case runs over its impact, which a worker rebuilds without
// the exposure rules: the highest exposure and urgency, the urgent workloads, and the workloads by exposure and their
// groups. Without runsIn, the impact stays as it is.
//
// The worker counts the workloads of every cluster that the queue names, the union of the matching clusters of the
// playbooks that select the case, and the queue holds the groups of the most urgent playbook's view alone (design of
// remote spokes 5.8). The workloads past those that the view counts, as the queue's order counts them, are Unknown to
// the worker, and go into the groups as such, so that the case file never under-states where the case runs.
func (im *Impact) LayRunsIn(q *triagev1alpha1.AssessmentQueue) {
	if q == nil || q.RunsIn == nil {
		return
	}
	r := q.RunsIn
	im.HighestExposure = configv1alpha1.SSVCExposure(ptr.Deref(r.HighestExposure, ""))
	im.HighestUrgency = configv1alpha1.SSVCOutcome(ptr.Deref(r.HighestUrgency, ""))
	im.UrgentResources = ptr.Deref(r.UrgentWorkloads, 0)
	// shortcut: the counts by exposure are those of the groups, so past MaxExposureGroups they lack the least exposed
	// groups; put the counts into the queue too if a case file needs them whole.
	im.WorkloadsByExposure, im.Exposure = map[configv1alpha1.SSVCExposure]int32{}, nil
	for _, g := range r.Exposure {
		exposure, n := configv1alpha1.SSVCExposure(g.Exposure), ptr.Deref(g.Workloads, 0)
		im.WorkloadsByExposure[exposure] += n
		im.Exposure = append(im.Exposure, ExposureGroup{Exposure: exposure, Rules: g.Rules, Missing: g.Missing,
			Workloads: n, First: g.First})
	}
	if rest := im.Resources - ptr.Deref(q.Order.Resources, im.Resources); rest > 0 && len(im.Exposure) > 0 {
		im.addUnknown(rest)
	}
}

// addUnknown counts n more workloads as Unknown, in the group of those whose exposure no rule decided, for no reason
// that a rule gives, which comes first of the Unknown groups: a group of its own unless the groups hold one. The highest
// exposure rises to Unknown where it was lower. The urgency stays: it is the most urgent view's, by the queue's tiers.
func (im *Impact) addUnknown(n int32) {
	unknown := configv1alpha1.SSVCExposureUnknown
	im.WorkloadsByExposure[unknown] += n
	if exposureRank(unknown) > exposureRank(im.HighestExposure) {
		im.HighestExposure = unknown
	}
	i := slices.IndexFunc(im.Exposure, func(g ExposureGroup) bool { return exposureRank(g.Exposure) <= exposureRank(unknown) })
	if i < 0 {
		i = len(im.Exposure)
	}
	if i < len(im.Exposure) && im.Exposure[i].Exposure == unknown && len(im.Exposure[i].Rules) == 0 &&
		len(im.Exposure[i].Missing) == 0 {
		im.Exposure[i].Workloads += n
		return
	}
	im.Exposure = slices.Insert(im.Exposure, i, ExposureGroup{Exposure: unknown, Workloads: n})
}

// TiersOfOrder returns the tiers of a case from its place in the queue. A knownExploited that this version doesn't know
// may say that it is, and goes with Listed.
func TiersOfOrder(o triagev1alpha1.QueueOrder) Tiers {
	return Tiers{UrgencyRank: ptr.Deref(o.UrgencyRank, 0), KnownExploited: o.KnownExploited != triagev1alpha1.KnownExploitedNotListed,
		EPSSPermille: ptr.Deref(o.EPSSPermille, -1), Resources: ptr.Deref(o.Resources, 0)}
}

// Miss counts a judgement of the queued case that failed, and a failure too when it may have spent tokens, and returns
// how long the case waits: delay, doubled for each miss in a row after the first, at most MaxBackoff.
func Miss(q *triagev1alpha1.AssessmentQueue, spent bool, delay time.Duration) time.Duration {
	if spent {
		q.Failures = ptr.To(ptr.Deref(q.Failures, 0) + 1)
	}
	q.Misses = ptr.To(ptr.Deref(q.Misses, 0) + 1)
	return min(delay<<min(*q.Misses-1, 16), MaxBackoff)
}

// Requeue hands a claimed case back to the queue, to wait until notBefore: Ready=False, Queued, and no claim.
func Requeue(a *triagev1alpha1.Assessment, notBefore time.Time) {
	a.Status.Claim = nil
	a.Status.Queue.NotBefore = ptr.To(metav1.NewTime(notBefore))
	SetWaiting(a, triagev1alpha1.ReasonQueued, "The case waits for the agent.", conditions.Reconciling)
}

// Withdraw takes the case out of the queue unjudged: Ready=False, Withdrawn, and not Reconciling, so that an
// investigation that selects it later doesn't take it for a case that it holds, and charges it as a new one.
func Withdraw(a *triagev1alpha1.Assessment, message string) {
	a.Status.Queue, a.Status.Claim = nil, nil
	SetWaiting(a, triagev1alpha1.ReasonWithdrawn, message, conditions.None)
}

// SetWaiting sets the Assessment's Ready condition False, for the reason, with the progress that goes with it.
func SetWaiting(a *triagev1alpha1.Assessment, reason, message string, progress conditions.Progress) {
	conditions.SetReady(&a.Status.Conditions, metav1.Condition{Status: metav1.ConditionFalse, Reason: reason,
		Message: message, ObservedGeneration: a.Generation}, progress)
	conditions.Observe(&a.Status.ObservedGeneration, a.Generation)
}
