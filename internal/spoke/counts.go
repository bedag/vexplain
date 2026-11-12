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

package spoke

import (
	"context"
	"fmt"
	"time"

	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	triagev1alpha1 "github.com/bedag/vexplain/api/triage/v1alpha1"
	"github.com/bedag/vexplain/internal/inventory"
)

// countsName is the name of the request that has the playbooks' counts written.
const countsName = "counts"

// countsDelay is how long the renderer waits after a report changed before it writes the counts: a start renders every
// report, and the counts are written once for them all, and not for each.
const countsDelay = 500 * time.Millisecond

// playbookCountsOf counts what one report holds for each playbook (design 5.6): the report is judged by a playbook
// when it holds the results of one of its sheets, and fails it when an action names the playbook as its requirement.
// The actions are those before the report's limits cut them, so that the counts miss none. Negligible counts as Low.
func playbookCountsOf(used []usedSheet, actions []triagev1alpha1.ResourceAction) map[string]inventory.Tally {
	out := map[string]inventory.Tally{}
	for _, u := range used {
		c := out[u.sheet.Spec.Playbook]
		c.Judged = 1
		out[u.sheet.Spec.Playbook] = c
	}
	for _, a := range actions {
		c := out[a.Requirement.Playbook]
		c.Failing = 1
		switch a.Step {
		case triagev1alpha1.ResourceStepUpdate:
			c.Updates++
		case triagev1alpha1.ResourceStepChange:
			c.Changes++
		case triagev1alpha1.ResourceStepMitigate:
			c.Mitigations++
		case triagev1alpha1.ResourceStepInvestigate:
			c.Investigations++
		}
		switch a.Severity {
		case triagev1alpha1.SeverityCritical:
			c.Critical++
		case triagev1alpha1.SeverityHigh:
			c.High++
		case triagev1alpha1.SeverityMedium:
			c.Medium++
		case triagev1alpha1.SeverityLow, triagev1alpha1.SeverityNegligible:
			c.Low++
		default:
			c.Unknown++
		}
		out[a.Requirement.Playbook] = c
	}
	return out
}

// playbookTotals sums the counts of every report that the collector holds, by playbook.
func (c *ReportsCollector) playbookTotals() map[string]inventory.Tally {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := map[string]inventory.Tally{}
	for _, e := range c.entries {
		for playbook, counts := range e.playbooks {
			out[playbook] = out[playbook].Plus(counts)
		}
	}
	return out
}

// writtenCounts is what the renderer last wrote for a playbook: its cluster, its Playbook's UID and its counts, or
// none when it deleted them, so that it writes only what differs.
type writtenCounts struct {
	cluster string
	uid     types.UID
	counts  *inventory.Tally
}

// requestCounts has the counts looked at, after a pause that lets the reports of a start settle.
func (r *Reports) requestCounts() {
	r.mu.Lock()
	queue := r.queue
	r.mu.Unlock()
	if queue != nil {
		queue.AddAfter(reconcile.Request{NamespacedName: types.NamespacedName{Name: countsName}}, countsDelay)
	}
}

// rendered notes that the report of the key has been looked at, so that the counts wait for the first sweep to have looked
// at every report.
func (r *Reports) rendered(key types.NamespacedName) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.pending, key)
}

// writeCounts writes, for each Playbook, what its reports in this cluster add up to, to the counts store, and deletes
// the counts of a playbook that no report holds results of. It writes only counts that differ from those that it last
// wrote, and the store writes only counts that differ from those it holds, so a restart writes nothing that stands. It
// writes nothing until the first sweep after a start has looked at every report. The
// counts of a Playbook that is gone go with it, since the Playbook owns them.
func (r *Reports) writeCounts(ctx context.Context, cluster string) error {
	all, err := r.playbooks.List(ctx)
	if err != nil {
		return err
	}
	totals := r.series.playbookTotals()
	r.mu.Lock()
	settled := r.swept && len(r.pending) == 0
	r.mu.Unlock()
	if !settled {
		// After a start the series fill report by report: counts written now would be partial, or, for a playbook that no
		// report has been rendered for yet, a delete of counts that stand. The render that settles the sweep asks again.
		return nil
	}
	r.countsMu.Lock()
	defer r.countsMu.Unlock()
	for _, p := range all {
		total := totals[p.Name]
		var want *inventory.Tally
		if total.Judged > 0 {
			want = &total
		}
		last, known := r.written[p.Name]
		if known && last.cluster == cluster && last.uid == p.UID && (last.counts == want || last.counts != nil && want != nil && *last.counts == *want) {
			continue
		}
		// A renamed cluster takes its counts to the new name, and the ones under the former name would be summed with them.
		// A restart after a rename has no memory of the former name and leaves them: a later phase expires counts that
		// stop updating.
		if known && last.cluster != cluster && last.counts != nil {
			if err := r.counts.Delete(ctx, p.Name, last.cluster); err != nil {
				return fmt.Errorf("delete the counts of playbook %s under the former cluster name: %w", p.Name, err)
			}
		}
		if want == nil {
			err = r.counts.Delete(ctx, p.Name, cluster)
		} else {
			err = r.counts.Put(ctx, p.Name, p.UID, cluster, *want)
		}
		if err != nil {
			return fmt.Errorf("write the counts of playbook %s: %w", p.Name, err)
		}
		r.written[p.Name] = writtenCounts{cluster: cluster, uid: p.UID, counts: want}
	}
	return nil
}
