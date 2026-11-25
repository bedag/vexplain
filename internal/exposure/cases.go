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

package exposure

import (
	"context"
	"fmt"
	"slices"
	"time"

	"github.com/bedag/vexplain/internal/agent/cases"
	"github.com/bedag/vexplain/internal/rules/engine"
	"github.com/bedag/vexplain/sdk/subject"
)

// clockSkew is how far ahead of the hub's clock the time of a record may lie and the record still count: a source whose
// clock runs ahead would otherwise keep its answers within their maxAge for longer than it.
const clockSkew = time.Minute

// PlaybookExposure is what the cases read of a playbook to decide the exposure of workloads (design of entry points,
// section 5.6), as the hub's check of the playbook finds it.
type PlaybookExposure struct {
	// Steps are the playbook's exposure rules: each compiled, or a step that can't be evaluated, which counts as
	// Unknown.
	Steps []*engine.Compiled
	// Types holds the type of each piece of the playbook's evidence, by its name.
	Types map[string]string
	// Sources holds the names of the evidence whose type a source produces, whose input about a workload is a map
	// from each of the workload's entry points to the source's answer about it. Optional holds the names of the
	// evidence that the playbook takes as optional.
	Sources, Optional map[string]bool
	// Producers holds the names of the Collectors whose evidence the rules read, by the name of each piece and then by
	// the cluster whose workloads they produce it for (design of remote spokes 5.7), as for the finding rules: those
	// that the playbook pins, or else every Collector that produces its type, each only while the capabilities that it
	// recorded declare the type, with the scope Hub unless it is a source of the type. A source answers about entry
	// points, whatever cluster runs the workload, so it counts for every cluster, under "".
	Producers map[string]map[string][]string
	// MaxAges holds how long the evidence of each producer counts, by the cluster under which Producers names it, its
	// name and the type: as its Collector says, or for a remote cluster as the cluster's Spoke mirrors it. Evidence of a
	// producer without one counts with no limit.
	MaxAges map[[3]string]time.Duration
	// Absent holds, by the name of each piece, the clusters in which a Collector that the playbook pins doesn't count as
	// a producer: its input is missing there, as the finding rules get the evidence of an absent producer.
	Absent map[string]map[string]bool
}

// Playbooks returns what the cases read of the playbook of the name.
type Playbooks func(ctx context.Context, name string) (PlaybookExposure, error)

// caseExposures decides the exposure of the workloads that run the manifests of cases, from the view. It reads each
// playbook once, so it serves one pass of the cases, and isn't safe for concurrent use.
type caseExposures struct {
	view      *View
	playbooks Playbooks
	record    func(manifest, playbook string, notEvaluated map[string]int)
	read      map[string]PlaybookExposure
}

// NewCaseExposures returns the Exposures of one pass of the cases: each workload's exposure comes from the playbook's
// exposure rules over the view. record gets, for the workloads of each manifest, how many each rule couldn't be
// evaluated for, as EvaluateExposure counts them.
func NewCaseExposures(view *View, playbooks Playbooks,
	record func(manifest, playbook string, notEvaluated map[string]int)) cases.Exposures {
	return &caseExposures{view: view, playbooks: playbooks, record: record, read: map[string]PlaybookExposure{}}
}

// Of decides the exposure of the workloads that presence names in each place, with the playbook's exposure rules, all in
// one evaluation, each workload once, and records what the rules couldn't be evaluated for. A place whose presence the
// view doesn't hold has no entry.
func (c *caseExposures) Of(ctx context.Context, playbook, manifest string, places []cases.Place) (
	map[cases.Place][]cases.WorkloadExposure, error) {
	pe, ok := c.read[playbook]
	if !ok {
		var err error
		if pe, err = c.playbooks(ctx, playbook); err != nil {
			return nil, fmt.Errorf("read the exposure rules of the playbook %q: %w", playbook, err)
		}
		c.read[playbook] = pe
	}
	named := map[cases.Place][]string{}
	var workloads []string
	for _, p := range places {
		if subjects, known := c.view.Workloads(p.Digest, p.Cluster); known {
			named[p] = subjects
			workloads = append(workloads, subjects...)
		}
	}
	slices.Sort(workloads)
	workloads = slices.Compact(workloads)
	now := time.Now()
	inputs := make([]map[string][]engine.Input, len(workloads))
	for i, w := range workloads {
		inputs[i] = c.inputsOf(pe, w, now)
	}
	result := engine.EvaluateExposure(pe.Steps, inputs)
	c.record(manifest, playbook, result.NotEvaluated)
	decided := make(map[string]engine.WorkloadExposure, len(workloads))
	for i, w := range workloads {
		decided[w] = result.Workloads[i]
	}
	found := make(map[cases.Place][]cases.WorkloadExposure, len(named))
	for p, subjects := range named {
		list := make([]cases.WorkloadExposure, 0, len(subjects))
		for _, w := range subjects {
			list = append(list, cases.WorkloadExposure{Subject: w, WorkloadExposure: decided[w]})
		}
		found[p] = list
	}
	return found, nil
}

// inputsOf returns what the exposure rules read about a workload: for each piece of the playbook's evidence, an input
// from each of its producers in the workload's cluster and from each source, which is missing where the view holds no
// record of the producer within its maxAge. A piece without such producers, or with an absent one in the workload's
// cluster, has one more input, which is missing.
func (c *caseExposures) inputsOf(pe PlaybookExposure, workload string, now time.Time) map[string][]engine.Input {
	// The view names only workloads whose subject parses, with the cluster of the stream that named them, which a
	// workload's subject never leaves empty.
	parsed, _ := subject.Parse(workload)
	cluster := parsed.Workload.Cluster
	inputs := map[string][]engine.Input{}
	for name, eventType := range pe.Types {
		optional, producers := pe.Optional[name], pe.Producers[name]
		if len(producers[""])+len(producers[cluster]) == 0 || pe.Absent[name][cluster] {
			inputs[name] = []engine.Input{{Optional: optional}}
		}
		for _, in := range []string{"", cluster} {
			for _, producer := range producers[in] {
				maxAge := pe.MaxAges[[3]string{in, producer, eventType}]
				input := engine.Input{Optional: optional}
				if pe.Sources[name] {
					input = c.answers(workload, eventType, producer, maxAge, now, optional)
				} else if r, ok := c.view.recordOf(eventType, workload, producer, cluster); ok && fresh(r.Time, now, maxAge) {
					input = inputOf(r, optional)
				}
				inputs[name] = append(inputs[name], input)
			}
		}
	}
	return inputs
}

// answers returns the input of a source's answers about a workload: a map from each entry point that the workload's
// exposure names to the producer's answer about it, without the answers that are missing or past their maxAge. It is
// present when every entry point has its answer, also when there is none, and missing while the view holds no exposure
// of the workload, whose entry points are unknown then. An address that two clusters name has no answer, which counts
// as missing: the answer can't be tied to one cluster's network.
func (c *caseExposures) answers(workload, eventType, producer string, maxAge time.Duration, now time.Time,
	optional bool) engine.Input {
	points, known := c.view.entryPointsOf(workload)
	if !known {
		return engine.Input{Optional: optional}
	}
	in := engine.Input{Present: true, Optional: optional, Subjects: make(map[string]engine.Input, len(points))}
	ambiguous := c.view.Ambiguous()
	for _, point := range points {
		r, ok := c.view.recordOf(eventType, point, producer, "")
		if _, shared := ambiguous[point]; shared || !ok || !fresh(r.Time, now, maxAge) {
			in.Present = false
			continue
		}
		in.Subjects[point] = inputOf(r, optional)
	}
	return in
}

// fresh reports whether a record of the time counts for the rules now: not past its maxAge, where its type has one, nor
// more than clockSkew ahead of now.
func fresh(at, now time.Time, maxAge time.Duration) bool {
	return !at.After(now.Add(clockSkew)) && (maxAge == 0 || now.Sub(at) <= maxAge)
}

// inputOf returns a record as a rule reads it: its data, its coverage, its time, and its event's source, as a finding
// rule reads the source of evidence about a manifest.
func inputOf(r Record, optional bool) engine.Input {
	return engine.Input{Present: true, Optional: optional, Data: r.Data, Coverage: r.Coverage, Time: r.Time,
		Source: r.EventSource}
}
