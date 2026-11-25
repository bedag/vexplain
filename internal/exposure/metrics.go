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
	"time"

	"github.com/bedag/vexplain/internal/metrics"
)

// The states of the gauge of entry points.
const (
	stateAnswered   = "answered"
	stateUnanswered = "unanswered"
	stateUnchecked  = "unchecked"
	stateAmbiguous  = "ambiguous"
)

// measure sets the gauge of entry points: for each cluster whose exposure names any, the entry points that every
// source asked about them answered, within the answer's maxAge, those that a source didn't, or that no source is
// asked about, the addresses that another cluster names too, which get no answer, and the reasons why a way in can't be
// asked about. A cluster whose exposure is gone loses its series.
func (a *Asker) measure(sources []source, points []point) {
	now := a.clock.Now()
	byPoint := make(map[string]point, len(points))
	for _, p := range points {
		byPoint[p.subject] = p
	}
	clusters := map[string]bool{}
	// One read of the view gives both, so that they never disagree.
	byName := a.view.byCluster()
	shared := ambiguousIn(byName)
	for cluster, n := range byName {
		answered, ambiguous := 0, 0
		for _, s := range n.points {
			if _, ok := shared[s]; ok {
				ambiguous++
			} else if p, ok := byPoint[s]; ok && a.isAnswered(sources, p, now) {
				answered++
			}
		}
		metrics.EntryPoints.WithLabelValues(cluster, stateAnswered).Set(float64(answered))
		metrics.EntryPoints.WithLabelValues(cluster, stateUnanswered).Set(float64(len(n.points) - answered - ambiguous))
		metrics.EntryPoints.WithLabelValues(cluster, stateAmbiguous).Set(float64(ambiguous))
		metrics.EntryPoints.WithLabelValues(cluster, stateUnchecked).Set(float64(n.unchecked))
		clusters[cluster] = true
	}
	for cluster := range a.clusters {
		if !clusters[cluster] {
			for _, state := range []string{stateAnswered, stateUnanswered, stateUnchecked, stateAmbiguous} {
				metrics.EntryPoints.DeleteLabelValues(cluster, state)
			}
		}
	}
	a.clusters = clusters
}

// isAnswered reports whether some source is asked about the entry point, and every one has an answer about it within
// the answer's maxAge.
func (a *Asker) isAnswered(sources []source, p point, now time.Time) bool {
	asked := false
	for i := range sources {
		src := &sources[i]
		if !src.takes(p) {
			continue
		}
		asked = true
		at, held := a.view.answered(src.eventType, p.subject, src.collector)
		if !held || (src.maxAge > 0 && now.Sub(at) >= src.maxAge) {
			return false
		}
	}
	return asked
}
