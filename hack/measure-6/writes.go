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

package main

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	dto "github.com/prometheus/client_model/go"
)

// writeSample is the count of the API server's writes to etcd of the inventory group's objects, by resource, at a
// moment: its creates, updates and deletes, which a record that didn't change doesn't make. byVerb counts the requests
// that wrote, by resource and verb (inventoryRequests).
type writeSample struct {
	at                 time.Time
	byResource, byVerb map[string]float64
}

func (s writeSample) total() float64 {
	total := 0.0
	for _, n := range s.byResource {
		total += n
	}
	return total
}

// sampleWrites samples the hub's writes every writePoll until ctx ends. A sample that fails is left out, and its error
// kept, so that a wait for the samples can tell why none came.
func (m *measurement) sampleWrites(ctx context.Context) {
	for {
		families, err := apiServerMetrics(ctx, m.hub)
		m.writesMu.Lock()
		if err == nil {
			m.writes = append(m.writes, writeSample{at: time.Now(), byResource: inventoryWrites(families),
				byVerb: inventoryRequests(families)})
		}
		m.writesErr = err
		m.writesMu.Unlock()
		select {
		case <-ctx.Done():
			return
		case <-time.After(writePoll):
		}
	}
}

// mark returns the index of the latest sample of writes. It waits firstSampleWait at most for the first, and stops when
// ctx ends.
func (m *measurement) mark(ctx context.Context) (int, error) {
	deadline := time.Now().Add(firstSampleWait)
	for {
		m.writesMu.Lock()
		n, lastErr := len(m.writes), m.writesErr
		m.writesMu.Unlock()
		switch {
		case n > 0:
			return n - 1, nil
		case time.Now().After(deadline) && lastErr != nil:
			return 0, fmt.Errorf("no sample of the hub's writes within %s: %w", firstSampleWait, lastErr)
		case time.Now().After(deadline):
			return 0, fmt.Errorf("no sample of the hub's writes within %s", firstSampleWait)
		}
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		case <-time.After(time.Second):
		}
	}
}

// samplesBetween returns a copy of the samples from begin to end, both included.
func (m *measurement) samplesBetween(begin, end int) []writeSample {
	m.writesMu.Lock()
	defer m.writesMu.Unlock()
	return slices.Clone(m.writes[begin : end+1])
}

// inventoryWrites sums etcd_requests_total of the inventory group by resource, over the operations that write.
func inventoryWrites(families map[string]*dto.MetricFamily) map[string]float64 {
	out := map[string]float64{}
	for _, metric := range families["etcd_requests_total"].GetMetric() {
		labels := labelsOf(metric)
		switch labels["operation"] {
		case "create", "update", "delete":
			if labels["group"] == inventoryGroup {
				out[labels["resource"]] += metric.GetCounter().GetValue()
			}
		}
	}
	return out
}

// writeVerbs name the verbs of the API server's requests that write, as Kubernetes names them in RBAC.
var writeVerbs = map[string]string{"POST": "create", "PUT": "update", "PATCH": "patch", "APPLY": "apply",
	"DELETE": "delete"}

// inventoryRequests sums apiserver_request_total of the requests that wrote to the inventory group and succeeded, by
// resource, its subresource and the verb. A create and a delete show a record that came and went, which an update of
// it doesn't. An update that changes nothing counts too, though it writes nothing to etcd.
func inventoryRequests(families map[string]*dto.MetricFamily) map[string]float64 {
	out := map[string]float64{}
	for _, metric := range families["apiserver_request_total"].GetMetric() {
		labels := labelsOf(metric)
		verb, writes := writeVerbs[labels["verb"]]
		if !writes || labels["group"] != inventoryGroup || !strings.HasPrefix(labels["code"], "2") {
			continue
		}
		resource := labels["resource"]
		if labels["subresource"] != "" {
			resource += "/" + labels["subresource"]
		}
		out[resource+" "+verb] += metric.GetCounter().GetValue()
	}
	return out
}

// waitQuiet waits until the hub has written at most quietWrites to the inventory group in the last quietFor of the
// phase whose first sample of writes is from: a write now and then, which the hub may make on a timer, doesn't keep a
// phase from ending, and a phase lasts quietFor at least.
func (m *measurement) waitQuiet(ctx context.Context, from int) error {
	err := m.waitFor(ctx, "the hub's writes to stand still for "+quietFor.String(), func(context.Context) (bool, error) {
		m.writesMu.Lock()
		defer m.writesMu.Unlock()
		last := m.writes[len(m.writes)-1]
		for _, earlier := range slices.Backward(m.writes[from:]) {
			if last.at.Sub(earlier.at) >= quietFor {
				return last.total()-earlier.total() <= quietWrites, nil
			}
		}
		return false, nil
	})
	m.writesMu.Lock()
	defer m.writesMu.Unlock()
	if err != nil && m.writesErr != nil {
		return fmt.Errorf("%w; the last sample of the writes failed: %w", err, m.writesErr)
	}
	return err
}

// rates are the writes of a phase's samples: their count, how long the phase took and the mean rate over that time, and
// the highest rates over a window of 10 seconds and of a minute. requests are the requests that wrote, by resource and
// verb, from the first sample to the last.
type rates struct {
	writes                    float64
	duration                  time.Duration
	mean, peak10s, peakMinute float64
	byResource, requests      map[string]float64
}

// ratesOf measures the samples of a phase, which are in the order of their times. A phase that ends once the writes
// stand still, settled, took until its last sample whose count changed: the quiet minute after it is the tool's wait,
// not the phase. Without any write it took the whole wait. The highest rates take every sample.
func ratesOf(samples []writeSample, settled bool) rates {
	first, last := samples[0], samples[len(samples)-1]
	if settled {
		last = samples[lastChange(samples)]
	}
	r := rates{writes: last.total() - first.total(), duration: last.at.Sub(first.at), byResource: map[string]float64{}}
	for resource, n := range last.byResource {
		r.byResource[resource] = n - first.byResource[resource]
	}
	if r.duration > 0 {
		r.mean = r.writes / r.duration.Seconds()
	}
	r.peak10s, r.peakMinute = peakRate(samples, 10*time.Second), peakRate(samples, time.Minute)
	r.requests = map[string]float64{}
	for request, n := range samples[len(samples)-1].byVerb {
		if made := n - first.byVerb[request]; made > 0 {
			r.requests[request] = made
		}
	}
	return r
}

// lastChange returns the index of the last sample whose count differs from the one before it, or of the last sample
// when no count changed.
func lastChange(samples []writeSample) int {
	for i := len(samples) - 1; i > 0; i-- {
		if samples[i].total() != samples[i-1].total() {
			return i
		}
	}
	return len(samples) - 1
}

// peakRate returns the highest rate of writes over any stretch between two samples that is at least window long.
func peakRate(samples []writeSample, window time.Duration) float64 {
	peak := 0.0
	for i := range samples {
		for j := i + 1; j < len(samples); j++ {
			if took := samples[j].at.Sub(samples[i].at); took >= window {
				peak = max(peak, (samples[j].total()-samples[i].total())/took.Seconds())
			}
		}
	}
	return peak
}

// reportWrites prints the writes of a phase, from the sample begin to the sample end, against 0004's trigger, and the
// raw samples. settled says that the phase ended once the writes stood still (ratesOf).
func (m *measurement) reportWrites(phase string, begin, end int, settled bool) {
	samples := m.samplesBetween(begin, end)
	r := ratesOf(samples, settled)
	took := "in"
	if settled {
		took = "up to the last, in"
	}
	m.say("writes to etcd of the inventory group, %s: %.0f %s %s, %.2f/s on average, at most %.2f/s over 10 s and "+
		"%.2f/s over a minute (0004's trigger: %.0f/s sustained)\n", phase, r.writes, took,
		r.duration.Round(time.Second), r.mean, r.peak10s, r.peakMinute, triggerWriteRate)
	for _, resource := range slices.Sorted(maps.Keys(r.byResource)) {
		m.say("  %s: %.0f\n", resource, r.byResource[resource])
	}
	m.say("  the requests that wrote, by resource and verb:\n")
	for _, request := range slices.Sorted(maps.Keys(r.requests)) {
		m.say("    %s: %.0f\n", request, r.requests[request])
	}
	for _, s := range samples {
		m.say("raw writes %s %s %.0f\n", phase, s.at.Format(time.RFC3339), s.total())
	}
	if pod, u := m.manager(); u != nil {
		m.say("the manager's memory at the end of the phase: %.1f MiB, at most %.1f MiB since %s started\n",
			mebibytes(u.currentBytes), mebibytes(u.peakBytes), pod)
	}
}
