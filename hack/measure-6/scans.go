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
	"cmp"
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// reportScans prints the scan Jobs that the hub made since the load's deployment, from their events, which outlive the
// Jobs, and the scanner's own count and times of its scans. A Job's events can't time a scan: the scanner deletes the
// Job once it has read the result, often before the Job's controller tells of its completion. The sampler times the
// scan pods instead (reportUsage).
func (m *measurement) reportScans(ctx context.Context, deployed time.Time) error {
	events, err := m.hub.clientset.CoreV1().Events(operatorNamespace).List(ctx,
		metav1.ListOptions{FieldSelector: "involvedObject.kind=Job"})
	if err != nil {
		return err
	}
	var created []time.Duration
	others := 0
	for _, event := range events.Items {
		if event.Reason != "SuccessfulCreate" || !strings.HasPrefix(event.InvolvedObject.Name, "scan-") {
			continue
		}
		at := event.FirstTimestamp.Time
		if !event.EventTime.IsZero() {
			at = event.EventTime.Time
		}
		m.say("raw scan %s load=%t %s\n", event.InvolvedObject.Name, m.ofLoad(event.InvolvedObject.Name),
			at.Format(time.RFC3339))
		if !m.ofLoad(event.InvolvedObject.Name) {
			others++
			continue
		}
		created = append(created, at.Sub(deployed).Round(time.Second))
	}
	slices.Sort(created)
	m.say("\nscan Jobs on the hub: %d of the load's images, made after the load's deployment: %s; %d of other images\n",
		len(created), spread(created), others)
	families, err := collectorMetrics(ctx, m.hub, scannerCollector)
	if err != nil {
		return err
	}
	for _, metric := range families["vexplain_scanner_scans_total"].GetMetric() {
		m.say("  the scanner's count: %s %.0f\n", labelsOf(metric)["result"], metric.GetCounter().GetValue())
	}
	for _, metric := range families["vexplain_scanner_scan_duration_seconds"].GetMetric() {
		h := metric.GetHistogram()
		if h.GetSampleCount() == 0 {
			continue
		}
		m.say("  the scanner's time in a slot, %s: %d scans, %.1f s on average;", labelsOf(metric)["result"],
			h.GetSampleCount(), h.GetSampleSum()/float64(h.GetSampleCount()))
		for _, bucket := range h.GetBucket() {
			m.say(" %d within %.0f s,", bucket.GetCumulativeCount(), bucket.GetUpperBound())
		}
		m.say("\n")
	}
	return nil
}

// spread formats sorted durations as their least, median and most.
func spread[T cmp.Ordered](values []T) string {
	if len(values) == 0 {
		return "none"
	}
	return fmt.Sprintf("least %v, median %v, most %v", values[0], values[len(values)/2], values[len(values)-1])
}
