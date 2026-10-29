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

package llm_test

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/require"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/bedag/vexplain/internal/llm"
	"github.com/bedag/vexplain/internal/metrics"
)

const (
	clusterA = "cluster-a"
	clusterB = "cluster-b"

	kindPrompt     = "prompt"
	kindCompletion = "completion"

	labelCluster = "cluster"
	labelModel   = "model"
)

// The metric vectors are global, so each test uses a model name of its own and compares a series
// before and after what it does.

// counterValue reads the counter of vec for labels.
func counterValue(t *testing.T, vec *prometheus.CounterVec, labels ...string) float64 {
	t.Helper()
	counter, err := vec.GetMetricWithLabelValues(labels...)
	require.NoError(t, err)
	var written dto.Metric
	require.NoError(t, counter.Write(&written))
	return written.GetCounter().GetValue()
}

// histogramValue reads the histogram of vec for labels.
func histogramValue(t *testing.T, vec *prometheus.HistogramVec, labels ...string) *dto.Histogram {
	t.Helper()
	observer, err := vec.GetMetricWithLabelValues(labels...)
	require.NoError(t, err)
	metric, ok := observer.(prometheus.Metric)
	require.True(t, ok)
	var written dto.Metric
	require.NoError(t, metric.Write(&written))
	return written.GetHistogram()
}

// growth returns by how much read grows while do runs.
func growth(read func() float64, do func()) float64 {
	before := read()
	do()
	return read() - before
}

func TestPrometheusObserver(t *testing.T) {
	const model = "observer-model"
	observe := llm.PrometheusObserver(func() string { return clusterA })
	requests := func() float64 { return counterValue(t, metrics.LLMRequestsTotal, clusterA, model, outcomeOK) }
	prompt := func() float64 { return counterValue(t, metrics.LLMTokensTotal, clusterA, model, kindPrompt) }
	generated := func() float64 { return counterValue(t, metrics.LLMTokensTotal, clusterA, model, kindCompletion) }
	durations := func() *dto.Histogram { return histogramValue(t, metrics.LLMRequestDurationSeconds, clusterA, model) }
	requestsBefore, promptBefore, generatedBefore := requests(), prompt(), generated()
	durationsBefore := durations()

	observe(llm.Observation{
		Model:    model,
		Outcome:  outcomeOK,
		Duration: 1500 * time.Millisecond,
		Usage:    llm.Usage{PromptTokens: 10, CompletionTokens: 5},
	})

	require.Equal(t, requestsBefore+1, requests())
	require.Equal(t, promptBefore+10, prompt())
	require.Equal(t, generatedBefore+5, generated())
	require.Equal(t, durationsBefore.GetSampleCount()+1, durations().GetSampleCount())
	require.InDelta(t, durationsBefore.GetSampleSum()+1.5, durations().GetSampleSum(), 1e-9)
}

func TestPrometheusObserverReadsTheClusterAtEachObservation(t *testing.T) {
	const model = "observer-rename"
	name := clusterA
	observe := llm.PrometheusObserver(func() string { return name })
	requestsOf := func(cluster string) func() float64 {
		return func() float64 { return counterValue(t, metrics.LLMRequestsTotal, cluster, model, outcomeOK) }
	}

	require.Equal(t, 1.0, growth(requestsOf(clusterA), func() { observe(llm.Observation{Model: model, Outcome: outcomeOK}) }))
	// The cluster is renamed: the next observation carries the new name.
	name = clusterB
	require.Equal(t, 1.0, growth(requestsOf(clusterB), func() { observe(llm.Observation{Model: model, Outcome: outcomeOK}) }))
}

func TestPrometheusObserverCountsEveryOutcomeAndSkipsEmptyUsage(t *testing.T) {
	const model = "observer-failures"
	observe := llm.PrometheusObserver(func() string { return clusterA })
	tokens := func() float64 {
		return counterValue(t, metrics.LLMTokensTotal, clusterA, model, kindPrompt) +
			counterValue(t, metrics.LLMTokensTotal, clusterA, model, kindCompletion)
	}

	for _, outcome := range []string{outcomeError, outcomeTimeout, outcomeUnauthorized} {
		requests := func() float64 { return counterValue(t, metrics.LLMRequestsTotal, clusterA, model, outcome) }
		before := tokens()

		require.Equal(t, 1.0, growth(requests, func() { observe(llm.Observation{Model: model, Outcome: outcome}) }), outcome)

		require.Equal(t, before, tokens(), outcome)
	}

	// A counter panics when it is given a negative value, so a bad usage must not reach it.
	before := tokens()
	require.NotPanics(t, func() {
		observe(llm.Observation{Model: model, Outcome: outcomeOK, Usage: llm.Usage{PromptTokens: -5, CompletionTokens: -1}})
	})
	require.Equal(t, before, tokens())
}

func TestPrometheusObserverRecordsTheCallsOfAClient(t *testing.T) {
	const model = "observer-client"
	server := serve(t, answer(completion))
	cfg := configFor(server)
	cfg.Model = model
	client := newClient(server, cfg, llm.WithObserver(llm.PrometheusObserver(func() string { return clusterA })))
	requests := func() float64 { return counterValue(t, metrics.LLMRequestsTotal, clusterA, model, outcomeOK) }
	prompt := func() float64 { return counterValue(t, metrics.LLMTokensTotal, clusterA, model, kindPrompt) }
	generated := func() float64 { return counterValue(t, metrics.LLMTokensTotal, clusterA, model, kindCompletion) }
	requestsBefore, promptBefore, generatedBefore := requests(), prompt(), generated()

	_, err := client.Complete(t.Context(), ping())

	require.NoError(t, err)
	require.Equal(t, requestsBefore+1, requests())
	// The server reported 3 prompt and 1 completion tokens.
	require.Equal(t, promptBefore+3, prompt())
	require.Equal(t, generatedBefore+1, generated())
}

func TestLLMMetricsAreRegisteredWithTheirNamesLabelsAndBuckets(t *testing.T) {
	// A vector shows up in the registry once it has a series.
	llm.PrometheusObserver(func() string { return clusterA })(llm.Observation{
		Model:    "observer-registry",
		Outcome:  outcomeOK,
		Duration: time.Second,
		Usage:    llm.Usage{PromptTokens: 1, CompletionTokens: 1},
	})

	families, err := ctrlmetrics.Registry.Gather()
	require.NoError(t, err)
	byName := make(map[string]*dto.MetricFamily, len(families))
	for _, family := range families {
		byName[family.GetName()] = family
	}
	labelsOf := func(name string, wantType dto.MetricType) []string {
		family := byName[name]
		require.NotNil(t, family, name)
		require.Equal(t, wantType, family.GetType(), name)
		pairs := family.GetMetric()[0].GetLabel()
		labels := make([]string, 0, len(pairs))
		for _, pair := range pairs {
			labels = append(labels, pair.GetName())
		}
		return labels
	}

	require.ElementsMatch(t, []string{labelCluster, labelModel, "outcome"},
		labelsOf("vexplain_llm_requests_total", dto.MetricType_COUNTER))
	require.ElementsMatch(t, []string{labelCluster, labelModel, "kind"},
		labelsOf("vexplain_llm_tokens_total", dto.MetricType_COUNTER))
	require.ElementsMatch(t, []string{labelCluster, labelModel},
		labelsOf("vexplain_llm_request_duration_seconds", dto.MetricType_HISTOGRAM))

	// LLM calls run from well under a second to minutes, where the default buckets stop at 10 s.
	buckets := byName["vexplain_llm_request_duration_seconds"].GetMetric()[0].GetHistogram().GetBucket()
	bounds := make([]float64, 0, len(buckets))
	for _, bucket := range buckets {
		bounds = append(bounds, bucket.GetUpperBound())
	}
	require.Equal(t, []float64{0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60, 120, 300}, bounds)
}
