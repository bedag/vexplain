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

// Package metrics holds the operator's own Prometheus metrics.
//
// They are package-level collectors, registered with controller-runtime's registry when the
// package is first imported, so the manager serves them with its own metrics. The collectors are
// global: code that records a metric imports this package and uses the collector it needs.
package metrics

import (
	"slices"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"
)

// clusterLabel is the label that every metric carries: the name of the cluster as set in its
// OperatorConfig, so that a hub that collects the metrics of several clusters can tell them apart.
const clusterLabel = "cluster"

// modelLabel is the label of the LLM metrics that names the model of the endpoint.
const modelLabel = "model"

var (
	// InventoryObjectBytes is the size of an ImageInventory object after a write: the length of
	// the whole object as json.Marshal encodes it. It is the early indicator for the storage
	// decision, which asks how close the objects come to the limit of about 1.5 MB per object.
	InventoryObjectBytes = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "vexplain_inventory_object_bytes",
		Help:    "Size in bytes of an ImageInventory object after a write, as the whole object encodes to JSON.",
		Buckets: prometheus.ExponentialBuckets(1024, 2, 12),
	}, []string{clusterLabel})

	// InventoryWritesTotal counts the writes to ImageInventory objects. The op label is create for
	// a new object, update for a write of the status of an object, and delete for a deleted
	// object. A write that the API server refused is not counted.
	InventoryWritesTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "vexplain_inventory_writes_total",
		Help: "Writes to ImageInventory objects, by op: create for a new object, update for a write " +
			"of the status, delete for a deleted object.",
	}, []string{clusterLabel, "op"})

	// EvidenceObjectBytes is the size of an Evidence object after a write: the length of the whole
	// object as json.Marshal encodes it, data included. It shows how close the evidence that a
	// collector delivers comes to the limit of an object.
	EvidenceObjectBytes = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "vexplain_evidence_object_bytes",
		Help:    "Size in bytes of an Evidence object after a write, as the whole object encodes to JSON.",
		Buckets: prometheus.ExponentialBuckets(1024, 2, 12),
	}, []string{clusterLabel})

	// EvidenceWritesTotal counts the writes to Evidence objects. The op label is create for a new
	// object and delete for a deleted object. An Evidence is written once, so update never occurs:
	// the evidence of a new version of its collector replaces an object by deleting it and creating
	// it again. A write that the API server refused is not counted.
	EvidenceWritesTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "vexplain_evidence_writes_total",
		Help: "Writes to Evidence objects, by op: create for a new object, delete for a deleted object. " +
			"They are written once, so never updated.",
	}, []string{clusterLabel, "op"})

	// VerdictsObjectBytes is the size of an ImageVerdicts object after a write: the length of the
	// whole object as json.Marshal encodes it, findings included.
	VerdictsObjectBytes = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "vexplain_verdicts_object_bytes",
		Help:    "Size in bytes of an ImageVerdicts object after a write, as the whole object encodes to JSON.",
		Buckets: prometheus.ExponentialBuckets(1024, 2, 12),
	}, []string{clusterLabel})

	// VerdictsWritesTotal counts the writes to ImageVerdicts objects, the result sheets. The op label
	// is create for a new sheet, update for a write of the status of a sheet, and delete for a deleted
	// sheet. A sheet is written only when it changes. A write that the API server refused is not
	// counted.
	VerdictsWritesTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "vexplain_verdicts_writes_total",
		Help: "Writes to ImageVerdicts objects, by op: create for a new sheet, update for a write of the " +
			"status, delete for a deleted sheet.",
	}, []string{clusterLabel, "op"})

	// ImagesRunning is the number of image digests that run in the cluster. The inventory gauge
	// updater sets it, from the ImageInventory objects that have an entry for the cluster.
	ImagesRunning = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "vexplain_images_running",
		Help: "Number of image digests that run in the cluster.",
	}, []string{clusterLabel})

	// LLMRequestsTotal counts the requests that the LLM client made to a model endpoint, by model and
	// outcome: ok for an answer, unauthorized for an HTTP 401 or 403, timeout for a request that ran
	// out of time, and error for any other failure. It changes when a request ends. A call that
	// never got one of the request slots made no request and isn't counted, and neither are the
	// probes of a ModelConfig, which are checks and not model work.
	LLMRequestsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "vexplain_llm_requests_total",
		Help: "Requests to the model endpoint, by model and outcome: ok, unauthorized (HTTP 401 or 403), " +
			"timeout, or error for any other failure.",
	}, []string{clusterLabel, modelLabel, "outcome"})

	// LLMRequestDurationSeconds is the time of one request to a model endpoint, from sending it to
	// reading the whole answer, whatever the outcome. It doesn't include the wait for a free request
	// slot. The buckets reach 300 seconds, because a call to a model runs from well under a second
	// to minutes, where the default buckets stop at 10 seconds.
	LLMRequestDurationSeconds = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "vexplain_llm_request_duration_seconds",
		Help:    "Duration of a request to the model endpoint, until the whole answer was read, in seconds.",
		Buckets: []float64{0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60, 120, 300},
	}, []string{clusterLabel, modelLabel})

	// CollectorContractBreaksTotal counts the streams and the calls of a collector that vexplain ended because the
	// collector passed a bound of what it may send (design 5.9), by collector and bound: snapshot_time for a snapshot
	// that didn't end within a minute, snapshot_size for one that held more than 64 MiB, answer_events for an answer
	// with more events than it may hold, answer_size for one that held more than 128 MiB, and deadline for an
	// evidence request that the collector didn't answer within its deadline.
	CollectorContractBreaksTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "vexplain_collector_contract_breaks_total",
		Help: "Streams and calls of a collector that vexplain ended because the collector passed a bound of what it " +
			"may send, by collector and bound: snapshot_time, snapshot_size, answer_events, answer_size or deadline.",
	}, []string{clusterLabel, "collector", "bound"})

	// EvidenceDroppedTotal counts the events of collectors' answers to evidence requests that the spoke's executor
	// didn't store, because the hub's evidence doesn't take them, by collector and reason: scope for an event of a
	// type that stays on the spoke, and subject for one about neither a platform manifest nor the image of the
	// request. The rest of the answer is stored.
	EvidenceDroppedTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "vexplain_evidence_dropped_total",
		Help: "Events of collectors' answers to evidence requests that weren't stored, by collector and reason: scope " +
			"for a type that stays on the spoke, subject for an event about neither a manifest nor the requested image.",
	}, []string{clusterLabel, "collector", "reason"})

	// LLMTokensTotal counts the tokens that a model endpoint reports for the requests that got an
	// answer, by model and kind: prompt for the tokens it read, completion for the tokens it wrote.
	// They are the numbers in the usage of the answers, so an endpoint that reports none adds nothing.
	LLMTokensTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "vexplain_llm_tokens_total",
		Help: "Tokens that the model endpoint reported, by model and kind: prompt for the tokens read, " +
			"completion for the tokens written.",
	}, []string{clusterLabel, modelLabel, "kind"})
)

// sources holds the collectors that build their series when scraped, by name. A collector with label names that
// aren't known beforehand can't be unregistered from a registry, so the registry holds this one collector instead and
// a source is replaced by name, as when a test starts the operator again in the same process.
type sources struct {
	mu     sync.Mutex
	byName map[string]prometheus.Collector
}

// Describe sends nothing, which makes the collector unchecked: the sources may send any series.
func (s *sources) Describe(chan<- *prometheus.Desc) {}

// Collect asks each source, in the order of their names, for its series.
func (s *sources) Collect(ch chan<- prometheus.Metric) {
	s.mu.Lock()
	names := make([]string, 0, len(s.byName))
	for name := range s.byName {
		names = append(names, name)
	}
	slices.Sort(names)
	collectors := make([]prometheus.Collector, 0, len(names))
	for _, name := range names {
		collectors = append(collectors, s.byName[name])
	}
	s.mu.Unlock()
	for _, c := range collectors {
		c.Collect(ch)
	}
}

var scraped = &sources{byName: map[string]prometheus.Collector{}}

// SetSource makes c the collector of the name, in place of the one that the name had, and serves its series with the
// manager's metrics. Its series must carry the label cluster.
func SetSource(name string, c prometheus.Collector) {
	scraped.mu.Lock()
	defer scraped.mu.Unlock()
	scraped.byName[name] = c
}

func init() {
	ctrlmetrics.Registry.MustRegister(scraped,
		InventoryObjectBytes, InventoryWritesTotal, EvidenceObjectBytes, EvidenceWritesTotal,
		VerdictsObjectBytes, VerdictsWritesTotal,
		ImagesRunning,
		CollectorContractBreaksTotal, EvidenceDroppedTotal,
		LLMRequestsTotal, LLMRequestDurationSeconds, LLMTokensTotal,
	)
}
