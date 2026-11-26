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

// collectorLabel is the label that names a collector.
const collectorLabel = "collector"

// modelLabel is the label of the LLM metrics that names the model of the endpoint.
const modelLabel = "model"

// reasonLabel is the label that says why something was dropped, refused or ended.
const reasonLabel = "reason"

// kindLabel is the label of the token counters that says whether the model read the tokens or wrote them.
const kindLabel = "kind"

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
	// object, update for an object written in place, and delete for a deleted object. An Evidence is
	// kept current: a changed event, such as one of a new version of its collector, updates its
	// object, and an equal one writes nothing. A write that the API server refused is not counted.
	EvidenceWritesTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "vexplain_evidence_writes_total",
		Help: "Writes to Evidence objects, by op: create for a new object, update for an object written in " +
			"place, delete for a deleted object.",
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
	}, []string{clusterLabel, collectorLabel, "bound"})

	// EvidenceDroppedTotal counts the events of collectors' answers to evidence requests that the spoke's executor
	// didn't store, because the hub's evidence doesn't take them, by collector and reason: scope for an event of a
	// type that stays on the spoke, and subject for one about neither a platform manifest nor the image of the
	// request. The rest of the answer is stored.
	EvidenceDroppedTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "vexplain_evidence_dropped_total",
		Help: "Events of collectors' answers to evidence requests that weren't stored, by collector and reason: scope " +
			"for a type that stays on the spoke, subject for an event about neither a manifest nor the requested image.",
	}, []string{clusterLabel, collectorLabel, reasonLabel})

	// EvidenceTooLargeTotal counts the refusals of evidence that the evidence store can't hold, by collector: each
	// is an image that gets no verdict from that collector until the cap is raised or the evidence shrinks.
	EvidenceTooLargeTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "vexplain_evidence_too_large_total",
		Help: "Pieces of evidence that the evidence store refused for being over its cap, by collector.",
	}, []string{clusterLabel, collectorLabel})

	// EvidenceStreamedRefusedTotal counts the events of collectors' streams, of a type that goes to the hub, that the
	// evidence store refused, by collector, type and reason: TooLarge for an event over the store's cap, and Invalid
	// for one that doesn't fit what a record holds, or for presence or exposure off the core's schema, which the spoke
	// refuses itself. The spoke drops such an event, which would be refused at every attempt, and deletes the record
	// of its subject: the hub lacks the record until the collector sends it again, and it fits. Presence off the
	// schema keeps its record instead, as the spoke's presence never forgets what it can't read (decision 0067).
	EvidenceStreamedRefusedTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "vexplain_evidence_streamed_refused_total",
		Help: "Events of collectors' streams, of a type that goes to the hub, that the evidence store refused, by " +
			"collector, type and reason: TooLarge for an event over its cap, Invalid for one that doesn't fit a record " +
			"or, of presence or exposure, the core's schema.",
	}, []string{clusterLabel, collectorLabel, "type", reasonLabel})

	// PresenceRefusedTotal counts the presence events of collectors' streams that the spoke's presence can't read, by
	// collector: data off the core's schema, as from a collector older than the manager that lacks a field the manager
	// requires, and a tombstone whose subject is no image. Presence never forgets what it can't read (decision 0067): a
	// snapshot that holds one keeps the collector's last readable snapshot, and a change that it can't read changes
	// nothing, so a count that grows says that the cluster's presence may be stale.
	PresenceRefusedTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "vexplain_presence_refused_total",
		Help: "Presence events of collectors' streams that the spoke can't read, by collector. Presence keeps what the " +
			"collector last delivered that it can read, which may be stale.",
	}, []string{clusterLabel, collectorLabel})

	// SpokeRecordsRefusedTotal counts the records and the entries of a spoke that the hub refused to copy into its stores
	// (decision 0063), by the spoke's cluster and reason: cluster for one of another cluster, clusterID for an entry of
	// another identity than the one that the hub recorded, scope for a record of a type that its Collector doesn't declare
	// with the scope Hub, and invalid for one that the hub's own validation refuses, such as the labels of a namespace
	// that are more than its record holds, which the hub never cuts. Each version of a record that the hub reads counts
	// once, and again at each round that reads everything: the first of a copier, as after the hub started, one after a
	// round that failed, and one after the spoke's Collectors changed which types they declare Hub.
	SpokeRecordsRefusedTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "vexplain_spoke_records_refused_total",
		Help: "Records and entries of a spoke that the hub refused to copy, by the spoke's cluster and reason: cluster, " +
			"clusterID, scope, or invalid.",
	}, []string{clusterLabel, reasonLabel})

	// EntryPoints is the number of entry points that the exposure of each cluster names, as the hub counts them, by the
	// cluster that names them and by state: answered for an entry point that every source asked about it has answered,
	// within the answer's maxAge; unanswered for one that a source hasn't answered, whose answer is past its maxAge, or
	// that no source is asked about; ambiguous for an address whose IP another cluster names too, which gets no answer; and
	// unchecked for the reasons why a way in can't be asked about, one for each workload that gives a reason.
	EntryPoints = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "vexplain_entry_points",
		Help: "Entry points that the exposure of each cluster names, by cluster and state: answered, unanswered, " +
			"ambiguous for an address that another cluster names too, or unchecked for the reasons why a way in can't be " +
			"asked about.",
	}, []string{clusterLabel, "state"})

	// SourceCallsTotal counts the hub's calls to the sources about entry points, by collector and result: Succeeded,
	// InvalidInput for a call that the source or the schema of its parameters refused, NotReady, Failed for a failure
	// of another reason, and Error for a call that got no answer.
	SourceCallsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "vexplain_source_calls_total",
		Help: "Calls of the hub to the sources about entry points, by collector and result: Succeeded, InvalidInput, " +
			"NotReady, Failed for another reason, or Error for a call that got no answer.",
	}, []string{clusterLabel, collectorLabel, "result"})

	// ExposureViewReadFailuresTotal counts the reads of a subject's evidence by the hub's view of exposure that failed,
	// such as one of a record that can't be decoded, each attempt once, and the records that it read and left out, whole
	// or in part, because they aren't what their type says: presence or exposure whose data doesn't decode, and presence
	// that names a workload of another cluster. What is left out is missing from the view, which counts as missing
	// evidence, and the view doesn't wait for it to be synced.
	ExposureViewReadFailuresTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "vexplain_exposure_view_read_failures_total",
		Help: "Reads of a subject's evidence by the hub's view of exposure that failed, and records that it left out " +
			"because they aren't what their type says; what is left out is missing from the view.",
	}, []string{clusterLabel})

	// SourceAnswersUnaskedTotal counts the events of the sources' answers that the hub dropped, by collector: an event
	// about a subject that the call didn't ask about, of another type than the one asked for, or about a point that
	// an earlier event of the answer answered.
	SourceAnswersUnaskedTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "vexplain_source_answers_unasked_total",
		Help: "Events of the sources' answers that the hub dropped, because the call didn't ask for them, by collector.",
	}, []string{clusterLabel, collectorLabel})

	// LLMTokensTotal counts the tokens that a model endpoint reports for the requests that got an
	// answer, by model and kind: prompt for the tokens it read, completion for the tokens it wrote.
	// They are the numbers in the usage of the answers, so an endpoint that reports none adds nothing.
	LLMTokensTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "vexplain_llm_tokens_total",
		Help: "Tokens that the model endpoint reported, by model and kind: prompt for the tokens read, " +
			"completion for the tokens written.",
	}, []string{clusterLabel, modelLabel, kindLabel})

	// AgentCasesTotal counts the cases that the agent ended, by outcome: the status of its verdict, Affected,
	// UnderInvestigation, NotAffected or Fixed, or NoVerdict. A case that went back to the queue isn't counted.
	AgentCasesTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "vexplain_agent_cases_total",
		Help: "Cases that the agent ended, by outcome: the status of the verdict, or NoVerdict.",
	}, []string{clusterLabel, "outcome"})

	// AgentNoVerdictsTotal counts the cases that ended without a verdict, by reason: GaveUp, ValidatorRejected,
	// MaxSteps, MaxTokens, Timeout or ModelError.
	AgentNoVerdictsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "vexplain_agent_no_verdicts_total",
		Help: "Cases that ended without a verdict, by reason: GaveUp, ValidatorRejected, MaxSteps, MaxTokens, Timeout " +
			"or ModelError.",
	}, []string{clusterLabel, reasonLabel})

	// AgentRejectionsTotal counts the problems that the validator found in the agent's verdicts, by check, such as
	// FixedForInstalled: those of a verdict that the agent repaired too.
	AgentRejectionsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "vexplain_agent_rejections_total",
		Help: "Problems that the validator found in the agent's verdicts, by check, the repaired ones included.",
	}, []string{clusterLabel, "check"})

	// AgentToolRefusalsTotal counts the agent's tool calls that vexplain refused before any request, by tool and
	// reason: UntrustedURL for a fetch of a URL that no trusted result of the case named.
	AgentToolRefusalsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "vexplain_agent_tool_refusals_total",
		Help: "Tool calls of the agent that vexplain refused before any request, by tool and reason.",
	}, []string{clusterLabel, "tool", reasonLabel})

	// AgentTokensTotal counts the tokens that the endpoint reported for the agent's cases, by kind: prompt or
	// completion. A case that went back to the queue counts what it spent.
	AgentTokensTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "vexplain_agent_tokens_total",
		Help: "Tokens that the endpoint reported for the agent's cases, by kind: prompt or completion.",
	}, []string{clusterLabel, kindLabel})

	// InvestigationAgentTokensTotal counts the tokens that the endpoint reported for the judgements made for each
	// investigation, by its namespace and name and by kind: prompt or completion. It is bound to the investigation that
	// spent them, so another investigation's judgement of a shared case doesn't move it. A recreated investigation of the
	// same name continues the series.
	InvestigationAgentTokensTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "vexplain_investigation_agent_tokens_total",
		Help: "Tokens that the endpoint reported for the judgements made for an investigation, by kind: prompt or completion.",
	}, []string{clusterLabel, "namespace", "investigation", kindLabel})

	// InvestigationAgentSecondsTotal counts the time that the agent spent on the judgements made for each investigation,
	// by its namespace and name, from the start of a judgement to its end, also of one that went back to the queue.
	InvestigationAgentSecondsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "vexplain_investigation_agent_seconds_total",
		Help: "Time that the agent spent on the judgements made for an investigation, in seconds.",
	}, []string{clusterLabel, "namespace", "investigation"})

	// AgentCaseDurationSeconds is how long the agent took for a case that it ended. The buckets reach two hours, the
	// longest timeoutSeconds.
	AgentCaseDurationSeconds = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "vexplain_agent_case_duration_seconds",
		Help:    "Duration of a case that the agent ended, in seconds.",
		Buckets: []float64{5, 15, 30, 60, 120, 300, 600, 900, 1800, 3600, 7200},
	}, []string{clusterLabel})
)

// CollectorReady describes vexplain_collector_ready, which has a series for each of the cluster's own Collectors and for
// each collector that a remote cluster's Spoke lists: one description for both, since a scrape refuses a metric whose
// series have two helps.
var CollectorReady = prometheus.NewDesc("vexplain_collector_ready",
	"1 when the Ready condition of the collector is True, 0 otherwise.",
	[]string{clusterLabel, collectorLabel}, nil)

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
		CollectorContractBreaksTotal, EvidenceDroppedTotal, EvidenceTooLargeTotal, EvidenceStreamedRefusedTotal,
		PresenceRefusedTotal, SpokeRecordsRefusedTotal, EntryPoints, SourceCallsTotal, SourceAnswersUnaskedTotal,
		ExposureViewReadFailuresTotal,
		LLMRequestsTotal, LLMRequestDurationSeconds, LLMTokensTotal,
		AgentCasesTotal, AgentNoVerdictsTotal, AgentRejectionsTotal, AgentToolRefusalsTotal, AgentTokensTotal,
		AgentCaseDurationSeconds, InvestigationAgentTokensTotal, InvestigationAgentSecondsTotal,
	)
}
