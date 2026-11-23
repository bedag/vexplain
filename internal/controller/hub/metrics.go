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
	"strings"
	"sync"
	"time"

	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
	inventoryv1alpha1 "github.com/bedag/vexplain/api/inventory/v1alpha1"
	triagev1alpha1 "github.com/bedag/vexplain/api/triage/v1alpha1"
	"github.com/bedag/vexplain/internal/inventory"
	"github.com/bedag/vexplain/internal/settings"
	"github.com/bedag/vexplain/internal/text"
)

// clusterLabel and playbookLabel are the labels of the series that hold the name of a cluster and of a playbook.
const (
	clusterLabel  = "cluster"
	playbookLabel = "playbook"
)

// scrapeTimeout bounds the reads that a scrape of the playbooks' series makes.
const scrapeTimeout = 5 * time.Second

var (
	playbookReadyDesc = prometheus.NewDesc("vexplain_playbook_ready",
		"1 when the Ready condition of the playbook is True, 0 otherwise.",
		[]string{clusterLabel, playbookLabel}, nil)
	playbookResourcesDesc = prometheus.NewDesc("vexplain_playbook_resources",
		"Resources of the cluster that the playbook judged, and of those the ones with an action, by state: judged or actionable.",
		[]string{clusterLabel, playbookLabel, "state"}, nil)
	playbookActionsDesc = prometheus.NewDesc("vexplain_playbook_actions",
		"Actions of the playbook in the cluster, by step: Update, Change, Mitigate or Investigate.",
		[]string{clusterLabel, playbookLabel, "step"}, nil)
	ruleFindingsDesc = prometheus.NewDesc("vexplain_rule_findings",
		"Findings that a rule of the playbook decided over the current result sheets, by status.",
		[]string{clusterLabel, playbookLabel, "rule", "status"}, nil)
)

// PlaybooksCollector reports whether each Playbook is ready, from its Ready condition when it is scraped (decision
// 0036), the fleet picture of each playbook from the counts that the spokes write (the resources it judged and
// those that fail it, and its actions by step, for each cluster), and the findings that each rule decided over the
// result sheets, by status. A Playbook that goes has no series from the next scrape on.
type PlaybooksCollector struct {
	reader   client.Reader
	counts   inventory.CountsStore
	findings *RuleFindings
	log      logr.Logger
}

// NewPlaybooksCollector returns a collector that reads the Playbooks, and the cluster's name, through reader, the
// counts through counts and the findings of the rules from the snapshot findings.
func NewPlaybooksCollector(reader client.Reader, counts inventory.CountsStore, findings *RuleFindings,
	log logr.Logger) *PlaybooksCollector {
	return &PlaybooksCollector{reader: reader, counts: counts, findings: findings, log: log}
}

// Describe sends the descriptions of its series.
func (c *PlaybooksCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- playbookReadyDesc
	ch <- playbookResourcesDesc
	ch <- playbookActionsDesc
	ch <- ruleFindingsDesc
}

// Collect sends 1 for each Playbook whose Ready condition is True and 0 for each other, and the counts and findings.
// A failed read sends an invalid metric, which the scrape reports as an error, and no value that might be wrong.
func (c *PlaybooksCollector) Collect(ch chan<- prometheus.Metric) {
	ctx, cancel := context.WithTimeout(context.Background(), scrapeTimeout)
	defer cancel()
	cfg, err := settings.Load(ctx, c.reader)
	if err != nil {
		ch <- prometheus.NewInvalidMetric(playbookReadyDesc, err)
		return
	}
	var list configv1alpha1.PlaybookList
	if err := c.reader.List(ctx, &list); err != nil {
		c.log.Error(err, "Could not list the playbooks for the metrics")
		ch <- prometheus.NewInvalidMetric(playbookReadyDesc, err)
		return
	}
	for _, obj := range list.Items {
		ready := 0.0
		if meta.IsStatusConditionTrue(obj.Status.Conditions, configv1alpha1.ConditionReady) {
			ready = 1
		}
		ch <- prometheus.MustNewConstMetric(playbookReadyDesc, prometheus.GaugeValue, ready,
			text.Printable(cfg.ClusterName), text.Printable(obj.Name))
		c.collectCounts(ctx, ch, obj.Name)
	}
	c.collectRuleFindings(ch, text.Printable(cfg.ClusterName))
}

// collectCounts sends the counts that the spokes wrote for the playbook, for each cluster.
func (c *PlaybooksCollector) collectCounts(ctx context.Context, ch chan<- prometheus.Metric, playbook string) {
	counts, err := c.counts.List(ctx, playbook)
	if err != nil {
		c.log.Error(err, "Could not list the counts of a playbook for the metrics", "playbook", playbook)
		ch <- prometheus.NewInvalidMetric(playbookResourcesDesc, err)
		return
	}
	gauge := func(desc *prometheus.Desc, value int32, labels ...string) {
		ch <- prometheus.MustNewConstMetric(desc, prometheus.GaugeValue, float64(value), labels...)
	}
	for _, obj := range counts {
		cluster, name := text.Printable(obj.Spec.Cluster), text.Printable(playbook)
		t := inventory.TallyOf(obj.Status)
		gauge(playbookResourcesDesc, t.Judged, cluster, name, "judged")
		gauge(playbookResourcesDesc, t.Actionable, cluster, name, "actionable")
		gauge(playbookActionsDesc, t.Updates, cluster, name, "Update")
		gauge(playbookActionsDesc, t.Changes, cluster, name, "Change")
		gauge(playbookActionsDesc, t.Mitigations, cluster, name, "Mitigate")
		gauge(playbookActionsDesc, t.Investigations, cluster, name, "Investigate")
	}
}

// collectRuleFindings sends the findings that each rule decided, as the last refresh of the snapshot counted them. A
// snapshot that has not been taken yet, as on a replica that is not the leader, sends none.
func (c *PlaybooksCollector) collectRuleFindings(ch chan<- prometheus.Metric, cluster string) {
	for k, n := range c.findings.snapshot() {
		ch <- prometheus.MustNewConstMetric(ruleFindingsDesc, prometheus.GaugeValue, n, cluster, k.playbook, k.rule, k.status)
	}
}

// ruleFindingsInterval is how often the snapshot of the findings that each rule decided is taken again.
const ruleFindingsInterval = 2 * time.Minute

// ruleKey is the playbook, rule and status that a count of findings is for.
type ruleKey struct{ playbook, rule, status string }

// RuleFindings counts, for each playbook, rule and status, the findings that the rule decided over the current result
// sheets. A count needs every sheet, each up to about 1 MiB, so it is taken from the API server on an interval and
// kept, and a scrape only reads it: a scrape never lists the sheets, and a count that fails keeps the last snapshot and
// fails no series. It is a manager.Runnable that runs on the leader only, so the series are sent once.
type RuleFindings struct {
	verdicts inventory.VerdictsStore
	log      logr.Logger
	interval time.Duration

	mu   sync.Mutex
	last map[ruleKey]float64
}

// NewRuleFindings returns a snapshot of the findings of each rule over the sheets that verdicts holds.
func NewRuleFindings(verdicts inventory.VerdictsStore, log logr.Logger) *RuleFindings {
	return &RuleFindings{verdicts: verdicts, log: log, interval: ruleFindingsInterval}
}

// Start takes the snapshot at once, and then every interval, until ctx is done.
func (r *RuleFindings) Start(ctx context.Context) error {
	wait.UntilWithContext(ctx, func(ctx context.Context) {
		if err := r.Refresh(ctx); err != nil {
			r.log.Error(err, "Could not count the findings of the rules; the metric keeps its last values")
		}
	}, r.interval)
	return nil
}

// Refresh counts the findings of every sheet and keeps the counts. A finding that no rule decided is left out. It keeps
// the last counts when a read fails.
func (r *RuleFindings) Refresh(ctx context.Context) error {
	found := map[ruleKey]float64{}
	err := r.verdicts.Each(ctx, func(sheet *inventoryv1alpha1.ImageVerdicts) error {
		for _, f := range sheet.Status.Findings {
			if f.Rule != nil {
				found[ruleKey{text.Printable(sheet.Spec.Playbook), text.Printable(*f.Rule), string(f.Status)}]++
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	r.mu.Lock()
	r.last = found
	r.mu.Unlock()
	return nil
}

func (r *RuleFindings) snapshot() map[ruleKey]float64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.last
}

var investigationCasesDesc = prometheus.NewDesc("vexplain_investigation_cases",
	"Cases of an investigation, by state: total, queued, inProgress, charged, judged, reused, overTheCap, "+
		"judgedElsewhere or notSelected, as its status counts them.",
	[]string{clusterLabel, "namespace", "investigation", "state"}, nil)

var investigationInfoDesc = prometheus.NewDesc("vexplain_investigation_vulnerability_info",
	"1 for each vulnerability of an investigation: each vulnerabilityID of its status.results, as the findings spell "+
		"it, and each ID of its spec.vulnerabilities that no result names, ignoring case. It joins an investigation to "+
		"the cve label of vexplain_open_case. An investigation without vulnerabilities names only the CVEs of its results.",
	[]string{clusterLabel, "namespace", "investigation", "cve"}, nil)

// InvestigationsCollector reports the cases of each Investigation by state, from its status when it is scraped (design
// of the agent on image cases, 5.12), and its vulnerabilities. An Investigation that goes has no series from the next
// scrape on, and one whose status counts no cases yet has none of the cases.
type InvestigationsCollector struct {
	reader client.Reader
	log    logr.Logger
}

// NewInvestigationsCollector returns a collector that reads the Investigations, and the cluster's name, through reader.
func NewInvestigationsCollector(reader client.Reader, log logr.Logger) *InvestigationsCollector {
	return &InvestigationsCollector{reader: reader, log: log}
}

// Describe sends the description of its series.
func (c *InvestigationsCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- investigationCasesDesc
	ch <- investigationInfoDesc
}

// Collect sends the vulnerabilities of each Investigation, and its cases by state. A failed read sends an invalid
// metric, and no value that might be wrong.
func (c *InvestigationsCollector) Collect(ch chan<- prometheus.Metric) {
	ctx, cancel := context.WithTimeout(context.Background(), scrapeTimeout)
	defer cancel()
	cfg, err := settings.Load(ctx, c.reader)
	if err != nil {
		ch <- prometheus.NewInvalidMetric(investigationCasesDesc, err)
		return
	}
	var list triagev1alpha1.InvestigationList
	if err := c.reader.List(ctx, &list); err != nil {
		c.log.Error(err, "Could not list the investigations for the metrics")
		ch <- prometheus.NewInvalidMetric(investigationCasesDesc, err)
		return
	}
	cluster := text.Printable(cfg.ClusterName)
	for _, inv := range list.Items {
		// The results come first, as the findings spell their IDs, and the spec's IDs only where no result names them,
		// compared as selection compares them, ignoring case.
		var ids []string
		add := func(id string) {
			if id = text.Printable(id); id != "" && !slices.ContainsFunc(ids, func(had string) bool { return strings.EqualFold(had, id) }) {
				ids = append(ids, id)
			}
		}
		for _, r := range inv.Status.Results {
			add(r.VulnerabilityID)
		}
		for _, id := range inv.Spec.Vulnerabilities {
			add(id)
		}
		slices.Sort(ids)
		for _, id := range ids {
			ch <- prometheus.MustNewConstMetric(investigationInfoDesc, prometheus.GaugeValue, 1,
				cluster, inv.Namespace, inv.Name, id)
		}
		counts := inv.Status.Cases
		if counts == nil {
			continue
		}
		for state, n := range map[string]*int32{"total": counts.Total, "queued": counts.Queued,
			"inProgress": counts.InProgress, "charged": counts.Charged, "judged": counts.Judged, "reused": counts.Reused,
			"overTheCap": counts.OverTheCap, "judgedElsewhere": counts.JudgedElsewhere, "notSelected": counts.NotSelected} {
			ch <- prometheus.MustNewConstMetric(investigationCasesDesc, prometheus.GaugeValue, float64(ptr.Deref(n, 0)),
				cluster, inv.Namespace, inv.Name, state)
		}
	}
}

var vexStatementsDesc = prometheus.NewDesc("vexplain_vex_statements",
	"VexStatements by review: Proposed, Accepted or Rejected, or Superseded for one that no longer stands.",
	[]string{clusterLabel, "review"}, nil)

// reviews are the values of the series of the VexStatements: the review states, and Superseded.
var reviews = []string{string(triagev1alpha1.ReviewStateProposed), string(triagev1alpha1.ReviewStateAccepted),
	string(triagev1alpha1.ReviewStateRejected), triagev1alpha1.ConditionSuperseded}

// VexStatementsCollector reports the VexStatements by review when it is scraped (design of the agent on image cases,
// 5.10): a statement that no longer stands counts as Superseded, whatever its review.
type VexStatementsCollector struct {
	reader client.Reader
	log    logr.Logger
}

// NewVexStatementsCollector returns a collector that reads the VexStatements, and the cluster's name, through reader.
func NewVexStatementsCollector(reader client.Reader, log logr.Logger) *VexStatementsCollector {
	return &VexStatementsCollector{reader: reader, log: log}
}

// Describe sends the description of its series.
func (c *VexStatementsCollector) Describe(ch chan<- *prometheus.Desc) { ch <- vexStatementsDesc }

// Collect sends the count of the VexStatements of each review, 0 included. A failed read sends an invalid metric, and
// no value that might be wrong.
func (c *VexStatementsCollector) Collect(ch chan<- prometheus.Metric) {
	ctx, cancel := context.WithTimeout(context.Background(), scrapeTimeout)
	defer cancel()
	cfg, err := settings.Load(ctx, c.reader)
	if err != nil {
		ch <- prometheus.NewInvalidMetric(vexStatementsDesc, err)
		return
	}
	var list triagev1alpha1.VexStatementList
	if err := c.reader.List(ctx, &list); err != nil {
		c.log.Error(err, "Could not list the VexStatements for the metrics")
		ch <- prometheus.NewInvalidMetric(vexStatementsDesc, err)
		return
	}
	counts := map[string]int{}
	for _, s := range list.Items {
		counts[reviewOf(&s)]++
	}
	for _, review := range reviews {
		ch <- prometheus.MustNewConstMetric(vexStatementsDesc, prometheus.GaugeValue, float64(counts[review]),
			text.Printable(cfg.ClusterName), review)
	}
}

// reviewOf returns the review of the statement as the series count it: Superseded once it no longer stands, and else
// its review state, Proposed until the API server defaults it.
func reviewOf(s *triagev1alpha1.VexStatement) string {
	if meta.IsStatusConditionTrue(s.Status.Conditions, triagev1alpha1.ConditionSuperseded) {
		return triagev1alpha1.ConditionSuperseded
	}
	if s.Spec.Review == nil {
		return string(triagev1alpha1.ReviewStateProposed)
	}
	return string(ptr.Deref(s.Spec.Review.State, triagev1alpha1.ReviewStateProposed))
}
