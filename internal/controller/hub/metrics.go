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
	"time"

	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus"
	"k8s.io/apimachinery/pkg/api/meta"
	"sigs.k8s.io/controller-runtime/pkg/client"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
	inventoryv1alpha1 "github.com/bedag/vexplain/api/inventory/v1alpha1"
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
		"Resources of the cluster that the playbook judged, and of those that fail it, by state: judged or failing.",
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
	verdicts inventory.VerdictsStore
	log      logr.Logger
}

// NewPlaybooksCollector returns a collector that reads the Playbooks, and the cluster's name, through reader, the
// counts through counts and the sheets through verdicts.
func NewPlaybooksCollector(reader client.Reader, counts inventory.CountsStore, verdicts inventory.VerdictsStore,
	log logr.Logger) *PlaybooksCollector {
	return &PlaybooksCollector{reader: reader, counts: counts, verdicts: verdicts, log: log}
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
	c.collectRuleFindings(ctx, ch, text.Printable(cfg.ClusterName))
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
		gauge(playbookResourcesDesc, t.Failing, cluster, name, "failing")
		gauge(playbookActionsDesc, t.Updates, cluster, name, "Update")
		gauge(playbookActionsDesc, t.Changes, cluster, name, "Change")
		gauge(playbookActionsDesc, t.Mitigations, cluster, name, "Mitigate")
		gauge(playbookActionsDesc, t.Investigations, cluster, name, "Investigate")
	}
}

// collectRuleFindings sends, for each playbook, rule and status, how many findings of the current sheets that rule
// decided. A finding that no rule decided is left out.
func (c *PlaybooksCollector) collectRuleFindings(ctx context.Context, ch chan<- prometheus.Metric, cluster string) {
	type key struct{ playbook, rule, status string }
	found := map[key]float64{}
	err := c.verdicts.Each(ctx, func(sheet *inventoryv1alpha1.ImageVerdicts) error {
		for _, f := range sheet.Status.Findings {
			if f.Rule != nil {
				found[key{text.Printable(sheet.Spec.Playbook), text.Printable(*f.Rule), string(f.Status)}]++
			}
		}
		return nil
	})
	if err != nil {
		c.log.Error(err, "Could not read the sheets for the metrics")
		ch <- prometheus.NewInvalidMetric(ruleFindingsDesc, err)
		return
	}
	for k, n := range found {
		ch <- prometheus.MustNewConstMetric(ruleFindingsDesc, prometheus.GaugeValue, n, cluster, k.playbook, k.rule, k.status)
	}
}
