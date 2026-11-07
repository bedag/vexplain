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
	"github.com/bedag/vexplain/internal/settings"
	"github.com/bedag/vexplain/internal/text"
)

// scrapeTimeout bounds the reads that a scrape of the playbooks' series makes.
const scrapeTimeout = 5 * time.Second

var playbookReadyDesc = prometheus.NewDesc("vexplain_playbook_ready",
	"1 when the Ready condition of the playbook is True, 0 otherwise.",
	[]string{"cluster", "playbook"}, nil)

// PlaybooksCollector reports whether each Playbook is ready, from its Ready condition when it is scraped (decision
// 0036). A Playbook that goes has no series from the next scrape on.
type PlaybooksCollector struct {
	reader client.Reader
	log    logr.Logger
}

// NewPlaybooksCollector returns a collector that reads the Playbooks, and the cluster's name, through reader.
func NewPlaybooksCollector(reader client.Reader, log logr.Logger) *PlaybooksCollector {
	return &PlaybooksCollector{reader: reader, log: log}
}

// Describe sends the description of its one series.
func (c *PlaybooksCollector) Describe(ch chan<- *prometheus.Desc) { ch <- playbookReadyDesc }

// Collect sends 1 for each Playbook whose Ready condition is True and 0 for each other. A failed read sends an
// invalid metric, which the scrape reports as an error, and no value that might be wrong.
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
	}
}
