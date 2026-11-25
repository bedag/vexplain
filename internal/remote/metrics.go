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

package remote

import (
	"context"
	"time"

	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/bedag/vexplain/internal/exposure"
	"github.com/bedag/vexplain/internal/inventory"
	"github.com/bedag/vexplain/internal/metrics"
	"github.com/bedag/vexplain/internal/text"
)

// scrapeTimeout bounds the reads that a scrape of the spokes' series makes.
const scrapeTimeout = 5 * time.Second

var withoutPresenceDesc = prometheus.NewDesc("vexplain_remote_images_without_presence",
	"Images with an entry of a remote cluster whose presence record the hub holds no copy of, as when the spoke's store "+
		"refused it as too large: they are missing from the cluster's series, though its cases count their workloads.",
	[]string{"cluster"}, nil)

// SpokesCollector reports, when it is scraped, what the hub holds of each remote cluster that it renders, as Spokes
// gives them (design of remote spokes 5.9): whether each of the cluster's collectors is ready, as the cluster's Spoke
// lists them, and the images with an entry of the cluster, by the identity that the Spoke recorded, whose presence
// record the hub holds no copy of. It sends the images without presence only once the view has read the store: before,
// as after a start, and on a replica that isn't the leader, whose view never reads it, every image would look as if
// the hub held no copy. A failed read sends an invalid metric, which the scrape reports as an error, and no value that
// might be wrong.
type SpokesCollector struct {
	reader client.Reader
	store  inventory.Store
	view   *exposure.View
	log    logr.Logger
}

// NewSpokesCollector returns a collector that reads the Spokes, and the name of the hub's own cluster, through reader,
// the entries of the images from store, and the copies of presence from view.
func NewSpokesCollector(reader client.Reader, store inventory.Store, view *exposure.View,
	log logr.Logger) *SpokesCollector {
	return &SpokesCollector{reader: reader, store: store, view: view, log: log}
}

// Describe sends nothing: it is served with the other sources, unchecked, and a remote collector's readiness is the
// same metric as each cluster's own collectors'.
func (c *SpokesCollector) Describe(chan<- *prometheus.Desc) {}

// Collect sends the readiness of each collector of each remote cluster, 1 when it is True and 0 otherwise, and the
// count of each cluster's images without a copy of their presence, from one read of the images for every cluster.
func (c *SpokesCollector) Collect(ch chan<- prometheus.Metric) {
	ctx, cancel := context.WithTimeout(context.Background(), scrapeTimeout)
	defer cancel()
	_, spokes, err := Spokes(ctx, c.reader)
	if err != nil {
		c.log.Error(err, "Could not list the Spokes for the metrics")
		ch <- prometheus.NewInvalidMetric(metrics.CollectorReady, err)
		return
	}
	for _, s := range spokes {
		for _, collector := range s.Status.Collectors {
			ready := 0.0
			if ptr.Deref(collector.Ready, "") == metav1.ConditionTrue {
				ready = 1
			}
			ch <- prometheus.MustNewConstMetric(metrics.CollectorReady, prometheus.GaugeValue, ready,
				text.Printable(s.Name), text.Printable(collector.Name))
		}
	}
	if !c.view.Synced() {
		return
	}
	byID, err := c.store.DigestsByCluster(ctx)
	if err != nil {
		c.log.Error(err, "Could not list the images of the remote clusters for the metrics")
		ch <- prometheus.NewInvalidMetric(withoutPresenceDesc, err)
		return
	}
	for _, s := range spokes {
		// A Spoke that no contact gave an identity has no entry to count.
		id := ptr.Deref(s.Status.ClusterID, "")
		if id == "" {
			continue
		}
		missing := 0
		for _, digest := range byID[id] {
			if _, known := c.view.Workloads(digest, s.Name); !known {
				missing++
			}
		}
		ch <- prometheus.MustNewConstMetric(withoutPresenceDesc, prometheus.GaugeValue, float64(missing),
			text.Printable(s.Name))
	}
}
