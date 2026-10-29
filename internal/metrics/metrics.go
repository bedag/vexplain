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
	"github.com/prometheus/client_golang/prometheus"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"
)

// clusterLabel is the label that every metric carries: the name of the cluster as set in its
// OperatorConfig, so that a hub that collects the metrics of several clusters can tell them apart.
const clusterLabel = "cluster"

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

	// ImagesRunning is the number of image digests that run in the cluster. The inventory gauge
	// updater sets it, from the ImageInventory objects that have an entry for the cluster.
	ImagesRunning = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "vexplain_images_running",
		Help: "Number of image digests that run in the cluster.",
	}, []string{clusterLabel})

	// UnparsableImageIDsTotal counts the containers that the pod inventory skips because the imageID
	// their container runtime reports is set but is not a digest. The image of such a container is
	// missing from the inventory, so an alert on this counter shows that running images go
	// unanalysed. A container counts once, when its imageID turns unparsable, and again after a
	// restart of the operator.
	UnparsableImageIDsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "vexplain_unparsable_image_ids_total",
		Help: "Containers skipped by the pod inventory because the imageID their container runtime reports is not a digest.",
	}, []string{clusterLabel})
)

func init() {
	ctrlmetrics.Registry.MustRegister(InventoryObjectBytes, InventoryWritesTotal, ImagesRunning, UnparsableImageIDsTotal)
}
