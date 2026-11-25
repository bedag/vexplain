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

package inventory

import (
	"context"
	"errors"
	"time"

	"k8s.io/apimachinery/pkg/util/wait"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/bedag/vexplain/internal/metrics"
)

// GaugeUpdater sets metrics.ImagesRunning, the number of image digests that run in each cluster,
// from the ImageInventory objects. It is a manager.Runnable.
//
// A gauge for a count of objects needs no event: the updater counts again every Interval.
type GaugeUpdater struct {
	// Store counts the objects that hold an entry of each cluster.
	Store Store
	// Clusters returns the clusters to count. The updater asks for them every round, so the series
	// follow a rename, a cluster that comes, and one that goes. An error skips the round and keeps
	// the gauge as it is, for clusters that can't be read just now.
	Clusters func(ctx context.Context) ([]Cluster, error)
	// Interval is the time from the end of one round to the start of the next. It must be positive.
	Interval time.Duration
}

// Cluster is a cluster whose images the gauge counts: its name, the label of its series, and its
// identity. An object counts when it has an entry with the identity, whatever name the entry
// carries: right after a rename, the entries still carry the former one.
type Cluster struct{ Name, ID string }

// Start sets the gauge at once, and then every Interval, until ctx is done.
func (u *GaugeUpdater) Start(ctx context.Context) error {
	if u.Interval <= 0 {
		return errors.New("the gauge of running images needs a positive interval")
	}
	wait.UntilWithContext(ctx, u.update, u.Interval)
	return nil
}

// update sets the gauge of each cluster to the number of objects with an entry of the cluster,
// from one read of the objects for every cluster. One reset for the round drops the series of a
// former name and of a cluster that went, so that the series of one cluster never wipe another's.
// A round that can't count keeps the gauge as it is.
func (u *GaugeUpdater) update(ctx context.Context) {
	clusters, err := u.Clusters(ctx)
	if err != nil {
		logf.FromContext(ctx).Error(err, "Could not read the clusters to count the images of; the gauge keeps its value")
		return
	}
	byID, err := u.Store.DigestsByCluster(ctx)
	if err != nil {
		logf.FromContext(ctx).Error(err, "Could not count the images that run in the clusters; the gauge keeps its value")
		return
	}
	metrics.ImagesRunning.Reset()
	for _, cluster := range clusters {
		metrics.ImagesRunning.WithLabelValues(cluster.Name).Set(float64(len(byID[cluster.ID])))
	}
}
