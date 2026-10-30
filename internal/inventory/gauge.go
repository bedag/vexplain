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

// GaugeUpdater sets metrics.ImagesRunning, the number of image digests that run in this cluster,
// from the ImageInventory objects. It is a manager.Runnable.
//
// A gauge for a count of objects needs no event: the updater counts again every Interval.
type GaugeUpdater struct {
	// Store counts the objects that hold an entry of this cluster.
	Store Store
	// Cluster returns the name of this cluster, the label of the series. The updater asks for it
	// every round, so the series follows a rename. An empty name skips the round and keeps the
	// gauge as it is, for a name that can't be read just now.
	Cluster func() string
	// ClusterID is the identity of this cluster. An object counts when it has an entry with this
	// ID, whatever name the entry carries: right after a rename, the entries still carry the former
	// one.
	ClusterID string
	// Interval is the time from the end of one round to the start of the next. It must be positive.
	Interval time.Duration
}

// Start sets the gauge at once, and then every Interval, until ctx is done.
func (u *GaugeUpdater) Start(ctx context.Context) error {
	if u.Interval <= 0 {
		return errors.New("the gauge of running images needs a positive interval")
	}
	wait.UntilWithContext(ctx, u.update, u.Interval)
	return nil
}

// update sets the gauge for the current cluster name to the number of objects with an entry for
// this cluster. The reset drops the series of any former name. A round that can't count keeps
// the gauge as it is.
func (u *GaugeUpdater) update(ctx context.Context) {
	cluster := u.Cluster()
	if cluster == "" {
		return
	}
	running, err := u.Store.CountForCluster(ctx, u.ClusterID)
	if err != nil {
		logf.FromContext(ctx).Error(err, "Could not count the images that run in the cluster; the gauge keeps its value")
		return
	}
	metrics.ImagesRunning.Reset()
	metrics.ImagesRunning.WithLabelValues(cluster).Set(float64(running))
}
