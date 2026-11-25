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

package inventory_test

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	"github.com/bedag/vexplain/internal/inventory"
	"github.com/bedag/vexplain/internal/metrics"
)

// The gauge tests count through a CRD store over a fake client, from inventoryOf and storeOf of the
// list tests, for the cluster local and the cluster other.
const (
	// renamedCluster is the name of the cluster local after a rename.
	renamedCluster = "kind-a"

	// gaugeInterval is short, so that a test sees many rounds of the updater within its timeout.
	gaugeInterval = 10 * time.Millisecond
	gaugeTimeout  = 5 * time.Second
)

// clusterList is the clusters that a test hands to the updater, and changes while it runs, or a
// failure to read them. It counts the calls to get, one per round of the updater, so that a test can
// wait for rounds.
type clusterList struct {
	clusters atomic.Pointer[[]inventory.Cluster]
	failing  atomic.Bool
	calls    atomic.Int64
}

// newClusterList returns clusters that start as the cluster local alone.
func newClusterList() *clusterList {
	c := &clusterList{}
	c.set(inventory.Cluster{Name: localCluster, ID: localID})
	return c
}

func (c *clusterList) get(context.Context) ([]inventory.Cluster, error) {
	c.calls.Add(1)
	if c.failing.Load() {
		return nil, errors.New("the clusters can't be read")
	}
	return *c.clusters.Load(), nil
}

func (c *clusterList) set(clusters ...inventory.Cluster) {
	c.clusters.Store(&clusters)
}

// waitForRounds waits until a whole round of the updater has run since the call. A round starts
// with a call to get, and the next one starts only once it has ended, because the interval runs
// from the end of a round. So the second call after this one marks the end of a whole round.
func (c *clusterList) waitForRounds(t *testing.T) {
	t.Helper()
	since := c.calls.Load()
	require.Eventually(t, func() bool { return c.calls.Load() >= since+2 }, gaugeTimeout, gaugeInterval)
}

// startGauge runs the updater until the end of the test. The gauge is global, so it is reset before
// and after.
func startGauge(t *testing.T, updater *inventory.GaugeUpdater) {
	t.Helper()
	metrics.ImagesRunning.Reset()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- updater.Start(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			assert.NoError(t, err)
		case <-time.After(gaugeTimeout):
			t.Error("the updater did not stop when its context was cancelled")
		}
		metrics.ImagesRunning.Reset()
	})
}

// runningSeries returns the series of the gauge of running images: the value by cluster name. It
// collects the gauge, because a read through WithLabelValues would create the series it looks for.
func runningSeries(t require.TestingT) map[string]float64 {
	collected := make(chan prometheus.Metric)
	go func() {
		metrics.ImagesRunning.Collect(collected)
		close(collected)
	}()
	var all []prometheus.Metric
	for metric := range collected {
		all = append(all, metric)
	}
	series := make(map[string]float64, len(all))
	for _, metric := range all {
		var written dto.Metric
		require.NoError(t, metric.Write(&written))
		for _, label := range written.GetLabel() {
			if label.GetName() == clusterLabel {
				series[label.GetValue()] = written.GetGauge().GetValue()
			}
		}
	}
	return series
}

// requireSeries waits until the gauge holds exactly the series in want.
func requireSeries(t *testing.T, want map[string]float64) {
	t.Helper()
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		assert.Equal(c, want, runningSeries(c))
	}, gaugeTimeout, gaugeInterval)
}

func TestGaugeUpdaterCountsTheObjectsWithAnEntryForThisCluster(t *testing.T) {
	store := storeOf(t, interceptor.Funcs{},
		inventoryOf(digest, [2]string{localCluster, localID}),
		inventoryOf(otherDigest, [2]string{localCluster, localID}, [2]string{otherCluster, otherID}),
		inventoryOf(thirdDigest, [2]string{otherCluster, otherID}),
	)

	startGauge(t, &inventory.GaugeUpdater{
		Store:    store,
		Clusters: newClusterList().get,
		Interval: gaugeInterval,
	})

	requireSeries(t, map[string]float64{localCluster: 2})
}

// The hub counts the images of each cluster that it serves in one round: its own, and each remote cluster by the
// identity that its Spoke recorded. A cluster that it no longer serves, as when its Spoke is deleted, loses its series.
func TestTheGaugeCountsEveryCluster(t *testing.T) {
	store := storeOf(t, interceptor.Funcs{},
		inventoryOf(digest, [2]string{localCluster, localID}, [2]string{otherCluster, otherID}),
		inventoryOf(otherDigest, [2]string{otherCluster, otherID}),
		inventoryOf(thirdDigest, [2]string{"third", "id-third"}),
	)
	clusters := newClusterList()
	clusters.set(inventory.Cluster{Name: localCluster, ID: localID}, inventory.Cluster{Name: otherCluster, ID: otherID})
	startGauge(t, &inventory.GaugeUpdater{Store: store, Clusters: clusters.get, Interval: gaugeInterval})

	requireSeries(t, map[string]float64{localCluster: 1, otherCluster: 2})

	clusters.set(inventory.Cluster{Name: localCluster, ID: localID})

	requireSeries(t, map[string]float64{localCluster: 1})
}

func TestGaugeUpdaterDropsTheSeriesOfAFormerClusterName(t *testing.T) {
	store := storeOf(t, interceptor.Funcs{},
		inventoryOf(digest, [2]string{localCluster, localID}),
		inventoryOf(otherDigest, [2]string{otherCluster, otherID}),
	)
	clusters := newClusterList()
	startGauge(t, &inventory.GaugeUpdater{Store: store, Clusters: clusters.get, Interval: gaugeInterval})
	requireSeries(t, map[string]float64{localCluster: 1})

	clusters.set(inventory.Cluster{Name: renamedCluster, ID: localID})

	// The entry still has the former name: the spoke's presence renames it when it writes it next. The
	// ID is the same, so it counts for the cluster under its new name.
	requireSeries(t, map[string]float64{renamedCluster: 1})
}

func TestGaugeUpdaterKeepsTheGaugeWhileTheClustersAreUnknown(t *testing.T) {
	store := storeOf(t, interceptor.Funcs{}, inventoryOf(digest, [2]string{localCluster, localID}))
	clusters := newClusterList()
	startGauge(t, &inventory.GaugeUpdater{Store: store, Clusters: clusters.get, Interval: gaugeInterval})
	requireSeries(t, map[string]float64{localCluster: 1})

	clusters.failing.Store(true)
	clusters.waitForRounds(t)

	require.Equal(t, map[string]float64{localCluster: 1}, runningSeries(t))
}

func TestGaugeUpdaterKeepsTheGaugeWhenTheListFails(t *testing.T) {
	var failing atomic.Bool
	store := storeOf(t, interceptor.Funcs{
		List: func(ctx context.Context, c client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
			if failing.Load() {
				return errors.New("the cache is gone")
			}
			return c.List(ctx, list, opts...)
		},
	}, inventoryOf(digest, [2]string{localCluster, localID}))
	clusters := newClusterList()
	startGauge(t, &inventory.GaugeUpdater{Store: store, Clusters: clusters.get, Interval: gaugeInterval})
	requireSeries(t, map[string]float64{localCluster: 1})

	failing.Store(true)
	clusters.waitForRounds(t)

	require.Equal(t, map[string]float64{localCluster: 1}, runningSeries(t))
}

func TestGaugeUpdaterNeedsAnInterval(t *testing.T) {
	updater := &inventory.GaugeUpdater{
		Store:    storeOf(t, interceptor.Funcs{}),
		Clusters: newClusterList().get,
	}

	// Without an interval it would list the objects in a tight loop.
	require.Error(t, updater.Start(t.Context()))
}
