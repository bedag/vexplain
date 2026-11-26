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

package main

import (
	"context"
	"errors"
	"fmt"
	"math"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// Each spoke runs 100 workloads over 30 images in 10 namespaces, and 10 of the images run on both spokes, so that an
// ImageInventory has entries of two clusters. A kind node runs 110 pods by default, so 100 workloads of one pod and the
// operator's own pods fit one node, which the measurement's kind config lets run 200 for the rollout of 50 of them.
func TestTheLoadRunsHundredWorkloadsOverThirtyImagesOnEachSpoke(t *testing.T) {
	perSpoke := [2]map[int]bool{}
	for s := range 2 {
		load := loadOf(s)
		require.Len(t, load, 100)
		perSpoke[s] = map[int]bool{}
		seen := map[string]bool{}
		namespaces := map[int]map[string]bool{}
		for _, w := range load {
			require.False(t, seen[w.namespace+"/"+w.name], "a workload is named twice: %s/%s", w.namespace, w.name)
			seen[w.namespace+"/"+w.name] = true
			perSpoke[s][w.image] = true
			if namespaces[w.image] == nil {
				namespaces[w.image] = map[string]bool{}
			}
			namespaces[w.image][w.namespace] = true
		}
		require.Len(t, perSpoke[s], spokeImages)
		for k, g := range imagesOf(s) {
			_, want := layout(k)
			require.Len(t, namespaces[g], want, "the namespaces of %s", imageName(g))
		}
	}
	shared := 0
	for g := range perSpoke[0] {
		if perSpoke[1][g] {
			shared++
		}
	}
	require.Equal(t, sharedImages, shared)
	require.Equal(t, imagesOf(0)[0], imagesOf(1)[0], "the image with the most workloads runs on both spokes")

	rolledImages := map[int]bool{}
	for _, w := range rolled() {
		rolledImages[w.image] = true
	}
	require.Len(t, rolled(), 50)
	require.Len(t, rolledImages, 23, "the images whose presence the rollout changes")
}

// The counts of the layout vary apart, so that the fits can tell a workload from a namespace.
func TestTheLayoutVariesWorkloadsAndNamespacesApart(t *testing.T) {
	pairs := map[[2]int]bool{}
	for k := range spokeImages {
		workloads, namespaces := layout(k)
		require.LessOrEqual(t, namespaces, workloads)
		pairs[[2]int{workloads, namespaces}] = true
	}
	for _, pair := range [][2]int{{2, 1}, {2, 2}, {4, 1}, {4, 4}, {3, 2}} {
		require.True(t, pairs[pair], "no image runs %d workloads in %d namespaces", pair[0], pair[1])
	}
}

func TestLeastSquaresFindsTheTermsOfALinearSize(t *testing.T) {
	var points []point
	for e := 1.0; e <= 2; e++ {
		for w := 1.0; w <= 4; w++ {
			for n := 1.0; n <= w; n++ {
				points = append(points, point{x: []float64{e, w, n}, y: []float64{900 + 300*e + 85*w + 120*n}})
			}
		}
	}

	found, err := leastSquares(points)

	require.NoError(t, err)
	for i, want := range []float64{900, 300, 85, 120} {
		require.InDelta(t, want, found.coefficients[i], 1e-6)
	}
	require.InDelta(t, 0, found.largestResidual, 1e-6)

	points[0].y[0] += 10
	found, err = leastSquares(points)
	require.NoError(t, err)
	require.Greater(t, found.largestResidual, 1.0, "a point off the line shows in the residual")
}

func TestLeastSquaresRefusesCountsThatAlwaysVaryTogether(t *testing.T) {
	var points []point
	for w := 1.0; w <= 4; w++ {
		points = append(points, point{x: []float64{w, 2 * w}, y: []float64{10 * w}})
	}
	_, err := leastSquares(points)
	require.Error(t, err)

	_, err = leastSquares(nil)
	require.Error(t, err)
}

// A projection names the first whole count at which the fitted bytes reach the limit.
func TestReachedAtProjectsAlongTheFittedLine(t *testing.T) {
	require.InDelta(t, 7865, reachedAt(0, 100, 786432), 1e-9)
	require.InDelta(t, 5232, reachedAt(1000, 100, 524200), 1e-9, "a count that reaches the limit exactly")
	require.InDelta(t, 488, reachedAt(2054, 1072, 524288), 1e-9, "the ImageInventory of entries of 1 workload")
	require.True(t, math.IsInf(reachedAt(1000, 0, 524288), 1), "bytes that don't grow never reach a limit")
}

// sample is a sample of writes that has all of them in one resource.
func sample(at time.Time, writes float64) writeSample {
	return writeSample{at: at, byResource: map[string]float64{"evidences": writes}}
}

func TestPeakRateTakesTheBusiestStretchOfTheWindow(t *testing.T) {
	start := time.Unix(1000, 0)
	// 5 s apart: quiet, a burst of 60 writes in 10 s, quiet again.
	samples := []writeSample{
		sample(start, 100), sample(start.Add(5*time.Second), 100), sample(start.Add(10*time.Second), 130),
		sample(start.Add(15*time.Second), 160), sample(start.Add(20*time.Second), 160),
		sample(start.Add(70*time.Second), 160),
	}

	require.InDelta(t, 6, peakRate(samples, 10*time.Second), 1e-9)
	// The shortest stretch of a minute or more that holds the burst runs from 5 s to 70 s.
	require.InDelta(t, 60.0/65, peakRate(samples, time.Minute), 1e-9)
	require.Zero(t, peakRate(samples[:2], time.Minute), "no stretch is a minute long")

	r := ratesOf(samples, false)
	require.InDelta(t, 60, r.writes, 1e-9)
	require.Equal(t, 70*time.Second, r.duration)
	require.InDelta(t, 60.0/70, r.mean, 1e-9)
}

// A phase that ends once the writes stand still took until its last write: the quiet minute after it is the tool's
// wait, not the phase. The busiest stretches take every sample, the quiet ones too.
func TestASettledPhaseTookUntilItsLastWrite(t *testing.T) {
	start := time.Unix(1000, 0)
	samples := []writeSample{sample(start, 100), sample(start.Add(5*time.Second), 130),
		sample(start.Add(10*time.Second), 160)}
	for i := 3; i <= 15; i++ {
		samples = append(samples, sample(start.Add(time.Duration(5*i)*time.Second), 160))
	}

	settled := ratesOf(samples, true)

	require.InDelta(t, 60, settled.writes, 1e-9)
	require.Equal(t, 10*time.Second, settled.duration)
	require.InDelta(t, 6, settled.mean, 1e-9)
	require.InDelta(t, 6, settled.peak10s, 1e-9)
	require.InDelta(t, 1, settled.peakMinute, 1e-9, "the busiest minute, from 0 s to 60 s")
	require.Equal(t, 75*time.Second, ratesOf(samples, false).duration, "a phase of a fixed time took all of it")

	quiet := ratesOf(samples[2:], true)
	require.Zero(t, quiet.writes)
	require.Equal(t, 65*time.Second, quiet.duration, "a settled phase without a write took the whole wait")
}

// mark waits for the first sample of the writes, and stops with the run, so that a hub whose metrics can't be read
// doesn't hold the tool for ever.
func TestMarkReturnsTheLatestSampleAndStopsWithTheRun(t *testing.T) {
	m := &measurement{writesErr: errors.New("the metrics can't be read")}
	stopped, stop := context.WithCancel(context.Background())
	stop()
	_, err := m.mark(stopped)
	require.ErrorIs(t, err, context.Canceled)

	m.writes = []writeSample{sample(time.Unix(1000, 0), 1), sample(time.Unix(1005, 0), 2)}
	index, err := m.mark(context.Background())
	require.NoError(t, err)
	require.Equal(t, 1, index)
}

func TestInventoryWritesCountsTheWritesOfTheInventoryGroup(t *testing.T) {
	families, err := parseMetrics([]byte(`# TYPE etcd_requests_total counter
etcd_requests_total{group="inventory.vexplain.bedag.ch",operation="create",resource="evidences"} 40
etcd_requests_total{group="inventory.vexplain.bedag.ch",operation="update",resource="evidences"} 2
etcd_requests_total{group="inventory.vexplain.bedag.ch",operation="get",resource="evidences"} 900
etcd_requests_total{group="inventory.vexplain.bedag.ch",operation="delete",resource="imageinventories"} 1
etcd_requests_total{group="",operation="update",resource="pods"} 70
`))
	require.NoError(t, err)

	require.Equal(t, map[string]float64{"evidences": 42, "imageinventories": 1}, inventoryWrites(families))
}

// The keys of the requests that wrote ImageInventory objects, by verb.
const (
	created = "imageinventories create"
	updated = "imageinventories/status update"
	deleted = "imageinventories delete"
)

// request returns a series of apiserver_request_total of the inventory group.
func request(code, resource, subresource, verb string, n int) string {
	return fmt.Sprintf("apiserver_request_total{code=%q,group=%q,resource=%q,subresource=%q,verb=%q} %d\n", code,
		inventoryGroup, resource, subresource, verb, n)
}

// The API server's requests that wrote to the inventory group, by resource and verb, tell creates and deletes apart
// from updates, which etcd's count of writes by resource doesn't.
func TestInventoryRequestsCountTheWritesThatSucceededByVerb(t *testing.T) {
	families, err := parseMetrics([]byte("# TYPE apiserver_request_total counter\n" +
		request("201", "imageinventories", "", "POST", 23) +
		request("200", "imageinventories", "status", "PUT", 40) +
		request("409", "imageinventories", "status", "PUT", 5) +
		request("200", "imageinventories", "status", "PATCH", 7) +
		request("200", "imageinventories", "", "DELETE", 23) +
		request("200", "evidences", "", "LIST", 900) +
		`apiserver_request_total{code="200",group="",resource="pods",subresource="",verb="PUT"} 70` + "\n"))
	require.NoError(t, err)

	require.Equal(t, map[string]float64{created: 23, updated: 40, "imageinventories/status patch": 7, deleted: 23},
		inventoryRequests(families))
}

// A phase's requests are those from its first sample to its last, also after its last write.
func TestAPhaseCountsItsRequestsFromItsFirstToItsLastSample(t *testing.T) {
	start := time.Unix(1000, 0)
	samples := []writeSample{sample(start, 10), sample(start.Add(5*time.Second), 12),
		sample(start.Add(70*time.Second), 12)}
	samples[0].byVerb = map[string]float64{created: 3, updated: 9}
	samples[1].byVerb = map[string]float64{created: 4, updated: 10}
	samples[2].byVerb = map[string]float64{created: 4, updated: 11, deleted: 1}

	require.Equal(t, map[string]float64{created: 1, updated: 2, deleted: 1}, ratesOf(samples, true).requests)
}

func TestTheSamplerKeepsThePeakAndTheLastReadingOfEachPod(t *testing.T) {
	s := &sampler{pods: map[string]*podUsage{}}
	s.record("1000 0e0a0d3f_3a12_413d_9a2a_7c669bb03ec0 5000 4000 120")
	s.record("1001 0e0a0d3f_3a12_413d_9a2a_7c669bb03ec0 7000 3000 180")
	s.record("1001 0e0a0d3f_3a12_413d_9a2a_7c669bb03ec0 cat: no such file")
	s.record("1002 0e0a0d3f_3a12_413d_9a2a_7c669bb03ec0 6000")

	u := s.pods["0e0a0d3f-3a12-413d-9a2a-7c669bb03ec0"]
	require.NotNil(t, u)
	require.Equal(t, podUsage{peakBytes: 7000, currentBytes: 3000, cpuMicros: 180, first: time.Unix(1000, 0),
		last: time.Unix(1001, 0)}, *u)
	require.Len(t, s.pods, 1)
}

func TestTheArgumentsNameTheHubTwoSpokesAndALocalRegistry(t *testing.T) {
	// args returns the command line of the values that aren't empty, and more.
	args := func(hub, spokes, registry string, more ...string) []string {
		var out []string
		for flagName, value := range map[string]string{"hub": hub, "spokes": spokes, "registry": registry} {
			if value != "" {
				out = append(out, "--"+flagName, value)
			}
		}
		return append(out, more...)
	}
	opts, err := parseArguments(args("hub", "a,b", "localhost:5001"))
	require.NoError(t, err)
	require.Equal(t, []string{"a", "b"}, opts.spokes)
	require.Equal(t, defaultIdle, opts.idle)

	for _, bad := range [][]string{
		args("", "a,b", "localhost:5001"),
		args("hub", "a", "localhost:5001"),
		args("hub", "a,", "localhost:5001"),
		args("hub", "a,b", ""),
		args("hub", "a,b", "localhost:5001", "--idle", "0s"),
	} {
		_, err := parseArguments(bad)
		require.Error(t, err, "%v", bad)
	}
}
