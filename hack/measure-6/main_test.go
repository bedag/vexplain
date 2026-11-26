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
	"math"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// The load is the one of the measurement's plan: on each spoke about 100 workloads over 30 images in 10 namespaces,
// 10 of the images on both spokes, and a rollout of 50 workloads on one spoke.
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

func TestReachedAtProjectsAlongTheFittedLine(t *testing.T) {
	require.InDelta(t, 7864.32, reachedAt(0, 100, 786432), 1e-9)
	require.InDelta(t, 5232, reachedAt(1000, 100, 524200), 1e-9)
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

	r := ratesOf(samples)
	require.InDelta(t, 60, r.writes, 1e-9)
	require.Equal(t, 70*time.Second, r.duration)
	require.InDelta(t, 60.0/70, r.mean, 1e-9)
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
