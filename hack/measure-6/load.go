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
	"fmt"
)

// imagesOf returns the numbers of the images that spoke s, 0 or 1, runs, in the order of their places in the layout:
// the shared images first, so that the one at the first place, which runs the most workloads, runs on both spokes.
func imagesOf(s int) []int {
	images := make([]int, 0, spokeImages)
	for g := spokeImages - sharedImages; g < spokeImages; g++ {
		images = append(images, g)
	}
	first := 0
	if s == 1 {
		first = spokeImages
	}
	for g := first; g < first+spokeImages-sharedImages; g++ {
		images = append(images, g)
	}
	return images
}

// layout returns how many workloads run the image at place k of a spoke's images, and in how many namespaces. The first
// image runs 28 workloads in all 10 namespaces, which makes the largest records. Each other image runs 1 to 4 workloads
// in 1 to 4 namespaces, the two counts varied apart, so that a fit can tell what a workload and a namespace each add to
// a record. The 30 places add up to 100 workloads.
func layout(k int) (workloads, namespaces int) {
	if k == 0 {
		return 28, loadNamespaces
	}
	workloads = 1 + k%4
	return workloads, min(workloads, 1+(k/4)%4)
}

// workload is a Deployment of the load.
type workload struct {
	namespace, name string
	image           int
}

// loadOf returns the Deployments of spoke s. The i-th workload of the image at place k runs in the namespace k+i%n,
// counted round the 10, where n is the image's count of namespaces.
func loadOf(s int) []workload {
	var load []workload
	for k, g := range imagesOf(s) {
		workloads, namespaces := layout(k)
		for i := range workloads {
			load = append(load, workload{namespace: namespaceOf((k + i%namespaces) % loadNamespaces),
				name: fmt.Sprintf("%s-%02d", imageName(g), i), image: g})
		}
	}
	return load
}

// rolled returns the workloads of the first spoke that the rollout changes: every second one in the order of the load,
// 50 workloads of 23 of the spoke's 30 images.
func rolled() []workload {
	var out []workload
	for j, w := range loadOf(0) {
		if j%2 == 0 {
			out = append(out, w)
		}
	}
	return out
}

func namespaceOf(i int) string { return fmt.Sprintf("measure-6-%02d", i) }

func imageName(g int) string { return fmt.Sprintf("img-%02d", g) }
