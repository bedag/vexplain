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
	"bufio"
	"context"
	"fmt"
	"maps"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// podInfo is what the tool saw of a pod of the hub's operator namespace.
type podInfo struct {
	name      string
	scan      bool
	manager   bool
	resources corev1.ResourceRequirements
}

// podNames keeps the pods of the hub's operator namespace by UID, as the tool lists them every second, so that the
// cgroups that the sampler reads by UID can be named, those of the scan Jobs' pods too, which live seconds.
type podNames struct {
	mu   sync.Mutex
	byID map[string]podInfo
}

func watchPods(ctx context.Context, c *cluster) *podNames {
	names := &podNames{byID: map[string]podInfo{}}
	go func() {
		for ctx.Err() == nil {
			if pods, err := c.clientset.CoreV1().Pods(operatorNamespace).List(ctx, metav1.ListOptions{}); err == nil {
				names.mu.Lock()
				for _, pod := range pods.Items {
					_, scan := pod.Labels[scannerLabel]
					info := podInfo{name: pod.Name, scan: scan, manager: pod.Labels["control-plane"] == "controller-manager"}
					if len(pod.Spec.Containers) > 0 {
						info.resources = pod.Spec.Containers[0].Resources
					}
					names.byID[string(pod.UID)] = info
				}
				names.mu.Unlock()
			}
			select {
			case <-ctx.Done():
			case <-time.After(time.Second):
			}
		}
	}()
	return names
}

func (p *podNames) get(uid string) (podInfo, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	info, ok := p.byID[uid]
	return info, ok
}

// podUsage is what the sampler read of one pod's cgroup: its peak memory, which the kernel keeps since the pod's start,
// its memory and CPU time at the last reading, and when it read it first and last.
type podUsage struct {
	peakBytes, currentBytes, cpuMicros int64
	first, last                        time.Time
}

// sampler reads the cgroup of every pod on the hub's node every second, through one docker exec that runs while the
// tool does: its peak memory (memory.peak), its memory now (memory.current), and its CPU time (usage_usec of cpu.stat).
type sampler struct {
	mu   sync.Mutex
	pods map[string]*podUsage
}

// samplerScript prints a line for each pod's cgroup every second: the time, the pod's UID as the cgroup's name spells
// it, its peak memory, its memory now and its CPU time in microseconds. Kind's kubelet puts the pods of each QoS class
// under kubelet-kubepods.slice, the Guaranteed ones directly.
const samplerScript = `cd /sys/fs/cgroup/kubelet.slice/kubelet-kubepods.slice || exit 1
while :; do
  t=$(date +%s)
  for d in kubelet-kubepods-pod*.slice kubelet-kubepods-*.slice/kubelet-kubepods-*-pod*.slice; do
    [ -r "$d/memory.peak" ] || continue
    u=${d##*-pod}
    echo "$t ${u%.slice} $(cat "$d/memory.peak") $(cat "$d/memory.current") $(sed -n 's/^usage_usec //p' "$d/cpu.stat")"
  done
  sleep 1
done`

func startSampler(ctx context.Context, node string) (*sampler, error) {
	cmd := exec.CommandContext(ctx, "docker", "exec", node, "sh", "-c", samplerScript)
	output, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err = cmd.Start(); err != nil {
		return nil, fmt.Errorf("start the sampler of the hub's cgroups: %w", err)
	}
	s := &sampler{pods: map[string]*podUsage{}}
	go func() {
		lines := bufio.NewScanner(output)
		for lines.Scan() {
			s.record(lines.Text())
		}
		_ = cmd.Wait()
	}()
	return s, nil
}

// record keeps what a line of samplerScript says. A line that it can't read is left out.
func (s *sampler) record(line string) {
	fields := strings.Fields(line)
	if len(fields) != 5 {
		return
	}
	var numbers [4]int64
	for i, field := range append([]string{fields[0]}, fields[2:]...) {
		n, err := strconv.ParseInt(field, 10, 64)
		if err != nil {
			return
		}
		numbers[i] = n
	}
	at := time.Unix(numbers[0], 0)
	uid := strings.ReplaceAll(fields[1], "_", "-")
	s.mu.Lock()
	defer s.mu.Unlock()
	u := s.pods[uid]
	if u == nil {
		u = &podUsage{first: at}
		s.pods[uid] = u
	}
	u.peakBytes, u.currentBytes = max(u.peakBytes, numbers[1]), numbers[2]
	u.cpuMicros, u.last = max(u.cpuMicros, numbers[3]), at
}

// manager returns the name and the usage of the manager pod that the sampler read last, or nil before it read one.
func (m *measurement) manager() (string, *podUsage) {
	m.usage.mu.Lock()
	defer m.usage.mu.Unlock()
	var podName string
	var newest *podUsage
	for uid, u := range m.usage.pods {
		if info, ok := m.pods.get(uid); ok && info.manager && (newest == nil || u.last.After(newest.last)) {
			podName, newest = info.name, u
		}
	}
	if newest == nil {
		return "", nil
	}
	return podName, new(*newest)
}

func mebibytes(b int64) float64 { return float64(b) / (1 << 20) }

// ofLoad says whether a scan Job or its pod scans an image of the load: the scanner names a Job after the first 12
// digits of the image's digest, and the Job names its pods after itself.
func (m *measurement) ofLoad(scanName string) bool {
	for _, digest := range m.digests {
		if strings.HasPrefix(scanName, "scan-"+strings.TrimPrefix(digest, "sha256:")[:12]+"-") {
			return true
		}
	}
	return false
}

// reportUsage prints the memory and CPU time of each manager pod of the run, and the peak memory and CPU time of the
// scan Jobs' pods of the load's images, with their requests and limits.
func (m *measurement) reportUsage() {
	m.usage.mu.Lock()
	defer m.usage.mu.Unlock()
	var scanPeaks []int64
	var scanCPU, scanLives []time.Duration
	var resources corev1.ResourceRequirements
	others := 0
	for _, uid := range slices.Sorted(maps.Keys(m.usage.pods)) {
		u := m.usage.pods[uid]
		info, ok := m.pods.get(uid)
		switch {
		case !ok:
			continue
		case info.manager:
			m.say("\nthe manager's pod %s: memory at most %.1f MiB, %.1f MiB at the end of the run; CPU %.1f s, "+
				"seen from %s to %s\n", info.name, mebibytes(u.peakBytes), mebibytes(u.currentBytes),
				float64(u.cpuMicros)/1e6, u.first.Format(time.RFC3339), u.last.Format(time.RFC3339))
		case info.scan && m.ofLoad(info.name):
			// The sampler reads each cgroup once a second, so a pod that it read from first to last lived about a
			// second more.
			life := u.last.Sub(u.first) + time.Second
			scanPeaks = append(scanPeaks, u.peakBytes)
			scanCPU = append(scanCPU, time.Duration(u.cpuMicros)*time.Microsecond)
			scanLives = append(scanLives, life)
			resources = info.resources
			m.say("raw scanpod %s peak=%d cpu_us=%d life=%s\n", info.name, u.peakBytes, u.cpuMicros, life)
		case info.scan:
			others++
		}
	}
	slices.Sort(scanPeaks)
	slices.Sort(scanCPU)
	slices.Sort(scanLives)
	m.say("\nthe scan Jobs' pods of the load's images that the sampler saw: %d, and %d of other images; their lives on "+
		"the node: %s; memory at most: %s B; CPU time: %s; requests %s, limits %s\n", len(scanPeaks), others,
		spread(scanLives), spread(scanPeaks), spread(scanCPU), quantities(resources.Requests),
		quantities(resources.Limits))
}

// quantities formats a list of resources as name=quantity, sorted by name.
func quantities(list corev1.ResourceList) string {
	out := make([]string, 0, len(list))
	for _, resourceName := range slices.Sorted(maps.Keys(list)) {
		quantity := list[resourceName]
		out = append(out, string(resourceName)+"="+quantity.String())
	}
	if len(out) == 0 {
		return "none"
	}
	return strings.Join(out, ",")
}
