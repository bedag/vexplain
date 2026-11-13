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

package presence

import (
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	collectorv1alpha1 "github.com/bedag/vexplain/sdk/api/collector/v1alpha1"
	"github.com/bedag/vexplain/sdk/evidence"
)

// The measurement of presence at scale (design 5.9): 200 Deployments in 20 namespaces, each with 10 pods of two
// containers, the Deployment's own image and a proxy that every pod runs, as a mesh injects one. envtest's API server
// runs no kubelet, so the test writes the image IDs of each pod through the status subresource. It measures the
// snapshot of a Watch, as the operator counts it against its bound of 64 MiB, and the time that a build of the whole
// presence takes, which the collector does again after each change. It runs only when measureScale is set, since it
// takes longer than the other tests: docs/measurements/2026-phase3a.md has the command and the results.
const (
	measureScale = "MEASURE_PRESENCE_SCALE"

	scaleNamespaces, scaleDeployments, scalePods = 20, 10, 10
	// scaleLabel marks the namespaces of the measurement, which its scope selects alone.
	scaleLabel = "measure"
	// scaleBuilds is how many builds the test times, and scaleWorkers how many objects it writes at once.
	scaleBuilds, scaleWorkers = 20, 32
	// maxSnapshotBytes is the operator's bound of a snapshot: its messages hold at most 64 MiB together.
	maxSnapshotBytes = 64 << 20
)

func TestPresenceAtScale(t *testing.T) {
	if os.Getenv(measureScale) == "" {
		t.Skipf("set %s to measure presence at scale", measureScale)
	}
	c, informers := startAPI(t)
	ctx := t.Context()

	proxy := newDigest()
	namespaces := map[string]bool{}
	pods := make([]*corev1.Pod, 0, scaleNamespaces*scaleDeployments*scalePods)
	for n := range scaleNamespaces {
		ns := newNamespace(t, map[string]string{scaleLabel: "presence"}, nil).Name
		namespaces[ns] = true
		for d := range scaleDeployments {
			replicaSet := scaleWorkload(t, ns, fmt.Sprintf("web-%02d-%02d", n, d))
			app := newDigest()
			for p := range scalePods {
				pods = append(pods, &corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: ns, Name: fmt.Sprintf("%s-%02d", replicaSet.Name, p),
						Labels:          maps.Clone(replicaSet.Spec.Template.Labels),
						OwnerReferences: []metav1.OwnerReference{*controlledBy(replicaSet, "apps/v1", "ReplicaSet")},
					},
					Spec: corev1.PodSpec{
						NodeName: []string{nodeAMD64, nodeARM64}[p%2],
						Containers: []corev1.Container{
							{Name: appContainer, Image: repository + "@" + app},
							{Name: proxyContainer, Image: repository + "-proxy@" + proxy},
						},
					},
				})
			}
		}
	}

	// Each pod is created, and then gets the status that a kubelet would write: running, with an image ID for each
	// container, which names the digest of its image.
	start := time.Now()
	inParallel(t, pods, func(p *corev1.Pod) error {
		if err := c.Create(ctx, p); err != nil {
			return err
		}
		p.Status = corev1.PodStatus{Phase: corev1.PodRunning, ContainerStatuses: []corev1.ContainerStatus{
			{Name: appContainer, ImageID: p.Spec.Containers[0].Image},
			{Name: proxyContainer, ImageID: p.Spec.Containers[1].Image},
		}}
		return c.Status().Update(ctx, p)
	})
	require.EventuallyWithT(t, func(collect *assert.CollectT) {
		var cached corev1.PodList
		if assert.NoError(collect, informers.List(ctx, &cached)) {
			assert.Equal(collect, len(pods), runningPodsIn(namespaces, cached.Items))
		}
	}, 2*time.Minute, time.Second, "the cache holds every pod with its status")
	images := scaleNamespaces*scaleDeployments + 1
	t.Logf("load: %d namespaces, %d Deployments, %d pods of 2 containers, %d images, written in %s",
		scaleNamespaces, scaleNamespaces*scaleDeployments, len(pods), images, time.Since(start).Round(time.Millisecond))

	w := newWatcher(t, nil)
	scope, err := json.Marshal(map[string]any{"includeNamespaces": metav1.LabelSelector{
		MatchLabels: map[string]string{scaleLabel: "presence"},
	}})
	require.NoError(t, err)
	watchContext := contextFor("vexplain-system", scope, "")
	start = time.Now()
	sink := watch(t, w, watchContext)
	snapshotTime := time.Since(start)

	sink.mu.Lock()
	snapshot := slices.Clone(sink.snapshot)
	sink.mu.Unlock()
	require.Len(t, snapshot, images, "an event for each Deployment's image, and one for the proxy")
	presence, ok := presenceIn(t, snapshot, proxy)
	require.True(t, ok, "the snapshot holds the proxy")
	require.Len(t, presence.Workloads, scaleNamespaces*scaleDeployments, "every Deployment runs the proxy")
	for _, workload := range presence.Workloads {
		require.Len(t, workload.Pods, scalePods, "the pods of %s/%s", workload.Namespace, workload.Name)
	}

	// The operator counts the size of each message of a snapshot, in protocol buffers: SnapshotStart, an event for each
	// image, and SnapshotEnd.
	size := proto.Size(&collectorv1alpha1.WatchResponse{Item: &collectorv1alpha1.WatchResponse_SnapshotStart{
		SnapshotStart: &collectorv1alpha1.SnapshotStart{},
	}}) + proto.Size(&collectorv1alpha1.WatchResponse{Item: &collectorv1alpha1.WatchResponse_SnapshotEnd{
		SnapshotEnd: &collectorv1alpha1.SnapshotEnd{},
	}})
	largest := 0
	for _, e := range snapshot {
		event, err := evidence.ToProto(e)
		require.NoError(t, err)
		message := proto.Size(&collectorv1alpha1.WatchResponse{Item: &collectorv1alpha1.WatchResponse_Event{Event: event}})
		size += message
		largest = max(largest, message)
	}
	require.Less(t, size, maxSnapshotBytes, "the snapshot passes the operator's bound")
	t.Logf("snapshot: %d events, %d bytes (%.2f%% of the 64 MiB bound), the largest event %d bytes, %s from the Watch "+
		"to SnapshotEnd", len(snapshot), size, 100*float64(size)/maxSnapshotBytes, largest,
		snapshotTime.Round(time.Millisecond))

	rl, err := rulesOf(watchContext)
	require.NoError(t, err)
	took := make([]time.Duration, 0, scaleBuilds)
	for range scaleBuilds {
		start := time.Now()
		built, err := w.build(ctx, 0, cluster, rl, map[string]bool{})
		took = append(took, time.Since(start))
		require.NoError(t, err)
		require.Len(t, built, images)
	}
	slices.Sort(took)
	t.Logf("rebuild: %d builds of the whole presence, fastest %s, median %s, slowest %s", scaleBuilds,
		took[0].Round(time.Microsecond), took[len(took)/2].Round(time.Microsecond),
		took[len(took)-1].Round(time.Microsecond))
}

// scaleWorkload creates the Deployment of the name in the namespace ns, whose pods carry the label app: <name>, and
// the ReplicaSet of it that runs them, and returns the ReplicaSet.
func scaleWorkload(t *testing.T, ns, name string) *appsv1.ReplicaSet {
	t.Helper()
	c, _ := startAPI(t)
	labels := map[string]string{appLabel: name}
	template := corev1.PodTemplateSpec{
		ObjectMeta: metav1.ObjectMeta{Labels: labels},
		Spec: corev1.PodSpec{Containers: []corev1.Container{
			{Name: appContainer, Image: repository + ":1.0"}, {Name: proxyContainer, Image: repository + "-proxy:1.0"},
		}},
	}
	d := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
		Spec:       appsv1.DeploymentSpec{Selector: &metav1.LabelSelector{MatchLabels: labels}, Template: template},
	}
	require.NoError(t, c.Create(t.Context(), d))
	rs := &appsv1.ReplicaSet{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: ns, Name: name + "-5d8f9",
			OwnerReferences: []metav1.OwnerReference{*controlledBy(d, "apps/v1", "Deployment")},
		},
		Spec: appsv1.ReplicaSetSpec{Selector: d.Spec.Selector, Template: template},
	}
	require.NoError(t, c.Create(t.Context(), rs))
	return rs
}

// inParallel runs write for each pod, scaleWorkers at once, and fails the test on an error.
func inParallel(t *testing.T, pods []*corev1.Pod, write func(*corev1.Pod) error) {
	t.Helper()
	todo := make(chan *corev1.Pod)
	errs := make(chan error, len(pods))
	var wg sync.WaitGroup
	for range scaleWorkers {
		wg.Go(func() {
			for p := range todo {
				if err := write(p); err != nil {
					errs <- fmt.Errorf("pod %s/%s: %w", p.Namespace, p.Name, err)
				}
			}
		})
	}
	for _, p := range pods {
		todo <- p
	}
	close(todo)
	wg.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}
}

// runningPodsIn counts the pods of the namespaces whose containers all report an image ID.
func runningPodsIn(namespaces map[string]bool, pods []corev1.Pod) int {
	running := 0
	for _, p := range pods {
		if namespaces[p.Namespace] && len(p.Status.ContainerStatuses) > 0 && !slices.ContainsFunc(
			p.Status.ContainerStatuses, func(s corev1.ContainerStatus) bool { return s.ImageID == "" }) {
			running++
		}
	}
	return running
}
