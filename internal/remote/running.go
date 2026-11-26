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
	"cmp"
	"context"
	"fmt"
	"maps"
	"slices"
	"sync"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
	"github.com/bedag/vexplain/internal/exposure"
	"github.com/bedag/vexplain/internal/settings"
	"github.com/bedag/vexplain/internal/spoke"
	sdkevidence "github.com/bedag/vexplain/sdk/evidence"
)

// RunningIn returns what runs in a remote cluster, as the hub's copies of the cluster's records say it, which the view
// holds: what each workload runs, from the copies of the cluster's presence, and how far it can be reached, from the
// copies of its exposure. copied says that the copy was current once, as the Spoke's status.lastSyncTime says, which
// outlives a restart of the hub. It knows what runs, and the exposure, once the copy was current and the view has read
// the store, whether or not the spoke can be reached: the copies stay while it can't (design of remote spokes 5.9).
// Before, as during the first round, the copies may hold some collectors' records of a workload and not yet the
// others', which would make the workload's exposure that of some collectors only.
func RunningIn(view *exposure.View, cluster string, copied bool) spoke.Running {
	return copies{view: view, cluster: cluster, copied: copied, index: &index{}}
}

// copies is what runs in a remote cluster, from the view's copies of its records.
type copies struct {
	view    *exposure.View
	cluster string
	copied  bool
	index   *index
}

// index is what runs in a cluster, by report, as IndexRunning made it of the cluster's presence at the view's count of
// its changes, at. It is built anew once the count moved, and shared by every copies of the cluster.
type index struct {
	mu      sync.Mutex
	built   bool
	at      uint64
	reports map[types.NamespacedName]spoke.RunningWorkload
}

// KnowsWhatRuns reports whether the copy was current once and the view has read the store, so that what it doesn't
// name doesn't run.
func (c copies) KnowsWhatRuns(context.Context) (bool, error) { return c.copied && c.view.Synced(), nil }

// ExposureKnown reports what KnowsWhatRuns does: the copies of exposure are copied and read with the rest.
func (c copies) ExposureKnown(ctx context.Context) (bool, error) { return c.KnowsWhatRuns(ctx) }

// RunningReports returns the namespace and name of the report of each workload that runs, sorted. The caller may
// change what it gets.
func (c copies) RunningReports() []types.NamespacedName {
	names := slices.Collect(maps.Keys(c.indexed()))
	slices.SortFunc(names, func(a, b types.NamespacedName) int {
		return cmp.Or(cmp.Compare(a.Namespace, b.Namespace), cmp.Compare(a.Name, b.Name))
	})
	return names
}

// Running returns the workload whose report has the name in the namespace, with its images, or false when none runs.
// The caller may change what it gets.
func (c copies) Running(namespace, report string) (spoke.RunningWorkload, bool) {
	running, ok := c.indexed()[types.NamespacedName{Namespace: namespace, Name: report}]
	running.Workload = cloneWorkload(running.Workload)
	running.Images = slices.Clone(running.Images)
	for i := range running.Images {
		running.Images[i].Platforms = slices.Clone(running.Images[i].Platforms)
		running.Images[i].Containers = slices.Clone(running.Images[i].Containers)
	}
	return running, ok
}

// Workloads returns the workloads that run the image of a digest, each once, sorted. The caller may change what it gets.
func (c copies) Workloads(image string) []sdkevidence.PresenceWorkload {
	presence, _ := c.view.PresenceOf(image, c.cluster)
	workloads := spoke.EachOnce(presence.Workloads)
	for i := range workloads {
		workloads[i] = cloneWorkload(workloads[i])
	}
	return workloads
}

// ExposureOf returns what a report shows of a workload's exposure, from the copies of its exposure, which passed the
// schema of exposure, as the copier checks each copy (decision 0067). The caller may change what it gets.
func (c copies) ExposureOf(w sdkevidence.PresenceWorkload) spoke.WorkloadExposure {
	return spoke.WorkloadExposureOf(c.view.ExposuresOf(w.Subject)...)
}

// indexed returns what runs in the cluster, by report, as IndexRunning makes it of the copies of the cluster's presence,
// with the workloads of each image each once and sorted, as it needs them. It builds it anew only after the cluster's
// presence changed, as the view counts it. The caller only reads what it gets.
func (c copies) indexed() map[types.NamespacedName]spoke.RunningWorkload {
	// The count is read before the presence, so that an index never outlives a change that it missed.
	at := c.view.PresenceChanges(c.cluster)
	c.index.mu.Lock()
	defer c.index.mu.Unlock()
	if c.index.built && c.index.at == at {
		return c.index.reports
	}
	images := c.view.PresenceIn(c.cluster)
	for digest, image := range images {
		image.Workloads = spoke.EachOnce(image.Workloads)
		images[digest] = image
	}
	c.index.built, c.index.at, c.index.reports = true, at, spoke.IndexRunning(images)
	return c.index.reports
}

// cloneWorkload returns a copy of a workload that shares nothing with the view.
func cloneWorkload(w sdkevidence.PresenceWorkload) sdkevidence.PresenceWorkload {
	w.Labels = slices.Clone(w.Labels)
	w.NamespaceLabels = slices.Clone(w.NamespaceLabels)
	w.NamespaceAnnotations = slices.Clone(w.NamespaceAnnotations)
	w.Pods = slices.Clone(w.Pods)
	for i := range w.Pods {
		w.Pods[i].Containers = slices.Clone(w.Pods[i].Containers)
	}
	return w
}

// Spokes returns the name of the hub's own cluster, as its OperatorConfig names it, and the Spokes whose clusters the
// hub renders: each that isn't being deleted, hasn't the name of the hub's own cluster, and that the hub didn't refuse
// as named like it (NameInUse) or as reaching it (OwnCluster), whose copies would be the hub's own, and whose series
// would take those of the hub's own cluster. A Spoke that the hub can't reach is rendered from its copies.
func Spokes(ctx context.Context, reader client.Reader) (string, []configv1alpha1.Spoke, error) {
	effective, err := settings.Load(ctx, reader)
	if err != nil {
		return "", nil, err
	}
	var list configv1alpha1.SpokeList
	if err := reader.List(ctx, &list); err != nil {
		return "", nil, fmt.Errorf("list the Spokes: %w", err)
	}
	rendered := slices.DeleteFunc(list.Items, func(s configv1alpha1.Spoke) bool {
		connected := meta.FindStatusCondition(s.Status.Conditions, configv1alpha1.ConditionConnected)
		refused := connected != nil && connected.Status == metav1.ConditionFalse &&
			(connected.Reason == configv1alpha1.ReasonNameInUse || connected.Reason == configv1alpha1.ReasonOwnCluster)
		return refused || s.Name == effective.ClusterName || !s.DeletionTimestamp.IsZero()
	})
	return effective.ClusterName, rendered, nil
}

// Clusters returns the remote clusters that the hub renders, as spoke.NewRemoteReports reads them: the cluster of each
// Spoke of Spokes, with the Spoke's labels, what runs in it from the view, as RunningIn says, and the labels of its
// namespaces from the view's copies. A cluster is copied while its Spoke records both its identity and a time of a
// current copy: an admin who accepts another cluster clears the identity, and the hub's next contact records the other
// cluster with no such time, so that the mix of the two clusters' copies is never rendered. Each cluster keeps one
// index of what runs in it from call to call, until the Spoke goes.
func Clusters(reader client.Reader, view *exposure.View) func(ctx context.Context) ([]spoke.RemoteCluster, error) {
	var mu sync.Mutex
	indexes := map[string]*index{}
	return func(ctx context.Context) ([]spoke.RemoteCluster, error) {
		_, spokes, err := Spokes(ctx, reader)
		if err != nil {
			return nil, err
		}
		mu.Lock()
		defer mu.Unlock()
		listed := make(map[string]*index, len(spokes))
		clusters := make([]spoke.RemoteCluster, 0, len(spokes))
		for _, s := range spokes {
			name := s.Name
			labels := make(map[string]string, len(s.Spec.Labels))
			for k, v := range s.Spec.Labels {
				labels[k] = string(v)
			}
			idx := indexes[name]
			if idx == nil {
				idx = &index{}
			}
			listed[name] = idx
			copied := s.Status.ClusterID != nil && s.Status.LastSyncTime != nil
			running := copies{view: view, cluster: name, copied: copied, index: idx}
			clusters = append(clusters, spoke.RemoteCluster{Name: name, Labels: labels, Running: running,
				NamespaceLabels: func(namespace string) (map[string]string, bool) {
					return view.NamespaceLabels(name, namespace)
				}})
		}
		indexes = listed
		return clusters, nil
	}
}
