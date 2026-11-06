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
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"k8s.io/apimachinery/pkg/util/rand"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/bedag/vexplain/sdk/collector"
	"github.com/bedag/vexplain/sdk/evidence"
	"github.com/bedag/vexplain/sdk/subject"
)

// The workloads collector takes the spoke role, where the pods are, and streams presence, which stays on the spoke.
// It reads pods, namespaces and nodes, and the metadata of ReplicaSets and Jobs, which ResolveOwner looks through, in
// the whole cluster, and needs to read nothing else.
func TestTheCapabilities(t *testing.T) {
	caps := newWatcher(t, nil).Capabilities()

	require.Equal(t, []collector.Role{collector.RoleSpoke}, caps.Roles)
	require.True(t, caps.Watches)
	require.Empty(t, caps.Operations)
	require.Len(t, caps.Produces, 1)
	require.Equal(t, evidence.TypePresence, caps.Produces[0].Type)
	require.Equal(t, collector.ScopeSpoke, caps.Produces[0].Scope)
	schema, ok := evidence.Schema(evidence.TypePresence)
	require.True(t, ok)
	require.JSONEq(t, string(schema), string(caps.Produces[0].Schema))
	listAndWatch := []string{"list", "watch"}
	require.Equal(t, []collector.Permission{
		{APIGroups: []string{""}, Resources: []string{"pods", "namespaces", "nodes"}, Verbs: listAndWatch},
		{APIGroups: []string{"apps"}, Resources: []string{"replicasets"}, Verbs: listAndWatch},
		{APIGroups: []string{"batch"}, Resources: []string{"jobs"}, Verbs: listAndWatch},
	}, caps.Permissions)
}

// A Watch starts with a snapshot of every image that runs in scope. After it, an image whose presence changed comes
// again, whole, and an image that no workload in scope runs any more comes as a tombstone.
func TestASnapshotThenAnEventForEachChangedImageAndATombstoneForOneThatRunsNoMore(t *testing.T) {
	ns := newNamespace(t, nil, nil).Name
	digest := newDigest()
	first := pod{namespace: ns, name: appPod, node: nodeAMD64}.run(t, digest)
	sink := watch(t, newWatcher(t, nil), contextFor("vexplain-system", everything, ""))

	snapshot, ok := sink.inSnapshot(t, digest)
	require.True(t, ok, "the snapshot lists the image")
	require.Len(t, snapshot.Workloads, 1)

	second := pod{namespace: ns, name: otherAppPod, node: nodeARM64}.run(t, digest)
	changed := dataOf(t, sink.nextChange(t, digest, 0))
	require.Len(t, changed.Workloads, 2, "the event lists every workload that runs the image")

	deletePod(t, first)
	require.Len(t, dataOf(t, sink.nextChange(t, digest, 1)).Workloads, 1)
	deletePod(t, second)
	require.Equal(t, change{tombstone: subject.Image(digest)}, sink.nextChange(t, digest, 2))
}

// A change that leaves the presence of every image as it was, such as a new annotation on a pod, sends nothing.
func TestAChangeThatChangesNoImageSendsNothing(t *testing.T) {
	c, _ := startAPI(t)
	ns := newNamespace(t, nil, nil).Name
	digest := newDigest()
	running := pod{namespace: ns, name: appPod, node: nodeAMD64}.run(t, digest)
	sink := watch(t, newWatcher(t, nil), contextFor("vexplain-system", everything, ""))

	running.Annotations = map[string]string{"example.com/note": "seen"}
	require.NoError(t, c.Update(t.Context(), running))
	cached(t, running)

	require.Never(t, func() bool { return len(sink.changesAbout(digest)) > 0 }, quiet, tick)
}

// A namespace that the scope starts to exclude takes its pods out of presence: an image that only they ran comes as a
// tombstone.
func TestANamespaceThatTheScopeStartsToExcludeDropsOut(t *testing.T) {
	c, _ := startAPI(t)
	namespace := newNamespace(t, nil, nil)
	digest := newDigest()
	pod{namespace: namespace.Name, name: appPod, node: nodeAMD64}.run(t, digest)
	scope := json.RawMessage(`{"excludeNamespaces": {"matchLabels": {"vexplain": "off"}}}`)
	sink := watch(t, newWatcher(t, nil), contextFor("vexplain-system", scope, ""))
	_, ok := sink.inSnapshot(t, digest)
	require.True(t, ok)

	namespace.Labels = map[string]string{"vexplain": "off"}
	require.NoError(t, c.Update(t.Context(), namespace))

	require.Equal(t, change{tombstone: subject.Image(digest)}, sink.nextChange(t, digest, 0))
}

// A context that the collector can't read fully is refused before the snapshot: a scope applied in part could report
// pods that it leaves out.
func TestAWatchRefusesAContextThatItCantRead(t *testing.T) {
	for name, c := range map[string]collector.Context{
		"a scope that isn't JSON": contextFor("vexplain-system", json.RawMessage(`{"includePods":`), ""),
		"a scope with a field that a scope lacks": contextFor("vexplain-system",
			json.RawMessage(`{"excludeNodes": {"matchLabels": {"pool": "gpu"}}}`), ""),
		"an empty exclude":            contextFor("vexplain-system", json.RawMessage(`{"excludePods": {}}`), ""),
		"allowlists that aren't JSON": contextFor("vexplain-system", everything, `{"namespaceLabels":`),
		"allowlists with a field that they lack": contextFor("vexplain-system", everything,
			`{"podAnnotations": ["contact"]}`),
	} {
		t.Run(name, func(t *testing.T) {
			sink := newRecordingSink()
			err := newWatcher(t, nil).Watch(t.Context(), collector.WatchRequest{Role: collector.RoleSpoke, Context: c}, sink)

			require.Equal(t, codes.InvalidArgument, status.Code(err), "%v", err)
			require.Empty(t, sink.snapshot)
			select {
			case <-sink.ended:
				require.Fail(t, "no snapshot ends")
			default:
			}
		})
	}
}

// vexplain_containers_skipped counts, while a Watch runs, the containers in its scope whose images it can't report,
// by why, for the cluster that its context names. Once the Watch ends, the collector knows nothing about them, and
// the gauge says nothing.
func TestTheGaugeOfSkippedContainersFollowsTheWatch(t *testing.T) {
	token := rand.String(6)
	ns := newNamespace(t, map[string]string{"run": token}, nil).Name
	tagged := pod{namespace: ns, name: taggedPod, node: nodeAMD64}.runReporting(t, byTag)
	skipped := NewSkipped()
	registry := prometheus.NewRegistry()
	require.NoError(t, registry.Register(skipped))
	scope := json.RawMessage(`{"includeNamespaces": {"matchLabels": {"run": "` + token + `"}}}`)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	sink := newRecordingSink()
	go func() {
		done <- newWatcher(t, skipped).Watch(ctx,
			collector.WatchRequest{Role: collector.RoleSpoke, Context: contextFor("vexplain-system", scope, "")}, sink)
	}()
	<-sink.ended

	require.NoError(t, testutil.GatherAndCompare(registry, strings.NewReader(`
# HELP vexplain_containers_skipped The containers in scope whose image the workloads collector can't report, by the cluster that its context names and by why: Unparsable for an image ID that isn't a digest, Pending for a container that has no image ID yet.
# TYPE vexplain_containers_skipped gauge
vexplain_containers_skipped{cluster="cluster-a",reason="Pending"} 0
vexplain_containers_skipped{cluster="cluster-a",reason="Unparsable"} 1
`), "vexplain_containers_skipped"))

	// The container starts to report a digest.
	c, _ := startAPI(t)
	tagged.Status.ContainerStatuses[0].ImageID = repository + "@" + newDigest()
	require.NoError(t, c.Status().Update(t.Context(), tagged))
	require.Eventually(t, func() bool { return gaugeValue(t, registry, reasonUnparsable) == 0 }, wait, tick)

	cancel()
	select {
	case <-done:
	case <-time.After(wait):
		require.FailNow(t, "the Watch didn't end with its context")
	}
	count, err := testutil.GatherAndCount(registry, "vexplain_containers_skipped")
	require.NoError(t, err)
	require.Zero(t, count, "no series once the Watch has ended")
	require.NoError(t, client.IgnoreNotFound(c.Delete(context.Background(), tagged)))
}

// gaugeValue returns the value of vexplain_containers_skipped for the cluster of the tests and the reason, or -1 when
// the registry has no such series.
func gaugeValue(t *testing.T, registry *prometheus.Registry, reason string) float64 {
	t.Helper()
	families, err := registry.Gather()
	require.NoError(t, err)
	for _, family := range families {
		if family.GetName() != "vexplain_containers_skipped" {
			continue
		}
		for _, m := range family.GetMetric() {
			if labelValue(m, "cluster") == cluster && labelValue(m, "reason") == reason {
				return m.GetGauge().GetValue()
			}
		}
	}
	return -1
}

// labelValue returns the value of the metric's label of the name, or "".
func labelValue(m *dto.Metric, name string) string {
	for _, label := range m.GetLabel() {
		if label.GetName() == name {
			return label.GetValue()
		}
	}
	return ""
}
