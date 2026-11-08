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
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/rand"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"

	"github.com/bedag/vexplain/sdk/collector"
	"github.com/bedag/vexplain/sdk/evidence"
	"github.com/bedag/vexplain/sdk/subject"
	"github.com/bedag/vexplain/sdk/workloads"
)

// The workloads collector takes the spoke role, where the pods are, and streams presence, which stays on the spoke.
// It reads pods, namespaces and nodes, the metadata of the ReplicaSets and Jobs that ResolveOwner looks through, and
// the metadata of the Deployments, StatefulSets, DaemonSets and CronJobs whose own labels it copies, in the whole
// cluster, and needs to read nothing else.
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
		{APIGroups: []string{"apps"}, Resources: []string{"replicasets", "deployments", "statefulsets", "daemonsets"},
			Verbs: listAndWatch},
		{APIGroups: []string{"batch"}, Resources: []string{"jobs", "cronjobs"}, Verbs: listAndWatch},
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

// The events name the containers of each pod, and a container that has no image ID yet is a Reference image that gives
// way to the image's digest once its pod reports one: the tombstone of the Reference image comes with the event of the
// digest.
func TestTheEventsNameTheContainersAndAPendingImageGivesWayToItsDigest(t *testing.T) {
	c, _ := startAPI(t)
	ns := newNamespace(t, nil, nil).Name
	digest := newDigest()
	// The image is this test's own, as the other tests leave pods in the cluster that no kubelet starts.
	image := repository + ":" + rand.String(6)
	starting := pod{namespace: ns, name: appPod, node: nodeAMD64, image: image}.create(t)
	reference := workloads.ReferenceDigest(image)
	sink := watch(t, newWatcher(t, nil), contextFor("vexplain-system", everything, ""))

	pending, ok := sink.inSnapshot(t, reference)
	require.True(t, ok, "the snapshot lists the image that has no digest yet")
	require.Equal(t, evidence.DigestKindReference, pending.DigestKind)
	require.Equal(t, appContainers, pending.Workloads[0].Pods[0].Containers)

	starting.Status = corev1.PodStatus{Phase: corev1.PodRunning, ContainerStatuses: []corev1.ContainerStatus{{
		Name: appContainer, Image: image, ImageID: repository + "@" + digest}}}
	require.NoError(t, c.Status().Update(t.Context(), starting))
	cached(t, starting)

	running := dataOf(t, sink.nextChange(t, digest, 0))
	require.Equal(t, "RepoDigest", running.DigestKind)
	require.Equal(t, appContainers, running.Workloads[0].Pods[0].Containers)
	require.Equal(t, change{tombstone: subject.Image(reference)}, sink.nextChange(t, reference, 0))
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

// A pod can come before the ReplicaSet that runs it is adopted by a Deployment, and its workload is the ReplicaSet until
// then. The collector watches the ReplicaSets' owner references, so the image's workload becomes the Deployment.
func TestAReplicaSetThatADeploymentAdoptsMovesItsPodsToTheDeployment(t *testing.T) {
	c, _ := startAPI(t)
	ns := newNamespace(t, nil, nil).Name
	d, rs := deployment(t, ns)
	rs.OwnerReferences = nil
	require.NoError(t, c.Update(t.Context(), rs))
	cached(t, rs)
	digest := newDigest()
	pod{namespace: ns, name: webPod, node: nodeAMD64,
		owner: controlledBy(rs, "apps/v1", "ReplicaSet")}.run(t, digest)
	sink := watch(t, newWatcher(t, nil), contextFor("vexplain-system", everything, ""))
	snapshot, ok := sink.inSnapshot(t, digest)
	require.True(t, ok)
	require.Equal(t, "ReplicaSet", snapshot.Workloads[0].Kind)

	rs.OwnerReferences = []metav1.OwnerReference{*controlledBy(d, "apps/v1", "Deployment")}
	require.NoError(t, c.Update(t.Context(), rs))

	adopted := dataOf(t, sink.nextChange(t, digest, 0))
	require.Len(t, adopted.Workloads, 1)
	require.Equal(t, "Deployment", adopted.Workloads[0].Kind)
	require.Equal(t, string(d.UID), adopted.Workloads[0].UID)
}

// A change of a workload's own labels changes what the collector says of the images that the workload runs.
func TestAChangeOfAWorkloadsOwnLabelsSendsItsImagesAgain(t *testing.T) {
	ns := newNamespace(t, nil, nil).Name
	d, rs := deployment(t, ns)
	labelled(t, d, map[string]string{partOf: shop})
	digest := newDigest()
	pod{namespace: ns, name: webPod, node: nodeAMD64, owner: controlledBy(rs, "apps/v1", "ReplicaSet")}.
		run(t, digest)
	sink := watch(t, newWatcher(t, nil), contextFor("vexplain-system", everything, workloadAttribution))
	snapshot, ok := sink.inSnapshot(t, digest)
	require.True(t, ok)
	require.Equal(t, []evidence.KeyValue{{Key: partOf, Value: shop}}, snapshot.Workloads[0].Labels)

	labelled(t, d, map[string]string{partOf: "checkout"})

	changed := dataOf(t, sink.nextChange(t, digest, 0))
	require.Equal(t, []evidence.KeyValue{{Key: partOf, Value: "checkout"}}, changed.Workloads[0].Labels)
}

// stableBuilds waits until the Watches of w build no more, and returns how often they built: the informers replay what
// they hold to a new Watch, which may build once more after its snapshot.
func stableBuilds(t *testing.T, w *Watcher) int64 {
	t.Helper()
	var builds int64
	require.Eventually(t, func() bool {
		builds = w.builds.Load()
		time.Sleep(20 * settle)
		return w.builds.Load() == builds
	}, wait, tick)
	return builds
}

// The Deployment controller writes the replicas of a rollout into a ReplicaSet's annotations at every scale, and
// presence reads none of them: such a change builds nothing. A change of the ReplicaSet's labels does.
func TestAnAnnotationOfAReplicaSetBuildsNothingAndALabelDoes(t *testing.T) {
	c, _ := startAPI(t)
	ns := newNamespace(t, nil, nil).Name
	_, rs := deployment(t, ns)
	pod{namespace: ns, name: webPod, node: nodeAMD64, owner: controlledBy(rs, "apps/v1", "ReplicaSet")}.
		run(t, newDigest())
	w := newWatcher(t, nil)
	watch(t, w, contextFor("vexplain-system", everything, ""))
	builds := stableBuilds(t, w)

	rs.Annotations = map[string]string{"deployment.kubernetes.io/desired-replicas": "3"}
	require.NoError(t, c.Update(t.Context(), rs))
	cached(t, rs)
	require.Never(t, func() bool { return w.builds.Load() != builds }, quiet, tick, "an annotation builds nothing")

	labelled(t, rs, map[string]string{appLabel: web, "tier": "frontend"})
	require.Eventually(t, func() bool { return w.builds.Load() > builds }, wait, tick, "a label builds again")
}

// Each kind that the collector reads as metadata builds again on what presence reads of it, and on nothing else:
// a namespace's labels and annotations, a node's labels, and a workload's labels and owner references.
func TestEachKindBuildsAgainOnWhatPresenceReadsOfIt(t *testing.T) {
	type part int
	const (
		labels part = iota
		annotations
		owners
	)
	before := &metav1.PartialObjectMetadata{ObjectMeta: metav1.ObjectMeta{
		Labels: map[string]string{appLabel: web}, Annotations: map[string]string{contactAnnotation: contact},
	}}
	changing := map[part]func(*metav1.PartialObjectMetadata){
		labels:      func(o *metav1.PartialObjectMetadata) { o.Labels = map[string]string{appLabel: "api"} },
		annotations: func(o *metav1.PartialObjectMetadata) { o.Annotations = map[string]string{contactAnnotation: "x"} },
		owners: func(o *metav1.PartialObjectMetadata) {
			o.OwnerReferences = []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "Deployment", Name: web, UID: "u"}}
		},
	}
	for _, tc := range []struct {
		kind    string
		changed func(old, updated any) bool
		builds  map[part]bool
	}{
		{"namespace", namespaceChanged, map[part]bool{labels: true, annotations: true}},
		{"node", nodeChanged, map[part]bool{labels: true}},
		{"workload", workloadChanged, map[part]bool{labels: true, owners: true}},
	} {
		for changed, change := range changing {
			t.Run(fmt.Sprintf("%s/%d", tc.kind, changed), func(t *testing.T) {
				after := before.DeepCopy()
				change(after)
				require.Equal(t, tc.builds[changed], tc.changed(before, after))
			})
		}
	}
}

// A collector whose service account lacks a right that it declares can't list a kind, and the informer of that kind
// never syncs. The Watch waits for the informers for Options.SyncTimeout, and then fails with Unavailable, naming the
// kind, rather than never sending its snapshot while the collector's health check says SERVING.
func TestAWatchWhoseInformerNeverSyncsFailsWithUnavailable(t *testing.T) {
	c, _ := startAPI(t)
	name := "workloads-" + rand.String(6)
	user, err := api.env.AddUser(envtest.User{Name: name}, nil)
	require.NoError(t, err)
	// Everything that the collector declares, but CronJobs.
	const withheld = "cronjobs"
	role := &rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: name}}
	for _, declared := range newWatcher(t, nil).Capabilities().Permissions {
		role.Rules = append(role.Rules, rbacv1.PolicyRule{
			APIGroups: declared.APIGroups, Verbs: declared.Verbs,
			Resources: slices.DeleteFunc(slices.Clone(declared.Resources), func(r string) bool { return r == withheld }),
		})
	}
	binding := &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: role.Name},
		RoleRef:    rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: role.Name},
		Subjects:   []rbacv1.Subject{{APIGroup: rbacv1.GroupName, Kind: rbacv1.UserKind, Name: name}},
	}
	for _, obj := range []client.Object{role, binding} {
		require.NoError(t, c.Create(t.Context(), obj))
		t.Cleanup(func() { assert.NoError(t, client.IgnoreNotFound(c.Delete(context.Background(), obj))) })
	}
	limited, err := cache.New(user.Config(), cache.Options{Scheme: clientgoscheme.Scheme})
	require.NoError(t, err)
	ctx, stop := context.WithCancel(context.Background())
	t.Cleanup(stop)
	go func() { _ = limited.Start(ctx) }()
	w := NewWatcher(limited, Options{Name: "workloads", Version: "0.1.0", Settle: settle, SyncTimeout: time.Second})

	done := make(chan error, 1)
	go func() {
		done <- w.Watch(ctx, collector.WatchRequest{Role: collector.RoleSpoke,
			Context: contextFor("vexplain-system", everything, "")}, newRecordingSink())
	}()

	select {
	case err := <-done:
		require.Equal(t, codes.Unavailable, status.Code(err), "%v", err)
		require.ErrorContains(t, err, "CronJob.batch")
	case <-time.After(wait):
		require.FailNow(t, "the Watch still waits for an informer that never syncs")
	}
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

// vexplain_containers_without_digest counts, while a Watch runs, the containers in its scope whose images have no
// digest, by why, for the cluster that its context names. Once the Watch ends, the collector knows nothing about them, and
// the gauge says nothing.
func TestTheGaugeOfContainersWithoutADigestFollowsTheWatch(t *testing.T) {
	token := rand.String(6)
	ns := newNamespace(t, map[string]string{"run": token}, nil).Name
	tagged := pod{namespace: ns, name: taggedPod, node: nodeAMD64}.runReporting(t, byTag)
	withoutDigest := NewWithoutDigest()
	registry := prometheus.NewRegistry()
	require.NoError(t, registry.Register(withoutDigest))
	scope := json.RawMessage(`{"includeNamespaces": {"matchLabels": {"run": "` + token + `"}}}`)

	_, stop := startWatch(t, newWatcher(t, withoutDigest), contextFor("vexplain-system", scope, ""))

	require.NoError(t, testutil.GatherAndCompare(registry, strings.NewReader(`
# HELP vexplain_containers_without_digest The containers in scope whose image has no digest, which presence keeps as images without one, by the cluster that its context names and by why: Unparsable for an image ID that isn't a digest, Pending for a container that has no image ID yet.
# TYPE vexplain_containers_without_digest gauge
vexplain_containers_without_digest{cluster="cluster-a",reason="Pending"} 0
vexplain_containers_without_digest{cluster="cluster-a",reason="Unparsable"} 1
`), "vexplain_containers_without_digest"))

	// The container starts to report a digest.
	c, _ := startAPI(t)
	tagged.Status.ContainerStatuses[0].ImageID = repository + "@" + newDigest()
	require.NoError(t, c.Status().Update(t.Context(), tagged))
	require.Eventually(t, func() bool { return gaugeValue(t, registry, reasonUnparsable) == 0 }, wait, tick)

	stop()
	count, err := testutil.GatherAndCount(registry, "vexplain_containers_without_digest")
	require.NoError(t, err)
	require.Zero(t, count, "no series once the Watch has ended")
	require.NoError(t, client.IgnoreNotFound(c.Delete(context.Background(), tagged)))
}

// gaugeValue returns the value of vexplain_containers_without_digest for the cluster of the tests and the reason, or -1 when
// the registry has no such series.
func gaugeValue(t *testing.T, registry *prometheus.Registry, reason string) float64 {
	t.Helper()
	families, err := registry.Gather()
	require.NoError(t, err)
	for _, family := range families {
		if family.GetName() != "vexplain_containers_without_digest" {
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
