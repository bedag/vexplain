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

package spoke_test

import (
	"context"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	cloudevents "github.com/cloudevents/sdk-go/v2"
	"github.com/go-logr/logr/testr"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/rand"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	ctrlconfig "sigs.k8s.io/controller-runtime/pkg/config"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
	inventoryv1alpha1 "github.com/bedag/vexplain/api/inventory/v1alpha1"
	triagev1alpha1 "github.com/bedag/vexplain/api/triage/v1alpha1"
	internalevidence "github.com/bedag/vexplain/internal/evidence"
	"github.com/bedag/vexplain/internal/exposure"
	"github.com/bedag/vexplain/internal/inventory"
	"github.com/bedag/vexplain/internal/remote"
	"github.com/bedag/vexplain/internal/spoke"
	"github.com/bedag/vexplain/sdk/evidence"
	"github.com/bedag/vexplain/sdk/subject"
)

// The tests of the remote reports run the hub's renderer of the remote clusters in a manager, wired as the hub wires it:
// over a view of the hub's evidence, with the clusters of the Spokes. Each test is a remote cluster of a Spoke of its
// own, whose copies it puts into the hub's stores, as the copier of the cluster's spoke does. No spoke runs: the
// renderer reads only the copies. The workloads' namespaces don't exist on the hub, as they don't on a real one.

// envLabel is a label of the clusters, which the Spokes of the tests set.
const envLabel = "example.com/env"

// startRemoteHub starts the hub's renderer of the remote clusters, which stops when the test ends, unless the test
// stops it before with the func that it returns.
func startRemoteHub(t *testing.T) func() {
	t.Helper()
	cfg, direct := startAPI(t)
	mgr, err := ctrl.NewManager(cfg, ctrl.Options{
		Scheme:  scheme,
		Metrics: metricsserver.Options{BindAddress: "0"},
		Logger:  testr.New(t),
		// Each test runs a manager of its own, whose controllers have the names of the others'.
		Controller: ctrlconfig.Controller{SkipNameValidation: ptr.To(true)},
	})
	require.NoError(t, err)
	require.NoError(t, mgr.GetFieldIndexer().IndexField(context.Background(), &inventoryv1alpha1.ImageInventory{},
		inventory.ManifestDigestIndex, inventory.IndexManifestDigests))
	hubName := func() string { return localCluster }
	view := exposure.NewView(internalevidence.NewCRDStore(direct, mgr.GetCache(), hubName))
	require.NoError(t, view.SetupWithManager(mgr))
	reports := spoke.NewRemoteReports(mgr, remote.Clusters(mgr.GetClient(), view),
		inventory.NewCRDStore(mgr.GetClient(), mgr.GetCache(), hubName),
		inventory.NewCRDVerdictsStore(mgr.GetClient(), hubName), inventory.NewPlaybooks(mgr.GetClient(), mgr.GetCache()),
		inventory.NewCRDCountsStore(mgr.GetClient(), mgr.GetCache()))
	require.NoError(t, reports.SetupWithManager(mgr))
	view.OnChange(reports.Changed)
	ctx, cancel := context.WithCancel(logf.IntoContext(context.Background(), testr.New(t)))
	done := make(chan error, 1)
	go func() { done <- mgr.Start(ctx) }()
	var once sync.Once
	stop := func() {
		once.Do(func() {
			cancel()
			select {
			case err := <-done:
				assert.NoError(t, err, "the manager stops once its context ends")
			case <-time.After(wait):
				assert.Fail(t, "the manager didn't stop")
			}
		})
	}
	t.Cleanup(stop)
	return stop
}

// remoteOf is a remote cluster of a test: its Spoke on the hub, and the hub's stores, which the test puts the copies of
// the cluster's records into.
type remoteOf struct {
	t         *testing.T
	spoke     *configv1alpha1.Spoke
	name, id  string
	evidence  internalevidence.Store
	inventory inventory.Store
}

// newRemote creates the Spoke of a cluster that no other test has, with the labels, and deletes it, and the counts of
// its cluster, when the test ends.
func newRemote(t *testing.T, labels map[string]string) *remoteOf {
	t.Helper()
	_, direct := startAPI(t)
	name := "cluster-" + rand.String(6)
	t.Cleanup(func() {
		var all inventoryv1alpha1.PlaybookClusterStatusList
		require.NoError(t, direct.List(context.Background(), &all))
		for i := range all.Items {
			if all.Items[i].Spec.Cluster == name {
				assert.NoError(t, client.IgnoreNotFound(direct.Delete(context.Background(), &all.Items[i])))
			}
		}
	})
	obj := &configv1alpha1.Spoke{ObjectMeta: metav1.ObjectMeta{Name: name}, Spec: configv1alpha1.SpokeSpec{
		CredentialsSecretRef: configv1alpha1.SecretReference{Name: name + "-credentials"}}}
	for k, v := range labels {
		if obj.Spec.Labels == nil {
			obj.Spec.Labels = map[string]configv1alpha1.LabelValue{}
		}
		obj.Spec.Labels[k] = configv1alpha1.LabelValue(v)
	}
	require.NoError(t, direct.Create(t.Context(), obj))
	t.Cleanup(func() { assert.NoError(t, client.IgnoreNotFound(direct.Delete(context.Background(), obj))) })
	hubName := func() string { return localCluster }
	return &remoteOf{t: t, spoke: obj, name: name, id: name + "-id",
		evidence: internalevidence.NewCRDStore(direct, nil, hubName), inventory: inventory.NewCRDStore(direct, nil, hubName)}
}

// workload returns the Deployment of the name in the namespace of the cluster, with one pod on each of the platforms.
func (r *remoteOf) workload(namespace, name string, platforms ...string) evidence.PresenceWorkload {
	w := running(namespace, name, platforms...)
	w.Subject = subject.ForWorkload(subject.Workload{Cluster: r.name, Namespace: namespace, Group: w.APIGroup,
		Kind: w.Kind, Name: name})
	return w
}

// copy puts the event, which the source delivered in the cluster, into the hub's evidence as the copier puts its copy,
// and deletes it when the test ends.
func (r *remoteOf) copy(source string, e cloudevents.Event) {
	r.t.Helper()
	require.NoError(r.t, r.evidence.Put(context.Background(), source, collectorVersion, e, internalevidence.InCluster(r.name)))
	key := internalevidence.Key{Subject: e.Subject(), Type: e.Type(), Source: source, Cluster: r.name}
	r.t.Cleanup(func() { assert.NoError(r.t, r.evidence.Delete(context.Background(), key)) })
}

// runs copies the presence of the image of the digest that the workloads run, with the cluster's entry of the image.
func (r *remoteOf) runs(digest string, workloads ...evidence.PresenceWorkload) {
	r.t.Helper()
	r.copy(workloadsName, presenceEvent(r.t, digest, workloads...))
	require.NoError(r.t, r.inventory.Observe(context.Background(), digest, inventory.Observation{Cluster: r.name,
		ClusterID: r.id, DigestKind: inventoryv1alpha1.DigestKindRepoDigest, Repositories: []string{repository},
		NamespaceCount: 1}))
}

// facts gives the image the facts that the hub's collectors would have recorded.
func (r *remoteOf) facts(digest string, facts *inventoryv1alpha1.ImageFacts) {
	r.t.Helper()
	exists, err := r.inventory.SetFacts(context.Background(), digest, facts)
	require.NoError(r.t, err)
	require.True(r.t, exists)
}

// namespace copies the labels of the namespace of the cluster, as the copier puts them.
func (r *remoteOf) namespace(name string, labels map[string]string) {
	r.t.Helper()
	about, err := subject.Namespace(r.name, name)
	require.NoError(r.t, err)
	var data evidence.NamespaceLabels
	for k, v := range labels {
		data.Labels = append(data.Labels, evidence.KeyValue{Key: k, Value: v})
	}
	e, err := evidence.New(evidence.TypeNamespace, about, data, evidence.WithSource("/clusters/"+r.name+"/namespaces"))
	require.NoError(r.t, err)
	r.copy(internalevidence.HubSource, e)
}

// remoteCases returns the vexplain_open_case series of the namespace of the cluster, as "workload cve verdict urgency
// digest".
func remoteCases(t *testing.T, cluster, namespace string) []string {
	t.Helper()
	families, err := ctrlmetrics.Registry.Gather()
	require.NoError(t, err)
	var out []string
	for _, family := range families {
		if family.GetName() != openCaseMetric {
			continue
		}
		for _, m := range family.Metric {
			labels := map[string]string{}
			for _, l := range m.Label {
				labels[l.GetName()] = l.GetValue()
			}
			if labels["cluster"] == cluster && labels["namespace"] == namespace {
				out = append(out, strings.Join([]string{labels["workload"], labels["cve"], labels["verdict"],
					labels["urgency"], labels["digest"]}, " "))
			}
		}
	}
	return out
}

// waitForRemoteCases waits until the open cases of the namespace of the cluster are those wanted.
func waitForRemoteCases(t *testing.T, cluster, namespace string, want ...string) {
	t.Helper()
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		assert.ElementsMatch(c, want, remoteCases(t, cluster, namespace))
	}, wait, tick, "the open cases of %s in %s", namespace, cluster)
}

// openCaseMetric is the metric of the worklist, and reportMetrics are every metric that the reports give.
const openCaseMetric = "vexplain_open_case"

var reportMetrics = []string{openCaseMetric, "vexplain_findings", "vexplain_funnel", "vexplain_namespace_owner_info"}

// remoteSeries counts the series of the reports' metrics that carry the cluster's name.
func remoteSeries(t *testing.T, cluster string) int {
	t.Helper()
	families, err := ctrlmetrics.Registry.Gather()
	require.NoError(t, err)
	n := 0
	for _, family := range families {
		if !slices.Contains(reportMetrics, family.GetName()) {
			continue
		}
		for _, m := range family.Metric {
			if slices.ContainsFunc(m.Label, func(l *dto.LabelPair) bool {
				return l.GetName() == "cluster" && l.GetValue() == cluster
			}) {
				n++
			}
		}
	}
	return n
}

// teamOf returns a namespace name that no other test has.
func teamOf() string { return "team-" + rand.String(6) }

// The hub renders what the report of a remote cluster's workload would say from the copies of its records, and keeps
// it as the cluster's series: the worklist has the workload's open case under the cluster's name, and no
// ResourceReport is written, neither in the workload's namespace nor in the hub's.
func TestARemoteWorkloadGetsItsSeries(t *testing.T) {
	b := newRemote(t, nil)
	ns := teamOf()
	digest, manifest := newDigest(t), newDigest(t)
	b.runs(digest, b.workload(ns, webName, linuxAMD64))
	b.facts(digest, manifestFacts(manifest))
	putSheet(t, manifest, sheetOf(manifest, exploited()).Status)
	startRemoteHub(t)

	waitForRemoteCases(t, b.name, ns, webName+" "+caseOf(exploited(), digest))
	_, direct := startAPI(t)
	var reports triagev1alpha1.ResourceReportList
	require.NoError(t, direct.List(t.Context(), &reports))
	require.False(t, slices.ContainsFunc(reports.Items, func(r triagev1alpha1.ResourceReport) bool {
		return r.Namespace == ns || r.Namespace == operatorNamespace
	}), "no report object of a remote workload")
}

// A remote cluster's series hold the playbooks that select the cluster, by its Spoke's labels, and the workload's
// namespace, by the labels of the hub's copy of it. Without a copy of a namespace's labels, a playbook that selects
// namespaces by their labels can't be decided there: its workloads get no series until the copy comes.
func TestARemoteClustersSeriesUseTheSpokesLabelsAndNamespaceLabels(t *testing.T) {
	env, stage := "env-"+rand.String(6), "remote-"+rand.String(6)
	b := newRemote(t, map[string]string{envLabel: env})
	onlyB, otherEnv := clusterPlaybook(t, env), clusterPlaybook(t, "other-"+env)
	staged := createPlaybook(t, "stage-"+rand.String(6), stage)
	ns, unlabelled := teamOf(), teamOf()
	b.namespace(ns, map[string]string{stageKey: stage})
	digest, manifest := newDigest(t), newDigest(t)
	b.runs(digest, b.workload(ns, webName, linuxAMD64), b.workload(unlabelled, webName, linuxAMD64))
	b.facts(digest, manifestFacts(manifest))
	byCluster, byNamespace := openFinding("CVE-2026-1001", "liba"), openFinding("CVE-2026-1002", "libb")
	elsewhere := openFinding("CVE-2026-1003", "libc")
	putSheetOf(t, manifest, onlyB, playbookSheet(onlyB, manifest, byCluster).Status)
	putSheetOf(t, manifest, staged.Name, playbookSheet(staged.Name, manifest, byNamespace).Status)
	putSheetOf(t, manifest, otherEnv, playbookSheet(otherEnv, manifest, elsewhere).Status)
	startRemoteHub(t)

	waitForRemoteCases(t, b.name, ns, webName+" "+caseOf(byCluster, digest), webName+" "+caseOf(byNamespace, digest))
	require.Never(t, func() bool { return len(remoteCases(t, b.name, unlabelled)) > 0 }, quiet, tick,
		"a namespace whose labels the hub holds no copy of")

	b.namespace(unlabelled, nil)

	waitForRemoteCases(t, b.name, unlabelled, webName+" "+caseOf(byCluster, digest))
}

// clusterPlaybook creates a playbook of the images in presence that selects the clusters of the env, and deletes it when
// the test ends. It returns its name.
func clusterPlaybook(t *testing.T, env string) string {
	t.Helper()
	_, direct := startAPI(t)
	playbook := playbookOf("env-" + rand.String(6))
	playbook.Spec.Match = &configv1alpha1.PlaybookMatch{
		Clusters: &metav1.LabelSelector{MatchLabels: map[string]string{envLabel: env}}}
	require.NoError(t, direct.Create(t.Context(), playbook))
	t.Cleanup(func() { assert.NoError(t, client.IgnoreNotFound(direct.Delete(context.Background(), playbook))) })
	return playbook.Name
}

// A workload that leaves the copies of its cluster's presence takes its series with it, and so does the last one.
func TestARemoteWorkloadsSeriesGoWithIt(t *testing.T) {
	b := newRemote(t, nil)
	ns := teamOf()
	digest, manifest := newDigest(t), newDigest(t)
	web, api := b.workload(ns, webName, linuxAMD64), b.workload(ns, "api", linuxAMD64)
	b.runs(digest, web, api)
	b.facts(digest, manifestFacts(manifest))
	putSheet(t, manifest, sheetOf(manifest, exploited()).Status)
	startRemoteHub(t)
	waitForRemoteCases(t, b.name, ns, webName+" "+caseOf(exploited(), digest), "api "+caseOf(exploited(), digest))

	b.runs(digest, api)

	waitForRemoteCases(t, b.name, ns, "api "+caseOf(exploited(), digest))

	require.NoError(t, b.evidence.Delete(t.Context(), internalevidence.Key{Subject: subject.Image(digest),
		Type: evidence.TypePresence, Source: workloadsName, Cluster: b.name}))

	waitForRemoteCases(t, b.name, ns)
}

// Deleting a Spoke deletes every series of its cluster, and the counts of each playbook for it. Another cluster keeps
// its own.
func TestDeletingTheSpokeDeletesItsSeriesAndCounts(t *testing.T) {
	b, c := newRemote(t, nil), newRemote(t, nil)
	ns := teamOf()
	digest, manifest := newDigest(t), newDigest(t)
	b.runs(digest, b.workload(ns, webName, linuxAMD64))
	c.runs(digest, c.workload(ns, webName, linuxAMD64))
	b.facts(digest, manifestFacts(manifest))
	putSheet(t, manifest, sheetOf(manifest, exploited()).Status)
	startRemoteHub(t)
	waitForRemoteCases(t, b.name, ns, webName+" "+caseOf(exploited(), digest))
	waitForRemoteCases(t, c.name, ns, webName+" "+caseOf(exploited(), digest))
	require.Eventually(t, func() bool {
		return countsOfCluster(t, defaultPlaybook, b.name) != nil && countsOfCluster(t, defaultPlaybook, c.name) != nil
	}, wait, tick, "the counts of each cluster")

	_, direct := startAPI(t)
	require.NoError(t, direct.Delete(t.Context(), b.spoke))

	require.Eventually(t, func() bool {
		return remoteSeries(t, b.name) == 0 && countsOfCluster(t, defaultPlaybook, b.name) == nil
	}, wait, tick, "the series and the counts of the deleted Spoke's cluster")
	waitForRemoteCases(t, c.name, ns, webName+" "+caseOf(exploited(), digest))
	require.NotNil(t, countsOfCluster(t, defaultPlaybook, c.name))
}

// The hub renders a remote cluster's series from the copies that its stores hold, also when no spoke can be reached:
// after each start, before anything is copied anew.
func TestRemoteSeriesRenderFromTheCopiesAfterAStart(t *testing.T) {
	b := newRemote(t, nil)
	meta.SetStatusCondition(&b.spoke.Status.Conditions, metav1.Condition{Type: configv1alpha1.ConditionConnected,
		Status: metav1.ConditionFalse, Reason: configv1alpha1.ReasonUnreachable, Message: "The spoke can't be reached."})
	_, direct := startAPI(t)
	require.NoError(t, direct.Status().Update(t.Context(), b.spoke))
	ns := teamOf()
	digest, manifest := newDigest(t), newDigest(t)
	b.runs(digest, b.workload(ns, webName, linuxAMD64))
	b.facts(digest, manifestFacts(manifest))
	putSheet(t, manifest, sheetOf(manifest, exploited()).Status)
	want := webName + " " + caseOf(exploited(), digest)

	stop := startRemoteHub(t)
	waitForRemoteCases(t, b.name, ns, want)
	stop()

	startRemoteHub(t)
	waitForRemoteCases(t, b.name, ns, want)
}
