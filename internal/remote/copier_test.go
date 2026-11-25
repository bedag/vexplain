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

package remote_test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/url"
	"slices"
	"sync"
	"testing"
	"time"

	cloudevents "github.com/cloudevents/sdk-go/v2"
	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	ctrlconfig "sigs.k8s.io/controller-runtime/pkg/config"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
	inventoryv1alpha1 "github.com/bedag/vexplain/api/inventory/v1alpha1"
	configcontroller "github.com/bedag/vexplain/internal/controller/config"
	"github.com/bedag/vexplain/internal/evidence"
	"github.com/bedag/vexplain/internal/inventory"
	"github.com/bedag/vexplain/internal/metrics"
	"github.com/bedag/vexplain/internal/remote"
	"github.com/bedag/vexplain/internal/settings"
	"github.com/bedag/vexplain/internal/setup"
	"github.com/bedag/vexplain/internal/testenv"
	sdkevidence "github.com/bedag/vexplain/sdk/evidence"
	"github.com/bedag/vexplain/sdk/subject"
	"github.com/bedag/vexplain/sdk/workloads"
)

// The copier's tests copy what a spoke holds into stores of the hub. The copier reads the spoke with a token of the
// ServiceAccount that the spoke's install creates for the hub, so with the hub's rights there. Each test is a spoke of
// a name of its own, whose records on the spoke are its own, and it removes what it wrote on the suite's spoke when it
// ends: every copier reads every image's object and every Collector of the spoke.

const (
	// The collectors whose streams store presence and exposure on the spokes of the tests, and their version.
	workloadsCollector = "workloads"
	reachCollector     = "network-reach"
	collectorVersion   = "1.0.0"
	// localType is a type that a collector produces with the scope Spoke: its evidence stays in its cluster.
	localType = "ch.example.reach.v1"
	// The namespaces of the workloads of the tests, which are Deployments.
	teamA, teamB                = "team-a", "team-b"
	deploymentGroup, deployment = "apps", "Deployment"
	// timeout bounds each wait of a test, and poll is the pause between its checks.
	timeout = 30 * time.Second
	poll    = 100 * time.Millisecond
	// quiet is how long a test watches that something doesn't happen.
	quiet = 3 * time.Second
)

// digests numbers the images of the tests.
var digests int

// newDigest returns a digest that no other test uses.
func newDigest() string {
	digests++
	return fmt.Sprintf("sha256:%064x", digests)
}

// hubType and spokeType are a type that a collector produces with the scope Hub or Spoke.
func hubType(eventType string) configv1alpha1.ProducedType {
	return configv1alpha1.ProducedType{Type: eventType, Scope: configv1alpha1.EvidenceScopeHub}
}

func spokeType(eventType string) configv1alpha1.ProducedType {
	return configv1alpha1.ProducedType{Type: eventType, Scope: configv1alpha1.EvidenceScopeSpoke}
}

// workloadIn returns the subject of the Deployment of the name in team-a of the cluster.
func workloadIn(cluster, name string) string {
	return subject.ForWorkload(subject.Workload{Cluster: cluster, Namespace: teamA, Group: deploymentGroup,
		Kind: deployment, Name: name})
}

// presenceIn returns the presence of the image of the digest in the cluster, which the Deployments of the names run.
func presenceIn(t *testing.T, cluster, digest string, names ...string) cloudevents.Event {
	t.Helper()
	data := sdkevidence.Presence{DigestKind: sdkevidence.DigestKindRepoDigest}
	for _, name := range names {
		data.Workloads = append(data.Workloads, sdkevidence.PresenceWorkload{Subject: workloadIn(cluster, name),
			APIGroup: deploymentGroup, Kind: deployment, Namespace: teamA, Name: name, UID: "uid-" + name})
	}
	return newEvent(t, sdkevidence.TypePresence, subject.Image(digest), data)
}

// exposureIn returns the exposure of the Deployment of the name in the cluster, which nothing outside reaches.
func exposureIn(t *testing.T, cluster, name string) cloudevents.Event {
	t.Helper()
	return newEvent(t, sdkevidence.TypeExposure, workloadIn(cluster, name), sdkevidence.Exposure{InternalReach: "Cluster"})
}

// newEvent returns evidence of the type about the subject.
func newEvent(t *testing.T, eventType, about string, data any) cloudevents.Event {
	t.Helper()
	e, err := sdkevidence.New(eventType, about, data, sdkevidence.WithSource("/spoke/collectors"))
	require.NoError(t, err)
	return e
}

// keyIn returns the key of the record of the event that the collector streamed in the cluster.
func keyIn(cluster, collector string, e cloudevents.Event) evidence.Key {
	return evidence.Key{Subject: e.Subject(), Type: e.Type(), Source: collector, Cluster: cluster}
}

// spokeSide writes what a spoke's collectors, its sink and its presence store in its cluster, for a spoke of a name.
type spokeSide struct {
	t         *testing.T
	client    client.Client
	name, id  string
	evidence  evidence.Store
	inventory inventory.Store
	// tidy says that what the test writes goes when it ends: the suite's spoke outlives the test.
	tidy bool
}

// sideOf returns the spoke whose API server c writes, as the cluster of the name.
func sideOf(t *testing.T, c client.Client, name string) *spokeSide {
	t.Helper()
	id, err := settings.ClusterID(ctx, c)
	require.NoError(t, err)
	// The spoke's writes are no metric of the hub's.
	noCluster := func() string { return "" }
	return &spokeSide{t: t, client: c, name: name, id: id, evidence: evidence.NewCRDStore(c, nil, noCluster),
		inventory: inventory.NewCRDStore(c, nil, noCluster)}
}

// onSpoke returns the suite's spoke as the cluster of the name, and removes what the test wrote there when it ends.
func onSpoke(t *testing.T, name string) *spokeSide {
	t.Helper()
	s := sideOf(t, spoke.client, name)
	s.tidy = true
	t.Cleanup(func() {
		var records inventoryv1alpha1.EvidenceList
		require.NoError(t, spoke.client.List(ctx, &records, client.MatchingLabels{evidence.ClusterLabel: name}))
		for i := range records.Items {
			require.NoError(t, client.IgnoreNotFound(spoke.client.Delete(ctx, &records.Items[i])))
		}
		var images inventoryv1alpha1.ImageInventoryList
		require.NoError(t, spoke.client.List(ctx, &images))
		for i := range images.Items {
			require.NoError(t, client.IgnoreNotFound(spoke.client.Delete(ctx, &images.Items[i])))
		}
	})
	return s
}

// run creates the Collector of the name on the spoke, with the capabilities that its collector answered: the types
// that it produces. It goes when the test ends.
func (s *spokeSide) run(name string, produces ...configv1alpha1.ProducedType) {
	s.t.Helper()
	obj := &configv1alpha1.Collector{ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: configv1alpha1.CollectorSpec{Package: ptr.To("artifacts.example/vexplain/" + name + ":0.1.0")}}
	require.NoError(s.t, s.client.Create(ctx, obj))
	if s.tidy {
		s.t.Cleanup(func() { require.NoError(s.t, client.IgnoreNotFound(s.client.Delete(ctx, obj))) })
	}
	s.declare(name, produces...)
}

// declare records on the Collector of the name what its collector answered, as the spoke's deployer does: the types
// that it produces, its version, and that it works.
func (s *spokeSide) declare(name string, produces ...configv1alpha1.ProducedType) {
	s.t.Helper()
	require.Eventually(s.t, func() bool {
		var obj configv1alpha1.Collector
		if s.client.Get(ctx, client.ObjectKey{Name: name}, &obj) != nil {
			return false
		}
		obj.Status.Version = ptr.To(collectorVersion)
		obj.Status.Capabilities = &configv1alpha1.CollectorCapabilities{Watch: configv1alpha1.CollectorWatchSupported,
			Roles: []configv1alpha1.CollectorRole{configv1alpha1.CollectorRoleSpoke}, Produces: produces}
		meta.SetStatusCondition(&obj.Status.Conditions, metav1.Condition{Type: configv1alpha1.ConditionReady,
			Status: metav1.ConditionTrue, Reason: "Healthy", Message: "The collector serves."})
		return s.client.Status().Update(ctx, &obj) == nil
	}, timeout, poll, "record the capabilities of the Collector %s", name)
}

// stream stores the event that the collector's stream delivered for the hub, as the spoke's sink does.
func (s *spokeSide) stream(collector string, e cloudevents.Event) {
	s.t.Helper()
	require.NoError(s.t, s.evidence.Put(ctx, collector, collectorVersion, e, evidence.InCluster(s.name)))
}

// observe records the entry of the digest that the spoke's presence observed.
func (s *spokeSide) observe(digest string, obs inventory.Observation) {
	s.t.Helper()
	require.NoError(s.t, s.inventory.Observe(ctx, digest, obs))
}

// entry returns what the spoke's presence observes of an image that n Deployments run, in two namespaces, under the
// spoke's name and identity.
func (s *spokeSide) entry(n int) inventory.Observation {
	controlled := map[inventoryv1alpha1.SSVCExposure]int32{inventoryv1alpha1.SSVCExposureControlled: int32(n)}
	obs := inventory.Observation{Cluster: s.name, ClusterID: s.id, DigestKind: inventoryv1alpha1.DigestKindRepoDigest,
		Repositories: []string{"artifacts.example/team-a/app"}, Platforms: []string{"linux/amd64"}, NamespaceCount: 2,
		Exposure: inventoryv1alpha1.SSVCExposureControlled, Namespaces: []inventory.NamespaceObservation{
			{Name: teamA, ByExposure: controlled, Owner: []inventoryv1alpha1.OwnerValue{{
				Source: inventoryv1alpha1.OwnerSourceNamespaceLabel, Key: "example.com/team", Value: ptr.To("a")}}},
			{Name: teamB, ByExposure: controlled},
		}}
	for i := range n {
		obs.Workloads = append(obs.Workloads, workloads.WorkloadRef{APIGroup: deploymentGroup, Kind: deployment,
			Namespace: []string{teamA, teamB}[i%2], Name: fmt.Sprintf("app-%03d", i)})
	}
	return obs
}

// entryOf returns the spoke's own entry of the digest.
func (s *spokeSide) entryOf(digest string) *inventoryv1alpha1.ClusterPresence {
	s.t.Helper()
	return entryIn(s.t, s.inventory, s.name, digest)
}

// hubSide reads, and writes, the hub's stores as the copier of a spoke does.
type hubSide struct {
	t *testing.T
	// writer is the label of the metrics of the evidence store's writes: the hub's cluster, as the store reads it.
	writer    string
	evidence  evidence.Store
	inventory inventory.Store
}

// hubOf returns the hub's stores, which the copier of the spoke of the name writes into, and the tests read.
func hubOf(t *testing.T, name string) *hubSide {
	writer := "hub-of-" + name
	return &hubSide{t: t, writer: writer, evidence: evidence.NewCRDStore(hub.client, nil, func() string { return writer }),
		inventory: inventory.NewCRDStore(hub.client, nil, func() string { return writer })}
}

// copyOf returns the hub's copy of the record of the event that the collector streamed in the cluster, or nil.
func (h *hubSide) copyOf(cluster, collector string, e cloudevents.Event) *evidence.Record {
	h.t.Helper()
	record, err := h.evidence.Get(ctx, keyIn(cluster, collector, e))
	require.NoError(h.t, err)
	return record
}

// holds says whether the hub holds a copy of the record of the event, with the event's data.
func (h *hubSide) holds(cluster, collector string, e cloudevents.Event) bool {
	record := h.copyOf(cluster, collector, e)
	return record != nil && bytes.Equal(record.Event.Data(), e.Data())
}

// entryOf returns the hub's entry of the cluster for the digest, or nil.
func (h *hubSide) entryOf(cluster, digest string) *inventoryv1alpha1.ClusterPresence {
	h.t.Helper()
	return entryIn(h.t, h.inventory, cluster, digest)
}

// writes sums the writes of the hub's stores that a copier of the spoke of the name made: those of the evidence, and of
// the spoke's entries.
func (h *hubSide) writes(name string) float64 {
	sum := 0.0
	for _, op := range []string{"create", "update", "delete"} {
		sum += testutil.ToFloat64(metrics.EvidenceWritesTotal.WithLabelValues(h.writer, op)) +
			testutil.ToFloat64(metrics.InventoryWritesTotal.WithLabelValues(name, op))
	}
	return sum
}

// entryIn returns the store's entry of the cluster for the digest, or nil.
func entryIn(t *testing.T, store inventory.Store, cluster, digest string) *inventoryv1alpha1.ClusterPresence {
	t.Helper()
	obj, err := store.Get(ctx, digest)
	require.NoError(t, err)
	if obj == nil {
		return nil
	}
	for i := range obj.Status.Clusters {
		if obj.Status.Clusters[i].Cluster == cluster {
			return &obj.Status.Clusters[i]
		}
	}
	return nil
}

// refusals returns how many records of the cluster the hub refused for the reason.
func refusals(cluster, reason string) float64 {
	return testutil.ToFloat64(metrics.SpokeRecordsRefusedTotal.WithLabelValues(cluster, reason))
}

// asHub returns the config of the spoke's API server that cfg reaches, with a token of the hub's ServiceAccount there.
func asHub(t *testing.T, cfg *rest.Config, c client.Client) *rest.Config {
	t.Helper()
	token, err := testenv.Token(ctx, c, namespace, testenv.HubAccount, 600)
	require.NoError(t, err)
	hubCfg := rest.AnonymousClientConfig(cfg)
	hubCfg.BearerToken = token
	return hubCfg
}

// startCopier starts a cache of the suite's spoke as the hub reads it, and returns a copier of the spoke s over it,
// which copies into the stores of h, and a func that stops the cache. The cache stops when the test ends at the latest.
func startCopier(t *testing.T, s *spokeSide, h *hubSide) (*remote.Copier, func()) {
	t.Helper()
	spokeCluster, err := remote.NewCluster(asHub(t, spoke.cfg, spoke.client), s.name, scheme, logr.Discard())
	require.NoError(t, err)
	running, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = spokeCluster.Start(running)
	}()
	stop := func() {
		cancel()
		<-done
	}
	t.Cleanup(stop)
	return remote.NewCopier(s.name, s.id, h.evidence, h.inventory, spokeCluster), stop
}

// syncUntil runs rounds of the copier until done says that the hub holds what the test expects: the cache of the spoke
// sees a change on the spoke a moment after it.
func syncUntil(t *testing.T, copier *remote.Copier, done func() bool, what string) {
	t.Helper()
	require.Eventually(t, func() bool {
		round, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		return copier.Sync(round) == nil && done()
	}, timeout, poll, what)
}

// Each record that a spoke's stream stored for the hub, of a type that its Collector declares with the scope Hub, is
// copied into the hub's evidence store under the spoke's cluster, with the version of its collector. A change on the
// spoke is copied, and a record that the spoke deletes is deleted on the hub.
func TestTheHubCopiesASpokesStreamedRecordsUnderItsCluster(t *testing.T) {
	s := onSpoke(t, fmt.Sprintf("cluster-%d", spokes.Add(1)))
	h := hubOf(t, s.name)
	s.run(workloadsCollector, hubType(sdkevidence.TypePresence))
	s.run(reachCollector, hubType(sdkevidence.TypeExposure))
	digest := newDigest()
	presence, exposure := presenceIn(t, s.name, digest, "web"), exposureIn(t, s.name, "web")
	s.stream(workloadsCollector, presence)
	s.stream(reachCollector, exposure)
	copier, _ := startCopier(t, s, h)

	syncUntil(t, copier, func() bool {
		return h.holds(s.name, workloadsCollector, presence) && h.holds(s.name, reachCollector, exposure)
	}, "copy the spoke's records")
	copied := h.copyOf(s.name, workloadsCollector, presence)
	require.Equal(t, s.name, copied.Cluster)
	require.Equal(t, collectorVersion, copied.CollectorVersion)
	require.Equal(t, presence.Source(), copied.Event.Source())

	changed := presenceIn(t, s.name, digest, "web", "api")
	s.stream(workloadsCollector, changed)
	require.NoError(t, s.evidence.Delete(ctx, keyIn(s.name, reachCollector, exposure)))
	syncUntil(t, copier, func() bool {
		return h.holds(s.name, workloadsCollector, changed) && h.copyOf(s.name, reachCollector, exposure) == nil
	}, "copy the change, and the deletion")
}

// Only what a spoke's Collector declares with the scope Hub now is copied. A record of a type that stays in the spoke's
// cluster is refused and counted, and a type that the Collector no longer declares Hub, as after a downgrade, has its
// copies deleted.
func TestTheHubCopiesOnlyTypesTheSpokeDeclaresHub(t *testing.T) {
	s := onSpoke(t, fmt.Sprintf("cluster-%d", spokes.Add(1)))
	h := hubOf(t, s.name)
	s.run(reachCollector, hubType(sdkevidence.TypeExposure), spokeType(localType))
	exposure := exposureIn(t, s.name, "web")
	local := newEvent(t, localType, workloadIn(s.name, "web"), map[string]string{"reach": "team-a"})
	s.stream(reachCollector, exposure)
	s.stream(reachCollector, local)
	refused := refusals(s.name, "scope")
	copier, _ := startCopier(t, s, h)

	syncUntil(t, copier, func() bool {
		return h.holds(s.name, reachCollector, exposure) && refusals(s.name, "scope") == refused+1
	}, "copy the exposure, and refuse the local record")
	require.Nil(t, h.copyOf(s.name, reachCollector, local))

	s.declare(reachCollector, spokeType(sdkevidence.TypeExposure), spokeType(localType))
	syncUntil(t, copier, func() bool { return h.copyOf(s.name, reachCollector, exposure) == nil },
		"delete the copies of a type that the Collector no longer declares Hub")
}

// A record whose label names the spoke's cluster, and whose key another cluster, is refused and counted once. The
// copier never touches another cluster's record on the hub: neither when it refuses the spoke's record, nor when the
// spoke deletes it.
func TestARecordOfAnotherClusterIsRefusedAndCounted(t *testing.T) {
	s := onSpoke(t, fmt.Sprintf("cluster-%d", spokes.Add(1)))
	h := hubOf(t, s.name)
	s.run(reachCollector, hubType(sdkevidence.TypeExposure))
	const other = "cluster-other"
	exposure := exposureIn(t, other, "web")
	require.NoError(t, h.evidence.Put(ctx, reachCollector, collectorVersion, exposure, evidence.InCluster(other)))
	t.Cleanup(func() { require.NoError(t, h.evidence.Delete(ctx, keyIn(other, reachCollector, exposure))) })

	t.Log("storing on the spoke a record of the other cluster that says otherwise, labelled as the spoke's")
	forged := newEvent(t, sdkevidence.TypeExposure, exposure.Subject(), sdkevidence.Exposure{InternalReach: "Namespace"})
	require.NoError(t, s.evidence.Put(ctx, reachCollector, collectorVersion, forged, evidence.InCluster(other)))
	var records inventoryv1alpha1.EvidenceList
	require.NoError(t, spoke.client.List(ctx, &records, client.MatchingLabels{evidence.ClusterLabel: other}))
	require.Len(t, records.Items, 1)
	record := &records.Items[0]
	record.Labels[evidence.ClusterLabel] = s.name
	require.NoError(t, spoke.client.Update(ctx, record))

	refused := refusals(s.name, "cluster")
	copier, _ := startCopier(t, s, h)
	syncUntil(t, copier, func() bool { return refusals(s.name, "cluster") == refused+1 }, "refuse the record")
	require.NoError(t, copier.Sync(ctx))
	require.Equal(t, refused+1, refusals(s.name, "cluster"), "a record is counted once")
	require.True(t, h.holds(other, reachCollector, exposure), "the other cluster's record on the hub is unchanged")
	require.Nil(t, h.copyOf(s.name, reachCollector, exposure))

	t.Log("deleting the record on the spoke")
	require.NoError(t, spoke.client.Delete(ctx, record))
	require.Never(t, func() bool {
		return copier.Sync(ctx) != nil || !h.holds(other, reachCollector, exposure)
	}, quiet, poll, "the other cluster's record on the hub stays")
}

// An entry of an image is copied only when it is the spoke's: of its cluster, and of the identity that the hub recorded
// for it. An entry under the spoke's name with another identity is refused and counted, and so is one of another
// cluster.
func TestAnEntryOfAnotherClusterIDIsRefused(t *testing.T) {
	s := onSpoke(t, fmt.Sprintf("cluster-%d", spokes.Add(1)))
	h := hubOf(t, s.name)
	own, forged, foreign := newDigest(), newDigest(), newDigest()
	s.observe(own, s.entry(1))
	withID := s.entry(1)
	withID.ClusterID = "uid-of-another-cluster"
	s.observe(forged, withID)
	ofOther := s.entry(1)
	ofOther.Cluster = "cluster-other"
	s.observe(foreign, ofOther)
	byID, byCluster := refusals(s.name, "clusterID"), refusals(s.name, "cluster")
	copier, _ := startCopier(t, s, h)

	syncUntil(t, copier, func() bool {
		return h.entryOf(s.name, own) != nil && refusals(s.name, "clusterID") == byID+1 &&
			refusals(s.name, "cluster") == byCluster+1
	}, "copy the spoke's entry, and refuse the others")
	for _, digest := range []string{forged, foreign} {
		obj, err := h.inventory.Get(ctx, digest)
		require.NoError(t, err)
		require.Nil(t, obj, "nothing of the image %s is copied", digest)
	}
}

// A spoke whose cluster isn't the one that the hub recorded at its first contact is copied from no more, and its copies
// stay as they are, until an admin clears the identity that the hub recorded.
func TestAnIdentityChangedSpokeCopiesNothing(t *testing.T) {
	obj := newSpoke(t, spokeCredentials(t))
	s := onSpoke(t, obj.Name)
	h := hubOf(t, obj.Name)
	s.run(reachCollector, hubType(sdkevidence.TypeExposure))
	exposure := exposureIn(t, s.name, "web")
	s.stream(reachCollector, exposure)
	// A copy that the hub made before, of a workload that the spoke no longer holds.
	gone := exposureIn(t, s.name, "gone")
	require.NoError(t, h.evidence.Put(ctx, reachCollector, collectorVersion, gone, evidence.InCluster(s.name)))
	obj.Status.ClusterID = ptr.To("uid-of-another-cluster")
	require.NoError(t, hub.client.Status().Update(ctx, obj))

	runHub(t)
	deleteBeforeTheHubStops(t, obj)
	spokeWhen(t, obj.Name, conditionIs(configv1alpha1.ConditionConnected, metav1.ConditionFalse,
		configv1alpha1.ReasonIdentityChanged), "see the other identity")
	require.Never(t, func() bool {
		return h.copyOf(s.name, reachCollector, exposure) != nil || h.copyOf(s.name, reachCollector, gone) == nil
	}, quiet, poll, "the hub copies nothing, and deletes nothing")

	t.Log("clearing the identity that the hub recorded, as an admin does")
	require.Eventually(t, func() bool {
		var got configv1alpha1.Spoke
		if hub.client.Get(ctx, client.ObjectKeyFromObject(obj), &got) != nil {
			return false
		}
		got.Status.ClusterID = nil
		return hub.client.Status().Update(ctx, &got) == nil
	}, timeout, poll)
	touch(t, obj.Name)
	require.Eventually(t, func() bool {
		return h.holds(s.name, reachCollector, exposure) && h.copyOf(s.name, reachCollector, gone) == nil
	}, timeout, poll, "copy the spoke's records, and delete the copy of what it no longer holds")
}

// The spoke's entry lists the first 100 of the workloads that run the image, and its count all 250 of them: the hub's
// copy keeps the count, and is the spoke's entry, but for when the hub first saw it.
func TestACopiedEntryKeepsItsWorkloadCountAbove100(t *testing.T) {
	s := onSpoke(t, fmt.Sprintf("cluster-%d", spokes.Add(1)))
	h := hubOf(t, s.name)
	digest := newDigest()
	s.observe(digest, s.entry(250))
	want := s.entryOf(digest)
	require.Equal(t, ptr.To(int32(250)), want.WorkloadCount)
	require.Len(t, want.Workloads, 100)
	copier, _ := startCopier(t, s, h)

	syncUntil(t, copier, func() bool { return h.entryOf(s.name, digest) != nil }, "copy the entry")
	got := h.entryOf(s.name, digest)
	want.FirstSeenTime = got.FirstSeenTime
	require.Equal(t, want, got)
}

// A copier that starts, as after the hub restarts, deletes the copies of what the spoke deleted while no copier ran,
// once its cache of the spoke has synced: the copies of each source's records of each type that it doesn't hold, and
// the cluster's entries of the images that it doesn't run. A copier that runs deletes the copy of each record and entry
// that the spoke deletes.
func TestASyncDeletesWhatTheSpokeNoLongerHolds(t *testing.T) {
	s := onSpoke(t, fmt.Sprintf("cluster-%d", spokes.Add(1)))
	h := hubOf(t, s.name)
	s.run(workloadsCollector, hubType(sdkevidence.TypePresence))
	kept, deleted := newDigest(), newDigest()
	presenceKept, presenceDeleted := presenceIn(t, s.name, kept, "web"), presenceIn(t, s.name, deleted, "api")
	for digest, presence := range map[string]cloudevents.Event{kept: presenceKept, deleted: presenceDeleted} {
		s.stream(workloadsCollector, presence)
		s.observe(digest, s.entry(1))
	}
	copier, stop := startCopier(t, s, h)
	syncUntil(t, copier, func() bool {
		return h.holds(s.name, workloadsCollector, presenceKept) && h.holds(s.name, workloadsCollector, presenceDeleted) &&
			h.entryOf(s.name, kept) != nil && h.entryOf(s.name, deleted) != nil
	}, "copy the spoke's records and entries")
	stop()

	t.Log("deleting a record and an entry on the spoke while no copier runs, beside a copy that the spoke never had")
	require.NoError(t, s.evidence.Delete(ctx, keyIn(s.name, workloadsCollector, presenceDeleted)))
	require.NoError(t, s.inventory.Forget(ctx, deleted, s.name, s.id))
	stale := newDigest()
	presenceStale := presenceIn(t, s.name, stale, "old")
	require.NoError(t, h.evidence.Put(ctx, workloadsCollector, collectorVersion, presenceStale,
		evidence.InCluster(s.name)))
	require.NoError(t, h.inventory.Observe(ctx, stale, s.entry(1)))

	copier, _ = startCopier(t, s, h)
	require.NoError(t, copier.Sync(ctx))
	require.True(t, h.holds(s.name, workloadsCollector, presenceKept))
	require.NotNil(t, h.entryOf(s.name, kept))
	for _, presence := range []cloudevents.Event{presenceDeleted, presenceStale} {
		require.Nil(t, h.copyOf(s.name, workloadsCollector, presence), "the copy of %s", presence.Subject())
	}
	for _, digest := range []string{deleted, stale} {
		require.Nil(t, h.entryOf(s.name, digest), "the entry of %s", digest)
	}

	t.Log("deleting a record and an entry on the spoke while the copier runs")
	require.NoError(t, s.evidence.Delete(ctx, keyIn(s.name, workloadsCollector, presenceKept)))
	require.NoError(t, s.inventory.Forget(ctx, kept, s.name, s.id))
	syncUntil(t, copier, func() bool {
		return h.copyOf(s.name, workloadsCollector, presenceKept) == nil && h.entryOf(s.name, kept) == nil
	}, "delete the copies of what the spoke deleted")
}

// The stores write a record or an entry only when it changes, and a round of copying asks for nothing else: a round
// over what the hub copied already writes nothing, whether the copier ran before it or starts, as after the hub
// restarts.
func TestAnUnchangedSyncWritesNothing(t *testing.T) {
	s := onSpoke(t, fmt.Sprintf("cluster-%d", spokes.Add(1)))
	h := hubOf(t, s.name)
	s.run(workloadsCollector, hubType(sdkevidence.TypePresence))
	s.run(reachCollector, hubType(sdkevidence.TypeExposure))
	digest := newDigest()
	presence, exposure := presenceIn(t, s.name, digest, "web"), exposureIn(t, s.name, "web")
	s.stream(workloadsCollector, presence)
	s.stream(reachCollector, exposure)
	s.observe(digest, s.entry(3))
	copier, stop := startCopier(t, s, h)
	syncUntil(t, copier, func() bool {
		return h.holds(s.name, workloadsCollector, presence) && h.holds(s.name, reachCollector, exposure) &&
			h.entryOf(s.name, digest) != nil
	}, "copy the spoke's records and entries")

	written := h.writes(s.name)
	require.NoError(t, copier.Sync(ctx))
	require.Equal(t, written, h.writes(s.name), "a round of the copier that ran")
	stop()
	copier, _ = startCopier(t, s, h)
	require.NoError(t, copier.Sync(ctx))
	require.Equal(t, written, h.writes(s.name), "the first round of a copier that starts")
}

// A spoke that the hub can't reach keeps its copies on the hub, unchanged, and the collectors that its Spoke lists: it
// never reads as running nothing. Its Spoke says that it isn't connected. The hub reaches the spoke through a proxy,
// which the test closes, as a network that fails does.
func TestAnUnreachableSpokeKeepsItsCopies(t *testing.T) {
	network := newProxy(t, spoke.cfg.Host)
	runHub(t)
	obj := newSpoke(t, credentials(network.url, spoke.cfg.CAData, bootstrapToken(t)))
	deleteBeforeTheHubStops(t, obj)
	s := onSpoke(t, obj.Name)
	h := hubOf(t, obj.Name)
	s.run(workloadsCollector, hubType(sdkevidence.TypePresence))
	digest := newDigest()
	presence := presenceIn(t, s.name, digest, "web")
	s.stream(workloadsCollector, presence)
	s.observe(digest, s.entry(1))
	synced := spokeWhen(t, obj.Name, func(got *configv1alpha1.Spoke) bool {
		return meta.IsStatusConditionTrue(got.Status.Conditions, configv1alpha1.ConditionSynced) &&
			slices.ContainsFunc(got.Status.Collectors, func(c configv1alpha1.SpokeCollector) bool {
				return c.Name == workloadsCollector
			}) && h.holds(s.name, workloadsCollector, presence) && h.entryOf(s.name, digest) != nil
	}, "copy the spoke's records and entries")
	entry := h.entryOf(s.name, digest)

	t.Log("cutting the hub off from the spoke")
	network.close()
	touch(t, obj.Name)
	got := spokeWhen(t, obj.Name, conditionIs(configv1alpha1.ConditionConnected, metav1.ConditionFalse,
		configv1alpha1.ReasonUnreachable), "lose the spoke")
	require.False(t, meta.IsStatusConditionTrue(got.Status.Conditions, configv1alpha1.ConditionSynced))
	require.Equal(t, synced.Status.Collectors, got.Status.Collectors, "the collectors that the hub last read")
	require.Never(t, func() bool {
		return !h.holds(s.name, workloadsCollector, presence) || !equalEntries(entry, h.entryOf(s.name, digest))
	}, quiet, poll, "the copies stay as they were")
}

// proxy passes the connections to its URL on to an API server, as the network between the hub and a spoke does, until
// it closes: then the API server can't be reached through it.
type proxy struct {
	url      string
	listener net.Listener

	mu          sync.Mutex
	connections []net.Conn
}

// newProxy returns a proxy to the API server of the URL, which closes when the test ends at the latest.
func newProxy(t *testing.T, server string) *proxy {
	t.Helper()
	target, err := url.Parse(server)
	require.NoError(t, err)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	p := &proxy{url: "https://" + listener.Addr().String(), listener: listener}
	go func() {
		for {
			in, err := listener.Accept()
			if err != nil {
				return
			}
			out, err := net.Dial("tcp", target.Host)
			if err != nil {
				_ = in.Close()
				continue
			}
			p.mu.Lock()
			p.connections = append(p.connections, in, out)
			p.mu.Unlock()
			go func() { _, _ = io.Copy(out, in); _ = out.Close() }()
			go func() { _, _ = io.Copy(in, out); _ = in.Close() }()
		}
	}()
	t.Cleanup(p.close)
	return p
}

// close closes the proxy, and every connection through it.
func (p *proxy) close() {
	_ = p.listener.Close()
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, c := range p.connections {
		_ = c.Close()
	}
	p.connections = nil
}

// Deleting a Spoke deletes every copy of its cluster's records on the hub: the streamed records of each type that its
// collectors produce, and the cluster's entry of each image, with the image's object when no other cluster runs it.
func TestDeletingTheSpokeDeletesItsCopies(t *testing.T) {
	runHub(t)
	obj := newSpoke(t, spokeCredentials(t))
	deleteBeforeTheHubStops(t, obj)
	s := onSpoke(t, obj.Name)
	h := hubOf(t, obj.Name)
	s.run(workloadsCollector, hubType(sdkevidence.TypePresence))
	s.run(reachCollector, hubType(sdkevidence.TypeExposure))
	digest := newDigest()
	presence, exposure := presenceIn(t, s.name, digest, "web"), exposureIn(t, s.name, "web")
	s.stream(workloadsCollector, presence)
	s.stream(reachCollector, exposure)
	s.observe(digest, s.entry(1))
	require.Eventually(t, func() bool {
		return h.holds(s.name, workloadsCollector, presence) && h.holds(s.name, reachCollector, exposure) &&
			h.entryOf(s.name, digest) != nil
	}, timeout, poll, "copy the spoke's records and entries")

	require.NoError(t, hub.client.Delete(ctx, obj))
	require.Eventually(t, func() bool { return gone(obj) }, timeout, poll, "let the Spoke go")
	require.Nil(t, h.copyOf(s.name, workloadsCollector, presence))
	require.Nil(t, h.copyOf(s.name, reachCollector, exposure))
	image, err := h.inventory.Get(ctx, digest)
	require.NoError(t, err)
	require.Nil(t, image, "the image ran in the spoke's cluster only")
}

// The Spoke lists the spoke's collectors as the hub last read them, each produced type with the maxAge that applies to
// its evidence: the one that the Collector's spec.produces sets, else the one that the collector declares.
func TestTheSpokesCollectorsAreMirroredWithTheirEffectiveMaxAge(t *testing.T) {
	runHub(t)
	obj := newSpoke(t, spokeCredentials(t))
	deleteBeforeTheHubStops(t, obj)
	s := onSpoke(t, obj.Name)
	exposure, local := hubType(sdkevidence.TypeExposure), spokeType(localType)
	exposure.MaxAgeSeconds, local.MaxAgeSeconds = ptr.To[int64](3600), ptr.To[int64](7200)
	s.run(reachCollector, exposure, local)
	require.Eventually(t, func() bool {
		var collector configv1alpha1.Collector
		if spoke.client.Get(ctx, client.ObjectKey{Name: reachCollector}, &collector) != nil {
			return false
		}
		collector.Spec.Produces = []configv1alpha1.ProducedTypeOverride{{Type: sdkevidence.TypeExposure,
			MaxAgeSeconds: 600}}
		return spoke.client.Update(ctx, &collector) == nil
	}, timeout, poll, "override the maxAge of exposure")

	exposure.MaxAgeSeconds = ptr.To[int64](600)
	want := configv1alpha1.SpokeCollector{Name: reachCollector, Version: ptr.To(collectorVersion),
		Ready: ptr.To(metav1.ConditionTrue), Capabilities: &configv1alpha1.CollectorCapabilities{
			Roles: []configv1alpha1.CollectorRole{configv1alpha1.CollectorRoleSpoke},
			Watch: configv1alpha1.CollectorWatchSupported, Produces: []configv1alpha1.ProducedType{exposure, local}}}
	got := spokeWhen(t, obj.Name, func(got *configv1alpha1.Spoke) bool {
		return slices.ContainsFunc(got.Status.Collectors, func(c configv1alpha1.SpokeCollector) bool {
			return c.Name == reachCollector && c.Capabilities != nil && len(c.Capabilities.Produces) == 2 &&
				ptr.Deref(c.Capabilities.Produces[0].MaxAgeSeconds, 0) == 600
		})
	}, "list the spoke's collectors")
	require.Equal(t, []configv1alpha1.SpokeCollector{want}, got.Status.Collectors)
}

// equalEntries says whether two entries hold the same.
func equalEntries(a, b *inventoryv1alpha1.ClusterPresence) bool {
	return a != nil && b != nil && equality.Semantic.DeepEqual(a, b)
}

// gone says whether the Spoke is gone from the hub.
func gone(obj *configv1alpha1.Spoke) bool {
	return apierrors.IsNotFound(hub.client.Get(ctx, client.ObjectKeyFromObject(obj), &configv1alpha1.Spoke{}))
}

// runHub runs the hub's Spoke controller until the test ends, as setup.Register wires it, with the hub's stores that it
// copies into. Its finalizer must let a Spoke of the test go before it stops: deleteBeforeTheHubStops.
func runHub(t *testing.T) {
	t.Helper()
	mgr, err := ctrl.NewManager(hub.cfg, ctrl.Options{Scheme: scheme, Cache: setup.CacheOptions(namespace),
		Client: setup.ClientOptions(), Metrics: metricsserver.Options{BindAddress: "0"},
		// Each test that runs the controller starts a manager of its own.
		Controller: ctrlconfig.Controller{SkipNameValidation: ptr.To(true)}})
	require.NoError(t, err)
	writer := func() string { return "hub" }
	require.NoError(t, (&configcontroller.SpokeReconciler{
		Client:            mgr.GetClient(),
		Scheme:            mgr.GetScheme(),
		APIReader:         mgr.GetAPIReader(),
		OperatorNamespace: namespace,
		Renewer:           &remote.Renewer{Client: mgr.GetClient(), Namespace: namespace, Lifetime: time.Hour},
		Evidence:          evidence.NewCRDStore(mgr.GetClient(), mgr.GetCache(), writer),
		Inventory:         inventory.NewCRDStore(mgr.GetClient(), mgr.GetCache(), writer),
	}).SetupWithManager(mgr))
	running, cancel := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- mgr.Start(running) }()
	t.Cleanup(func() {
		cancel()
		require.NoError(t, <-done)
	})
}

// deleteBeforeTheHubStops deletes the Spoke when the test ends, and waits until the controller's finalizer has let it
// go. Call it after runHub, so that it runs before the controller stops.
func deleteBeforeTheHubStops(t *testing.T, obj *configv1alpha1.Spoke) {
	t.Helper()
	t.Cleanup(func() {
		require.NoError(t, client.IgnoreNotFound(hub.client.Delete(ctx, obj)))
		require.Eventually(t, func() bool { return gone(obj) }, timeout, poll, "let the Spoke %s go", obj.Name)
	})
}

// touch changes the labels of the Spoke of the name: a change of a Spoke brings a check of its spoke at once, where the
// controller would check it within a minute.
func touch(t *testing.T, name string) {
	t.Helper()
	require.Eventually(t, func() bool {
		var obj configv1alpha1.Spoke
		if hub.client.Get(ctx, client.ObjectKey{Name: name}, &obj) != nil {
			return false
		}
		obj.Spec.Labels = map[string]configv1alpha1.LabelValue{"example.com/touched": configv1alpha1.LabelValue(
			fmt.Sprint(time.Now().UnixNano()))}
		return hub.client.Update(ctx, &obj) == nil
	}, timeout, poll, "change the Spoke %s", name)
}

// spokeWhen waits until the Spoke of the name holds what ok says, and returns it.
func spokeWhen(t *testing.T, name string, ok func(*configv1alpha1.Spoke) bool, what string) *configv1alpha1.Spoke {
	t.Helper()
	var got configv1alpha1.Spoke
	require.Eventually(t, func() bool {
		return hub.client.Get(ctx, client.ObjectKey{Name: name}, &got) == nil && ok(&got)
	}, timeout, poll, what)
	return &got
}

// conditionIs says whether a Spoke has the condition of the type with the status and the reason.
func conditionIs(conditionType string, status metav1.ConditionStatus, reason string) func(*configv1alpha1.Spoke) bool {
	return func(got *configv1alpha1.Spoke) bool {
		c := meta.FindStatusCondition(got.Status.Conditions, conditionType)
		return c != nil && c.Status == status && c.Reason == reason
	}
}
