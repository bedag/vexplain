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
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	cloudevents "github.com/cloudevents/sdk-go/v2"
	"github.com/go-logr/logr"
	"github.com/go-logr/logr/funcr"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/rest"
	toolscache "k8s.io/client-go/tools/cache"
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
	// namespaceReach is the internal reach of a workload that only its own namespace reaches, and clusterReach of one
	// that the whole cluster reaches.
	namespaceReach = "Namespace"
	clusterReach   = "Cluster"
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
	return newEvent(t, sdkevidence.TypeExposure, workloadIn(cluster, name), sdkevidence.Exposure{InternalReach: clusterReach})
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
	copier, _, stop := startCopierOver(t, s, h)
	return copier, stop
}

// startCopierOver is startCopier, which also returns the cache of the spoke that the copier reads.
func startCopierOver(t *testing.T, s *spokeSide, h *hubSide) (*remote.Copier, client.Reader, func()) {
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
	return remote.NewCopier(s.name, s.id, h.evidence, h.inventory, spokeCluster), spokeCluster.GetCache(), stop
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
	forged := newEvent(t, sdkevidence.TypeExposure, exposure.Subject(), sdkevidence.Exposure{InternalReach: namespaceReach})
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
// collectors produce, the labels of its namespaces, and the cluster's entry of each image, with the image's object when
// no other cluster runs it. The cluster's counts go too, and so do the series of the store's writes of its entries,
// which the deletion of the copies wrote last.
func TestDeletingTheSpokeDeletesItsCopies(t *testing.T) {
	runHub(t)
	obj := newSpoke(t, spokeCredentials(t))
	deleteBeforeTheHubStops(t, obj)
	s := onSpoke(t, obj.Name)
	h := hubOf(t, obj.Name)
	s.run(workloadsCollector, hubType(sdkevidence.TypePresence))
	s.run(reachCollector, hubType(sdkevidence.TypeExposure))
	digest, shared := newDigest(), newDigest()
	presence, exposure := presenceIn(t, s.name, digest, "web"), exposureIn(t, s.name, "web")
	s.stream(workloadsCollector, presence)
	s.stream(reachCollector, exposure)
	s.observe(digest, s.entry(1))
	s.observe(shared, s.entry(1))
	// The hub's own cluster streams the same collector's exposure, and runs the shared image too.
	ownExposure := hubsOwn(t, h, shared)
	playbook := countedPlaybook(t, s.name, settings.DefaultClusterName)
	require.Eventually(t, func() bool {
		return h.holds(s.name, workloadsCollector, presence) && h.holds(s.name, reachCollector, exposure) &&
			h.entryOf(s.name, digest) != nil && h.entryOf(s.name, shared) != nil && h.labelsOf(s.name, namespace) != nil
	}, timeout, poll, "copy the spoke's records, entries and namespaces")
	require.Positive(t, storeSeries(t, s.name), "the hub counts its writes of the spoke's entries")

	require.NoError(t, hub.client.Delete(ctx, obj))
	require.Eventually(t, func() bool { return gone(obj) }, timeout, poll, "let the Spoke go")
	require.Nil(t, h.copyOf(s.name, workloadsCollector, presence))
	require.Nil(t, h.copyOf(s.name, reachCollector, exposure))
	require.Nil(t, h.labelsOf(s.name, namespace), "the labels of the spoke's operator namespace")
	image, err := h.inventory.Get(ctx, digest)
	require.NoError(t, err)
	require.Nil(t, image, "the image ran in the spoke's cluster only")
	require.Nil(t, h.entryOf(s.name, shared))
	require.True(t, h.holds(settings.DefaultClusterName, reachCollector, ownExposure), "the hub's own record stays")
	require.NotNil(t, h.entryOf(settings.DefaultClusterName, shared), "the hub's own entry stays")
	require.Zero(t, storeSeries(t, s.name), "the store's series of the cluster")
	require.Equal(t, []string{settings.DefaultClusterName}, countedClusters(t, playbook), "only the hub's own counts stay")
}

// countedPlaybook creates a Playbook of the images in presence with counts for each of the clusters, as their renderers
// write them, and deletes them when the test ends: no garbage collector deletes the counts with their Playbook here.
func countedPlaybook(t *testing.T, clusters ...string) string {
	t.Helper()
	playbook := &configv1alpha1.Playbook{ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf("counted-%d", spokes.Add(1))},
		Spec: configv1alpha1.PlaybookSpec{Subjects: configv1alpha1.PlaybookSource{Type: sdkevidence.TypePresence},
			Findings: configv1alpha1.PlaybookFindings{Type: ptr.To(sdkevidence.TypeFindings)},
			Pipeline: []configv1alpha1.PlaybookStep{{Rule: "known-exploited"}}}}
	require.NoError(t, hub.client.Create(ctx, playbook))
	counts := inventory.NewCRDCountsStore(hub.client, nil)
	for _, cluster := range clusters {
		require.NoError(t, counts.Put(ctx, playbook.Name, playbook.UID, cluster, inventory.Tally{Judged: 1}))
	}
	t.Cleanup(func() {
		for _, cluster := range clusters {
			require.NoError(t, counts.Delete(ctx, playbook.Name, cluster))
		}
		require.NoError(t, client.IgnoreNotFound(hub.client.Delete(ctx, playbook)))
	})
	return playbook.Name
}

// countedClusters returns the clusters that the playbook has counts for, sorted.
func countedClusters(t *testing.T, playbook string) []string {
	t.Helper()
	list, err := inventory.NewCRDCountsStore(hub.client, nil).List(ctx, playbook)
	require.NoError(t, err)
	clusters := make([]string, 0, len(list))
	for _, counts := range list {
		clusters = append(clusters, counts.Spec.Cluster)
	}
	return clusters
}

// storeSeries counts the series of the inventory store's writes, and of the sizes of what it wrote, under the cluster's
// name.
func storeSeries(t *testing.T, cluster string) int {
	t.Helper()
	n := 0
	for _, c := range []prometheus.Collector{metrics.InventoryWritesTotal, metrics.InventoryObjectBytes} {
		collected := make(chan prometheus.Metric)
		go func() {
			c.Collect(collected)
			close(collected)
		}()
		for m := range collected {
			var written dto.Metric
			if m.Write(&written) != nil {
				continue
			}
			for _, l := range written.GetLabel() {
				if l.GetName() == "cluster" && l.GetValue() == cluster {
					n++
				}
			}
		}
	}
	return n
}

// The hub copies the labels of each of a spoke's namespaces into a record of its own, about namespace/<spoke>/<name>,
// from the source vexplain and under the spoke's cluster. A change of the labels rewrites the record, and a namespace
// that the spoke deletes has its record deleted. A namespace of more labels than a record holds is refused and counted,
// never cut, and copied once it fits. The records are the hub's own: a Collector of the spoke that has the name of their
// source has its record refused, and counted, and none of it copied over them.
func TestTheHubCopiesTheSpokesNamespaceLabels(t *testing.T) {
	s := onSpoke(t, fmt.Sprintf("cluster-%d", spokes.Add(1)))
	h := hubOf(t, s.name)
	apps := s.namespace("apps", map[string]string{teamLabel: "a"})
	many := map[string]string{}
	for i := range 1000 {
		many[fmt.Sprintf("example.com/label-%04d", i)] = "v"
	}
	crowded := s.namespace("crowded", many)
	require.Len(t, crowded.Labels, 1001, "the API server adds kubernetes.io/metadata.name")
	about, err := subject.Namespace(s.name, apps.Name)
	require.NoError(t, err)
	s.run(evidence.HubSource, hubType(sdkevidence.TypeNamespace))
	s.stream(evidence.HubSource, newEvent(t, sdkevidence.TypeNamespace, about, sdkevidence.NamespaceLabels{
		Labels: []sdkevidence.KeyValue{{Key: teamLabel, Value: "forged"}}}))
	invalid := refusals(s.name, "invalid")
	copier, _ := startCopier(t, s, h)

	syncUntil(t, copier, func() bool {
		return maps.Equal(apps.Labels, h.labelsOf(s.name, apps.Name)) && refusals(s.name, "invalid") == invalid+2
	}, "copy the labels, and refuse the crowded namespace and the Collector's record")
	require.Nil(t, h.labelsOf(s.name, crowded.Name), "nothing of the crowded namespace is copied")

	t.Log("changing a label, and taking one from the crowded namespace")
	apps.Labels[teamLabel] = "b"
	delete(crowded.Labels, "example.com/label-0000")
	for _, obj := range []*corev1.Namespace{apps, crowded} {
		require.NoError(t, spoke.client.Update(ctx, obj))
	}
	syncUntil(t, copier, func() bool {
		return maps.Equal(apps.Labels, h.labelsOf(s.name, apps.Name)) &&
			maps.Equal(crowded.Labels, h.labelsOf(s.name, crowded.Name))
	}, "copy the change, and the namespace that fits")

	t.Log("deleting the namespace on the spoke")
	s.deleteNamespace(apps.Name)
	syncUntil(t, copier, func() bool { return h.labelsOf(s.name, apps.Name) == nil }, "delete the copy")
}

// A copier that starts, as after the hub restarts, deletes the hub's copy of each namespace that the spoke deleted while
// no copier ran: its first round reads every namespace, and keeps the copies of those that the spoke holds alone.
func TestAFullRoundDeletesTheCopiesOfNamespacesThatTheSpokeNoLongerHolds(t *testing.T) {
	s := onSpoke(t, fmt.Sprintf("cluster-%d", spokes.Add(1)))
	h := hubOf(t, s.name)
	apps := s.namespace("apps", map[string]string{teamLabel: "a"})
	gone, err := subject.Namespace(s.name, s.name+"-gone")
	require.NoError(t, err)
	copied, err := sdkevidence.New(sdkevidence.TypeNamespace, gone, sdkevidence.NamespaceLabels{
		Labels: []sdkevidence.KeyValue{{Key: teamLabel, Value: "a"}}}, sdkevidence.WithSource("/clusters/"+s.name+"/namespaces"))
	require.NoError(t, err)
	require.NoError(t, h.evidence.Put(ctx, evidence.HubSource, "v1alpha1", copied, evidence.InCluster(s.name)))
	require.NotNil(t, h.labelsOf(s.name, s.name+"-gone"), "the hub's copy, from before the start")
	copier, _ := startCopier(t, s, h)

	syncUntil(t, copier, func() bool {
		return h.labelsOf(s.name, s.name+"-gone") == nil && maps.Equal(apps.Labels, h.labelsOf(s.name, apps.Name))
	}, "delete the copy of the namespace that the spoke deleted, and copy the one that it holds")
}

// The bound of a namespace's labels fits a record: 1000 labels of Kubernetes' longest key and value pass the copier's
// check, and take less than the evidence store's default cap even uncompressed. One more label is refused.
func TestTheLongestLabelsOfANamespaceFitARecord(t *testing.T) {
	about, err := subject.Namespace("cluster-a", "team-a")
	require.NoError(t, err)
	var labels sdkevidence.NamespaceLabels
	for i := range 1001 {
		// A prefix of 253 characters, a slash, and a name of 63.
		labels.Labels = append(labels.Labels, sdkevidence.KeyValue{Key: fmt.Sprintf("%0253d/%063d", i, i),
			Value: strings.Repeat("v", 63)})
	}
	crowded := newEvent(t, sdkevidence.TypeNamespace, about, labels)
	require.Error(t, remote.CheckCore(crowded), "1001 labels")

	labels.Labels = labels.Labels[:1000]
	longest := newEvent(t, sdkevidence.TypeNamespace, about, labels)
	require.NoError(t, remote.CheckCore(longest))
	require.Less(t, len(longest.Data()), evidence.DefaultMaxCompressedBytes)
}

// teamLabel is a label of a namespace that names its team.
const teamLabel = "example.com/team"

// namespace creates on the spoke the namespace of the name, after the spoke's own, with the labels, and returns it as
// the API server stored it, with the label kubernetes.io/metadata.name too. It goes when the test ends.
func (s *spokeSide) namespace(name string, labels map[string]string) *corev1.Namespace {
	s.t.Helper()
	obj := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: s.name + "-" + name, Labels: labels}}
	require.NoError(s.t, s.client.Create(ctx, obj))
	s.t.Cleanup(func() { s.deleteNamespace(obj.Name) })
	return obj
}

// deleteNamespace deletes the namespace of the name on the spoke, and waits until it is gone. envtest runs no namespace
// controller, which removes the finalizer of a deleted namespace once it is empty, so the test removes it.
func (s *spokeSide) deleteNamespace(name string) {
	s.t.Helper()
	require.Eventually(s.t, func() bool {
		var obj corev1.Namespace
		switch err := s.client.Get(ctx, client.ObjectKey{Name: name}, &obj); {
		case apierrors.IsNotFound(err):
			return true
		case err == nil && obj.DeletionTimestamp.IsZero():
			_ = s.client.Delete(ctx, &obj)
		case err == nil:
			obj.Spec.Finalizers = nil
			_ = s.client.SubResource("finalize").Update(ctx, &obj)
		}
		return false
	}, timeout, poll, "delete the namespace %s", name)
}

// labelsOf returns the labels of the namespace of the cluster as the hub's copy holds them, or nil when it holds none.
func (h *hubSide) labelsOf(cluster, namespace string) map[string]string {
	h.t.Helper()
	about, err := subject.Namespace(cluster, namespace)
	require.NoError(h.t, err)
	record, err := h.evidence.Get(ctx, evidence.Key{Subject: about, Type: sdkevidence.TypeNamespace,
		Source: evidence.HubSource, Cluster: cluster})
	require.NoError(h.t, err)
	if record == nil {
		return nil
	}
	var data sdkevidence.NamespaceLabels
	require.NoError(h.t, json.Unmarshal(record.Event.Data(), &data))
	labels := map[string]string{}
	for _, l := range data.Labels {
		labels[l.Key] = l.Value
	}
	return labels
}

// hubsOwn stores, beside the copies of h, a record and an entry of the hub's own cluster, as the hub's own collectors and
// presence keep them: the exposure that reachCollector streams of a workload, which it returns, and the entry of the
// image of the digest. Both go when the test ends.
func hubsOwn(t *testing.T, h *hubSide, digest string) cloudevents.Event {
	t.Helper()
	own := settings.DefaultClusterName
	id, err := settings.ClusterID(ctx, hub.client)
	require.NoError(t, err)
	exposure := newEvent(t, sdkevidence.TypeExposure, workloadIn(own, "web"), sdkevidence.Exposure{
		InternalReach: namespaceReach})
	require.NoError(t, h.evidence.Put(ctx, reachCollector, collectorVersion, exposure, evidence.InCluster(own)))
	entry := (&spokeSide{name: own, id: id}).entry(2)
	require.NoError(t, h.inventory.Observe(ctx, digest, entry))
	t.Cleanup(func() {
		require.NoError(t, h.evidence.Delete(ctx, keyIn(own, reachCollector, exposure)))
		require.NoError(t, h.inventory.Forget(ctx, digest, own, ""))
	})
	return exposure
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

// A Spoke named like the hub's own cluster would have its copies take the keys of the hub's own records and entries:
// the copies would overwrite them, and their deletion delete them, with the facts of an image that ran nowhere else. The
// hub refuses such a Spoke: it contacts the spoke not at all, copies nothing and deletes nothing, also when the Spoke is
// deleted.
func TestASpokeNamedLikeTheHubsOwnClusterIsRefused(t *testing.T) {
	own := settings.DefaultClusterName
	s := onSpoke(t, own)
	h := hubOf(t, own)
	s.run(reachCollector, hubType(sdkevidence.TypeExposure))
	digest := newDigest()
	s.stream(reachCollector, exposureIn(t, own, "web"))
	s.observe(digest, s.entry(1))
	ownExposure := hubsOwn(t, h, digest)
	ownEntry := h.entryOf(own, digest)
	unchanged := func() bool {
		return h.holds(own, reachCollector, ownExposure) && equalEntries(ownEntry, h.entryOf(own, digest))
	}
	playbook := countedPlaybook(t, own)

	runHub(t)
	obj := namedSpoke(t, own, spokeCredentials(t))
	deleteBeforeTheHubStops(t, obj)
	got := spokeWhen(t, own, conditionIs(configv1alpha1.ConditionConnected, metav1.ConditionFalse,
		configv1alpha1.ReasonNameInUse), "refuse the Spoke")
	require.True(t, meta.IsStatusConditionTrue(got.Status.Conditions, configv1alpha1.ConditionStalled))
	require.Nil(t, got.Status.ClusterID, "the hub doesn't contact the spoke")
	require.Never(t, func() bool { return !unchanged() }, quiet, poll, "the hub's own record and entry stay as they are")

	require.NoError(t, hub.client.Delete(ctx, obj))
	require.Eventually(t, func() bool { return gone(obj) }, timeout, poll, "let the Spoke go")
	require.True(t, unchanged(), "deleting the Spoke leaves the hub's own record and entry")
	require.Positive(t, storeSeries(t, own), "and the series of the hub's own writes")
	require.Equal(t, []string{own}, countedClusters(t, playbook), "and the hub's own counts")
}

// A Spoke whose Secret reaches the hub's own cluster under another name is refused, as one named like it is: its copies
// would carry the hub's own identity, and they and the hub's own entries would replace each other. The hub starts no
// copier and renews no token there, and records no identity, so that the Secret, once it names the right spoke, makes
// a first contact.
func TestASpokeOfTheHubsOwnClusterIsRefused(t *testing.T) {
	runHub(t)
	obj := newSpoke(t, hubCredentials(t))
	deleteBeforeTheHubStops(t, obj)
	got := spokeWhen(t, obj.Name, conditionIs(configv1alpha1.ConditionConnected, metav1.ConditionFalse,
		configv1alpha1.ReasonOwnCluster), "refuse the Spoke")
	require.True(t, meta.IsStatusConditionTrue(got.Status.Conditions, configv1alpha1.ConditionStalled))
	require.Nil(t, got.Status.ClusterID, "the hub records no identity")
	require.Zero(t, starts(obj.Name), "the hub starts no cache of its own cluster")
	require.Empty(t, ownToken(obj), "the hub renews no token on its own cluster")

	t.Log("pointing the admin's Secret at the spoke")
	admin := adminSecret(t, obj)
	admin.Data = spokeCredentials(t)
	require.NoError(t, hub.client.Update(ctx, admin))
	touch(t, obj.Name)
	got = spokeWhen(t, obj.Name, conditionIs(configv1alpha1.ConditionConnected, metav1.ConditionTrue,
		configv1alpha1.ReasonConnected), "contact the spoke for the first time")
	id, err := clusterID(spoke.cfg)
	require.NoError(t, err)
	require.Equal(t, ptr.To(id), got.Status.ClusterID)
}

// The hub reads the identity of its own cluster once, not at each check of each Spoke: the UID of kube-system doesn't
// change while the cluster lives.
func TestTheHubReadsItsOwnIdentityOnce(t *testing.T) {
	reads := &namespaceReads{}
	runHub(t, func(r *configcontroller.SpokeReconciler) {
		reads.Reader, r.APIReader = r.APIReader, reads
	})
	obj := newSpoke(t, spokeCredentials(t))
	deleteBeforeTheHubStops(t, obj)
	spokeWhen(t, obj.Name, conditionIs(configv1alpha1.ConditionSynced, metav1.ConditionTrue,
		configv1alpha1.ReasonSynced), "copy the spoke's records")
	for range 3 {
		touch(t, obj.Name)
		spokeWhen(t, obj.Name, func(got *configv1alpha1.Spoke) bool {
			return ptr.Deref(got.Status.ObservedGeneration, 0) == got.Generation
		}, "check the spoke")
	}
	require.Equal(t, int64(1), reads.n.Load(), "the hub read its own identity once")
}

// namespaceReads is a reader that counts the namespaces that it reads.
type namespaceReads struct {
	client.Reader
	n atomic.Int64
}

// Get reads the object, and counts it if it is a namespace.
func (r *namespaceReads) Get(ctx context.Context, key client.ObjectKey, obj client.Object,
	opts ...client.GetOption) error {
	if _, ok := obj.(*corev1.Namespace); ok {
		r.n.Add(1)
	}
	return r.Reader.Get(ctx, key, obj, opts...)
}

// A check verifies the spoke with the config that the seam gives, and the cache that it starts runs on that config, not
// on one that a second read of the Secret gives: a Secret that changed in between would have the cache read a server
// that the check never saw, under the identity that it found there.
func TestTheCacheStartsOnTheConfigThatTheCheckVerified(t *testing.T) {
	name := fmt.Sprintf("cluster-%d", spokes.Add(1))
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	elsewhere := "https://" + listener.Addr().String()
	require.NoError(t, listener.Close())
	flip := &secretFlip{name: name + "-credentials", server: elsewhere}
	runHub(t, func(r *configcontroller.SpokeReconciler) {
		flip.Reader, r.APIReader = r.APIReader, flip
	})
	obj := namedSpoke(t, name, spokeCredentials(t))
	deleteBeforeTheHubStops(t, obj)

	require.Eventually(t, func() bool { return starts(name) > 0 }, timeout, poll, "start a cache of the spoke")
	require.Equal(t, spoke.cfg.Host, startedOn(name)[0], "the server that the check verified")
	spokeWhen(t, name, conditionIs(configv1alpha1.ConditionConnected, metav1.ConditionFalse,
		configv1alpha1.ReasonUnreachable), "check the changed Secret")
	require.NotContains(t, startedOn(name), elsewhere)
}

// secretFlip reads as its Reader does, but for the admin's Secret of the name, which names server from its second read
// on, as a Secret that changes right after a check read it.
type secretFlip struct {
	client.Reader
	name, server string
	reads        atomic.Int64
}

// Get reads the object, and changes the server of the admin's Secret from its second read on.
func (f *secretFlip) Get(ctx context.Context, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
	if err := f.Reader.Get(ctx, key, obj, opts...); err != nil {
		return err
	}
	if secret, ok := obj.(*corev1.Secret); ok && key.Name == f.name && f.reads.Add(1) > 1 {
		secret.Data[remote.ServerKey] = []byte(f.server)
	}
	return nil
}

// startedOn returns the server of each cache of the spoke of the name that the controller logged that it started.
func startedOn(name string) []string {
	server := regexp.MustCompile(`"server":"([^"]*)"`)
	var servers []string
	for line := range strings.SplitSeq(logs.String(), "\n") {
		if strings.Contains(line, `"msg":"Started a cache of the spoke"`) && strings.Contains(line, `"name":"`+name+`"`) {
			if m := server.FindStringSubmatch(line); m != nil {
				servers = append(servers, m[1])
			}
		}
	}
	return servers
}

// hubCredentials are the credentials of the hub's own API server, with a token of the hub's ServiceAccount there, which
// may read there what it reads on a spoke, as an admin who points a Spoke at the hub by mistake writes them.
func hubCredentials(t *testing.T) map[string][]byte {
	t.Helper()
	if err := testenv.GrantHub(ctx, hub.client, namespace); !apierrors.IsAlreadyExists(err) {
		require.NoError(t, err)
	}
	token, err := testenv.Token(ctx, hub.client, namespace, testenv.HubAccount, 600)
	require.NoError(t, err)
	return credentials(hub.cfg.Host, hub.cfg.CAData, token)
}

// The hub's API server can refuse a record that the store's own checks took, as invalid or as a bad request, as it
// refuses one of a schema newer or older than the store's. The record is refused and counted, by its type's rule, and the
// round goes on with the others: presence keeps the copy that the hub took before (decision 0067), and exposure has its
// copy deleted. Neither the log nor the outcome of the round holds the API's text, which quotes the record.
func TestARecordThatTheHubRefusesStopsNothingElse(t *testing.T) {
	s := onSpoke(t, fmt.Sprintf("cluster-%d", spokes.Add(1)))
	h := hubOf(t, s.name)
	s.run(workloadsCollector, hubType(sdkevidence.TypePresence))
	s.run(reachCollector, hubType(sdkevidence.TypeExposure))
	refusedDigest := newDigest()
	took, presence := presenceIn(t, s.name, refusedDigest, "old"), presenceIn(t, s.name, refusedDigest, "web")
	tookExposure := newEvent(t, sdkevidence.TypeExposure, workloadIn(s.name, "web"),
		sdkevidence.Exposure{InternalReach: namespaceReach})
	exposure, accepted := exposureIn(t, s.name, "web"), presenceIn(t, s.name, newDigest(), "api")
	require.NoError(t, h.evidence.Put(ctx, workloadsCollector, collectorVersion, took, evidence.InCluster(s.name)))
	require.NoError(t, h.evidence.Put(ctx, reachCollector, collectorVersion, tookExposure, evidence.InCluster(s.name)))
	s.stream(workloadsCollector, presence)
	s.stream(reachCollector, exposure)
	s.stream(workloadsCollector, accepted)
	const apiText = "the API server quotes the record"
	refusing := *h
	refusing.evidence = refusingStore{Store: h.evidence, refused: map[string]error{
		presence.Subject(): apierrors.NewInvalid(inventoryv1alpha1.GroupVersion.WithKind("Evidence").GroupKind(),
			"ev-refused", field.ErrorList{field.Invalid(field.NewPath("spec", "subject"), presence.Subject(), apiText)}),
		exposure.Subject(): apierrors.NewBadRequest(apiText + ": " + exposure.Subject()),
	}}
	invalid := refusals(s.name, "invalid")
	copier, _ := startCopier(t, s, &refusing)

	syncUntil(t, copier, func() bool {
		return h.holds(s.name, workloadsCollector, accepted) && refusals(s.name, "invalid") == invalid+2
	}, "copy the record that the hub takes, and refuse the two")
	require.True(t, h.holds(s.name, workloadsCollector, took), "presence keeps the copy that the hub took")
	require.Nil(t, h.copyOf(s.name, reachCollector, exposure), "exposure has its copy deleted")
	synced, _, err := copier.Synced()
	require.NoError(t, err)
	require.True(t, synced)
	require.NotContains(t, logs.String(), apiText)
}

// refusingStore is a hub's evidence store whose API server refuses the events of the subjects with the errors, as it
// refuses a record of a schema that the store's own checks don't know.
type refusingStore struct {
	evidence.Store
	refused map[string]error
}

// Put returns the error of the event's subject, as the store returns the API server's, and else stores the event.
func (s refusingStore) Put(ctx context.Context, source, version string, e cloudevents.Event,
	opts ...evidence.PutOption) error {
	if err := s.refused[e.Subject()]; err != nil {
		return fmt.Errorf("create Evidence %q: %w", "ev-refused", err)
	}
	return s.Store.Put(ctx, source, version, e, opts...)
}

// Presence or exposure off the core's schema is refused as invalid, by its type's rule (decision 0067): presence keeps
// the copy that the hub has, since presence never forgets what it can't read, and exposure has its copy deleted, so
// that the workload's exposure reads Unknown.
func TestAnOffSchemaRecordFollowsTheRuleOfItsType(t *testing.T) {
	s := onSpoke(t, fmt.Sprintf("cluster-%d", spokes.Add(1)))
	h := hubOf(t, s.name)
	s.run(workloadsCollector, hubType(sdkevidence.TypePresence))
	s.run(reachCollector, hubType(sdkevidence.TypeExposure))
	presence, exposure := presenceIn(t, s.name, newDigest(), "web"), exposureIn(t, s.name, "web")
	require.NoError(t, h.evidence.Put(ctx, workloadsCollector, collectorVersion, presence, evidence.InCluster(s.name)))
	require.NoError(t, h.evidence.Put(ctx, reachCollector, collectorVersion, exposure, evidence.InCluster(s.name)))
	// What a collector of another version might send: presence without its workloads, and exposure without its external
	// exposure.
	s.stream(workloadsCollector, newEvent(t, sdkevidence.TypePresence, presence.Subject(),
		map[string]string{"digestKind": sdkevidence.DigestKindRepoDigest}))
	s.stream(reachCollector, newEvent(t, sdkevidence.TypeExposure, exposure.Subject(),
		map[string]any{"internalReach": "Cluster", "indirect": false}))
	invalid := refusals(s.name, "invalid")
	copier, _ := startCopier(t, s, h)

	syncUntil(t, copier, func() bool {
		return refusals(s.name, "invalid") == invalid+2 && h.copyOf(s.name, reachCollector, exposure) == nil
	}, "refuse both records, and delete the copy of the exposure")
	require.True(t, h.holds(s.name, workloadsCollector, presence), "presence keeps the copy that the hub could read")
}

// A renewed token restarts the cache of the spoke, which reads the spoke with it, and the copier goes on from what it
// copied: Synced stays True, the round after the renewal writes nothing of what didn't change, and a change after it is
// copied.
func TestARenewalKeepsTheCopySynced(t *testing.T) {
	// A renewer whose clock runs an hour ahead finds every token due, so each check renews.
	runHub(t, func(r *configcontroller.SpokeReconciler) {
		r.Renewer.Now = func() time.Time { return time.Now().Add(time.Hour) }
	})
	obj := newSpoke(t, spokeCredentials(t))
	deleteBeforeTheHubStops(t, obj)
	s := onSpoke(t, obj.Name)
	h := hubOf(t, obj.Name)
	s.run(reachCollector, hubType(sdkevidence.TypeExposure))
	exposure := exposureIn(t, s.name, "web")
	s.stream(reachCollector, exposure)
	synced := spokeWhen(t, obj.Name, func(got *configv1alpha1.Spoke) bool {
		return meta.IsStatusConditionTrue(got.Status.Conditions, configv1alpha1.ConditionSynced) &&
			h.holds(s.name, reachCollector, exposure)
	}, "copy the spoke's records")
	since := meta.FindStatusCondition(synced.Status.Conditions, configv1alpha1.ConditionSynced).LastTransitionTime
	token, written := ownToken(obj), controllerWrites(s.name)

	t.Log("renewing the token at the next check")
	touch(t, obj.Name)
	require.Eventually(t, func() bool { return ownToken(obj) != token }, timeout, poll, "renew the token")
	require.Never(t, func() bool {
		var got configv1alpha1.Spoke
		if hub.client.Get(ctx, client.ObjectKeyFromObject(obj), &got) != nil {
			return false
		}
		c := meta.FindStatusCondition(got.Status.Conditions, configv1alpha1.ConditionSynced)
		return c == nil || c.Status != metav1.ConditionTrue || !c.LastTransitionTime.Equal(&since) ||
			controllerWrites(s.name) != written
	}, quiet, poll, "Synced stays True, and nothing that didn't change is written")

	t.Log("changing the spoke's record after the renewal")
	changed := newEvent(t, sdkevidence.TypeExposure, exposure.Subject(), sdkevidence.Exposure{InternalReach: namespaceReach})
	s.stream(reachCollector, changed)
	require.Eventually(t, func() bool { return h.holds(s.name, reachCollector, changed) }, timeout, poll,
		"copy the change over the new cache")
}

// status.lastSyncTime says when the copy became current, and when a round last copied a change of the spoke: a check
// that finds nothing new leaves it, so that a Spoke whose spoke is quiet costs no write at each check.
func TestLastSyncTimeMovesOnlyWithTheCopy(t *testing.T) {
	runHub(t)
	obj := newSpoke(t, spokeCredentials(t))
	deleteBeforeTheHubStops(t, obj)
	s := onSpoke(t, obj.Name)
	h := hubOf(t, obj.Name)
	s.run(reachCollector, hubType(sdkevidence.TypeExposure))
	exposure := exposureIn(t, s.name, "web")
	s.stream(reachCollector, exposure)
	spokeWhen(t, obj.Name, func(got *configv1alpha1.Spoke) bool {
		return got.Status.LastSyncTime != nil && h.holds(s.name, reachCollector, exposure)
	}, "copy the spoke's records")
	// checked has the controller check the spoke, and waits until the check has recorded what it found.
	checked := func() *configv1alpha1.Spoke {
		t.Helper()
		touch(t, obj.Name)
		return spokeWhen(t, obj.Name, func(got *configv1alpha1.Spoke) bool {
			return ptr.Deref(got.Status.ObservedGeneration, 0) == got.Generation
		}, "check the spoke")
	}
	current := checked()

	// A check a second later would write a time of its own.
	time.Sleep(1100 * time.Millisecond)
	require.Equal(t, current.Status.LastSyncTime, checked().Status.LastSyncTime, "a check that finds nothing new")

	t.Log("changing the spoke's record")
	changed := newEvent(t, sdkevidence.TypeExposure, exposure.Subject(), sdkevidence.Exposure{InternalReach: namespaceReach})
	s.stream(reachCollector, changed)
	require.Eventually(t, func() bool { return h.holds(s.name, reachCollector, changed) }, timeout, poll, "copy the change")
	require.True(t, checked().Status.LastSyncTime.After(current.Status.LastSyncTime.Time), "a round that copied a change")
}

// The hub starts the cache of a spoke anew when the config that the seam gives changes, as with a new token in the
// admin's Secret, and only then: a check that finds the same config leaves the cache, and its watches, as they are.
func TestOnlyAChangedConfigRestartsTheCache(t *testing.T) {
	runHub(t)
	obj := newSpoke(t, spokeCredentials(t))
	deleteBeforeTheHubStops(t, obj)
	checked := func() {
		t.Helper()
		spokeWhen(t, obj.Name, func(got *configv1alpha1.Spoke) bool {
			return meta.IsStatusConditionTrue(got.Status.Conditions, configv1alpha1.ConditionSynced) &&
				ptr.Deref(got.Status.ObservedGeneration, 0) == got.Generation
		}, "check the spoke")
	}
	checked()
	require.Equal(t, 1, starts(obj.Name))

	touch(t, obj.Name)
	checked()
	require.Equal(t, 1, starts(obj.Name), "the same config")

	t.Log("putting a new bootstrap token into the admin's Secret")
	admin := adminSecret(t, obj)
	admin.Data[remote.TokenKey] = []byte(bootstrapToken(t))
	require.NoError(t, hub.client.Update(ctx, admin))
	touch(t, obj.Name)
	checked()
	require.Eventually(t, func() bool { return starts(obj.Name) == 2 }, timeout, poll, "start the cache anew")
}

// A new cache of a spoke whose copier goes on over it, as after a new config, keeps Synced True until its first round
// ends, and for a grace at most: a cache that never syncs, as when the hub's account on the spoke can no longer list
// its records, turns Synced False within the grace, and lastSyncTime stops moving from the moment the new cache
// started. The first round over the new cache, once it syncs, tells the controller at once.
func TestANewCacheThatNeverSyncsTurnsSyncedFalseWithinTheGrace(t *testing.T) {
	var ahead atomic.Int64
	runHub(t, func(r *configcontroller.SpokeReconciler) {
		r.Now = func() time.Time { return time.Now().Add(time.Duration(ahead.Load())) }
	})
	obj := newSpoke(t, spokeCredentials(t))
	deleteBeforeTheHubStops(t, obj)
	spokeWhen(t, obj.Name, conditionIs(configv1alpha1.ConditionSynced, metav1.ConditionTrue,
		configv1alpha1.ReasonSynced), "copy the spoke's records")

	t.Log("taking the hub's list of the spoke's records away, and starting a new cache with a new token")
	giveBack := withoutListing(t)
	admin := adminSecret(t, obj)
	admin.Data[remote.TokenKey] = []byte(bootstrapToken(t))
	require.NoError(t, hub.client.Update(ctx, admin))
	touch(t, obj.Name)
	require.Eventually(t, func() bool { return starts(obj.Name) == 2 }, timeout, poll, "start a new cache")
	checked := func() *configv1alpha1.Spoke {
		t.Helper()
		return spokeWhen(t, obj.Name, func(got *configv1alpha1.Spoke) bool {
			return ptr.Deref(got.Status.ObservedGeneration, 0) == got.Generation
		}, "check the spoke")
	}
	since := checked().Status.LastSyncTime
	require.NotNil(t, since)

	ahead.Store(int64(10 * time.Second))
	touch(t, obj.Name)
	within := checked()
	require.True(t, meta.IsStatusConditionTrue(within.Status.Conditions, configv1alpha1.ConditionSynced),
		"within the grace, Synced holds")
	require.Equal(t, since, within.Status.LastSyncTime, "lastSyncTime stops moving")

	ahead.Store(int64(3 * time.Minute))
	touch(t, obj.Name)
	got := spokeWhen(t, obj.Name, conditionIs(configv1alpha1.ConditionSynced, metav1.ConditionFalse,
		configv1alpha1.ReasonSyncing), "give up waiting for the new cache")
	require.False(t, meta.IsStatusConditionTrue(got.Status.Conditions, configv1alpha1.ConditionReady))
	require.Equal(t, since, got.Status.LastSyncTime, "lastSyncTime stops moving")

	t.Log("giving the hub its list back, so that the new cache syncs, well before the next check")
	giveBack()
	back := spokeWhen(t, obj.Name, conditionIs(configv1alpha1.ConditionSynced, metav1.ConditionTrue,
		configv1alpha1.ReasonSynced), "copy again once the new cache syncs")
	require.True(t, back.Status.LastSyncTime.After(since.Time), "lastSyncTime moves again")
}

// withoutListing takes from the hub's account on the suite's spoke the list and the watch of the spoke's records, as a
// changed role of a spoke's install could, until the test ends, or it calls the function that withoutListing returns.
func withoutListing(t *testing.T) (giveBack func()) {
	t.Helper()
	var role rbacv1.ClusterRole
	require.NoError(t, spoke.client.Get(ctx, client.ObjectKey{Name: testenv.HubAccount}, &role))
	granted := slices.Clone(role.Rules)
	giveBack = func() {
		require.Eventually(t, func() bool {
			var now rbacv1.ClusterRole
			if spoke.client.Get(ctx, client.ObjectKey{Name: testenv.HubAccount}, &now) != nil {
				return false
			}
			now.Rules = granted
			return spoke.client.Update(ctx, &now) == nil
		}, timeout, poll, "give the hub its list back")
	}
	t.Cleanup(giveBack)
	role.Rules = slices.DeleteFunc(role.Rules, func(rule rbacv1.PolicyRule) bool {
		return slices.Contains(rule.Resources, "evidences")
	})
	require.NoError(t, spoke.client.Update(ctx, &role))
	return giveBack
}

// When the hub's own cluster is renamed, the hub's presence moves its entries to the new name only as it next
// reconciles each image: until then, an entry under the old name, which a Spoke may now carry, has the hub's own
// identity. The copier's rounds and the Spoke's deletion forget entries under the Spoke's name, and never one of the
// hub's own identity, which would take the image's object, with its facts, if it was the last.
func TestAnEntryOfTheHubsOwnIdentityIsNeverForgotten(t *testing.T) {
	runHub(t)
	name := fmt.Sprintf("cluster-%d", spokes.Add(1))
	h := hubOf(t, name)
	id, err := settings.ClusterID(ctx, hub.client)
	require.NoError(t, err)
	digest := newDigest()
	// The hub's own entry, from when the hub's own cluster had the name.
	require.NoError(t, h.inventory.Observe(ctx, digest, (&spokeSide{name: name, id: id}).entry(1)))
	t.Cleanup(func() { require.NoError(t, h.inventory.Forget(ctx, digest, name, id)) })

	obj := namedSpoke(t, name, spokeCredentials(t))
	deleteBeforeTheHubStops(t, obj)
	spokeWhen(t, name, conditionIs(configv1alpha1.ConditionSynced, metav1.ConditionTrue, configv1alpha1.ReasonSynced),
		"run the copier's first round, which reads everything")
	require.NotNil(t, h.entryOf(name, digest), "a round leaves the hub's own entry")

	require.NoError(t, hub.client.Delete(ctx, obj))
	require.Eventually(t, func() bool { return gone(obj) }, timeout, poll, "let the Spoke go")
	require.NotNil(t, h.entryOf(name, digest), "the Spoke's deletion leaves the hub's own entry")
}

// A round that its run's end cuts short after it wrote has the next round read everything: the cut round may have
// copied a record that the copier doesn't know of yet, and that the spoke deletes before the next round.
func TestARoundCutShortAfterItWroteIsFollowedByAFullOne(t *testing.T) {
	s := onSpoke(t, fmt.Sprintf("cluster-%d", spokes.Add(1)))
	h := hubOf(t, s.name)
	s.run(reachCollector, hubType(sdkevidence.TypeExposure))
	first, second := exposureIn(t, s.name, "web"), exposureIn(t, s.name, "api")
	s.stream(reachCollector, first)
	cutting := &cuttingStore{Store: h.evidence, subject: second.Subject()}
	withCut := *h
	withCut.evidence = cutting
	copier, spokeCache, _ := startCopierOver(t, s, &withCut)
	syncUntil(t, copier, func() bool { return h.holds(s.name, reachCollector, first) }, "copy the first record")

	t.Log("cutting a round short right after it copied a new record")
	s.stream(reachCollector, second)
	require.Eventually(t, func() bool {
		round, cancel := context.WithCancel(ctx)
		defer cancel()
		cutting.cancel = cancel
		_ = copier.Sync(round)
		return cutting.cut.Load()
	}, timeout, poll, "cut a round after its copy of the new record")
	require.True(t, h.holds(s.name, reachCollector, second), "the cut round copied the record")

	t.Log("deleting the record on the spoke, and letting the copier's cache see it, before the next round")
	require.NoError(t, s.evidence.Delete(ctx, keyIn(s.name, reachCollector, second)))
	require.Eventually(t, func() bool {
		var records inventoryv1alpha1.EvidenceList
		return spokeCache.List(ctx, &records) == nil && !slices.ContainsFunc(records.Items,
			func(r inventoryv1alpha1.Evidence) bool { return r.Spec.Subject == second.Subject() })
	}, timeout, poll, "see the deletion in the copier's cache")
	require.NoError(t, copier.Sync(ctx))
	require.Nil(t, h.copyOf(s.name, reachCollector, second), "the next round deletes the copy that the cut round made")
}

// cuttingStore is a hub's evidence store that ends the round that copies the record of the subject right after the
// copy, as the end of a copier's run would: it cancels the round's context, and returns its error.
type cuttingStore struct {
	evidence.Store
	subject string
	// cancel cancels the context of the round that runs, and cut says that a round was cut.
	cancel context.CancelFunc
	cut    atomic.Bool
}

// Put stores the event, and cuts the round when the event is of the subject.
func (s *cuttingStore) Put(ctx context.Context, source, version string, e cloudevents.Event,
	opts ...evidence.PutOption) error {
	if err := s.Store.Put(ctx, source, version, e, opts...); err != nil || e.Subject() != s.subject {
		return err
	}
	s.cut.Store(true)
	s.cancel()
	return ctx.Err()
}

// A watch of a spoke's cache ends with its Stop, also while nobody reads it any more, as after the cache's reflector
// stopped it: no goroutine of it stays behind, blocked on an event, at each stop of a spoke's cache. The ERROR events
// that it passes on carry their code alone.
func TestAWatchOfTheSpokeEndsWithItsStop(t *testing.T) {
	fake := watch.NewFakeWithChanSize(2, false)
	lw := &toolscache.ListWatch{WatchFuncWithContext: func(context.Context, metav1.ListOptions) (watch.Interface,
		error) {
		return fake, nil
	}}
	w, err := remote.WithheldAnswers(lw).WatchWithContext(ctx, metav1.ListOptions{})
	require.NoError(t, err)
	const echo = "no such token: Bearer a-token-of-the-hub"
	refusal := &metav1.Status{Status: metav1.StatusFailure, Reason: echo, Message: echo, Code: http.StatusForbidden}

	fake.Error(refusal)
	e := <-w.ResultChan()
	require.Equal(t, watch.Error, e.Type)
	require.Equal(t, &metav1.Status{Status: metav1.StatusFailure, Code: http.StatusForbidden}, e.Object)

	fake.Error(refusal)
	w.Stop()
	_, open := <-w.ResultChan()
	require.False(t, open, "the watch ended at its stop, and dropped the event that nobody read")
}

// The cache of a spoke lists and watches it with a logger that drops client-go's debug lines, whatever the verbosity of
// the logger of the cache's informers, the manager's own: they can carry what the spoke answers.
func TestTheCacheOfASpokeListsAndWatchesWithoutDebugLines(t *testing.T) {
	var got []logr.Logger
	keep := func(ctx context.Context) { got = append(got, logr.FromContextOrDiscard(ctx)) }
	lw := &toolscache.ListWatch{
		ListWithContextFunc: func(ctx context.Context, _ metav1.ListOptions) (runtime.Object, error) {
			keep(ctx)
			return &inventoryv1alpha1.EvidenceList{}, nil
		},
		WatchFuncWithContext: func(ctx context.Context, _ metav1.ListOptions) (watch.Interface, error) {
			keep(ctx)
			return watch.NewFake(), nil
		},
	}
	verbose := logr.NewContext(ctx, funcr.New(func(string, string) {}, funcr.Options{Verbosity: 10}))

	_, err := remote.WithheldAnswers(lw).ListWithContext(verbose, metav1.ListOptions{})
	require.NoError(t, err)
	w, err := remote.WithheldAnswers(lw).WatchWithContext(verbose, metav1.ListOptions{})
	require.NoError(t, err)
	w.Stop()

	require.Len(t, got, 2)
	for _, logger := range got {
		require.True(t, logger.V(3).Enabled(), "the lines up to V(3) stay")
		require.False(t, logger.V(4).Enabled(), "client-go's debug lines go")
	}
}

// Renaming the hub's own cluster to the name of a Spoke stops the hub copying under that name at once: a change of the
// OperatorConfig brings a check of every Spoke.
func TestRenamingTheHubOntoASpokesNameStopsItsCopyAtOnce(t *testing.T) {
	runHub(t)
	obj := newSpoke(t, spokeCredentials(t))
	deleteBeforeTheHubStops(t, obj)
	spokeWhen(t, obj.Name, conditionIs(configv1alpha1.ConditionSynced, metav1.ConditionTrue,
		configv1alpha1.ReasonSynced), "copy the spoke's records")

	operatorConfig := &configv1alpha1.OperatorConfig{ObjectMeta: metav1.ObjectMeta{Name: settings.ConfigName},
		Spec: configv1alpha1.OperatorConfigSpec{ClusterName: ptr.To(obj.Name)}}
	require.NoError(t, hub.client.Create(ctx, operatorConfig))
	t.Cleanup(func() { require.NoError(t, client.IgnoreNotFound(hub.client.Delete(ctx, operatorConfig))) })
	spokeWhen(t, obj.Name, conditionIs(configv1alpha1.ConditionConnected, metav1.ConditionFalse,
		configv1alpha1.ReasonNameInUse), "refuse the Spoke at once")
}

// A spoke that names its cluster otherwise than its Spoke is refused with ClusterNameMismatch, and Stalled: its records
// carry the other name. The hub copies nothing from a spoke left at the default name, and records no identity for it.
// A rename on a spoke that the hub copies stops the copy, and the copies stay as they were, the entries that the
// spoke's presence moves to the new name included.
func TestASpokeThatNamesItselfOtherwiseIsRefused(t *testing.T) {
	name := fmt.Sprintf("cluster-%d", spokes.Add(1))
	s := onSpoke(t, name)
	h := hubOf(t, name)
	s.run(reachCollector, hubType(sdkevidence.TypeExposure))
	exposure := exposureIn(t, name, "web")
	s.stream(reachCollector, exposure)
	digest := newDigest()
	s.observe(digest, s.entry(1))
	obj := namedSpoke(t, name, spokeCredentials(t))
	require.NoError(t, spoke.client.Delete(ctx, &configv1alpha1.OperatorConfig{
		ObjectMeta: metav1.ObjectMeta{Name: settings.ConfigName}}), "leave the spoke at the default name")

	runHub(t)
	deleteBeforeTheHubStops(t, obj)
	got := spokeWhen(t, name, conditionIs(configv1alpha1.ConditionConnected, metav1.ConditionFalse,
		configv1alpha1.ReasonClusterNameMismatch), "refuse the spoke of the default name")
	require.True(t, meta.IsStatusConditionTrue(got.Status.Conditions, configv1alpha1.ConditionStalled))
	require.Contains(t, meta.FindStatusCondition(got.Status.Conditions, configv1alpha1.ConditionConnected).Message,
		`"`+settings.DefaultClusterName+`"`)
	require.Nil(t, got.Status.ClusterID, "the hub records no identity")
	require.Never(t, func() bool {
		return h.copyOf(name, reachCollector, exposure) != nil || h.entryOf(name, digest) != nil
	}, quiet, poll, "the hub copies nothing")

	t.Log("naming the spoke's cluster as its Spoke")
	nameSpoke(t, name)
	touch(t, name)
	spokeWhen(t, name, func(got *configv1alpha1.Spoke) bool {
		return meta.IsStatusConditionTrue(got.Status.Conditions, configv1alpha1.ConditionSynced) &&
			h.holds(name, reachCollector, exposure) && h.entryOf(name, digest) != nil
	}, "copy the spoke's records")
	entry := h.entryOf(name, digest)

	t.Log("renaming the spoke's cluster, whose presence moves the entry to the new name")
	nameSpoke(t, name+"-renamed")
	renamed := s.entry(1)
	renamed.Cluster = name + "-renamed"
	s.observe(digest, renamed)
	touch(t, name)
	spokeWhen(t, name, conditionIs(configv1alpha1.ConditionConnected, metav1.ConditionFalse,
		configv1alpha1.ReasonClusterNameMismatch), "refuse the renamed spoke")
	require.Never(t, func() bool {
		return !h.holds(name, reachCollector, exposure) || !equalEntries(entry, h.entryOf(name, digest))
	}, quiet, poll, "the copies stay as they were")
}

// Once a spoke renamed its cluster, its presence writes each entry under the new name, with the cluster's identity. The
// copier refuses such an entry, and counts it, and keeps the hub's copy under the Spoke's name, in a round that follows
// the spoke's changes and in one that reads everything: the check of the spoke stops the copier then, and the cluster's
// images never read as running nowhere in between.
func TestAnEntryOfTheSpokesIdentityUnderAnotherNameKeepsItsCopy(t *testing.T) {
	s := onSpoke(t, fmt.Sprintf("cluster-%d", spokes.Add(1)))
	h := hubOf(t, s.name)
	digest := newDigest()
	s.observe(digest, s.entry(1))
	copier, _ := startCopier(t, s, h)
	syncUntil(t, copier, func() bool { return h.entryOf(s.name, digest) != nil }, "copy the entry")
	entry := h.entryOf(s.name, digest)

	renamed := s.entry(1)
	renamed.Cluster = s.name + "-renamed"
	s.observe(digest, renamed)
	refused := refusals(s.name, "cluster")
	syncUntil(t, copier, func() bool { return refusals(s.name, "cluster") > refused }, "refuse the renamed entry")
	require.True(t, equalEntries(entry, h.entryOf(s.name, digest)), "a round that follows the changes keeps the copy")

	full, _ := startCopier(t, s, h)
	require.NoError(t, full.Sync(ctx))
	require.True(t, equalEntries(entry, h.entryOf(s.name, digest)), "a round that reads everything keeps the copy")
}

// A cluster has one Spoke. A first contact with a cluster whose identity another Spoke records is refused with
// IdentityInUse, and Stalled, and records no identity: the two Spokes' copies of the cluster would replace each other's
// entries. Once the other Spoke is gone, the first contact is made.
func TestASecondSpokeOfAClusterIsRefused(t *testing.T) {
	runHub(t)
	first := newSpoke(t, spokeCredentials(t))
	deleteBeforeTheHubStops(t, first)
	spokeWhen(t, first.Name, conditionIs(configv1alpha1.ConditionConnected, metav1.ConditionTrue,
		configv1alpha1.ReasonConnected), "contact the spoke")

	second := newSpoke(t, spokeCredentials(t))
	deleteBeforeTheHubStops(t, second)
	got := spokeWhen(t, second.Name, conditionIs(configv1alpha1.ConditionConnected, metav1.ConditionFalse,
		configv1alpha1.ReasonIdentityInUse), "refuse the second Spoke")
	require.True(t, meta.IsStatusConditionTrue(got.Status.Conditions, configv1alpha1.ConditionStalled))
	require.Contains(t, meta.FindStatusCondition(got.Status.Conditions, configv1alpha1.ConditionConnected).Message,
		first.Name)
	require.Nil(t, got.Status.ClusterID, "the hub records no identity")
	require.Zero(t, starts(second.Name), "the hub starts no cache")

	t.Log("deleting the first Spoke")
	require.NoError(t, hub.client.Delete(ctx, first))
	require.Eventually(t, func() bool { return gone(first) }, timeout, poll, "let the first Spoke go")
	touch(t, second.Name)
	got = spokeWhen(t, second.Name, conditionIs(configv1alpha1.ConditionConnected, metav1.ConditionTrue,
		configv1alpha1.ReasonConnected), "contact the spoke for the first time")
	require.Equal(t, ptr.To(spokeID(t)), got.Status.ClusterID)
}

// ownToken returns the token of the hub's own Secret of obj, or "" while there is none.
func ownToken(obj *configv1alpha1.Spoke) string {
	var secret corev1.Secret
	if hub.client.Get(ctx, client.ObjectKey{Namespace: namespace, Name: remote.TokenSecretName(obj.Name)},
		&secret) != nil {
		return ""
	}
	return string(secret.Data[remote.TokenKey])
}

// controllerWrites sums the writes of the hub's stores that runHub's controller made of the spoke of the name: those of
// the evidence, which its store labels with the hub's own cluster, and of the spoke's entries.
func controllerWrites(name string) float64 {
	sum := 0.0
	for _, op := range []string{"create", "update", "delete"} {
		sum += testutil.ToFloat64(metrics.EvidenceWritesTotal.WithLabelValues(settings.DefaultClusterName, op)) +
			testutil.ToFloat64(metrics.InventoryWritesTotal.WithLabelValues(name, op))
	}
	return sum
}

// starts counts the starts of a cache of the spoke of the name that the controller logged.
func starts(name string) int {
	n := 0
	for line := range strings.SplitSeq(logs.String(), "\n") {
		if strings.Contains(line, `"msg":"Started a cache of the spoke"`) && strings.Contains(line, `"name":"`+name+`"`) {
			n++
		}
	}
	return n
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
// copies into, as change leaves it. The hub's own cluster has the default name while the hub holds no OperatorConfig.
// The controller's finalizer must let a Spoke of the test go before it stops: deleteBeforeTheHubStops.
func runHub(t *testing.T, change ...func(*configcontroller.SpokeReconciler)) {
	t.Helper()
	mgr, err := ctrl.NewManager(hub.cfg, ctrl.Options{Scheme: scheme, Cache: setup.CacheOptions(namespace),
		Client: setup.ClientOptions(), Metrics: metricsserver.Options{BindAddress: "0"},
		// Each test that runs the controller starts a manager of its own.
		Controller: ctrlconfig.Controller{SkipNameValidation: ptr.To(true)}})
	require.NoError(t, err)
	own := func() string { return settings.DefaultClusterName }
	reconciler := &configcontroller.SpokeReconciler{
		Client:            mgr.GetClient(),
		Scheme:            mgr.GetScheme(),
		APIReader:         mgr.GetAPIReader(),
		OperatorNamespace: namespace,
		Renewer:           &remote.Renewer{Client: mgr.GetClient(), Namespace: namespace, Lifetime: time.Hour},
		Evidence:          evidence.NewCRDStore(mgr.GetClient(), mgr.GetCache(), own),
		Inventory:         inventory.NewCRDStore(mgr.GetClient(), mgr.GetCache(), own),
		Counts:            inventory.NewCRDCountsStore(mgr.GetClient(), mgr.GetCache()),
	}
	for _, c := range change {
		c(reconciler)
	}
	require.NoError(t, reconciler.SetupWithManager(mgr))
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
