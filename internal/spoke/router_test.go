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
	"testing"

	cloudevents "github.com/cloudevents/sdk-go/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"sigs.k8s.io/controller-runtime/pkg/client"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
	"github.com/bedag/vexplain/internal/spoke"
	"github.com/bedag/vexplain/sdk/evidence"
	"github.com/bedag/vexplain/sdk/subject"
)

// exposureEvent returns an event of the exposure type about a workload, which presence doesn't read.
func exposureEvent(t *testing.T) cloudevents.Event {
	t.Helper()
	e, err := evidence.New(evidence.TypeExposure, subject.ForWorkload(subject.Workload{
		Cluster: clusterA, Namespace: teamA, Group: appsGroup, Kind: deployment, Name: "web",
	}), evidence.Exposure{InternalReach: reachCluster}, evidence.WithSource("/clusters/cluster-a/collectors/exposure"))
	require.NoError(t, err)
	return e
}

// A collector that runs no workload in scope any more sends an empty snapshot. It reaches presence through the
// Router, which hands each snapshot to the consumer of every type that the collector declares, and presence forgets
// what the collector delivered before.
func TestAnEmptySnapshotReachesPresenceThroughTheRouter(t *testing.T) {
	c := newCluster()
	s := startSpoke(t, c)
	router := spoke.NewRouter(s.manager.GetClient(), s.presence, s.exposure)
	name := newCollector(t, evidence.TypePresence)
	s.sees(t, name)
	digest := newDigest(t)
	router.Snapshot(name, []cloudevents.Event{presenceEvent(t, digest, running("team-a", "web", linuxAMD64))})
	present(t, c, digest)

	router.Snapshot(name, nil)

	absent(t, c, digest)
}

// The snapshot of a collector that doesn't declare the presence type says nothing about what runs, even an empty one.
// Presence would otherwise take it for its first snapshot after a start, and forget every entry of the cluster.
func TestASnapshotReachesNoConsumerOfATypeThatTheCollectorDoesntDeclare(t *testing.T) {
	c := newCluster()
	stale := newDigest(t)
	observe(t, c, stale)
	s := startSpoke(t, c)
	router := spoke.NewRouter(s.manager.GetClient(), s.presence, s.exposure)

	exposing := newCollector(t, evidence.TypeExposure)
	s.sees(t, exposing)
	router.Snapshot(exposing, []cloudevents.Event{exposureEvent(t)})

	stays(t, c, stale, true)
}

// A collector that stops producing presence, as after an upgrade, delivers none any more, and its next snapshot says
// so: presence forgets what it delivered, as when its Collector goes.
func TestACollectorThatStopsProducingPresenceIsForgottenAtItsNextSnapshot(t *testing.T) {
	c := newCluster()
	s := startSpoke(t, c)
	reader := s.manager.GetClient()
	router := spoke.NewRouter(reader, s.presence, s.exposure)
	name := newCollector(t, evidence.TypePresence, evidence.TypeExposure)
	s.sees(t, name)
	digest := newDigest(t)
	router.Snapshot(name, []cloudevents.Event{presenceEvent(t, digest, running("team-a", "web", linuxAMD64))})
	present(t, c, digest)

	_, direct := startAPI(t)
	var upgraded configv1alpha1.Collector
	require.NoError(t, direct.Get(t.Context(), client.ObjectKey{Name: name}, &upgraded))
	upgraded.Status.Capabilities.Produces = []configv1alpha1.ProducedType{
		{Type: evidence.TypeExposure, Scope: configv1alpha1.EvidenceScopeSpoke},
	}
	require.NoError(t, direct.Status().Update(t.Context(), &upgraded))
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		var seen configv1alpha1.Collector
		if assert.NoError(c, reader.Get(t.Context(), client.ObjectKey{Name: name}, &seen)) {
			assert.Len(c, seen.Status.Capabilities.Produces, 1)
		}
	}, wait, tick, "the Router reads the upgrade")

	router.Snapshot(name, []cloudevents.Event{exposureEvent(t)})

	absent(t, c, digest)
}

// After the snapshot, the Router hands each change to the consumer of its type, and drops what no consumer reads.
// Forget reaches every consumer.
func TestTheRouterHandsEachChangeToTheConsumerOfItsType(t *testing.T) {
	c := newCluster()
	s := startSpoke(t, c)
	router := spoke.NewRouter(s.manager.GetClient(), s.presence, s.exposure)
	name := newCollector(t, evidence.TypePresence, evidence.TypeExposure)
	s.sees(t, name)
	router.Snapshot(name, nil)
	digest := newDigest(t)
	web := running("team-a", "web", linuxAMD64)

	router.Upsert(name, presenceEvent(t, digest, web))
	present(t, c, digest)
	exposure := exposureEvent(t)
	router.Upsert(name, exposure)
	router.Remove(name, evidence.TypeExposure, exposure.Subject())
	router.SourceChanged(name, nil)
	stays(t, c, digest, true)

	router.Remove(name, evidence.TypePresence, subject.Image(digest))
	absent(t, c, digest)

	router.Upsert(name, presenceEvent(t, digest, web))
	present(t, c, digest)
	router.Forget(name)
	absent(t, c, digest)
}
