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

package collectorclient_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
	"github.com/bedag/vexplain/internal/collectorclient"
	"github.com/bedag/vexplain/sdk/collector"
	"github.com/bedag/vexplain/sdk/subject"
)

// spokeOnly returns the sinks of a cluster with the spoke's role only: sink, for the Spoke role.
func spokeOnly(sink collectorclient.Sink) map[configv1alpha1.CollectorRole]collectorclient.Sink {
	return map[configv1alpha1.CollectorRole]collectorclient.Sink{configv1alpha1.CollectorRoleSpoke: sink}
}

func TestAWholeSnapshotArrivesAsOneCallAndChangesAfterItPassThrough(t *testing.T) {
	e := newEnv(t)
	h := newHello(collector.RoleSpoke)
	e.serve("hello-snapshot", h)
	e.createCollector("hello-snapshot", "", noData(), configv1alpha1.CollectorRoleSpoke)
	sink := &recordingSink{}
	e.startStreams(spokeOnly(sink))

	call := h.next(t, collector.RoleSpoke)
	one, two, three := event(t, 1), event(t, 2), event(t, 3)
	require.NoError(t, call.sink.SnapshotStart())
	require.NoError(t, call.sink.Event(one))
	require.NoError(t, call.sink.Event(two))
	sink.stays(t)
	require.NoError(t, call.sink.Event(three))
	require.NoError(t, call.sink.SnapshotEnd())
	snapshot := snapshotCall("hello-snapshot", one, two, three)
	sink.await(t, snapshot)

	four := event(t, 4)
	require.NoError(t, call.sink.Event(four))
	require.NoError(t, call.sink.Tombstone(helloType, one.Subject()))
	require.NoError(t, call.sink.SourceChanged(two.Subject()))
	require.NoError(t, call.sink.SourceChanged())
	sink.await(t, snapshot,
		upsertCall("hello-snapshot", four),
		removeCall("hello-snapshot", helloType, one.Subject()),
		sourceChangedCall("hello-snapshot", two.Subject()),
		sourceChangedCall("hello-snapshot"))
}

// Review Focus 1: a collector's stream breaks, or the collector restarts, in the middle of a snapshot. The sink keeps
// the last complete snapshot, never part of one, until a new snapshot ends.
func TestAStreamCutInTheMiddleOfItsSnapshotHandsOverNothingOfIt(t *testing.T) {
	e := newEnv(t)
	h := newHello(collector.RoleSpoke)
	e.serve("hello-cut", h)
	e.createCollector("hello-cut", "", noData(), configv1alpha1.CollectorRoleSpoke)
	sink := &recordingSink{}
	e.startStreams(spokeOnly(sink))

	first := h.next(t, collector.RoleSpoke)
	one, two := event(t, 1), event(t, 2)
	first.snapshot(t, one, two)
	earlier := snapshotCall("hello-cut", one, two)
	sink.await(t, earlier)
	first.cut()

	// The stream opens again, and breaks after two of the three events of its snapshot.
	second := h.next(t, collector.RoleSpoke)
	three, four, five := event(t, 3), event(t, 4), event(t, 5)
	require.NoError(t, second.sink.SnapshotStart())
	require.NoError(t, second.sink.Event(three))
	require.NoError(t, second.sink.Event(four))
	second.cut()

	// It opens again. Until its snapshot ends, the sink keeps the earlier one, which nothing replaced, and then the
	// new snapshot replaces it.
	third := h.next(t, collector.RoleSpoke)
	sink.stays(t, earlier)
	third.snapshot(t, three, four, five)
	sink.await(t, earlier, snapshotCall("hello-cut", three, four, five))
}

func TestAChangeOfTheSettingsTheContextOrTheRunningDigestOpensANewStream(t *testing.T) {
	e := newEnv(t)
	h := newHello(collector.RoleSpoke)
	e.serve("hello-changes", h)
	e.createCollector("hello-changes", `{"greeting": "hello"}`, noData(), configv1alpha1.CollectorRoleSpoke)
	e.startStreams(spokeOnly(&recordingSink{}))

	first := h.next(t, collector.RoleSpoke)
	require.JSONEq(t, `{"greeting": "hello"}`, string(first.req.Settings))
	require.Equal(t, "local", first.req.Context.Cluster, "the default name of a cluster")
	require.Equal(t, namespace, first.req.Context.OperatorNamespace)
	require.Equal(t, "vexplain.bedag.ch/task", first.req.Context.OwnPodLabel)
	require.JSONEq(t, `{}`, string(first.req.Context.Scope), "no scope: every pod")
	require.JSONEq(t, `{}`, string(first.req.Context.OwnerAttribution), "no allowlists: nothing is copied")

	// spec.settings change.
	e.updateCollector("hello-changes", false, func(c *configv1alpha1.Collector) {
		c.Spec.Settings = &runtime.RawExtension{Raw: []byte(`{"greeting": "bonjour"}`)}
	})
	second := h.next(t, collector.RoleSpoke)
	require.JSONEq(t, `{"greeting": "bonjour"}`, string(second.req.Settings))
	require.Eventually(t, first.ended, wait, tick, "the stream with the old settings stops")

	// The OperatorConfig sets a scope, with the cluster's name and an allowlist of owner attribution.
	config := &configv1alpha1.OperatorConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "default"},
		Spec: configv1alpha1.OperatorConfigSpec{
			ClusterName: ptr.To("cluster-a"),
			Scope: &configv1alpha1.Scope{
				IncludeNamespaces: &metav1.LabelSelector{MatchLabels: map[string]string{"team": "team-a"}},
			},
			OwnerAttribution: &configv1alpha1.OwnerAttribution{NamespaceLabels: []string{"team"}},
		},
	}
	require.NoError(t, e.api.Create(t.Context(), config))
	t.Cleanup(func() { assert.NoError(t, client.IgnoreNotFound(e.api.Delete(context.Background(), config))) })
	third := h.next(t, collector.RoleSpoke)
	require.JSONEq(t, `{"includeNamespaces": {"matchLabels": {"team": "team-a"}}}`, string(third.req.Context.Scope))
	require.Equal(t, "cluster-a", third.req.Context.Cluster)
	require.JSONEq(t, `{"namespaceLabels": ["team"]}`, string(third.req.Context.OwnerAttribution))
	require.Equal(t, namespace, third.req.Context.OperatorNamespace)
	require.Equal(t, "vexplain.bedag.ch/task", third.req.Context.OwnPodLabel)
	require.JSONEq(t, `{"greeting": "bonjour"}`, string(third.req.Settings))
	require.Eventually(t, second.ended, wait, tick, "the stream with the old context stops")

	// Another digest runs: the collector was upgraded.
	e.updateCollector("hello-changes", true, func(c *configv1alpha1.Collector) {
		c.Status.PackageDigest = ptr.To(packageDigest(1))
	})
	h.next(t, collector.RoleSpoke)
	require.Eventually(t, third.ended, wait, tick, "the stream of the old digest stops")
}

func TestOnlyAUsableCollectorGetsAStream(t *testing.T) {
	e := newEnv(t)
	usable, unusable := newHello(collector.RoleSpoke), newHello(collector.RoleSpoke)
	e.serve("hello-usable", usable)
	e.serve("hello-unusable", unusable)
	e.createCollector("hello-usable", "", noData(), configv1alpha1.CollectorRoleSpoke)
	e.createCollector("hello-unusable", "", notReady(configv1alpha1.ReasonSettingsInvalid),
		configv1alpha1.CollectorRoleSpoke)
	sink := &recordingSink{}
	e.startStreams(spokeOnly(sink))

	call := usable.next(t, collector.RoleSpoke)
	unusable.none(t, collector.RoleSpoke)

	// Once the deployer finds the settings valid, that collector gets its stream too.
	e.setReady("hello-unusable", noData())
	unusable.next(t, collector.RoleSpoke)

	// A collector that turns unhealthy gets no new requests: its stream stops. What it delivered stays, since its
	// health gates new evidence and not what it already delivered: the sink isn't told to forget it.
	one := event(t, 1)
	call.snapshot(t, one)
	sink.await(t, snapshotCall("hello-usable", one))
	e.setReady("hello-usable", notReady(configv1alpha1.ReasonCollectorFailing))
	require.Eventually(t, call.ended, wait, tick)
	usable.none(t, collector.RoleSpoke)
	sink.stays(t, snapshotCall("hello-usable", one))
}

func TestEachRoleStreamsToTheSinkOfItsRole(t *testing.T) {
	e := newEnv(t)
	h := newHello(collector.RoleSpoke, collector.RoleHub)
	e.serve("hello-roles", h)
	e.createCollector("hello-roles", "", noData(), configv1alpha1.CollectorRoleSpoke, configv1alpha1.CollectorRoleHub)
	spokeSink, hubSink := &recordingSink{}, &recordingSink{}
	e.startStreams(map[configv1alpha1.CollectorRole]collectorclient.Sink{
		configv1alpha1.CollectorRoleSpoke: spokeSink,
		configv1alpha1.CollectorRoleHub:   hubSink,
	})

	spoke := h.next(t, collector.RoleSpoke)
	hub := h.next(t, collector.RoleHub)
	one := event(t, 1)
	spoke.snapshot(t, one)
	hub.snapshot(t)
	require.NoError(t, hub.sink.SourceChanged(one.Subject()))

	spokeSink.await(t, snapshotCall("hello-roles", one))
	hubSink.await(t, snapshotCall("hello-roles"), sourceChangedCall("hello-roles", one.Subject()))
}

// Hub and spoke meet only through the stores and the executor, so a cluster that runs one role has the sink of that
// role only, and a collector's other role gets no stream there.
func TestARoleWithoutASinkGetsNoStream(t *testing.T) {
	e := newEnv(t)
	h := newHello(collector.RoleSpoke, collector.RoleHub)
	e.serve("hello-hub-only", h)
	e.createCollector("hello-hub-only", "", noData(), configv1alpha1.CollectorRoleSpoke,
		configv1alpha1.CollectorRoleHub)
	// A collector that doesn't watch gets no stream in any role.
	quietOne := newHello(collector.RoleHub)
	e.serve("hello-no-watch", quietOne)
	e.createCollector("hello-no-watch", "", noData(), configv1alpha1.CollectorRoleHub)
	e.updateCollector("hello-no-watch", true, func(c *configv1alpha1.Collector) {
		c.Status.Capabilities.Watch = configv1alpha1.CollectorWatchNotSupported
	})
	e.startStreams(map[configv1alpha1.CollectorRole]collectorclient.Sink{configv1alpha1.CollectorRoleHub: &recordingSink{}})

	h.next(t, collector.RoleHub)
	h.none(t, collector.RoleSpoke)
	quietOne.none(t, collector.RoleHub)
}

func TestADeletedCollectorsStreamsStopAndEachSinkForgetsIt(t *testing.T) {
	e := newEnv(t)
	h := newHello(collector.RoleSpoke, collector.RoleHub)
	e.serve("hello-deleted", h)
	e.createCollector("hello-deleted", "", noData(), configv1alpha1.CollectorRoleSpoke, configv1alpha1.CollectorRoleHub)
	spokeSink, hubSink := &recordingSink{}, &recordingSink{}
	e.startStreams(map[configv1alpha1.CollectorRole]collectorclient.Sink{
		configv1alpha1.CollectorRoleSpoke: spokeSink,
		configv1alpha1.CollectorRoleHub:   hubSink,
	})
	spoke, hub := h.next(t, collector.RoleSpoke), h.next(t, collector.RoleHub)
	one := event(t, 1)
	spoke.snapshot(t, one)
	hub.snapshot(t)
	spokeSink.await(t, snapshotCall("hello-deleted", one))
	hubSink.await(t, snapshotCall("hello-deleted"))
	require.True(t, e.pool.Connected("hello-deleted"))

	deleted := &configv1alpha1.Collector{ObjectMeta: metav1.ObjectMeta{Name: "hello-deleted"}}
	require.NoError(t, e.api.Delete(t.Context(), deleted))
	require.Eventually(t, func() bool { return spoke.ended() && hub.ended() }, wait, tick, "its streams stop")
	spokeSink.await(t, snapshotCall("hello-deleted", one), forgetCall("hello-deleted"))
	hubSink.await(t, snapshotCall("hello-deleted"), forgetCall("hello-deleted"))
	require.False(t, e.pool.Connected("hello-deleted"), "its connection is closed")
	h.none(t, collector.RoleSpoke)
	spokeSink.stays(t, snapshotCall("hello-deleted", one), forgetCall("hello-deleted"))
}

func TestABrokenStreamCallsNoSinkAndReportsNoHealth(t *testing.T) {
	e := newEnv(t)
	h := newHello(collector.RoleSpoke)
	e.serve("hello-broken", h)
	e.createCollector("hello-broken", "", noData(), configv1alpha1.CollectorRoleSpoke)
	var before configv1alpha1.Collector
	require.NoError(t, e.api.Get(t.Context(), client.ObjectKey{Name: "hello-broken"}, &before))
	sink := &recordingSink{}
	e.startStreams(spokeOnly(sink))

	// The stream breaks before its snapshot, then in the middle of it, and opens again each time.
	h.next(t, collector.RoleSpoke).cut()
	second := h.next(t, collector.RoleSpoke)
	require.NoError(t, second.sink.SnapshotStart())
	require.NoError(t, second.sink.Event(event(t, 1)))
	second.cut()
	h.next(t, collector.RoleSpoke)

	sink.stays(t)
	var after configv1alpha1.Collector
	require.NoError(t, e.api.Get(t.Context(), client.ObjectKey{Name: "hello-broken"}, &after))
	require.Equal(t, before.ResourceVersion, after.ResourceVersion, "the streams write nothing to the Collector")
	ready := meta.FindStatusCondition(after.Status.Conditions, configv1alpha1.ConditionReady)
	require.NotNil(t, ready)
	require.Equal(t, configv1alpha1.ReasonNoData, ready.Reason, "a broken stream is no health failure")
}

func TestABrokenStreamOpensAgainAfterASecondAndTheWaitDoubles(t *testing.T) {
	e := newEnv(t)
	h := newHello(collector.RoleSpoke)
	e.serve("hello-retry", h)
	e.createCollector("hello-retry", "", noData(), configv1alpha1.CollectorRoleSpoke)
	sink := &recordingSink{}
	e.startStreams(spokeOnly(sink))

	call := h.next(t, collector.RoleSpoke)
	broke := time.Now()
	call.cut()
	call = h.next(t, collector.RoleSpoke)
	require.GreaterOrEqual(t, time.Since(broke), collectorclient.FirstRetry)
	broke = time.Now()
	call.cut()
	call = h.next(t, collector.RoleSpoke)
	require.GreaterOrEqual(t, time.Since(broke), 2*collectorclient.FirstRetry, "the wait doubles")

	// A stream that delivered its snapshot starts the waits again from a second.
	call.snapshot(t)
	sink.await(t, snapshotCall("hello-retry"))
	broke = time.Now()
	call.cut()
	h.next(t, collector.RoleSpoke)
	waited := time.Since(broke)
	require.GreaterOrEqual(t, waited, collectorclient.FirstRetry)
	require.Less(t, waited, 4*collectorclient.FirstRetry, "the wait starts again from a second, and not from four")
}

func TestTheWaitBeforeABrokenStreamOpensAgainDoublesUpToAMinute(t *testing.T) {
	t.Parallel()
	require.Equal(t, time.Second, collectorclient.FirstRetry)
	require.Equal(t, time.Minute, collectorclient.MaxRetry)
	var waits []time.Duration
	for d := collectorclient.FirstRetry; len(waits) < 8; d = collectorclient.NextRetry(d) {
		waits = append(waits, d)
	}
	require.Equal(t, []time.Duration{
		time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second, 16 * time.Second, 32 * time.Second,
		time.Minute, time.Minute,
	}, waits)
}

// A collector needn't be built with the SDK, so the streams check what it sends again. What isn't valid is dropped,
// and never reaches a sink. The logs say what was dropped, and repeat nothing that the collector chose.
func TestWhatACollectorSendsIsCheckedAgain(t *testing.T) {
	e := newEnv(t)
	r := newRaw()
	e.serveRaw("hello-raw", r)
	e.createCollector("hello-raw", "", noData(), configv1alpha1.CollectorRoleSpoke)
	sink := &recordingSink{}
	logs := &logLines{}
	e.startStreamsLogging(spokeOnly(sink), logs.logger())

	// The marks are text that the collector chose.
	valid := event(t, 1)
	invalid := eventOf(t, helloType, "marker-subject", map[string]int{"n": 2})
	invalid.SetID("marker-id")
	undeclared := eventOf(t, "com.example.marker.v1alpha1", subject.Image(digest(3)), map[string]int{"n": 3})
	undeclared.SetID("marker-undeclared-id")

	// In the snapshot: an event that isn't valid evidence, and one of a type that the collector doesn't declare.
	w := r.next(t)
	w.send(t, snapshotStart(), eventItem(t, valid), eventItem(t, invalid), eventItem(t, undeclared), snapshotEnd())
	sink.await(t, snapshotCall("hello-raw", valid))

	// After it: a tombstone of a type that the collector doesn't declare, a tombstone and a change of source about
	// what is no subject, and an event that isn't valid evidence. Without the subject that is none, the change of
	// source would name no subject, which means every subject, so the whole change is dropped.
	w.send(t,
		tombstoneItem("com.example.marker.v1alpha1", valid.Subject()),
		tombstoneItem(helloType, "marker-tombstone"),
		sourceChangedItem(valid.Subject(), "marker-source-changed"),
		eventItem(t, invalid),
		eventItem(t, undeclared),
		sourceChangedItem(valid.Subject()),
	)
	sink.await(t, snapshotCall("hello-raw", valid), sourceChangedCall("hello-raw", valid.Subject()))
	require.Contains(t, logs.String(), "Dropped")
	require.NotContains(t, logs.String(), "marker")

	// The collector restarts, and breaks the order of its new stream: a tombstone in the middle of a snapshot. The
	// streams end that stream, nothing of its snapshot reaches the sink, and the stream opens again.
	w.end <- status.Error(codes.Unavailable, "restarting")
	w = r.next(t)
	two, three := event(t, 2), event(t, 3)
	w.send(t, snapshotStart(), eventItem(t, two), tombstoneItem(helloType, two.Subject()))
	require.Eventually(t, func() bool { return w.ctx.Err() != nil }, wait, tick, "the streams end the stream")
	w = r.next(t)
	w.send(t, snapshotStart(), eventItem(t, three), snapshotEnd())
	sink.await(t, snapshotCall("hello-raw", valid), sourceChangedCall("hello-raw", valid.Subject()),
		snapshotCall("hello-raw", three))
	require.NotContains(t, logs.String(), "marker")
}
