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
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/require"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
	"github.com/bedag/vexplain/internal/collectorclient"
	"github.com/bedag/vexplain/internal/metrics"
	"github.com/bedag/vexplain/internal/settings"
	collectorv1alpha1 "github.com/bedag/vexplain/sdk/api/collector/v1alpha1"
	"github.com/bedag/vexplain/sdk/collector"
	"github.com/bedag/vexplain/sdk/subject"
)

// What a collector sends is bounded (design 5.9): a snapshot ends within a minute and holds at most 64 MiB, and an
// answer holds at most 64 events and 128 MiB. A collector past a bound breaks the contract: the streams end its
// stream, and Invoke ends its call, and each logs which bound it passed and counts it.

// clusterName is the name of the cluster of the tests: no OperatorConfig names one, so the context carries the default.
const clusterName = settings.DefaultClusterName

// breaks returns how often the collector of the name passed the bound, as the metric counts it.
func breaks(name, bound string) float64 {
	return testutil.ToFloat64(metrics.CollectorContractBreaksTotal.WithLabelValues(clusterName, name, bound))
}

func TestTheBoundsOfWhatACollectorSends(t *testing.T) {
	t.Parallel()
	require.Equal(t, time.Minute, collectorclient.MaxSnapshotTime, "the contract's minute")
	require.Equal(t, 64<<20, collectorclient.MaxSnapshotBytes)
	require.Equal(t, time.Minute, collectorclient.SettledAfter)
	require.Equal(t, 64, collectorclient.MaxAnswerEvents)
	require.Equal(t, 128<<20, collectorclient.MaxAnswerBytes, "8 platforms of an image, each in a message of 16 MiB")
	require.Equal(t, 64, collectorclient.EventsBound())
	require.Equal(t, 1, collectorclient.EventsBound(collectorclient.MaxEvents(1)))
	require.Equal(t, 64, collectorclient.EventsBound(collectorclient.MaxEvents(100)), "never above the contract's")
}

// A snapshot that doesn't end within its bound ends the stream: nothing of it reaches the sink, and the stream opens
// again after a pause, with a new snapshot.
func TestASnapshotThatDoesNotEndInTimeEndsTheStream(t *testing.T) {
	e := newEnv(t)
	r := newRaw()
	const name = "hello-slow"
	e.serveRaw(name, r)
	e.createCollector(name, "", noData(), configv1alpha1.CollectorRoleSpoke)
	sink := &recordingSink{}
	logs := &logLines{}
	e.startStreamsWith(spokeOnly(sink), logs.logger(), func(s *collectorclient.Streams) {
		s.SetBounds(500*time.Millisecond, collectorclient.MaxSnapshotBytes, collectorclient.SettledAfter)
	})
	before := breaks(name, "snapshot_time")

	w := r.next(t)
	w.send(t, snapshotStart(), eventItem(t, event(t, 1)))
	require.Eventually(t, func() bool { return w.ctx.Err() != nil }, wait, tick, "the streams end the stream")
	sink.stays(t)
	require.Equal(t, before+1, breaks(name, "snapshot_time"))
	require.Contains(t, logs.String(), `"bound"="snapshot_time"`)
	require.Contains(t, logs.String(), `"collector"="hello-slow"`)

	two := event(t, 2)
	w = r.next(t)
	w.send(t, snapshotStart(), eventItem(t, two), snapshotEnd())
	sink.await(t, snapshotCall(name, two))
}

// A snapshot whose messages hold more than 64 MiB ends the stream at the message that passes the bound: the streams
// hold a snapshot until its end, so one without a bound could hold the operator's memory.
func TestASnapshotOverItsBoundEndsTheStream(t *testing.T) {
	e := newEnv(t)
	r := newRaw()
	const name = "hello-large"
	e.serveRaw(name, r)
	e.createCollector(name, "", noData(), configv1alpha1.CollectorRoleSpoke)
	sink := &recordingSink{}
	logs := &logLines{}
	e.startStreamsLogging(spokeOnly(sink), logs.logger())
	before := breaks(name, "snapshot_size")

	// Each event holds a little less than 4 MiB of data: the seventeenth passes 64 MiB.
	w := r.next(t)
	w.send(t, snapshotStart())
	padding := strings.Repeat("a", 4<<20-1024)
	for n := range 17 {
		w.send(t, eventItem(t, eventOf(t, helloType, subject.Image(digest(n)), map[string]string{"pad": padding})))
	}
	require.Eventually(t, func() bool { return w.ctx.Err() != nil }, wait, tick, "the streams end the stream")
	sink.stays(t)
	require.Equal(t, before+1, breaks(name, "snapshot_size"))
	require.Contains(t, logs.String(), `"bound"="snapshot_size"`)
	require.NotContains(t, logs.String(), padding[:64], "the log repeats nothing that the collector sent")

	one := event(t, 1)
	w = r.next(t)
	w.send(t, snapshotStart(), eventItem(t, one), snapshotEnd())
	sink.await(t, snapshotCall(name, one))
}

// A collector whose Watch ends right after its snapshot, an easy mistake, would otherwise be watched again every
// second, each time with a whole snapshot. Its stream opens again after the waits of a stream that fails: a second,
// then twice as long each time. Only a stream that stayed open a while past its snapshot starts the waits again.
func TestAStreamThatEndsRightAfterItsSnapshotWaitsAsAFailingStreamDoes(t *testing.T) {
	e := newEnv(t)
	h := newHello(collector.RoleSpoke)
	const name = "hello-returns"
	e.serve(name, h)
	e.createCollector(name, "", noData(), configv1alpha1.CollectorRoleSpoke)
	sink := &recordingSink{}
	e.startStreams(spokeOnly(sink))

	call := h.next(t, collector.RoleSpoke)
	waits := make([]time.Duration, 0, 3)
	for range 3 {
		call.snapshot(t)
		ended := time.Now()
		call.end <- nil
		call = h.next(t, collector.RoleSpoke)
		waits = append(waits, time.Since(ended))
	}
	require.GreaterOrEqual(t, waits[0], collectorclient.FirstRetry)
	require.GreaterOrEqual(t, waits[1], 2*collectorclient.FirstRetry, "the wait doubles")
	require.GreaterOrEqual(t, waits[2], 4*collectorclient.FirstRetry, "and again: the snapshots don't start it again")
}

// An answer that doesn't end, as from a collector that sends events in a loop, ends at its 65th event: Invoke returns
// the error of the contract, and reads no further.
func TestAnAnswerThatDoesNotEndEndsAtItsBoundOfEvents(t *testing.T) {
	e := newEnv(t)
	r := newRaw()
	const name = "hello-endless"
	var sent atomic.Int64
	r.answerStreaming(func(ctx context.Context, send func(*collectorv1alpha1.InvokeResponse) error) error {
		for n := 0; ctx.Err() == nil; n++ {
			if err := send(answerEvent(t, event(t, n))); err != nil {
				return err
			}
			sent.Add(1)
		}
		return ctx.Err()
	})
	e.serveRaw(name, r)
	before := breaks(name, "answer_events")
	ctx, cancel := context.WithTimeout(t.Context(), wait)
	defer cancel()

	events, failure, err := e.pool.Invoke(ctx, name, inCluster(greeting(1)))

	require.ErrorIs(t, err, collectorclient.ErrContract)
	require.Empty(t, events)
	require.Nil(t, failure)
	require.Equal(t, before+1, breaks(name, "answer_events"))
	require.Eventually(t, func() bool {
		n := sent.Load()
		time.Sleep(10 * tick)
		return sent.Load() == n
	}, wait, tick, "the collector can send no more")
	require.Less(t, sent.Load(), int64(1000), "the call ended near the bound")
}

// An answer whose messages hold more than its bound ends at the message that passes it.
func TestAnAnswerOverItsBoundOfBytesEndsTheCall(t *testing.T) {
	e := newEnv(t)
	r := newRaw()
	const name = "hello-large-answer"
	padding := strings.Repeat("a", 300<<10)
	r.answerWith(func(*collectorv1alpha1.InvokeRequest) ([]*collectorv1alpha1.InvokeResponse, error) {
		answer := make([]*collectorv1alpha1.InvokeResponse, 0, 4)
		for n := range 4 {
			answer = append(answer, answerEvent(t, eventOf(t, helloType, subject.Image(digest(n)), map[string]string{"pad": padding})))
		}
		return answer, nil
	})
	e.serveRaw(name, r)
	e.pool.SetAnswerBounds(collectorclient.MaxAnswerEvents, 1<<20)
	before := breaks(name, "answer_size")

	events, failure, err := e.pool.Invoke(t.Context(), name, inCluster(greeting(1)))

	require.ErrorIs(t, err, collectorclient.ErrContract)
	require.NotContains(t, err.Error(), padding[:64])
	require.Empty(t, events)
	require.Nil(t, failure)
	require.Equal(t, before+1, breaks(name, "answer_size"))
}

// A caller that takes one event, as the hub's match does, gets the error of the contract at the second, and Invoke
// reads no further: the call ends there, even when the collector would never end it.
func TestInvokeStopsReadingAtTheFirstEventPastTheCallersBound(t *testing.T) {
	e := newEnv(t)
	r := newRaw()
	const name = "hello-two"
	r.answerStreaming(func(ctx context.Context, send func(*collectorv1alpha1.InvokeResponse) error) error {
		for n := range 2 {
			if err := send(answerEvent(t, event(t, n))); err != nil {
				return err
			}
		}
		<-ctx.Done()
		return ctx.Err()
	})
	e.serveRaw(name, r)
	ctx, cancel := context.WithTimeout(t.Context(), wait)
	defer cancel()

	start := time.Now()
	events, _, err := e.pool.Invoke(ctx, name, inCluster(greeting(1)), collectorclient.MaxEvents(1))

	require.ErrorIs(t, err, collectorclient.ErrContract)
	require.Empty(t, events)
	require.Less(t, time.Since(start), wait/2, "Invoke didn't wait for the end of the answer")
}

// inCluster returns req with the context of the tests' cluster, as every call of the operator carries one.
func inCluster(req *collectorv1alpha1.InvokeRequest) *collectorv1alpha1.InvokeRequest {
	req.Context = &collectorv1alpha1.Context{Cluster: clusterName, OperatorNamespace: namespace}
	return req
}
