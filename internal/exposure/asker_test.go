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

package exposure_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	cloudevents "github.com/cloudevents/sdk-go/v2"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	clocktesting "k8s.io/utils/clock/testing"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
	"github.com/bedag/vexplain/internal/collectorclient"
	"github.com/bedag/vexplain/internal/evidence"
	"github.com/bedag/vexplain/internal/exposure"
	"github.com/bedag/vexplain/internal/metrics"
	collectorv1alpha1 "github.com/bedag/vexplain/sdk/api/collector/v1alpha1"
	sdkcollector "github.com/bedag/vexplain/sdk/collector"
	sdkevidence "github.com/bedag/vexplain/sdk/evidence"
)

// The asker runs on a fake client, whose store the view reads at each write, as its watch would deliver the write, and
// on a fake clock. The sources are a fake collector pool.

const (
	// dmz and dmzBackup are sources of dmzType that take hosts and addresses.
	dmz       = "dmz"
	dmzBackup = "dmz-backup"
	// names is a source of namesType that takes hosts only, and addresses one of addressesType that takes addresses
	// only.
	names         = "names"
	namesType     = "ch.example.names.publication.v1alpha1"
	addresses     = "addresses"
	addressesType = "ch.example.addresses.publication.v1alpha1"
	// lookup is the operation of every source, in the hub role.
	lookup = "lookup"
	// playbook is the name of the playbooks of the tests.
	playbook = "container-cves"
)

// watched is the store of an asker's test. Each write reads its subject into the view at once, as the view's
// controller reads it once the watch delivers the write.
type watched struct {
	evidence.Store
	view *exposure.View
	t    *testing.T
}

func (w watched) Put(ctx context.Context, source, collectorVersion string, e cloudevents.Event,
	opts ...evidence.PutOption) error {
	err := w.Store.Put(ctx, source, collectorVersion, e, opts...)
	w.read(ctx, e.Subject())
	return err
}

func (w watched) Delete(ctx context.Context, k evidence.Key) error {
	err := w.Store.Delete(ctx, k)
	w.read(ctx, k.Subject)
	return err
}

func (w watched) read(ctx context.Context, about string) {
	_, err := w.view.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Name: about}})
	assert.NoError(w.t, err, "the view reads %s", about)
}

// call is one call that a source got.
type call struct {
	collector, operation, subject, parameters, cluster string
	role                                               collectorv1alpha1.Role
	hosts, addresses                                   []string
}

// pool stands in for the collector pool of the hub. Each source answers every point that it is asked about with
// None, unless answer says otherwise.
type pool struct {
	clock *clocktesting.FakeClock
	// types are the types that the sources answer with, by the names of their Collectors.
	types map[string]string

	mu     sync.Mutex
	calls  []call
	answer func(c call) ([]cloudevents.Event, *collectorclient.Failure, error)
}

func (p *pool) Invoke(_ context.Context, collector string, req *collectorv1alpha1.InvokeRequest,
	_ ...collectorclient.InvokeOption) ([]cloudevents.Event, *collectorclient.Failure, error) {
	var params sdkcollector.EntryPointParameters
	if err := json.Unmarshal(req.GetParameters(), &params); err != nil {
		return nil, nil, err
	}
	c := call{collector: collector, operation: req.GetOperation(), subject: req.GetSubject(),
		parameters: string(req.GetParameters()), cluster: req.GetContext().GetCluster(), role: req.GetRole(),
		hosts: params.Hosts, addresses: params.Addresses}
	p.mu.Lock()
	p.calls = append(p.calls, c)
	answer := p.answer
	p.mu.Unlock()
	if answer != nil {
		return answer(c)
	}
	return p.answers(c, none), nil, nil
}

// answers returns an answer about each point of the call, of its source's type, given now.
func (p *pool) answers(c call, publishedTo string) []cloudevents.Event {
	events := make([]cloudevents.Event, 0, len(c.hosts)+len(c.addresses))
	for _, h := range c.hosts {
		events = append(events, p.answerAbout(c.collector, "host/"+h, publishedTo))
	}
	for _, a := range c.addresses {
		events = append(events, p.answerAbout(c.collector, "address/"+a, publishedTo))
	}
	return events
}

// answerAbout returns the answer of the source of the name about a point, given now.
func (p *pool) answerAbout(collector, point, publishedTo string) cloudevents.Event {
	e, err := sdkevidence.New(p.types[collector], point, publication{PublishedTo: publishedTo},
		sdkevidence.WithSource("/hub/collectors/"+collector), sdkevidence.WithTime(p.clock.Now()))
	if err != nil {
		panic(err)
	}
	return e
}

// taken returns the calls since the last time, and forgets them.
func (p *pool) taken() []call {
	p.mu.Lock()
	defer p.mu.Unlock()
	calls := p.calls
	p.calls = nil
	return calls
}

// count returns how many calls there were since the last taken.
func (p *pool) count() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.calls)
}

// answering sets how the sources answer.
func (p *pool) answering(answer func(c call) ([]cloudevents.Event, *collectorclient.Failure, error)) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.answer = answer
}

// fixture is what an asker's test runs on.
type fixture struct {
	t      *testing.T
	client client.Client
	store  evidence.Store
	view   *exposure.View
	clock  *clocktesting.FakeClock
	pool   *pool
	asker  *exposure.Asker
}

// start is when an asker's test starts, by its clock: an hour before now, so that the store, which measures by the
// real clock how old a record is, finds an answer of the test's past as old as the fake clock says, or older.
var start = time.Now().Add(-time.Hour).Truncate(time.Second).UTC()

// newFixture returns a fixture with no Collector and no Playbook, a view that has read the empty store, and an asker.
func newFixture(t *testing.T) *fixture {
	t.Helper()
	c := fake.NewClientBuilder().WithScheme(scheme).Build()
	crd := evidence.NewCRDStore(c, nil, func() string { return hub })
	view := exposure.NewView(crd)
	require.NoError(t, view.FirstList(t.Context()))
	require.True(t, view.Synced(), "the first list of an empty store reads everything")
	clock := clocktesting.NewFakeClock(start)
	f := &fixture{t: t, client: c, store: watched{Store: crd, view: view, t: t}, view: view, clock: clock,
		pool: &pool{clock: clock, types: map[string]string{}}}
	f.asker = f.newAsker()
	return f
}

// newAsker returns an asker of the fixture, as the hub starts one.
func (f *fixture) newAsker() *exposure.Asker {
	a := exposure.NewAsker(f.view, f.store, f.client, f.pool, func(context.Context) (*collectorv1alpha1.Context, error) {
		return &collectorv1alpha1.Context{Cluster: hub}, nil
	})
	a.UseClock(f.clock)
	return a
}

// pass runs one pass of the fixture's asker.
func (f *fixture) pass() {
	f.asker.Pass(f.t.Context())
}

// run runs the fixture's asker until the test ends, as the manager runs it.
func (f *fixture) run() {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- f.asker.Start(ctx) }()
	f.t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			assert.NoError(f.t, err, "the asker stops once its context ends")
		case <-time.After(wait):
			assert.Fail(f.t, "the asker didn't stop")
		}
	})
}

// advance moves the clock on by d, in steps of the asker's resync, after each of which the running asker makes a
// pass. Before each step, and at the end, it waits until the asker sleeps.
func (f *fixture) advance(d time.Duration) {
	f.t.Helper()
	for ; d > 0; d -= exposure.Resync {
		require.Eventually(f.t, f.clock.HasWaiters, wait, time.Millisecond, "the asker sleeps")
		f.clock.Step(min(d, exposure.Resync))
	}
	require.Eventually(f.t, f.clock.HasWaiters, wait, time.Millisecond, "the asker sleeps")
}

// addSource adds a Collector that can be used, whose operation lookup answers about entry points, of the type, and
// takes the parameters.
func (f *fixture) addSource(name, eventType string, parameters ...string) {
	f.t.Helper()
	c := &configv1alpha1.Collector{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Status: configv1alpha1.CollectorStatus{
			Version: ptr.To(version),
			Capabilities: &configv1alpha1.CollectorCapabilities{
				Roles:    []configv1alpha1.CollectorRole{configv1alpha1.CollectorRoleHub},
				Produces: []configv1alpha1.ProducedType{{Type: eventType, Scope: configv1alpha1.EvidenceScopeHub}},
				Operations: []configv1alpha1.CollectorOperation{{Name: lookup,
					Role: ptr.To(configv1alpha1.CollectorRoleHub), Parameters: parameters, Produces: []string{eventType}}},
			},
		},
	}
	require.NoError(f.t, f.client.Create(f.t.Context(), c))
	f.pool.types[name] = eventType
}

// changeDMZ changes the Collector dmz, as the deployer records what its collector says.
func (f *fixture) changeDMZ(change func(c *configv1alpha1.Collector)) {
	f.t.Helper()
	var c configv1alpha1.Collector
	require.NoError(f.t, f.client.Get(f.t.Context(), client.ObjectKey{Name: dmz}, &c))
	change(&c)
	require.NoError(f.t, f.client.Update(f.t.Context(), &c))
}

// addPlaybook adds a playbook of the name, Ready or not, which takes the evidence of the entries. Only its Ready
// condition and its evidence count for the asker.
func (f *fixture) addPlaybook(name string, ready bool, entries ...configv1alpha1.PlaybookEvidence) {
	f.t.Helper()
	p := &configv1alpha1.Playbook{ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: configv1alpha1.PlaybookSpec{Evidence: entries}}
	setReady(p, ready)
	require.NoError(f.t, f.client.Create(f.t.Context(), p))
}

// setReady sets the Ready condition of a playbook.
func setReady(p *configv1alpha1.Playbook, ready bool) {
	condition := metav1.Condition{Type: configv1alpha1.ConditionReady, Status: metav1.ConditionTrue, Reason: "Valid",
		LastTransitionTime: metav1.Now()}
	if !ready {
		condition.Status, condition.Reason = metav1.ConditionFalse, "CollectorMissing"
	}
	p.Status.Conditions = []metav1.Condition{condition}
}

// takes returns evidence of the type, as a playbook names it, pinned to the Collectors when any are given.
func takes(eventType string, collectors ...string) configv1alpha1.PlaybookEvidence {
	return configv1alpha1.PlaybookEvidence{Name: "answers", Type: eventType, Collectors: collectors}
}

// name stores the exposure of the workload of the name in the cluster, which names the entry points.
func (f *fixture) name(cluster, name string, points ...string) {
	f.t.Helper()
	putIn(f.t, f.store, networkReach, cluster, exposureEvent(f.t, workload(cluster, name), points))
}

// answer returns the stored answer of the source of the name about a point, or nil when there is none.
func (f *fixture) answer(eventType, point, collector string) *evidence.Record {
	f.t.Helper()
	record, err := f.store.Get(f.t.Context(), evidence.Key{Subject: point, Type: eventType, Source: collector})
	require.NoError(f.t, err)
	return record
}

// publishedTo returns what a stored answer says.
func publishedTo(t *testing.T, record *evidence.Record) string {
	t.Helper()
	var data publication
	require.NoError(t, json.Unmarshal(record.Event.Data(), &data))
	return data.PublishedTo
}

// hostsOf returns the host names of the subjects.
func hostsOf(subjects []string) []string {
	hosts := make([]string, len(subjects))
	for i, s := range subjects {
		hosts[i] = strings.TrimPrefix(s, "host/")
	}
	return hosts
}

// dmzCalls returns the counter of calls to the source dmz with the result.
func dmzCalls(result string) float64 {
	return testutil.ToFloat64(metrics.SourceCallsTotal.WithLabelValues(hub, dmz, result))
}

// A new entry point is asked of every source, in calls of at most 64 points, in the order of their subjects. The view
// wakes the running asker when the exposure that names it arrives.
func TestANewEntryPointIsAskedOfEachSource(t *testing.T) {
	f := newFixture(t)
	f.addSource(dmz, dmzType, "hosts", "addresses")
	f.addSource(dmzBackup, dmzType, "hosts", "addresses")
	f.addPlaybook(playbook, true, takes(dmzType))
	f.run()

	points := make([]string, 70)
	for i := range points {
		points[i] = fmt.Sprintf("host/h%02d.app.example", i)
	}
	f.name(clusterA, "web", points...)

	require.Eventually(t, func() bool { return f.pool.count() >= 4 }, wait, poll)
	got := f.pool.taken()
	want := []call{
		{collector: dmz, subject: points[0], hosts: hostsOf(points[:64])},
		{collector: dmz, subject: points[64], hosts: hostsOf(points[64:])},
		{collector: dmzBackup, subject: points[0], hosts: hostsOf(points[:64])},
		{collector: dmzBackup, subject: points[64], hosts: hostsOf(points[64:])},
	}
	require.Len(t, got, len(want))
	for i, c := range got {
		require.Equal(t, want[i].collector, c.collector, "call %d", i)
		require.Equal(t, want[i].subject, c.subject, "call %d: the subject of its first point", i)
		require.Equal(t, want[i].hosts, c.hosts, "call %d", i)
		require.Empty(t, c.addresses, "call %d", i)
		require.NotContains(t, c.parameters, "addresses", "call %d: hosts only", i)
		require.Equal(t, lookup, c.operation)
		require.Equal(t, collectorv1alpha1.Role_ROLE_HUB, c.role)
		require.Equal(t, hub, c.cluster, "the context of the hub's calls")
	}
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		for _, collector := range []string{dmz, dmzBackup} {
			for _, p := range points {
				held, err := f.store.Get(t.Context(), evidence.Key{Subject: p, Type: dmzType, Source: collector})
				assert.NoError(c, err)
				assert.NotNil(c, held, "%s's answer about %s", collector, p)
			}
		}
	}, wait, poll)
	require.Never(t, func() bool { return f.pool.count() > 0 }, 200*time.Millisecond, poll,
		"an answered entry point isn't asked again")
}

// A source is asked about hosts only when its operation takes hosts, and about addresses only when it takes addresses.
func TestAnOperationThatTakesOnlyHostsIsNeverAskedAboutAddresses(t *testing.T) {
	f := newFixture(t)
	f.addSource(names, namesType, "hosts")
	f.addSource(addresses, addressesType, "addresses")
	f.addPlaybook(playbook, true, takes(namesType), takes(addressesType))
	f.name(clusterA, "web", shop, shopAddress)

	f.pass()
	got := f.pool.taken()
	require.Len(t, got, 2)
	require.Equal(t, addresses, got[0].collector)
	require.Equal(t, shopAddress, got[0].subject)
	require.Equal(t, []string{shopIP}, got[0].addresses)
	require.Empty(t, got[0].hosts)
	require.Equal(t, names, got[1].collector)
	require.Equal(t, shop, got[1].subject)
	require.Equal(t, []string{shopHost}, got[1].hosts)
	require.Empty(t, got[1].addresses)

	f.clock.Step(time.Hour)
	f.pass()
	require.Empty(t, f.pool.taken(), "the address stays unasked of names, and every answer stands")
	require.Nil(t, f.answer(namesType, shopAddress, names))
	require.Nil(t, f.answer(addressesType, shop, addresses))
}

// A source that refuses a call as InvalidInput can't read one of its points. The call is asked again in halves, down
// to the single point that it refuses, so that every other point gets its answer. The refused point stays unanswered,
// and is asked again after a minute, not at every pass.
func TestARefusedCallIsSplitInHalves(t *testing.T) {
	for name, refusal := range map[string]struct {
		failure *collectorclient.Failure
		err     error
	}{
		"by the source": {failure: &collectorclient.Failure{Reason: sdkcollector.ReasonInvalidInput,
			Message: "a point isn't a name"}},
		"by the schema of the parameters": {err: status.Error(codes.InvalidArgument,
			"the parameters are not valid: at '/hosts/5': got localhost")},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			f.addSource(dmz, dmzType, "hosts", "addresses")
			f.addPlaybook(playbook, true, takes(dmzType))
			hosts := []string{"api", "cart", "docs", "edge", "files", "localhost", "mail", "news", "shop", "web"}
			points := make([]string, len(hosts))
			for i, h := range hosts {
				points[i] = "host/" + h + ".app.example"
			}
			localhost := points[5]
			f.pool.answering(func(c call) ([]cloudevents.Event, *collectorclient.Failure, error) {
				if slices.ContainsFunc(c.hosts, func(h string) bool { return strings.HasPrefix(h, "localhost.") }) {
					return nil, refusal.failure, refusal.err
				}
				return f.pool.answers(c, none), nil, nil
			})
			f.name(clusterA, "web", points...)
			refused, succeeded := dmzCalls(sdkcollector.ReasonInvalidInput), dmzCalls("Succeeded")

			f.pass()
			taken := f.pool.taken()
			sizes := make([]int, len(taken))
			for i, c := range taken {
				sizes[i] = len(c.hosts)
			}
			require.Equal(t, []int{10, 5, 5, 2, 1, 1, 3}, sizes,
				"all, the first half, the second, its first half, localhost alone, mail, and the rest")
			for _, p := range points {
				if p == localhost {
					require.Nil(t, f.answer(dmzType, p, dmz), "the refused point stays unanswered")
				} else {
					require.NotNil(t, f.answer(dmzType, p, dmz), "%s gets its answer", p)
				}
			}
			require.Equal(t, refused+4, dmzCalls(sdkcollector.ReasonInvalidInput))
			require.Equal(t, succeeded+3, dmzCalls("Succeeded"))

			f.pass()
			require.Empty(t, f.pool.taken(), "the refused point isn't asked again at once")
			f.clock.Step(time.Minute)
			f.pass()
			again := f.pool.taken()
			require.Len(t, again, 1, "a minute later")
			require.Equal(t, []string{"localhost.app.example"}, again[0].hosts)
			f.clock.Step(time.Minute)
			f.pass()
			require.Empty(t, f.pool.taken(), "two minutes after the second refusal")
		})
	}
}

// A source that fails a call, as NotReady or without any answer, is asked nothing more for a minute, then for two,
// four and eight, and then for a quarter of an hour each time. The running asker wakes on its own timer.
func TestAFailureWaitsAMinuteThenLonger(t *testing.T) {
	for name, failing := range map[string]struct {
		result string
		answer func(c call) ([]cloudevents.Event, *collectorclient.Failure, error)
	}{
		"NotReady": {result: sdkcollector.ReasonNotReady, answer: func(call) ([]cloudevents.Event, *collectorclient.Failure, error) {
			return nil, &collectorclient.Failure{Reason: sdkcollector.ReasonNotReady, Message: "the data is being rebuilt"}, nil
		}},
		"no answer": {result: "Error", answer: func(call) ([]cloudevents.Event, *collectorclient.Failure, error) {
			return nil, nil, errors.New("the collector can't be reached")
		}},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			f.addSource(dmz, dmzType, "hosts", "addresses")
			f.addPlaybook(playbook, true, takes(dmzType))
			f.pool.answering(failing.answer)
			f.name(clusterA, "web", shop)
			failed := dmzCalls(failing.result)
			f.run()

			require.Eventually(t, func() bool { return f.pool.count() == 1 }, wait, poll)
			for _, after := range []time.Duration{time.Minute, 2 * time.Minute, 4 * time.Minute, 8 * time.Minute,
				15 * time.Minute, 15 * time.Minute} {
				before := f.pool.count()
				f.advance(after - exposure.Resync)
				require.Equal(t, before, f.pool.count(), "nothing is asked within %s", after)
				f.advance(exposure.Resync)
				require.Equal(t, before+1, f.pool.count(), "the source is asked again after %s", after)
			}
			require.Equal(t, failed+7, dmzCalls(failing.result))

			// A source that answers again is asked about a new entry point at once.
			f.pool.answering(nil)
			f.advance(15 * time.Minute)
			f.pool.taken()
			f.name(clusterA, "api", api)
			require.Eventually(t, func() bool { return f.pool.count() == 1 }, wait, poll)
		})
	}
}

// An answer counts until its maxAge ends it, so the hub asks again at half its maxAge. An equal answer then writes
// only its new time, which keeps it current.
func TestAnAnswerIsAskedAgainAtHalfItsMaxAge(t *testing.T) {
	f := newFixture(t)
	f.addSource(dmz, dmzType, "hosts", "addresses")
	f.changeDMZ(func(c *configv1alpha1.Collector) {
		c.Status.Capabilities.Produces[0].MaxAgeSeconds = ptr.To[int64](120)
	})
	f.addPlaybook(playbook, true, takes(dmzType))
	f.name(clusterA, "web", shop)

	f.pass()
	require.Len(t, f.pool.taken(), 1)
	first := f.answer(dmzType, shop, dmz)
	require.Equal(t, start, first.Event.Time())

	f.clock.Step(59 * time.Second)
	f.pass()
	require.Empty(t, f.pool.taken(), "before half its maxAge")

	f.clock.Step(time.Second)
	f.pass()
	require.Len(t, f.pool.taken(), 1, "at half its maxAge")
	refreshed := f.answer(dmzType, shop, dmz)
	require.Equal(t, start.Add(time.Minute), refreshed.Event.Time(), "the equal answer's time is stored")
	require.Equal(t, publishedTo(t, first), publishedTo(t, refreshed))

	f.clock.Step(59 * time.Second)
	f.pass()
	require.Empty(t, f.pool.taken(), "the refreshed answer counts from its new time")

	// A source whose answers keep an old time, against its contract, is still asked no more often than every half
	// maxAge.
	f.pool.answering(func(c call) ([]cloudevents.Event, *collectorclient.Failure, error) {
		e, err := sdkevidence.New(dmzType, shop, publication{PublishedTo: none},
			sdkevidence.WithSource("/hub/collectors/dmz"), sdkevidence.WithTime(start))
		return []cloudevents.Event{e}, nil, err
	})
	f.clock.Step(time.Second)
	f.pass()
	require.Len(t, f.pool.taken(), 1, "at half its maxAge again")
	require.Equal(t, start.Add(time.Minute), f.answer(dmzType, shop, dmz).Event.Time(), "an older answer writes nothing")
	f.pass()
	f.clock.Step(59 * time.Second)
	f.pass()
	require.Empty(t, f.pool.taken(), "not again before another half of its maxAge")
	f.clock.Step(time.Second)
	f.pass()
	require.Len(t, f.pool.taken(), 1)
}

// A source's data changed when its version or its collector's did: every entry point is asked again at once. The
// answers stand meanwhile.
func TestAChangeOfTheSourcesVersionAsksAgainAtOnce(t *testing.T) {
	f := newFixture(t)
	f.addSource(dmz, dmzType, "hosts", "addresses")
	f.changeDMZ(func(c *configv1alpha1.Collector) {
		c.Status.Sources = []configv1alpha1.CollectorSource{{Name: "publications", Version: "1"}}
	})
	f.addPlaybook(playbook, true, takes(dmzType))
	f.name(clusterA, "web", shop, shopAddress)

	f.pass()
	require.Len(t, f.pool.taken(), 1)
	f.pass()
	require.Empty(t, f.pool.taken())

	f.changeDMZ(func(c *configv1alpha1.Collector) { c.Status.Sources[0].Version = "2" })
	f.pass()
	again := f.pool.taken()
	require.Len(t, again, 1, "the source's version changed")
	require.Equal(t, []string{shopHost}, again[0].hosts)
	require.Equal(t, []string{shopIP}, again[0].addresses)

	f.changeDMZ(func(c *configv1alpha1.Collector) { c.Status.Version = ptr.To("1.1.0") })
	f.pass()
	require.Len(t, f.pool.taken(), 1, "the collector's version changed")
	require.NotNil(t, f.answer(dmzType, shop, dmz))
	f.pass()
	require.Empty(t, f.pool.taken())
}

// The hub keeps no source version with an answer, so after a start it asks every entry point again. An equal answer
// writes nothing.
func TestEveryEntryPointIsAskedAgainAfterAStart(t *testing.T) {
	f := newFixture(t)
	f.addSource(dmz, dmzType, "hosts", "addresses")
	f.addPlaybook(playbook, true, takes(dmzType))
	f.name(clusterA, "web", shop, shopAddress)
	f.pass()
	require.Len(t, f.pool.taken(), 1)
	stored := f.answer(dmzType, shop, dmz)

	f.asker = f.newAsker()
	f.pass()
	again := f.pool.taken()
	require.Len(t, again, 1)
	require.Equal(t, []string{shopHost}, again[0].hosts)
	require.Equal(t, []string{shopIP}, again[0].addresses)
	require.Equal(t, stored.Event.ID(), f.answer(dmzType, shop, dmz).Event.ID(), "the equal answer wrote nothing")
	f.pass()
	require.Empty(t, f.pool.taken())
}

// A source answers each point that it is asked about with one event of its type. The hub stores nothing else: an
// event about a subject that it didn't ask about, of another type, or about a point already answered, is dropped and
// counted.
func TestAnAnswerAboutASubjectThatWasntAskedIsDroppedAndCounted(t *testing.T) {
	f := newFixture(t)
	f.addSource(dmz, dmzType, "hosts", "addresses")
	f.addPlaybook(playbook, true, takes(dmzType))
	f.name(clusterA, "web", shop)
	f.pool.answering(func(c call) ([]cloudevents.Event, *collectorclient.Failure, error) {
		other, err := sdkevidence.New(namesType, shop, publication{PublishedTo: internet},
			sdkevidence.WithSource("/hub/collectors/dmz"))
		if err != nil {
			return nil, nil, err
		}
		return append(f.pool.answers(c, none), f.pool.answerAbout(dmz, api, internet), other,
			f.pool.answerAbout(dmz, shop, internet)), nil, nil
	})
	unasked := testutil.ToFloat64(metrics.SourceAnswersUnaskedTotal.WithLabelValues(hub, dmz))

	f.pass()
	require.Len(t, f.pool.taken(), 1)
	require.Equal(t, none, publishedTo(t, f.answer(dmzType, shop, dmz)), "the first answer about the point")
	require.Nil(t, f.answer(dmzType, api, dmz), "a subject that wasn't asked about")
	require.Nil(t, f.answer(namesType, shop, dmz), "another type")
	require.Equal(t, unasked+3, testutil.ToFloat64(metrics.SourceAnswersUnaskedTotal.WithLabelValues(hub, dmz)))
}

// An answer about an entry point that no cluster names any more is deleted. One that a cluster still names stays.
func TestAnAnswerAboutAnEntryPointThatNoClusterNamesIsDeleted(t *testing.T) {
	f := newFixture(t)
	f.addSource(dmz, dmzType, "hosts", "addresses")
	f.addPlaybook(playbook, true, takes(dmzType))
	f.name(clusterA, "web", shop, api)
	f.name(clusterB, "web", shop)
	f.pass()
	require.Len(t, f.pool.taken(), 1)
	require.NotNil(t, f.answer(dmzType, api, dmz))

	f.name(clusterA, "web", shop)
	f.pass()
	require.Nil(t, f.answer(dmzType, api, dmz), "no cluster names it")
	require.NotNil(t, f.answer(dmzType, shop, dmz), "both clusters name it")

	f.name(clusterA, "web")
	f.pass()
	require.NotNil(t, f.answer(dmzType, shop, dmz), "cluster-b names it still")
	require.Empty(t, f.pool.taken(), "nothing new to ask")
}

// A source is asked only for a type that a Ready playbook takes as evidence, and only when the playbook doesn't pin
// other Collectors for it.
func TestOnlySourcesOfAReadyPlaybooksTypeAreAsked(t *testing.T) {
	f := newFixture(t)
	f.addSource(dmz, dmzType, "hosts", "addresses")
	f.addSource(dmzBackup, dmzType, "hosts", "addresses")
	f.addSource(names, namesType, "hosts")
	f.addPlaybook(playbook, true, takes(dmzType, dmz))
	f.addPlaybook("names", false, takes(namesType))
	f.name(clusterA, "web", shop)

	f.pass()
	got := f.pool.taken()
	require.Len(t, got, 1)
	require.Equal(t, dmz, got[0].collector, "dmz-backup isn't pinned, and the playbook that takes names isn't Ready")

	var p configv1alpha1.Playbook
	require.NoError(t, f.client.Get(t.Context(), client.ObjectKey{Name: "names"}, &p))
	setReady(&p, true)
	require.NoError(t, f.client.Update(t.Context(), &p))
	f.pass()
	got = f.pool.taken()
	require.Len(t, got, 1)
	require.Equal(t, names, got[0].collector, "its playbook is Ready")
}

// The gauge of entry points counts, for each cluster, the entry points that its exposure names, by whether every
// source that is asked about one answered it, and the ways in that can't be asked about.
func TestEntryPointsAreCountedByClusterAndState(t *testing.T) {
	const clusterC, clusterD = "cluster-c", "cluster-d"
	f := newFixture(t)
	f.addSource(names, namesType, "hosts")
	f.addPlaybook(playbook, true, takes(namesType))
	putIn(t, f.store, networkReach, clusterC, exposureEvent(t, workload(clusterC, "web"), []string{shop, shopAddress},
		sdkevidence.UncheckedHostNetwork))
	putIn(t, f.store, networkReach, clusterC, exposureEvent(t, workload(clusterC, "api"), []string{shop}))
	f.name(clusterD, "web", api)

	f.pass()
	require.Equal(t, map[string]float64{
		clusterC + "/answered": 1, clusterC + "/unanswered": 1, clusterC + "/unchecked": 1, clusterC + "/ambiguous": 0,
		clusterD + "/answered": 1, clusterD + "/unanswered": 0, clusterD + "/unchecked": 0, clusterD + "/ambiguous": 0,
	}, gauges(t, clusterC, clusterD), "no source takes the address")

	require.NoError(t, f.store.Delete(t.Context(), evidence.Key{Subject: workload(clusterD, "web"),
		Type: sdkevidence.TypeExposure, Source: networkReach, Cluster: clusterD}))
	f.pass()
	require.Equal(t, map[string]float64{
		clusterC + "/answered": 1, clusterC + "/unanswered": 1, clusterC + "/unchecked": 1, clusterC + "/ambiguous": 0,
	}, gauges(t, clusterC, clusterD), "a cluster without exposure has no series")
}

// gauges returns the values of the gauge of entry points of the clusters, by cluster/state.
func gauges(t *testing.T, clusters ...string) map[string]float64 {
	t.Helper()
	ch := make(chan prometheus.Metric, 100)
	metrics.EntryPoints.Collect(ch)
	close(ch)
	values := map[string]float64{}
	for m := range ch {
		var d dto.Metric
		require.NoError(t, m.Write(&d))
		labels := map[string]string{}
		for _, l := range d.GetLabel() {
			labels[l.GetName()] = l.GetValue()
		}
		if slices.Contains(clusters, labels["cluster"]) {
			values[labels["cluster"]+"/"+labels["state"]] = d.GetGauge().GetValue()
		}
	}
	return values
}

// An address that two clusters name counts as ambiguous for each of them, and not as answered or unanswered, also when
// a source has answered it.
func TestAmbiguousAddressesAreCountedPerCluster(t *testing.T) {
	const clusterC, clusterD = "cluster-c", "cluster-d"
	f := newFixture(t)
	f.addSource(dmz, dmzType, "hosts", "addresses")
	f.addPlaybook(playbook, true, takes(dmzType))
	f.name(clusterC, "web", shop, shopAddress)
	f.name(clusterD, "web", shopAddress)

	f.pass()
	require.NotNil(t, f.answer(dmzType, shopAddress, dmz), "the source has answered the address")
	require.Equal(t, map[string]float64{
		clusterC + "/answered": 1, clusterC + "/unanswered": 0, clusterC + "/unchecked": 0, clusterC + "/ambiguous": 1,
		clusterD + "/answered": 0, clusterD + "/unanswered": 0, clusterD + "/unchecked": 0, clusterD + "/ambiguous": 1,
	}, gauges(t, clusterC, clusterD))
}
