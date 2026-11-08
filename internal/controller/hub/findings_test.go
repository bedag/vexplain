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

package hub_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	cloudevents "github.com/cloudevents/sdk-go/v2"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
	"github.com/bedag/vexplain/internal/collectorclient"
	"github.com/bedag/vexplain/internal/controller/hub"
	collectorv1alpha1 "github.com/bedag/vexplain/sdk/api/collector/v1alpha1"
	sdkevidence "github.com/bedag/vexplain/sdk/evidence"
	subjects "github.com/bedag/vexplain/sdk/subject"
)

// These tests cover CollectorFindings: the findings collector of a playbook, which matches through the operation
// match of a Collector in the hub role and, as the hub's sink, learns when that collector's database changed. The
// vulnerabilities collector's own tests, and the chain through the operator, are elsewhere.

const (
	// vulnerabilitiesSettings are the vulnerabilities collector's settings in its Collector, which Find sends as they are.
	vulnerabilitiesSettings = `{"maxConcurrent": 3}`
	// crafted stands for text of an image that a collector's failure message could quote.
	crafted = "\x1b[31mcrafted"
)

// vulnerabilitiesCollectorOf returns the Collector of a vulnerabilities collector whose capabilities the deployer recorded, with the changes
// that the spec makes to it.
func vulnerabilitiesCollectorOf(name string, changes ...func(*configv1alpha1.Collector)) *configv1alpha1.Collector {
	c := &configv1alpha1.Collector{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec:       configv1alpha1.CollectorSpec{Settings: &runtime.RawExtension{Raw: []byte(vulnerabilitiesSettings)}},
		Status: configv1alpha1.CollectorStatus{
			Capabilities: &configv1alpha1.CollectorCapabilities{
				Roles:    []configv1alpha1.CollectorRole{configv1alpha1.CollectorRoleHub},
				Produces: []configv1alpha1.ProducedType{{Type: sdkevidence.TypeFindings, Scope: configv1alpha1.EvidenceScopeHub}},
				Consumes: []string{sdkevidence.TypeSBOM},
				Watch:    configv1alpha1.CollectorWatchSupported,
				Operations: []configv1alpha1.CollectorOperation{{
					Name: matchOperation, Consumes: []string{sdkevidence.TypeSBOM}, Produces: []string{sdkevidence.TypeFindings},
				}},
			},
			Conditions: []metav1.Condition{{
				Type: configv1alpha1.ConditionReady, Status: metav1.ConditionTrue, Reason: "Healthy",
				LastTransitionTime: metav1.Now(),
			}},
		},
	}
	for _, change := range changes {
		change(c)
	}
	return c
}

// recordingInvoker answers Invoke as its fields say, and records the requests, with the most events that each takes.
// An answer with more events than a call takes breaks the contract, as the pool finds.
type recordingInvoker struct {
	mu       sync.Mutex
	events   []cloudevents.Event
	failure  *collectorclient.Failure
	err      error
	collects []string
	requests []*collectorv1alpha1.InvokeRequest
	deadline []time.Duration
	bounds   []int
}

func (i *recordingInvoker) Invoke(ctx context.Context, collector string, req *collectorv1alpha1.InvokeRequest,
	opts ...collectorclient.InvokeOption) ([]cloudevents.Event, *collectorclient.Failure, error) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.collects = append(i.collects, collector)
	i.requests = append(i.requests, req)
	if at, ok := ctx.Deadline(); ok {
		i.deadline = append(i.deadline, time.Until(at))
	}
	bound := collectorclient.EventsBound(opts...)
	i.bounds = append(i.bounds, bound)
	if len(i.events) > bound {
		return nil, nil, fmt.Errorf("collector %s, Invoke: %w: more than %d events", collector, collectorclient.ErrContract, bound)
	}
	return i.events, i.failure, i.err
}

// findingsEvent returns the findings event that a vulnerabilities collector answers with for the manifest.
func findingsEvent(t *testing.T, manifest string, found sdkevidence.Findings) cloudevents.Event {
	t.Helper()
	e, err := sdkevidence.New(sdkevidence.TypeFindings, subjects.Manifest(manifest), found,
		sdkevidence.WithPlatform(linuxAMD64), sdkevidence.WithSource("/hub/collectors/vulnerabilities"))
	require.NoError(t, err)
	return e
}

// fixture is a findings collector over the Collectors in a fake client, and a recording invoker.
type fixture struct {
	findings *hub.CollectorFindings
	invoker  *recordingInvoker
	client   client.Client
	queue    workqueue.TypedRateLimitingInterface[reconcile.Request]
}

func newFixture(t *testing.T, collectors ...*configv1alpha1.Collector) *fixture {
	t.Helper()
	scheme := runtime.NewScheme()
	require.NoError(t, configv1alpha1.AddToScheme(scheme))
	builder := fake.NewClientBuilder().WithScheme(scheme)
	for _, c := range collectors {
		builder = builder.WithObjects(c)
	}
	c := builder.Build()
	invoker := &recordingInvoker{}
	findings := hub.NewCollectorFindings(c, invoker, func(context.Context) (*collectorv1alpha1.Context, error) {
		return &collectorv1alpha1.Context{Cluster: "cluster-a", OperatorNamespace: operatorNamespace}, nil
	})
	return &fixture{findings: findings, invoker: invoker, client: c}
}

// start starts the source of the findings collector, as the assessor's controller does, and returns the queue.
func (f *fixture) start(t *testing.T) {
	t.Helper()
	f.queue = workqueue.NewTypedRateLimitingQueue(workqueue.DefaultTypedControllerRateLimiter[reconcile.Request]())
	t.Cleanup(f.queue.ShutDown)
	require.NoError(t, f.findings.Changed().Start(t.Context(), f.queue))
}

// drain takes every request out of the queue, as the controller's workers would.
func drain(queue workqueue.TypedRateLimitingInterface[reconcile.Request]) []reconcile.Request {
	var requests []reconcile.Request
	for queue.Len() > 0 {
		req, _ := queue.Get()
		requests = append(requests, req)
		queue.Done(req)
	}
	return requests
}

// everySubject is the request through which a findings collector says that every subject changed.
var everySubject = []reconcile.Request{{}}

func TestFindInvokesMatchOnTheCollectorWithTheEvidenceAsItsInput(t *testing.T) {
	f := newFixture(t, vulnerabilitiesCollectorOf(vulnerabilitiesCollector))
	manifest := digestOf(101)
	want := sdkevidence.Findings{Version: v1, Matches: []sdkevidence.Match{{
		VulnerabilityID: otherCVE, PackageID: otherPackage, PackageName: otherName, PackageVersion: otherVersion,
		PackageType: deb, Severity: critical, FixState: fixedState, FixedVersions: []string{otherFix}, KnownExploited: true,
		CVSS: []sdkevidence.CVSS{{Version: "3.1", Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}},
	}}}
	f.invoker.events = []cloudevents.Event{findingsEvent(t, manifest, want)}
	input := sbomEventOf(t0, evidenceOf(manifest))

	got, err := f.findings.Find(t.Context(), vulnerabilitiesCollector, input)

	require.NoError(t, err)
	require.Equal(t, want, got)
	require.Equal(t, []string{vulnerabilitiesCollector}, f.invoker.collects)
	require.Len(t, f.invoker.requests, 1)
	req := f.invoker.requests[0]
	require.Equal(t, matchOperation, req.GetOperation())
	require.Equal(t, subjects.Manifest(manifest), req.GetSubject())
	require.Equal(t, collectorv1alpha1.Role_ROLE_HUB, req.GetRole())
	require.JSONEq(t, vulnerabilitiesSettings, string(req.GetSettings()), "the settings of the Collector")
	require.Equal(t, "cluster-a", req.GetContext().GetCluster())
	require.Len(t, req.GetInputs(), 1)
	sent, err := sdkevidence.FromProto(req.GetInputs()[0])
	require.NoError(t, err)
	require.Equal(t, input.ID(), sent.ID(), "the evidence is the input")
	require.Equal(t, input.Data(), sent.Data())
	require.Len(t, f.invoker.deadline, 1)
	require.Positive(t, f.invoker.deadline[0], "a match is bounded")
}

// A manifest without a match is the usual case: the findings are an empty list, and they are an answer.
func TestFindReturnsFindingsWithNoMatches(t *testing.T) {
	f := newFixture(t, vulnerabilitiesCollectorOf(vulnerabilitiesCollector))
	manifest := digestOf(101)
	f.invoker.events = []cloudevents.Event{findingsEvent(t, manifest, sdkevidence.Findings{Version: v1})}

	got, err := f.findings.Find(t.Context(), vulnerabilitiesCollector, sbomEventOf(t0, evidenceOf(manifest)))

	require.NoError(t, err)
	require.Equal(t, v1, got.Version)
	require.Empty(t, got.Matches)
}

func TestFindRefusesACollectorThatCannotMatch(t *testing.T) {
	input := sbomEventOf(t0, evidenceOf(digestOf(101)))
	notReady := func(c *configv1alpha1.Collector) {
		c.Status.Conditions = []metav1.Condition{{Type: configv1alpha1.ConditionReady, Status: metav1.ConditionFalse,
			Reason: configv1alpha1.ReasonCollectorFailing, LastTransitionTime: metav1.Now()}}
	}
	for name, tc := range map[string]struct {
		collectors []*configv1alpha1.Collector
		name       string
		input      cloudevents.Event
		want       string
	}{
		"no such Collector": {nil, vulnerabilitiesCollector, input, vulnerabilitiesCollector},
		"a Collector that is not ready": {
			[]*configv1alpha1.Collector{vulnerabilitiesCollectorOf(vulnerabilitiesCollector, notReady)}, vulnerabilitiesCollector, input, "can't be used",
		},
		"a Collector without capabilities": {
			[]*configv1alpha1.Collector{vulnerabilitiesCollectorOf(vulnerabilitiesCollector, func(c *configv1alpha1.Collector) { c.Status.Capabilities = nil })},
			vulnerabilitiesCollector, input, "can't be used",
		},
		"a Collector in the spoke role": {
			[]*configv1alpha1.Collector{vulnerabilitiesCollectorOf(vulnerabilitiesCollector, func(c *configv1alpha1.Collector) {
				c.Status.Capabilities.Roles = []configv1alpha1.CollectorRole{configv1alpha1.CollectorRoleSpoke}
			})}, vulnerabilitiesCollector, input, "no hub role",
		},
		"a Collector without the operation": {
			[]*configv1alpha1.Collector{vulnerabilitiesCollectorOf(vulnerabilitiesCollector, func(c *configv1alpha1.Collector) {
				c.Status.Capabilities.Operations[0].Name = "other"
			})}, vulnerabilitiesCollector, input, "no operation match",
		},
		"evidence that it doesn't consume": {
			[]*configv1alpha1.Collector{vulnerabilitiesCollectorOf(vulnerabilitiesCollector, func(c *configv1alpha1.Collector) {
				c.Status.Capabilities.Operations[0].Consumes = []string{"com.example.sbom.v1"}
			})}, vulnerabilitiesCollector, input, sdkevidence.TypeSBOM,
		},
		"an operation that produces no findings": {
			[]*configv1alpha1.Collector{vulnerabilitiesCollectorOf(vulnerabilitiesCollector, func(c *configv1alpha1.Collector) {
				c.Status.Capabilities.Operations[0].Produces = []string{"com.example.other.v1"}
			})}, vulnerabilitiesCollector, input, "doesn't produce findings",
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, tc.collectors...)

			_, err := f.findings.Find(t.Context(), tc.name, tc.input)

			require.ErrorContains(t, err, tc.want)
			require.Empty(t, f.invoker.requests, "nothing is asked of a collector that can't match")
		})
	}
}

// A failure of the collector, such as NotReady while it has no database, is no answer, and never an empty list of
// findings. Only its reason reaches the error: the message is the collector's text, which can quote an image.
func TestFindReturnsAFailureAsAnErrorThatNamesItsReasonOnly(t *testing.T) {
	f := newFixture(t, vulnerabilitiesCollectorOf(vulnerabilitiesCollector))
	f.invoker.failure = &collectorclient.Failure{Reason: "NotReady", Message: crafted}

	_, err := f.findings.Find(t.Context(), vulnerabilitiesCollector, sbomEventOf(t0, evidenceOf(digestOf(101))))

	require.ErrorContains(t, err, "NotReady")
	require.NotContains(t, err.Error(), "crafted")
}

func TestFindReturnsAnErrorOfTheCall(t *testing.T) {
	f := newFixture(t, vulnerabilitiesCollectorOf(vulnerabilitiesCollector))
	f.invoker.err = errors.New("collector vulnerabilities, Invoke: the collector is unavailable")

	_, err := f.findings.Find(t.Context(), vulnerabilitiesCollector, sbomEventOf(t0, evidenceOf(digestOf(101))))

	require.ErrorContains(t, err, "the collector is unavailable")
}

// An answer is one findings event about the subject. Anything else is no answer, and its text, which is the
// collector's, stays out of the error.
func TestFindRefusesAnAnswerThatIsNotOneFindingsEventAboutTheSubject(t *testing.T) {
	manifest, other := digestOf(101), digestOf(102)
	own := findingsEvent(t, manifest, sdkevidence.Findings{Version: v1})
	aboutOther := findingsEvent(t, other, sdkevidence.Findings{Version: v1})
	wrongType, err := sdkevidence.New("com.example.other.v1", subjects.Manifest(manifest), map[string]string{"x": crafted},
		sdkevidence.WithPlatform(linuxAMD64))
	require.NoError(t, err)
	notFindings := findingsEvent(t, manifest, sdkevidence.Findings{})
	notFindings.DataEncoded = []byte(`{"version": ["` + crafted + `"]}`)

	for name, events := range map[string][]cloudevents.Event{
		"no event":                  nil,
		"two events":                {own, own},
		"an event about other":      {aboutOther},
		"an event of another type":  {wrongType},
		"data that are no findings": {notFindings},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, vulnerabilitiesCollectorOf(vulnerabilitiesCollector))
			f.invoker.events = events

			_, err := f.findings.Find(t.Context(), vulnerabilitiesCollector, sbomEventOf(t0, evidenceOf(manifest)))

			require.Error(t, err)
			require.NotContains(t, err.Error(), "crafted")
		})
	}
}

// What a findings collector consumes rests on its Collector and the capabilities that it recorded, and not on its
// health: a collector that can't be used now still vouches for the findings that it matched before (design 5.9), and
// Find refuses it.
// The findings of an answer are checked against the core's schema of findings, as presence and exposure are on the
// spoke: a findings collector may declare a looser schema for the type. Findings that don't follow it, such as ones
// without their matches, are no answer, and never "no findings", which a reader can't tell from a clean manifest.
func TestFindRefusesFindingsThatDontFollowTheSchemaOfFindings(t *testing.T) {
	manifest := digestOf(101)
	for name, data := range map[string]string{
		"findings without matches":  `{"version": "x"}`,
		"matches that are null":     `{"version": "x", "matches": null}`,
		"findings without version":  `{"matches": []}`,
		"a match without a package": `{"version": "x", "matches": [{"vulnerabilityID": "CVE-2026-0001"}]}`,
		"a field of no findings":    `{"version": "x", "matches": [], "crafted": true}`,
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, vulnerabilitiesCollectorOf(vulnerabilitiesCollector))
			e, err := sdkevidence.New(sdkevidence.TypeFindings, subjects.Manifest(manifest), json.RawMessage(data),
				sdkevidence.WithPlatform(linuxAMD64), sdkevidence.WithSource("/hub/collectors/vulnerabilities"))
			require.NoError(t, err)
			f.invoker.events = []cloudevents.Event{e}

			found, err := f.findings.Find(t.Context(), vulnerabilitiesCollector, sbomEventOf(t0, evidenceOf(manifest)))

			require.Error(t, err, "no answer")
			require.Empty(t, found.Matches)
			require.NotContains(t, err.Error(), "crafted", "the error repeats nothing of the answer")
		})
	}
}

// A match answers with one findings event. Find takes one, and the pool reads no further than a second: an answer that
// doesn't end after its second event can't hold the hub's match until its timeout.
func TestFindTakesOneEventAndAnAnswerWithTwoIsNoAnswer(t *testing.T) {
	f := newFixture(t, vulnerabilitiesCollectorOf(vulnerabilitiesCollector))
	manifest := digestOf(101)
	f.invoker.events = []cloudevents.Event{
		findingsEvent(t, manifest, sdkevidence.Findings{Version: v1, Matches: []sdkevidence.Match{exampleMatch}}),
		findingsEvent(t, manifest, sdkevidence.Findings{Version: v1}),
	}

	_, err := f.findings.Find(t.Context(), vulnerabilitiesCollector, sbomEventOf(t0, evidenceOf(manifest)))

	require.ErrorIs(t, err, collectorclient.ErrContract)
	require.Equal(t, []int{1}, f.invoker.bounds, "Find takes one event")
}

func TestConsumesIsWhatTheRecordedCapabilitiesSayMatchConsumes(t *testing.T) {
	f := newFixture(t,
		vulnerabilitiesCollectorOf(vulnerabilitiesCollector),
		vulnerabilitiesCollectorOf("spoke-only", func(c *configv1alpha1.Collector) {
			c.Status.Capabilities.Roles = []configv1alpha1.CollectorRole{configv1alpha1.CollectorRoleSpoke}
		}),
		vulnerabilitiesCollectorOf("no-capabilities", func(c *configv1alpha1.Collector) { c.Status.Capabilities = nil }),
		vulnerabilitiesCollectorOf("failing", func(c *configv1alpha1.Collector) {
			c.Status.Conditions[0].Status, c.Status.Conditions[0].Reason = metav1.ConditionFalse, configv1alpha1.ReasonCollectorFailing
		}),
		vulnerabilitiesCollectorOf("being-deleted", func(c *configv1alpha1.Collector) {
			c.Finalizers, c.DeletionTimestamp = []string{"vexplain.bedag.ch/evidence"}, ptr.To(metav1.Now())
		}),
	)

	for name, want := range map[string][]string{
		vulnerabilitiesCollector: {sdkevidence.TypeSBOM},
		"failing":                {sdkevidence.TypeSBOM},
		"being-deleted":          {sdkevidence.TypeSBOM},
		"spoke-only":             nil,
		"no-capabilities":        nil,
		"no-such-collector":      nil,
	} {
		consumes, err := f.findings.Consumes(t.Context(), name)
		require.NoError(t, err, name)
		require.Equal(t, want, consumes, name)
	}
}

// A read of the Collector that fails says nothing about what the collector consumes, and never that it consumes
// nothing, which would leave the sheets that its findings made without a findings collector that vouches for them.
func TestConsumesReturnsAReadOfTheCollectorThatFails(t *testing.T) {
	errRead := errors.New("the cache is not synced yet")
	scheme := runtime.NewScheme()
	require.NoError(t, configv1alpha1.AddToScheme(scheme))
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(vulnerabilitiesCollectorOf(vulnerabilitiesCollector)).
		WithInterceptorFuncs(interceptor.Funcs{Get: func(context.Context, client.WithWatch, client.ObjectKey, client.Object,
			...client.GetOption) error {
			return errRead
		}}).Build()
	findings := hub.NewCollectorFindings(c, &recordingInvoker{}, nil)

	consumes, err := findings.Consumes(t.Context(), vulnerabilitiesCollector)

	require.ErrorIs(t, err, errRead)
	require.Nil(t, consumes)
}

// ---- the sink ----

func TestSourceChangedSaysEverySubjectChangedWhenItNamesNone(t *testing.T) {
	f := newFixture(t, vulnerabilitiesCollectorOf(vulnerabilitiesCollector))
	f.start(t)

	f.findings.SourceChanged(vulnerabilitiesCollector, nil)

	require.Equal(t, everySubject, drain(f.queue))
}

func TestSourceChangedSaysTheSubjectsThatItNames(t *testing.T) {
	f := newFixture(t, vulnerabilitiesCollectorOf(vulnerabilitiesCollector))
	f.start(t)
	first, second := subjects.Manifest(digestOf(101)), subjects.Manifest(digestOf(102))

	f.findings.SourceChanged(vulnerabilitiesCollector, []string{first, second})

	requests := drain(f.queue)
	require.ElementsMatch(t, []string{first, second}, []string{requests[0].Name, requests[1].Name})
	require.Len(t, requests, 2)
}

// The change is the collector's own, by the name that the stream gives. What the collector writes as the source of
// its events is its own word, and says nothing of which collector the stream is.
func TestSourceChangedIsAttributedByTheStreamsCollectorAndNotByAnEventsSource(t *testing.T) {
	f := newFixture(t,
		vulnerabilitiesCollectorOf(vulnerabilitiesCollector),
		vulnerabilitiesCollectorOf("scanner-like", func(c *configv1alpha1.Collector) {
			c.Status.Capabilities.Operations[0].Name = "scan"
			c.Status.Capabilities.Roles = []configv1alpha1.CollectorRole{configv1alpha1.CollectorRoleSpoke}
		}),
	)
	f.start(t)

	// A collector that has no operation match is no findings collector: its change matches nothing again.
	f.findings.Upsert("scanner-like", findingsEvent(t, digestOf(101), sdkevidence.Findings{Version: v1}))
	f.findings.SourceChanged("scanner-like", nil)
	require.Empty(t, drain(f.queue))

	// Nor does a collector that the Collectors don't know, once they can be read.
	f.findings.SourceChanged("no-such-collector", nil)
	require.Equal(t, everySubject, drain(f.queue), "a Collector that can't be read counts: a change that is lost isn't safe")
}

func TestSourceChangedBeforeTheAssessorStartedIsHandedOverThenAndNeverBlocks(t *testing.T) {
	f := newFixture(t, vulnerabilitiesCollectorOf(vulnerabilitiesCollector))
	first := subjects.Manifest(digestOf(101))
	done := make(chan struct{})

	go func() {
		defer close(done)
		f.findings.SourceChanged(vulnerabilitiesCollector, []string{first})
		f.findings.SourceChanged(vulnerabilitiesCollector, nil)
		f.findings.SourceChanged(vulnerabilitiesCollector, []string{first})
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		require.FailNow(t, "SourceChanged blocks while nothing reads Changed")
	}
	f.start(t)

	requests := drain(f.queue)
	require.Contains(t, requests, reconcile.Request{}, "every subject")
}

func TestSourceChangedBeforeTheAssessorStartedKeepsTheSubjectsThatItNamed(t *testing.T) {
	f := newFixture(t, vulnerabilitiesCollectorOf(vulnerabilitiesCollector))
	first := subjects.Manifest(digestOf(101))
	f.findings.SourceChanged(vulnerabilitiesCollector, []string{first})
	f.start(t)

	requests := drain(f.queue)

	require.Len(t, requests, 1)
	require.Equal(t, first, requests[0].Name)
	// What was handed over is gone.
	f.findings.SourceChanged("no-such-collector", []string{first})
	require.Len(t, drain(f.queue), 1)
}

// Findings aren't evidence that the hub keeps, so what a stream delivers besides SourceChanged is dropped, and no call
// waits for anything.
func TestTheSinkDropsWhatItDoesNotUse(t *testing.T) {
	f := newFixture(t, vulnerabilitiesCollectorOf(vulnerabilitiesCollector))
	f.start(t)
	e := findingsEvent(t, digestOf(101), sdkevidence.Findings{Version: v1})

	f.findings.Snapshot(vulnerabilitiesCollector, []cloudevents.Event{e})
	f.findings.Upsert(vulnerabilitiesCollector, e)
	f.findings.Remove(vulnerabilitiesCollector, sdkevidence.TypeFindings, e.Subject())
	f.findings.Forget(vulnerabilitiesCollector)

	require.Empty(t, drain(f.queue))
	require.Empty(t, f.invoker.requests)
}

var _ collectorclient.Sink = (*hub.CollectorFindings)(nil)
