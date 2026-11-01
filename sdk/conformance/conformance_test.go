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

package conformance_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"path"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	cloudevents "github.com/cloudevents/sdk-go/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	collectorv1alpha1 "github.com/bedag/vexplain/sdk/api/collector/v1alpha1"
	"github.com/bedag/vexplain/sdk/collector"
	"github.com/bedag/vexplain/sdk/conformance"
	"github.com/bedag/vexplain/sdk/evidence"
	"github.com/bedag/vexplain/sdk/subject"
)

const (
	collectorName    = "hello"
	collectorVersion = "1.2.3"
	clusterA         = "cluster-a"
	eventSource      = "/clusters/cluster-a/collectors/hello"
	// typeHello is what the collector produces, and the operation too. typeOther is a second type that the
	// collector produces and the operation doesn't. typeInput is what the operation consumes, and
	// typeUndeclared is none of them.
	typeHello      = "com.example.hello.v1alpha1"
	typeOther      = "com.example.other.v1alpha1"
	typeInput      = "com.example.input.v1alpha1"
	typeUndeclared = "com.example.undeclared.v1alpha1"
	operationGreet = "greet"
	apiVersion     = "v1alpha1"
	// aboutSettings is in what a check says about the settings schema.
	aboutSettings = "settings"

	helloSchema     = `{"type": "object", "properties": {"greeting": {"type": "string"}}, "required": ["greeting"]}`
	parameterSchema = `{"type": "object", "properties": {"name": {"type": "string"}}}`
	parameters      = `{"name": "web"}`
	settingsSchema  = `{
		"type": "object",
		"properties": {"greeting": {"type": "string", "minLength": 1}},
		"additionalProperties": false
	}`
	validSettings = `{"greeting": "hello"}`
	// brokenSettings break settingsSchema.
	brokenSettings = `{"greeting": ""}`
	// refusedSettings pass the schema, and a collector's own check refuses them.
	refusedSettings = `{"greeting": "goodbye"}`

	// snapshotWait and presenceWait are the limits of the suite in these tests: a snapshot that never ends, or a
	// pod that is never listed, fails within seconds.
	snapshotWait = 2 * time.Second
	presenceWait = time.Second
	bufferSize   = 1 << 20
	wait         = 10 * time.Second
)

// The names of the checks, as the suite reports them: the group and the check, joined by a slash, as the names of
// subtests are.
const (
	checkDial         = "Dial"
	checkInfo         = "Identity/GetInfo has a name, a version and v1alpha1"
	checkCapabilities = "Identity/GetCapabilities answers"
	checkSchemas      = "Capabilities/every schema compiles"
	checkRoles        = "Capabilities/the collector takes at least one role, spoke or hub"
	checkTypeNames    = "Capabilities/every produced type is reverse-DNS and versioned"
	checkScopes       = "Capabilities/every produced type has a scope"
	checkOperations   = "Capabilities/every operation produces only declared types"
	checkAccepted     = "Settings/the settings are accepted"
	checkRefused      = "Settings/InvalidSettings are refused"
	checkStart        = "Watch/spoke/starts with SnapshotStart"
	checkOrder        = "Watch/spoke/holds events only until SnapshotEnd"
	checkEnd          = "Watch/spoke/reaches SnapshotEnd in time"
	checkValid        = "Watch/spoke/every event is valid evidence"
	checkDeclared     = "Watch/spoke/every event is of a declared type"
	checkData         = "Watch/spoke/every event's data validates against its type's schema"
	checkAgain        = "Watch/spoke/a second Watch starts with a snapshot again"
	checkInvoke       = "Invoke/greet"
)

// goodChecks are the checks that run against a collector that watches and has an operation, when the target has
// settings that must be refused and an invocation, in the order that they run.
var goodChecks = []string{
	checkDial,
	"Identity", checkInfo, checkCapabilities,
	"Capabilities", checkSchemas, checkRoles, checkTypeNames, checkScopes, checkOperations,
	"Settings", checkAccepted, checkRefused,
	"Watch", "Watch/spoke", checkStart, checkOrder, checkEnd, checkValid, checkDeclared, checkData, checkAgain,
	"Invoke", checkInvoke,
}

// workload is what the tests' events are about.
var workload = subject.ForWorkload(subject.Workload{
	Cluster: clusterA, Namespace: "team-a", Group: "apps", Kind: "Deployment", Name: "web",
})

// record is what a recorder keeps, and its recorders share.
type record struct {
	mu       sync.Mutex
	ran      []string
	failures []failure
}

// failure is one report of a failure: the check that made it, and its text.
type failure struct{ check, message string }

// recorder is a Reporter that keeps what the suite reports, so that a test can say which checks ran, and which
// failed with what. As testing.T does, it runs each check in a goroutine of its own, so that Fatalf ends that
// check and not the test. A failure marks the groups above the check as failed, as it does there.
type recorder struct {
	record *record
	path   string
	failed bool
}

func newRecorder() *recorder { return &recorder{record: &record{}} }

func (r *recorder) Helper() {}

func (r *recorder) Errorf(format string, args ...any) {
	r.failed = true
	r.record.mu.Lock()
	defer r.record.mu.Unlock()
	r.record.failures = append(r.record.failures, failure{check: r.path, message: fmt.Sprintf(format, args...)})
}

func (r *recorder) Fatalf(format string, args ...any) {
	r.Errorf(format, args...)
	runtime.Goexit()
}

func (r *recorder) Run(name string, f func(conformance.Reporter)) bool {
	child := &recorder{record: r.record, path: path.Join(r.path, name)}
	r.record.mu.Lock()
	r.record.ran = append(r.record.ran, child.path)
	r.record.mu.Unlock()
	done := make(chan struct{})
	go func() {
		defer close(done)
		f(child)
	}()
	<-done
	if child.failed {
		r.failed = true
	}
	return !child.failed
}

// ran returns the names of the checks that ran, groups included, in the order that they started.
func (r *recorder) ran() []string { return r.record.ran }

// failedChecks returns the names of the checks that reported a failure, each once, in the order of their first.
func (r *recorder) failedChecks() []string {
	var checks []string
	for _, f := range r.record.failures {
		if !slices.Contains(checks, f.check) {
			checks = append(checks, f.check)
		}
	}
	return checks
}

// messages returns everything that a check reported, as one text.
func (r *recorder) messages(check string) string {
	var text []string
	for _, f := range r.record.failures {
		if f.check == check {
			text = append(text, f.message)
		}
	}
	return strings.Join(text, "\n")
}

// run runs the suite against target with a recorder, and the short limits of these tests.
func run(t *testing.T, target conformance.Target) *recorder {
	t.Helper()
	rec := newRecorder()
	conformance.RunWithin(rec, target, snapshotWait, presenceWait)
	return rec
}

// requireFailed checks that exactly one check failed, and that what it reported says why.
func requireFailed(t *testing.T, rec *recorder, check, why string) {
	t.Helper()
	require.Equal(t, []string{check}, rec.failedChecks(), "the checks that failed")
	require.Contains(t, rec.messages(check), why)
}

// requirePassed checks that no check failed, and that the checks named ran: a suite that runs nothing fails
// nothing.
func requirePassed(t *testing.T, rec *recorder, ran ...string) {
	t.Helper()
	require.Empty(t, rec.failedChecks(), "the checks that failed")
	for _, check := range ran {
		require.Contains(t, rec.ran(), check)
	}
}

// dialer is Target.Dial.
type dialer = func(ctx context.Context) (*grpc.ClientConn, error)

// dialerFor returns a Dial that connects to the server on listener, without TLS.
func dialerFor(listener *bufconn.Listener) dialer {
	return func(context.Context) (*grpc.ClientConn, error) {
		return grpc.NewClient("passthrough:///bufconn",
			grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
				return listener.DialContext(ctx)
			}),
			grpc.WithTransportCredentials(insecure.NewCredentials()))
	}
}

// serve runs the SDK's server for c until the test ends, as the collectors that people write run, and returns
// the Dial that reaches it.
func serve(t *testing.T, c collector.Collector) dialer {
	t.Helper()
	listener := bufconn.Listen(bufferSize)
	health, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- collector.Serve(ctx, c, collector.Options{Insecure: true, GRPCListener: listener, HealthListener: health})
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			assert.NoError(t, err, "Serve returns nil once its context ends")
		case <-time.After(wait):
			t.Error("Serve didn't return after its context ended")
		}
	})
	return dialerFor(listener)
}

// greeting is the data of a greeting. The schema of the collector's type wants a string.
func greeting(value any) map[string]any { return map[string]any{"greeting": value} }

// newEvent returns valid evidence of eventType about the workload, with a greeting as its data.
func newEvent(t *testing.T, eventType string) cloudevents.Event {
	t.Helper()
	return eventWith(t, eventType, workload, greeting("hello"))
}

// eventWith returns an event of eventType about a subject, with the data. It is valid evidence unless the
// subject or the data make it not.
func eventWith(t *testing.T, eventType, about string, data any) cloudevents.Event {
	t.Helper()
	e, err := evidence.New(eventType, about, data, evidence.WithSource(eventSource))
	require.NoError(t, err)
	return e
}

// testContext is what a target tells the collector about its cluster.
func testContext() collector.Context {
	return collector.Context{
		Cluster:           clusterA,
		OperatorNamespace: "vexplain-system",
		OwnPodLabel:       "vexplain.bedag.ch/task",
		Scope:             json.RawMessage(`{"excludeNamespaces": {"matchLabels": {"team": "off"}}}`),
		OwnerAttribution:  json.RawMessage(`{"namespaceLabels": ["team"]}`),
	}
}

// good is a collector that conforms, written as people write them, on the SDK: it watches, has one operation,
// and checks its settings. Its operation keeps the inputs that it gets.
type good struct {
	mu     sync.Mutex
	inputs [][]cloudevents.Event
}

func (g *good) Info() collector.Info {
	return collector.Info{Name: collectorName, Version: collectorVersion}
}

func (g *good) Capabilities() collector.Capabilities {
	return collector.Capabilities{
		Roles:    []collector.Role{collector.RoleSpoke},
		Produces: []collector.EvidenceType{{Type: typeHello, Scope: collector.ScopeSpoke, Schema: []byte(helloSchema)}},
		Consumes: []string{typeInput},
		Watches:  true,
		Operations: []collector.Operation{{
			Name:            operationGreet,
			Description:     "Greets a workload.",
			Role:            collector.RoleSpoke,
			Produces:        []string{typeHello},
			Consumes:        []string{typeInput},
			ParameterSchema: []byte(parameterSchema),
		}},
		SettingsSchema: []byte(settingsSchema),
	}
}

func (g *good) Watch(ctx context.Context, _ collector.WatchRequest, sink collector.Sink) error {
	hello, err := evidence.New(typeHello, workload, greeting("hello"), evidence.WithSource(eventSource))
	if err != nil {
		return err
	}
	for _, step := range []func() error{sink.SnapshotStart, func() error { return sink.Event(hello) }, sink.SnapshotEnd} {
		if err := step(); err != nil {
			return err
		}
	}
	<-ctx.Done()
	return ctx.Err()
}

// Invoke greets the subject when it gets an input, and else fails with a reason.
func (g *good) Invoke(_ context.Context, req collector.InvokeRequest) ([]cloudevents.Event, *collector.Failure, error) {
	g.mu.Lock()
	g.inputs = append(g.inputs, req.Inputs)
	g.mu.Unlock()
	if len(req.Inputs) == 0 {
		return nil, &collector.Failure{Reason: "NoInput", Message: "the operation needs an input"}, nil
	}
	hello, err := evidence.New(typeHello, req.Subject, greeting("hello"), evidence.WithSource(eventSource))
	return []cloudevents.Event{hello}, nil, err
}

func (g *good) ValidateSettings(settings json.RawMessage) []string {
	if strings.Contains(string(settings), "goodbye") {
		return []string{"greeting: the collector only says hello"}
	}
	return nil
}

// received returns the inputs of each call of the operation.
func (g *good) received() [][]cloudevents.Event {
	g.mu.Lock()
	defer g.mu.Unlock()
	return slices.Clone(g.inputs)
}

// goodTarget serves g, and returns a target that gives the collector everything to check: settings, settings
// that it must refuse, and one invocation with an input.
func goodTarget(t *testing.T, g *good) conformance.Target {
	t.Helper()
	return conformance.Target{
		Dial:            serve(t, g),
		Settings:        json.RawMessage(validSettings),
		InvalidSettings: json.RawMessage(brokenSettings),
		Context:         testContext(),
		Invocations: []conformance.Invocation{{
			Operation:  operationGreet,
			Subject:    workload,
			Parameters: json.RawMessage(parameters),
			Inputs:     []cloudevents.Event{newEvent(t, typeInput)},
		}},
	}
}

func TestRunPassesACollectorThatConforms(t *testing.T) {
	g := &good{}
	input := newEvent(t, typeInput)
	target := goodTarget(t, g)
	target.Invocations[0].Inputs = []cloudevents.Event{input}

	rec := newRecorder()
	conformance.RunWith(rec, target)

	require.Empty(t, rec.failedChecks(), "the checks that failed")
	require.Equal(t, goodChecks, rec.ran())
	require.Equal(t, [][]cloudevents.Event{{input}}, g.received(), "the operation gets the invocation's inputs")
}

func TestRunTakesTestingTAsAReporter(t *testing.T) {
	conformance.Run(t, goodTarget(t, &good{}))
}

func TestRunChecksOnlyWhatTheTargetAsksFor(t *testing.T) {
	target := goodTarget(t, &good{})
	target.InvalidSettings, target.Invocations = nil, nil

	rec := run(t, target)

	requirePassed(t, rec, checkStart)
	require.NotContains(t, rec.ran(), checkRefused)
	require.NotContains(t, rec.ran(), "Invoke")
}

func TestAFailureWithAReasonConforms(t *testing.T) {
	g := &good{}
	target := goodTarget(t, g)
	target.Invocations[0].Inputs = nil // the operation then fails with the reason NoInput

	rec := run(t, target)

	requirePassed(t, rec, checkInvoke)
	require.Len(t, g.received(), 1)
	require.Empty(t, g.received()[0], "the operation got no inputs, and answered with a failure")
}

// watchStream and invokeStream are the server side of the two streams.
type (
	watchStream  = grpc.ServerStreamingServer[collectorv1alpha1.WatchResponse]
	invokeStream = grpc.ServerStreamingServer[collectorv1alpha1.InvokeResponse]
)

// watchFunc is a collector's Watch. call counts the Watches that the collector has had, from 1.
type watchFunc func(call int, stream watchStream) error

// invokeFunc is a collector's Invoke.
type invokeFunc func(req *collectorv1alpha1.InvokeRequest, stream invokeStream) error

// fake speaks the collector API itself, and not through the SDK's server, so that it can break the contract that
// the server keeps for every collector that uses it. A collector in any other language could. It conforms
// until a test changes one of its parts.
type fake struct {
	collectorv1alpha1.UnimplementedIdentityServer
	collectorv1alpha1.UnimplementedEvidenceServer
	info     *collectorv1alpha1.GetInfoResponse
	caps     *collectorv1alpha1.GetCapabilitiesResponse
	capsErr  error // what GetCapabilities answers instead of caps, when it is set
	problems func(settings []byte) ([]string, error)
	watch    watchFunc
	invoke   invokeFunc

	mu      sync.Mutex
	watches []*collectorv1alpha1.WatchRequest
	invokes []*collectorv1alpha1.InvokeRequest
}

func (f *fake) GetInfo(context.Context, *collectorv1alpha1.GetInfoRequest) (*collectorv1alpha1.GetInfoResponse, error) {
	return f.info, nil
}

func (f *fake) GetCapabilities(context.Context, *collectorv1alpha1.GetCapabilitiesRequest) (
	*collectorv1alpha1.GetCapabilitiesResponse, error) {
	return f.caps, f.capsErr
}

func (f *fake) ValidateSettings(_ context.Context, req *collectorv1alpha1.ValidateSettingsRequest) (
	*collectorv1alpha1.ValidateSettingsResponse, error) {
	problems, err := f.problems(req.GetSettings())
	return &collectorv1alpha1.ValidateSettingsResponse{Problems: problems}, err
}

func (f *fake) Watch(req *collectorv1alpha1.WatchRequest, stream watchStream) error {
	f.mu.Lock()
	f.watches = append(f.watches, req)
	call := len(f.watches)
	f.mu.Unlock()
	return f.watch(call, stream)
}

func (f *fake) Invoke(req *collectorv1alpha1.InvokeRequest, stream invokeStream) error {
	f.mu.Lock()
	f.invokes = append(f.invokes, req)
	f.mu.Unlock()
	return f.invoke(req, stream)
}

// goodCaps are the capabilities of a collector that conforms: it takes the spoke role, produces typeHello and
// typeOther, watches, and has an operation that consumes typeInput and produces typeHello.
func goodCaps() *collectorv1alpha1.GetCapabilitiesResponse {
	return &collectorv1alpha1.GetCapabilitiesResponse{
		Roles: []collectorv1alpha1.Role{collectorv1alpha1.Role_ROLE_SPOKE},
		Produces: []*collectorv1alpha1.EvidenceType{
			{Type: typeHello, Scope: collectorv1alpha1.Scope_SCOPE_SPOKE, Schema: []byte(helloSchema)},
			{Type: typeOther, Scope: collectorv1alpha1.Scope_SCOPE_HUB, Schema: []byte(helloSchema)},
		},
		Consumes: []string{typeInput},
		Watches:  true,
		Operations: []*collectorv1alpha1.Operation{{
			Name:            operationGreet,
			Role:            collectorv1alpha1.Role_ROLE_SPOKE,
			Produces:        []string{typeHello},
			Consumes:        []string{typeInput},
			ParameterSchema: []byte(parameterSchema),
		}},
		SettingsSchema: []byte(settingsSchema),
	}
}

// newFake returns a fake that conforms: it streams a snapshot with one event, and its operation answers with one
// event.
func newFake(t *testing.T) *fake {
	t.Helper()
	return &fake{
		info: &collectorv1alpha1.GetInfoResponse{
			Name: collectorName, Version: collectorVersion, ApiVersions: []string{apiVersion},
		},
		caps:     goodCaps(),
		problems: func([]byte) ([]string, error) { return nil, nil },
		watch:    plan(start(), sends(t, newEvent(t, typeHello)), end()),
		invoke:   answer(answerEvent(t, newEvent(t, typeHello))),
	}
}

// serveRaw serves f on its own gRPC server until the test ends, and returns the Dial that reaches it.
func serveRaw(t *testing.T, f *fake) dialer {
	t.Helper()
	listener := bufconn.Listen(bufferSize)
	server := grpc.NewServer()
	collectorv1alpha1.RegisterIdentityServer(server, f)
	collectorv1alpha1.RegisterEvidenceServer(server, f)
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(server.Stop)
	return dialerFor(listener)
}

// baseTarget is a target with settings and a context, and with no invocation or settings to refuse. It has no
// Dial: a test serves the collector once it has changed it.
func baseTarget() conformance.Target {
	return conformance.Target{Settings: json.RawMessage(validSettings), Context: testContext()}
}

// rawTarget serves f and returns a base target that reaches it.
func rawTarget(t *testing.T, f *fake) conformance.Target {
	t.Helper()
	target := baseTarget()
	target.Dial = serveRaw(t, f)
	return target
}

type watchItem = *collectorv1alpha1.WatchResponse

func start() watchItem {
	return &collectorv1alpha1.WatchResponse{Item: &collectorv1alpha1.WatchResponse_SnapshotStart{
		SnapshotStart: &collectorv1alpha1.SnapshotStart{},
	}}
}

func end() watchItem {
	return &collectorv1alpha1.WatchResponse{Item: &collectorv1alpha1.WatchResponse_SnapshotEnd{
		SnapshotEnd: &collectorv1alpha1.SnapshotEnd{},
	}}
}

func tombstone() watchItem {
	return &collectorv1alpha1.WatchResponse{Item: &collectorv1alpha1.WatchResponse_Tombstone{
		Tombstone: &collectorv1alpha1.Tombstone{Type: typeHello, Subject: workload},
	}}
}

func sourceChanged() watchItem {
	return &collectorv1alpha1.WatchResponse{Item: &collectorv1alpha1.WatchResponse_SourceChanged{
		SourceChanged: &collectorv1alpha1.SourceChanged{},
	}}
}

func sends(t *testing.T, e cloudevents.Event) watchItem {
	t.Helper()
	p, err := evidence.ToProto(e)
	require.NoError(t, err)
	return &collectorv1alpha1.WatchResponse{Item: &collectorv1alpha1.WatchResponse_Event{Event: p}}
}

// plan is a Watch that sends the items, and then waits until the stream ends.
func plan(items ...watchItem) watchFunc {
	return func(_ int, stream watchStream) error {
		for _, item := range items {
			if err := stream.Send(item); err != nil {
				return err
			}
		}
		<-stream.Context().Done()
		return stream.Context().Err()
	}
}

// ends is a Watch that sends the items and then ends the stream, which is not what a Watch does.
func ends(items ...watchItem) watchFunc {
	return func(_ int, stream watchStream) error {
		for _, item := range items {
			if err := stream.Send(item); err != nil {
				return err
			}
		}
		return nil
	}
}

type invokeItem = *collectorv1alpha1.InvokeResponse

func answerEvent(t *testing.T, e cloudevents.Event) invokeItem {
	t.Helper()
	p, err := evidence.ToProto(e)
	require.NoError(t, err)
	return &collectorv1alpha1.InvokeResponse{Item: &collectorv1alpha1.InvokeResponse_Event{Event: p}}
}

func answerFailure(reason string) invokeItem {
	return &collectorv1alpha1.InvokeResponse{Item: &collectorv1alpha1.InvokeResponse_Failure{
		Failure: &collectorv1alpha1.Failure{Reason: reason, Message: "the operation failed"},
	}}
}

// answer is an Invoke that sends the items.
func answer(items ...invokeItem) invokeFunc {
	return func(_ *collectorv1alpha1.InvokeRequest, stream invokeStream) error {
		for _, item := range items {
			if err := stream.Send(item); err != nil {
				return err
			}
		}
		return nil
	}
}

func TestAFakeThatConformsPasses(t *testing.T) {
	target := rawTarget(t, newFake(t))
	target.InvalidSettings = json.RawMessage(brokenSettings)
	target.Invocations = []conformance.Invocation{{
		Operation: operationGreet, Subject: workload, Parameters: json.RawMessage(parameters),
		Inputs: []cloudevents.Event{newEvent(t, typeInput)},
	}}

	rec := run(t, target)

	require.Empty(t, rec.failedChecks())
	require.Equal(t, goodChecks, rec.ran())
}

func TestEachBreakOfTheContractFailsOneNamedCheck(t *testing.T) {
	tests := []struct {
		name   string
		change func(t *testing.T, f *fake, target *conformance.Target)
		check  string
		why    string
	}{
		{
			name: "an event of an undeclared type",
			change: func(t *testing.T, f *fake, _ *conformance.Target) {
				f.watch = plan(start(), sends(t, newEvent(t, typeUndeclared)), end())
			},
			check: checkDeclared,
			why:   typeUndeclared,
		},
		{
			name: "a snapshot that never ends",
			change: func(t *testing.T, f *fake, _ *conformance.Target) {
				f.watch = plan(start(), sends(t, newEvent(t, typeHello)))
			},
			check: checkEnd,
			why:   "SnapshotEnd",
		},
		{
			name: "an event whose data breaks its schema",
			change: func(t *testing.T, f *fake, _ *conformance.Target) {
				f.watch = plan(start(), sends(t, eventWith(t, typeHello, workload, greeting(5))), end())
			},
			check: checkData,
			why:   "/greeting",
		},
		{
			name: "settings that it accepts, though they must be refused",
			change: func(_ *testing.T, f *fake, target *conformance.Target) {
				f.caps.SettingsSchema = nil
				target.InvalidSettings = json.RawMessage(brokenSettings)
			},
			check: checkRefused,
			why:   "accepts",
		},
		{
			name: "an event that is not valid evidence",
			change: func(t *testing.T, f *fake, _ *conformance.Target) {
				f.watch = plan(start(), sends(t, eventWith(t, typeHello, "web", greeting("hello"))), end())
			},
			check: checkValid,
			why:   "subject",
		},
		{
			name: "a stream that doesn't start with SnapshotStart",
			change: func(t *testing.T, f *fake, _ *conformance.Target) {
				f.watch = plan(sends(t, newEvent(t, typeHello)), end())
			},
			check: checkStart,
			why:   "SnapshotStart",
		},
		{
			name:   "a Watch that the collector refuses",
			change: func(_ *testing.T, f *fake, _ *conformance.Target) { f.watch = refuses(codes.InvalidArgument) },
			check:  checkStart,
			why:    "InvalidArgument",
		},
		{
			name: "a tombstone inside the snapshot",
			change: func(_ *testing.T, f *fake, _ *conformance.Target) {
				f.watch = plan(start(), tombstone(), end())
			},
			check: checkOrder,
			why:   "tombstone",
		},
		{
			name: "SourceChanged inside the snapshot",
			change: func(_ *testing.T, f *fake, _ *conformance.Target) {
				f.watch = plan(start(), sourceChanged(), end())
			},
			check: checkOrder,
			why:   "SourceChanged",
		},
		{
			name: "a second SnapshotStart",
			change: func(_ *testing.T, f *fake, _ *conformance.Target) {
				f.watch = plan(start(), start(), end())
			},
			check: checkOrder,
			why:   "second SnapshotStart",
		},
		{
			name: "a stream that fails before SnapshotEnd",
			change: func(_ *testing.T, f *fake, _ *conformance.Target) {
				f.watch = func(_ int, stream watchStream) error {
					if err := stream.Send(start()); err != nil {
						return err
					}
					return status.Error(codes.Internal, "the source is gone")
				}
			},
			check: checkEnd,
			why:   "Internal",
		},
		{
			name: "a stream that ends before SnapshotEnd",
			change: func(_ *testing.T, f *fake, _ *conformance.Target) {
				f.watch = ends(start())
			},
			check: checkEnd,
			why:   "ended",
		},
		{
			name: "a second Watch that doesn't start with a snapshot",
			change: func(t *testing.T, f *fake, _ *conformance.Target) {
				first := plan(start(), sends(t, newEvent(t, typeHello)), end())
				later := plan(sends(t, newEvent(t, typeHello)))
				f.watch = func(call int, stream watchStream) error {
					if call == 1 {
						return first(call, stream)
					}
					return later(call, stream)
				}
			},
			check: checkAgain,
			why:   "SnapshotStart",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			f := newFake(t)
			target := baseTarget()
			test.change(t, f, &target)
			target.Dial = serveRaw(t, f)

			requireFailed(t, run(t, target), test.check, test.why)
		})
	}
}

// refuses is a Watch that the collector refuses with the code.
func refuses(code codes.Code) watchFunc {
	return func(int, watchStream) error { return status.Error(code, "the collector refuses this Watch") }
}

func TestCapabilitiesThatBreakTheContract(t *testing.T) {
	renamed := func(name string) func(*collectorv1alpha1.GetCapabilitiesResponse) {
		return func(caps *collectorv1alpha1.GetCapabilitiesResponse) {
			caps.Produces[0].Type = name
			caps.Operations[0].Produces = []string{name}
		}
	}
	tests := []struct {
		name   string
		change func(caps *collectorv1alpha1.GetCapabilitiesResponse)
		check  string
		why    string
	}{
		{"a settings schema that isn't JSON", func(c *collectorv1alpha1.GetCapabilitiesResponse) {
			c.SettingsSchema = []byte("{")
		}, checkSchemas, aboutSettings},
		{"a settings schema that doesn't compile", func(c *collectorv1alpha1.GetCapabilitiesResponse) {
			c.SettingsSchema = []byte(`{"type": 5}`)
		}, checkSchemas, aboutSettings},
		{"a settings schema that refers outside itself", func(c *collectorv1alpha1.GetCapabilitiesResponse) {
			c.SettingsSchema = []byte(`{"$ref": "https://schemas.example/settings.json"}`)
		}, checkSchemas, aboutSettings},
		{"a parameter schema that doesn't compile", func(c *collectorv1alpha1.GetCapabilitiesResponse) {
			c.Operations[0].ParameterSchema = []byte(`{"minimum": "one"}`)
		}, checkSchemas, operationGreet},
		{"a type schema that doesn't compile", func(c *collectorv1alpha1.GetCapabilitiesResponse) {
			c.Produces[1].Schema = []byte(`{"required": "greeting"}`)
		}, checkSchemas, typeOther},
		{"no role", func(c *collectorv1alpha1.GetCapabilitiesResponse) { c.Roles = nil }, checkRoles, "role"},
		{"a role that is none of them", func(c *collectorv1alpha1.GetCapabilitiesResponse) {
			c.Roles = []collectorv1alpha1.Role{collectorv1alpha1.Role_ROLE_SPOKE, collectorv1alpha1.Role_ROLE_UNSPECIFIED}
		}, checkRoles, "role"},
		{"a type without a domain", renamed("hello"), checkTypeNames, "hello"},
		{"a type that has no domain before its version", renamed("hello.v1alpha1"), checkTypeNames, "hello.v1alpha1"},
		{"a type without a version", renamed("com.example.hello"), checkTypeNames, "com.example.hello"},
		{"a type whose version has no number after alpha", renamed("com.example.hello.v1alpha"), checkTypeNames,
			"com.example.hello.v1alpha"},
		{"a type with capitals", renamed("com.example.Hello.v1alpha1"), checkTypeNames, "com.example.Hello.v1alpha1"},
		{"a type with an underscore", renamed("com.example.hello_world.v1alpha1"), checkTypeNames,
			"com.example.hello_world.v1alpha1"},
		{"a type after which something follows", renamed("com.example.hello.v1alpha1.x"), checkTypeNames,
			"com.example.hello.v1alpha1.x"},
		{"a type without a scope", func(c *collectorv1alpha1.GetCapabilitiesResponse) {
			c.Produces[1].Scope = collectorv1alpha1.Scope_SCOPE_UNSPECIFIED
		}, checkScopes, typeOther},
		{"an operation that produces an undeclared type", func(c *collectorv1alpha1.GetCapabilitiesResponse) {
			c.Operations[0].Produces = []string{typeHello, typeUndeclared}
		}, checkOperations, typeUndeclared},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			f := newFake(t)
			f.watch = plan(start(), end())
			test.change(f.caps)

			requireFailed(t, run(t, rawTarget(t, f)), test.check, test.why)
		})
	}
}

func TestGetInfoThatBreaksTheContract(t *testing.T) {
	tests := map[string]*collectorv1alpha1.GetInfoResponse{
		"no name":                  {Version: collectorVersion, ApiVersions: []string{apiVersion}},
		"no version":               {Name: collectorName, ApiVersions: []string{apiVersion}},
		"no API version":           {Name: collectorName, Version: collectorVersion},
		"another API version only": {Name: collectorName, Version: collectorVersion, ApiVersions: []string{"v9"}},
		"a version that only looks like it": {
			Name: collectorName, Version: collectorVersion, ApiVersions: []string{"v1alpha10"},
		},
	}
	for name, info := range tests {
		t.Run(name, func(t *testing.T) {
			f := newFake(t)
			f.info = info

			requireFailed(t, run(t, rawTarget(t, f)), checkInfo, "")
		})
	}
}

func TestACollectorMaySpeakSeveralVersions(t *testing.T) {
	f := newFake(t)
	f.info.ApiVersions = []string{"v9", apiVersion}

	requirePassed(t, run(t, rawTarget(t, f)), checkInfo)
}

func TestNothingRunsAfterTheDialFails(t *testing.T) {
	t.Run("without a Dial", func(t *testing.T) {
		rec := run(t, conformance.Target{})

		requireFailed(t, rec, checkDial, "Dial")
		require.Equal(t, []string{checkDial}, rec.ran())
	})
	t.Run("with a Dial that fails", func(t *testing.T) {
		rec := run(t, conformance.Target{Dial: func(context.Context) (*grpc.ClientConn, error) {
			return nil, errors.New("no route to the collector")
		}})

		requireFailed(t, rec, checkDial, "no route to the collector")
		require.Equal(t, []string{checkDial}, rec.ran())
	})
}

func TestNothingRunsWhenTheCollectorCannotSayWhatItDoes(t *testing.T) {
	f := newFake(t)
	f.capsErr = status.Error(codes.Unavailable, "not ready")

	rec := run(t, rawTarget(t, f))

	requireFailed(t, rec, checkCapabilities, "GetCapabilities")
	require.NotContains(t, rec.ran(), "Settings")
}

func TestSettings(t *testing.T) {
	refusedByTheCollector := func(settings []byte) ([]string, error) {
		if strings.Contains(string(settings), "goodbye") {
			return []string{"greeting: the collector only says hello"}, nil
		}
		return nil, nil
	}
	t.Run("settings that the collector's own check refuses are refused", func(t *testing.T) {
		f := newFake(t)
		f.caps.SettingsSchema = nil
		f.problems = refusedByTheCollector
		target := rawTarget(t, f)
		target.InvalidSettings = json.RawMessage(refusedSettings)

		requirePassed(t, run(t, target), checkRefused)
	})
	t.Run("settings that the schema refuses are refused, whatever the collector's own check says", func(t *testing.T) {
		f := newFake(t)
		target := rawTarget(t, f)
		target.InvalidSettings = json.RawMessage(brokenSettings)

		requirePassed(t, run(t, target), checkRefused)
	})
	t.Run("settings that are not JSON are refused", func(t *testing.T) {
		f := newFake(t)
		target := rawTarget(t, f)
		target.InvalidSettings = json.RawMessage("{")

		requirePassed(t, run(t, target), checkRefused)
	})
	t.Run("settings that the schema refuses stop the checks that need them", func(t *testing.T) {
		f := newFake(t)
		target := rawTarget(t, f)
		target.Settings = json.RawMessage(brokenSettings)

		rec := run(t, target)

		requireFailed(t, rec, checkAccepted, "/greeting")
		require.NotContains(t, rec.ran(), "Watch")
	})
	t.Run("settings that the collector's own check refuses stop them too", func(t *testing.T) {
		f := newFake(t)
		f.problems = refusedByTheCollector
		target := rawTarget(t, f)
		target.Settings = json.RawMessage(refusedSettings)

		rec := run(t, target)

		requireFailed(t, rec, checkAccepted, "only says hello")
		require.NotContains(t, rec.ran(), "Watch")
	})
	t.Run("a ValidateSettings that fails is no answer", func(t *testing.T) {
		f := newFake(t)
		f.problems = func([]byte) ([]string, error) { return nil, status.Error(codes.Internal, "no answer") }

		rec := run(t, rawTarget(t, f))

		requireFailed(t, rec, checkAccepted, "ValidateSettings")
		require.NotContains(t, rec.ran(), "Watch")
	})
}

func TestInvocationsThatBreakTheContract(t *testing.T) {
	invalid := eventWith(t, typeHello, "web", greeting("hello"))
	tests := []struct {
		name   string
		invoke invokeFunc
		change func(t *testing.T, inv *conformance.Invocation)
		why    string
	}{
		{
			name:   "an operation that the collector doesn't declare",
			invoke: answer(),
			change: func(_ *testing.T, inv *conformance.Invocation) { inv.Operation = "farewell" },
			why:    "farewell",
		},
		{
			name:   "an input that is not valid evidence",
			invoke: answer(),
			change: func(_ *testing.T, inv *conformance.Invocation) { inv.Inputs = []cloudevents.Event{invalid} },
			why:    "input 0",
		},
		{
			name: "a call that fails",
			invoke: func(*collectorv1alpha1.InvokeRequest, invokeStream) error {
				return status.Error(codes.Internal, "boom")
			},
			why: "Internal",
		},
		{
			name:   "an event that is not valid evidence",
			invoke: answer(answerEvent(t, invalid)),
			why:    "subject",
		},
		{
			name:   "an event of an undeclared type",
			invoke: answer(answerEvent(t, newEvent(t, typeUndeclared))),
			why:    typeUndeclared,
		},
		{
			name:   "an event of a type that the operation doesn't produce",
			invoke: answer(answerEvent(t, newEvent(t, typeOther))),
			why:    typeOther,
		},
		{
			name: "an event whose data breaks its schema",
			invoke: answer(answerEvent(t,
				eventWith(t, typeHello, workload, greeting(5)))),
			why: "/greeting",
		},
		{
			name:   "a failure without a reason",
			invoke: answer(answerFailure("")),
			why:    "reason",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			f := newFake(t)
			f.invoke = test.invoke
			target := rawTarget(t, f)
			inv := conformance.Invocation{
				Operation: operationGreet, Subject: workload, Parameters: json.RawMessage(parameters),
				Inputs: []cloudevents.Event{newEvent(t, typeInput)},
			}
			if test.change != nil {
				test.change(t, &inv)
			}
			target.Invocations = []conformance.Invocation{inv}

			rec := run(t, target)

			require.Equal(t, []string{"Invoke/" + inv.Operation}, rec.failedChecks())
			require.Contains(t, rec.messages("Invoke/"+inv.Operation), test.why)
		})
	}
}

func TestInvocationsThatConform(t *testing.T) {
	tests := map[string]invokeFunc{
		"an answer without events or a failure": answer(),
		"a failure with a reason":               answer(answerFailure("NotFound")),
		"events and then a failure":             answer(answerEvent(t, newEvent(t, typeHello)), answerFailure("TooLarge")),
	}
	for name, invoke := range tests {
		t.Run(name, func(t *testing.T) {
			f := newFake(t)
			f.invoke = invoke
			target := rawTarget(t, f)
			target.Invocations = []conformance.Invocation{{Operation: operationGreet, Subject: workload}}

			requirePassed(t, run(t, target), checkInvoke)
		})
	}
}

func TestTheSuiteSendsWhatTheTargetSays(t *testing.T) {
	f := newFake(t)
	target := rawTarget(t, f)
	input := newEvent(t, typeInput)
	target.Invocations = []conformance.Invocation{{
		Operation: operationGreet, Subject: workload, Parameters: json.RawMessage(parameters),
		Inputs: []cloudevents.Event{input},
	}}

	requirePassed(t, run(t, target), checkInvoke)

	want := &collectorv1alpha1.Context{
		Cluster:           clusterA,
		OperatorNamespace: "vexplain-system",
		OwnPodLabel:       "vexplain.bedag.ch/task",
		Scope:             []byte(`{"excludeNamespaces": {"matchLabels": {"team": "off"}}}`),
		OwnerAttribution:  []byte(`{"namespaceLabels": ["team"]}`),
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	require.Len(t, f.watches, 2, "the snapshot, and the second Watch")
	for _, req := range f.watches {
		require.Equal(t, collectorv1alpha1.Role_ROLE_SPOKE, req.GetRole())
		require.JSONEq(t, validSettings, string(req.GetSettings()))
		require.Equal(t, want.GetCluster(), req.GetContext().GetCluster())
		require.Equal(t, want.GetOperatorNamespace(), req.GetContext().GetOperatorNamespace())
		require.Equal(t, want.GetOwnPodLabel(), req.GetContext().GetOwnPodLabel())
		require.Equal(t, want.GetScope(), req.GetContext().GetScope())
		require.Equal(t, want.GetOwnerAttribution(), req.GetContext().GetOwnerAttribution())
	}
	require.Len(t, f.invokes, 1)
	req := f.invokes[0]
	require.Equal(t, operationGreet, req.GetOperation())
	require.Equal(t, workload, req.GetSubject())
	require.JSONEq(t, parameters, string(req.GetParameters()))
	require.JSONEq(t, validSettings, string(req.GetSettings()))
	require.Equal(t, collectorv1alpha1.Role_ROLE_SPOKE, req.GetRole(), "the role of the operation")
	require.Equal(t, want.GetScope(), req.GetContext().GetScope())
	require.Len(t, req.GetInputs(), 1)
	got, err := evidence.FromProto(req.GetInputs()[0])
	require.NoError(t, err)
	require.Equal(t, input, got)
}

func TestWatchChecksRunForEachRole(t *testing.T) {
	f := newFake(t)
	f.caps.Roles = []collectorv1alpha1.Role{collectorv1alpha1.Role_ROLE_SPOKE, collectorv1alpha1.Role_ROLE_HUB}
	f.caps.Operations = nil

	rec := run(t, rawTarget(t, f))

	requirePassed(t, rec, checkStart, "Watch/hub/starts with SnapshotStart")
	f.mu.Lock()
	defer f.mu.Unlock()
	roles := make([]collectorv1alpha1.Role, 0, len(f.watches))
	for _, req := range f.watches {
		roles = append(roles, req.GetRole())
	}
	require.Equal(t, []collectorv1alpha1.Role{
		collectorv1alpha1.Role_ROLE_SPOKE, collectorv1alpha1.Role_ROLE_SPOKE,
		collectorv1alpha1.Role_ROLE_HUB, collectorv1alpha1.Role_ROLE_HUB,
	}, roles, "a Watch and a second Watch for each role")
}

func TestACollectorThatDoesNotWatchIsNotWatched(t *testing.T) {
	f := newFake(t)
	f.caps.Watches = false
	f.watch = func(int, watchStream) error {
		t.Error("the suite called Watch, and the collector says that it doesn't watch")
		return status.Error(codes.Unimplemented, "")
	}

	rec := run(t, rawTarget(t, f))

	requirePassed(t, rec, checkInfo)
	require.NotContains(t, rec.ran(), "Watch")
}

func TestALongListOfProblemsIsCutShort(t *testing.T) {
	f := newFake(t)
	undeclared := slices.Repeat([]watchItem{sends(t, newEvent(t, typeUndeclared))}, 25)
	f.watch = plan(slices.Concat([]watchItem{start()}, undeclared, []watchItem{end()})...)

	rec := run(t, rawTarget(t, f))

	require.Equal(t, []string{checkDeclared}, rec.failedChecks())
	require.Contains(t, rec.messages(checkDeclared), "15 more", "the first 10 are listed, and the rest counted")
}
