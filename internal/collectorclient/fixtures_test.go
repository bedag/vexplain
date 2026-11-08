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
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	cloudevents "github.com/cloudevents/sdk-go/v2"
	"github.com/go-logr/logr"
	"github.com/go-logr/logr/funcr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/health"
	"google.golang.org/grpc/stats"
	"google.golang.org/grpc/status"

	collectorv1alpha1 "github.com/bedag/vexplain/sdk/api/collector/v1alpha1"
	"github.com/bedag/vexplain/sdk/collector"
	"github.com/bedag/vexplain/sdk/evidence"
	"github.com/bedag/vexplain/sdk/subject"
)

const (
	// helloType is the type of evidence that the collectors of the tests produce.
	helloType = "com.example.hello.v1alpha1"
	// helloSource is the source of their events.
	helloSource = "/clusters/cluster-a/collectors/hello"
	// greet is their operation.
	greet = "greet"
)

// digest is the digest of the image that event n is about.
func digest(n int) string {
	return fmt.Sprintf("sha256:%064x", n)
}

// event returns evidence of helloType about the image of digest(n).
func event(t *testing.T, n int) cloudevents.Event {
	t.Helper()
	return eventOf(t, helloType, subject.Image(digest(n)), map[string]int{"n": n})
}

// eventOf returns an event of the type about the subject, with data, that evidence.New builds, as a collector does.
// It doesn't check the event, so a test can build evidence that isn't valid.
func eventOf(t *testing.T, eventType, about string, data any) cloudevents.Event {
	t.Helper()
	e, err := evidence.New(eventType, about, data, evidence.WithSource(helloSource))
	require.NoError(t, err)
	return e
}

// ids returns the IDs of the events, or nil for none.
func ids(events ...cloudevents.Event) []string {
	if len(events) == 0 {
		return nil
	}
	out := make([]string, 0, len(events))
	for _, e := range events {
		out = append(out, e.ID())
	}
	return out
}

// hello is a collector of the tests, which the SDK serves in the test's process. It takes the roles that a test
// gives it, watches, produces helloType, and runs the operation greet in its first role. Each of its Watches waits
// for the test, which drives the stream through the watchCall that it receives.
type hello struct {
	roles   []collector.Role
	watches map[collector.Role]chan *watchCall
	// greeter answers greet; nil answers nothing.
	greeter func(req collector.InvokeRequest) ([]cloudevents.Event, *collector.Failure, error)
}

func newHello(roles ...collector.Role) *hello {
	h := &hello{roles: roles, watches: map[collector.Role]chan *watchCall{}}
	for _, role := range roles {
		h.watches[role] = make(chan *watchCall)
	}
	return h
}

func (h *hello) Info() collector.Info {
	return collector.Info{Name: "hello", Version: "0.1.0"}
}

func (h *hello) Capabilities() collector.Capabilities {
	return collector.Capabilities{
		Roles: h.roles,
		Produces: []collector.EvidenceType{
			{Type: helloType, Scope: collector.ScopeSpoke, Schema: []byte(`{"type": "object"}`)},
		},
		Watches:    true,
		Operations: []collector.Operation{{Name: greet, Role: h.roles[0], Produces: []string{helloType}}},
		SettingsSchema: []byte(
			`{"type": "object", "properties": {"greeting": {"type": "string"}}, "additionalProperties": false}`),
	}
}

func (h *hello) Watch(ctx context.Context, req collector.WatchRequest, sink collector.Sink) error {
	call := &watchCall{ctx: ctx, req: req, sink: sink, end: make(chan error, 1)}
	select {
	case h.watches[req.Role] <- call:
	case <-ctx.Done():
		return ctx.Err()
	}
	select {
	case err := <-call.end:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (h *hello) Invoke(_ context.Context, req collector.InvokeRequest) ([]cloudevents.Event, *collector.Failure, error) {
	if h.greeter == nil {
		return nil, nil, nil
	}
	return h.greeter(req)
}

// next waits for the collector's next Watch in the role.
func (h *hello) next(t *testing.T, role collector.Role) *watchCall {
	t.Helper()
	select {
	case call := <-h.watches[role]:
		return call
	case <-time.After(wait):
		require.FailNow(t, "no Watch came", "in the role %d", role)
		return nil
	}
}

// none checks that no Watch comes in the role for a while.
func (h *hello) none(t *testing.T, role collector.Role) {
	t.Helper()
	select {
	case <-h.watches[role]:
		require.FailNow(t, "a Watch came", "in the role %d", role)
	case <-time.After(quiet):
	}
}

// watchCall is one Watch of hello, which the test drives: it sends through sink, and ends the stream through end.
type watchCall struct {
	ctx  context.Context
	req  collector.WatchRequest
	sink collector.Sink
	end  chan error
}

// snapshot sends a whole snapshot of the events.
func (c *watchCall) snapshot(t *testing.T, events ...cloudevents.Event) {
	t.Helper()
	require.NoError(t, c.sink.SnapshotStart())
	for _, e := range events {
		require.NoError(t, c.sink.Event(e))
	}
	require.NoError(t, c.sink.SnapshotEnd())
}

// cut ends the stream with an error, as a collector that fails or restarts does.
func (c *watchCall) cut() {
	c.end <- status.Error(codes.Unavailable, "the test cut the stream")
}

// ended says whether the Watch's context has ended, as it does when the client stops the stream.
func (c *watchCall) ended() bool {
	return c.ctx.Err() != nil
}

// raw is a collector that sends whatever the test tells it, without the SDK and its checks, as a collector that
// isn't built with the SDK can. Each of its Watches hands its stream to the test. It records the compression of
// each call that comes in.
type raw struct {
	collectorv1alpha1.UnimplementedEvidenceServer
	health  *health.Server
	watches chan *rawWatch

	mu sync.Mutex
	// answer is what Invoke sends for a request, and the error that it ends with. streaming, when it is set, sends
	// the answer itself, item by item, until it returns.
	answer       func(req *collectorv1alpha1.InvokeRequest) ([]*collectorv1alpha1.InvokeResponse, error)
	streaming    func(ctx context.Context, send func(*collectorv1alpha1.InvokeResponse) error) error
	compressions []string
	// fire is what Fire does for a request. Without it, Fire answers at once.
	fire func(ctx context.Context, req *collectorv1alpha1.FireRequest) error
}

func newRaw() *raw {
	return &raw{health: health.NewServer(), watches: make(chan *rawWatch)}
}

func (r *raw) Watch(_ *collectorv1alpha1.WatchRequest,
	stream grpc.ServerStreamingServer[collectorv1alpha1.WatchResponse]) error {
	w := &rawWatch{ctx: stream.Context(), stream: stream, end: make(chan error, 1)}
	select {
	case r.watches <- w:
	case <-stream.Context().Done():
		return stream.Context().Err()
	}
	select {
	case err := <-w.end:
		return err
	case <-stream.Context().Done():
		return stream.Context().Err()
	}
}

// fireWith makes Fire do what fire does.
func (r *raw) fireWith(fire func(ctx context.Context, req *collectorv1alpha1.FireRequest) error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.fire = fire
}

func (r *raw) Fire(ctx context.Context, req *collectorv1alpha1.FireRequest) (*collectorv1alpha1.FireResponse, error) {
	r.mu.Lock()
	fire := r.fire
	r.mu.Unlock()
	if fire == nil {
		return &collectorv1alpha1.FireResponse{}, nil
	}
	return &collectorv1alpha1.FireResponse{}, fire(ctx, req)
}

// answerWith makes Invoke answer with what answer returns.
func (r *raw) answerWith(answer func(req *collectorv1alpha1.InvokeRequest) ([]*collectorv1alpha1.InvokeResponse, error)) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.answer = answer
}

// answerStreaming makes Invoke send its answer through streaming, item by item, until streaming returns.
func (r *raw) answerStreaming(streaming func(ctx context.Context, send func(*collectorv1alpha1.InvokeResponse) error) error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.streaming = streaming
}

func (r *raw) Invoke(req *collectorv1alpha1.InvokeRequest,
	stream grpc.ServerStreamingServer[collectorv1alpha1.InvokeResponse]) error {
	r.mu.Lock()
	answer, streaming := r.answer, r.streaming
	r.mu.Unlock()
	if streaming != nil {
		return streaming(stream.Context(), stream.Send)
	}
	items, err := answer(req)
	for _, item := range items {
		if sendErr := stream.Send(item); sendErr != nil {
			return sendErr
		}
	}
	return err
}

// The methods of stats.Handler, through which raw records the compression of the calls that come in.

func (r *raw) TagRPC(ctx context.Context, _ *stats.RPCTagInfo) context.Context { return ctx }

func (r *raw) HandleRPC(_ context.Context, s stats.RPCStats) {
	if header, ok := s.(*stats.InHeader); ok {
		r.mu.Lock()
		defer r.mu.Unlock()
		r.compressions = append(r.compressions, header.Compression)
	}
}

func (r *raw) TagConn(ctx context.Context, _ *stats.ConnTagInfo) context.Context { return ctx }

func (r *raw) HandleConn(context.Context, stats.ConnStats) {}

// compressionsOfCalls returns the compression of each call that came in, in order.
func (r *raw) compressionsOfCalls() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.compressions)
}

// next waits for the next Watch.
func (r *raw) next(t *testing.T) *rawWatch {
	t.Helper()
	select {
	case w := <-r.watches:
		return w
	case <-time.After(wait):
		require.FailNow(t, "no Watch came")
		return nil
	}
}

// rawWatch is one Watch of raw, which the test drives.
type rawWatch struct {
	ctx    context.Context
	stream grpc.ServerStreamingServer[collectorv1alpha1.WatchResponse]
	end    chan error
}

// send sends the items, as they are.
func (w *rawWatch) send(t *testing.T, items ...*collectorv1alpha1.WatchResponse) {
	t.Helper()
	for _, item := range items {
		require.NoError(t, w.stream.Send(item))
	}
}

// The items of a stream, as raw sends them.

func snapshotStart() *collectorv1alpha1.WatchResponse {
	return &collectorv1alpha1.WatchResponse{Item: &collectorv1alpha1.WatchResponse_SnapshotStart{
		SnapshotStart: &collectorv1alpha1.SnapshotStart{},
	}}
}

func snapshotEnd() *collectorv1alpha1.WatchResponse {
	return &collectorv1alpha1.WatchResponse{Item: &collectorv1alpha1.WatchResponse_SnapshotEnd{
		SnapshotEnd: &collectorv1alpha1.SnapshotEnd{},
	}}
}

func eventItem(t *testing.T, e cloudevents.Event) *collectorv1alpha1.WatchResponse {
	t.Helper()
	p, err := evidence.ToProto(e)
	require.NoError(t, err)
	return &collectorv1alpha1.WatchResponse{Item: &collectorv1alpha1.WatchResponse_Event{Event: p}}
}

func tombstoneItem(eventType, about string) *collectorv1alpha1.WatchResponse {
	return &collectorv1alpha1.WatchResponse{Item: &collectorv1alpha1.WatchResponse_Tombstone{
		Tombstone: &collectorv1alpha1.Tombstone{Type: eventType, Subject: about},
	}}
}

func sourceChangedItem(subjects ...string) *collectorv1alpha1.WatchResponse {
	return &collectorv1alpha1.WatchResponse{Item: &collectorv1alpha1.WatchResponse_SourceChanged{
		SourceChanged: &collectorv1alpha1.SourceChanged{Subjects: subjects},
	}}
}

// The items of an answer to Invoke, as raw sends them.

func answerEvent(t *testing.T, e cloudevents.Event) *collectorv1alpha1.InvokeResponse {
	t.Helper()
	p, err := evidence.ToProto(e)
	require.NoError(t, err)
	return &collectorv1alpha1.InvokeResponse{Item: &collectorv1alpha1.InvokeResponse_Event{Event: p}}
}

func answerFailure(reason, message string) *collectorv1alpha1.InvokeResponse {
	return &collectorv1alpha1.InvokeResponse{Item: &collectorv1alpha1.InvokeResponse_Failure{
		Failure: &collectorv1alpha1.Failure{Reason: reason, Message: message},
	}}
}

// sinkCall is a call of a sink, with what identifies its arguments: the IDs of the events of a snapshot or an
// upsert, the type and the subject of a removal, and the subjects of a change of source.
type sinkCall struct {
	Method    string
	Collector string
	IDs       []string
	Type      string
	Subject   string
	Subjects  []string
}

func snapshotCall(name string, events ...cloudevents.Event) sinkCall {
	return sinkCall{Method: "Snapshot", Collector: name, IDs: ids(events...)}
}

func upsertCall(name string, e cloudevents.Event) sinkCall {
	return sinkCall{Method: "Upsert", Collector: name, IDs: ids(e)}
}

func removeCall(name, eventType, about string) sinkCall {
	return sinkCall{Method: "Remove", Collector: name, Type: eventType, Subject: about}
}

func sourceChangedCall(name string, subjects ...string) sinkCall {
	return sinkCall{Method: "SourceChanged", Collector: name, Subjects: subjects}
}

func forgetCall(name string) sinkCall {
	return sinkCall{Method: "Forget", Collector: name}
}

// recordingSink is a sink that records its calls.
type recordingSink struct {
	mu    sync.Mutex
	calls []sinkCall
}

func (s *recordingSink) record(call sinkCall) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = append(s.calls, call)
}

func (s *recordingSink) Snapshot(name string, events []cloudevents.Event) {
	s.record(snapshotCall(name, events...))
}

func (s *recordingSink) Upsert(name string, e cloudevents.Event) {
	s.record(upsertCall(name, e))
}

func (s *recordingSink) Remove(name, eventType, about string) {
	s.record(removeCall(name, eventType, about))
}

func (s *recordingSink) SourceChanged(name string, subjects []string) {
	s.record(sourceChangedCall(name, subjects...))
}

func (s *recordingSink) Forget(name string) {
	s.record(forgetCall(name))
}

// recorded returns the calls so far.
func (s *recordingSink) recorded() []sinkCall {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.calls)
}

// await waits until the sink has had exactly the calls.
func (s *recordingSink) await(t *testing.T, want ...sinkCall) {
	t.Helper()
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		assert.Equal(c, want, s.recorded())
	}, wait, tick)
}

// stays checks that the sink has had exactly the calls, for a while.
func (s *recordingSink) stays(t *testing.T, want ...sinkCall) {
	t.Helper()
	require.Never(t, func() bool { return !assert.ObjectsAreEqual(want, s.recorded()) }, quiet, tick,
		"the sink had other calls than %v", want)
	require.Equal(t, want, s.recorded())
}

// logLines collects what a logger writes, so that a test can read it.
type logLines struct {
	mu    sync.Mutex
	lines []string
}

func (l *logLines) logger() logr.Logger {
	return funcr.New(func(prefix, args string) {
		l.mu.Lock()
		defer l.mu.Unlock()
		l.lines = append(l.lines, prefix+" "+args)
	}, funcr.Options{Verbosity: 10})
}

func (l *logLines) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return strings.Join(l.lines, "\n")
}
