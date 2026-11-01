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

// Package conformance runs a collector against the contract of the collector API, as CSI's csi-sanity does for
// storage drivers. Every collector of vexplain's own passes it in CI, and so should every collector that anyone
// else writes. The collector is a server, in any language: the suite calls it over gRPC, as vexplain does, and
// never looks inside it.
//
// A test serves the collector, and runs the suite against what it serves:
//
//	func TestConformance(t *testing.T) {
//		conformance.Run(t, conformance.Target{
//			Dial:     dialTheCollector,
//			Settings: json.RawMessage(`{"greeting": "Hello"}`),
//			Context:  collector.Context{Cluster: "cluster-a"},
//		})
//	}
//
// The suite checks that:
//   - GetInfo has a name, a version and v1alpha1, and GetCapabilities answers.
//   - Every schema in the capabilities compiles. Every type that the collector produces is reverse-DNS and
//     versioned, and has a scope. Every operation produces only types that the collector declares, and the
//     collector takes a role.
//   - The Target's Settings pass the schema and ValidateSettings, and its InvalidSettings, when it has any,
//     don't.
//   - A collector that watches starts each Watch, for each of its roles, with SnapshotStart, and reaches
//     SnapshotEnd within a minute. Only events come in between. A second Watch starts with a snapshot again.
//   - Every event of a snapshot is valid evidence, of a type that the collector declares, and its data validates
//     against the schema of its type.
//   - Each of the Target's Invocations answers with valid events, of types that the operation produces, or with
//     a failure that has a reason.
//   - A collector that produces the presence type applies the scope and leaves out vexplain's own pods. This
//     presence check needs a Kubernetes client: see Target.Client.
//
// Each check is a subtest, or a Reporter's Run, named by its group and what it checks, such as
// "Watch/spoke/reaches SnapshotEnd in time". The design of collectors, evidence and rules gives the reasons for
// the contract, in docs/design/2026-10-31-collectors-evidence-rules.md, sections 5.3 and 5.5.
package conformance

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/cloudevents/sdk-go/binding/format/protobuf/v2/pb"
	cloudevents "github.com/cloudevents/sdk-go/v2"
	"github.com/santhosh-tekuri/jsonschema/v6"
	"google.golang.org/grpc"
	"google.golang.org/grpc/encoding/gzip"
	"google.golang.org/grpc/status"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/rand"
	"sigs.k8s.io/controller-runtime/pkg/client"

	collectorv1alpha1 "github.com/bedag/vexplain/sdk/api/collector/v1alpha1"
	"github.com/bedag/vexplain/sdk/collector"
	"github.com/bedag/vexplain/sdk/evidence"
	subjects "github.com/bedag/vexplain/sdk/subject"
)

// Reporter is what the suite reports to: the part of testing.T that it uses. Run makes a Reporter of a *testing.T,
// whose Run is a subtest. A test of the suite itself passes a Reporter that records what it is told.
//
// The suite reports every failure inside a named check, a Run of its own: it never calls Errorf or Fatalf on the
// Reporter that RunWith got.
type Reporter interface {
	// Helper marks the calling function as a helper, as testing.T's does.
	Helper()
	// Errorf reports a failure of the check that runs, and lets the check go on.
	Errorf(format string, args ...any)
	// Fatalf reports a failure of the check that runs, and ends the check.
	Fatalf(format string, args ...any)
	// Run runs a check, or a group of checks, under a name, and reports whether it passed.
	Run(name string, f func(Reporter)) bool
}

// Target is the collector to check, and what the suite needs to call it.
type Target struct {
	// Dial connects to the collector. The suite calls it once, and closes the connection that it returns when it
	// is done. The collector can run anywhere: in the process of the test, behind a listener of its own, or in
	// a cluster.
	Dial func(ctx context.Context) (*grpc.ClientConn, error)
	// Settings are valid settings of the collector, as JSON, which the suite sends with every Watch and Invoke.
	// Without any, the suite sends none, and the collector must take that as an empty object.
	Settings json.RawMessage
	// InvalidSettings, when set, are settings that the collector must refuse: its settings schema, or its own
	// check, finds a problem with them.
	InvalidSettings json.RawMessage
	// Context is what vexplain tells the collector about its cluster, which the suite sends with every Watch and
	// Invoke. The presence check, which tests how a collector applies the scope and the label of vexplain's own
	// pods, sets a scope, an operator namespace and an own-pod label of its own, and takes the rest from here.
	Context collector.Context
	// Invocations are the operations to call, each with a subject, parameters and inputs. The suite calls the
	// operations of a collector only through them.
	Invocations []Invocation
	// Client, when set, is a client of the cluster that the collector reads, which turns on the presence check
	// for a collector that produces the presence type. The suite then creates namespaces, with pods in them,
	// and sets their image IDs as a kubelet would, through the status subresource. It deletes the namespaces when
	// it is done. It reaches the cluster only through this client, so give it a client of a cluster for tests,
	// such as envtest or kind, and never of a cluster that anyone uses. A collector that produces the presence
	// type, and gets no Client, fails the check: its conformance needs a Kubernetes client.
	Client client.Client
}

// Invocation is a call of one operation, with what it needs.
type Invocation struct {
	// Operation is the name of an operation that the collector declares, and Subject is what it runs for, such as
	// image/sha256:<64 hex>.
	Operation, Subject string
	// Parameters are the operation's parameters, as JSON. The suite sends none for none.
	Parameters json.RawMessage
	// Inputs are evidence of the types that the operation consumes, which vexplain would gather first. Each must
	// be valid evidence.
	Inputs []cloudevents.Event
}

// Run runs the suite against the target, with each check a subtest of t.
func Run(t *testing.T, target Target) {
	t.Helper()
	RunWith(testingReporter{t}, target)
}

// testingReporter makes a *testing.T a Reporter, whose Run runs a subtest.
type testingReporter struct{ *testing.T }

func (r testingReporter) Run(name string, f func(Reporter)) bool {
	return r.T.Run(name, func(t *testing.T) { f(testingReporter{t}) })
}

// RunWith runs the suite against the target, and reports to r.
func RunWith(r Reporter, target Target) {
	r.Helper()
	run(r, target, defaultLimits)
}

// limits are how long the suite waits for a collector.
type limits struct {
	// call bounds Dial, and each call that has one answer.
	call time.Duration
	// snapshot bounds a Watch from its start to SnapshotEnd. The API's contract says a minute.
	snapshot time.Duration
	// invoke bounds an Invoke, to the end of its answer.
	invoke time.Duration
	// presence bounds how long the presence check waits for pods that it expects the snapshot to list. A
	// collector that reads through a cache needs a moment to see pods that were created just now.
	presence time.Duration
}

var defaultLimits = limits{
	call:     30 * time.Second,
	snapshot: time.Minute,
	invoke:   5 * time.Minute,
	presence: 30 * time.Second,
}

const (
	// maxMessageSize is the largest message of the collector API, 16 MiB, where gRPC's default allows 4.
	maxMessageSize = 16 << 20
	// maxReported is how many problems of one check the suite lists. A collector that breaks a rule breaks it for
	// every event, and a snapshot can have thousands: the first few are what the author needs.
	maxReported = 10
	// collectorSchemaURL names a schema of the settings or of an operation's parameters while it compiles, and
	// typeSchemaPrefix starts the name of a type's schema, as evidence.New starts the dataschema of its events.
	collectorSchemaURL = "urn:vexplain:collector:schema"
	typeSchemaPrefix   = "urn:vexplain:schema:"
)

// typePattern is what a type of evidence looks like: reverse-DNS, and versioned, such as
// ch.bedag.vexplain.presence.v1alpha1.
var typePattern = regexp.MustCompile(`^[a-z0-9-]+(\.[a-z0-9-]+)+\.v[0-9]+((alpha|beta)[0-9]+)?$`)

// session is the suite's connection to the collector, and what it learned from GetCapabilities.
type session struct {
	target   Target
	lim      limits
	conn     *grpc.ClientConn
	identity collectorv1alpha1.IdentityClient
	stream   collectorv1alpha1.EvidenceClient
	caps     *collectorv1alpha1.GetCapabilitiesResponse

	// settings is the compiled schema of the settings. It is nil without one, and when it doesn't compile.
	settings *jsonschema.Schema
	// schemaErrors say which schemas of the capabilities don't compile, and why.
	schemaErrors []string
	// types are the types that the collector produces, by name, with their compiled schemas.
	types      map[string]*jsonschema.Schema
	operations map[string]*collectorv1alpha1.Operation
}

// callOptions are how the suite calls, as vexplain does: compressed, and with messages of up to 16 MiB.
func callOptions() []grpc.CallOption {
	return []grpc.CallOption{grpc.UseCompressor(gzip.Name), grpc.MaxCallRecvMsgSize(maxMessageSize)}
}

func run(r Reporter, target Target, lim limits) {
	r.Helper()
	var s *session
	if !r.Run("Dial", func(r Reporter) { s = connect(r, target, lim) }) {
		return
	}
	defer func() { _ = s.conn.Close() }()

	r.Run("Identity", s.identityChecks)
	if s.caps == nil {
		return
	}
	r.Run("Capabilities", s.capabilityChecks)
	if !s.settingsChecks(r) {
		return
	}
	if s.caps.GetWatches() {
		r.Run("Watch", s.watchChecks)
	}
	if len(target.Invocations) > 0 {
		r.Run("Invoke", s.invokeChecks)
	}
	if _, presence := s.types[evidence.TypePresence]; presence {
		r.Run("Presence", s.presenceChecks)
	}
}

// connect dials the collector.
func connect(r Reporter, target Target, lim limits) *session {
	r.Helper()
	if target.Dial == nil {
		r.Fatalf("the Target has no Dial, which connects the suite to the collector")
	}
	ctx, cancel := context.WithTimeout(context.Background(), lim.call)
	defer cancel()
	conn, err := target.Dial(ctx)
	if err != nil {
		r.Fatalf("Dial: %v", err)
	}
	if conn == nil {
		r.Fatalf("Dial returned no connection, and no error")
	}
	return &session{
		target:   target,
		lim:      lim,
		conn:     conn,
		identity: collectorv1alpha1.NewIdentityClient(conn),
		stream:   collectorv1alpha1.NewEvidenceClient(conn),
	}
}

// describe says what an error of a call is, with its gRPC code.
func describe(err error) string {
	if st, ok := status.FromError(err); ok {
		return st.Code().String() + ": " + st.Message()
	}
	return err.Error()
}

// report reports the problems of one check, the first few of them.
func report(r Reporter, problems []string) {
	r.Helper()
	for i, problem := range problems {
		if i == maxReported {
			r.Errorf("and %d more", len(problems)-maxReported)
			return
		}
		r.Errorf("%s", problem)
	}
}

func (s *session) identityChecks(r Reporter) {
	r.Helper()
	r.Run("GetInfo has a name, a version and v1alpha1", s.getInfo)
	r.Run("GetCapabilities answers", s.getCapabilities)
}

func (s *session) getInfo(r Reporter) {
	r.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), s.lim.call)
	defer cancel()
	info, err := s.identity.GetInfo(ctx, &collectorv1alpha1.GetInfoRequest{}, callOptions()...)
	if err != nil {
		r.Fatalf("GetInfo: %s", describe(err))
	}
	if info.GetName() == "" {
		r.Errorf("GetInfo has no name")
	}
	if info.GetVersion() == "" {
		r.Errorf("GetInfo has no version, and vexplain stores evidence at the collector's version")
	}
	if !slices.Contains(info.GetApiVersions(), collector.APIVersion) {
		r.Errorf("GetInfo lists the API versions %q, and not %s: vexplain uses the newest version that both sides speak",
			info.GetApiVersions(), collector.APIVersion)
	}
}

// getCapabilities reads what the collector does, and compiles its schemas.
func (s *session) getCapabilities(r Reporter) {
	r.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), s.lim.call)
	defer cancel()
	caps, err := s.identity.GetCapabilities(ctx, &collectorv1alpha1.GetCapabilitiesRequest{}, callOptions()...)
	if err != nil {
		r.Fatalf("GetCapabilities: %s", describe(err))
	}
	s.caps = caps
	s.types = make(map[string]*jsonschema.Schema, len(caps.GetProduces()))
	s.operations = make(map[string]*collectorv1alpha1.Operation, len(caps.GetOperations()))

	settings, err := compile(collectorSchemaURL, caps.GetSettingsSchema())
	if err != nil {
		s.schemaErrors = append(s.schemaErrors, "the settings schema "+err.Error())
	}
	s.settings = settings
	for _, produced := range caps.GetProduces() {
		schema, err := compile(typeSchemaPrefix+produced.GetType(), produced.GetSchema())
		if err != nil {
			s.schemaErrors = append(s.schemaErrors, fmt.Sprintf("the schema of type %q %v", produced.GetType(), err))
		}
		s.types[produced.GetType()] = schema
	}
	for _, op := range caps.GetOperations() {
		s.operations[op.GetName()] = op
		if _, err := compile(collectorSchemaURL, op.GetParameterSchema()); err != nil {
			s.schemaErrors = append(s.schemaErrors, fmt.Sprintf("the parameter schema of operation %q %v", op.GetName(), err))
		}
	}
}

// compile compiles a schema of the capabilities, or returns nil for an empty one. A schema stands alone: vexplain
// compiles it too, from the capabilities and without the collector's files, so nothing but the metaschemas is
// loaded. An error says what is wrong, as a continuation of "the schema of …".
func compile(url string, schema []byte) (*jsonschema.Schema, error) {
	if len(schema) == 0 {
		return nil, nil
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(schema))
	if err != nil {
		return nil, fmt.Errorf("is not JSON: %w", err)
	}
	compiler := jsonschema.NewCompiler()
	compiler.UseLoader(jsonschema.SchemeURLLoader{})
	if err := compiler.AddResource(url, doc); err != nil {
		return nil, fmt.Errorf("can't be added to the compiler: %w", err)
	}
	compiled, err := compiler.Compile(url)
	if err != nil {
		return nil, fmt.Errorf("doesn't compile: %w", err)
	}
	return compiled, nil
}

func (s *session) capabilityChecks(r Reporter) {
	r.Helper()
	r.Run("every schema compiles", func(r Reporter) { report(r, s.schemaErrors) })
	r.Run("the collector takes at least one role, spoke or hub", s.rolesAreValid)
	r.Run("every produced type is reverse-DNS and versioned", func(r Reporter) {
		for _, produced := range s.caps.GetProduces() {
			if !typePattern.MatchString(produced.GetType()) {
				r.Errorf("the type %q is not reverse-DNS and versioned, such as com.example.hello.v1alpha1",
					produced.GetType())
			}
		}
	})
	r.Run("every produced type has a scope", func(r Reporter) {
		for _, produced := range s.caps.GetProduces() {
			if scope := produced.GetScope(); scope != collectorv1alpha1.Scope_SCOPE_SPOKE &&
				scope != collectorv1alpha1.Scope_SCOPE_HUB {
				r.Errorf("the type %q has the scope %s, and a scope is SCOPE_SPOKE or SCOPE_HUB", produced.GetType(), scope)
			}
		}
	})
	r.Run("every operation produces only declared types", func(r Reporter) {
		for _, op := range s.caps.GetOperations() {
			for _, produced := range op.GetProduces() {
				if _, declared := s.types[produced]; !declared {
					r.Errorf("operation %q produces %q, which the collector doesn't declare among the types it produces",
						op.GetName(), produced)
				}
			}
		}
	})
}

func (s *session) rolesAreValid(r Reporter) {
	r.Helper()
	if len(s.caps.GetRoles()) == 0 {
		r.Errorf("the collector takes no role: it takes the spoke role, the hub role, or both")
	}
	for _, role := range s.caps.GetRoles() {
		if role != collectorv1alpha1.Role_ROLE_SPOKE && role != collectorv1alpha1.Role_ROLE_HUB {
			r.Errorf("the collector takes the role %s, and a role is ROLE_SPOKE or ROLE_HUB", role)
		}
	}
}

// settingsChecks checks the settings. It reports whether the Target's valid settings are accepted: a collector that
// refuses them can't be watched or invoked with them, and the checks that need them would say nothing new.
func (s *session) settingsChecks(r Reporter) bool {
	r.Helper()
	accepted := false
	r.Run("Settings", func(r Reporter) {
		accepted = r.Run("the settings are accepted", func(r Reporter) {
			if problems := s.settingsProblems(r, s.target.Settings); len(problems) > 0 {
				r.Fatalf("the Target's Settings are refused, and every later check sends them: %s",
					strings.Join(problems, "; "))
			}
		})
		if len(s.target.InvalidSettings) > 0 {
			r.Run("InvalidSettings are refused", func(r Reporter) {
				if problems := s.settingsProblems(r, s.target.InvalidSettings); len(problems) == 0 {
					r.Errorf("the collector accepts the Target's InvalidSettings: its settings schema allows them, " +
						"and ValidateSettings finds no problem with them")
				}
			})
		}
	})
	return accepted
}

// settingsProblems says what is wrong with settings, by the two checks that vexplain makes: their schema, which
// comes from the capabilities, and the collector's own ValidateSettings.
func (s *session) settingsProblems(r Reporter, settings []byte) []string {
	r.Helper()
	var problems []string
	instance := settings
	if len(bytes.TrimSpace(instance)) == 0 {
		instance = []byte("{}")
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(instance))
	switch {
	case err != nil:
		problems = append(problems, "the settings are not JSON")
	case s.settings != nil:
		problems = append(problems, violations(s.settings.Validate(doc))...)
	}
	ctx, cancel := context.WithTimeout(context.Background(), s.lim.call)
	defer cancel()
	resp, err := s.identity.ValidateSettings(ctx, &collectorv1alpha1.ValidateSettingsRequest{Settings: settings},
		callOptions()...)
	if err != nil {
		r.Fatalf("ValidateSettings: %s", describe(err))
	}
	return append(problems, resp.GetProblems()...)
}

// violations lists what a validation against a schema found: one problem for each violation that has no causes of
// its own, such as "at '/greeting': got number, want string".
func violations(err error) []string {
	if err == nil {
		return nil
	}
	var invalid *jsonschema.ValidationError
	if !errors.As(err, &invalid) {
		return []string{err.Error()}
	}
	problems := leaves(*invalid.DetailedOutput(), nil)
	slices.Sort(problems)
	return slices.Compact(problems)
}

// leaves appends the violations of unit that have no causes of their own.
func leaves(unit jsonschema.OutputUnit, problems []string) []string {
	if unit.Error != nil {
		return append(problems, fmt.Sprintf("at '%s': %s", unit.InstanceLocation, unit.Error.String()))
	}
	for _, cause := range unit.Errors {
		problems = leaves(cause, problems)
	}
	return problems
}

// received is an event that came over a stream: converted, or with the reason that it can't be. n counts the
// events of the stream from 1.
type received struct {
	n     int
	event cloudevents.Event
	err   error
}

func convert(n int, p *pb.CloudEvent) received {
	e, err := evidence.FromProto(p)
	return received{n: n, event: e, err: err}
}

func (e received) String() string {
	if e.err != nil {
		return fmt.Sprintf("event %d", e.n)
	}
	return fmt.Sprintf("event %d (type %s, subject %s)", e.n, e.event.Type(), e.event.Subject())
}

// validProblems says which events are not valid evidence.
func validProblems(events []received) []string {
	var problems []string
	for _, e := range events {
		err := e.err
		if err == nil {
			err = evidence.Validate(e.event)
		}
		if err != nil {
			problems = append(problems, fmt.Sprintf("%s is not valid evidence: %v", e, err))
		}
	}
	return problems
}

// declaredProblems says which events are of a type that the collector doesn't declare among the types it produces.
func (s *session) declaredProblems(events []received) []string {
	var problems []string
	for _, e := range events {
		if _, declared := s.types[e.event.Type()]; e.err == nil && !declared {
			problems = append(problems, e.String()+" is of a type that the collector doesn't declare among the types "+
				"it produces")
		}
	}
	return problems
}

// dataProblems says which events have data that breaks the schema of their type. An event of a type without a
// schema, or with one that doesn't compile, can't be checked: a schema that doesn't compile is another check's.
func (s *session) dataProblems(events []received) []string {
	var problems []string
	for _, e := range events {
		if e.err != nil || s.types[e.event.Type()] == nil {
			continue
		}
		data, err := jsonschema.UnmarshalJSON(bytes.NewReader(e.event.Data()))
		if err != nil {
			continue // the data is not JSON, which the check of valid evidence reports
		}
		for _, violation := range violations(s.types[e.event.Type()].Validate(data)) {
			problems = append(problems, fmt.Sprintf("%s: its data breaks the schema of its type: %s", e, violation))
		}
	}
	return problems
}

// eventChecks are the checks of the events that a snapshot delivered.
func (s *session) eventChecks(r Reporter, events []received) {
	r.Helper()
	r.Run("every event is valid evidence", func(r Reporter) { report(r, validProblems(events)) })
	r.Run("every event is of a declared type", func(r Reporter) { report(r, s.declaredProblems(events)) })
	r.Run("every event's data validates against its type's schema", func(r Reporter) {
		report(r, s.dataProblems(events))
	})
}

// protoContext converts the context of a target to the message of the API.
func protoContext(c collector.Context) *collectorv1alpha1.Context {
	return &collectorv1alpha1.Context{
		Cluster:           c.Cluster,
		OperatorNamespace: c.OperatorNamespace,
		OwnPodLabel:       c.OwnPodLabel,
		Scope:             c.Scope,
		OwnerAttribution:  c.OwnerAttribution,
	}
}

// roleName is how a check names a role, such as spoke.
func roleName(role collectorv1alpha1.Role) string {
	return strings.ToLower(strings.TrimPrefix(role.String(), "ROLE_"))
}

// watchRoles returns the roles that the collector takes and that a Watch is for, each once. A role that is neither
// the spoke nor the hub is for the check of the roles to report.
func (s *session) watchRoles() []collectorv1alpha1.Role {
	var roles []collectorv1alpha1.Role
	for _, role := range s.caps.GetRoles() {
		if (role == collectorv1alpha1.Role_ROLE_SPOKE || role == collectorv1alpha1.Role_ROLE_HUB) &&
			!slices.Contains(roles, role) {
			roles = append(roles, role)
		}
	}
	return roles
}

func (s *session) watchChecks(r Reporter) {
	r.Helper()
	for _, role := range s.watchRoles() {
		r.Run(roleName(role), func(r Reporter) { s.watchChecksFor(r, role) })
	}
}

// watchChecksFor checks the Watch of one role.
func (s *session) watchChecksFor(r Reporter, role collectorv1alpha1.Role) {
	r.Helper()
	snap := s.snapshot(role, s.target.Context, s.target.Settings)
	started := r.Run("starts with SnapshotStart", func(r Reporter) {
		if snap.start != "" {
			r.Fatalf("%s", snap.start)
		}
	})
	if started {
		r.Run("holds events only until SnapshotEnd", func(r Reporter) { report(r, snap.order) })
		r.Run("reaches SnapshotEnd in time", func(r Reporter) {
			if snap.end != "" {
				r.Fatalf("%s", snap.end)
			}
		})
	}
	s.eventChecks(r, snap.events)
	if started {
		r.Run("a second Watch starts with a snapshot again", func(r Reporter) { s.secondWatch(r, role) })
	}
}

// snapshot is what a Watch delivered until SnapshotEnd.
type snapshot struct {
	// start says why the stream doesn't start with SnapshotStart. It is empty when the stream does.
	start string
	// end says why the snapshot doesn't reach SnapshotEnd, and is only set for a stream that started well.
	end string
	// order lists what came between SnapshotStart and SnapshotEnd, and was not an event.
	order  []string
	events []received
}

// watchStream is the client side of a Watch.
type watchStream = grpc.ServerStreamingClient[collectorv1alpha1.WatchResponse]

// openWatch opens a Watch for the role, and reads its first item. what names the Watch in the problem that it
// returns, which says why the stream doesn't start with SnapshotStart, and is empty when it does. The time that a
// snapshot has is ctx's deadline.
func (s *session) openWatch(ctx context.Context, what string, role collectorv1alpha1.Role, c collector.Context,
	settings []byte) (watchStream, string) {
	req := &collectorv1alpha1.WatchRequest{Role: role, Settings: settings, Context: protoContext(c)}
	stream, err := s.stream.Watch(ctx, req, callOptions()...)
	if err != nil {
		return nil, fmt.Sprintf("%s failed: %s", what, describe(err))
	}
	item, err := stream.Recv()
	switch {
	case errors.Is(err, io.EOF):
		return nil, what + " ended without an item, and a Watch starts with SnapshotStart"
	case err != nil && ctx.Err() != nil:
		return nil, fmt.Sprintf("%s sent nothing within %s, and a Watch starts with SnapshotStart", what, s.lim.snapshot)
	case err != nil:
		return nil, fmt.Sprintf("%s failed before its first item: %s", what, describe(err))
	case item.GetSnapshotStart() == nil:
		return nil, fmt.Sprintf("%s starts with %s, and a Watch starts with SnapshotStart: every Watch begins with a "+
			"snapshot, so that vexplain can reconnect at any time", what, itemName(item))
	}
	return stream, ""
}

// itemName says what an item of a Watch is.
func itemName(item *collectorv1alpha1.WatchResponse) string {
	switch {
	case item.GetSnapshotStart() != nil:
		return "SnapshotStart"
	case item.GetEvent() != nil:
		return "an event"
	case item.GetTombstone() != nil:
		return "a tombstone"
	case item.GetSnapshotEnd() != nil:
		return "SnapshotEnd"
	case item.GetSourceChanged() != nil:
		return "SourceChanged"
	default:
		return "an item without content"
	}
}

// snapshot opens a Watch and reads it until SnapshotEnd, an error, the end of the stream, or the time that a
// snapshot has. It then ends the Watch.
func (s *session) snapshot(role collectorv1alpha1.Role, c collector.Context, settings []byte) *snapshot {
	ctx, cancel := context.WithTimeout(context.Background(), s.lim.snapshot)
	defer cancel()
	snap := &snapshot{}
	stream, problem := s.openWatch(ctx, "the Watch", role, c, settings)
	if stream == nil {
		snap.start = problem
		return snap
	}
	for {
		item, err := stream.Recv()
		switch {
		case errors.Is(err, io.EOF):
			snap.end = "the stream ended before SnapshotEnd, and a Watch ends only when its context does"
			return snap
		case err != nil && ctx.Err() != nil:
			snap.end = fmt.Sprintf("SnapshotEnd didn't come within %s", s.lim.snapshot)
			return snap
		case err != nil:
			snap.end = "the stream failed before SnapshotEnd: " + describe(err)
			return snap
		}
		switch {
		case item.GetSnapshotEnd() != nil:
			return snap
		case item.GetEvent() != nil:
			snap.events = append(snap.events, convert(len(snap.events)+1, item.GetEvent()))
		case item.GetSnapshotStart() != nil:
			snap.order = append(snap.order, "a second SnapshotStart came before SnapshotEnd, and a stream holds one snapshot")
		default:
			snap.order = append(snap.order, fmt.Sprintf("%s came before SnapshotEnd, and only events come before it",
				itemName(item)))
		}
	}
}

// secondWatch checks that a new Watch starts with a snapshot again, as one does after vexplain reconnects.
func (s *session) secondWatch(r Reporter, role collectorv1alpha1.Role) {
	r.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), s.lim.snapshot)
	defer cancel()
	if _, problem := s.openWatch(ctx, "the second Watch", role, s.target.Context, s.target.Settings); problem != "" {
		r.Fatalf("%s", problem)
	}
}

func (s *session) invokeChecks(r Reporter) {
	r.Helper()
	for _, inv := range s.target.Invocations {
		r.Run(inv.Operation, func(r Reporter) { s.invoke(r, inv) })
	}
}

// answer is what an Invoke returned.
type answer struct {
	events  []received
	failure *collectorv1alpha1.Failure
	// err says why the call ended with an error, and is empty when it didn't.
	err string
}

// invoke calls one operation, and checks the answer.
func (s *session) invoke(r Reporter, inv Invocation) {
	r.Helper()
	op, declared := s.operations[inv.Operation]
	if !declared {
		r.Fatalf("the collector declares no operation %q, and the Target's Invocation calls it", inv.Operation)
	}
	inputs := make([]*pb.CloudEvent, 0, len(inv.Inputs))
	for i, input := range inv.Inputs {
		if err := evidence.Validate(input); err != nil {
			r.Fatalf("input %d of the Invocation is not valid evidence: %v", i, err)
		}
		p, err := evidence.ToProto(input)
		if err != nil {
			r.Fatalf("input %d of the Invocation can't be converted: %v", i, err)
		}
		inputs = append(inputs, p)
	}
	ans := s.call(&collectorv1alpha1.InvokeRequest{
		Operation:  inv.Operation,
		Subject:    inv.Subject,
		Parameters: inv.Parameters,
		Inputs:     inputs,
		Settings:   s.target.Settings,
		Context:    protoContext(s.target.Context),
		Role:       op.GetRole(),
	})

	var problems []string
	if ans.err != "" {
		problems = append(problems, "the call failed: "+ans.err)
	}
	problems = append(problems, validProblems(ans.events)...)
	for _, e := range ans.events {
		if e.err == nil && !slices.Contains(op.GetProduces(), e.event.Type()) {
			problems = append(problems, fmt.Sprintf("%s is of a type that operation %q doesn't produce", e, inv.Operation))
		}
	}
	problems = append(problems, s.dataProblems(ans.events)...)
	if ans.failure != nil && ans.failure.GetReason() == "" {
		problems = append(problems, "the failure has no reason: a failure always has one, such as NotFound")
	}
	report(r, problems)
}

// call runs an Invoke to the end of its answer.
func (s *session) call(req *collectorv1alpha1.InvokeRequest) answer {
	ctx, cancel := context.WithTimeout(context.Background(), s.lim.invoke)
	defer cancel()
	var ans answer
	stream, err := s.stream.Invoke(ctx, req, callOptions()...)
	if err != nil {
		ans.err = describe(err)
		return ans
	}
	for {
		item, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			return ans
		}
		if err != nil {
			ans.err = describe(err)
			return ans
		}
		switch {
		case item.GetEvent() != nil:
			ans.events = append(ans.events, convert(len(ans.events)+1, item.GetEvent()))
		case item.GetFailure() != nil && ans.failure == nil:
			ans.failure = item.GetFailure()
		}
	}
}

// The presence check puts pods in a cluster, which the collector reads, and checks what the collector lists. The
// names that it uses are its own, and not vexplain's. vexplain tells a collector in its context which label marks
// its own pods, and a collector that has the label in its code, and doesn't read it from the context, must fail.
const (
	// ownPodLabel marks the pods that stand in for vexplain's own, such as its scan pods.
	ownPodLabel = "conformance.example/own-pod"
	// runLabel marks the namespaces of one run, which the scope includes. excludedLabel marks one of them that the
	// scope excludes. analyseLabel marks the pods that the scope includes, and skipLabel one of them that it
	// excludes.
	runLabel      = "conformance.example/run"
	excludedLabel = "conformance.example/excluded"
	analyseLabel  = "conformance.example/analyse"
	skipLabel     = "conformance.example/skip"
	// The suite marks the namespaces that it creates, so that anyone can tell what a failed run left behind.
	managedByLabel = "app.kubernetes.io/managed-by"
	managedBy      = "vexplain-conformance"
	// neverScheduler names a scheduler that no cluster runs, so that no pod of the check is placed on a node.
	neverScheduler = "vexplain-conformance-never"
	// The pods of the check run images of this repository, which doesn't exist.
	repository = "artifacts.example/conformance/"
	// marked is the value of the labels that mark a namespace or a pod.
	marked = "true"
	// imageSelected is the image that two pods of the check run: one in scope, and one that is not.
	imageSelected = "selected"
	// retryInterval is how long the presence check waits between two snapshots, when the collector doesn't list
	// a pod yet.
	retryInterval = 250 * time.Millisecond
)

// The namespaces of the check, by what each is for.
const (
	// nsOperator is vexplain's own namespace: in scope, and the only one where the own-pod label counts.
	nsOperator = "operator"
	// nsIn is in scope.
	nsIn = "in"
	// nsExcluded is selected by includeNamespaces, and then excluded by excludeNamespaces.
	nsExcluded = "excluded"
	// nsOutside is not selected by includeNamespaces.
	nsOutside = "outside"
)

var namespaceRoles = []string{nsOperator, nsIn, nsExcluded, nsOutside}

// rule is what a pod of the check tests.
type rule int

const (
	// ruleSelected pods are in scope, and the collector lists them.
	ruleSelected rule = iota
	// ruleLabelled pods carry the own-pod label outside the operator's namespace, where it counts for nothing, and
	// the collector lists them. Otherwise anyone who can create pods could hide a workload from triage by
	// adding the label.
	ruleLabelled
	// ruleScope pods are out of scope, and the collector leaves them out.
	ruleScope
	// ruleOwn pods are vexplain's own, and the collector leaves them out.
	ruleOwn
)

// standIn is a pod that the check creates.
type standIn struct {
	name, namespace string
	labels          map[string]string
	// image names the image that the pod runs. Pods of one image run one digest.
	image string
	rule  rule
	// why says what decides whether the collector lists the pod, for the message of a failure.
	why string
}

// standIns are the pods of the check. Each runs an image of its own, so that a snapshot says which pods the
// collector lists, except for shared, which runs the image of selected: the collector must leave it out of the
// workloads of that image, too.
var standIns = []standIn{
	{
		name: "selected", namespace: nsIn, image: imageSelected, rule: ruleSelected,
		labels: map[string]string{analyseLabel: marked},
		why:    "its namespace and its labels pass the scope",
	},
	{
		name: "shared", namespace: nsOutside, image: imageSelected, rule: ruleScope,
		labels: map[string]string{analyseLabel: marked},
		why:    "its namespace isn't selected by includeNamespaces, though a pod in scope runs its image",
	},
	{
		name: "labelled", namespace: nsIn, image: "labelled", rule: ruleLabelled,
		labels: map[string]string{analyseLabel: marked, ownPodLabel: "conformance"},
		why:    "the own-pod label counts only in the operator's namespace, and this pod is in another",
	},
	{
		name: "own", namespace: nsOperator, image: "own", rule: ruleOwn,
		labels: map[string]string{analyseLabel: marked, ownPodLabel: "conformance"},
		why:    "it carries the own-pod label in the operator's namespace",
	},
	{
		name: "other-namespace", namespace: nsOutside, image: "other-namespace", rule: ruleScope,
		labels: map[string]string{analyseLabel: marked},
		why:    "its namespace isn't selected by includeNamespaces",
	},
	{
		name: "excluded-namespace", namespace: nsExcluded, image: "excluded-namespace", rule: ruleScope,
		labels: map[string]string{analyseLabel: marked},
		why:    "its namespace is excluded by excludeNamespaces, which wins over includeNamespaces",
	},
	{
		name: "not-included", namespace: nsIn, image: "not-included", rule: ruleScope,
		why: "includePods doesn't select it",
	},
	{
		name: "excluded-pod", namespace: nsIn, image: "excluded-pod", rule: ruleScope,
		labels: map[string]string{analyseLabel: marked, skipLabel: marked},
		why:    "excludePods excludes it, which wins over includePods",
	},
}

// scene is what the presence check puts in the cluster, under a token that is unique to one run.
type scene struct {
	api   client.Client
	token string
}

func newScene(api client.Client) *scene { return &scene{api: api, token: rand.String(6)} }

// namespace returns the name of the namespace for a role.
func (sc *scene) namespace(role string) string {
	return "vexplain-conformance-" + sc.token + "-" + role
}

// digest returns the digest that the pods of an image run.
func (sc *scene) digest(image string) string {
	sum := sha256.Sum256([]byte(sc.token + "/" + image))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// context returns the context for the presence check: the Target's, with the operator namespace, the own-pod label
// and the scope that the check makes its own.
func (sc *scene) context(base collector.Context) collector.Context {
	base.OperatorNamespace = sc.namespace(nsOperator)
	base.OwnPodLabel = ownPodLabel
	base.Scope = sc.scope()
	return base
}

// scope is OperatorConfig.spec.scope for the check, as JSON: it includes the namespaces of this run and the pods
// that are marked, and excludes a namespace and a pod by label. It is written by hand, because the SDK can't
// import the operator's API.
func (sc *scene) scope() json.RawMessage {
	return json.RawMessage(fmt.Sprintf(`{
  "includeNamespaces": {"matchLabels": {%q: %q}},
  "excludeNamespaces": {"matchExpressions": [{"key": %q, "operator": "In", "values": [%q]}]},
  "includePods": {"matchLabels": {%q: %q}},
  "excludePods": {"matchExpressions": [{"key": %q, "operator": "Exists"}]}
}`, runLabel, sc.token, excludedLabel, marked, analyseLabel, marked, skipLabel))
}

// create makes the namespaces and the pods, and sets what a kubelet would report: the image of each pod's
// container, through the status subresource.
func (sc *scene) create(ctx context.Context) error {
	for _, role := range namespaceRoles {
		labels := map[string]string{managedByLabel: managedBy}
		if role != nsOutside {
			labels[runLabel] = sc.token
		}
		if role == nsExcluded {
			labels[excludedLabel] = marked
		}
		namespace := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: sc.namespace(role), Labels: labels}}
		if err := sc.api.Create(ctx, namespace); err != nil {
			return fmt.Errorf("creating namespace %s: %w", namespace.Name, err)
		}
	}
	for _, in := range standIns {
		pod := &corev1.Pod{
			// The labels are a copy: the client decodes the answer of the API server into the pod.
			ObjectMeta: metav1.ObjectMeta{Name: in.name, Namespace: sc.namespace(in.namespace), Labels: maps.Clone(in.labels)},
			Spec: corev1.PodSpec{
				SchedulerName: neverScheduler,
				Containers:    []corev1.Container{{Name: "app", Image: repository + in.image + ":latest"}},
			},
		}
		if err := sc.api.Create(ctx, pod); err != nil {
			return fmt.Errorf("creating pod %s/%s: %w", pod.Namespace, pod.Name, err)
		}
		pod.Status.ContainerStatuses = []corev1.ContainerStatus{{
			Name:    "app",
			Image:   repository + in.image + ":latest",
			ImageID: repository + in.image + "@" + sc.digest(in.image),
		}}
		if err := sc.api.Status().Update(ctx, pod); err != nil {
			return fmt.Errorf("setting the image ID of pod %s/%s: %w", pod.Namespace, pod.Name, err)
		}
	}
	return nil
}

// cleanup deletes the namespaces, and with them everything in them.
func (sc *scene) cleanup(ctx context.Context) error {
	var failed []error
	for _, role := range namespaceRoles {
		namespace := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: sc.namespace(role)}}
		if err := sc.api.Delete(ctx, namespace); err != nil && !apierrors.IsNotFound(err) {
			failed = append(failed, err)
		}
	}
	return errors.Join(failed...)
}

// listing is what the events of a snapshot say about pods.
type listing struct {
	// images are the digests that an event is about.
	images map[string]bool
	// pods are the pods that an event lists, as workloads or as the pods of a workload.
	pods map[podRef]bool
}

type podRef struct{ namespace, name string }

// listingOf reads the presence events of a snapshot.
func listingOf(events []received) listing {
	found := listing{images: make(map[string]bool), pods: make(map[podRef]bool)}
	for _, e := range events {
		if e.err != nil || e.event.Type() != evidence.TypePresence {
			continue
		}
		about, err := subjects.Parse(e.event.Subject())
		if err != nil || about.Kind != subjects.KindImage {
			continue
		}
		found.images[about.Digest] = true
		var data evidence.Presence
		if json.Unmarshal(e.event.Data(), &data) != nil {
			continue
		}
		for _, workload := range data.Workloads {
			found.pods[podRef{workload.Namespace, workload.Name}] = true
			for _, pod := range workload.Pods {
				found.pods[podRef{workload.Namespace, pod.Name}] = true
			}
		}
	}
	return found
}

// of returns the pods of the check that test one of the rules.
func (sc *scene) of(rules ...rule) []standIn {
	var pods []standIn
	for _, in := range standIns {
		if slices.Contains(rules, in.rule) {
			pods = append(pods, in)
		}
	}
	return pods
}

// missing lists the pods that must be listed, according to the rules, and whose image no event is about.
func (sc *scene) missing(found listing, rules ...rule) []string {
	var problems []string
	for _, in := range sc.of(rules...) {
		if !found.images[sc.digest(in.image)] {
			problems = append(problems, fmt.Sprintf("no event is about the image of pod %s/%s, which the collector must "+
				"list: %s", sc.namespace(in.namespace), in.name, in.why))
		}
	}
	return problems
}

// leaks lists the pods that must be left out, according to the rules, and that an event lists, or whose image an
// event is about, when no pod that must be listed runs it.
func (sc *scene) leaks(found listing, rules ...rule) []string {
	var problems []string
	for _, in := range sc.of(rules...) {
		ref := podRef{sc.namespace(in.namespace), in.name}
		if found.pods[ref] {
			problems = append(problems, fmt.Sprintf("an event lists pod %s/%s, which the collector must leave out: %s",
				ref.namespace, ref.name, in.why))
		}
		if found.images[sc.digest(in.image)] && len(sc.runningImage(in.image, ruleSelected, ruleLabelled)) == 0 {
			problems = append(problems, fmt.Sprintf("an event is about the image of pod %s/%s, which only pods that the "+
				"collector must leave out run: %s", ref.namespace, ref.name, in.why))
		}
	}
	return problems
}

// runningImage returns the pods of the check that run an image, and test one of the rules.
func (sc *scene) runningImage(image string, rules ...rule) []standIn {
	return slices.DeleteFunc(sc.of(rules...), func(in standIn) bool { return in.image != image })
}

// presenceChecks checks a collector of the presence type: it applies the scope, and counts the label of vexplain's
// own pods only in vexplain's namespace, as its context says. It creates pods that the collector reads, and
// checks the snapshot that the collector then delivers.
func (s *session) presenceChecks(r Reporter) {
	r.Helper()
	var (
		sc     *scene
		events []received
		found  listing
	)
	defer func() {
		if sc == nil {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), s.lim.call)
		defer cancel()
		if err := sc.cleanup(ctx); err != nil {
			r.Errorf("deleting the namespaces that the check created: %v", err)
		}
	}()
	prepared := r.Run("prepares the cluster and takes a snapshot", func(r Reporter) {
		s.presencePrerequisites(r)
		sc = newScene(s.target.Client)
		ctx, cancel := context.WithTimeout(context.Background(), s.lim.call)
		defer cancel()
		if err := sc.create(ctx); err != nil {
			r.Fatalf("%v", err)
		}
		events, found = s.presenceSnapshot(r, sc)
	})
	if !prepared {
		return
	}
	r.Run("lists the pods that the scope selects", func(r Reporter) { report(r, sc.missing(found, ruleSelected)) })
	r.Run("leaves out the pods that the scope excludes", func(r Reporter) { report(r, sc.leaks(found, ruleScope)) })
	r.Run("leaves out vexplain's own pods", func(r Reporter) { report(r, sc.leaks(found, ruleOwn)) })
	r.Run("counts the own-pod label only in the operator's namespace", func(r Reporter) {
		report(r, sc.missing(found, ruleLabelled))
	})
	s.eventChecks(r, events)
}

// presencePrerequisites ends the check when it can't run: it needs a client of the cluster that the collector
// reads, and a collector that delivers presence from a Watch of the spoke role, where the pods are.
func (s *session) presencePrerequisites(r Reporter) {
	r.Helper()
	switch {
	case s.target.Client == nil:
		r.Fatalf("a collector that produces %s is checked against a cluster, and its conformance needs a Kubernetes "+
			"client: set Target.Client to a client of the cluster that the collector reads", evidence.TypePresence)
	case !s.caps.GetWatches():
		r.Fatalf("a collector that produces %s delivers it from Watch, and this one says that it doesn't watch",
			evidence.TypePresence)
	case !slices.Contains(s.caps.GetRoles(), collectorv1alpha1.Role_ROLE_SPOKE):
		r.Fatalf("a collector that produces %s takes the spoke role, where the pods are, and this one doesn't",
			evidence.TypePresence)
	}
}

// presenceSnapshot takes a snapshot of the spoke's Watch, with the context of the check. A collector that reads
// through a cache may not list a pod that was created just now, so it takes another snapshot until the pods that
// must be listed are, or the time is up. A pod that must be left out and is listed is never waited for.
func (s *session) presenceSnapshot(r Reporter, sc *scene) ([]received, listing) {
	r.Helper()
	deadline := time.Now().Add(s.lim.presence)
	c := sc.context(s.target.Context)
	for {
		snap := s.snapshot(collectorv1alpha1.Role_ROLE_SPOKE, c, s.target.Settings)
		if snap.start != "" {
			r.Fatalf("%s", snap.start)
		}
		if snap.end != "" {
			r.Fatalf("%s", snap.end)
		}
		found := listingOf(snap.events)
		waiting := len(sc.missing(found, ruleSelected, ruleLabelled)) > 0 &&
			len(sc.leaks(found, ruleScope, ruleOwn)) == 0 && time.Now().Before(deadline)
		if !waiting {
			return snap.events, found
		}
		time.Sleep(retryInterval)
	}
}
