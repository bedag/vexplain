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
	"context"
	cryptorand "crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode"

	"github.com/cloudevents/sdk-go/binding/format/protobuf/v2/pb"
	cloudevents "github.com/cloudevents/sdk-go/v2"
	"github.com/go-logr/logr/testr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/rand"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
	inventoryv1alpha1 "github.com/bedag/vexplain/api/inventory/v1alpha1"
	"github.com/bedag/vexplain/internal/collector/certs"
	"github.com/bedag/vexplain/internal/collectorclient"
	internalevidence "github.com/bedag/vexplain/internal/evidence"
	"github.com/bedag/vexplain/internal/inventory"
	"github.com/bedag/vexplain/internal/spoke"
	"github.com/bedag/vexplain/internal/tasks"
	collectorv1alpha1 "github.com/bedag/vexplain/sdk/api/collector/v1alpha1"
	"github.com/bedag/vexplain/sdk/collector"
	"github.com/bedag/vexplain/sdk/evidence"
	"github.com/bedag/vexplain/sdk/subject"
	"github.com/bedag/vexplain/sdk/workloads"
)

// These tests run the spoke's executor against an API server of envtest, with the evidence and inventory stores on
// it, and with a scanner that the SDK serves in the test's process over mutual TLS, as the deployer's Deployment
// would. The scanner of the tests declares what the scanner collector declares, and answers each scan as a test says.
// Nothing else of the operator runs: each test records the status of its Collector as the deployer would.

const (
	// scannerType is the type of the scanner's evidence, and scanOperation its operation.
	scannerType   = "ch.bedag.vexplain.scanner.image-contents.v1alpha1"
	scanOperation = "scan"
	// otherType is a type that a collector of the tests produces besides, and versionOf the version of the scanners.
	otherType = "com.example.other.v1alpha1"
	scanned   = "0.2.0"
	// The platform manifests of the images of the tests.
	amd64Manifest = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	arm64Manifest = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
)

// fakeScanner is the scanner of a test: it declares the scanner collector's capabilities, with its operation scan,
// which produces the scanner's type and the extra types, and answers each scan through answer. Each scan waits for
// hold, when it is set.
type fakeScanner struct {
	extra  []string
	answer func(req collector.InvokeRequest) ([]cloudevents.Event, *collector.Failure, error)
	hold   chan struct{}

	mu      sync.Mutex
	calls   []collector.InvokeRequest
	started chan collector.InvokeRequest
}

func newFakeScanner(answer func(req collector.InvokeRequest) ([]cloudevents.Event, *collector.Failure, error),
	extra ...string) *fakeScanner {
	return &fakeScanner{extra: extra, answer: answer, started: make(chan collector.InvokeRequest, 64)}
}

func (s *fakeScanner) Info() collector.Info {
	return collector.Info{Name: "scanner", Version: scanned}
}

func (s *fakeScanner) Capabilities() collector.Capabilities {
	produces := make([]collector.EvidenceType, 0, 1+len(s.extra))
	produces = append(produces, collector.EvidenceType{Type: scannerType, Scope: collector.ScopeHub,
		Schema: []byte(`{"type": "object"}`)})
	for _, t := range s.extra {
		produces = append(produces, collector.EvidenceType{Type: t, Scope: collector.ScopeHub, Schema: []byte(`{}`)})
	}
	return collector.Capabilities{
		Roles:    []collector.Role{collector.RoleSpoke},
		Produces: produces,
		Operations: []collector.Operation{{
			Name: scanOperation, Role: collector.RoleSpoke, Produces: append([]string{scannerType}, s.extra...),
			ParameterSchema: []byte(`{"type": "object", "additionalProperties": false, "required": ["repositories"],
				"properties": {"repositories": {"type": "array", "items": {"type": "string"}},
					"pods": {"type": "array", "items": {"type": "object", "additionalProperties": false,
						"required": ["namespace", "name"],
						"properties": {"namespace": {"type": "string"}, "name": {"type": "string"}}}}}}`),
		}},
	}
}

func (s *fakeScanner) Invoke(ctx context.Context, req collector.InvokeRequest) ([]cloudevents.Event, *collector.Failure,
	error) {
	s.mu.Lock()
	s.calls = append(s.calls, req)
	s.mu.Unlock()
	s.started <- req
	if s.hold != nil {
		select {
		case <-s.hold:
		case <-ctx.Done():
			return nil, nil, ctx.Err()
		}
	}
	return s.answer(req)
}

// invoked returns the scans that the scanner was asked for, in order.
func (s *fakeScanner) invoked() []collector.InvokeRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.calls)
}

// manifestEvent returns the scanner's evidence about the manifest of the platform, with the coverage.
func manifestEvent(t *testing.T, cluster, platform, manifest string, coverage int32) cloudevents.Event {
	t.Helper()
	e, err := evidence.New(scannerType, subject.Manifest(manifest),
		map[string]any{"platform": platform, "digest": manifest, "sbom": map[string]any{"artifacts": []any{}}},
		evidence.WithPlatform(platform), evidence.WithCoverage(coverage),
		evidence.WithTime(time.Date(2026, time.October, 31, 9, 30, 0, 0, time.UTC)),
		evidence.WithSource("/clusters/"+cluster+"/collectors/scanner"))
	require.NoError(t, err)
	return e
}

// scansIndex answers each scan with the evidence of the index's two manifests.
func scansIndex(t *testing.T) func(collector.InvokeRequest) ([]cloudevents.Event, *collector.Failure, error) {
	return func(req collector.InvokeRequest) ([]cloudevents.Event, *collector.Failure, error) {
		return []cloudevents.Event{
			manifestEvent(t, req.Context.Cluster, linuxAMD64, amd64Manifest, 75),
			manifestEvent(t, req.Context.Cluster, "linux/arm64/v8", arm64Manifest, 100),
		}, nil, nil
	}
}

// failsWith answers each scan with the failure.
func failsWith(failure collector.Failure) func(collector.InvokeRequest) ([]cloudevents.Event, *collector.Failure, error) {
	return func(collector.InvokeRequest) ([]cloudevents.Event, *collector.Failure, error) {
		return nil, &failure, nil
	}
}

// executorEnv is what a test of the executor runs against: the stores, the spoke's presence of a cluster of its own,
// an authority of the operator's and a pool that reaches the scanners that the test serves, and the executor, which
// runs until the test ends.
type executorEnv struct {
	t         *testing.T
	api       client.Client
	cluster   cluster
	store     inventory.Store
	evidence  internalevidence.Store
	presence  *spoke.Presence
	authority *certs.Authority
	pool      *collectorclient.Pool
	executor  *spoke.Executor

	mu     sync.Mutex
	routes map[string]string
}

func newExecutorEnv(t *testing.T) *executorEnv {
	t.Helper()
	return newExecutorEnvWith(t, interceptor.Funcs{})
}

// newExecutorEnvWith returns the environment of a test whose stores write through a client that acts with funcs,
// which can have the API server refuse a write.
func newExecutorEnvWith(t *testing.T, funcs interceptor.Funcs) *executorEnv {
	t.Helper()
	cfg, direct := startAPI(t)
	e := &executorEnv{t: t, api: direct, cluster: newCluster(), routes: map[string]string{}}
	watching, err := client.NewWithWatch(cfg, client.Options{Scheme: scheme})
	require.NoError(t, err)
	stores := interceptor.NewClient(watching, funcs)
	clusterName := func() string { return e.cluster.name }
	e.store = inventory.NewCRDStore(stores, nil, clusterName)
	e.evidence = internalevidence.NewCRDStore(stores, nil, clusterName)
	e.presence = spoke.NewPresence(e.store, func(context.Context) (string, string, error) {
		return e.cluster.name, e.cluster.id, nil
	})
	e.authority = certs.NewAuthority(direct, direct, operatorNamespace, time.Now)
	require.NoError(t, e.authority.EnsureCA(t.Context()))
	e.pool = collectorclient.NewPool(e.authority.ClientTLS, operatorNamespace)
	e.pool.Dialer = e.dial
	e.executor = spoke.NewExecutor(e.pool, direct, e.presence, e.evidence, internalevidence.NewFactsWriter(e.store))
	ctx, cancel := context.WithCancel(logf.IntoContext(context.Background(), testr.New(t)))
	done := make(chan error, 1)
	go func() { done <- e.executor.Start(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			assert.NoError(t, err, "Start returns nil once its context ends")
		case <-time.After(wait):
			assert.Fail(t, "the executor didn't stop")
		}
		e.mu.Lock()
		defer e.mu.Unlock()
		for name := range e.routes {
			e.pool.Forget(name)
		}
	})
	return e
}

// dial reaches the scanner that the test serves at the address of its Service.
func (e *executorEnv) dial(ctx context.Context, address string) (net.Conn, error) {
	e.mu.Lock()
	target := ""
	for name, listen := range e.routes {
		if address == net.JoinHostPort(certs.ServerName(name, operatorNamespace), "9443") {
			target = listen
		}
	}
	e.mu.Unlock()
	if target == "" {
		return nil, fmt.Errorf("the test serves no collector at %s", address)
	}
	var dialer net.Dialer
	return dialer.DialContext(ctx, "tcp", target)
}

// serve serves s under a new name, with the certificates that the authority issues for it, until the test ends, and
// creates its Collector with the settings and the status that the deployer records for it: its capabilities, as
// change makes them, its version, and ready. It returns the Collector's name.
func (e *executorEnv) serve(s *fakeScanner, settings string, ready metav1.Condition,
	change func(*configv1alpha1.CollectorCapabilities)) string {
	e.t.Helper()
	name := "scanner-" + rand.String(6)
	dir := e.tlsFiles(name)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(e.t, err)
	health, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(e.t, err)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- collector.Serve(ctx, s, collector.Options{TLSDir: dir, GRPCListener: listener, HealthListener: health})
	}()
	e.t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			assert.NoError(e.t, err)
		case <-time.After(wait):
			assert.Fail(e.t, "the scanner didn't stop")
		}
	})
	e.route(name, listener.Addr().String())
	e.record(name, settings, ready, change)
	return name
}

// tlsFiles writes the files of the TLS Secret that the authority issues for the collector of the name into a
// directory of their own, as its Deployment mounts them, and returns the directory.
func (e *executorEnv) tlsFiles(name string) string {
	e.t.Helper()
	_, err := e.authority.EnsureServer(e.t.Context(), name)
	require.NoError(e.t, err)
	secret := &corev1.Secret{}
	require.NoError(e.t, e.api.Get(e.t.Context(),
		client.ObjectKey{Namespace: operatorNamespace, Name: certs.SecretName(name)}, secret))
	e.t.Cleanup(func() { assert.NoError(e.t, client.IgnoreNotFound(e.api.Delete(context.Background(), secret))) })
	dir := e.t.TempDir()
	for _, file := range []string{corev1.TLSCertKey, corev1.TLSPrivateKeyKey, "ca.crt"} {
		require.NoError(e.t, os.WriteFile(filepath.Join(dir, file), secret.Data[file], 0o600))
	}
	return dir
}

// route makes the pool reach the collector of the name at listen.
func (e *executorEnv) route(name, listen string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.routes[name] = listen
}

// record creates the Collector of the name with the settings, and the status that the deployer records for a scanner:
// its capabilities, as change makes them, its version, and ready. It deletes the Collector when the test ends.
func (e *executorEnv) record(name, settings string, ready metav1.Condition,
	change func(*configv1alpha1.CollectorCapabilities)) {
	e.t.Helper()
	c := &configv1alpha1.Collector{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec:       configv1alpha1.CollectorSpec{Package: "artifacts.example/vexplain/scanner:" + scanned},
	}
	if settings != "" {
		c.Spec.Settings = &runtime.RawExtension{Raw: []byte(settings)}
	}
	require.NoError(e.t, e.api.Create(e.t.Context(), c))
	e.t.Cleanup(func() { assert.NoError(e.t, client.IgnoreNotFound(e.api.Delete(context.Background(), c))) })
	c.Status.Capabilities = &configv1alpha1.CollectorCapabilities{
		Roles:      []configv1alpha1.CollectorRole{configv1alpha1.CollectorRoleSpoke},
		Produces:   []configv1alpha1.ProducedType{{Type: scannerType, Scope: configv1alpha1.EvidenceScopeHub}},
		Watch:      configv1alpha1.CollectorWatchNotSupported,
		Operations: []configv1alpha1.CollectorOperation{{Name: scanOperation, Produces: []string{scannerType}}},
	}
	if change != nil {
		change(c.Status.Capabilities)
	}
	c.Status.Version = ptr.To(scanned)
	ready.ObservedGeneration = c.Generation
	meta.SetStatusCondition(&c.Status.Conditions, ready)
	require.NoError(e.t, e.api.Status().Update(e.t.Context(), c))
}

// rawScanner is a scanner that isn't built with the SDK: its Invoke sends the items of answer as they are, without
// the SDK's checks.
type rawScanner struct {
	collectorv1alpha1.UnimplementedEvidenceServer
	answer []*collectorv1alpha1.InvokeResponse
}

func (r *rawScanner) Invoke(_ *collectorv1alpha1.InvokeRequest,
	stream grpc.ServerStreamingServer[collectorv1alpha1.InvokeResponse]) error {
	for _, item := range r.answer {
		if err := stream.Send(item); err != nil {
			return err
		}
	}
	return nil
}

// serveRaw serves r under a new name, over mutual TLS with the certificates that the authority issues for it, as the
// SDK would have, until the test ends, and creates its Collector as serve does. It returns the Collector's name.
func (e *executorEnv) serveRaw(r *rawScanner) string {
	e.t.Helper()
	name := "scanner-" + rand.String(6)
	dir := e.tlsFiles(name)
	pair, err := tls.LoadX509KeyPair(filepath.Join(dir, corev1.TLSCertKey), filepath.Join(dir, corev1.TLSPrivateKeyKey))
	require.NoError(e.t, err)
	caPEM, err := os.ReadFile(filepath.Join(dir, "ca.crt"))
	require.NoError(e.t, err)
	clients := x509.NewCertPool()
	require.True(e.t, clients.AppendCertsFromPEM(caPEM))
	server := grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{
		MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{pair},
		ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: clients,
	})))
	collectorv1alpha1.RegisterEvidenceServer(server, r)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(e.t, err)
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = server.Serve(listener)
	}()
	e.t.Cleanup(func() {
		server.Stop()
		<-done
	})
	e.route(name, listener.Addr().String())
	e.record(name, "", healthy, nil)
	return name
}

// noData is Ready until the first health check, healthy after a check that passed, and failing after one that
// didn't.
var (
	noData = metav1.Condition{Type: configv1alpha1.ConditionReady, Status: metav1.ConditionUnknown,
		Reason: configv1alpha1.ReasonNoData, Message: "The collector has not been checked yet."}
	healthy = metav1.Condition{Type: configv1alpha1.ConditionReady, Status: metav1.ConditionTrue,
		Reason: configv1alpha1.ReasonHealthy, Message: "The collector answers its health check."}
	failing = metav1.Condition{Type: configv1alpha1.ConditionReady, Status: metav1.ConditionFalse,
		Reason: configv1alpha1.ReasonCollectorFailing, Message: "The collector can't be reached."}
)

// runs makes the image of digest run in the cluster: its ImageInventory has this cluster's entry, and the spoke's
// presence holds the workloads, as a presence collector delivered them, besides the images that run already.
func (e *executorEnv) runs(digest string, running ...evidence.PresenceWorkload) {
	e.t.Helper()
	require.NoError(e.t, e.store.Observe(e.t.Context(), digest, inventory.Observation{
		Cluster: e.cluster.name, ClusterID: e.cluster.id, DigestKind: inventoryv1alpha1.DigestKindRepoDigest,
		Repositories: []string{repository}, NamespaceCount: 1,
	}))
	e.presence.Upsert("workloads", presenceEvent(e.t, digest, running...))
}

// request asks the executor for the scanner's evidence about the image of digest, as the hub does.
func (e *executorEnv) request(digest string) {
	e.t.Helper()
	require.NoError(e.t, e.executor.Request(e.t.Context(), tasks.Request{
		Type: scannerType, Subject: subject.Image(digest), Repositories: []string{repository},
	}))
}

// factsOf reads the facts of digest.
func (e *executorEnv) factsOf(digest string) *inventoryv1alpha1.ImageFacts {
	e.t.Helper()
	facts, err := e.factsNow(digest)
	require.NoError(e.t, err)
	return facts
}

// factsNow reads the facts of digest, for a condition that a check polls: it may run after the test has ended, so it
// reads with a context of its own, and returns what fails.
func (e *executorEnv) factsNow(digest string) (*inventoryv1alpha1.ImageFacts, error) {
	obj, err := e.store.Get(context.Background(), digest)
	if err != nil || obj == nil {
		return nil, fmt.Errorf("read the ImageInventory of %s: %v", digest, err)
	}
	return obj.Status.Facts, nil
}

// failureOf waits until the facts of digest hold a failure of the collector that has counted attempts, and returns
// it.
func (e *executorEnv) failureOf(digest, name string, attempts int32) inventoryv1alpha1.ScanFailure {
	e.t.Helper()
	var found inventoryv1alpha1.ScanFailure
	require.EventuallyWithT(e.t, func(c *assert.CollectT) {
		facts, err := e.factsNow(digest)
		if !assert.NoError(c, err) || !assert.NotNil(c, facts) {
			return
		}
		i := slices.IndexFunc(facts.Failures, func(f inventoryv1alpha1.ScanFailure) bool { return f.Source == name })
		if assert.GreaterOrEqual(c, i, 0) {
			found = facts.Failures[i]
			assert.Equal(c, attempts, found.Attempts)
		}
	}, wait, tick)
	return found
}

// recordOf reads the collector's record of the scanner's evidence about the manifest, or nil.
func (e *executorEnv) recordOf(name, manifest string) *internalevidence.Record {
	e.t.Helper()
	record, err := e.recordNow(name, manifest)
	require.NoError(e.t, err)
	return record
}

// recordNow reads the collector's record of the scanner's evidence about the manifest, or nil, for a condition that a
// check polls, as factsNow does.
func (e *executorEnv) recordNow(name, manifest string) (*internalevidence.Record, error) {
	return e.evidence.Get(context.Background(),
		internalevidence.Key{Subject: subject.Manifest(manifest), Type: scannerType, Source: name})
}

// nothingWritten reports whether nothing of the collector is written about the image of digest: no record about the
// manifest, and no manifest, evidence or failure in the facts. A read that fails counts as something written.
func (e *executorEnv) nothingWritten(name, digest, manifest string) bool {
	record, err := e.recordNow(name, manifest)
	if err != nil || record != nil {
		return false
	}
	facts, err := e.factsNow(digest)
	if err != nil {
		return false
	}
	return facts == nil || (len(facts.Manifests) == 0 && len(facts.Evidence) == 0 && len(facts.Failures) == 0)
}

// readyOf reads the Ready condition of the Collector.
func (e *executorEnv) readyOf(name string) *metav1.Condition {
	e.t.Helper()
	var c configv1alpha1.Collector
	require.NoError(e.t, e.api.Get(e.t.Context(), client.ObjectKey{Name: name}, &c))
	return meta.FindStatusCondition(c.Status.Conditions, configv1alpha1.ConditionReady)
}

// started waits for the next scan that the scanner starts.
func started(t *testing.T, s *fakeScanner) collector.InvokeRequest {
	t.Helper()
	select {
	case req := <-s.started:
		return req
	case <-time.After(wait):
		require.FailNow(t, "the scanner is asked to scan")
		return collector.InvokeRequest{}
	}
}

// startsNoScan checks that the scanner is asked for no scan for a while.
func startsNoScan(t *testing.T, s *fakeScanner) {
	t.Helper()
	select {
	case req := <-s.started:
		require.FailNow(t, "the scanner is asked to scan", "%s", req.Subject)
	case <-time.After(quiet):
	}
}

func TestARequestStoresTheEventsAtTheCollectorsVersionAndWritesTheFacts(t *testing.T) {
	e := newExecutorEnv(t)
	scanner := newFakeScanner(scansIndex(t))
	name := e.serve(scanner, `{"maxConcurrentScans": 3}`, healthy, nil)
	digest := newDigest(t)
	e.runs(digest, running("team-a", "web", linuxAMD64, linuxARM64))

	e.request(digest)

	t.Log("invoking the collector's operation for the image, with the pods that run it and the collector's settings")
	req := started(t, scanner)
	require.Equal(t, scanOperation, req.Operation)
	require.Equal(t, subject.Image(digest), req.Subject)
	require.Equal(t, collector.RoleSpoke, req.Role)
	require.JSONEq(t, `{"repositories": ["`+repository+`"],
		"pods": [{"namespace": "team-a", "name": "web-0"}, {"namespace": "team-a", "name": "web-1"}]}`,
		string(req.Parameters))
	require.JSONEq(t, `{"maxConcurrentScans": 3}`, string(req.Settings))
	require.Equal(t, operatorNamespace, req.Context.OperatorNamespace)
	require.Equal(t, workloads.TaskLabel, req.Context.OwnPodLabel)

	t.Log("storing each event at the Collector's version, and recording the facts")
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		facts, err := e.factsNow(digest)
		if assert.NoError(c, err) && assert.NotNil(c, facts) {
			assert.Equal(c, []inventoryv1alpha1.ManifestFact{
				{Platform: linuxAMD64, Digest: amd64Manifest}, {Platform: "linux/arm64/v8", Digest: arm64Manifest},
			}, facts.Manifests)
		}
	}, wait, tick)
	facts := e.factsOf(digest)
	require.Len(t, facts.Evidence, 1)
	require.Equal(t, name, facts.Evidence[0].Source)
	require.Equal(t, scannerType, facts.Evidence[0].Type)
	require.Equal(t, scanned, facts.Evidence[0].CollectorVersion)
	require.Equal(t, ptr.To(int32(75)), facts.Evidence[0].Coverage, "the lowest coverage of the type's events")
	require.Empty(t, facts.Failures)
	for _, manifest := range []string{amd64Manifest, arm64Manifest} {
		record := e.recordOf(name, manifest)
		require.NotNil(t, record)
		require.Equal(t, scanned, record.CollectorVersion)
	}
}

// A failure is about one subject: it counts an attempt of the collector in the facts of the image, and never says
// anything about the collector's health, which the deployer's health check alone decides.
func TestAFailureAddsAnAttemptAndLeavesTheCollectorsReadyAsItWas(t *testing.T) {
	e := newExecutorEnv(t)
	scanner := newFakeScanner(failsWith(collector.Failure{Reason: "Unauthorized", Message: "the registry refused the pull"}))
	name := e.serve(scanner, "", healthy, nil)
	before := e.readyOf(name)
	digest := newDigest(t)
	e.runs(digest, running("team-a", "web", linuxAMD64))

	e.request(digest)
	failure := e.failureOf(digest, name, 1)
	// A request that comes while the first runs changes nothing, so the hub's next request waits until it has ended.
	require.Eventually(t, func() bool {
		e.request(digest)
		return len(scanner.invoked()) >= 2
	}, wait, tick)
	e.failureOf(digest, name, 2)

	require.Equal(t, inventoryv1alpha1.ScanFailureReason("Unauthorized"), failure.Reason)
	require.Equal(t, ptr.To("the registry refused the pull"), failure.Message)
	require.Equal(t, before, e.readyOf(name))
	require.Nil(t, e.recordOf(name, amd64Manifest))
}

// A collector is used while its Ready condition isn't False: Unknown with NoData, before its first health check,
// gets requests, and False with CollectorFailing gets none.
func TestACollectorWithReadyUnknownIsInvokedAndAFailingOneIsNot(t *testing.T) {
	e := newExecutorEnv(t)
	unchecked := newFakeScanner(scansIndex(t))
	broken := newFakeScanner(scansIndex(t))
	uncheckedName := e.serve(unchecked, "", noData, nil)
	e.serve(broken, "", failing, nil)
	digest := newDigest(t)
	e.runs(digest, running("team-a", "web", linuxAMD64))

	e.request(digest)

	started(t, unchecked)
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		record, err := e.recordNow(uncheckedName, amd64Manifest)
		assert.NoError(c, err)
		assert.NotNil(c, record)
	}, wait, tick)
	startsNoScan(t, broken)
	require.Empty(t, broken.invoked())
}

// Review Focus 4: evidence that the store can't hold fails the request as TooLarge, and no manifest of it comes into
// the facts.
func TestErrTooLargeFromTheStoreGivesTooLarge(t *testing.T) {
	e := newExecutorEnv(t)
	// Random bytes don't compress, so 1 MiB of them is more than a record of the evidence store holds compressed.
	noise := make([]byte, 1<<20)
	_, err := cryptorand.Read(noise)
	require.NoError(t, err)
	scanner := newFakeScanner(func(req collector.InvokeRequest) ([]cloudevents.Event, *collector.Failure, error) {
		large, err := evidence.New(scannerType, subject.Manifest(amd64Manifest),
			map[string]any{"noise": base64.StdEncoding.EncodeToString(noise)},
			evidence.WithPlatform(linuxAMD64), evidence.WithSource("/clusters/cluster-a/collectors/scanner"))
		require.NoError(t, err)
		return []cloudevents.Event{large}, nil, nil
	})
	name := e.serve(scanner, "", healthy, nil)
	digest := newDigest(t)
	e.runs(digest, running("team-a", "web", linuxAMD64))

	e.request(digest)

	failure := e.failureOf(digest, name, 1)
	require.Equal(t, inventoryv1alpha1.ScanFailureReasonTooLarge, failure.Reason)
	require.Nil(t, e.recordOf(name, amd64Manifest))
	require.Empty(t, e.factsOf(digest).Manifests)
}

// The executor checks what a collector returns against the capabilities that the deployer recorded, since a collector
// needn't be built with the SDK: an event of a type that the operation doesn't produce breaks the contract, so the
// request fails, and none of the answer is stored.
func TestAnEventOfATypeThatTheOperationDoesntProduceFailsTheRequest(t *testing.T) {
	e := newExecutorEnv(t)
	scanner := newFakeScanner(func(req collector.InvokeRequest) ([]cloudevents.Event, *collector.Failure, error) {
		other, err := evidence.New(otherType, subject.Image(strings.TrimPrefix(req.Subject, "image/")), map[string]any{},
			evidence.WithSource("/clusters/cluster-a/collectors/scanner"))
		require.NoError(t, err)
		return []cloudevents.Event{manifestEvent(t, "cluster-a", linuxAMD64, amd64Manifest, 75), other}, nil, nil
	}, otherType)
	name := e.serve(scanner, "", healthy, func(caps *configv1alpha1.CollectorCapabilities) {
		caps.Produces = append(caps.Produces, configv1alpha1.ProducedType{Type: otherType, Scope: configv1alpha1.EvidenceScopeHub})
	})
	digest := newDigest(t)
	e.runs(digest, running("team-a", "web", linuxAMD64))

	e.request(digest)

	failure := e.failureOf(digest, name, 1)
	require.Equal(t, inventoryv1alpha1.ScanFailureReasonInternal, failure.Reason)
	require.Nil(t, e.recordOf(name, amd64Manifest))
	require.Empty(t, e.factsOf(digest).Manifests)
}

// What a collector says is its text, which the facts show: it is made printable and cut to the facts' limit, and a
// reason that isn't a word of the facts' vocabulary is recorded as Internal.
func TestTheTextOfAFailureIsMadePrintableAndBounded(t *testing.T) {
	cases := map[string]struct {
		answer func(collector.InvokeRequest) ([]cloudevents.Event, *collector.Failure, error)
		reason inventoryv1alpha1.ScanFailureReason
	}{
		"a failure": {
			answer: failsWith(collector.Failure{Reason: "not a reason\n", Message: "line one\nline two\x1b[31m" +
				strings.Repeat("x", 300)}),
			reason: inventoryv1alpha1.ScanFailureReasonInternal,
		},
		"an error": {
			answer: func(collector.InvokeRequest) ([]cloudevents.Event, *collector.Failure, error) {
				return nil, nil, status.Error(codes.FailedPrecondition, "line one\nline two\x1b[31m"+strings.Repeat("x", 300))
			},
			reason: inventoryv1alpha1.ScanFailureReasonInternal,
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			e := newExecutorEnv(t)
			collectorName := e.serve(newFakeScanner(tc.answer), "", healthy, nil)
			digest := newDigest(t)
			e.runs(digest, running("team-a", "web", linuxAMD64))

			e.request(digest)

			failure := e.failureOf(digest, collectorName, 1)
			require.Equal(t, tc.reason, failure.Reason)
			require.NotNil(t, failure.Message)
			require.LessOrEqual(t, len([]rune(*failure.Message)), 256)
			for _, r := range *failure.Message {
				require.True(t, unicode.IsPrint(r), "%q is printable", r)
			}
			require.Contains(t, *failure.Message, "line one")
			require.NotContains(t, *failure.Message, "rpc error", "the collector's own text, and not the call's")
		})
	}
}

// A collector that can't be reached isn't the image's failure: the request counts no attempt, and the hub asks again
// after its wait.
func TestAnUnreachableCollectorCountsNoAttempt(t *testing.T) {
	e := newExecutorEnv(t)
	scanner := newFakeScanner(func(collector.InvokeRequest) ([]cloudevents.Event, *collector.Failure, error) {
		return nil, nil, status.Error(codes.Unavailable, "the collector is restarting")
	})
	name := e.serve(scanner, "", healthy, nil)
	digest := newDigest(t)
	e.runs(digest, running("team-a", "web", linuxAMD64))

	e.request(digest)

	started(t, scanner)
	require.Never(t, func() bool { return !e.nothingWritten(name, digest, amd64Manifest) }, quiet, tick)
}

// An Invoke that is still running when its Collector is deleted must not write evidence after the deployer's finalizer
// has removed what the collector delivered: the executor drops what it returns.
func TestAnInvokeWhoseCollectorIsDeletedMeanwhileStoresNothing(t *testing.T) {
	for name, gone := range map[string]func(e *executorEnv, name string){
		"deleted": func(e *executorEnv, name string) {
			require.NoError(e.t, e.api.Delete(e.t.Context(), &configv1alpha1.Collector{ObjectMeta: metav1.ObjectMeta{Name: name}}))
		},
		"being deleted": func(e *executorEnv, name string) {
			var c configv1alpha1.Collector
			require.NoError(e.t, e.api.Get(e.t.Context(), client.ObjectKey{Name: name}, &c))
			c.Finalizers = []string{"vexplain.bedag.ch/evidence"}
			require.NoError(e.t, e.api.Update(e.t.Context(), &c))
			e.t.Cleanup(func() {
				var held configv1alpha1.Collector
				if err := e.api.Get(context.Background(), client.ObjectKey{Name: name}, &held); err == nil {
					held.Finalizers = nil
					assert.NoError(e.t, e.api.Update(context.Background(), &held))
				}
			})
			require.NoError(e.t, e.api.Delete(e.t.Context(), &c))
		},
		"replaced by another of the same name": func(e *executorEnv, name string) {
			require.NoError(e.t, e.api.Delete(e.t.Context(), &configv1alpha1.Collector{ObjectMeta: metav1.ObjectMeta{Name: name}}))
			require.NoError(e.t, e.api.Create(e.t.Context(), &configv1alpha1.Collector{
				ObjectMeta: metav1.ObjectMeta{Name: name},
				Spec:       configv1alpha1.CollectorSpec{Package: "artifacts.example/vexplain/scanner:" + scanned},
			}))
		},
	} {
		t.Run(name, func(t *testing.T) {
			e := newExecutorEnv(t)
			scanner := newFakeScanner(scansIndex(t))
			scanner.hold = make(chan struct{})
			collectorName := e.serve(scanner, "", healthy, nil)
			digest := newDigest(t)
			e.runs(digest, running("team-a", "web", linuxAMD64))
			e.request(digest)
			started(t, scanner)

			gone(e, collectorName)
			close(scanner.hold)

			require.Never(t, func() bool { return !e.nothingWritten(collectorName, digest, amd64Manifest) }, quiet, tick)
		})
	}
}

// The executor keeps one request per type and subject: a request for evidence that is being collected changes
// nothing.
func TestARequestForEvidenceThatIsBeingCollectedChangesNothing(t *testing.T) {
	e := newExecutorEnv(t)
	scanner := newFakeScanner(scansIndex(t))
	scanner.hold = make(chan struct{})
	e.serve(scanner, "", healthy, nil)
	digest := newDigest(t)
	e.runs(digest, running("team-a", "web", linuxAMD64))

	e.request(digest)
	started(t, scanner)
	e.request(digest)
	e.request(digest)
	startsNoScan(t, scanner)
	close(scanner.hold)

	startsNoScan(t, scanner)
	require.Len(t, scanner.invoked(), 1)
}

// A request names at most 16 of the pods that run the image, and among them one of each platform that runs it, so
// that the scan covers every platform.
func TestARequestNamesAtMostSixteenPodsWithOneOfEachPlatform(t *testing.T) {
	e := newExecutorEnv(t)
	scanner := newFakeScanner(scansIndex(t))
	e.serve(scanner, "", healthy, nil)
	digest := newDigest(t)
	amd64Pods := slices.Repeat([]string{linuxAMD64}, 20)
	e.runs(digest, running("team-a", "web", amd64Pods...), running("team-b", "worker", linuxARM64))

	e.request(digest)

	var params struct {
		Pods []struct{ Namespace, Name string } `json:"pods"`
	}
	require.NoError(t, json.Unmarshal(started(t, scanner).Parameters, &params))
	require.Len(t, params.Pods, 16)
	require.Contains(t, params.Pods, struct{ Namespace, Name string }{"team-b", "worker-0"}, "the only arm64 pod")
}

// A collector gets at most 16 requests at once.
func TestACollectorRunsAtMostSixteenRequestsAtOnce(t *testing.T) {
	e := newExecutorEnv(t)
	scanner := newFakeScanner(scansIndex(t))
	scanner.hold = make(chan struct{})
	e.serve(scanner, "", healthy, nil)
	for range 17 {
		digest := newDigest(t)
		e.runs(digest, running("team-a", "web", linuxAMD64))
		e.request(digest)
	}

	for range 16 {
		started(t, scanner)
	}
	startsNoScan(t, scanner)

	scanner.hold <- struct{}{}
	started(t, scanner)
	close(scanner.hold)
}

// Without a pod that runs the image in this cluster, there is nothing to collect evidence for here.
func TestARequestForAnImageThatRunsNowhereHereInvokesNothing(t *testing.T) {
	e := newExecutorEnv(t)
	scanner := newFakeScanner(scansIndex(t))
	e.serve(scanner, "", healthy, nil)
	digest := newDigest(t)
	require.NoError(t, e.store.Observe(t.Context(), digest, inventory.Observation{
		Cluster: e.cluster.name, ClusterID: e.cluster.id, DigestKind: inventoryv1alpha1.DigestKindRepoDigest,
		Repositories: []string{repository}, NamespaceCount: 1,
	}))

	e.request(digest)

	startsNoScan(t, scanner)
}

// The hub asks a spoke for evidence about images, which a request names by digest, with the repositories to pull
// them from.
func TestTheExecutorRefusesARequestThatIsNoImageRequest(t *testing.T) {
	e := newExecutorEnv(t)
	digest := "sha256:" + strings.Repeat("c", 64)
	for name, req := range map[string]tasks.Request{
		"a manifest":            {Type: scannerType, Subject: subject.Manifest(digest), Repositories: []string{repository}},
		"a subject that is bad": {Type: scannerType, Subject: "image/" + digest[:20], Repositories: []string{repository}},
		"no repository":         {Type: scannerType, Subject: subject.Image(digest)},
		"an empty repository":   {Type: scannerType, Subject: subject.Image(digest), Repositories: []string{""}},
		"a type that is bad":    {Type: "Scanner", Subject: subject.Image(digest), Repositories: []string{repository}},
	} {
		require.Error(t, e.executor.Request(t.Context(), req), name)
	}
}

// An answer that breaks the API's contract, which the pool finds in an answer that the SDK didn't check, is a failure
// of the request, recorded with what is wrong with the answer.
func TestAnAnswerThatBreaksTheContractIsRecordedWithWhatBreaksIt(t *testing.T) {
	e := newExecutorEnv(t)
	notJSON, err := evidence.ToProto(manifestEvent(t, "cluster-a", linuxAMD64, amd64Manifest, 75))
	require.NoError(t, err)
	notJSON.Data = &pb.CloudEvent_BinaryData{BinaryData: []byte("not JSON at all")}
	name := e.serveRaw(&rawScanner{answer: []*collectorv1alpha1.InvokeResponse{
		{Item: &collectorv1alpha1.InvokeResponse_Event{Event: notJSON}},
	}})
	digest := newDigest(t)
	e.runs(digest, running("team-a", "web", linuxAMD64))

	e.request(digest)

	failure := e.failureOf(digest, name, 1)
	require.Equal(t, inventoryv1alpha1.ScanFailureReasonInternal, failure.Reason)
	require.NotNil(t, failure.Message)
	require.Contains(t, *failure.Message, "contract")
	require.Contains(t, *failure.Message, "not valid evidence")
	require.Nil(t, e.recordOf(name, amd64Manifest))
}

// A store that refuses what a collector delivered refuses it again at every attempt: the request fails, and counts an
// attempt, so that the image waits as after any failure, and isn't scanned again at every look.
func TestARefusalOfTheStoresCountsAnAttempt(t *testing.T) {
	evidenceRefused := apierrors.NewInvalid(schema.GroupKind{Group: inventoryv1alpha1.GroupVersion.Group, Kind: "Evidence"},
		"ev-refused", field.ErrorList{field.Invalid(field.NewPath("spec", "platform"), "x", "the schema refuses it")})
	factsRefused := apierrors.NewBadRequest("the facts don't fit the schema")
	cases := map[string]struct {
		funcs  interceptor.Funcs
		answer func(*testing.T) func(collector.InvokeRequest) ([]cloudevents.Event, *collector.Failure, error)
	}{
		"the evidence store refuses an event that the API can't hold": {
			answer: func(t *testing.T) func(collector.InvokeRequest) ([]cloudevents.Event, *collector.Failure, error) {
				return func(collector.InvokeRequest) ([]cloudevents.Event, *collector.Failure, error) {
					// CloudEvents takes a platform in upper case, and the API doesn't.
					return []cloudevents.Event{manifestEvent(t, "cluster-a", "Linux/AMD64", amd64Manifest, 75)}, nil, nil
				}
			},
		},
		"the API server refuses the evidence": {
			funcs: interceptor.Funcs{Create: func(ctx context.Context, c client.WithWatch, obj client.Object,
				opts ...client.CreateOption) error {
				if _, ok := obj.(*inventoryv1alpha1.Evidence); ok {
					return evidenceRefused
				}
				return c.Create(ctx, obj, opts...)
			}},
			answer: scansIndex,
		},
		"the API server refuses the facts of the evidence": {
			funcs: interceptor.Funcs{SubResourceUpdate: func(ctx context.Context, c client.Client, subResource string,
				obj client.Object, opts ...client.SubResourceUpdateOption) error {
				if inv, ok := obj.(*inventoryv1alpha1.ImageInventory); ok && inv.Status.Facts != nil &&
					len(inv.Status.Facts.Evidence) > 0 {
					return factsRefused
				}
				return c.SubResource(subResource).Update(ctx, obj, opts...)
			}},
			answer: scansIndex,
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			e := newExecutorEnvWith(t, tc.funcs)
			collectorName := e.serve(newFakeScanner(tc.answer(t)), "", healthy, nil)
			digest := newDigest(t)
			e.runs(digest, running("team-a", "web", linuxAMD64))

			e.request(digest)

			failure := e.failureOf(digest, collectorName, 1)
			require.Equal(t, inventoryv1alpha1.ScanFailureReasonInternal, failure.Reason)
		})
	}
}
