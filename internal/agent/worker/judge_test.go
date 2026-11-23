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

package worker_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	cloudevents "github.com/cloudevents/sdk-go/v2"
	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/events"
	clocktesting "k8s.io/utils/clock/testing"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
	inventoryv1alpha1 "github.com/bedag/vexplain/api/inventory/v1alpha1"
	triagev1alpha1 "github.com/bedag/vexplain/api/triage/v1alpha1"
	"github.com/bedag/vexplain/internal/agent/cases"
	"github.com/bedag/vexplain/internal/agent/profile"
	"github.com/bedag/vexplain/internal/agent/prompt"
	"github.com/bedag/vexplain/internal/agent/validator"
	"github.com/bedag/vexplain/internal/agent/worker"
	"github.com/bedag/vexplain/internal/collectorclient"
	"github.com/bedag/vexplain/internal/controller/hub"
	"github.com/bedag/vexplain/internal/evidence"
	"github.com/bedag/vexplain/internal/inventory"
	"github.com/bedag/vexplain/internal/llm"
	"github.com/bedag/vexplain/internal/metrics"
	"github.com/bedag/vexplain/internal/settings"
	collectorv1alpha1 "github.com/bedag/vexplain/sdk/api/collector/v1alpha1"
	sdkevidence "github.com/bedag/vexplain/sdk/evidence"
	subjects "github.com/bedag/vexplain/sdk/subject"
	"github.com/bedag/vexplain/sdk/workloads"
)

// These tests run the agent as the workers run it, on a client of its own: the hub's investigation queues its case, a
// worker's loop claims it, and the Agent judges it against a scripted model over TLS and writes the outcome.

const (
	judgedManifest = "sha256:4242424242424242424242424242424242424242424242424242424242424242"
	judgedCVE      = "CVE-2026-0042"
	judgedPlaybook = "agent-cves"
	judgedModel    = "model-a"
)

// judgedInvestigation is the investigation of these tests.
var judgedInvestigation = types.NamespacedName{Namespace: "team-c", Name: "judged"}

// The uids of the investigations of these tests: the fake API server sets none. earlierUID is that of an object of the
// judged investigation's name that is gone.
const (
	judgedUID    types.UID = "uid-judged"
	elsewhereUID types.UID = "uid-elsewhere"
	otherUID     types.UID = "uid-other"
	earlierUID   types.UID = "uid-earlier"
)

// judgedReference is the reference to the judged investigation, as the queue holds it.
var judgedReference = triagev1alpha1.InvestigationReference{Namespace: judgedInvestigation.Namespace,
	Name: judgedInvestigation.Name, UID: judgedUID}

// judgedFinding is the finding of the case: an open one in the package of the SBOM that sbomOf gives.
var judgedFinding = inventoryv1alpha1.Finding{
	VulnerabilityID: judgedCVE,
	Package:         inventoryv1alpha1.PackageReference{ID: examplePackage, Name: exampleName, Version: ptr.To(exampleVersion), Type: deb},
	Status:          inventoryv1alpha1.VEXStatusUnderInvestigation, Severity: inventoryv1alpha1.SeverityHigh,
	FixState: inventoryv1alpha1.FixStateNotFixed, KnownExploited: inventoryv1alpha1.KnownExploitedNotListed,
	Aliases: []string{"GHSA-aaaa-bbbb-cccc"},
}

// chatRequest is what the scripted model reads of a request.
type chatRequest struct {
	Messages []struct {
		Role    string  `json:"role"`
		Content *string `json:"content"`
	} `json:"messages"`
	Tools []json.RawMessage `json:"tools"`
}

// hasResult reports whether the request carries the result of a tool.
func (r chatRequest) hasResult() bool {
	for _, m := range r.Messages {
		if m.Role == "tool" {
			return true
		}
	}
	return false
}

// chatAnswer is what the scripted model answers: a text, or tool calls, each a name and its arguments. hold keeps the
// request until the client gives up on it, status answers with that HTTP status alone, and cut answers 200 with a body
// that breaks off.
type chatAnswer struct {
	text   string
	calls  [][2]string
	hold   bool
	status int
	cut    bool
}

func callOf(name string, args any) chatAnswer {
	raw, err := json.Marshal(args)
	if err != nil {
		panic(err)
	}
	return chatAnswer{calls: [][2]string{{name, string(raw)}}}
}

// chatModel is a scripted model over TLS.
type chatModel struct {
	*httptest.Server
	script func(r chatRequest) chatAnswer
	// requests counts the requests, and held those that it holds now.
	requests, held atomic.Int32
}

func newChatModel(t *testing.T, script func(r chatRequest) chatAnswer) *chatModel {
	t.Helper()
	m := &chatModel{script: script}
	m.Server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		body, _ := io.ReadAll(req.Body)
		var r chatRequest
		if json.Unmarshal(body, &r) != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		n := m.requests.Add(1)
		a := m.script(r)
		if a.hold {
			m.held.Add(1)
			<-req.Context().Done()
			m.held.Add(-1)
			return
		}
		if a.status != 0 {
			w.WriteHeader(a.status)
			return
		}
		if a.cut {
			// Less than the length that the header promises: the server closes the connection.
			w.Header().Set("Content-Length", "1024")
			_, _ = io.WriteString(w, `{"choices":[`)
			return
		}
		msg := map[string]any{"role": "assistant", "content": nil}
		if a.text != "" {
			msg["content"] = a.text
		}
		var calls []map[string]any
		for i, c := range a.calls {
			calls = append(calls, map[string]any{"id": fmt.Sprintf("call_%d_%d", n, i), "type": "function",
				"function": map[string]any{"name": c[0], "arguments": c[1]}})
		}
		if calls != nil {
			msg["tool_calls"] = calls
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"choices": []map[string]any{{"message": msg, "finish_reason": "stop"}},
			"usage":   map[string]any{"prompt_tokens": 10, "completion_tokens": 5},
		})
	}))
	t.Cleanup(m.Close)
	return m
}

// searchSBOMFor returns the arguments of a search of the case file's SBOM.
func searchSBOMFor(query string) map[string]any {
	return map[string]any{"name": sbomName, "query": query}
}

// searchSBOM is the arguments of a search of the case file's SBOM.
var searchSBOM = searchSBOMFor(exampleName)

// verdictArgs returns the arguments of submit_verdict with the status, citing ev-1.
func verdictArgs(status string) map[string]any {
	return map[string]any{"status": status, "nextStep": "Update the image once a fixed version exists.",
		"summary": "The image installs libexample1 1.0-1, which the database lists as vulnerable (ev-1).",
		"claims":  []map[string]any{{"text": "the image installs the package", "evidence": []string{"ev-1"}}}}
}

// searchThenAffected is a model that searches the SBOM, and then finds the case affected.
func searchThenAffected(r chatRequest) chatAnswer {
	if !r.hasResult() {
		return callOf("search_evidence", searchSBOM)
	}
	return callOf("submit_verdict", verdictArgs("affected"))
}

// judging is the hub's agent on a client of its own, with what a case needs: the investigation, its playbook and
// sheet, the SBOM, the default profile and its model.
type judging struct {
	api      client.Client
	evidence evidence.Store
	verdicts inventory.VerdictsStore
	images   inventory.Store
	ledgers  inventory.LedgerStore
	recorder *events.FakeRecorder
	model    *chatModel
	agent    *worker.Agent
	seen     []string
}

func newJudging(t *testing.T, script func(r chatRequest) chatAnswer) *judging {
	t.Helper()
	ctx := t.Context()
	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	require.NoError(t, configv1alpha1.AddToScheme(scheme))
	require.NoError(t, inventoryv1alpha1.AddToScheme(scheme))
	require.NoError(t, triagev1alpha1.AddToScheme(scheme))
	api := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(&triagev1alpha1.Investigation{},
		&triagev1alpha1.Assessment{}, &configv1alpha1.AgentProfile{}, &configv1alpha1.ModelConfig{},
		&inventoryv1alpha1.ImageVerdicts{}, &inventoryv1alpha1.ImageInventory{}).Build()
	local := func() string { return settings.DefaultClusterName }
	j := &judging{
		api: api, evidence: evidence.NewCRDStore(api, nil, local), verdicts: inventory.NewCRDVerdictsStore(api, local),
		ledgers: inventory.NewCRDLedgerStore(api), recorder: events.NewFakeRecorder(1000),
		model: newChatModel(t, script),
	}
	j.agent = &worker.Agent{
		Client: api, APIReader: api, OperatorNamespace: operatorNamespace, Verdicts: j.verdicts, Evidence: j.evidence,
		Ledgers: j.ledgers,
		ClientConfig: func(context.Context, string) (llm.Config, error) {
			return llm.Config{BaseURL: j.model.URL, Model: judgedModel, APIKey: llm.NewSecret("key-123")}, nil
		},
		HTTPClient: j.model.Client(), Recorder: j.recorder, SwitchPoll: 20 * time.Millisecond,
	}

	require.NoError(t, api.Create(ctx, &configv1alpha1.Playbook{ObjectMeta: metav1.ObjectMeta{Name: judgedPlaybook},
		Spec: configv1alpha1.PlaybookSpec{Agent: &configv1alpha1.PlaybookAgent{
			ProfileRef: &configv1alpha1.AgentProfileRef{Name: profile.DefaultName}, Evidence: []string{sbomName}}}}))
	require.NoError(t, api.Create(ctx, &configv1alpha1.ModelConfig{ObjectMeta: metav1.ObjectMeta{Name: profile.DefaultName},
		Spec: configv1alpha1.ModelConfigSpec{Endpoint: "https://llm.example/v1", Model: judgedModel,
			APIKeySecretRef:     configv1alpha1.SecretKeyRef{Name: "llm-api-key", Key: "api-key"},
			ContextWindowTokens: ptr.To(int32(200000))}}))
	j.setReady(t, &configv1alpha1.ModelConfig{}, metav1.ConditionTrue)
	require.NoError(t, api.Create(ctx, &configv1alpha1.AgentProfile{ObjectMeta: metav1.ObjectMeta{Name: profile.DefaultName},
		Spec: configv1alpha1.AgentProfileSpec{ModelRef: configv1alpha1.ModelConfigReference{Name: profile.DefaultName}}}))
	j.setReady(t, &configv1alpha1.AgentProfile{}, metav1.ConditionTrue)

	sbom, err := sdkevidence.New(sdkevidence.TypeSBOM, subjects.Manifest(judgedManifest), sbomOf(),
		sdkevidence.WithPlatform(linuxAMD64), sdkevidence.WithSource("/clusters/cluster-a/collectors/scanner"))
	require.NoError(t, err)
	require.NoError(t, j.evidence.Put(ctx, scanner, v1, sbom))
	// A workload runs the image: selection leaves out one that runs nowhere.
	images := inventory.NewCRDStore(api, nil, local)
	j.images = images
	require.NoError(t, images.Observe(ctx, judgedManifest, inventory.Observation{Cluster: localCluster, ClusterID: localCluster + "-id",
		DigestKind: inventoryv1alpha1.DigestKindRepoDigest, Repositories: []string{repository}, NamespaceCount: 1,
		Workloads: []workloads.WorkloadRef{{Kind: deployment, Namespace: "default", Name: appName}}}))
	_, err = images.SetFacts(ctx, judgedManifest, &inventoryv1alpha1.ImageFacts{
		Manifests: []inventoryv1alpha1.ManifestFact{{Platform: linuxAMD64, Digest: judgedManifest}}})
	require.NoError(t, err)
	require.NoError(t, j.verdicts.Put(ctx, judgedManifest, judgedPlaybook, inventoryv1alpha1.ImageVerdictsStatus{
		Playbook: ptr.To(judgedPlaybook), FindingsVersion: ptr.To(v1), Findings: []inventoryv1alpha1.Finding{judgedFinding},
		Evidence: []inventoryv1alpha1.SheetEvidence{{Name: sbomName, Source: scanner, Type: sdkevidence.TypeSBOM,
			Version: ptr.To(v1)}},
	}))
	require.NoError(t, api.Create(ctx, &triagev1alpha1.Investigation{
		ObjectMeta: metav1.ObjectMeta{Namespace: judgedInvestigation.Namespace, Name: judgedInvestigation.Name, UID: judgedUID},
		Spec: triagev1alpha1.InvestigationSpec{PlaybookRef: triagev1alpha1.PlaybookReference{Name: judgedPlaybook},
			Vulnerabilities: []string{judgedCVE}, Agent: triagev1alpha1.InvestigationAgent{MaxCases: 10}},
	}))
	return j
}

// setReady sets the Ready condition of the default config object of obj's kind, at its generation.
func (j *judging) setReady(t *testing.T, obj client.Object, status metav1.ConditionStatus) {
	t.Helper()
	require.NoError(t, j.api.Get(t.Context(), client.ObjectKey{Name: profile.DefaultName}, obj))
	condition := metav1.Condition{Type: configv1alpha1.ConditionReady, Status: status, Reason: "Probed",
		ObservedGeneration: obj.GetGeneration()}
	switch o := obj.(type) {
	case *configv1alpha1.ModelConfig:
		meta.SetStatusCondition(&o.Status.Conditions, condition)
	case *configv1alpha1.AgentProfile:
		meta.SetStatusCondition(&o.Status.Conditions, condition)
	}
	require.NoError(t, j.api.Status().Update(t.Context(), obj))
}

// capAtOne sets the investigation's maxCases to 1, before its first reconcile.
func (j *judging) capAtOne(t *testing.T) {
	t.Helper()
	var inv triagev1alpha1.Investigation
	require.NoError(t, j.api.Get(t.Context(), judgedInvestigation, &inv))
	inv.Spec.Agent.MaxCases = 1
	require.NoError(t, j.api.Update(t.Context(), &inv))
}

// investigation returns the investigation as it stands.
func (j *judging) investigation(t *testing.T) *triagev1alpha1.Investigation {
	t.Helper()
	var inv triagev1alpha1.Investigation
	require.NoError(t, j.api.Get(t.Context(), judgedInvestigation, &inv))
	return &inv
}

// charged returns the hand-overs that the investigation's cap counts.
func (j *judging) charged(t *testing.T) int32 {
	t.Helper()
	inv := j.investigation(t)
	if inv.Status.Cases == nil {
		return 0
	}
	return ptr.Deref(inv.Status.Cases.Charged, 0)
}

// switchAgentTo sets the agent's switch in the OperatorConfig.
func (j *judging) switchAgentTo(t *testing.T, state configv1alpha1.AgentState) {
	t.Helper()
	cfg := &configv1alpha1.OperatorConfig{ObjectMeta: metav1.ObjectMeta{Name: settings.ConfigName}}
	_, err := ctrl.CreateOrUpdate(t.Context(), j.api, cfg, func() error {
		cfg.Spec.Agent = &configv1alpha1.AgentSettings{State: ptr.To(state)}
		return nil
	})
	require.NoError(t, err)
}

// judgingWorker names the worker of these tests in its claims.
const judgingWorker = "vexplain-agent-a"

// start returns the hub's queue, and starts a worker that judges its cases with the agent, as a manager's start does,
// with the worker's stop, which waits for it.
func (j *judging) start(t *testing.T) (*hub.APIQueue, func()) {
	t.Helper()
	return j.queue(), j.run(t)
}

// queue returns the hub's queue in the API server of the tests.
func (j *judging) queue() *hub.APIQueue {
	return &hub.APIQueue{Client: j.api, APIReader: j.api}
}

// run starts a worker that claims the cases and judges them with the agent, and returns its stop, which waits for it.
func (j *judging) run(t *testing.T) func() {
	t.Helper()
	l := &worker.Loop{Client: j.api, APIReader: j.api, Verdicts: j.verdicts, Store: j.images, Name: judgingWorker,
		Limit: func() int { return 2 }, CanStart: j.agent.CanStart, Judge: j.agent.Judge, RetryDelay: 50 * time.Millisecond}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- l.Start(ctx) }()
	stopped := false
	stop := func() {
		if stopped {
			return
		}
		stopped = true
		cancel()
		select {
		case err := <-done:
			require.NoError(t, err)
		case <-time.After(within):
			t.Error("the worker didn't stop")
		}
	}
	t.Cleanup(stop)
	return stop
}

// claimed writes the claim of the tests' worker on the case, as its loop does before it calls the judge, and returns
// the context of the judge.
func (j *judging) claimed(t *testing.T) context.Context {
	t.Helper()
	a := j.assessment(t)
	a.Status.Claim = &triagev1alpha1.QueueClaim{Worker: judgingWorker, LeaseEndTime: ptr.To(metav1.NewTime(time.Now().Add(time.Hour)))}
	require.NoError(t, j.api.Status().Update(t.Context(), a))
	return worker.WithClaimant(t.Context(), judgingWorker)
}

// investigate runs a reconcile of the investigation that queues to q, as a manager runs one at its start and after
// each change.
func (j *judging) investigate(t *testing.T, q cases.Queue) {
	t.Helper()
	j.reconcile(t, q, judgedInvestigation)
}

// reconcile runs a reconcile of the investigation of the key that queues to q.
func (j *judging) reconcile(t *testing.T, q cases.Queue, key types.NamespacedName) {
	t.Helper()
	_, err := j.reconciler(q, j.api).Reconcile(t.Context(), ctrl.Request{NamespacedName: key})
	require.NoError(t, err)
}

// reconciler returns the investigation controller on the client c, which queues to q.
func (j *judging) reconciler(q cases.Queue, c client.Client) *hub.InvestigationReconciler {
	return &hub.InvestigationReconciler{Client: c, APIReader: j.api, Store: inventory.NewCRDStore(j.api, nil, func() string { return "" }),
		Verdicts: j.verdicts, Evidence: j.evidence, Queue: q, Recorder: j.recorder}
}

// assessment returns the Assessment of the case.
func (j *judging) assessment(t *testing.T) *triagev1alpha1.Assessment {
	t.Helper()
	a := &triagev1alpha1.Assessment{}
	require.NoError(t, j.api.Get(t.Context(), client.ObjectKey{Name: cases.Name(judgedCVE, judgedManifest)}, a))
	return a
}

// judged reports whether the Assessment of the case records a verdict or no verdict.
func (j *judging) judged(t *testing.T) func() bool {
	return func() bool {
		a := j.assessment(t)
		return a.Status.Verdict != nil || a.Status.NoVerdict != nil
	}
}

// ledger returns the Ledger of the case, or nil.
func (j *judging) ledger(t *testing.T) *inventoryv1alpha1.Ledger {
	t.Helper()
	l, err := j.ledgers.Get(t.Context(), cases.Name(judgedCVE, judgedManifest))
	require.NoError(t, err)
	return l
}

// events returns the events recorded so far.
func (j *judging) events() []string {
	for {
		select {
		case e := <-j.recorder.Events:
			j.seen = append(j.seen, e)
		default:
			return j.seen
		}
	}
}

// hasEvent reports whether an event of the reason was recorded.
func (j *judging) hasEvent(reason string) bool {
	for _, e := range j.events() {
		if strings.Contains(e, " "+reason+" ") {
			return true
		}
	}
	return false
}

// readyOfAssessment returns the Ready condition of the Assessment.
func readyOfAssessment(a *triagev1alpha1.Assessment) *metav1.Condition {
	return meta.FindStatusCondition(a.Status.Conditions, configv1alpha1.ConditionReady)
}

func TestTheAgentRecordsTheVerdictTheLedgerAndTheInputHashThatTheInvestigationComputes(t *testing.T) {
	j := newJudging(t, searchThenAffected)
	cases0 := testutil.ToFloat64(metrics.AgentCasesTotal.WithLabelValues(settings.DefaultClusterName, "Affected"))
	q, _ := j.start(t)

	j.investigate(t, q)
	require.Eventually(t, j.judged(t), within, often)

	a := j.assessment(t)
	require.Equal(t, &triagev1alpha1.AssessmentVerdict{Status: triagev1alpha1.VEXStatusAffected,
		Summary:  "The image installs libexample1 1.0-1, which the database lists as vulnerable (ev-1).",
		NextStep: ptr.To("Update the image once a fixed version exists."),
		Claims:   []triagev1alpha1.AssessmentClaim{{Text: "the image installs the package", Evidence: []string{"ev-1"}}},
	}, a.Status.Verdict)
	require.Nil(t, a.Status.NoVerdict)
	require.Equal(t, &triagev1alpha1.AssessmentValidation{Result: triagev1alpha1.ValidationPassed, Repairs: ptr.To(int32(0))},
		a.Status.Validation)
	sheet, err := j.verdicts.Get(t.Context(), judgedManifest, judgedPlaybook)
	require.NoError(t, err)
	hashes, err := cases.EvidenceHashes(t.Context(), j.evidence, sheet, []string{sbomName})
	require.NoError(t, err)
	require.Equal(t, cases.InputHash([]inventoryv1alpha1.Finding{judgedFinding}, hashes), ptr.Deref(a.Status.InputHash, ""))
	require.Equal(t, &triagev1alpha1.LedgerReference{Name: a.Name}, a.Status.LedgerRef)
	require.Equal(t, &triagev1alpha1.AssessmentRunner{Type: triagev1alpha1.RunnerBuiltin}, a.Status.Runner)
	require.NotNil(t, a.Status.Model)
	require.Equal(t, profile.DefaultName, a.Status.Model.AgentProfile)
	require.Equal(t, profile.DefaultName, a.Status.Model.ModelConfig)
	require.Equal(t, judgedModel, a.Status.Model.Model)
	require.Equal(t, prompt.CoreVersion, a.Status.Model.PromptCore)
	require.Len(t, a.Status.Model.GuidanceSHA256, 64)
	require.NotNil(t, a.Status.Usage)
	require.Equal(t, ptr.To(int32(2)), a.Status.Usage.Steps)
	require.Equal(t, ptr.To(int64(20)), a.Status.Usage.PromptTokens)
	require.Equal(t, ptr.To(int64(10)), a.Status.Usage.CompletionTokens)
	require.NotNil(t, a.Status.JudgedTime)
	require.Equal(t, &judgedReference, a.Status.InvestigationRef, "the judgement is made for the investigation that queued it")
	require.Nil(t, a.Status.Queue)
	require.Nil(t, a.Status.Claim)
	ready := readyOfAssessment(a)
	require.NotNil(t, ready)
	require.Equal(t, metav1.ConditionTrue, ready.Status)
	require.Equal(t, triagev1alpha1.ReasonJudged, ready.Reason)
	l := j.ledger(t)
	require.NotNil(t, l, "the ledger is written with the outcome")
	require.Len(t, l.Spec.Entries, 1)
	require.Equal(t, "search_evidence", l.Spec.Entries[0].Tool)
	require.Equal(t, cases0+1, testutil.ToFloat64(metrics.AgentCasesTotal.WithLabelValues(settings.DefaultClusterName, "Affected")))

	// The investigation computes the same inputHash, so the verdict is fresh, and nothing is queued again.
	requests := j.model.requests.Load()
	j.investigate(t, q)
	queued, inProgress := q.Pending(judgedInvestigation, judgedUID)
	require.Zero(t, queued+inProgress)
	var inv triagev1alpha1.Investigation
	require.NoError(t, j.api.Get(t.Context(), judgedInvestigation, &inv))
	require.Equal(t, ptr.To(int32(1)), inv.Status.Cases.Judged)
	require.Never(t, func() bool { return j.model.requests.Load() != requests }, 200*time.Millisecond, often)
}

func TestALimitOrARejectionEndsTheCaseWithoutAVerdict(t *testing.T) {
	t.Run("the step limit", func(t *testing.T) {
		steps := atomic.Int32{}
		j := newJudging(t, func(r chatRequest) chatAnswer {
			if len(r.Tools) == 0 {
				return chatAnswer{text: "The image installs libexample1 (ev-1).\n\nA fixed version would settle it."}
			}
			// Each step searches anew: a repeated call is answered from the ledger, without an entry.
			return callOf("search_evidence", searchSBOMFor(fmt.Sprintf("%s %d", exampleName, steps.Add(1))))
		})
		var limited configv1alpha1.AgentProfile
		require.NoError(t, j.api.Get(t.Context(), client.ObjectKey{Name: profile.DefaultName}, &limited))
		limited.Spec.Limits = &configv1alpha1.AgentLimits{MaxSteps: ptr.To(int32(2))}
		require.NoError(t, j.api.Update(t.Context(), &limited))
		j.setReady(t, &configv1alpha1.AgentProfile{}, metav1.ConditionTrue)
		before := testutil.ToFloat64(metrics.AgentNoVerdictsTotal.WithLabelValues(settings.DefaultClusterName, "MaxSteps"))
		q, _ := j.start(t)

		j.investigate(t, q)
		require.Eventually(t, j.judged(t), within, often)

		a := j.assessment(t)
		require.Nil(t, a.Status.Verdict, "a limit never ends in a verdict")
		require.NotNil(t, a.Status.NoVerdict)
		require.Equal(t, ptr.To(triagev1alpha1.NoVerdictMaxSteps), a.Status.NoVerdict.Reason)
		require.Contains(t, a.Status.NoVerdict.Summary, "maxSteps")
		require.Contains(t, a.Status.NoVerdict.Summary, "The image installs libexample1 (ev-1).")
		require.Contains(t, a.Status.NoVerdict.Summary, "A fixed version would settle it.")
		require.Nil(t, a.Status.Validation, "no verdict was submitted")
		require.NotNil(t, a.Status.JudgedTime)
		require.Len(t, j.ledger(t).Spec.Entries, 2)
		require.True(t, j.hasEvent("NoVerdict"))
		require.Equal(t, before+1,
			testutil.ToFloat64(metrics.AgentNoVerdictsTotal.WithLabelValues(settings.DefaultClusterName, "MaxSteps")))
	})

	t.Run("two rejections", func(t *testing.T) {
		submits := atomic.Int32{}
		j := newJudging(t, func(r chatRequest) chatAnswer {
			if !r.hasResult() {
				return callOf("search_evidence", searchSBOM)
			}
			submits.Add(1)
			return callOf("submit_verdict", verdictArgs("fixed"))
		})
		before := testutil.ToFloat64(metrics.AgentRejectionsTotal.WithLabelValues(settings.DefaultClusterName, "FixedForInstalled"))
		q, _ := j.start(t)

		j.investigate(t, q)
		require.Eventually(t, j.judged(t), within, often)

		a := j.assessment(t)
		require.Nil(t, a.Status.Verdict)
		require.NotNil(t, a.Status.NoVerdict)
		require.Equal(t, ptr.To(triagev1alpha1.NoVerdictValidatorRejected), a.Status.NoVerdict.Reason)
		summary := a.Status.NoVerdict.Summary
		require.True(t, strings.HasPrefix(summary, "The agent proposed fixed: "), "a proposal, never an established fact: %s", summary)
		require.NotContains(t, summary, "Established", "the rejected claim isn't what was established")
		require.Contains(t, summary, "rejected")
		require.Equal(t, &triagev1alpha1.AssessmentValidation{Result: triagev1alpha1.ValidationRejected, Repairs: ptr.To(int32(1))},
			a.Status.Validation)
		require.Equal(t, int32(2), submits.Load())
		require.True(t, j.hasEvent("VerdictRejected"))
		require.Equal(t, before+2, testutil.ToFloat64(metrics.AgentRejectionsTotal.WithLabelValues(
			settings.DefaultClusterName, "FixedForInstalled")), "both rejections count, the repaired one too")
	})
}

func TestACaseWaitsInTheQueueWhileItsModelIsNotReady(t *testing.T) {
	j := newJudging(t, searchThenAffected)
	j.setReady(t, &configv1alpha1.ModelConfig{}, metav1.ConditionFalse)
	q, _ := j.start(t)

	j.investigate(t, q)
	require.Never(t, j.judged(t), 300*time.Millisecond, often)
	require.Zero(t, j.model.requests.Load(), "no model is called")
	queued, inProgress := q.Pending(judgedInvestigation, judgedUID)
	require.Equal(t, 1, queued+inProgress, "the case stays in the queue, and isn't ended without a verdict")
	// A worker claims it, Judging, and hands it back, Queued, each time it tries.
	require.Contains(t, []string{triagev1alpha1.ReasonQueued, triagev1alpha1.ReasonJudging},
		readyOfAssessment(j.assessment(t)).Reason)

	j.setReady(t, &configv1alpha1.ModelConfig{}, metav1.ConditionTrue)
	require.Eventually(t, j.judged(t), within, often)
	require.NotNil(t, j.assessment(t).Status.Verdict)
}

// Design 5.11: switching the agent off returns the cases in progress to the queue, with nothing written, and records
// the event AgentDisabled on the OperatorConfig.
func TestSwitchingTheAgentOffReturnsCasesInProgressWithNothingWritten(t *testing.T) {
	var holding atomic.Bool
	holding.Store(true)
	j := newJudging(t, func(r chatRequest) chatAnswer {
		if r.hasResult() && holding.Load() {
			return chatAnswer{hold: true}
		}
		return searchThenAffected(r)
	})
	j.switchAgentTo(t, configv1alpha1.AgentStateEnabled)
	q, _ := j.start(t)
	j.investigate(t, q)
	require.Eventually(t, func() bool { return j.model.held.Load() == 1 }, within, often, "the case is in progress")
	require.Equal(t, triagev1alpha1.ReasonJudging, readyOfAssessment(j.assessment(t)).Reason)

	j.switchAgentTo(t, configv1alpha1.AgentStateDisabled)

	require.Eventually(t, func() bool { queued, _ := q.Pending(judgedInvestigation, judgedUID); return queued == 1 }, within, often,
		"the case goes back to the queue")
	require.Eventually(t, func() bool { return readyOfAssessment(j.assessment(t)).Reason == triagev1alpha1.ReasonQueued },
		within, often, "it waits again")
	a := j.assessment(t)
	require.Nil(t, a.Status.Verdict)
	require.Nil(t, a.Status.NoVerdict)
	require.Nil(t, a.Status.JudgedTime)
	require.Nil(t, a.Status.InputHash)
	require.Nil(t, j.ledger(t), "nothing written")
	require.True(t, meta.IsStatusConditionTrue(a.Status.Conditions, "Reconciling"))
	require.Eventually(t, func() bool { return j.hasEvent("AgentDisabled") }, within, often)
	requests := j.model.requests.Load()
	require.Never(t, func() bool { return j.model.requests.Load() != requests }, 300*time.Millisecond, often,
		"no model is called while the agent is off")

	holding.Store(false)
	j.switchAgentTo(t, configv1alpha1.AgentStateEnabled)
	require.Eventually(t, j.judged(t), within, often, "switched on again, the agent judges the case")
	require.NotNil(t, j.assessment(t).Status.Verdict)
}

// Review Focus 4: a manager stopped in the middle of a case leaves the Assessment without a verdict and without a
// ledger. After the start, its investigation queues it again, and it is judged once.
func TestARestartQueuesThePendingCasesAgain(t *testing.T) {
	var holding atomic.Bool
	holding.Store(true)
	var submits atomic.Int32
	j := newJudging(t, func(r chatRequest) chatAnswer {
		if r.hasResult() && holding.Load() {
			return chatAnswer{hold: true}
		}
		a := searchThenAffected(r)
		if a.calls[0][0] == "submit_verdict" {
			submits.Add(1)
		}
		return a
	})
	before, stop := j.start(t)
	j.investigate(t, before)
	require.Eventually(t, func() bool { return j.model.held.Load() == 1 }, within, often, "the case is in progress")

	stop()

	a := j.assessment(t)
	require.Nil(t, a.Status.Verdict, "nothing half-written")
	require.Nil(t, a.Status.NoVerdict)
	require.Nil(t, a.Status.JudgedTime)
	require.Nil(t, j.ledger(t))
	require.Equal(t, metav1.ConditionFalse, readyOfAssessment(a).Status, "the case is still held, for its investigation")
	require.Equal(t, triagev1alpha1.ReasonQueued, readyOfAssessment(a).Reason, "it waits again")

	holding.Store(false)
	after, _ := j.start(t)
	j.investigate(t, after)
	require.Eventually(t, j.judged(t), within, often, "queued again, and judged")
	require.NotNil(t, j.assessment(t).Status.Verdict)
	require.Len(t, j.ledger(t).Spec.Entries, 1, "the ledger of the one judgement that ended")

	j.investigate(t, after)
	queued, inProgress := after.Pending(judgedInvestigation, judgedUID)
	require.Zero(t, queued+inProgress)
	require.Equal(t, int32(1), submits.Load(), "judged once")
}

// A verdict whose inputs changed is stale: the investigation queues the case again, and the agent judges it again.
func TestAStaleVerdictIsQueuedAndJudgedAgain(t *testing.T) {
	j := newJudging(t, searchThenAffected)
	q, _ := j.start(t)
	j.investigate(t, q)
	require.Eventually(t, j.judged(t), within, often)

	changed := judgedFinding
	changed.Package.Version = ptr.To("1.0-2")
	require.NoError(t, j.verdicts.Put(t.Context(), judgedManifest, judgedPlaybook, inventoryv1alpha1.ImageVerdictsStatus{
		Playbook: ptr.To(judgedPlaybook), FindingsVersion: ptr.To(v1), Findings: []inventoryv1alpha1.Finding{changed},
		Evidence: []inventoryv1alpha1.SheetEvidence{{Name: sbomName, Source: scanner, Type: sdkevidence.TypeSBOM,
			Version: ptr.To(v1)}},
	}))
	var inv triagev1alpha1.Investigation
	require.NoError(t, j.api.Get(t.Context(), judgedInvestigation, &inv))
	inv.Spec.Agent.MaxCases = 11 // a new run of a Once investigation
	require.NoError(t, j.api.Update(t.Context(), &inv))
	j.investigate(t, q)

	require.Eventually(t, func() bool {
		return ptr.Deref(j.assessment(t).Status.InputHash, "") == cases.InputHash([]inventoryv1alpha1.Finding{changed},
			map[string][]string{sbomName: {sbomHash(t, j)}})
	}, within, often, "judged again, on the new inputs")
}

// An investigation whose judgePolicy is IfJudgedElsewhere has a case judged again whose fresh verdict another
// investigation was charged for: it asks for an outcome a second past that verdict, which stays the same across its
// reconciles, so that the agent doesn't take the verdict that is there. Once the new outcome lands, charged to it, the
// investigation reuses it, and queues the case no more.
func TestIfJudgedElsewhereJudgesACaseAgainOnceForTheInvestigation(t *testing.T) {
	var submits atomic.Int32
	j := newJudging(t, func(r chatRequest) chatAnswer {
		a := searchThenAffected(r)
		if a.calls[0][0] == "submit_verdict" {
			submits.Add(1)
		}
		return a
	})
	q := j.queue()
	stop := j.run(t)
	j.investigate(t, q)
	require.Eventually(t, j.judged(t), within, often)
	stop()
	first := j.assessment(t).Status.JudgedTime.Time

	elsewhere := types.NamespacedName{Namespace: judgedInvestigation.Namespace, Name: "elsewhere"}
	require.NoError(t, j.api.Create(t.Context(), &triagev1alpha1.Investigation{
		ObjectMeta: metav1.ObjectMeta{Namespace: elsewhere.Namespace, Name: elsewhere.Name, UID: elsewhereUID},
		Spec: triagev1alpha1.InvestigationSpec{PlaybookRef: triagev1alpha1.PlaybookReference{Name: judgedPlaybook},
			Vulnerabilities: []string{judgedCVE}, Agent: triagev1alpha1.InvestigationAgent{MaxCases: 10,
				JudgePolicy: ptr.To(triagev1alpha1.InvestigationJudgeIfJudgedElsewhere)}}}))
	for range 2 {
		j.reconcile(t, q, elsewhere)
		queue := j.assessment(t).Status.Queue
		require.NotNil(t, queue)
		require.Equal(t, &triagev1alpha1.InvestigationReference{Namespace: elsewhere.Namespace, Name: elsewhere.Name,
			UID: elsewhereUID}, queue.InvestigationRef)
		require.NotNil(t, queue.JudgedAfter)
		require.True(t, first.Truncate(time.Second).Add(time.Second).Equal(queue.JudgedAfter.Time),
			"a second past the verdict that is there, at each reconcile: %s, after %s", queue.JudgedAfter, first)
	}

	j.run(t)
	require.Eventually(t, func() bool {
		c := j.assessment(t).Status.InvestigationRef
		return c != nil && c.Name == elsewhere.Name && c.UID == elsewhereUID
	}, within, often, "judged again, for the investigation")
	j.reconcile(t, q, elsewhere)
	j.reconcile(t, q, elsewhere)

	require.Nil(t, j.assessment(t).Status.Queue, "not queued again")
	var inv triagev1alpha1.Investigation
	require.NoError(t, j.api.Get(t.Context(), elsewhere, &inv))
	require.Equal(t, ptr.To(int32(1)), inv.Status.Cases.Charged)
	require.Equal(t, ptr.To(int32(0)), inv.Status.Cases.JudgedElsewhere)
	require.Equal(t, int32(2), submits.Load(), "judged once for each investigation")

	// The first investigation, IfStale, reuses the newer verdict, which was judged elsewhere.
	j.investigate(t, q)
	require.Nil(t, j.assessment(t).Status.Queue)
	require.Equal(t, ptr.To(int32(1)), j.investigation(t).Status.Cases.JudgedElsewhere)
	require.True(t, j.hasEvent("JudgedElsewhere"))
}

// An Investigation stored before spec.agent existed reads back without it, so its maxCases is 0: it is Stalled, says
// to apply it again, and judges nothing, rather than skip every case over a cap of 0.
func TestAnInvestigationWithoutSpecAgentIsStalledAndJudgesNothing(t *testing.T) {
	j := newJudging(t, searchThenAffected)
	inv := j.investigation(t)
	inv.Spec.Agent = triagev1alpha1.InvestigationAgent{}
	require.NoError(t, j.api.Update(t.Context(), inv))
	q := j.queue()

	j.investigate(t, q)

	inv = j.investigation(t)
	ready := meta.FindStatusCondition(inv.Status.Conditions, configv1alpha1.ConditionReady)
	require.NotNil(t, ready)
	require.Equal(t, metav1.ConditionFalse, ready.Status)
	require.Equal(t, triagev1alpha1.ReasonAgentSettingsMissing, ready.Reason)
	require.Contains(t, ready.Message, "apply it again with spec.agent")
	require.True(t, meta.IsStatusConditionTrue(inv.Status.Conditions, configv1alpha1.ConditionStalled))
	queued, inProgress := q.Pending(judgedInvestigation, judgedUID)
	require.Zero(t, queued+inProgress)
	var list triagev1alpha1.AssessmentList
	require.NoError(t, j.api.List(t.Context(), &list))
	require.Empty(t, list.Items, "no case is handed over")
}

// sbomHash returns the SHA-256 of the SBOM's data, in hex, as the inputHash counts it.
func sbomHash(t *testing.T, j *judging) string {
	t.Helper()
	sheet, err := j.verdicts.Get(t.Context(), judgedManifest, judgedPlaybook)
	require.NoError(t, err)
	hashes, err := cases.EvidenceHashes(t.Context(), j.evidence, sheet, []string{sbomName})
	require.NoError(t, err)
	require.Len(t, hashes[sbomName], 1)
	return hashes[sbomName][0]
}

func TestTheInvestigationMetricsCountTheCasesByState(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, configv1alpha1.AddToScheme(scheme))
	require.NoError(t, triagev1alpha1.AddToScheme(scheme))
	inv := &triagev1alpha1.Investigation{ObjectMeta: metav1.ObjectMeta{Namespace: teamD, Name: "exploited-cves"},
		Status: triagev1alpha1.InvestigationStatus{Cases: &triagev1alpha1.InvestigationCases{Total: ptr.To(int32(5)),
			Queued: ptr.To(int32(2)), InProgress: ptr.To(int32(1)), Judged: ptr.To(int32(1)), Reused: ptr.To(int32(1)),
			JudgedElsewhere: ptr.To(int32(3)), Charged: ptr.To(int32(4))}}}
	api := fake.NewClientBuilder().WithScheme(scheme).WithObjects(inv,
		&triagev1alpha1.Investigation{ObjectMeta: metav1.ObjectMeta{Namespace: "team-b", Name: "new"}}).Build()

	series := gatherGauges(t, hub.NewInvestigationsCollector(api, logr.Discard()))["vexplain_investigation_cases"]

	expected := make([]map[string]string, 0, 9)
	for state, n := range map[string]string{"total": "5", "queued": "2", "inProgress": "1", "judged": "1", "reused": "1",
		"overTheCap": "0", "notSelected": "0", "judgedElsewhere": "3", "charged": "4"} {
		expected = append(expected, map[string]string{clusterLabel: settings.DefaultClusterName, "namespace": teamD,
			"investigation": "exploited-cves", "state": state, valueKey: n})
	}
	require.ElementsMatch(t, expected, series, "an investigation without counts has no series")
}

// A worker that knows its cluster's name serves each known value of the counters of cases, no-verdicts, rejections and
// tokens at 0, so that a board's increase() sees the first case.
func TestAWorkerStartsTheAgentsCountersAtZero(t *testing.T) {
	const cluster = "zeroed-cluster"
	scheme := runtime.NewScheme()
	require.NoError(t, configv1alpha1.AddToScheme(scheme))
	api := fake.NewClientBuilder().WithScheme(scheme).WithObjects(&configv1alpha1.OperatorConfig{
		ObjectMeta: metav1.ObjectMeta{Name: settings.ConfigName}, Spec: configv1alpha1.OperatorConfigSpec{ClusterName: ptr.To(cluster)}}).Build()

	(&worker.Agent{Client: api}).CanStart()

	families, err := ctrlmetrics.Registry.Gather()
	require.NoError(t, err)
	got := map[string][]string{}
	for _, family := range families {
		for _, m := range family.Metric {
			var value string
			for _, l := range m.Label {
				if l.GetName() == "cluster" && l.GetValue() != cluster {
					value = ""
					break
				}
				if l.GetName() != "cluster" {
					value = l.GetValue()
				}
			}
			if value != "" && m.GetCounter().GetValue() == 0 {
				got[family.GetName()] = append(got[family.GetName()], value)
			}
		}
	}
	require.ElementsMatch(t, []string{"Affected", "UnderInvestigation", "NotAffected", "Fixed", "NoVerdict"},
		got["vexplain_agent_cases_total"])
	require.ElementsMatch(t, []string{"GaveUp", "ValidatorRejected", "MaxSteps", "MaxTokens", "Timeout", "ContextLimit",
		"ModelError"}, got["vexplain_agent_no_verdicts_total"])
	require.ElementsMatch(t, validator.Checks, got["vexplain_agent_rejections_total"])
	require.ElementsMatch(t, []string{"prompt", "completion"}, got["vexplain_agent_tokens_total"])
}

// An ID that the spec and a result both name, in any case, has one series, as the result spells it: the finding's ID,
// which the cve label of vexplain_open_case holds.
func TestTheInvestigationInfoSeriesNamesEachVulnerabilityOnce(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, configv1alpha1.AddToScheme(scheme))
	require.NoError(t, triagev1alpha1.AddToScheme(scheme))
	result := func(id string) triagev1alpha1.InvestigationResult {
		return triagev1alpha1.InvestigationResult{VulnerabilityID: id}
	}
	named := &triagev1alpha1.Investigation{ObjectMeta: metav1.ObjectMeta{Namespace: teamD, Name: "named"},
		Spec: triagev1alpha1.InvestigationSpec{Vulnerabilities: []string{"cve-2026-0001", "GHSA-aaaa-bbbb-cccc"}},
		Status: triagev1alpha1.InvestigationStatus{Results: []triagev1alpha1.InvestigationResult{
			result("CVE-2026-0001"), result("CVE-2026-0001"), result("CVE-2026-0002")}}}
	all := &triagev1alpha1.Investigation{ObjectMeta: metav1.ObjectMeta{Namespace: teamD, Name: "all"},
		Status: triagev1alpha1.InvestigationStatus{Results: []triagev1alpha1.InvestigationResult{result("CVE-2026-0003")}}}
	api := fake.NewClientBuilder().WithScheme(scheme).WithObjects(named, all).Build()

	series := gatherGauges(t, hub.NewInvestigationsCollector(api, logr.Discard()))["vexplain_investigation_vulnerability_info"]

	info := func(inv, cve string) map[string]string {
		return map[string]string{clusterLabel: settings.DefaultClusterName, "namespace": teamD, "investigation": inv,
			"cve": cve, valueKey: "1"}
	}
	require.ElementsMatch(t, []map[string]string{info("named", "CVE-2026-0001"), info("named", "GHSA-aaaa-bbbb-cccc"),
		info("named", "CVE-2026-0002"), info("all", "CVE-2026-0003")}, series)

	require.NoError(t, api.Delete(t.Context(), named))
	series = gatherGauges(t, hub.NewInvestigationsCollector(api, logr.Discard()))["vexplain_investigation_vulnerability_info"]
	require.ElementsMatch(t, []map[string]string{info("all", "CVE-2026-0003")}, series, "an investigation that goes has no series")
}

// describeOp is the operation of the collector vulnerabilities that describes a vulnerability.
const describeOp = "describe"

// teamD is the namespace of the investigations of the metrics tests.
const teamD = "team-d"

// describePool is the collector vulnerabilities with its operation describe, which answers that the case's package has
// the fix, as the database says of a distribution's backport.
type describePool struct{}

func (describePool) Capabilities(context.Context, string) (*collectorv1alpha1.GetCapabilitiesResponse, error) {
	return &collectorv1alpha1.GetCapabilitiesResponse{Operations: []*collectorv1alpha1.Operation{{Name: describeOp,
		Description: "Describes a vulnerability from the vulnerability database.", Role: collectorv1alpha1.Role_ROLE_HUB,
		Produces: []string{sdkevidence.TypeDescription}, ParameterSchema: []byte(`{"type":"object"}`)}}}, nil
}

func (describePool) Invoke(context.Context, string, *collectorv1alpha1.InvokeRequest, ...collectorclient.InvokeOption) (
	[]cloudevents.Event, *collectorclient.Failure, error) {
	purl := sbomOf().Packages[0].PURL
	e, err := sdkevidence.New(sdkevidence.TypeDescription, "vulnerability/"+judgedCVE, sdkevidence.Description{
		VulnerabilityID: judgedCVE,
		Packages:        []sdkevidence.DescribedPackage{{Name: exampleName, Version: exampleVersion, Type: deb, PURL: purl}},
		Providers: []sdkevidence.ProviderFix{{Provider: debian, VulnerabilityID: judgedCVE,
			Namespace: "debian:distro:debian:12", Package: "example", FixState: "fixed", FixedVersions: []string{exampleVersion},
			Packages: []sdkevidence.PackageFix{{Name: exampleName, Version: exampleVersion,
				FixedForInstalled: sdkevidence.FixedForInstalledYes}}}},
	}, sdkevidence.WithSource("/hub/collectors/vulnerabilities"))
	return []cloudevents.Event{e}, nil, err
}

// The agent's own write of a validated fixed, on describe's answer that the case's package has the fix, names its
// statement, which the hub's assessor then proposes for review, as its own tests show.
func TestAValidatedFixedNamesItsStatement(t *testing.T) {
	j := newJudging(t, func(r chatRequest) chatAnswer {
		results := 0
		for _, m := range r.Messages {
			if m.Role == "tool" {
				results++
			}
		}
		switch results {
		case 0:
			return callOf("search_tools", map[string]any{"query": describeOp})
		case 1:
			return callOf("vulnerabilities__"+describeOp, map[string]any{"vulnerabilityID": judgedCVE,
				"packages": []sdkevidence.DescribedPackage{{Name: exampleName, Version: exampleVersion, Type: deb,
					PURL: sbomOf().Packages[0].PURL}}})
		}
		args := verdictArgs("fixed")
		args["summary"] = "Debian 12's libexample1 1.0-1 holds the fix (ev-2)."
		args["claims"] = []map[string]any{{"text": "describe says that the installed version has the fix",
			"evidence": []string{"ev-2"}}}
		return callOf("submit_verdict", args)
	})
	j.agent.Pool = describePool{}
	j.agent.ClusterContext = func(context.Context) (*collectorv1alpha1.Context, error) {
		return &collectorv1alpha1.Context{Cluster: "cluster-a"}, nil
	}
	collector := &configv1alpha1.Collector{ObjectMeta: metav1.ObjectMeta{Name: "vulnerabilities"}}
	collector.Status.Capabilities = &configv1alpha1.CollectorCapabilities{Roles: []configv1alpha1.CollectorRole{configv1alpha1.CollectorRoleHub}}
	require.NoError(t, j.api.Create(t.Context(), collector))
	var p configv1alpha1.AgentProfile
	require.NoError(t, j.api.Get(t.Context(), client.ObjectKey{Name: profile.DefaultName}, &p))
	p.Spec.Tools = []configv1alpha1.AgentToolGrant{{Collector: "vulnerabilities", Operations: []string{describeOp}}}
	require.NoError(t, j.api.Update(t.Context(), &p))
	j.setReady(t, &configv1alpha1.AgentProfile{}, metav1.ConditionTrue)
	q, _ := j.start(t)

	j.investigate(t, q)
	require.Eventually(t, j.judged(t), within, often)

	a := j.assessment(t)
	require.NotNil(t, a.Status.Verdict, "the case ended with %+v", a.Status.NoVerdict)
	require.Equal(t, triagev1alpha1.VEXStatusFixed, a.Status.Verdict.Status)
	require.Equal(t, triagev1alpha1.ValidationPassed, a.Status.Validation.Result)
	name := cases.StatementName(a.Name, *a.Status.InputHash, string(triagev1alpha1.VEXStatusFixed), "")
	require.Equal(t, ptr.To(name), a.Status.Verdict.Statement, "the verdict names its statement")
}

// The statements are counted by review: Proposed, Accepted or Rejected, and Superseded for one that no longer stands,
// whatever its review.
func TestTheStatementMetricsCountTheStatementsByReview(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, configv1alpha1.AddToScheme(scheme))
	require.NoError(t, triagev1alpha1.AddToScheme(scheme))
	reviewed := func(name string, state triagev1alpha1.ReviewState, superseded metav1.ConditionStatus) client.Object {
		s := &triagev1alpha1.VexStatement{ObjectMeta: metav1.ObjectMeta{Name: name},
			Spec: triagev1alpha1.VexStatementSpec{Review: &triagev1alpha1.VexStatementReview{State: ptr.To(state)}}}
		meta.SetStatusCondition(&s.Status.Conditions, metav1.Condition{Type: triagev1alpha1.ConditionSuperseded,
			Status: superseded, Reason: "Test"})
		return s
	}
	api := fake.NewClientBuilder().WithScheme(scheme).WithObjects(
		reviewed("a", triagev1alpha1.ReviewStateProposed, metav1.ConditionFalse),
		reviewed("b", triagev1alpha1.ReviewStateAccepted, metav1.ConditionFalse),
		reviewed("c", triagev1alpha1.ReviewStateAccepted, metav1.ConditionTrue),
		&triagev1alpha1.VexStatement{ObjectMeta: metav1.ObjectMeta{Name: "new"}}).Build()

	series := gatherGauges(t, hub.NewVexStatementsCollector(api, logr.Discard()))["vexplain_vex_statements"]

	expected := make([]map[string]string, 0, 4)
	for review, n := range map[string]string{"Proposed": "2", "Accepted": "1", "Rejected": "0", "Superseded": "1"} {
		expected = append(expected, map[string]string{clusterLabel: settings.DefaultClusterName, "review": review, valueKey: n})
	}
	require.ElementsMatch(t, expected, series)
}

// theJudgedCase is the case of the tests, as an investigation hands it over.
var theJudgedCase = cases.Case{ManifestDigest: judgedManifest, VulnerabilityID: judgedCVE,
	Findings: []inventoryv1alpha1.Finding{judgedFinding}, Subject: cases.Subject{ManifestDigest: judgedManifest}}

// A case is judged with the guidance of the investigation that it is charged to, after the profile's guidance, under a
// heading of its own: none when that investigation has none, is gone, is another object of its name, or wants the case
// no more. One that the
// workers' cache doesn't show yet is read from the API server.
func TestTheAgentJudgesACaseWithTheGuidanceOfItsInvestigation(t *testing.T) {
	const guidance = "Only images built with the HTTP/2 module are affected."
	profileOnly := prompt.Core() + "\n\n" + prompt.Guidance()
	withGuidance := profileOnly + "\n\n# This investigation's guidance\n\n" + guidance
	for name, tt := range map[string]struct {
		guidance *string
		// then changes what the case starts with, once it is queued.
		then func(t *testing.T, j *judging, q *hub.APIQueue, inv *triagev1alpha1.Investigation)
		want string
	}{
		"with guidance":    {guidance: ptr.To(guidance), want: withGuidance},
		"without guidance": {want: profileOnly},
		"gone": {guidance: ptr.To(guidance), want: profileOnly,
			then: func(t *testing.T, j *judging, _ *hub.APIQueue, inv *triagev1alpha1.Investigation) {
				require.NoError(t, j.api.Delete(t.Context(), inv))
			}},
		"wanted no more": {guidance: ptr.To(guidance), want: profileOnly,
			then: func(t *testing.T, j *judging, q *hub.APIQueue, _ *triagev1alpha1.Investigation) {
				// Another investigation wants the case too, so it stays queued, charged to the first.
				other := types.NamespacedName{Namespace: judgedInvestigation.Namespace, Name: "other"}
				require.NoError(t, j.api.Create(t.Context(), &triagev1alpha1.Investigation{
					ObjectMeta: metav1.ObjectMeta{Namespace: other.Namespace, Name: other.Name, UID: otherUID},
					Spec: triagev1alpha1.InvestigationSpec{PlaybookRef: triagev1alpha1.PlaybookReference{Name: judgedPlaybook},
						Vulnerabilities: []string{judgedCVE}, Agent: triagev1alpha1.InvestigationAgent{MaxCases: 10}}}))
				j.reconcile(t, q, other)
				q.Keep(judgedInvestigation, nil)
				queue := j.assessment(t).Status.Queue
				require.NotNil(t, queue)
				require.Equal(t, judgedReference, *queue.InvestigationRef)
			}},
		// The queue names an object of the investigation's name that is gone, and the object there now is another one: its
		// guidance isn't that of the object that queued the case.
		"queued by an earlier object of its name": {guidance: ptr.To(guidance), want: profileOnly,
			then: func(t *testing.T, j *judging, _ *hub.APIQueue, _ *triagev1alpha1.Investigation) {
				a := j.assessment(t)
				earlier := judgedReference
				earlier.UID = earlierUID
				a.Status.Queue.InvestigationRef = &earlier
				a.Status.Queue.Requests = []triagev1alpha1.QueueRequest{{InvestigationRef: earlier,
					Trigger: triagev1alpha1.InvestigationTriggerOnce}}
				require.NoError(t, j.api.Status().Update(t.Context(), a))
			}},
		"not in the cache yet": {guidance: ptr.To(guidance), want: withGuidance,
			then: func(t *testing.T, j *judging, _ *hub.APIQueue, _ *triagev1alpha1.Investigation) {
				j.agent.Client = interceptor.NewClient(j.api.(client.WithWatch), interceptor.Funcs{
					Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey, obj client.Object,
						opts ...client.GetOption) error {
						if _, ok := obj.(*triagev1alpha1.Investigation); ok {
							return apierrors.NewNotFound(triagev1alpha1.GroupVersion.WithResource("investigations").GroupResource(),
								key.Name)
						}
						return c.Get(ctx, key, obj, opts...)
					},
				})
			}},
	} {
		t.Run(name, func(t *testing.T) {
			var system atomic.Pointer[string]
			j := newJudging(t, func(r chatRequest) chatAnswer {
				if len(r.Messages) > 0 && r.Messages[0].Role == "system" {
					system.Store(r.Messages[0].Content)
				}
				return searchThenAffected(r)
			})
			inv := j.investigation(t)
			inv.Spec.Agent.Guidance = tt.guidance
			require.NoError(t, j.api.Update(t.Context(), inv))
			q := j.queue()
			j.investigate(t, q)
			if tt.then != nil {
				tt.then(t, j, q, inv)
			}

			j.run(t)
			require.Eventually(t, j.judged(t), within, often)

			require.NotNil(t, system.Load())
			require.Equal(t, tt.want, *system.Load())
		})
	}
}

// The validator checks the verdict against the guidance that the case was judged with: a summary that repeats it
// doesn't stand on its own, so the case ends without a verdict once the repair repeats it too.
func TestTheValidatorKnowsTheGuidanceThatTheCaseWasJudgedWith(t *testing.T) {
	const guidance = "Only images built with the HTTP/2 module and the default proxy settings are affected."
	j := newJudging(t, func(r chatRequest) chatAnswer {
		if !r.hasResult() {
			return callOf("search_evidence", searchSBOM)
		}
		args := verdictArgs("affected")
		args["summary"] = "Only images built with the HTTP/2 module and the default proxy settings are affected (ev-1)."
		return callOf("submit_verdict", args)
	})
	before := testutil.ToFloat64(metrics.AgentRejectionsTotal.WithLabelValues(settings.DefaultClusterName, "Explainable"))
	inv := j.investigation(t)
	inv.Spec.Agent.Guidance = ptr.To(guidance)
	require.NoError(t, j.api.Update(t.Context(), inv))
	q := j.queue()
	j.investigate(t, q)

	j.run(t)
	require.Eventually(t, j.judged(t), within, often)

	a := j.assessment(t)
	require.NotNil(t, a.Status.NoVerdict)
	require.Equal(t, ptr.To(triagev1alpha1.NoVerdictValidatorRejected), a.Status.NoVerdict.Reason)
	require.Equal(t, before+2, testutil.ToFloat64(metrics.AgentRejectionsTotal.WithLabelValues(settings.DefaultClusterName,
		"Explainable")), "the verdict and its repair")
}

// investigationSeries returns the values of the agent's series of the investigation, by name and kind, as the
// registry has them, without creating any.
func investigationSeries(t *testing.T, investigation types.NamespacedName) map[string]float64 {
	t.Helper()
	families, err := ctrlmetrics.Registry.Gather()
	require.NoError(t, err)
	got := map[string]float64{}
	for _, family := range families {
		for _, m := range family.Metric {
			labels := map[string]string{}
			for _, l := range m.Label {
				labels[l.GetName()] = l.GetValue()
			}
			if labels["namespace"] == investigation.Namespace && labels["investigation"] == investigation.Name {
				got[strings.TrimSpace(family.GetName()+" "+labels["kind"])] = m.GetCounter().GetValue()
			}
		}
	}
	return got
}

// The tokens and the time of a judgement count for the investigation that it was made for, from 0 once the case
// starts, so that a board's increase() sees the first judgement.
func TestTheTokensAndTheTimeOfAJudgementCountForItsInvestigation(t *testing.T) {
	const read, written, seconds = "vexplain_investigation_agent_tokens_total prompt",
		"vexplain_investigation_agent_tokens_total completion", "vexplain_investigation_agent_seconds_total"
	var atStart atomic.Pointer[map[string]float64]
	j := newJudging(t, func(r chatRequest) chatAnswer {
		if !r.hasResult() {
			got := investigationSeries(t, judgedInvestigation)
			atStart.CompareAndSwap(nil, &got)
		}
		return searchThenAffected(r)
	})
	// Earlier tests of the package counted for the same investigation: without its series, the start shows them made.
	ns, name := judgedInvestigation.Namespace, judgedInvestigation.Name
	metrics.InvestigationAgentTokensTotal.DeleteLabelValues(settings.DefaultClusterName, ns, name, "prompt")
	metrics.InvestigationAgentTokensTotal.DeleteLabelValues(settings.DefaultClusterName, ns, name, "completion")
	metrics.InvestigationAgentSecondsTotal.DeleteLabelValues(settings.DefaultClusterName, ns, name)
	before := investigationSeries(t, judgedInvestigation)
	require.Empty(t, before)
	q := j.queue()
	j.investigate(t, q)

	j.run(t)
	require.Eventually(t, j.judged(t), within, often)

	require.NotNil(t, atStart.Load())
	started := *atStart.Load()
	for _, series := range []string{read, written, seconds} {
		require.Contains(t, started, series, "the series exists before the first count")
		require.Equal(t, before[series], started[series])
	}
	after := investigationSeries(t, judgedInvestigation)
	require.Equal(t, before[read]+20, after[read], "two requests of 10 prompt tokens")
	require.Equal(t, before[written]+10, after[written])
	require.Greater(t, after[seconds], before[seconds])
}

// The judgement counts for the investigation that its cap is charged to, also once that investigation wants the case
// no more and another keeps it queued.
func TestAJudgementCountsForTheInvestigationItIsChargedTo(t *testing.T) {
	const read = "vexplain_investigation_agent_tokens_total prompt"
	j := newJudging(t, searchThenAffected)
	before := investigationSeries(t, judgedInvestigation)
	q := j.queue()
	j.investigate(t, q)
	other := types.NamespacedName{Namespace: judgedInvestigation.Namespace, Name: "other"}
	require.NoError(t, j.api.Create(t.Context(), &triagev1alpha1.Investigation{
		ObjectMeta: metav1.ObjectMeta{Namespace: other.Namespace, Name: other.Name, UID: "uid-other"},
		Spec: triagev1alpha1.InvestigationSpec{PlaybookRef: triagev1alpha1.PlaybookReference{Name: judgedPlaybook},
			Vulnerabilities: []string{judgedCVE}, Agent: triagev1alpha1.InvestigationAgent{MaxCases: 10}}}))
	j.reconcile(t, q, other)
	q.Keep(judgedInvestigation, nil)
	otherBefore := investigationSeries(t, other)

	j.run(t)
	require.Eventually(t, j.judged(t), within, often)

	require.Equal(t, before[read]+20, investigationSeries(t, judgedInvestigation)[read])
	require.Equal(t, otherBefore[read], investigationSeries(t, other)[read], "the investigation that kept it queued spent nothing")
}

// A recreated investigation takes over the charge of a case that the earlier object of its name queued and that waits
// unclaimed: it is charged once, against its own cap, and the case is judged with its guidance.
func TestARecreatedInvestigationTakesOverItsCaseThatWaits(t *testing.T) {
	const guidance, recreatedUID = "Only images built with the HTTP/2 module are affected.", types.UID("uid-recreated")
	var system atomic.Pointer[string]
	j := newJudging(t, func(r chatRequest) chatAnswer {
		if len(r.Messages) > 0 && r.Messages[0].Role == "system" {
			system.Store(r.Messages[0].Content)
		}
		return searchThenAffected(r)
	})
	q := j.queue()
	j.investigate(t, q)
	require.Equal(t, int32(1), j.charged(t))

	earlier := j.investigation(t)
	require.NoError(t, j.api.Delete(t.Context(), earlier))
	recreated := &triagev1alpha1.Investigation{ObjectMeta: metav1.ObjectMeta{Namespace: earlier.Namespace,
		Name: earlier.Name, UID: recreatedUID}, Spec: earlier.Spec}
	recreated.Spec.Agent.Guidance = ptr.To(guidance)
	require.NoError(t, j.api.Create(t.Context(), recreated))
	j.reconcile(t, q, judgedInvestigation)

	require.Equal(t, int32(1), j.charged(t), "the recreated investigation is charged for the case that it took over")
	require.Equal(t, recreatedUID, j.assessment(t).Status.Queue.InvestigationRef.UID)
	j.reconcile(t, q, judgedInvestigation)
	require.Equal(t, int32(1), j.charged(t), "once")

	j.run(t)
	require.Eventually(t, j.judged(t), within, often)
	require.NotNil(t, system.Load())
	require.Contains(t, *system.Load(), guidance)
	require.Equal(t, recreatedUID, j.assessment(t).Status.InvestigationRef.UID)
}

// A read of the guidance that doesn't end, as from a cache that can't list Investigations, is cut off: the case waits,
// and no token is spent.
func TestAGuidanceReadThatDoesntEndLeavesTheCaseWaiting(t *testing.T) {
	j := newJudging(t, searchThenAffected)
	j.investigate(t, j.queue())
	agent := *j.agent
	agent.GuidanceTimeout = 50 * time.Millisecond
	agent.Client = interceptor.NewClient(j.api.(client.WithWatch), interceptor.Funcs{
		Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
			if _, ok := obj.(*triagev1alpha1.Investigation); ok {
				<-ctx.Done()
				return ctx.Err()
			}
			return c.Get(ctx, key, obj, opts...)
		},
	})

	ctx := j.claimed(t)
	require.Equal(t, worker.Wait, agent.Judge(ctx, theJudgedCase, theRequest, 0))
	require.Zero(t, j.model.requests.Load())
}

// The queue spends no tokens on a case that no investigation wants any more: one whose investigation went, or was
// disabled, leaves the queue unjudged.
func TestTheCaseOfADeletedOrDisabledInvestigationIsNotJudged(t *testing.T) {
	for name, drop := range map[string]func(*testing.T, *judging){
		"deleted": func(t *testing.T, j *judging) {
			require.NoError(t, j.api.Delete(t.Context(), &triagev1alpha1.Investigation{ObjectMeta: metav1.ObjectMeta{
				Namespace: judgedInvestigation.Namespace, Name: judgedInvestigation.Name}}))
		},
		"disabled": func(t *testing.T, j *judging) {
			var inv triagev1alpha1.Investigation
			require.NoError(t, j.api.Get(t.Context(), judgedInvestigation, &inv))
			inv.Spec.State = ptr.To(triagev1alpha1.InvestigationStateDisabled)
			require.NoError(t, j.api.Update(t.Context(), &inv))
		},
	} {
		t.Run(name, func(t *testing.T) {
			j := newJudging(t, searchThenAffected)
			q := j.queue()
			j.investigate(t, q)
			queued, _ := q.Pending(judgedInvestigation, judgedUID)
			require.Equal(t, 1, queued)

			drop(t, j)
			j.investigate(t, q)

			queued, inProgress := q.Pending(judgedInvestigation, judgedUID)
			require.Zero(t, queued+inProgress, "the investigation wants the case no more")
			j.run(t)
			require.Never(t, j.judged(t), 300*time.Millisecond, often)
			require.Zero(t, j.model.requests.Load(), "no token is spent on it")
		})
	}
}

// A case waits while its findings change: it is judged on those of its last hand-over, and its inputHash is theirs.
func TestACaseIsJudgedOnTheFindingsOfItsLastHandOver(t *testing.T) {
	j := newJudging(t, searchThenAffected)
	j.setReady(t, &configv1alpha1.ModelConfig{}, metav1.ConditionFalse)
	q, _ := j.start(t)
	j.investigate(t, q)

	changed := judgedFinding
	changed.Package.Version = ptr.To("1.0-2")
	require.NoError(t, j.verdicts.Put(t.Context(), judgedManifest, judgedPlaybook, inventoryv1alpha1.ImageVerdictsStatus{
		Playbook: ptr.To(judgedPlaybook), FindingsVersion: ptr.To(v1), Findings: []inventoryv1alpha1.Finding{changed},
		Evidence: []inventoryv1alpha1.SheetEvidence{{Name: sbomName, Source: scanner, Type: sdkevidence.TypeSBOM,
			Version: ptr.To(v1)}},
	}))
	j.investigate(t, q)
	j.setReady(t, &configv1alpha1.ModelConfig{}, metav1.ConditionTrue)

	require.Eventually(t, j.judged(t), within, often)
	require.Equal(t, cases.InputHash([]inventoryv1alpha1.Finding{changed}, map[string][]string{sbomName: {sbomHash(t, j)}}),
		ptr.Deref(j.assessment(t).Status.InputHash, ""), "judged on the newer findings")
	queued, inProgress := q.Pending(judgedInvestigation, judgedUID)
	require.Zero(t, queued+inProgress)
}

// A case that its Assessment shows judged on its current inputs, as when an investigation queued it again from a cache
// that hadn't seen the outcome yet, isn't judged twice.
func TestACaseThatHoldsItsOutcomeAlreadyIsNotJudgedAgain(t *testing.T) {
	j := newJudging(t, searchThenAffected)
	q, _ := j.start(t)
	j.investigate(t, q)
	require.Eventually(t, j.judged(t), within, often)
	judgedAt := j.assessment(t).Status.JudgedTime
	requests := j.model.requests.Load()

	require.True(t, q.Add(theJudgedCase, cases.Request{Investigation: judgedInvestigation, InvestigationUID: judgedUID, Playbook: judgedPlaybook}))

	require.Eventually(t, func() bool { a, b := q.Pending(judgedInvestigation, judgedUID); return a+b == 0 }, within, often)
	require.Equal(t, requests, j.model.requests.Load(), "no model call")
	require.Equal(t, judgedAt, j.assessment(t).Status.JudgedTime)
}

// The playbook of a case's case file can go, lose its agent section or its sheet of the manifest: the case is then
// judged with the playbook of an investigation that wants it, which its Assessment records as its case-file playbook.
func TestACaseFallsBackToThePlaybookOfAnInvestigationThatWantsIt(t *testing.T) {
	const gone = "gone-cves"
	j := newJudging(t, searchThenAffected)
	a := &triagev1alpha1.Assessment{ObjectMeta: metav1.ObjectMeta{Name: cases.Name(judgedCVE, judgedManifest),
		Labels: cases.Labels(judgedCVE, judgedManifest)},
		Spec: triagev1alpha1.AssessmentSpec{Subject: triagev1alpha1.AssessmentSubject{
			Type: triagev1alpha1.SubjectTypeContainerImage, ContainerImage: &triagev1alpha1.ContainerImageSubject{Digest: judgedManifest}},
			VulnerabilityID: judgedCVE}}
	require.NoError(t, j.api.Create(t.Context(), a))
	a.Status.CaseFilePlaybook, a.Status.Playbooks = ptr.To(gone), []string{gone}
	require.NoError(t, j.api.Status().Update(t.Context(), a))
	q, _ := j.start(t)

	j.investigate(t, q)

	require.Eventually(t, j.judged(t), within, often, "not stuck on a playbook that is gone")
	got := j.assessment(t)
	require.NotNil(t, got.Status.Verdict)
	require.Equal(t, judgedPlaybook, ptr.Deref(got.Status.CaseFilePlaybook, ""), "the playbook that served the case")
	requests := j.model.requests.Load()
	j.investigate(t, q)
	queued, inProgress := q.Pending(judgedInvestigation, judgedUID)
	require.Zero(t, queued+inProgress, "the investigation reuses the verdict")
	require.Equal(t, requests, j.model.requests.Load())
}

// A request that fails for the endpoint's sake hands the case back to the queue, with nothing written, to be tried again
// later; a request that the endpoint refuses as such ends the case without a verdict.
func TestAFailedModelRequestHandsTheCaseBackOrEndsIt(t *testing.T) {
	for _, status := range []int{http.StatusServiceUnavailable, http.StatusTooManyRequests, http.StatusUnauthorized,
		http.StatusNotFound} {
		t.Run(fmt.Sprintf("HTTP %d hands it back", status), func(t *testing.T) {
			j := newJudging(t, func(chatRequest) chatAnswer { return chatAnswer{status: status} })
			q, _ := j.start(t)
			j.investigate(t, q)

			require.Eventually(t, func() bool { return j.model.requests.Load() > 0 }, within, often)
			require.Eventually(t, func() bool { return readyOfAssessment(j.assessment(t)).Reason == triagev1alpha1.ReasonQueued },
				within, often)
			require.Never(t, j.judged(t), 200*time.Millisecond, often)
			queued, inProgress := q.Pending(judgedInvestigation, judgedUID)
			require.Equal(t, 1, queued+inProgress, "it stays in the queue")
			require.Nil(t, j.assessment(t).Status.InputHash)
			require.Nil(t, j.ledger(t))
		})
	}

	t.Run("HTTP 400 ends it", func(t *testing.T) {
		j := newJudging(t, func(chatRequest) chatAnswer { return chatAnswer{status: http.StatusBadRequest} })
		q, _ := j.start(t)
		j.investigate(t, q)

		require.Eventually(t, j.judged(t), within, often)
		a := j.assessment(t)
		require.NotNil(t, a.Status.NoVerdict)
		require.Equal(t, ptr.To(triagev1alpha1.NoVerdictModelError), a.Status.NoVerdict.Reason)
		require.NotNil(t, a.Status.InputHash)
		require.Equal(t, int32(1), j.model.requests.Load())
	})
}

// The changedSheet writes the sheet with the finding of another package version, and returns the finding.
func (j *judging) changedSheet(t *testing.T) inventoryv1alpha1.Finding {
	t.Helper()
	changed := judgedFinding
	changed.Package.Version = ptr.To("1.0-2")
	require.NoError(t, j.verdicts.Put(t.Context(), judgedManifest, judgedPlaybook, inventoryv1alpha1.ImageVerdictsStatus{
		Playbook: ptr.To(judgedPlaybook), FindingsVersion: ptr.To(v1), Findings: []inventoryv1alpha1.Finding{changed},
		Evidence: []inventoryv1alpha1.SheetEvidence{{Name: sbomName, Source: scanner, Type: sdkevidence.TypeSBOM,
			Version: ptr.To(v1)}},
	}))
	return changed
}

// At its cap, an investigation still hands over the case that it holds, so the case waits on its current findings.
func TestAtTheCapAWaitingCaseIsJudgedOnItsCurrentFindings(t *testing.T) {
	j := newJudging(t, searchThenAffected)
	j.capAtOne(t)
	j.setReady(t, &configv1alpha1.ModelConfig{}, metav1.ConditionFalse)
	q, _ := j.start(t)
	j.investigate(t, q)
	require.Equal(t, int32(1), j.charged(t))

	changed := j.changedSheet(t)
	j.investigate(t, q)
	j.setReady(t, &configv1alpha1.ModelConfig{}, metav1.ConditionTrue)

	require.Eventually(t, j.judged(t), within, often)
	require.Equal(t, cases.InputHash([]inventoryv1alpha1.Finding{changed}, map[string][]string{sbomName: {sbomHash(t, j)}}),
		ptr.Deref(j.assessment(t).Status.InputHash, ""), "judged on the newer findings")
	require.Equal(t, int32(1), j.charged(t), "a case handed over again isn't charged again")
}

// Design 5.11: switched off, the agent keeps the cases that wait; switched on, it judges them, without charging the cap
// again, and a run at its cap completes.
func TestAtTheCapTheAgentSwitchedOffAndOnJudgesTheWaitingCaseOnce(t *testing.T) {
	j := newJudging(t, searchThenAffected)
	j.capAtOne(t)
	j.setReady(t, &configv1alpha1.ModelConfig{}, metav1.ConditionFalse)
	j.switchAgentTo(t, configv1alpha1.AgentStateEnabled)
	q, _ := j.start(t)
	j.investigate(t, q)
	queued, inProgress := q.Pending(judgedInvestigation, judgedUID)
	require.Equal(t, 1, queued+inProgress)

	j.switchAgentTo(t, configv1alpha1.AgentStateDisabled)
	j.investigate(t, q)
	queued, inProgress = q.Pending(judgedInvestigation, judgedUID)
	require.Equal(t, 1, queued+inProgress, "switched off, the agent keeps the case waiting")
	require.Equal(t, triagev1alpha1.ReasonAgentDisabled, readyReasonOf(j.investigation(t).Status.Conditions))

	j.switchAgentTo(t, configv1alpha1.AgentStateEnabled)
	j.investigate(t, q)
	queued, inProgress = q.Pending(judgedInvestigation, judgedUID)
	require.Equal(t, 1, queued+inProgress)
	j.setReady(t, &configv1alpha1.ModelConfig{}, metav1.ConditionTrue)
	require.Eventually(t, j.judged(t), within, often)
	j.investigate(t, q)

	inv := j.investigation(t)
	require.Equal(t, int32(1), j.charged(t), "charged once")
	require.NotNil(t, inv.Status.CompletionTime, "the run completes")
	require.Equal(t, triagev1alpha1.ReasonJudged, readyReasonOf(inv.Status.Conditions))
}

// After a restart, an investigation at its cap queues the case that it holds again, without charging it again.
func TestARestartAtTheCapQueuesTheHeldCaseAgain(t *testing.T) {
	var holding atomic.Bool
	holding.Store(true)
	j := newJudging(t, func(r chatRequest) chatAnswer {
		if r.hasResult() && holding.Load() {
			return chatAnswer{hold: true}
		}
		return searchThenAffected(r)
	})
	j.capAtOne(t)
	before, stop := j.start(t)
	j.investigate(t, before)
	require.Eventually(t, func() bool { return j.model.held.Load() == 1 }, within, often)
	stop()

	holding.Store(false)
	after, _ := j.start(t)
	j.investigate(t, after)

	require.Eventually(t, j.judged(t), within, often, "queued again at the cap")
	require.NotNil(t, j.assessment(t).Status.Verdict)
	require.Equal(t, int32(1), j.charged(t))
}

// Design 5.11: switching the agent off returns a case in progress with nothing written, even while it makes the final
// call of a limit.
func TestSwitchingTheAgentOffDuringTheFinalCallWritesNothing(t *testing.T) {
	var holding atomic.Bool
	holding.Store(true)
	j := newJudging(t, func(r chatRequest) chatAnswer {
		if len(r.Tools) == 0 && holding.Load() {
			return chatAnswer{hold: true}
		}
		if len(r.Tools) == 0 {
			return chatAnswer{text: "The image installs libexample1 (ev-1).\n\nA fixed version would settle it."}
		}
		return callOf("search_evidence", searchSBOM)
	})
	var limited configv1alpha1.AgentProfile
	require.NoError(t, j.api.Get(t.Context(), client.ObjectKey{Name: profile.DefaultName}, &limited))
	limited.Spec.Limits = &configv1alpha1.AgentLimits{MaxSteps: ptr.To(int32(1))}
	require.NoError(t, j.api.Update(t.Context(), &limited))
	j.setReady(t, &configv1alpha1.AgentProfile{}, metav1.ConditionTrue)
	j.switchAgentTo(t, configv1alpha1.AgentStateEnabled)
	q, _ := j.start(t)
	j.investigate(t, q)
	require.Eventually(t, func() bool { return j.model.held.Load() == 1 }, within, often, "the final call goes")

	j.switchAgentTo(t, configv1alpha1.AgentStateDisabled)

	require.Eventually(t, func() bool { return readyOfAssessment(j.assessment(t)).Reason == triagev1alpha1.ReasonQueued },
		within, often, "handed back")
	a := j.assessment(t)
	require.Nil(t, a.Status.Verdict)
	require.Nil(t, a.Status.NoVerdict, "no no-verdict for a limit whose final call the switch cut off")
	require.Nil(t, a.Status.JudgedTime)
	require.Nil(t, j.ledger(t))
	require.Eventually(t, func() bool { return j.hasEvent("AgentDisabled") }, within, often)

	holding.Store(false)
	j.switchAgentTo(t, configv1alpha1.AgentStateEnabled)
	require.Eventually(t, j.judged(t), within, often)
	require.Equal(t, ptr.To(triagev1alpha1.NoVerdictMaxSteps), j.assessment(t).Status.NoVerdict.Reason)
}

// A failure that recurs stops spending the earlier steps' tokens: after five attempts in a row that spent tokens and
// then failed, the case ends without a verdict, ModelError.
func TestFiveFailuresInARowEndTheCaseWithModelError(t *testing.T) {
	j := newJudging(t, func(r chatRequest) chatAnswer {
		if !r.hasResult() {
			return callOf("search_evidence", searchSBOM)
		}
		return chatAnswer{status: http.StatusServiceUnavailable}
	})
	q, _ := j.start(t)
	j.investigate(t, q)

	require.Eventually(t, j.judged(t), within, often)
	a := j.assessment(t)
	require.NotNil(t, a.Status.NoVerdict)
	require.Equal(t, ptr.To(triagev1alpha1.NoVerdictModelError), a.Status.NoVerdict.Reason)
	require.Contains(t, a.Status.NoVerdict.Summary, "5 times")
	require.NotNil(t, a.Status.InputHash)
	require.Equal(t, int32(10), j.model.requests.Load(), "five attempts, each a step and a failure")
	queued, inProgress := q.Pending(judgedInvestigation, judgedUID)
	require.Zero(t, queued+inProgress)
}

// An endpoint that is down, or refuses the key, from the first request on spends no token: the case waits, with a
// backoff, and is never ended for it.
func TestAnEndpointDownFromTheFirstRequestNeverEndsTheCase(t *testing.T) {
	j := newJudging(t, func(chatRequest) chatAnswer { return chatAnswer{status: http.StatusServiceUnavailable} })
	q, _ := j.start(t)
	j.investigate(t, q)

	require.Eventually(t, func() bool { return j.model.requests.Load() > 6 }, within, often, "more attempts than five")
	require.False(t, j.judged(t)())
	queued, inProgress := q.Pending(judgedInvestigation, judgedUID)
	require.Equal(t, 1, queued+inProgress)
	require.Equal(t, triagev1alpha1.ReasonQueued, readyOfAssessment(j.assessment(t)).Reason)
}

// A case whose Assessment the cache doesn't show yet waits: only the read from the API server says that it is gone.
func TestACaseThatTheCacheDoesntShowYetWaits(t *testing.T) {
	j := newJudging(t, searchThenAffected)
	j.investigate(t, j.queue())
	var hidden atomic.Bool
	hidden.Store(true)
	lagging := interceptor.NewClient(j.api.(client.WithWatch), interceptor.Funcs{
		Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
			if _, ok := obj.(*triagev1alpha1.Assessment); ok && hidden.Load() {
				return apierrors.NewNotFound(triagev1alpha1.GroupVersion.WithResource("assessments").GroupResource(), key.Name)
			}
			return c.Get(ctx, key, obj, opts...)
		},
	})
	agent := *j.agent
	agent.Client = lagging
	request := cases.Request{Investigation: judgedInvestigation, InvestigationUID: judgedUID, Playbook: judgedPlaybook}

	ctx := j.claimed(t)
	require.Equal(t, worker.Wait, agent.Judge(ctx, theJudgedCase, request, 0))
	require.Zero(t, j.model.requests.Load())

	hidden.Store(false)
	require.Equal(t, worker.Done, agent.Judge(ctx, theJudgedCase, request, 0))
	require.NotNil(t, j.assessment(t).Status.Verdict)
}

// A case that left the queue because no investigation wanted it any more is withdrawn: an investigation that selects it
// later doesn't take it for one that it holds, and charges it as a new one.
func TestAWithdrawnCaseIsChargedAsANewOne(t *testing.T) {
	const other = "CVE-2026-0041"
	j := newJudging(t, searchThenAffected)
	j.setReady(t, &configv1alpha1.ModelConfig{}, metav1.ConditionFalse)
	otherFinding := judgedFinding
	otherFinding.VulnerabilityID, otherFinding.Aliases = other, nil
	otherFinding.Package = inventoryv1alpha1.PackageReference{ID: otherPackage, Name: otherName, Version: ptr.To(otherVersion),
		Type: deb}
	require.NoError(t, j.verdicts.Put(t.Context(), judgedManifest, judgedPlaybook, inventoryv1alpha1.ImageVerdictsStatus{
		Playbook: ptr.To(judgedPlaybook), FindingsVersion: ptr.To(v1),
		Findings: []inventoryv1alpha1.Finding{otherFinding, judgedFinding},
		Evidence: []inventoryv1alpha1.SheetEvidence{{Name: sbomName, Source: scanner, Type: sdkevidence.TypeSBOM,
			Version: ptr.To(v1)}},
	}))
	both := types.NamespacedName{Namespace: judgedInvestigation.Namespace, Name: "both"}
	gone := types.NamespacedName{Namespace: judgedInvestigation.Namespace, Name: "gone"}
	for key, spec := range map[types.NamespacedName]triagev1alpha1.InvestigationSpec{
		both: {PlaybookRef: triagev1alpha1.PlaybookReference{Name: judgedPlaybook}, Vulnerabilities: []string{other, judgedCVE},
			Agent: triagev1alpha1.InvestigationAgent{MaxCases: 1}},
		gone: {PlaybookRef: triagev1alpha1.PlaybookReference{Name: judgedPlaybook}, Vulnerabilities: []string{judgedCVE},
			Agent: triagev1alpha1.InvestigationAgent{MaxCases: 10}},
	} {
		require.NoError(t, j.api.Create(t.Context(), &triagev1alpha1.Investigation{
			ObjectMeta: metav1.ObjectMeta{Namespace: key.Namespace, Name: key.Name, UID: "uid-" + types.UID(key.Name)}, Spec: spec}))
	}
	q := j.queue()

	// An investigation queues the case, and goes.
	j.reconcile(t, q, gone)
	require.NoError(t, j.api.Delete(t.Context(), &triagev1alpha1.Investigation{
		ObjectMeta: metav1.ObjectMeta{Namespace: gone.Namespace, Name: gone.Name}}))
	j.reconcile(t, q, gone)
	require.Equal(t, triagev1alpha1.ReasonWithdrawn, readyOfAssessment(j.assessment(t)).Reason)

	// An investigation at its cap selects it.
	j.reconcile(t, q, both)
	queued, inProgress := q.Pending(both, "uid-both")
	require.Equal(t, 1, queued+inProgress, "only the case that its cap had room for")
	var inv triagev1alpha1.Investigation
	require.NoError(t, j.api.Get(t.Context(), both, &inv))
	require.Equal(t, ptr.To(int32(1)), inv.Status.Cases.Charged)
	require.Equal(t, triagev1alpha1.ReasonWithdrawn, readyOfAssessment(j.assessment(t)).Reason, "not handed over")

	// An investigation with room charges it as a new case.
	fresh := types.NamespacedName{Namespace: judgedInvestigation.Namespace, Name: "fresh"}
	require.NoError(t, j.api.Create(t.Context(), &triagev1alpha1.Investigation{
		ObjectMeta: metav1.ObjectMeta{Namespace: fresh.Namespace, Name: fresh.Name, UID: "uid-fresh"},
		Spec: triagev1alpha1.InvestigationSpec{PlaybookRef: triagev1alpha1.PlaybookReference{Name: judgedPlaybook},
			Vulnerabilities: []string{judgedCVE}, Agent: triagev1alpha1.InvestigationAgent{MaxCases: 1}}}))
	j.reconcile(t, q, fresh)
	queued, inProgress = q.Pending(fresh, "uid-fresh")
	require.Equal(t, 1, queued+inProgress)
	require.NoError(t, j.api.Get(t.Context(), fresh, &inv))
	require.Equal(t, ptr.To(int32(1)), inv.Status.Cases.Charged, "the withdrawn case is charged")
	require.Equal(t, triagev1alpha1.ReasonQueued, readyOfAssessment(j.assessment(t)).Reason, "and held again")
}

// With the agent off, an investigation still hands over the cases that it holds, so that they wait on their current
// findings, and the queue judges them on those once the agent is on again.
func TestWithTheAgentOffAHeldCaseTakesItsCurrentFindings(t *testing.T) {
	j := newJudging(t, searchThenAffected)
	j.capAtOne(t)
	j.setReady(t, &configv1alpha1.ModelConfig{}, metav1.ConditionFalse)
	j.switchAgentTo(t, configv1alpha1.AgentStateEnabled)
	q, _ := j.start(t)
	j.investigate(t, q)

	j.switchAgentTo(t, configv1alpha1.AgentStateDisabled)
	j.investigate(t, q)
	changed := j.changedSheet(t)
	j.investigate(t, q)
	j.switchAgentTo(t, configv1alpha1.AgentStateEnabled)
	j.setReady(t, &configv1alpha1.ModelConfig{}, metav1.ConditionTrue)

	require.Eventually(t, j.judged(t), within, often, "the queue judges it before the investigation reconciles again")
	require.Equal(t, cases.InputHash([]inventoryv1alpha1.Finding{changed}, map[string][]string{sbomName: {sbomHash(t, j)}}),
		ptr.Deref(j.assessment(t).Status.InputHash, ""), "judged on the newer findings")
	require.Equal(t, int32(1), j.charged(t))
}

// A case whose Assessment holds the outcome of its current inputs already isn't judged again, and the Assessment says
// that it is judged: one left Queued would stay held, and its investigation would wait for it.
func TestAnOutcomeWrittenAlreadyLeavesTheCaseJudged(t *testing.T) {
	j := newJudging(t, searchThenAffected)
	j.investigate(t, j.queue())
	ctx := j.claimed(t)
	require.Equal(t, worker.Done, j.agent.Judge(ctx, theJudgedCase, theRequest, 0))
	requests := j.model.requests.Load()
	// An investigation queues it again, as when it selected the case before the outcome was written.
	a := j.assessment(t)
	meta.SetStatusCondition(&a.Status.Conditions, metav1.Condition{Type: configv1alpha1.ConditionReady,
		Status: metav1.ConditionFalse, Reason: triagev1alpha1.ReasonQueued, Message: "The case waits for the agent."})
	require.NoError(t, j.api.Status().Update(t.Context(), a))

	require.Equal(t, worker.Done, j.agent.Judge(ctx, theJudgedCase, theRequest, 0))

	require.Equal(t, requests, j.model.requests.Load(), "not judged again")
	ready := readyOfAssessment(j.assessment(t))
	require.Equal(t, metav1.ConditionTrue, ready.Status)
	require.Equal(t, triagev1alpha1.ReasonJudged, ready.Reason)
	j.queue().Sweep(t.Context())
	require.Equal(t, triagev1alpha1.ReasonJudged, readyOfAssessment(j.assessment(t)).Reason, "the sweep leaves it")
}

// conflictOnce returns a client of j's API server whose first status update of an object that fails says so fails
// with a conflict, as when the object changed since it was read.
func (j *judging) conflictOnce(fails func(client.Object) bool) client.Client {
	var done atomic.Bool
	return interceptor.NewClient(j.api.(client.WithWatch), interceptor.Funcs{
		SubResourceUpdate: func(ctx context.Context, c client.Client, sub string, obj client.Object,
			opts ...client.SubResourceUpdateOption) error {
			if fails(obj) && done.CompareAndSwap(false, true) {
				return apierrors.NewConflict(triagev1alpha1.GroupVersion.WithResource("objects").GroupResource(),
					obj.GetName(), errors.New("the object changed"))
			}
			return c.SubResource(sub).Update(ctx, obj, opts...)
		},
	})
}

// A reconcile whose status write conflicts after the queue took a case keeps the case's charge: the next reconcile
// finds the case held, and doesn't charge it, so its room isn't spent again.
func TestAChargeOutlivesAStatusWriteThatConflicts(t *testing.T) {
	j := newJudging(t, searchThenAffected)
	q := j.queue()
	r := j.reconciler(q, j.conflictOnce(func(obj client.Object) bool {
		_, ok := obj.(*triagev1alpha1.Investigation)
		return ok
	}))

	_, err := r.Reconcile(t.Context(), ctrl.Request{NamespacedName: judgedInvestigation})

	require.Error(t, err)
	require.Equal(t, int32(1), j.charged(t), "the charge of the case that the queue took is kept")
	j.investigate(t, q)
	require.Equal(t, int32(1), j.charged(t), "and the held case isn't charged again")
}

// A case that an earlier version held, Queued or Judging without a queue, outlives the manager's start: the first sweep
// waits, and the investigation's first reconcile queues the case again, held, without charging it a second time.
// Withdrawn first, the case would be charged again, past the cap of an investigation that used it up.
func TestTheFirstSweepWaitsForTheInvestigationsToQueueHeldCasesAgain(t *testing.T) {
	j := newJudging(t, searchThenAffected)
	j.investigate(t, j.queue())
	require.Equal(t, int32(1), j.charged(t))
	a := j.assessment(t)
	a.Status.Queue, a.Status.Claim = nil, nil
	meta.SetStatusCondition(&a.Status.Conditions, metav1.Condition{Type: configv1alpha1.ConditionReady,
		Status: metav1.ConditionFalse, Reason: triagev1alpha1.ReasonJudging, Message: "Left by an earlier version."})
	require.NoError(t, j.api.Status().Update(t.Context(), a))
	clock := clocktesting.NewFakeClock(time.Now())
	q := &hub.APIQueue{Client: j.api, APIReader: j.api, Clock: clock}
	ctx, cancel := context.WithCancel(t.Context())
	swept := make(chan error, 1)
	go func() { swept <- q.Sweeps(ctx) }()
	t.Cleanup(func() {
		cancel()
		require.NoError(t, <-swept)
	})
	withdrawn := func() bool { return readyOfAssessment(j.assessment(t)).Reason == triagev1alpha1.ReasonWithdrawn }

	require.Never(t, withdrawn, quiet, often, "the manager's start sweeps nothing yet")
	require.Eventually(t, clock.HasWaiters, within, often, "the first sweep waits")
	j.investigate(t, q)

	a = j.assessment(t)
	require.NotNil(t, a.Status.Queue, "queued again")
	require.Equal(t, triagev1alpha1.ReasonQueued, readyOfAssessment(a).Reason)
	require.Equal(t, int32(1), j.charged(t), "and not charged again")
	clock.Step(90 * time.Second)
	require.Never(t, withdrawn, quiet, often, "the first sweep leaves the case queued")
}

// A reconcile that fails at a later case, after the queue took an earlier one, keeps the earlier one's charge.
func TestAChargeOutlivesAConflictAtALaterCase(t *testing.T) {
	j := newJudging(t, searchThenAffected)
	const other = "CVE-2026-0043"
	second := judgedFinding
	second.VulnerabilityID, second.Aliases = other, nil
	require.NoError(t, j.verdicts.Put(t.Context(), judgedManifest, judgedPlaybook, inventoryv1alpha1.ImageVerdictsStatus{
		Playbook: ptr.To(judgedPlaybook), FindingsVersion: ptr.To(v1), Findings: []inventoryv1alpha1.Finding{judgedFinding, second},
		Evidence: []inventoryv1alpha1.SheetEvidence{{Name: sbomName, Source: scanner, Type: sdkevidence.TypeSBOM,
			Version: ptr.To(v1)}},
	}))
	inv := j.investigation(t)
	inv.Spec.Vulnerabilities = []string{judgedCVE, other}
	require.NoError(t, j.api.Update(t.Context(), inv))
	q := j.queue()
	// The first case's Assessment takes Queued, and the second's write conflicts.
	var assessments atomic.Int32
	r := j.reconciler(q, j.conflictOnce(func(obj client.Object) bool {
		_, ok := obj.(*triagev1alpha1.Assessment)
		return ok && assessments.Add(1) == 2
	}))

	_, err := r.Reconcile(t.Context(), ctrl.Request{NamespacedName: judgedInvestigation})

	require.Error(t, err)
	require.Equal(t, int32(1), j.charged(t), "the charge of the case that the queue took is kept")
	j.investigate(t, q)
	require.Equal(t, int32(2), j.charged(t), "the held case isn't charged again, and the other is charged once")
}

// A condition that fails on the cases, as one on EPSS of findings without it, says so in the Ready condition: how many
// cases it skipped, and the first error, with the condition's name.
func TestAConditionThatFailsNamesItsErrorInTheReadyCondition(t *testing.T) {
	j := newJudging(t, searchThenAffected)
	inv := j.investigation(t)
	inv.Spec.MatchConditions = []triagev1alpha1.MatchCondition{{Name: "likely", Expression: "finding.epssPermille >= 100"}}
	require.NoError(t, j.api.Update(t.Context(), inv))

	j.investigate(t, j.queue())

	ready := meta.FindStatusCondition(j.investigation(t).Status.Conditions, configv1alpha1.ConditionReady)
	require.NotNil(t, ready)
	require.Contains(t, ready.Message, "1 cases are skipped because a condition failed on them")
	require.Contains(t, ready.Message, `the condition "likely" failed`)
	require.Contains(t, ready.Message, "epssPermille")
}

// Every reconcile of an investigation comes back within 5 minutes, so that its impact follows the inventory, which it
// doesn't watch: a Once run that is over shows its impact again, and queues nothing.
func TestAnInvestigationIsReconciledAgainWithinFiveMinutes(t *testing.T) {
	j := newJudging(t, searchThenAffected)
	for _, trigger := range []triagev1alpha1.InvestigationTrigger{{Type: triagev1alpha1.InvestigationTriggerOnce},
		{Type: triagev1alpha1.InvestigationTriggerContinuous},
		{Type: triagev1alpha1.InvestigationTriggerSchedule, Schedule: ptr.To("0 0 1 1 *")}} {
		inv := j.investigation(t)
		inv.Spec.Trigger = &trigger
		require.NoError(t, j.api.Update(t.Context(), inv))

		// A queue of its own for each, with nothing pending, so that no tick is skipped.
		res, err := j.reconciler(idleQueue{}, j.api).Reconcile(t.Context(), ctrl.Request{NamespacedName: judgedInvestigation})

		require.NoError(t, err)
		require.Equal(t, 5*time.Minute, res.RequeueAfter, trigger.Type)
	}
}

// readyReasonOf returns the reason of the Ready condition, or "".
func readyReasonOf(list []metav1.Condition) string {
	if c := meta.FindStatusCondition(list, configv1alpha1.ConditionReady); c != nil {
		return c.Reason
	}
	return ""
}

// theRequest is the request of the tests' investigation for the case.
var theRequest = cases.Request{Investigation: judgedInvestigation, InvestigationUID: judgedUID, Playbook: judgedPlaybook}

// A first request that timed out, whose answer wasn't a chat completion or broke off, or that a gateway gave up on, may
// have been billed: it counts toward the five failures in a row that end the case.
func TestAFirstRequestThatMayHaveBeenBilledCountsTowardTheFive(t *testing.T) {
	for name, answer := range map[string]chatAnswer{"timed out": {hold: true}, "no chat completion": {status: http.StatusOK},
		"broken off": {cut: true}, "gateway timeout": {status: http.StatusGatewayTimeout}} {
		t.Run(name, func(t *testing.T) {
			j := newJudging(t, func(chatRequest) chatAnswer { return answer })
			config := j.agent.ClientConfig
			j.agent.ClientConfig = func(ctx context.Context, name string) (llm.Config, error) {
				c, err := config(ctx, name)
				c.Timeout = 100 * time.Millisecond
				return c, err
			}
			q, _ := j.start(t)
			j.investigate(t, q)

			require.Eventually(t, j.judged(t), within, often)
			nv := j.assessment(t).Status.NoVerdict
			require.NotNil(t, nv)
			require.Equal(t, ptr.To(triagev1alpha1.NoVerdictModelError), nv.Reason)
			require.Contains(t, nv.Summary, "5 times")
			require.Equal(t, int32(5), j.model.requests.Load())
		})
	}
}

// An outcome that the API server refuses every time, such as one that the schema rejects, isn't judged again without
// end: after five refusals in a row, the case ends without a verdict, saying that its outcome couldn't be written.
func TestFiveRefusedOutcomeWritesEndTheCase(t *testing.T) {
	j := newJudging(t, searchThenAffected)
	j.agent.Client = interceptor.NewClient(j.api.(client.WithWatch), interceptor.Funcs{
		SubResourceUpdate: func(ctx context.Context, c client.Client, sub string, obj client.Object,
			opts ...client.SubResourceUpdateOption) error {
			if a, ok := obj.(*triagev1alpha1.Assessment); ok && a.Status.Verdict != nil {
				return apierrors.NewInvalid(triagev1alpha1.GroupVersion.WithKind("Assessment").GroupKind(), a.Name, nil)
			}
			return c.SubResource(sub).Update(ctx, obj, opts...)
		},
	})
	q, _ := j.start(t)
	j.investigate(t, q)

	require.Eventually(t, j.judged(t), within, often)
	nv := j.assessment(t).Status.NoVerdict
	require.NotNil(t, nv)
	require.Equal(t, ptr.To(triagev1alpha1.NoVerdictModelError), nv.Reason)
	require.Contains(t, nv.Summary, "couldn't be written")
	require.Equal(t, int32(10), j.model.requests.Load(), "five judgements, of two requests each")
}

// A judge whose case another worker claimed meanwhile, as after its lease ran out, writes nothing: neither the outcome
// nor the ledger, and the other's claim stands.
func TestAJudgeWhoseClaimWasTakenWritesNothing(t *testing.T) {
	const other = "vexplain-agent-b"
	var j *judging
	j = newJudging(t, func(r chatRequest) chatAnswer {
		if r.hasResult() {
			a := j.assessment(t)
			a.Status.Claim = &triagev1alpha1.QueueClaim{Worker: other, LeaseEndTime: ptr.To(metav1.NewTime(time.Now().Add(time.Hour)))}
			require.NoError(t, j.api.Status().Update(context.Background(), a))
		}
		return searchThenAffected(r)
	})
	j.investigate(t, j.queue())
	ctx := j.claimed(t)

	require.Equal(t, worker.Done, j.agent.Judge(ctx, theJudgedCase, theRequest, 0))

	a := j.assessment(t)
	require.Nil(t, a.Status.Verdict)
	require.Nil(t, a.Status.JudgedTime)
	require.Nil(t, j.ledger(t))
	require.Equal(t, other, a.Status.Claim.Worker)
	require.NotNil(t, a.Status.Queue)
}

// A case whose workers stopped five times while they judged it, as their leases that ran out count, ends without a
// verdict, ModelError, before it spends tokens again.
func TestACaseWhoseWorkersStoppedFiveTimesEndsWithModelError(t *testing.T) {
	j := newJudging(t, searchThenAffected)
	j.investigate(t, j.queue())
	ctx := j.claimed(t)

	require.Equal(t, worker.Done, j.agent.Judge(ctx, theJudgedCase, theRequest, 5))

	a := j.assessment(t)
	require.NotNil(t, a.Status.NoVerdict)
	require.Equal(t, ptr.To(triagev1alpha1.NoVerdictModelError), a.Status.NoVerdict.Reason)
	require.Contains(t, a.Status.NoVerdict.Summary, "5 times")
	require.NotNil(t, a.Status.InputHash)
	require.Nil(t, a.Status.Queue)
	require.Zero(t, j.model.requests.Load(), "no model call")
}
