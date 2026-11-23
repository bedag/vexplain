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

package runner_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	inventoryv1alpha1 "github.com/bedag/vexplain/api/inventory/v1alpha1"
	"github.com/bedag/vexplain/internal/agent/casefile"
	"github.com/bedag/vexplain/internal/agent/cases"
	"github.com/bedag/vexplain/internal/agent/core"
	"github.com/bedag/vexplain/internal/agent/ledger"
	"github.com/bedag/vexplain/internal/agent/profile"
	"github.com/bedag/vexplain/internal/agent/prompt"
	"github.com/bedag/vexplain/internal/agent/runner"
	"github.com/bedag/vexplain/internal/agent/validator"
	"github.com/bedag/vexplain/internal/evidence"
	"github.com/bedag/vexplain/internal/llm"
)

// These tests run the runner against a scripted endpoint over TLS, as cmd/llm-smoke's do, and against vexplain's MCP
// server for a case, over the SDK's in-memory transport, as the hub runs them.

const (
	manifest      = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	vulnerability = "CVE-2026-0001"
	describe      = "vulnerabilities__describe"
	fetch         = "advisories__fetch"
	// contents is the evidence of the case file.
	contents = "contents"
)

// theCase is a case of one vulnerability in one package.
var theCase = cases.Case{
	ManifestDigest: manifest, VulnerabilityID: vulnerability,
	Findings: []inventoryv1alpha1.Finding{{
		VulnerabilityID: vulnerability,
		Package:         inventoryv1alpha1.PackageReference{ID: "pkg-1", Name: "libbrotli1", Version: ptr.To("1.0.9-2"), Type: "deb"},
		Status:          inventoryv1alpha1.VEXStatusUnderInvestigation, Severity: inventoryv1alpha1.SeverityHigh,
		FixState: inventoryv1alpha1.FixStateNotFixed, KnownExploited: inventoryv1alpha1.KnownExploitedNotListed,
	}},
	Subject: cases.Subject{ManifestDigest: manifest},
}

// defaultLimits are the profile's defaults.
var defaultLimits = profile.Limits{MaxSteps: 15, MaxTokens: 300000, TimeoutSeconds: 900, ToolTimeoutSeconds: 120,
	ReservedTokens: 4000, ToolResultMaxTokens: 4000, CaseFileMaxTokens: 16000}

// thePrompt is the system prompt of the tests: the core and the guidance that the operator ships.
var thePrompt = prompt.Core() + "\n\n" + prompt.Guidance()

// The JSON of the chat completions API, as far as the scripted endpoint reads it.
type (
	request struct {
		Messages   []message `json:"messages"`
		Tools      []tool    `json:"tools"`
		ToolChoice string    `json:"tool_choice"`
		MaxTokens  int       `json:"max_tokens"`
		// size is the length of the request's body.
		size int
	}
	message struct {
		Role       string     `json:"role"`
		Content    *string    `json:"content"`
		ToolCalls  []toolCall `json:"tool_calls"`
		ToolCallID string     `json:"tool_call_id"`
	}
	toolCall struct {
		ID       string `json:"id"`
		Function struct {
			Name      string `json:"name"`
			Arguments string `json:"arguments"`
		} `json:"function"`
	}
	tool struct {
		Function struct {
			Name string `json:"name"`
		} `json:"function"`
	}
)

// toolNames returns the names of the request's tools.
func (r request) toolNames() []string {
	names := make([]string, 0, len(r.Tools))
	for _, t := range r.Tools {
		names = append(names, t.Function.Name)
	}
	return names
}

// toolResults returns the contents of the request's tool messages.
func (r request) toolResults() []string {
	var results []string
	for _, m := range r.Messages {
		if m.Role == "tool" {
			results = append(results, ptr.Deref(m.Content, ""))
		}
	}
	return results
}

// answer is what the scripted endpoint answers one request with.
type answer struct {
	// status is the HTTP status; zero means 200.
	status int
	// delay is how long the endpoint takes.
	delay time.Duration
	text  string
	// calls are the tool calls: each a name and its arguments, as the model writes them.
	calls [][2]string
	// prompt and completion are the usage that it reports; zero reports 10 and 5. measured reports the request's
	// size / 4 as its prompt, as an endpoint counts what it reads.
	prompt, completion int
	measured           bool
}

// call returns an answer that calls a tool with the arguments, marshalled.
func call(name string, args any) answer {
	raw, err := json.Marshal(args)
	if err != nil {
		panic(err)
	}
	return answer{calls: [][2]string{{name, string(raw)}}}
}

// model is a scripted endpoint: it answers the n-th request, from 1, as script says.
type model struct {
	*httptest.Server
	script func(n int, r request) answer

	mu   sync.Mutex
	seen []request
}

func newModel(t *testing.T, script func(n int, r request) answer) *model {
	t.Helper()
	m := &model{script: script}
	m.Server = httptest.NewTLSServer(http.HandlerFunc(m.handle))
	t.Cleanup(m.Close)
	return m
}

func (m *model) handle(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	var req request
	if err != nil || json.Unmarshal(body, &req) != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	req.size = len(body)
	m.mu.Lock()
	m.seen = append(m.seen, req)
	n := len(m.seen)
	m.mu.Unlock()
	a := m.script(n, req)
	time.Sleep(a.delay)
	if a.status != 0 {
		w.WriteHeader(a.status)
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
	read, written := a.prompt, a.completion
	switch {
	case a.measured:
		read = (req.size + 3) / 4
	case read == 0 && written == 0:
		read, written = 10, 5
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"choices": []map[string]any{{"message": msg, "finish_reason": "stop"}},
		"usage":   map[string]any{"prompt_tokens": read, "completion_tokens": written},
	})
}

// requests returns the requests that the endpoint got.
func (m *model) requests() []request {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]request(nil), m.seen...)
}

// forwarder stands in for the collectors' tools: it lists its tools, and answers each call with out.
type forwarder struct {
	tools []core.Tool
	out   []byte
}

func (f *forwarder) Tools(context.Context) ([]core.Tool, error) { return f.tools, nil }

func (f *forwarder) Call(_ context.Context, tool string, _ json.RawMessage) ([]byte, ledger.Trust, error) {
	if f.out != nil {
		return f.out, ledger.Known, nil
	}
	return []byte("answer of " + tool + "\n"), ledger.Known, nil
}

// describeTool is a collector's tool that takes a vulnerability ID.
var describeTool = core.Tool{Name: describe, Description: "Describe a vulnerability from the database",
	InputSchema: json.RawMessage(`{"type":"object","properties":{"vulnerabilityID":{"type":"string"}}}`)}

// fetchTool is a collector's tool that a case finds by search.
var fetchTool = core.Tool{Name: fetch, Description: "Fetch a page that a trusted result linked to",
	InputSchema: json.RawMessage(`{"type":"object","properties":{"url":{"type":"string"}}}`)}

// fixture is a run of the runner on the case.
type fixture struct {
	model   *model
	session *core.Session
	result  runner.Result
}

// options change what run builds.
type options struct {
	limits    profile.Limits
	forwarder *forwarder
	// window is the model's context window; zero means 200000.
	window int
}

// run judges the case with the runner against the scripted endpoint, with the evidence contents of a few lines.
func run(t *testing.T, o options, script func(n int, r request) answer) *fixture {
	t.Helper()
	ctx := t.Context()
	scheme := runtime.NewScheme()
	require.NoError(t, inventoryv1alpha1.AddToScheme(scheme))
	store := evidence.NewCRDStore(fake.NewClientBuilder().WithScheme(scheme).Build(), nil, func() string { return "hub" })
	limits := o.limits
	if limits == (profile.Limits{}) {
		limits = defaultLimits
	}
	file, err := casefile.Build(theCase, map[string][]json.RawMessage{
		contents: {json.RawMessage(`{"files":[{"path":"/usr/lib/libbrotlidec.so.1"},{"path":"/usr/bin/app"}]}`)},
	}, nil, 4*limits.CaseFileMaxTokens)
	require.NoError(t, err)
	fwd := o.forwarder
	if fwd == nil {
		fwd = &forwarder{}
	}
	f := &fixture{model: newModel(t, script)}
	f.session = core.NewSession(core.Deps{Evidence: store, Forwarder: fwd,
		Validator: validator.New(validator.Case{VulnerabilityID: vulnerability})},
		theCase, file, profile.Effective{Name: "default", Limits: limits})

	serverTransport, clientTransport := mcp.NewInMemoryTransports()
	serverSession, err := f.session.Server().Connect(ctx, serverTransport, nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = serverSession.Close() })
	clientSession, err := mcp.NewClient(&mcp.Implementation{Name: "runner", Version: "test"}, nil).
		Connect(ctx, clientTransport, nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = clientSession.Close() })

	client := llm.New(llm.Config{BaseURL: f.model.URL, Model: "model-a", APIKey: llm.NewSecret("key-123")},
		llm.WithHTTPClient(f.model.Client()))
	window := o.window
	if window == 0 {
		window = 200000
	}
	f.result = runner.Builtin{Client: client}.Run(ctx, clientSession,
		runner.Input{Prompt: thePrompt, CaseFile: file.JSON, Limits: limits, ContextWindowTokens: window})
	return f
}

// searchOf returns the arguments of a search of the evidence of the name.
func searchOf(name, query string) map[string]any { return map[string]any{"name": name, "query": query} }

// searchLib is the arguments of a search of the case file's contents.
var searchLib = searchOf(contents, "lib")

// searches counts the searches that anotherSearch made.
var searches atomic.Int32

// anotherSearch returns the arguments of a search of the case file's contents that no earlier call made: the core
// answers a call that repeats an earlier one from the ledger, without an entry.
func anotherSearch() map[string]any {
	return searchOf(contents, fmt.Sprintf("lib %d", searches.Add(1)))
}

// describing is the arguments of describe of the case's vulnerability.
var describing = map[string]any{"vulnerabilityID": vulnerability}

// findTools returns the arguments of search_tools.
func findTools(query string) map[string]any { return map[string]any{"query": query} }

// affected returns the arguments of submit_verdict with the status affected, citing the IDs.
func affected(ids ...string) map[string]any {
	return map[string]any{"status": "affected", "nextStep": "update the image once a fixed version exists",
		"summary": "The image installs libbrotli1 1.0.9-2, which the database lists as vulnerable.",
		"claims":  []map[string]any{{"text": "the image installs the package", "evidence": ids}}}
}

// worstCase is the fit check's worst case for the limits and the prompt of the tests: what one request may hold.
func worstCase(l profile.Limits) int {
	return prompt.EstimateTokens(thePrompt) + l.CaseFileMaxTokens + prompt.CoreToolSchemaTokens +
		profile.SearchedToolsTokens + l.MaxSteps*(l.ToolResultMaxTokens+prompt.StepMaxTokens) + l.ReservedTokens
}

// summary is what the scripted model writes in the final call: what it established, and what would settle the case.
const summary = "The image installs libbrotli1 1.0.9-2 (ev-1).\n\nA fixed version for the release would settle it."

// isFinal reports whether a request is the final call, which offers no tools.
func isFinal(r request) bool { return len(r.Tools) == 0 }

// lines returns n lines of text, each of 100 bytes.
func lines(n int) []byte {
	return []byte(strings.Repeat(strings.Repeat("x", 99)+"\n", n))
}
