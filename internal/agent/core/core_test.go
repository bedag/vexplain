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

package core_test

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"maps"
	"math/rand/v2"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"unicode/utf8"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	inventoryv1alpha1 "github.com/bedag/vexplain/api/inventory/v1alpha1"
	"github.com/bedag/vexplain/internal/agent/casefile"
	"github.com/bedag/vexplain/internal/agent/cases"
	"github.com/bedag/vexplain/internal/agent/core"
	"github.com/bedag/vexplain/internal/agent/ledger"
	"github.com/bedag/vexplain/internal/agent/profile"
	"github.com/bedag/vexplain/internal/agent/prompt"
	"github.com/bedag/vexplain/internal/agent/verdict"
	"github.com/bedag/vexplain/internal/evidence"
	"github.com/bedag/vexplain/internal/inventory"
	sdkevidence "github.com/bedag/vexplain/sdk/evidence"
)

// These tests talk to vexplain's MCP server as a runner does: through a client session over the in-memory transport.

const (
	manifest      = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	vulnerability = "CVE-2026-0001"
	describe      = "vulnerabilities__describe"
	cluster       = "cluster-a"
	// contents is the evidence of the tests whose searches return long results, and first the ID of the first entry.
	contents = "contents"
	first    = "ev-1"
)

// fixedForInstalled is the validator's check that a package has the fix.
const fixedForInstalled = "FixedForInstalled"

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

// assessment is the name of the case's Assessment, and of its ledger.
var assessment = cases.Name(vulnerability, manifest)

// fixture is a session of the case, and a runner's client session on its server.
type fixture struct {
	session   *core.Session
	client    *mcp.ClientSession
	evidence  evidence.Store
	forwarder *forwarder
	validator *validator
	// ledgerWrites counts the writes of Ledger objects through the client that the evidence store uses.
	ledgerWrites *atomic.Int32
	api          client.Client
}

// options change what start builds.
type options struct {
	evidence       map[string][]json.RawMessage
	limits         profile.Limits
	maxCompressed  int64
	forwarderTools []core.Tool
	// forwarder replaces the stand-in forwarder.
	forwarder core.Forwarder
	// theCase replaces the case.
	theCase *cases.Case
}

// defaultLimits are the profile's defaults.
var defaultLimits = profile.Limits{MaxSteps: 15, MaxTokens: 300000, TimeoutSeconds: 900, ToolTimeoutSeconds: 120,
	ReservedTokens: 4000, ToolResultMaxTokens: 4000, CaseFileMaxTokens: 16000}

// start opens a session of the case with the evidence, and connects a client to its server.
func start(t *testing.T, o options) *fixture {
	t.Helper()
	ctx := t.Context()
	scheme := runtime.NewScheme()
	require.NoError(t, inventoryv1alpha1.AddToScheme(scheme))
	writes := &atomic.Int32{}
	api := fake.NewClientBuilder().WithScheme(scheme).WithInterceptorFuncs(interceptor.Funcs{
		Create: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
			if _, ok := obj.(*inventoryv1alpha1.Ledger); ok {
				writes.Add(1)
			}
			return c.Create(ctx, obj, opts...)
		},
	}).Build()
	maxCompressed := cmpOr(o.maxCompressed, evidence.DefaultMaxCompressedBytes)
	store := evidence.NewCRDStore(api, nil, func() string { return "hub" },
		evidence.WithMaxCompressedBytes(func() int64 { return maxCompressed }))
	limits := o.limits
	if limits == (profile.Limits{}) {
		limits = defaultLimits
	}
	c := theCase
	if o.theCase != nil {
		c = *o.theCase
	}
	file, err := casefile.Build(c, o.evidence, nil, 4*limits.CaseFileMaxTokens)
	require.NoError(t, err)
	f := &fixture{
		evidence: store, forwarder: &forwarder{tools: o.forwarderTools, trust: ledger.Known},
		validator: &validator{}, ledgerWrites: writes, api: api,
	}
	var forwarder core.Forwarder = f.forwarder
	if o.forwarder != nil {
		forwarder = o.forwarder
	}
	f.session = core.NewSession(core.Deps{Evidence: store, Validator: f.validator, Forwarder: forwarder,
		Cluster: cluster}, c, file, profile.Effective{Name: "default", Limits: limits})

	serverTransport, clientTransport := mcp.NewInMemoryTransports()
	serverSession, err := f.session.Server().Connect(ctx, serverTransport, nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = serverSession.Close() })
	f.client, err = mcp.NewClient(&mcp.Implementation{Name: "runner", Version: "test"}, nil).Connect(ctx, clientTransport, nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = f.client.Close() })
	return f
}

func cmpOr(a, b int64) int64 {
	if a != 0 {
		return a
	}
	return b
}

// call calls a tool with the arguments, and returns the text of its result and whether it is a tool error.
func (f *fixture) call(t *testing.T, tool string, args any) (string, bool) {
	t.Helper()
	res, err := f.client.CallTool(t.Context(), &mcp.CallToolParams{Name: tool, Arguments: args})
	require.NoError(t, err, "a tool's failure is a tool error, never a protocol error")
	var text strings.Builder
	for _, c := range res.Content {
		text.WriteString(c.(*mcp.TextContent).Text)
	}
	return text.String(), res.IsError
}

// search returns the arguments of search_evidence.
func search(name, query string) map[string]any { return map[string]any{"name": name, "query": query} }

// describing returns the arguments of describe, with aliases where given.
func describing(id string, aliases ...string) map[string]any {
	args := map[string]any{"vulnerabilityID": id}
	if len(aliases) > 0 {
		args["aliases"] = aliases
	}
	return args
}

// find returns the arguments of search_tools.
func find(query string) map[string]any { return map[string]any{"query": query} }

// packagesOf returns evidence that lists the packages.
func packagesOf(t *testing.T, packages []map[string]string) json.RawMessage {
	t.Helper()
	data, err := json.Marshal(map[string]any{"packages": packages})
	require.NoError(t, err)
	return data
}

// verdictOf returns the arguments of submit_verdict, with one claim that cites the IDs.
func verdictOf(status, justification, summary string, ids ...string) map[string]any {
	args := map[string]any{"status": status, "nextStep": "update the image once a fixed version exists",
		"summary": summary, "claims": []map[string]any{{"text": "the database lists the package", "evidence": ids}}}
	if justification != "" {
		args["justification"] = justification
	}
	return args
}

// tools returns the names of the tools that the session lists.
func (f *fixture) tools(t *testing.T) []string {
	t.Helper()
	res, err := f.client.ListTools(t.Context(), nil)
	require.NoError(t, err)
	names := make([]string, 0, len(res.Tools))
	for _, tool := range res.Tools {
		names = append(names, tool.Name)
	}
	slices.Sort(names)
	return names
}

// stored returns the whole output of a ledger entry, as the evidence store holds it.
func (f *fixture) stored(t *testing.T, id string) sdkevidence.ToolOutput {
	t.Helper()
	record, err := f.evidence.Get(t.Context(), evidence.Key{Subject: "assessment/" + assessment, Type: sdkevidence.TypeToolOutput,
		Source: id})
	require.NoError(t, err)
	require.NotNil(t, record, "the output of %s is in the evidence store", id)
	var out sdkevidence.ToolOutput
	require.NoError(t, json.Unmarshal(record.Event.Data(), &out))
	return out
}

// forwarder is a stand-in for the collectors' tools: it lists its tools, and answers a call with the tool's name and
// the arguments.
type forwarder struct {
	tools []core.Tool
	trust ledger.Trust
	calls []string
}

func (f *forwarder) Tools(context.Context) ([]core.Tool, error) { return f.tools, nil }

func (f *forwarder) Call(_ context.Context, tool string, args json.RawMessage) ([]byte, ledger.Trust, error) {
	f.calls = append(f.calls, tool+" "+string(args))
	return []byte("answer of " + tool), f.trust, nil
}

// validator is a stand-in for the validator: it returns its problems, one list per call, and then none.
type validator struct {
	problems [][]verdict.Problem
	got      []verdict.Verdict
}

func (v *validator) Validate(vd verdict.Verdict, l *ledger.Ledger) []verdict.Problem {
	v.got = append(v.got, vd)
	if len(v.problems) == 0 {
		return nil
	}
	p := v.problems[0]
	v.problems = v.problems[1:]
	return p
}

// tool returns a collector's tool that takes a vulnerability ID.
func tool(name, description string) core.Tool {
	return core.Tool{Name: name, Description: description,
		InputSchema: json.RawMessage(`{"type":"object","properties":{"vulnerabilityID":{"type":"string"}}}`)}
}

// coreTools are the tools that a session starts with.
var coreTools = []string{"read_evidence", "search_evidence", "search_tools", "submit_no_verdict", "submit_verdict"}

func TestTheSessionListsDescribeFromTheStart(t *testing.T) {
	f := start(t, options{forwarderTools: []core.Tool{
		tool(describe, "What the vulnerability database holds for a vulnerability"),
		tool("advisories__fetch", "Fetch a page that a trusted result linked to"),
	}})

	require.Equal(t, append(slices.Clone(coreTools), describe), sorted(f.tools(t)), "not advisories__fetch, until a search")

	text, failed := f.call(t, "search_tools", find("fetch a page"))
	require.False(t, failed, text)
	require.Contains(t, text, "advisories__fetch")
	require.Contains(t, text, `"vulnerabilityID"`, "a found tool comes with its parameters")
	require.Equal(t, sorted(append(slices.Clone(coreTools), describe, "advisories__fetch")), sorted(f.tools(t)))

	text, failed = f.call(t, describe, describing(vulnerability))
	require.False(t, failed, text)
	require.Contains(t, text, "answer of "+describe)

	f = start(t, options{forwarderTools: []core.Tool{tool("advisories__fetch", "Fetch a page")}})
	require.Equal(t, coreTools, f.tools(t), "describe is listed only where the profile grants it")
}

func TestTheCoreAddsTheCasesAliasesToDescribe(t *testing.T) {
	c := theCase
	const goID = "GO-2026-6612"
	c.VulnerabilityID = goID
	c.Findings = []inventoryv1alpha1.Finding{
		{VulnerabilityID: goID, Aliases: []string{"CVE-2026-78663"}, Package: theCase.Findings[0].Package},
		{VulnerabilityID: "GHSA-aaaa-bbbb-cccc", Package: theCase.Findings[0].Package},
	}
	f := start(t, options{theCase: &c, forwarderTools: []core.Tool{tool(describe, "vulnerability database")}})

	_, failed := f.call(t, describe, describing("CVE-2026-78663"))
	require.False(t, failed)
	_, failed = f.call(t, describe, describing("cve-2026-78663", "OSV-1", goID))
	require.False(t, failed)
	many := []string{"A-1", "A-2", "A-3", "A-4", "A-5", "A-6", "A-7"}
	_, failed = f.call(t, describe, describing("CVE-2026-78663", many...))
	require.False(t, failed)
	_, failed = f.call(t, describe, describing("CVE-2099-0001", "OSV-1"))
	require.False(t, failed)

	require.Equal(t, []string{
		describe + `{"aliases":["GHSA-aaaa-bbbb-cccc","GO-2026-6612"],"vulnerabilityID":"CVE-2026-78663"}`,
		describe + `{"aliases":["OSV-1","GO-2026-6612","GHSA-aaaa-bbbb-cccc"],"vulnerabilityID":"cve-2026-78663"}`,
		describe + `{"aliases":["A-1","A-2","A-3","A-4","A-5","A-6","A-7","GHSA-aaaa-bbbb-cccc"],"vulnerabilityID":"CVE-2026-78663"}`,
		describe + `{"aliases":["OSV-1"],"vulnerabilityID":"CVE-2099-0001"}`,
	}, spaced(f.forwarder.calls))

	entry, ok := f.session.Outcome().Ledger.Entry(first)
	require.True(t, ok)
	require.JSONEq(t, `{"aliases":["GHSA-aaaa-bbbb-cccc","GO-2026-6612"],"vulnerabilityID":"CVE-2026-78663"}`,
		entry.Arguments, "the ledger holds the arguments as sent")
}

// spaced drops the space between a call's tool and its arguments.
func spaced(calls []string) []string {
	out := make([]string, len(calls))
	for i, c := range calls {
		out[i] = strings.Replace(c, " ", "", 1)
	}
	return out
}

func sorted(s []string) []string { slices.Sort(s); return s }

// The definitions of the core tools take what the fit check counts for them, as bytes / 4 of their names, descriptions
// and input schemas.
func TestTheCoreToolsTakeTheTokensThatTheFitCheckCounts(t *testing.T) {
	f := start(t, options{})
	res, err := f.client.ListTools(t.Context(), nil)
	require.NoError(t, err)
	var all strings.Builder
	for _, tool := range res.Tools {
		// A function's definition, as an OpenAI-compatible endpoint takes it.
		definition, err := json.Marshal(struct {
			Name        string `json:"name"`
			Description string `json:"description"`
			Parameters  any    `json:"parameters"`
		}{tool.Name, tool.Description, tool.InputSchema})
		require.NoError(t, err)
		all.Write(definition)
	}
	require.Equal(t, prompt.EstimateTokens(all.String()), prompt.CoreToolSchemaTokens)
}

// A case loads at most 8 tools, and a search returns at most 5.
func TestSearchToolsLoadsAtMostEightTools(t *testing.T) {
	tools := make([]core.Tool, 0, 13)
	for _, word := range []string{"alpha", "beta"} {
		for i := range 6 {
			tools = append(tools, tool(fmt.Sprintf("%s__op%d", word, i), "An operation of "+word))
		}
	}
	tools = append(tools, tool("not.a.tool", "alpha with a name that a model can't call"))
	f := start(t, options{forwarderTools: tools})

	text, failed := f.call(t, "search_tools", find("alpha"))
	require.False(t, failed, text)
	require.Len(t, f.tools(t), 5+5)
	require.NotContains(t, text, "not.a.tool")

	text, failed = f.call(t, "search_tools", find("beta"))
	require.False(t, failed, text)
	require.Len(t, f.tools(t), 5+8)
	require.Contains(t, text, "at most 8")
}

func TestSearchEvidenceFindsLinesOfTheNamedEvidence(t *testing.T) {
	named := func(name string) map[string]string { return map[string]string{"name": name} }
	packages := make([]map[string]string, 0, 301)
	for i := range 300 {
		packages = append(packages, named(fmt.Sprintf("libbrotli-%03d", i)))
	}
	packages = append(packages, named("zlib1g"))
	f := start(t, options{evidence: map[string][]json.RawMessage{"sbom": {packagesOf(t, packages)}}})

	text, failed := f.call(t, "search_evidence", search("sbom", "LibBrotli"))
	require.False(t, failed, text)
	lines := strings.Split(text, "\n")
	require.Equal(t, `packages[0].name = "libbrotli-000"`, lines[0])
	require.Equal(t, `packages[199].name = "libbrotli-199"`, lines[199], "at most 200 lines")
	require.NotContains(t, text, "libbrotli-200")
	require.NotContains(t, text, "zlib1g")
	require.Contains(t, text, "200 of 300")
	require.Contains(t, text, first)

	text, failed = f.call(t, "search_evidence", search("secrets", "password"))
	require.True(t, failed, "an unknown name is a tool error")
	require.Contains(t, text, "sbom", "the error names the evidence that the case file holds")
	require.NotContains(t, text, "secrets", "and never repeats the model's name")
}

// longLines returns evidence of n packages whose descriptions are long, so that searching it returns about n × 512
// bytes.
func longLines(t *testing.T, n int) map[string][]json.RawMessage {
	t.Helper()
	packages := make([]map[string]string, 0, n)
	for i := range n {
		packages = append(packages, map[string]string{"description": fmt.Sprintf("%03d ", i) + strings.Repeat("x", 480)})
	}
	return map[string][]json.RawMessage{contents: {packagesOf(t, packages)}}
}

// whole is the output of the search that the tests of long results make: every line of longLines(t, 200).
func whole(t *testing.T, f *fixture) []byte {
	t.Helper()
	out := f.stored(t, first)
	require.Equal(t, int64(len(out.Output)), out.OutputBytes, "stored whole")
	return []byte(out.Output)
}

func TestEveryCallGoesIntoTheLedgerWhole(t *testing.T) {
	f := start(t, options{evidence: longLines(t, 200)})

	text, failed := f.call(t, "search_evidence", search(contents, "xxx"))
	require.False(t, failed, text)

	out := whole(t, f)
	require.Greater(t, len(out), 100*1024, "a result of 100 KiB")
	shown, trailer, found := strings.Cut(text, "\n[")
	shown += "\n"
	require.True(t, found, text)
	require.LessOrEqual(t, len(shown), 4*4000, "the model sees at most 4 × toolResultMaxTokens bytes")
	require.Greater(t, len(shown), 4*4000-600, "cut on the last line that fits")
	require.True(t, strings.HasPrefix(string(out), shown), "the first bytes of the output, cut on a line")
	require.Contains(t, trailer, "ev-1")
	require.Contains(t, trailer, fmt.Sprintf("%d of %d bytes", len(shown), len(out)))
	require.Contains(t, trailer, `read_evidence(id: "ev-1", page: 2)`)

	entry, ok := f.session.Outcome().Ledger.Entry(first)
	require.True(t, ok)
	require.Equal(t, out, entry.Output)
	require.Equal(t, len(shown), entry.ShownBytes)
}

func TestReadEvidencePagesThroughAnEntry(t *testing.T) {
	f := start(t, options{evidence: longLines(t, 200)})
	_, failed := f.call(t, "search_evidence", search(contents, "xxx"))
	require.False(t, failed)
	out := whole(t, f)
	entry, _ := f.session.Outcome().Ledger.Entry(first)

	read := out[:entry.ShownBytes]
	for page := 2; ; page++ {
		args := map[string]any{"id": first}
		if page > 2 {
			args["page"] = page
		}
		text, failed := f.call(t, "read_evidence", args)
		require.False(t, failed, text)
		body, trailer, found := strings.Cut(text, "\n[")
		require.True(t, found, text)
		require.LessOrEqual(t, len(body)+1, 4*4000)
		require.Contains(t, trailer, fmt.Sprintf("page %d of", page))
		require.Contains(t, trailer, "of ev-1")
		read = append(read, body+"\n"...)
		if !strings.Contains(trailer, "Read on") {
			break
		}
		require.Contains(t, trailer, fmt.Sprintf(`read_evidence(id: "ev-1", page: %d)`, page+1))
	}
	require.Equal(t, string(out), string(read), "the pages are the whole output")

	text, failed := f.call(t, "read_evidence", map[string]any{"id": first, "page": 99})
	require.True(t, failed, text)
	text, failed = f.call(t, "read_evidence", map[string]any{"id": "ev-99"})
	require.True(t, failed, text)
	require.Contains(t, text, "ev-99")

	// Reading a page is a call too, of the trust of what it reads.
	read2, ok := f.session.Outcome().Ledger.Entry("ev-2")
	require.True(t, ok)
	require.Equal(t, "read_evidence", read2.Tool)
	require.Equal(t, entry.Trust, read2.Trust)
}

// An output over the evidence store's cap is stored cut, and the ledger keeps its whole size.
func TestAnOutputOverTheStoresCapIsStoredCut(t *testing.T) {
	random := rand.New(rand.NewPCG(1, 2))
	packages := make([]map[string]string, 0, 200)
	for range 200 {
		b := make([]byte, 256)
		for i := range b {
			b[i] = byte(random.UintN(256))
		}
		packages = append(packages, map[string]string{"digest": hex.EncodeToString(b)})
	}
	f := start(t, options{evidence: map[string][]json.RawMessage{contents: {packagesOf(t, packages)}}, maxCompressed: 8192})

	_, failed := f.call(t, "search_evidence", search(contents, "digest"))
	require.False(t, failed)

	entry, ok := f.session.Outcome().Ledger.Entry(first)
	require.True(t, ok)
	out := f.stored(t, first)
	require.Equal(t, int64(len(entry.Output)), out.OutputBytes, "the size of the whole output")
	require.Less(t, len(out.Output), len(entry.Output), "stored cut")
	require.NotEmpty(t, out.Output)
	require.True(t, strings.HasPrefix(string(entry.Output), out.Output), "the first bytes of the output")
}

func TestTheLedgerIsWrittenOnceAtTheEnd(t *testing.T) {
	f := start(t, options{evidence: longLines(t, 3), forwarderTools: []core.Tool{tool(describe, "Describe a vulnerability")}})
	f.forwarder.trust = ledger.External

	long := strings.Repeat("ü", 5000)
	_, failed := f.call(t, "search_evidence", search(contents, long))
	require.False(t, failed)
	_, failed = f.call(t, "search_tools", find("describe"))
	require.False(t, failed)
	_, failed = f.call(t, describe, describing(vulnerability))
	require.False(t, failed)
	require.Zero(t, f.ledgerWrites.Load(), "the core never writes the ledger in the middle of a case")

	text, failed := f.call(t, "submit_verdict", verdictOf("affected", "",
		"The image installs libbrotli1 1.0.9-2, which the database lists as vulnerable (ev-3).", "ev-3"))
	require.False(t, failed, text)
	require.Zero(t, f.ledgerWrites.Load())

	outcome := f.session.Outcome()
	require.NotNil(t, outcome.Verdict)
	require.Nil(t, outcome.NoVerdict)
	obj := outcome.Ledger.Object()
	require.Equal(t, assessment, obj.Name, "named as its Assessment")
	require.Equal(t, cases.Labels(vulnerability, manifest), obj.Labels)
	require.Len(t, obj.Spec.Entries, 3, "every call but the submit")
	for i, e := range obj.Spec.Entries {
		require.Equal(t, fmt.Sprintf("ev-%d", i+1), e.ID)
		require.Equal(t, inventoryv1alpha1.LedgerOutputReference{Subject: "assessment/" + assessment,
			Type: sdkevidence.TypeToolOutput, Source: e.ID}, e.OutputRef)
		stored := f.stored(t, e.ID)
		require.Equal(t, *e.OutputBytes, stored.OutputBytes)
		require.NotEmpty(t, *e.Preview)
		require.LessOrEqual(t, utf8.RuneCountInString(*e.Preview), 512)
		require.True(t, strings.HasPrefix(stored.Output, *e.Preview))
		require.LessOrEqual(t, utf8.RuneCountInString(*e.Arguments), 4096, "no arguments over 4096 characters")
		require.Len(t, e.OutputSHA256, 64)
	}
	require.Equal(t, 4096, utf8.RuneCountInString(*obj.Spec.Entries[0].Arguments), "cut at 4096 characters")
	require.Equal(t, inventoryv1alpha1.LedgerTrustKnown, obj.Spec.Entries[0].Trust)
	require.Equal(t, inventoryv1alpha1.LedgerTrustExternal, obj.Spec.Entries[1].Trust, "a tool listing is never evidence")
	require.Equal(t, inventoryv1alpha1.LedgerTrustExternal, obj.Spec.Entries[2].Trust, "the trust that the tool declared")
	require.Equal(t, describe, obj.Spec.Entries[2].Tool)

	// The writer of the case writes it once, at the end.
	store := inventory.NewCRDLedgerStore(f.api)
	require.NoError(t, store.Put(t.Context(), obj))
	require.Equal(t, int32(1), f.ledgerWrites.Load())
	got, err := store.Get(t.Context(), assessment)
	require.NoError(t, err)
	require.Equal(t, obj.Spec, got.Spec)
}

func TestSubmitVerdictHandsTheVerdictToTheValidator(t *testing.T) {
	f := start(t, options{evidence: longLines(t, 3)})
	_, failed := f.call(t, "search_evidence", search(contents, "000"))
	require.False(t, failed)
	f.validator.problems = [][]verdict.Problem{{{Check: "CitedEntriesExist", Message: "ev-7 is not in the ledger"}}}
	submit := verdictOf("not_affected", "vulnerable_code_not_present", "The installed version holds the fix (ev-1).",
		first, "ev-7")

	text, failed := f.call(t, "submit_verdict", submit)
	require.True(t, failed, "a rejection comes back as the tool's result")
	require.Contains(t, text, "ev-7 is not in the ledger")
	require.Nil(t, f.session.Outcome().Verdict)
	_, failed = f.call(t, "submit_verdict", verdictOf("unknown", "", "a", first))
	require.True(t, failed, "a status outside OpenVEX's")
	require.Len(t, f.validator.got, 1, "refused before the validator, so it is no rejection")

	text, failed = f.call(t, "submit_verdict", submit)
	require.False(t, failed, text)
	require.Equal(t, verdict.Verdict{Status: "NotAffected", Justification: "VulnerableCodeNotPresent",
		Step: "update the image once a fixed version exists", Summary: "The installed version holds the fix (ev-1).",
		Claims: []verdict.Claim{{Text: "the database lists the package", Evidence: []string{first, "ev-7"}}}},
		*f.session.Outcome().Verdict)
	require.Len(t, f.validator.got, 2)

	text, failed = f.call(t, "search_evidence", search(contents, "000"))
	require.True(t, failed, "the case has ended")
	require.Contains(t, text, "ended")
}

func TestSubmitNoVerdictNeedsItsThreeParts(t *testing.T) {
	f := start(t, options{evidence: longLines(t, 3)})
	_, failed := f.call(t, "search_evidence", search(contents, "000"))
	require.False(t, failed)
	const why, established, wouldSettle = "why", "established", "wouldSettle"
	parts := map[string]any{
		why:         "No provider names a fix for the release of the image.",
		established: "The image installs libbrotli1 1.0.9-2 (ev-1).",
		wouldSettle: "A fixed version for the distribution, or the advisory of the distribution.",
	}

	for _, missing := range []string{why, established, wouldSettle} {
		without := maps.Clone(parts)
		delete(without, missing)
		_, failed := f.call(t, "submit_no_verdict", without)
		require.True(t, failed, "without %s", missing)
		without[missing] = "  "
		_, failed = f.call(t, "submit_no_verdict", without)
		require.True(t, failed, "with a blank %s", missing)
	}
	uncited := maps.Clone(parts)
	uncited[established] = "The image installs libbrotli1 1.0.9-2."
	text, failed := f.call(t, "submit_no_verdict", uncited)
	require.True(t, failed, "what was established cites the ledger")
	require.Contains(t, text, "ev-")
	unknown := maps.Clone(parts)
	unknown[established] = "The image installs libbrotli1 1.0.9-2 (ev-1, ev-9)."
	text, failed = f.call(t, "submit_no_verdict", unknown)
	require.True(t, failed, "an ID that the ledger doesn't hold")
	require.Contains(t, text, "ev-9")
	for name, most := range map[string]int{why: 500, established: 1000, wouldSettle: 500} {
		long := maps.Clone(parts)
		long[name] = "ev-1 " + strings.Repeat("x", most)
		_, failed = f.call(t, "submit_no_verdict", long)
		require.True(t, failed, "%s of more than %d characters, so that the three fit an Assessment's summary", name, most)
	}
	require.Nil(t, f.session.Outcome().NoVerdict)

	text, failed = f.call(t, "submit_no_verdict", parts)
	require.False(t, failed, text)
	require.Equal(t, &verdict.NoVerdict{Reason: verdict.ReasonGaveUp, Why: parts[why].(string),
		Established: parts[established].(string), WouldSettle: parts[wouldSettle].(string)},
		f.session.Outcome().NoVerdict)
	_, failed = f.call(t, "submit_no_verdict", parts)
	require.True(t, failed, "the case has ended")
}

// A rejected verdict comes back once for a repair. A second rejection ends the case without a verdict.
func TestOneRepair(t *testing.T) {
	f := start(t, options{evidence: longLines(t, 3)})
	_, failed := f.call(t, "search_evidence", search(contents, "000"))
	require.False(t, failed)
	f.validator.problems = [][]verdict.Problem{
		{{Check: fixedForInstalled, Message: "no cited answer of describe says that libbrotli1 has the fix"}},
		{{Check: "AgentHold", Message: "completeness-guard holds the finding against the agent"}},
	}
	summary := "The installed version holds the fix (ev-1). " + strings.Repeat("y", 2000)
	submit := verdictOf("fixed", "", summary, first)

	text, failed := f.call(t, "submit_verdict", submit)
	require.True(t, failed, "the first rejection comes back as the tool's result")
	require.Contains(t, text, "libbrotli1 has the fix")
	require.Contains(t, text, "Repair it")
	going := f.session.Outcome()
	require.Equal(t, core.Outcome{Ledger: going.Ledger, Rejections: [][]string{{fixedForInstalled}}}, going,
		"the case goes on")
	_, failed = f.call(t, "search_evidence", search(contents, "001"))
	require.False(t, failed, "the agent can gather more evidence for its repair")

	text, failed = f.call(t, "submit_verdict", submit)
	require.True(t, failed)
	require.Contains(t, text, "completeness-guard")
	require.Contains(t, text, "ended")
	outcome := f.session.Outcome()
	require.Nil(t, outcome.Verdict)
	require.NotNil(t, outcome.NoVerdict, "a second rejection ends the case without a verdict")
	require.Equal(t, verdict.ReasonValidatorRejected, outcome.NoVerdict.Reason)
	require.Contains(t, outcome.NoVerdict.Why, "completeness-guard")
	require.Contains(t, outcome.NoVerdict.Established, "The installed version holds the fix (ev-1).")
	require.NotEmpty(t, outcome.NoVerdict.WouldSettle)
	require.LessOrEqual(t, utf8.RuneCountInString(outcome.NoVerdict.Why), 500)
	require.LessOrEqual(t, utf8.RuneCountInString(outcome.NoVerdict.Established), 1000)
	require.LessOrEqual(t, utf8.RuneCountInString(outcome.NoVerdict.WouldSettle), 500)
	require.Equal(t, [][]string{{fixedForInstalled}, {"AgentHold"}}, outcome.Rejections,
		"the checks of each rejection, the repaired one too")

	_, failed = f.call(t, "submit_verdict", submit)
	require.True(t, failed, "the case has ended")
	require.Len(t, f.validator.got, 2)
}

// The tools that a case loads take at most the 16000 bytes that the fit check sets aside for them.
func TestFoundToolsTakeAtMost16000Bytes(t *testing.T) {
	tools := make([]core.Tool, 0, 3)
	for i := range 3 {
		tools = append(tools, tool(fmt.Sprintf("gamma__op%d", i), "gamma "+strings.Repeat("x", 7000)))
	}
	f := start(t, options{forwarderTools: tools})

	text, failed := f.call(t, "search_tools", find("gamma"))
	require.False(t, failed, text)
	require.Equal(t, sorted(append(slices.Clone(coreTools), "gamma__op0", "gamma__op1")), f.tools(t))
	require.Contains(t, text, "gamma__op2 can't be offered")
	require.Equal(t, 4*profile.SearchedToolsTokens, 16000)
}

// A call that repeats an earlier call of the case, with the same arguments in any order, isn't run again: its answer
// names the earlier ledger ID. A loop of repetitions so adds nothing to the ledger, and ends at the runner's maxSteps.
func TestARepeatedCallIsAnsweredFromTheLedger(t *testing.T) {
	const lookup = "vulnerabilities__lookup"
	f := start(t, options{forwarderTools: []core.Tool{tool(lookup, "vulnerability database")}})
	_, failed := f.call(t, "search_tools", find("lookup"))
	require.False(t, failed)
	text, failed := f.call(t, lookup, json.RawMessage(`{"vulnerabilityID": "CVE-2026-0001", "page": 1}`))
	require.False(t, failed, text)
	require.Contains(t, text, "[ledger ID ev-2]")

	text, failed = f.call(t, lookup, json.RawMessage(`{"page": 1, "vulnerabilityID": "CVE-2026-0001"}`))
	require.False(t, failed, text)
	require.Contains(t, text, "ev-2")
	require.Contains(t, text, `read_evidence(id: "ev-2", page: 1)`, "page 1, which a result of one page has")
	require.NotContains(t, text, "answer of", "the result isn't repeated")
	require.Len(t, f.forwarder.calls, 1, "the repetition reaches no collector")
	require.Equal(t, 2, f.session.Outcome().Ledger.Len(), "the repetition is no entry")

	_, failed = f.call(t, lookup, json.RawMessage(`{"vulnerabilityID": "CVE-2026-0001", "page": 2}`))
	require.False(t, failed)
	require.Len(t, f.forwarder.calls, 2, "other arguments run")
	require.Equal(t, 3, f.session.Outcome().Ledger.Len())
}

// A search of the tools may find other tools later in the case, as when a collector comes back, so it runs again.
func TestARepeatedSearchOfTheToolsRunsAgain(t *testing.T) {
	f := start(t, options{forwarderTools: []core.Tool{tool("vulnerabilities__lookup", "vulnerability database")}})
	for range 2 {
		text, failed := f.call(t, "search_tools", find("lookup"))
		require.False(t, failed, text)
		require.NotContains(t, text, "You made this call already")
	}
	require.Equal(t, 2, f.session.Outcome().Ledger.Len())
}

// A call that failed may run again, since a collector or a page may fail only for a moment.
func TestARepeatedCallThatFailedRunsAgain(t *testing.T) {
	f := start(t, options{})
	for range 2 {
		_, failed := f.call(t, "search_evidence", search("no-such-evidence", "apk"))
		require.True(t, failed)
	}
	require.Equal(t, 2, f.session.Outcome().Ledger.Len())
}
