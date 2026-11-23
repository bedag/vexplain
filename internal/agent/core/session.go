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

package core

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/bedag/vexplain/internal/agent/casefile"
	"github.com/bedag/vexplain/internal/agent/cases"
	"github.com/bedag/vexplain/internal/agent/ledger"
	"github.com/bedag/vexplain/internal/agent/profile"
	"github.com/bedag/vexplain/internal/agent/verdict"
	"github.com/bedag/vexplain/internal/evidence"
	sdkevidence "github.com/bedag/vexplain/sdk/evidence"
)

// Validator checks a verdict against the case and its ledger (main design 6.7). It returns the problems that it finds,
// none for a verdict that it accepts.
type Validator interface {
	Validate(v verdict.Verdict, l *ledger.Ledger) []verdict.Problem
}

// Tool is a tool that the core can forward to: its name, <collector>__<operation>, what it does, and the JSON Schema
// of its arguments.
type Tool struct {
	Name, Description string
	InputSchema       json.RawMessage
	// Fetches is true for a tool that fetches the page of its argument url, such as advisories' fetch: the core
	// forwards its call only for a URL that a trusted result of the case named.
	Fetches bool
	// AllowedDomains are the hosts that a tool that fetches reaches, in the form of hosts.Domains, or nil where they
	// aren't known.
	AllowedDomains []string
}

// Forwarder lists the tools beyond the core tools that a case may use, and calls them: the operations of collectors
// and the tools of MCP collectors that the profile allows. Its errors and outputs reach the model, so they never carry
// a secret value.
type Forwarder interface {
	Tools(ctx context.Context) ([]Tool, error)
	// Call calls the tool with the model's arguments, and returns its output and how far the output may count as
	// evidence.
	Call(ctx context.Context, tool string, args json.RawMessage) (out []byte, trust ledger.Trust, err error)
}

// Deps are what a session works with. Each but Cluster is required.
type Deps struct {
	// Evidence keeps the whole output of every call, at once.
	Evidence  evidence.Store
	Validator Validator
	Forwarder Forwarder
	// Cluster names this cluster in the metrics.
	Cluster string
}

// Outcome is how a case ended: with a verdict, with no verdict, or with neither while it runs or when a limit ended
// it, and its ledger.
type Outcome struct {
	Verdict   *verdict.Verdict
	NoVerdict *verdict.NoVerdict
	// Ledger holds every call of the case. The writer of the case's outcome writes it as the case's Ledger, once, when
	// the case ends: the core never writes it.
	Ledger *ledger.Ledger
	// Rejections holds the checks of the problems of each verdict that the validator rejected, in order: the one that
	// the agent repaired too.
	Rejections [][]string
}

// The keys of the _meta of vexplain's MCP server.
const (
	// LimitMeta names the limit that ended a case, in the _meta of a call of submit_no_verdict, as a runner makes it
	// at a limit: one of verdict.Limits. The model never writes a request's _meta, only its arguments.
	LimitMeta = "vexplain.bedag.ch/limit"
	// EndedMeta is true in the _meta of the result of the call that ended the case.
	EndedMeta = "vexplain.bedag.ch/ended"
)

// eventSource is the source of the events of the tool outputs that the core stores.
const eventSource = "/hub/agent"

// Session is vexplain's MCP server for one case (decision 0053): every tool call of the case passes through it, and
// it records each in the case's ledger itself, so that the validator checks the claims of a verdict against what
// vexplain recorded, whoever runs the loop.
type Session struct {
	deps   Deps
	file   casefile.CaseFile
	limits profile.Limits
	server *mcp.Server
	// run is the version under which the evidence store keeps the case's outputs: one for each session, so that the
	// outputs of a case judged again replace those of its earlier judgement.
	run string

	// mu serializes the calls, which a runner makes one at a time.
	mu      sync.Mutex
	ledger  *ledger.Ledger
	outcome Outcome
	// loaded are the names of the tools that searches loaded, and loadedBytes the size of their definitions.
	loaded      map[string]bool
	loadedBytes int
	// ids are the IDs of the case's vulnerability and of its findings, with their aliases, sorted.
	ids []string
	// rejections holds the checks of each verdict that the validator rejected.
	rejections [][]string
	// answered maps each call of the case that didn't fail, by its tool and its arguments, to its ledger ID.
	answered map[string]string
	// fetch is the granted tool that fetches, which describe's answers say the unreachable references of, if any.
	fetch *Tool
}

// NewSession returns the session of the case c, with its case file and the profile p.
func NewSession(deps Deps, c cases.Case, file casefile.CaseFile, p profile.Effective) *Session {
	s := &Session{
		deps: deps, file: file, limits: p.Limits, run: time.Now().UTC().Format(time.RFC3339Nano),
		ledger: ledger.New(cases.Name(c.VulnerabilityID, c.ManifestDigest), cases.Labels(c.VulnerabilityID, c.ManifestDigest),
			pageBytes(p.Limits)),
		loaded: map[string]bool{}, ids: caseIDs(c), answered: map[string]string{},
	}
	s.server = newServer(s)
	s.loadDescribe()
	return s
}

// loadDescribe lists describe from the first step, when the forwarder offers it: it is the tool that every case
// needs, and finding it by search costs a step.
func (s *Session) loadDescribe() {
	ctx, cancel := context.WithTimeout(context.Background(), s.toolTimeout())
	defer cancel()
	tools, err := s.deps.Forwarder.Tools(ctx)
	if err != nil {
		logf.FromContext(ctx).Error(err, "Could not list the tools for the first step")
		return
	}
	if i := slices.IndexFunc(tools, func(t Tool) bool { return t.Fetches && t.AllowedDomains != nil }); i >= 0 {
		s.fetch = &tools[i]
	}
	if i := slices.IndexFunc(tools, func(t Tool) bool { return t.Name == describeTool }); i >= 0 {
		if err := s.load(tools[i]); err != nil {
			logf.FromContext(ctx).Error(err, "Could not load describe", "tool", describeTool)
		}
	}
}

// Server returns the session's MCP server, which a runner connects to through the SDK's in-memory transport.
func (s *Session) Server() *mcp.Server { return s.server }

// Outcome returns how the case ended, and a copy of its ledger as it stands: a call that a cancelled runner left
// running can't change what the writer of the outcome writes.
func (s *Session) Outcome() Outcome {
	s.mu.Lock()
	defer s.mu.Unlock()
	o := s.outcome
	o.Ledger = s.ledger.Clone()
	o.Rejections = slices.Clone(s.rejections)
	return o
}

// pageBytes is the most of a tool's output that the model sees at once: toolResultMaxTokens, at 4 bytes a token.
func pageBytes(l profile.Limits) int { return 4 * l.ToolResultMaxTokens }

// ended returns why the case takes no more calls, and "" while it does. The caller holds mu.
func (s *Session) ended() string {
	switch {
	case s.outcome.Verdict != nil || s.outcome.NoVerdict != nil:
		return "The case has ended: its outcome is submitted."
	case s.ledger.Len() >= s.limits.MaxSteps:
		return fmt.Sprintf("The case has made the %d tool calls that its profile allows: submit_verdict or "+
			"submit_no_verdict now.", s.limits.MaxSteps)
	}
	return ""
}

// call runs a call of tool, records it in the ledger, and returns its result: the first page of its output, and a line
// with its ledger ID and how to read on. An error of run is the output of a failed call, whose trust is External. note
// writes that line, or nil for the usual one. A call that the case refuses, or whose output can't be stored, is a tool
// error, and no entry.
func (s *Session) call(ctx context.Context, tool string, args json.RawMessage,
	run func(context.Context) ([]byte, ledger.Trust, error), note func(ledger.Entry) string) *mcp.CallToolResult {
	s.mu.Lock()
	defer s.mu.Unlock()
	if why := s.ended(); why != "" {
		return failure(why)
	}
	// A call that repeats one that didn't fail would answer the same, so it isn't run, and adds no entry: a model that
	// repeats itself spends its steps, not the ledger or the collectors. A search of the tools may find others later,
	// as when a collector comes back, so it always runs.
	key := callKey(tool, args)
	if id, ok := s.answered[key]; ok && tool != searchTools {
		return success(fmt.Sprintf("You made this call already: its result is ledger ID %s, and it would be the "+
			"same. Read it again with read_evidence(id: %q, page: 1) if you need it, or try something else.", id, id))
	}
	start := time.Now()
	out, trust, err := run(ctx)
	duration := time.Since(start)
	if err != nil {
		out, trust = []byte(err.Error()), ledger.External
	}
	if trust == "" {
		trust = ledger.External
	}
	id := s.ledger.NextID()
	if err := s.store(ctx, id, tool, out); err != nil {
		logf.FromContext(ctx).Error(err, "Could not store the output of a tool call", "tool", tool, "entry", id)
		return failure(fmt.Sprintf("vexplain could not record the output of %s, so it can't be evidence. Call it again.",
			tool))
	}
	e := s.ledger.Add(tool, args, out, trust, duration)
	if err == nil {
		s.answered[key] = e.ID
	}
	text := e.Output[:e.ShownBytes]
	if note == nil {
		note = s.note
	}
	result := string(text)
	if len(text) > 0 && !strings.HasSuffix(result, "\n") {
		result += "\n"
	}
	return &mcp.CallToolResult{IsError: err != nil, Content: []mcp.Content{&mcp.TextContent{Text: result + note(e)}}}
}

// callKey is a call's tool and its arguments, with the arguments' keys in order, so that two calls that differ only
// in that order are one.
func callKey(tool string, args json.RawMessage) string {
	var v any
	decoder := json.NewDecoder(bytes.NewReader(args))
	decoder.UseNumber()
	if decoder.Decode(&v) == nil {
		if canonical, err := json.Marshal(v); err == nil {
			args = canonical
		}
	}
	return tool + "\x00" + string(args)
}

// note is the line after a result: its ledger ID, and how to read on where the model was shown only a part.
func (s *Session) note(e ledger.Entry) string {
	_, pages, _ := s.ledger.Page(e, 1)
	if pages == 1 {
		return fmt.Sprintf("[ledger ID %s]", e.ID)
	}
	return fmt.Sprintf("[ledger ID %s: shown are the first %d of %d bytes, page 1 of %d. Read on with "+
		"read_evidence(id: %q, page: 2).]", e.ID, e.ShownBytes, len(e.Output), pages, e.ID)
}

// store writes the whole output of the entry id into the evidence store, about the case. An output over the store's
// cap is stored cut to its first bytes, with the size of the whole.
func (s *Session) store(ctx context.Context, id, tool string, out []byte) error {
	data := sdkevidence.ToolOutput{Entry: id, Tool: tool, Output: string(out), OutputBytes: int64(len(out))}
	for {
		e, err := sdkevidence.New(sdkevidence.TypeToolOutput, s.ledger.Subject(), data, sdkevidence.WithSource(eventSource))
		if err != nil {
			return err
		}
		// The entry's ID is the record's source, so that each call of the case has a record of its own. No Collector
		// takes such a name, so deleting one never deletes these records.
		err = s.deps.Evidence.Put(ctx, id, s.run, e)
		var tooLarge *evidence.TooLargeError
		if !errors.As(err, &tooLarge) || data.Output == "" {
			return err
		}
		// The share of the output that fits, as compressed the output takes about its share of the data, with a margin.
		// Each round keeps less, so the loop ends.
		keep := int(int64(len(data.Output)) * tooLarge.Cap / tooLarge.Bytes * 9 / 10)
		data.Output = strings.ToValidUTF8(data.Output[:keep], "")
	}
}

// failure returns a tool error with the text.
func failure(text string) *mcp.CallToolResult {
	return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: text}}}
}

// success returns a result with the text.
func success(text string) *mcp.CallToolResult {
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: text}}}
}

// ending marks a result as the one that ended the case.
func ending(r *mcp.CallToolResult) *mcp.CallToolResult {
	r.Meta = mcp.Meta{EndedMeta: true}
	return r
}
