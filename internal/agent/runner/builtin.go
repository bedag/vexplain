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

// Package runner drives the model through one case (design of the agent on image cases, 5.6). It needs only the
// model, a session on vexplain's MCP server and the profile's limits: the session holds the tools, records every call
// in the ledger and hands a verdict to the validator, so a runner never reports a tool's output itself.
//
// Builtin is vexplain's own runner, on the operator's LLM client. It offers the session's tools, passes each tool call
// to the session, and stops when the case ends or a limit trips. At a limit it makes one final call without tools, for
// the summary that it passes to submit_no_verdict.
package runner

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/bedag/vexplain/internal/agent/core"
	"github.com/bedag/vexplain/internal/agent/profile"
	"github.com/bedag/vexplain/internal/agent/prompt"
	"github.com/bedag/vexplain/internal/agent/verdict"
	"github.com/bedag/vexplain/internal/llm"
	"github.com/bedag/vexplain/internal/text"
)

// Input is what a runner judges a case with.
type Input struct {
	// Prompt is the system prompt: the core, the profile's guidance, and the investigation's.
	Prompt string
	// CaseFile is the case file, which the first request carries.
	CaseFile []byte
	Limits   profile.Limits
	// ContextWindowTokens is the model's context window, which no request passes. Zero means unknown.
	ContextWindowTokens int
}

// Result is how a run went.
type Result struct {
	// Usage is what the endpoint reported for every request of the case, the final call included.
	Usage llm.Usage
	// Steps counts the model calls with tools.
	Steps int
	// PeakContextTokens is the most tokens that one request carried, estimated as bytes / 4, as the fit check counts
	// them.
	PeakContextTokens int
	// Limit is the limit that ended the case, one of verdict.Limits, and empty when the agent ended it. A case at a
	// limit ends without a verdict: with the summary of the final call, or, when that call failed, with the limit
	// alone.
	Limit string
	// Err is why the run ended without an outcome and without a limit: a request to the model that failed, or the
	// end of the caller's context.
	Err error
}

// Builtin is vexplain's own runner.
type Builtin struct {
	Client *llm.Client
}

// The roles of the messages.
const (
	roleSystem    = "system"
	roleUser      = "user"
	roleAssistant = "assistant"
	roleTool      = "tool"
)

// The texts that the runner adds to the conversation.
const (
	caseFileLead = "The case file of the case to judge:\n"
	nudge        = "Call a tool. End the case with submit_verdict or submit_no_verdict once the evidence settles it, " +
		"or shows that it can't be settled."
	notMade = "This call was not made: the case ended before it."
	// tooMany is the result of a call over maxCalls in one message.
	tooMany = "This call was not made: too many calls in one message. Make at most 8 at once."
	// leftOut stands for a tool result that the final call leaves out to fit the model's context window.
	leftOut = "[Left out of this request to fit the model's context window; the ledger holds it.]"
	// notSaid stands for what would settle the case, when the final summary doesn't say it apart.
	notSaid = "Not said apart in the summary."
	// maxQuoted is the most bytes of malformed arguments that the tool error quotes.
	maxQuoted = 1024
)

// The most characters of the three parts of a summary at a limit, as the schema of submit_no_verdict allows them.
const (
	maxWhy         = 500
	maxEstablished = 1000
	maxWouldSettle = 500
)

// maxCalls is the most tool calls of one message that the runner makes: each result goes into the next request, so the
// calls of one message, like the steps, are bounded by what the fit check counts.
const maxCalls = 8

// fields are the names of the limits in the profile and the ModelConfig, which the texts about them use.
var fields = map[string]string{verdict.ReasonMaxSteps: "maxSteps", verdict.ReasonMaxTokens: "maxTokens",
	verdict.ReasonTimeout: "timeoutSeconds", verdict.ReasonContextLimit: "contextWindowTokens"}

// Run judges a case through the session s, within the limits. It returns when the case has ended, at a limit, or at an
// error of the model or the end of ctx, which leave the case without an outcome. Whatever ends it, the session holds
// what the case recorded.
func (b Builtin) Run(ctx context.Context, s *mcp.ClientSession, in Input) Result {
	l := in.Limits
	caseCtx, cancel := context.WithTimeout(ctx, time.Duration(l.TimeoutSeconds)*time.Second)
	defer cancel()
	// timedOut reports whether the case's own deadline, and not the caller, ended the work.
	timedOut := func() bool { return ctx.Err() == nil && errors.Is(caseCtx.Err(), context.DeadlineExceeded) }
	c := &conversation{messages: []llm.Message{
		{Role: roleSystem, Content: in.Prompt},
		{Role: roleUser, Content: caseFileLead + string(in.CaseFile)},
	}}
	var res Result
	for res.Limit == "" {
		if res.Steps >= l.MaxSteps {
			res.Limit = verdict.ReasonMaxSteps
			continue
		}
		tools, err := toolsOf(caseCtx, s)
		if err == nil {
			next := estimate(c.messages, tools)
			// A step needs room for its answer, and the final call for the summary from the reserve. Budgets count
			// the endpoint's usage, and a step near maxTokens spends a whole prompt, and the final call another.
			switch {
			case in.ContextWindowTokens > 0 && next+max(prompt.StepMaxTokens, l.ReservedTokens) > in.ContextWindowTokens:
				res.Limit = verdict.ReasonContextLimit
				continue
			case res.Usage.PromptTokens+res.Usage.CompletionTokens+2*next+l.ReservedTokens > l.MaxTokens:
				res.Limit = verdict.ReasonMaxTokens
				continue
			}
			res.PeakContextTokens = max(res.PeakContextTokens, next)
			var resp *llm.Response
			if resp, err = b.Client.Complete(caseCtx, llm.Request{Messages: c.messages, Tools: tools, ToolChoice: "auto",
				MaxTokens: prompt.StepMaxTokens}); err == nil {
				res.Steps++
				res.add(resp.Usage)
				var ended bool
				if ended, err = c.answer(caseCtx, s, resp.Message); ended {
					return res
				}
			}
		}
		switch {
		case err == nil:
		case timedOut():
			res.Limit = verdict.ReasonTimeout
		default:
			res.Err = err
			return res
		}
	}
	b.final(ctx, s, c, in, &res)
	return res
}

// final makes the one call without tools at a limit, from the reserved budget, and passes its summary to
// submit_no_verdict with the limit. A reserve of 0 keeps no budget for it. To fit the model's context window, the call
// leaves out tool results, the latest first. A call that doesn't fit even so, that fails, or that answers with no
// text, leaves the case with the limit alone, which the result names.
func (b Builtin) final(ctx context.Context, s *mcp.ClientSession, c *conversation, in Input, res *Result) {
	l := in.Limits
	if l.ReservedTokens <= 0 {
		return
	}
	messages := append(slices.Clone(c.messages), llm.Message{Role: roleUser, Content: fmt.Sprintf("The case has "+
		"reached its limit %s, so you can call no more tools. Write its summary for a person, without a tool and "+
		"without headings, in two parts of a few sentences each. Start the first with the line \"Established:\", "+
		"and say what you established, citing the ledger IDs (ev-N). Start the second with the line \"Would "+
		"settle:\", and say what evidence would settle the case.", fields[res.Limit])})
	if in.ContextWindowTokens > 0 {
		room := in.ContextWindowTokens - l.ReservedTokens
		for i := len(messages) - 1; i >= 0 && estimate(messages, nil) > room; i-- {
			if messages[i].Role == roleTool && len(messages[i].Content) > len(leftOut) {
				messages[i].Content = leftOut
			}
		}
		if estimate(messages, nil) > room {
			return
		}
	}
	res.PeakContextTokens = max(res.PeakContextTokens, estimate(messages, nil))
	resp, err := b.Client.Complete(ctx, llm.Request{Messages: messages, MaxTokens: l.ReservedTokens})
	if err != nil {
		return
	}
	res.add(resp.Usage)
	summary := strings.TrimSpace(resp.Message.Content)
	if summary == "" {
		return
	}
	established, wouldSettle := splitSummary(summary)
	if wouldSettle == "" {
		wouldSettle = notSaid
	}
	// The session ends the case with the limit as its reason. Whether it took the summary shows in its outcome.
	_, _ = s.CallTool(ctx, &mcp.CallToolParams{Name: "submit_no_verdict", Meta: mcp.Meta{core.LimitMeta: res.Limit},
		Arguments: map[string]string{
			"why":         text.CutChars(why(res.Limit, in, res.Usage), maxWhy),
			"established": text.CutChars(strings.TrimSpace(established), maxEstablished),
			"wouldSettle": text.CutChars(wouldSettle, maxWouldSettle),
		}})
}

// splitSummary splits the summary at a limit into what the model established and what would settle the case: at the
// label "Would settle", where it wrote one, else at the first blank line. The labels and the lines of headings go, so
// that a heading such as "# What I established" lands in neither part. Where that leaves nothing established, the
// whole summary is, and what would settle the case isn't said apart: the session refuses an empty established, and
// the summary would be lost.
func splitSummary(summary string) (established, wouldSettle string) {
	lines := strings.Split(summary, "\n")
	at := slices.IndexFunc(lines, func(line string) bool { return isLabel(line, wouldSettleLabels) })
	if at < 0 {
		first, rest, _ := strings.Cut(summary, "\n\n")
		established, wouldSettle = withoutLabels(strings.Split(first, "\n")), withoutLabels(strings.Split(rest, "\n"))
	} else {
		rest := slices.Clone(lines[at:])
		rest[0] = afterLabel(rest[0])
		established, wouldSettle = withoutLabels(lines[:at]), withoutLabels(rest)
	}
	if established == "" {
		return withoutLabels(lines), notSaid
	}
	return established, wouldSettle
}

var (
	// wouldSettleLabels and establishedLabels are how a model labels the two parts of a summary at a limit.
	wouldSettleLabels = []string{"would settle", "would settle the case", "what would settle",
		"what would settle the case"}
	establishedLabels = []string{"established", "what i established", "what was established"}
)

// isLabel reports whether the line is one of the labels: a heading that starts with one, or one before a colon, also
// as an item of a list.
func isLabel(line string, labels []string) bool {
	bare := strings.TrimLeft(line, "#*_- \t")
	head, _, colon := strings.Cut(bare, ":")
	head = strings.ToLower(strings.Trim(head, "*_ \t"))
	heading := strings.HasPrefix(strings.TrimSpace(line), "#")
	return slices.ContainsFunc(labels, func(label string) bool {
		return (colon && head == label) || (heading && strings.HasPrefix(head, label))
	})
}

// withoutLabels joins the lines without headings, and without the label "Established" that may open them.
func withoutLabels(lines []string) string {
	var kept []string
	for _, line := range lines {
		switch {
		case len(kept) == 0 && isLabel(line, establishedLabels):
			line = afterLabel(line)
		case strings.HasPrefix(strings.TrimSpace(line), "#"):
			continue
		}
		if len(kept) > 0 || strings.TrimSpace(line) != "" {
			kept = append(kept, line)
		}
	}
	return strings.TrimSpace(strings.Join(kept, "\n"))
}

// afterLabel returns what follows a label such as "**Would settle:**" or "## Established:" on its line: "" for a
// heading without a colon, or a line that holds only the label.
func afterLabel(line string) string {
	_, rest, colon := strings.Cut(line, ":")
	if !colon {
		return ""
	}
	return strings.TrimSpace(strings.TrimLeft(rest, "*_ "))
}

// why says which limit ended the case, in the runner's words.
func why(limit string, in Input, used llm.Usage) string {
	l := in.Limits
	switch limit {
	case verdict.ReasonMaxSteps:
		return fmt.Sprintf("The case reached its limit of %d model calls with tools (maxSteps) without a verdict.",
			l.MaxSteps)
	case verdict.ReasonMaxTokens:
		return fmt.Sprintf("The case spent %d tokens, and its next step with this summary could have passed its "+
			"limit of %d (maxTokens), without a verdict.", used.PromptTokens+used.CompletionTokens, l.MaxTokens)
	case verdict.ReasonContextLimit:
		return fmt.Sprintf("The case's next request would no longer fit the model's context window of %d tokens "+
			"(contextWindowTokens), with room for an answer, without a verdict.", in.ContextWindowTokens)
	}
	return fmt.Sprintf("The case ran out of its %d seconds (timeoutSeconds) without a verdict.", l.TimeoutSeconds)
}

// add adds the usage of a request.
func (r *Result) add(u llm.Usage) {
	r.Usage.PromptTokens += u.PromptTokens
	r.Usage.CompletionTokens += u.CompletionTokens
}
