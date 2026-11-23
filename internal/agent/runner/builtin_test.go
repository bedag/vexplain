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
	"fmt"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"k8s.io/utils/ptr"

	"github.com/bedag/vexplain/internal/agent/core"
	"github.com/bedag/vexplain/internal/agent/prompt"
	"github.com/bedag/vexplain/internal/agent/verdict"
)

// coreTools are the tools that a case starts with.
var coreTools = []string{"read_evidence", "search_evidence", "search_tools", "submit_no_verdict", "submit_verdict"}

func sorted(names []string) []string { return slices.Sorted(slices.Values(names)) }

func TestTheRunnerStartsWithTheCoreToolsAndDescribeAndLoadsFoundOnes(t *testing.T) {
	f := run(t, options{forwarder: &forwarder{tools: []core.Tool{describeTool, fetchTool}}}, func(n int, _ request) answer {
		switch n {
		case 1:
			return call("search_tools", findTools("fetch a page"))
		case 2:
			return call(describe, describing)
		}
		return call("submit_verdict", affected("ev-2"))
	})

	requests := f.model.requests()
	require.Len(t, requests, 3)
	require.Equal(t, sorted(append(slices.Clone(coreTools), describe)), sorted(requests[0].toolNames()),
		"the core tools and describe, and search_tools to find the others")
	require.Equal(t, sorted(append(slices.Clone(coreTools), describe, fetch)), sorted(requests[1].toolNames()),
		"the found tool is listed from the next request on")
	require.Equal(t, "auto", requests[0].ToolChoice)
	require.Equal(t, 4096, prompt.StepMaxTokens)
	for _, r := range requests {
		require.Equal(t, prompt.StepMaxTokens, r.MaxTokens, "a step's answer is bounded, as the fit check counts it")
	}
	require.Equal(t, "system", requests[0].Messages[0].Role)
	require.Equal(t, thePrompt, ptr.Deref(requests[0].Messages[0].Content, ""))
	require.Contains(t, ptr.Deref(requests[0].Messages[1].Content, ""), vulnerability, "the case file comes first")
	require.Contains(t, requests[2].toolResults()[1], "answer of "+describe)

	outcome := f.session.Outcome()
	require.NotNil(t, outcome.Verdict)
	require.Equal(t, "Affected", outcome.Verdict.Status)
	require.Equal(t, 3, f.result.Steps)
	require.Empty(t, f.result.Limit)
	require.NoError(t, f.result.Err)
	require.Equal(t, 30, f.result.Usage.PromptTokens, "the usage that the endpoint reported, summed")
	require.Equal(t, 15, f.result.Usage.CompletionTokens)
}

// Review Focus 3: a tool result far over toolResultMaxTokens, every step. The model sees a page of each, so no request
// passes the profile's worst case, and at the limit the case ends without a verdict, with a summary.
func TestAToolResultOverTheCapIsCutForTheModel(t *testing.T) {
	limits := defaultLimits
	page := 4 * limits.ToolResultMaxTokens
	f := run(t, options{forwarder: &forwarder{tools: []core.Tool{describeTool}, out: lines(10 * page / 100)}},
		func(n int, r request) answer {
			switch {
			case isFinal(r):
				return answer{text: summary}
			}
			return call(describe, describing)
		})

	requests := f.model.requests()
	require.Len(t, requests, limits.MaxSteps+1, "maxSteps calls with tools, and the final call")
	worst := worstCase(limits)
	for i, r := range requests {
		require.LessOrEqual(t, (r.size+3)/4, worst, "request %d stays within the worst case, JSON and all", i+1)
		for _, result := range r.toolResults() {
			require.LessOrEqual(t, len(result), page+256, "a result is a page, and the line that says how to read on")
		}
	}
	require.Contains(t, requests[2].toolResults()[1], "read_evidence", "the model learns how to read on")
	require.Positive(t, f.result.PeakContextTokens)
	require.LessOrEqual(t, f.result.PeakContextTokens, worst)

	outcome := f.session.Outcome()
	require.Nil(t, outcome.Verdict, "a limit never ends in a verdict")
	require.NotNil(t, outcome.NoVerdict)
	require.Equal(t, verdict.ReasonMaxSteps, outcome.NoVerdict.Reason)
}

func TestAtTheStepLimitOneFinalCallWithoutTools(t *testing.T) {
	limits := defaultLimits
	limits.MaxSteps = 3
	f := run(t, options{limits: limits}, func(_ int, r request) answer {
		if isFinal(r) {
			return answer{text: summary}
		}
		return call("search_evidence", anotherSearch())
	})

	requests := f.model.requests()
	require.Len(t, requests, 4, "maxSteps calls with tools, then one without")
	for _, r := range requests[:3] {
		require.NotEmpty(t, r.Tools)
	}
	final := requests[3]
	require.Empty(t, final.Tools, "the final call offers no tool")
	require.Empty(t, final.ToolChoice)
	require.Equal(t, limits.ReservedTokens, final.MaxTokens, "the final call answers from the reserved budget")
	asked := ptr.Deref(final.Messages[len(final.Messages)-1].Content, "")
	require.Contains(t, asked, "maxSteps")
	require.Len(t, final.toolResults(), 3, "the final call sees every result")

	require.Equal(t, verdict.ReasonMaxSteps, f.result.Limit)
	require.Equal(t, 3, f.result.Steps, "the final call is no step")
	outcome := f.session.Outcome()
	require.Nil(t, outcome.Verdict)
	require.NotNil(t, outcome.NoVerdict, "the summary goes to submit_no_verdict")
	require.Equal(t, verdict.ReasonMaxSteps, outcome.NoVerdict.Reason)
	require.Contains(t, outcome.NoVerdict.Why, "maxSteps")
	require.Equal(t, "The image installs libbrotli1 1.0.9-2 (ev-1).", outcome.NoVerdict.Established)
	require.Equal(t, "A fixed version for the release would settle it.", outcome.NoVerdict.WouldSettle)
	require.Equal(t, 3, outcome.Ledger.Len())
}

// The summary at a limit is split at its label, and a model's headings land in neither part.
func TestTheSummaryAtALimitIsSplitAtItsLabel(t *testing.T) {
	const fact, settle = "The image installs libbrotli1 1.0.9-2 (ev-1).", "A fixed version."
	for name, tc := range map[string]struct{ text, established, wouldSettle string }{
		"labelled": {"Established:\n" + fact + "\n\nWould settle:\n" + settle, fact, settle},
		"headings": {"# What I Established\n\n- " + fact + "\n- Nothing loads it (ev-2).\n\n# What Would Settle " +
			"the Case\n\n" + settle, "- " + fact + "\n- Nothing loads it (ev-2).", settle},
		"on one line": {"**Established:** " + fact + "\n**Would settle:** " + settle, fact, settle},
		"unlabelled":  {summary, fact, "A fixed version for the release would settle it."},
		"a list":      {"- Established: " + fact + "\n- Would settle: " + settle, fact, settle},
		// Where the split leaves nothing established, the whole summary is, so that none of it is lost.
		"a label alone before a blank line": {"Established:\n\n" + fact + "\n\nWhat would settle the case is a fixed version.",
			fact + "\n\nWhat would settle the case is a fixed version.", "Not said apart in the summary."},
		"a labelled heading": {"## Established: " + fact + "\n\nWould settle: " + settle, fact, settle},
		"would settle first": {"Would settle: " + settle + "\n\nEstablished: " + fact,
			"Would settle: " + settle + "\n\nEstablished: " + fact, "Not said apart in the summary."},
	} {
		t.Run(name, func(t *testing.T) {
			limits := defaultLimits
			limits.MaxSteps = 1
			f := run(t, options{limits: limits}, func(_ int, r request) answer {
				if isFinal(r) {
					return answer{text: tc.text}
				}
				return call("search_evidence", searchLib)
			})
			final := f.model.requests()[1]
			asked := ptr.Deref(final.Messages[len(final.Messages)-1].Content, "")
			require.Contains(t, asked, "Established:")
			require.Contains(t, asked, "Would settle:")
			outcome := f.session.Outcome()
			require.NotNil(t, outcome.NoVerdict)
			require.Equal(t, tc.established, outcome.NoVerdict.Established)
			require.Equal(t, tc.wouldSettle, outcome.NoVerdict.WouldSettle)
		})
	}
}

func TestWhenTheFinalCallFailsTheLimitIsRecorded(t *testing.T) {
	limits := defaultLimits
	limits.MaxSteps = 2
	for name, final := range map[string]answer{
		"an error of the endpoint": {status: http.StatusInternalServerError},
		"an empty answer":          {},
		"a tool call":              call("search_evidence", anotherSearch()),
	} {
		t.Run(name, func(t *testing.T) {
			f := run(t, options{limits: limits}, func(_ int, r request) answer {
				if isFinal(r) {
					return final
				}
				return call("search_evidence", anotherSearch())
			})

			require.Len(t, f.model.requests(), 3)
			require.Equal(t, verdict.ReasonMaxSteps, f.result.Limit, "which limit tripped")
			require.Equal(t, 2, f.session.Outcome().Ledger.Len())
			require.Nil(t, f.session.Outcome().Verdict)
			require.Nil(t, f.session.Outcome().NoVerdict, "no summary to pass on")
		})
	}
}

func TestTheTokenBudgetAndTheTimeoutAreLimitsToo(t *testing.T) {
	t.Run("maxTokens", func(t *testing.T) {
		limits := defaultLimits
		limits.MaxTokens, limits.ReservedTokens = 12000, 500
		f := run(t, options{limits: limits}, func(_ int, r request) answer {
			if isFinal(r) {
				return answer{text: summary, measured: true, completion: 50}
			}
			a := call("search_evidence", anotherSearch())
			a.measured, a.completion = true, 50
			return a
		})

		requests := f.model.requests()
		final := requests[len(requests)-1]
		require.True(t, isFinal(final))
		require.Equal(t, 500, final.MaxTokens)
		require.Equal(t, verdict.ReasonMaxTokens, f.result.Limit)
		require.Less(t, f.result.Steps, limits.MaxSteps)
		require.LessOrEqual(t, f.result.Usage.PromptTokens+f.result.Usage.CompletionTokens, limits.MaxTokens,
			"the steps and the final call stay within maxTokens")
		require.NotNil(t, f.session.Outcome().NoVerdict)
		require.Equal(t, verdict.ReasonMaxTokens, f.session.Outcome().NoVerdict.Reason)
		require.Contains(t, f.session.Outcome().NoVerdict.Why, "maxTokens")
	})

	t.Run("timeoutSeconds", func(t *testing.T) {
		limits := defaultLimits
		limits.TimeoutSeconds = 1
		start := time.Now()
		f := run(t, options{limits: limits}, func(n int, r request) answer {
			switch {
			case isFinal(r):
				return answer{text: summary}
			case n == 2:
				return answer{delay: 3 * time.Second, text: "too late"}
			}
			return call("search_evidence", anotherSearch())
		})

		require.Less(t, time.Since(start), 3*time.Second, "the case ends at its deadline, not the request's")
		require.Equal(t, verdict.ReasonTimeout, f.result.Limit)
		require.Len(t, f.model.requests(), 3, "the final call comes after the deadline")
		require.NotNil(t, f.session.Outcome().NoVerdict)
		require.Equal(t, verdict.ReasonTimeout, f.session.Outcome().NoVerdict.Reason)
		require.Contains(t, f.session.Outcome().NoVerdict.Why, "timeoutSeconds")
	})
}

// Main design 6.6: a tool call whose arguments aren't JSON gets a tool error that quotes them, and the history replays
// it with {}, because some endpoints parse replayed arguments and refuse the whole request.
func TestMalformedArgumentsGetAToolErrorAndEmptyArgumentsInTheHistory(t *testing.T) {
	const malformed = `{"name": "contents", "query":`
	f := run(t, options{}, func(n int, _ request) answer {
		switch n {
		case 1:
			return answer{calls: [][2]string{{"search_evidence", malformed}}}
		case 2:
			return call("search_evidence", anotherSearch())
		}
		return call("submit_no_verdict", map[string]any{"why": "The database names no fix.",
			"established": "The image installs the library (ev-1).", "wouldSettle": "A fixed version."})
	})

	requests := f.model.requests()
	require.Len(t, requests, 3)
	second := requests[1]
	assistant := second.Messages[len(second.Messages)-2]
	require.Equal(t, "assistant", assistant.Role)
	require.Equal(t, "{}", assistant.ToolCalls[0].Function.Arguments, "the history replays {}")
	result := second.toolResults()[0]
	require.Contains(t, result, malformed, "the tool error quotes the raw text")
	require.Contains(t, strings.ToLower(result), "json")
	require.Equal(t, 1, f.session.Outcome().Ledger.Len(), "the malformed call never reached the core")
	require.NotNil(t, f.session.Outcome().NoVerdict)
	require.Equal(t, verdict.ReasonGaveUp, f.session.Outcome().NoVerdict.Reason)
}

// One message's tool calls are made up to 8: each call's result goes into the next request, so a message of many calls
// could pass the context that the fit check counts.
func TestAtMostEightToolCallsOfOneMessageAreMade(t *testing.T) {
	f := run(t, options{}, func(n int, _ request) answer {
		if n > 1 {
			return call("submit_no_verdict", map[string]any{"why": "The database names no fix.",
				"established": "The image installs the library (ev-1).", "wouldSettle": "A fixed version."})
		}
		var a answer
		for range 10 {
			a.calls = append(a.calls, call("search_evidence", anotherSearch()).calls...)
		}
		return a
	})

	results := f.model.requests()[1].toolResults()
	require.Len(t, results, 10, "every call gets a result")
	for _, r := range results[8:] {
		require.Contains(t, r, "too many calls in one message")
	}
	require.Equal(t, 8, f.session.Outcome().Ledger.Len())
}

// A request that, with the reserve for the summary, would no longer fit the model's context window isn't made: the case
// ends at the limit ContextLimit.
func TestTheContextWindowIsALimitToo(t *testing.T) {
	limits := defaultLimits
	limits.ReservedTokens = 500
	page := 4 * limits.ToolResultMaxTokens
	window := 15000
	f := run(t, options{limits: limits, window: window,
		forwarder: &forwarder{tools: []core.Tool{describeTool}, out: lines(2 * page / 100)}},
		func(n int, r request) answer {
			switch {
			case isFinal(r):
				return answer{text: summary}
			}
			// Each step asks anew: a repeated call is answered from the ledger, and fills no context.
			return call(describe, map[string]any{"vulnerabilityID": vulnerability, "aliases": []string{fmt.Sprint("A-", n)}})
		})

	require.Equal(t, verdict.ReasonContextLimit, f.result.Limit)
	require.Less(t, f.result.Steps, limits.MaxSteps)
	for i, r := range f.model.requests() {
		require.LessOrEqual(t, (r.size+3)/4+limits.ReservedTokens, window+window/10,
			"request %d fits the window, with the reserve", i+1)
	}
	require.NotNil(t, f.session.Outcome().NoVerdict)
	require.Equal(t, verdict.ReasonContextLimit, f.session.Outcome().NoVerdict.Reason)
	require.Contains(t, f.session.Outcome().NoVerdict.Why, "contextWindowTokens")
}
