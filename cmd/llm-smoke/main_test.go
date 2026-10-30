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

package main

import (
	"bytes"
	"context"
	"net/http"
	"regexp"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/bedag/vexplain/internal/llm"
)

// summaryPattern matches the line that the tool ends with.
var summaryPattern = regexp.MustCompile(`(?m)^tool_call_ok=(\d+)/(\d+) p50_ms=(\d+) p95_ms=(\d+)$`)

// summary returns the numbers of the summary line of the output: the runs that passed, the runs,
// and the two latencies in milliseconds.
func summary(t *testing.T, output string) (passed, runs, p50, p95 int) {
	t.Helper()
	match := summaryPattern.FindStringSubmatch(output)
	require.NotNil(t, match, "no summary line in:\n%s", output)
	numbers := make([]int, 0, 4)
	for _, text := range match[1:] {
		n, err := strconv.Atoi(text)
		require.NoError(t, err)
		numbers = append(numbers, n)
	}
	return numbers[0], numbers[1], numbers[2], numbers[3]
}

// runsFrom returns the numbers of the runs from first to last.
func runsFrom(first, last int) []int {
	runs := make([]int, 0, last-first+1)
	for run := first; run <= last; run++ {
		runs = append(runs, run)
	}
	return runs
}

func TestPassingRunsScoreInFull(t *testing.T) {
	server := newScriptedServer(t, newScript())

	code, output := runSmoke(t, server)

	require.Equal(t, exitOK, code)
	passed, runs, _, _ := summary(t, output)
	require.Equal(t, 20, passed)
	require.Equal(t, 20, runs)
	// Two turns for each of the 20 runs, and one replay check.
	require.Len(t, server.chats(), 40)
	require.Len(t, server.replays(), 1)
	requireNoLeak(t, output, testKey)
}

func TestExitCodeFollowsTheThreshold(t *testing.T) {
	for name, tc := range map[string]struct {
		broken []int
		passed int
		code   int
	}{
		"all runs pass":                  {nil, 20, exitOK},
		"18 of 20 is the lowest to pass": {[]int{4, 11}, 18, exitOK},
		"17 of 20 is below it":           {[]int{4, 11, 19}, 17, exitBelowThreshold},
		"nothing passes":                 {runsFrom(1, 20), 0, exitBelowThreshold},
	} {
		t.Run(name, func(t *testing.T) {
			s := newScript()
			for i, run := range tc.broken {
				// The broken runs fail in turn 1 and in turn 2 in turn.
				if i%2 == 0 {
					s.breaking1(reply{calls: []toolCall{{toolLookup, badArguments}}}, run)
				} else {
					s.breaking2(lookupReply, run)
				}
			}
			server := newScriptedServer(t, s)

			code, output := runSmoke(t, server)

			require.Equal(t, tc.code, code)
			passed, runs, _, _ := summary(t, output)
			require.Equal(t, tc.passed, passed)
			require.Equal(t, 20, runs)
		})
	}
}

func TestARunCountsOnlyWhenBothTurnsPass(t *testing.T) {
	server := newScriptedServer(t, newScript().
		breaking1(reply{text: knowsAlready}, 1).
		breaking2(reply{text: "Done."}, 2))

	code, output := runSmoke(t, server, "--runs=3")

	passed, runs, _, _ := summary(t, output)
	require.Equal(t, 1, passed, "run 1 fails in turn 1 and run 2 in turn 2")
	require.Equal(t, 3, runs)
	require.Equal(t, exitBelowThreshold, code)
	// Run 1 stops after turn 1, because there is no tool call to answer.
	require.Len(t, server.chats(), 5)
}

func TestEachKindOfFailureFailsTheRun(t *testing.T) {
	const turn1, turn2 = "turn 1", "turn 2"
	notJSON := toolCall{toolSubmit, badArguments}
	for name, tc := range map[string]struct {
		script *script
		turn   string
	}{
		"turn 1 arguments that are no JSON": {
			newScript().breaking1(reply{calls: []toolCall{{toolLookup, badArguments}}}, 1), turn1},
		"turn 1 no arguments at all": {
			newScript().breaking1(reply{calls: []toolCall{{toolLookup, ""}}}, 1), turn1},
		"turn 1 a text and no tool call": {
			newScript().breaking1(reply{text: knowsAlready}, 1), turn1},
		"turn 1 two tool calls": {
			newScript().breaking1(reply{calls: []toolCall{lookupReply.calls[0], lookupReply.calls[0]}}, 1), turn1},
		"turn 1 the wrong tool": {
			newScript().breaking1(submitReply, 1), turn1},
		"turn 1 an HTTP error": {
			newScript().breaking1(reply{status: http.StatusInternalServerError}, 1), turn1},
		"turn 2 arguments that are no JSON": {
			newScript().breaking2(reply{calls: []toolCall{notJSON}}, 1), turn2},
		"turn 2 a text and no tool call": {
			newScript().breaking2(reply{text: "Done."}, 1), turn2},
		"turn 2 the wrong tool": {
			newScript().breaking2(lookupReply, 1), turn2},
		"turn 2 an HTTP error": {
			newScript().breaking2(reply{status: http.StatusBadRequest}, 1), turn2},
	} {
		t.Run(name, func(t *testing.T) {
			server := newScriptedServer(t, tc.script)

			code, output := runSmoke(t, server, "--runs=1")

			passed, runs, _, _ := summary(t, output)
			require.Equal(t, 0, passed)
			require.Equal(t, 1, runs)
			require.Equal(t, exitBelowThreshold, code)
			require.Regexp(t, `(?m)^run 1 failed: `+tc.turn+`: .+$`, output)
			requireNoLeak(t, output, testKey)
		})
	}
}

func TestTurn2MayCallOtherToolsBesidesSubmitAnswer(t *testing.T) {
	both := reply{calls: []toolCall{lookupReply.calls[0], submitReply.calls[0]}}
	server := newScriptedServer(t, newScript().breaking2(both, 1))

	_, output := runSmoke(t, server, "--runs=1")

	passed, _, _, _ := summary(t, output)
	require.Equal(t, 1, passed, "turn 2 needs a submit_answer call, and doesn't mind others")
}

func TestARunFailingDoesNotStopTheOthers(t *testing.T) {
	server := newScriptedServer(t, newScript().breaking1(reply{status: http.StatusInternalServerError}, 2))

	_, output := runSmoke(t, server, "--runs=4")

	passed, runs, _, _ := summary(t, output)
	require.Equal(t, 3, passed)
	require.Equal(t, 4, runs)
}

func TestTheRequestsOfTheTwoTurns(t *testing.T) {
	server := newScriptedServer(t, newScript())

	runSmoke(t, server, "--runs=1")

	chats := server.chats()
	require.Len(t, chats, 2)
	first, second := chats[0], chats[1]

	// Turn 1: a system message and a question about Brotli, both tools, and the model decides.
	require.Equal(t, "Bearer "+testKey, first.authorization)
	require.Equal(t, testModel, first.Model)
	require.InDelta(t, 0.2, first.Temperature, 1e-9)
	require.Equal(t, "auto", first.ToolChoice)
	require.Equal(t, []string{toolLookup, toolSubmit}, first.toolNames())
	require.Equal(t, roleSystem+" "+roleUser, roles(first.Messages))
	require.Contains(t, *first.Messages[1].Content, "Brotli")

	// Turn 2: the same conversation, the assistant message with its tool call, the result of the
	// call, and a tool call is required.
	require.Equal(t, "required", second.ToolChoice)
	require.Equal(t, []string{toolLookup, toolSubmit}, second.toolNames())
	require.Equal(t, roleSystem+" "+roleUser+" "+roleAssistant+" "+roleTool, roles(second.Messages))
	assistant, result := second.Messages[2], second.Messages[3]
	require.Len(t, assistant.ToolCalls, 1)
	require.Equal(t, toolLookup, assistant.ToolCalls[0].Function.Name)
	require.JSONEq(t, `{"name":"brotli"}`, assistant.ToolCalls[0].Function.Arguments)
	require.NotEmpty(t, assistant.ToolCalls[0].ID)
	require.Equal(t, assistant.ToolCalls[0].ID, result.ToolCallID, "the result answers the call")
	require.NotEmpty(t, *result.Content)
}

func TestTurn2ReplaysTheModelsMessageAsAnAssistantMessage(t *testing.T) {
	// Whatever role the server wrote in its answer, the message goes back as the assistant's.
	asked := reply{role: "model", calls: lookupReply.calls}
	server := newScriptedServer(t, newScript().breaking1(asked, 1))

	runSmoke(t, server, "--runs=1")

	second := server.chats()[1]
	require.Equal(t, roleAssistant, second.Messages[2].Role)
}

func TestTheReplayCheckIsNoLatency(t *testing.T) {
	// Two requests of the run, and a replay that takes much longer than they do. The 95th percentile
	// of three durations is the slowest of them, so it would show the replay if it counted.
	server := newScriptedServer(t, newScript().replaying(reply{text: noted, delay: 400 * time.Millisecond}))

	_, output := runSmoke(t, server, "--runs=1")

	_, _, _, p95 := summary(t, output)
	require.Less(t, p95, 400)
}

func TestTheReplayCheckIsInformationOnly(t *testing.T) {
	const prefix = `bad_arguments_replay=`
	for name, tc := range map[string]struct {
		answer reply
		line   string
	}{
		"accepted":            {reply{text: noted}, prefix + `accepted`},
		"rejected with a 400": {reply{status: http.StatusBadRequest}, prefix + `rejected \(HTTP 400\)`},
		"rejected with a 422": {reply{status: http.StatusUnprocessableEntity}, prefix + `rejected \(HTTP 422\)`},
		"a server error says little": {
			reply{status: http.StatusInternalServerError}, prefix + `inconclusive \(.*HTTP 500.*\)`},
		"a refused key says little": {
			reply{status: http.StatusUnauthorized}, prefix + `inconclusive \(.*HTTP 401.*\)`},
	} {
		t.Run(name, func(t *testing.T) {
			server := newScriptedServer(t, newScript().replaying(tc.answer))

			code, output := runSmoke(t, server)

			require.Regexp(t, `(?m)^`+tc.line+`$`, output)
			passed, _, _, _ := summary(t, output)
			require.Equal(t, 20, passed, "the replay is no run, and not a score")
			require.Equal(t, exitOK, code, "and not the exit code")
		})
	}
}

func TestTheReplayCheckSendsOneToolCallWithBadArguments(t *testing.T) {
	server := newScriptedServer(t, newScript())

	runSmoke(t, server, "--runs=2")

	replays := server.replays()
	require.Len(t, replays, 1)
	messages := replays[0].Messages
	require.Equal(t, roleSystem+" "+roleUser+" "+roleAssistant+" "+roleTool, roles(messages))
	require.Len(t, messages[2].ToolCalls, 1)
	require.Equal(t, badArguments, messages[2].ToolCalls[0].Function.Arguments)
	require.Equal(t, messages[2].ToolCalls[0].ID, messages[3].ToolCallID)
}

func TestTheReplayCheckDoesNotRescueAFailingScore(t *testing.T) {
	server := newScriptedServer(t, newScript().
		breaking1(reply{text: knowsAlready}, 1, 2, 3).
		replaying(reply{text: noted}))

	code, output := runSmoke(t, server)

	require.Regexp(t, `(?m)^bad_arguments_replay=accepted$`, output)
	require.Equal(t, exitBelowThreshold, code)
}

func TestTheSummaryComesLast(t *testing.T) {
	server := newScriptedServer(t, newScript().breaking1(reply{text: knowsAlready}, 1))

	_, output := runSmoke(t, server, "--runs=2")

	lines := bytes.Split(bytes.TrimSpace([]byte(output)), []byte("\n"))
	require.Regexp(t, summaryPattern, string(lines[len(lines)-1]))
}

func TestLatenciesAreInMilliseconds(t *testing.T) {
	server := newScriptedServer(t, newScript())
	server.delay = 30 * time.Millisecond

	_, output := runSmoke(t, server, "--runs=3")

	_, _, p50, p95 := summary(t, output)
	require.GreaterOrEqual(t, p50, 30, "every request takes at least 30 ms")
	require.GreaterOrEqual(t, p95, p50)
}

func TestARequestThatFailsCountsInTheLatencies(t *testing.T) {
	// The only request of the run fails after 100 ms. A request that runs into a timeout is the
	// slowest there is, and the latencies must show it.
	server := newScriptedServer(t, newScript().
		breaking1(reply{status: http.StatusInternalServerError, delay: 100 * time.Millisecond}, 1))

	_, output := runSmoke(t, server, "--runs=1")

	_, _, p50, _ := summary(t, output)
	require.GreaterOrEqual(t, p50, 100)
}

func TestRunsAreSequential(t *testing.T) {
	server := newScriptedServer(t, newScript())
	server.delay = 5 * time.Millisecond

	runSmoke(t, server, "--runs=5")

	require.Equal(t, 1, server.peakConcurrency(), "one request at a time")
}

func TestTheNumberOfRunsIsAFlag(t *testing.T) {
	server := newScriptedServer(t, newScript())

	code, output := runSmoke(t, server, "--runs=5")

	passed, runs, _, _ := summary(t, output)
	require.Equal(t, 5, passed)
	require.Equal(t, 5, runs)
	require.Equal(t, exitOK, code)
	require.Len(t, server.chats(), 10)
}

func TestPassMarkIsNinetyPercentRoundedUp(t *testing.T) {
	for runs, want := range map[int]int{20: 18, 10: 9, 5: 5, 3: 3, 1: 1, 100: 90} {
		require.Equal(t, want, passMark(runs), "runs: %d", runs)
	}
}

func TestAnEmptyKeyIsAUsageErrorBeforeAnyRequest(t *testing.T) {
	for name, key := range map[string]string{"empty": "", "blank": "  \n"} {
		t.Run(name, func(t *testing.T) {
			server := newScriptedServer(t, newScript())
			var out bytes.Buffer

			code := run(context.Background(), []string{flagEndpoint, server.URL, flagModel, testModel},
				environment(key), &out, llm.WithHTTPClient(server.Client()))

			require.Equal(t, exitUsage, code)
			require.Contains(t, out.String(), keyEnv)
			require.Empty(t, server.all(), "no request was made")
		})
	}
}

func TestUsageErrors(t *testing.T) {
	for name, args := range map[string][]string{
		"no endpoint":        {flagModel, testModel},
		"no model":           {flagEndpoint, exampleURL},
		"no runs":            {flagEndpoint, exampleURL, flagModel, testModel, "--runs=0"},
		"negative runs":      {flagEndpoint, exampleURL, flagModel, testModel, "--runs=-3"},
		"an unknown flag":    {flagEndpoint, exampleURL, flagModel, testModel, "--verbose"},
		"a stray argument":   {flagEndpoint, exampleURL, flagModel, testModel, "extra"},
		"runs that are text": {flagEndpoint, exampleURL, flagModel, testModel, "--runs=many"},
	} {
		t.Run(name, func(t *testing.T) {
			var out bytes.Buffer

			code := run(context.Background(), args, environment(testKey), &out)

			require.Equal(t, exitUsage, code)
			require.Contains(t, out.String(), "Usage:")
			requireNoLeak(t, out.String(), testKey)
		})
	}
}

func TestTheEndpointIsNeverPrinted(t *testing.T) {
	// An endpoint can carry credentials in its userinfo or its query. Neither a usage error nor a
	// failed request may print it. This one is not https, so the client refuses it before any
	// request is made.
	const secrets = "pw-12345@llm.example/v1?token=tok-12345"
	for name, extra := range map[string][]string{
		"a usage error": {"--runs=0"},
		"failed runs":   {"--runs=1"},
	} {
		t.Run(name, func(t *testing.T) {
			var out bytes.Buffer
			args := append([]string{flagEndpoint, "http://user:" + secrets, flagModel, testModel}, extra...)

			run(context.Background(), args, environment(testKey), &out)

			require.NotContains(t, out.String(), "pw-12345")
			require.NotContains(t, out.String(), "tok-12345")
			requireNoLeak(t, out.String(), testKey)
		})
	}
}

func TestHelpExitsCleanly(t *testing.T) {
	var out bytes.Buffer

	code := run(context.Background(), []string{"--help"}, environment(testKey), &out)

	require.Equal(t, exitOK, code)
	require.Contains(t, out.String(), "Usage:")
}

func TestTheKeyIsNeverPrinted(t *testing.T) {
	// The server echoes the key it received into the body of its error, as some gateways do. The
	// key that the tool sends is not the one the server accepts, so every request fails.
	const wrongKey = "wrong-key-456"
	server := newScriptedServer(t, newScript())
	var out bytes.Buffer

	code := run(context.Background(), []string{flagEndpoint, server.URL, flagModel, testModel, "--runs=3"},
		environment(wrongKey), &out, llm.WithHTTPClient(server.Client()))

	require.Equal(t, exitBelowThreshold, code)
	passed, _, _, _ := summary(t, out.String())
	require.Equal(t, 0, passed)
	require.Contains(t, out.String(), "HTTP 401")
	requireNoLeak(t, out.String(), wrongKey)
}

func TestAnInterruptedRunStopsWithoutRequests(t *testing.T) {
	server := newScriptedServer(t, newScript())
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var out bytes.Buffer

	code := run(ctx, []string{flagEndpoint, server.URL, flagModel, testModel}, environment(testKey), &out,
		llm.WithHTTPClient(server.Client()))

	require.Equal(t, exitBelowThreshold, code)
	require.Contains(t, out.String(), "interrupted")
	require.Empty(t, server.all())
}

func TestSmokeConfigMatchesTheModelConfigDefaults(t *testing.T) {
	cfg := smokeConfig(exampleURL, testModel, llm.NewSecret(testKey))

	require.Equal(t, exampleURL, cfg.BaseURL)
	require.Equal(t, testModel, cfg.Model)
	require.Equal(t, 60*time.Second, cfg.Timeout)
	require.Equal(t, 1, cfg.MaxConcurrent)
	require.Equal(t, int32(200), cfg.TemperatureMilli)
}

func TestPercentile(t *testing.T) {
	ms := func(values ...int) []time.Duration {
		durations := make([]time.Duration, 0, len(values))
		for _, v := range values {
			durations = append(durations, time.Duration(v)*time.Millisecond)
		}
		return durations
	}
	twenty := ms(20, 1, 19, 2, 18, 3, 17, 4, 16, 5, 15, 6, 14, 7, 13, 8, 12, 9, 11, 10)

	require.Equal(t, 30*time.Millisecond, percentile(ms(50, 10, 30, 20, 40), 50), "the median of five")
	require.Equal(t, 50*time.Millisecond, percentile(ms(50, 10, 30, 20, 40), 95), "the nearest rank rounds up")
	require.Equal(t, 10*time.Millisecond, percentile(twenty, 50))
	require.Equal(t, 19*time.Millisecond, percentile(twenty, 95))
	require.Equal(t, 7*time.Millisecond, percentile(ms(7), 95))
	require.Zero(t, percentile(nil, 50))

	unsorted := ms(3, 1, 2)
	percentile(unsorted, 50)
	require.Equal(t, ms(3, 1, 2), unsorted, "the input is left as it was")
}
