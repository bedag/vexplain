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

// Command llm-smoke checks that a model endpoint can drive the agent loop of phase 4. It is the
// go/no-go for that loop: the loop is a conversation in which the model calls tools, so a model that
// can't do that reliably can't run it.
//
// A run has two turns. In turn 1 the model gets a question about a package and two tools, and may
// choose: it should call lookup_package, once, with arguments that are JSON. In turn 2 it gets the
// result of that call back and must call a tool: it should call submit_answer, with arguments that
// are JSON. A run passes only if both turns do. The tool makes 20 runs by default, prints how many
// passed with the latency of the requests, and exits non-zero when fewer than 90% did, which is 18
// of 20.
//
// It also tries one thing that doesn't count. Some servers, vLLM among them, parse the arguments of
// the tool calls that a conversation replays, and answer 400 when they are not JSON. The tool replays
// one call with arguments that are not, and prints whether the server takes it. That result decides
// how strictly the agent loop must clean its history of malformed calls (design section 6.6).
//
// Run it with the API key in the environment, never in a flag:
//
//	VEXPLAIN_LLM_API_KEY=... go run ./cmd/llm-smoke --endpoint https://llm.example/v1 --model model-a
//
// The key is only ever sent to the endpoint, and never printed: the client refuses to send it over a
// connection that is not https, except to the loopback, and its errors carry no response body.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/bedag/vexplain/internal/llm"
)

const (
	// keyEnv is the environment variable that holds the API key. The key doesn't come from a flag,
	// because a flag shows in the list of processes and in the history of the shell.
	keyEnv = "VEXPLAIN_LLM_API_KEY"

	// defaultRuns is the number of runs when --runs says nothing.
	defaultRuns = 20
)

// The exit codes.
const (
	exitOK             = 0
	exitBelowThreshold = 1
	exitUsage          = 2
)

// The settings of the client. The timeout and the temperature are the defaults of a ModelConfig
// (requestTimeoutSeconds 60, temperatureMilli 200), so that the tool measures what the operator will
// get. It makes one request at a time. The runs are sequential anyway, and the latencies should be
// those of a single call.
const (
	requestTimeout   = 60 * time.Second
	maxConcurrent    = 1
	temperatureMilli = 200
)

// The roles of the messages, and the values of tool_choice that the runs use.
const (
	roleSystem    = "system"
	roleUser      = "user"
	roleAssistant = "assistant"
	roleTool      = "tool"

	toolChoiceAuto     = "auto"
	toolChoiceRequired = "required"
)

// The two tools of a run, and the conversation around them.
const (
	toolLookup = "lookup_package"
	toolSubmit = "submit_answer"

	systemPrompt = "You answer questions about software packages. You know nothing about a package until you " +
		"have looked it up, so call lookup_package first. When you have its result, give your answer by " +
		"calling submit_answer. Always answer through a tool call, never in plain text."
	question = "What is the Brotli package, and what is it used for?"
	// lookupResult is what lookup_package returns in turn 2, whatever the model asked for.
	lookupResult = `{"name":"brotli","found":true,"summary":"A general-purpose lossless compression library ` +
		`and format, mostly used to compress web content."}`

	// badArguments are the arguments of the tool call that the replay check sends: not JSON.
	badArguments = "{bad"
	// replayCallID is the ID of that call.
	replayCallID = "call_replayed"
)

// tools are the tools that every request offers.
var tools = []llm.Tool{
	{
		Name:        toolLookup,
		Description: "Look a software package up by its name and return what is known about it.",
		Parameters: json.RawMessage(`{"type":"object","properties":{"name":{"type":"string",` +
			`"description":"the name of the package"}},"required":["name"]}`),
	},
	{
		Name:        toolSubmit,
		Description: "Submit the final answer to the question.",
		Parameters: json.RawMessage(`{"type":"object","properties":{"text":{"type":"string",` +
			`"description":"the answer"}},"required":["text"]}`),
	},
}

const usage = `Usage: llm-smoke --endpoint URL --model NAME [--runs N]

  --endpoint  the base URL of the endpoint, such as https://llm.example/v1
  --model     the name of the model, as the endpoint knows it
  --runs      the number of runs, each of which makes two requests (default 20)

The API key is read from the environment variable VEXPLAIN_LLM_API_KEY.

The exit code is 0 when at least 90% of the runs pass (18 of 20), 1 when fewer do, and 2 for a
usage error.
`

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := run(ctx, os.Args[1:], os.Getenv, os.Stdout)
	stop() // os.Exit doesn't run deferred calls.
	os.Exit(code)
}

// run is the tool. It takes what main takes from the process, so that a test can give it a script
// and read what it printed, and returns the exit code. opts change how the client is built: a test
// passes the HTTP client that trusts its TLS server.
func run(ctx context.Context, args []string, getenv func(string) string, out io.Writer, opts ...llm.Option) int {
	cfg, err := parseArguments(args, getenv)
	switch {
	case errors.Is(err, flag.ErrHelp):
		say(out, "%s", usage)
		return exitOK
	case err != nil:
		say(out, "llm-smoke: %v\n\n%s", err, usage)
		return exitUsage
	}

	s := &smoke{client: llm.New(smokeConfig(cfg.endpoint, cfg.model, cfg.key), opts...)}
	passed := 0
	for n := 1; n <= cfg.runs; n++ {
		if ctx.Err() != nil {
			say(out, "interrupted after %d of %d runs\n", n-1, cfg.runs)
			return exitBelowThreshold
		}
		if failure := s.attempt(ctx); failure != "" {
			say(out, "run %d failed: %s\n", n, failure)
			continue
		}
		passed++
	}

	// The replay check comes before the score, so that the score is the last line.
	say(out, "bad_arguments_replay=%s\n", s.replayBadArguments(ctx))
	say(out, "tool_call_ok=%d/%d p50_ms=%d p95_ms=%d\n", passed, cfg.runs,
		percentile(s.latencies, 50).Milliseconds(), percentile(s.latencies, 95).Milliseconds())
	if passed < passMark(cfg.runs) {
		return exitBelowThreshold
	}
	return exitOK
}

// say prints to out. The tool can do nothing about a terminal that it can't write to.
func say(out io.Writer, format string, args ...any) {
	_, _ = fmt.Fprintf(out, format, args...)
}

// arguments are what the command line and the environment say.
type arguments struct {
	endpoint, model string
	runs            int
	// key is the API key. It is a Secret, so that no print of the arguments can show it.
	key llm.Secret
}

// parseArguments reads the flags and the key. Its errors are for the person who ran the tool, and
// never quote the key.
func parseArguments(args []string, getenv func(string) string) (arguments, error) {
	flags := flag.NewFlagSet("llm-smoke", flag.ContinueOnError)
	flags.SetOutput(io.Discard) // run prints the error and the usage.
	endpoint := flags.String("endpoint", "", "")
	model := flags.String("model", "", "")
	runs := flags.Int("runs", defaultRuns, "")
	if err := flags.Parse(args); err != nil {
		return arguments{}, err
	}

	key := strings.TrimSpace(getenv(keyEnv))
	switch {
	case flags.NArg() > 0:
		return arguments{}, errors.New("unexpected arguments")
	case *endpoint == "":
		return arguments{}, errors.New("--endpoint is required")
	case *model == "":
		return arguments{}, errors.New("--model is required")
	case *runs < 1:
		return arguments{}, errors.New("--runs must be at least 1")
	case key == "":
		return arguments{}, fmt.Errorf("the API key is not set: put it in %s", keyEnv)
	}
	return arguments{endpoint: *endpoint, model: *model, runs: *runs, key: llm.NewSecret(key)}, nil
}

// smokeConfig returns the config of the client.
func smokeConfig(endpoint, model string, key llm.Secret) llm.Config {
	return llm.Config{
		BaseURL:          endpoint,
		Model:            model,
		APIKey:           key,
		Timeout:          requestTimeout,
		MaxConcurrent:    maxConcurrent,
		TemperatureMilli: temperatureMilli,
	}
}

// passMark is the number of runs that must pass: 90% of them, rounded up. Of the default 20 it is 18.
func passMark(runs int) int {
	return (runs*9 + 9) / 10
}

// percentile returns the p-th percentile of the durations by the nearest-rank method: the smallest
// value that at least p percent of the values are not above. It returns zero for no durations, and
// leaves its argument as it was.
func percentile(durations []time.Duration, p int) time.Duration {
	if len(durations) == 0 {
		return 0
	}
	sorted := slices.Clone(durations)
	slices.Sort(sorted)
	rank := (p*len(sorted) + 99) / 100 // the rank is p/100 of the count, rounded up
	return sorted[min(max(rank, 1), len(sorted))-1]
}

// conversation returns the start of every conversation of the tool, the system message and the
// question, followed by the messages that a turn adds.
func conversation(more ...llm.Message) []llm.Message {
	return append([]llm.Message{
		{Role: roleSystem, Content: systemPrompt},
		{Role: roleUser, Content: question},
	}, more...)
}

// smoke makes the requests and keeps how long they took.
type smoke struct {
	client *llm.Client
	// latencies are the durations of the requests of the runs, whether or not they succeeded. A
	// request that times out is the slowest there is, and that should show.
	latencies []time.Duration
}

// complete makes a request of a run, and records its duration.
func (s *smoke) complete(ctx context.Context, req llm.Request) (*llm.Response, error) {
	start := time.Now()
	resp, err := s.client.Complete(ctx, req)
	s.latencies = append(s.latencies, time.Since(start))
	return resp, err
}

// attempt makes the two turns of one run. It returns "" when both pass, and otherwise why one did
// not, in words that are fixed in this file and in the client: what the model wrote is never quoted
// but for the name of a tool, which is cut short.
func (s *smoke) attempt(ctx context.Context) string {
	first, err := s.complete(ctx, llm.Request{Messages: conversation(), Tools: tools, ToolChoice: toolChoiceAuto})
	if err != nil {
		return "turn 1: " + err.Error()
	}
	if why := checkLookup(first.Message); why != "" {
		return "turn 1: " + why
	}

	// Turn 2 sends back what the model said, and the result of its call. The role is set because the
	// message is the model's, whatever the server wrote in it.
	assistant := first.Message
	assistant.Role = roleAssistant
	result := llm.Message{Role: roleTool, ToolCallID: assistant.ToolCalls[0].ID, Content: lookupResult}
	second, err := s.complete(ctx, llm.Request{
		Messages: conversation(assistant, result), Tools: tools, ToolChoice: toolChoiceRequired,
	})
	if err != nil {
		return "turn 2: " + err.Error()
	}
	if why := checkSubmit(second.Message); why != "" {
		return "turn 2: " + why
	}
	return ""
}

// checkLookup returns what is wrong with the answer to turn 1: it must call lookup_package, and
// nothing else, with arguments that are JSON. It returns "" when nothing is.
func checkLookup(answer llm.Message) string {
	calls := answer.ToolCalls
	switch {
	case len(calls) == 0:
		return "the model made no tool call"
	case len(calls) > 1:
		return fmt.Sprintf("the model made %d tool calls, and one call of %s was expected", len(calls), toolLookup)
	case calls[0].Name != toolLookup:
		return fmt.Sprintf("the model called %s, and %s was expected", quoted(calls[0].Name), toolLookup)
	case !json.Valid([]byte(calls[0].Arguments)):
		return "the arguments of the call are not valid JSON"
	}
	return ""
}

// checkSubmit returns what is wrong with the answer to turn 2: it must call submit_answer, with
// arguments that are JSON. Other calls beside it don't matter. It returns "" when nothing is wrong.
func checkSubmit(answer llm.Message) string {
	calls := answer.ToolCalls
	if len(calls) == 0 {
		return "the model made no tool call"
	}
	i := slices.IndexFunc(calls, func(call llm.ToolCall) bool { return call.Name == toolSubmit })
	switch {
	case i < 0:
		return fmt.Sprintf("none of the %d tool calls is a call of %s, the first is %s",
			len(calls), toolSubmit, quoted(calls[0].Name))
	case !json.Valid([]byte(calls[i].Arguments)):
		return "the arguments of the call are not valid JSON"
	}
	return ""
}

// quoted returns a name from the model in quotes, and cut short, so that it can be printed.
func quoted(name string) string {
	const longest = 40
	if len(name) > longest {
		name = name[:longest] + "..."
	}
	return strconv.Quote(name)
}

// replayBadArguments sends a conversation that replays a tool call whose arguments are not JSON,
// and says whether the server takes it: "accepted", "rejected (HTTP 400)" or "inconclusive" with
// the reason. Only a 400 and a 422 are taken for a rejection. Any other failure, such as a server
// error or a refused key, doesn't show what the server thinks of the arguments.
//
// The request is no run, and its duration is not a latency.
func (s *smoke) replayBadArguments(ctx context.Context) string {
	call := llm.ToolCall{ID: replayCallID, Name: toolLookup, Arguments: badArguments}
	_, err := s.client.Complete(ctx, llm.Request{
		Messages: conversation(
			llm.Message{Role: roleAssistant, ToolCalls: []llm.ToolCall{call}},
			llm.Message{Role: roleTool, ToolCallID: replayCallID, Content: "error: the arguments are not valid JSON"},
		),
		Tools: tools, ToolChoice: toolChoiceAuto,
	})

	var refusal *llm.StatusError
	switch {
	case err == nil:
		return "accepted"
	case errors.As(err, &refusal) &&
		(refusal.Code == http.StatusBadRequest || refusal.Code == http.StatusUnprocessableEntity):
		return fmt.Sprintf("rejected (HTTP %d)", refusal.Code)
	default:
		return "inconclusive (" + err.Error() + ")"
	}
}
