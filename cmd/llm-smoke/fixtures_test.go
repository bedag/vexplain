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
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/bedag/vexplain/internal/llm"
)

const (
	// testKey is the API key of the tests. It is made up, and it must not show up in the output.
	testKey   = "smoke-key-123"
	testModel = "model-a"

	// exampleURL is an endpoint for the tests that never reach a server.
	exampleURL = "https://llm.example/v1"

	// The flags of the tool, and the texts of the scripted replies.
	flagEndpoint = "--endpoint"
	flagModel    = "--model"
	noted        = "noted"
	knowsAlready = "I know it already."

	// bodyMarker stands for the text of an error body. A gateway may echo the key in one.
	bodyMarker = "the-gateway-says"
)

// reply is what the scripted server answers to one request.
type reply struct {
	// status is the HTTP status. Zero means 200.
	status int
	// role is the role of the assistant message. Empty means "assistant".
	role string
	// delay is how long the server takes to answer this reply, on top of the delay of the server.
	delay time.Duration
	// text is the content of the assistant message.
	text string
	// calls are its tool calls.
	calls []toolCall
}

// toolCall is a tool call of an answer, as the model writes it.
type toolCall struct{ name, arguments string }

var (
	// lookupReply and submitReply are the answers of a model that works, to turn 1 and turn 2.
	lookupReply = reply{calls: []toolCall{{toolLookup, `{"name":"brotli"}`}}}
	submitReply = reply{calls: []toolCall{{toolSubmit, `{"text":"A compression library."}`}}}
)

// script says how the scripted server answers. The runs count from 1. A run without an entry gets
// the answers of a model that works, and the replay is accepted unless the script says otherwise.
type script struct {
	turn1  replies
	turn2  replies
	replay reply
}

// replies maps a run to the reply that the script gives it.
type replies map[int]reply

// orElse returns the reply of a run, or fallback when the run has none.
func (m replies) orElse(run int, fallback reply) reply {
	if r, ok := m[run]; ok {
		return r
	}
	return fallback
}

// newScript returns the script of a model that works in every run.
func newScript() *script {
	return &script{turn1: replies{}, turn2: replies{}, replay: reply{text: noted}}
}

// breaking1 makes the answer to turn 1 of the given runs r.
func (s *script) breaking1(r reply, runs ...int) *script {
	for _, run := range runs {
		s.turn1[run] = r
	}
	return s
}

// breaking2 makes the answer to turn 2 of the given runs r.
func (s *script) breaking2(r reply, runs ...int) *script {
	for _, run := range runs {
		s.turn2[run] = r
	}
	return s
}

// replaying makes the answer to the replay check r.
func (s *script) replaying(r reply) *script {
	s.replay = r
	return s
}

// The JSON of the chat completions API, as far as the server reads it.
type (
	wireRequest struct {
		Model       string        `json:"model"`
		Messages    []wireMessage `json:"messages"`
		Tools       []wireTool    `json:"tools"`
		ToolChoice  string        `json:"tool_choice"`
		Temperature float64       `json:"temperature"`
	}
	wireMessage struct {
		Role       string         `json:"role"`
		Content    *string        `json:"content"`
		ToolCalls  []wireToolCall `json:"tool_calls"`
		ToolCallID string         `json:"tool_call_id"`
	}
	wireToolCall struct {
		ID       string `json:"id"`
		Type     string `json:"type"`
		Function struct {
			Name      string `json:"name"`
			Arguments string `json:"arguments"`
		} `json:"function"`
	}
	wireTool struct {
		Function struct {
			Name string `json:"name"`
		} `json:"function"`
	}
)

// seen is one request that reached the scripted server.
type seen struct {
	wireRequest
	authorization string
}

// toolNames returns the names of the tools of the request.
func (s seen) toolNames() []string {
	names := make([]string, 0, len(s.Tools))
	for _, tool := range s.Tools {
		names = append(names, tool.Function.Name)
	}
	return names
}

// isReplay says whether the request replays a tool call with arguments that are not JSON.
func (s seen) isReplay() bool {
	for _, message := range s.Messages {
		for _, call := range message.ToolCalls {
			if call.Function.Arguments == badArguments {
				return true
			}
		}
	}
	return false
}

// isTurn2 says whether the request carries the result of a tool.
func (s seen) isTurn2() bool {
	return !s.isReplay() && strings.Contains(roles(s.Messages), roleTool)
}

// roles returns the roles of the messages, in order, separated by spaces.
func roles(messages []wireMessage) string {
	names := make([]string, 0, len(messages))
	for _, message := range messages {
		names = append(names, message.Role)
	}
	return strings.Join(names, " ")
}

// scriptedServer is a TLS server that plays a script. It tells the turns apart by what a request
// carries, and counts the runs by the requests of turn 1.
type scriptedServer struct {
	*httptest.Server
	script *script
	// delay is how long the server takes to answer. Set it before the first request.
	delay time.Duration

	mu       sync.Mutex
	requests []seen
	run      int
	nextCall int
	inFlight int
	peak     int
}

// newScriptedServer starts a server that plays s until the end of the test.
func newScriptedServer(t *testing.T, s *script) *scriptedServer {
	t.Helper()
	server := &scriptedServer{script: s}
	server.Server = httptest.NewTLSServer(http.HandlerFunc(server.handle))
	t.Cleanup(server.Close)
	return server
}

func (s *scriptedServer) handle(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	s.inFlight++
	s.peak = max(s.peak, s.inFlight)
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		s.inFlight--
		s.mu.Unlock()
	}()

	time.Sleep(s.delay)
	var request seen
	body, err := io.ReadAll(r.Body)
	if err != nil || json.Unmarshal(body, &request.wireRequest) != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	request.authorization = r.Header.Get("Authorization")

	answer := s.answerTo(request)
	time.Sleep(answer.delay)
	if answer.status != 0 && answer.status != http.StatusOK {
		// Like a gateway that echoes what it received into the body of its error.
		w.WriteHeader(answer.status)
		_, _ = io.WriteString(w, bodyMarker+" "+request.authorization)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(s.encode(answer))
}

// answerTo records the request and returns what the script says to answer it.
func (s *scriptedServer) answerTo(request seen) reply {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.requests = append(s.requests, request)
	switch {
	case request.authorization != "Bearer "+testKey:
		return reply{status: http.StatusUnauthorized}
	case request.isReplay():
		return s.script.replay
	case request.isTurn2():
		return s.script.turn2.orElse(s.run, submitReply)
	default:
		s.run++
		return s.script.turn1.orElse(s.run, lookupReply)
	}
}

// encode returns the body of a chat completion that carries the reply.
func (s *scriptedServer) encode(answer reply) []byte {
	message := map[string]any{"role": cmp.Or(answer.role, "assistant"), "content": nil}
	if answer.text != "" {
		message["content"] = answer.text
	}
	if len(answer.calls) > 0 {
		calls := make([]map[string]any, 0, len(answer.calls))
		s.mu.Lock()
		for _, call := range answer.calls {
			s.nextCall++
			calls = append(calls, map[string]any{
				"id":       fmt.Sprintf("call_%d", s.nextCall),
				"type":     "function",
				"function": map[string]any{"name": call.name, "arguments": call.arguments},
			})
		}
		s.mu.Unlock()
		message["tool_calls"] = calls
	}
	body, err := json.Marshal(map[string]any{
		"choices": []map[string]any{{"message": message, "finish_reason": "stop"}},
		"usage":   map[string]any{"prompt_tokens": 10, "completion_tokens": 5},
	})
	if err != nil {
		panic(err) // The values are made up here, and always encode.
	}
	return body
}

// peakConcurrency returns the most requests that the server had in flight at once.
func (s *scriptedServer) peakConcurrency() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.peak
}

// all returns the requests that the server has seen.
func (s *scriptedServer) all() []seen {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]seen(nil), s.requests...)
}

// chats returns the requests that are part of a run: not the replay check.
func (s *scriptedServer) chats() []seen {
	var chats []seen
	for _, request := range s.all() {
		if !request.isReplay() {
			chats = append(chats, request)
		}
	}
	return chats
}

// replays returns the replay checks that the server has seen.
func (s *scriptedServer) replays() []seen {
	var replays []seen
	for _, request := range s.all() {
		if request.isReplay() {
			replays = append(replays, request)
		}
	}
	return replays
}

// environment returns the lookup of an environment that holds the test key.
func environment(key string) func(string) string {
	return func(name string) string {
		if name == keyEnv {
			return key
		}
		return ""
	}
}

// runSmoke runs the tool against the server with the made-up key, the extra arguments and the TLS
// client of the server, and returns the exit code and what it printed.
func runSmoke(t *testing.T, server *scriptedServer, extra ...string) (int, string) {
	t.Helper()
	args := append([]string{flagEndpoint, server.URL, flagModel, testModel}, extra...)
	var out bytes.Buffer
	code := run(context.Background(), args, environment(testKey), &out, llm.WithHTTPClient(server.Client()))
	return code, out.String()
}

// requireNoLeak fails the test if the output carries the key, or anything of an error body.
func requireNoLeak(t *testing.T, output, key string) {
	t.Helper()
	require.NotContains(t, output, key)
	require.NotContains(t, output, bodyMarker)
	require.NotContains(t, output, "Bearer")
}
