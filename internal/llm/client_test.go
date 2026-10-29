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

package llm_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/bedag/vexplain/internal/llm"
)

func TestCompleteSendsOpenAIRequest(t *testing.T) {
	type sent struct {
		method, path string
		header       http.Header
		body         map[string]any
	}
	got := make(chan sent, 1)
	server := serve(t, func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		assert.NoError(t, json.NewDecoder(r.Body).Decode(&body))
		got <- sent{method: r.Method, path: r.URL.Path, header: r.Header.Clone(), body: body}
		answer(completion)(w, r)
	})
	// The trailing slash of the base URL must not end up in the path twice.
	client := llm.New(llm.Config{
		BaseURL:          server.URL + "/v1/",
		Model:            testModel,
		APIKey:           "k",
		TemperatureMilli: 200,
	}, llm.WithHTTPClient(server.Client()))

	_, err := client.Complete(t.Context(), llm.Request{
		Messages: []llm.Message{{Role: roleUser, Content: "hi"}},
		Tools: []llm.Tool{{
			Name:        toolName,
			Description: "Look a package up.",
			Parameters:  json.RawMessage(`{"type":"object","properties":{"pkg":{"type":"string"}}}`),
		}},
		ToolChoice: "auto",
	})
	require.NoError(t, err)

	request := <-got
	require.Equal(t, http.MethodPost, request.method)
	require.Equal(t, "/v1/chat/completions", request.path)
	require.Equal(t, "Bearer k", request.header.Get("Authorization"))
	require.Equal(t, "application/json", request.header.Get("Content-Type"))
	require.Equal(t, testModel, request.body["model"])
	require.Equal(t, 0.2, request.body["temperature"])
	require.Equal(t, "auto", request.body["tool_choice"])
	require.NotContains(t, request.body, "max_tokens")
	messages, err := json.Marshal(request.body["messages"])
	require.NoError(t, err)
	require.JSONEq(t, `[{"role":"user","content":"hi"}]`, string(messages))
	tools, err := json.Marshal(request.body["tools"])
	require.NoError(t, err)
	require.JSONEq(t, `[{"type":"function","function":{"name":"lookup","description":"Look a package up.",`+
		`"parameters":{"type":"object","properties":{"pkg":{"type":"string"}}}}}]`, string(tools))
}

func TestCompleteSendsToolChoiceAndMaxTokensOnlyWhenSet(t *testing.T) {
	bodies := make(chan map[string]any, 1)
	server := serve(t, func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		assert.NoError(t, json.NewDecoder(r.Body).Decode(&body))
		bodies <- body
		answer(completion)(w, r)
	})
	client := newClient(server, configFor(server))

	_, err := client.Complete(t.Context(), ping())
	require.NoError(t, err)
	bare := <-bodies
	for _, field := range []string{"tools", "tool_choice", "max_tokens"} {
		require.NotContains(t, bare, field)
	}

	request := ping()
	request.ToolChoice = "required"
	request.MaxTokens = 7
	request.Tools = []llm.Tool{{Name: toolName}}
	_, err = client.Complete(t.Context(), request)
	require.NoError(t, err)
	full := <-bodies
	require.Equal(t, "required", full["tool_choice"])
	require.Equal(t, float64(7), full["max_tokens"])
	require.Len(t, full["tools"], 1)
}

func TestCompleteSendsZeroTemperature(t *testing.T) {
	bodies := make(chan map[string]any, 1)
	server := serve(t, func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		assert.NoError(t, json.NewDecoder(r.Body).Decode(&body))
		bodies <- body
		answer(completion)(w, r)
	})
	cfg := configFor(server)
	cfg.TemperatureMilli = 0

	_, err := newClient(server, cfg).Complete(t.Context(), ping())
	require.NoError(t, err)

	// Without the field, the server would use its own default, and not 0.0.
	body := <-bodies
	require.Contains(t, body, "temperature")
	require.Equal(t, float64(0), body["temperature"])
}

func TestNewAppliesDefaults(t *testing.T) {
	for name, cfg := range map[string]llm.Config{
		"zero values":     {},
		"negative values": {Timeout: -time.Second, MaxConcurrent: -1},
	} {
		t.Run(name, func(t *testing.T) {
			server := serve(t, answer(completion))
			cfg.BaseURL, cfg.Model, cfg.APIKey = server.URL, testModel, testKey
			// Without the defaults, a zero Timeout would end each request at once, and a semaphore of
			// size zero would never let a call through. The context stops the second case.
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()

			resp, err := newClient(server, cfg).Complete(ctx, ping())

			require.NoError(t, err)
			require.Equal(t, "pong", resp.Message.Content)
		})
	}
}

func TestCompleteParsesToolCalls(t *testing.T) {
	server := serve(t, answer(`{"choices":[{"message":{"role":"assistant","content":null,"tool_calls":[
		{"id":"c1","type":"function","function":{"name":"lookup","arguments":"{\"pkg\":\"brotli\"}"}},
		{"id":"c2","type":"function","function":{"name":"lookup","arguments":"{bad"}}
	]},"finish_reason":"tool_calls"}],"usage":{"prompt_tokens":11,"completion_tokens":7,"total_tokens":18}}`))

	resp, err := newClient(server, configFor(server)).Complete(t.Context(), ping())

	require.NoError(t, err)
	// The arguments are the text that the server sent, valid JSON or not: the caller validates.
	require.Equal(t, llm.Message{
		Role: roleAssistant,
		ToolCalls: []llm.ToolCall{
			{ID: "c1", Name: toolName, Arguments: `{"pkg":"brotli"}`},
			{ID: "c2", Name: toolName, Arguments: badArguments},
		},
	}, resp.Message)
	require.Equal(t, "tool_calls", resp.FinishReason)
	require.Equal(t, llm.Usage{PromptTokens: 11, CompletionTokens: 7}, resp.Usage)
}

func TestCompleteReplaysToolCalls(t *testing.T) {
	raw := make(chan []byte, 1)
	server := serve(t, func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		assert.NoError(t, err)
		raw <- body
		answer(completion)(w, r)
	})
	history := []llm.Message{
		{Role: roleUser, Content: "What is brotli?"},
		{Role: roleAssistant, ToolCalls: []llm.ToolCall{{ID: "c1", Name: toolName, Arguments: badArguments}}},
		{Role: roleTool, ToolCallID: "c1", Content: "the arguments are not JSON"},
	}

	_, err := newClient(server, configFor(server)).Complete(t.Context(), llm.Request{Messages: history})
	require.NoError(t, err)

	// The client sends what it is given. That the agent loop never replays invalid arguments is its
	// own policy.
	body := <-raw
	require.True(t, json.Valid(body))
	require.Contains(t, string(body), `"arguments":"{bad"`)
	require.Contains(t, string(body), `"tool_call_id":"c1"`)
	var sent struct {
		Messages []struct {
			Role      string `json:"role"`
			ToolCalls []struct {
				ID       string `json:"id"`
				Type     string `json:"type"`
				Function struct {
					Name      string `json:"name"`
					Arguments string `json:"arguments"`
				} `json:"function"`
			} `json:"tool_calls"`
			ToolCallID string `json:"tool_call_id"`
		} `json:"messages"`
	}
	require.NoError(t, json.Unmarshal(body, &sent))
	require.Len(t, sent.Messages, 3)
	call := sent.Messages[1].ToolCalls[0]
	require.Equal(t, "c1", call.ID)
	require.Equal(t, "function", call.Type)
	require.Equal(t, toolName, call.Function.Name)
	require.Equal(t, badArguments, call.Function.Arguments)
	require.Equal(t, roleTool, sent.Messages[2].Role)
	require.Equal(t, "c1", sent.Messages[2].ToolCallID)
}

func TestCompleteEncodesMessageContent(t *testing.T) {
	bodies := make(chan map[string]any, 1)
	server := serve(t, func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		assert.NoError(t, json.NewDecoder(r.Body).Decode(&body))
		bodies <- body
		answer(completion)(w, r)
	})
	call := []llm.ToolCall{{ID: "c1", Name: toolName, Arguments: "{}"}}
	history := []llm.Message{
		{Role: roleUser},
		{Role: roleAssistant, ToolCalls: call},
		{Role: roleAssistant, Content: "Looking it up.", ToolCalls: call},
		{Role: roleTool, ToolCallID: "c1"},
		{Role: roleAssistant},
	}

	_, err := newClient(server, configFor(server)).Complete(t.Context(), llm.Request{Messages: history})
	require.NoError(t, err)

	messages, ok := (<-bodies)["messages"].([]any)
	require.True(t, ok)
	contents := make([]any, 0, len(messages))
	for _, message := range messages {
		fields, ok := message.(map[string]any)
		require.True(t, ok)
		// Every message has a content. Servers require it for the roles with text, and they send
		// null themselves for an assistant message that only calls tools, so it goes back as null.
		require.Contains(t, fields, "content")
		contents = append(contents, fields["content"])
	}
	require.Equal(t, []any{"", nil, "Looking it up.", "", ""}, contents)
}

func TestCompleteObservesTheModelAndTheUsage(t *testing.T) {
	server := serve(t, answer(completion))
	seen := &observations{}

	_, err := newClient(server, configFor(server), llm.WithObserver(seen.observe)).Complete(t.Context(), ping())
	require.NoError(t, err)

	observed := seen.all()
	require.Len(t, observed, 1)
	require.Equal(t, testModel, observed[0].Model)
	require.Equal(t, outcomeOK, observed[0].Outcome)
	require.Equal(t, llm.Usage{PromptTokens: 3, CompletionTokens: 1}, observed[0].Usage)
	require.Positive(t, observed[0].Duration)
}

func TestCompleteSendsEmptyArgumentsOfAToolCall(t *testing.T) {
	raw := make(chan []byte, 1)
	server := serve(t, func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		assert.NoError(t, err)
		raw <- body
		answer(completion)(w, r)
	})
	history := []llm.Message{
		{Role: roleAssistant, ToolCalls: []llm.ToolCall{{ID: "c1", Name: toolName}}},
		{Role: roleTool, ToolCallID: "c1", Content: "done"},
	}

	_, err := newClient(server, configFor(server)).Complete(t.Context(), llm.Request{Messages: history})
	require.NoError(t, err)

	// The API requires the field of a call, also for a tool without arguments.
	require.Contains(t, string(<-raw), `"arguments":""`)
}

func TestCompleteMakesNoRequestForToolParametersThatAreNoJSON(t *testing.T) {
	var requests atomic.Int32
	server := serve(t, func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		answer(completion)(w, r)
	})
	request := ping()
	request.Tools = []llm.Tool{{Name: toolName, Parameters: json.RawMessage("{not JSON")}}

	_, err := newClient(server, configFor(server)).Complete(t.Context(), request)

	require.Error(t, err)
	require.Zero(t, requests.Load())
}
