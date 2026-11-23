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

package runner

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/bedag/vexplain/internal/agent/core"
	"github.com/bedag/vexplain/internal/llm"
)

// conversation is the history of a case, which every request carries whole: an OpenAI-compatible endpoint keeps no
// state. Tools are found by search (decision 0055): every request lists the session's tools as they are then, so a tool
// that a search loaded is offered from the next request on.
type conversation struct {
	messages []llm.Message
}

// answer adds the model's message to the history, passes each of its tool calls to the session and adds each result.
// It reports whether a call ended the case. A message without a tool call gets a nudge to call one. A call whose
// arguments aren't a JSON object gets a tool error that quotes them, and goes into the history with {}, since some
// endpoints parse the replayed arguments and refuse the whole request (main design 6.6). Once ctx is done, or a call
// ended the case, the calls left get a result that says they weren't made, so the history stays one that an endpoint
// takes, and it returns the error of ctx.
func (c *conversation) answer(ctx context.Context, s *mcp.ClientSession, m llm.Message) (bool, error) {
	replayed := llm.Message{Role: roleAssistant, Content: m.Content}
	args := make([]json.RawMessage, len(m.ToolCalls))
	for i, call := range m.ToolCalls {
		args[i] = argumentsOf(call.Arguments)
		if args[i] == nil {
			call.Arguments = "{}"
		} else {
			call.Arguments = string(args[i])
		}
		replayed.ToolCalls = append(replayed.ToolCalls, call)
	}
	c.messages = append(c.messages, replayed)
	if len(m.ToolCalls) == 0 {
		c.messages = append(c.messages, llm.Message{Role: roleUser, Content: nudge})
		return false, nil
	}
	ended := false
	for i, call := range m.ToolCalls {
		var result string
		switch {
		case ended || ctx.Err() != nil:
			result = notMade
		case i >= maxCalls:
			result = tooMany
		case args[i] == nil:
			result = fmt.Sprintf("The arguments of %s are not a JSON object, so it was not called. They were: %s",
				call.Name, quoted(call.Arguments))
		default:
			res, err := s.CallTool(ctx, &mcp.CallToolParams{Name: call.Name, Arguments: args[i]})
			switch {
			case err != nil && ctx.Err() != nil:
				result = notMade
			case err != nil:
				result = fmt.Sprintf("The call of %s failed: %v", call.Name, err)
			default:
				result = textOf(res)
				ended = res.Meta[core.EndedMeta] == true
			}
		}
		c.messages = append(c.messages, llm.Message{Role: roleTool, ToolCallID: call.ID, Content: result})
	}
	if !ended && ctx.Err() != nil {
		return false, ctx.Err()
	}
	return ended, nil
}

// argumentsOf returns the arguments of a tool call as a JSON object, or nil when they are none. Empty arguments are
// the empty object, as some models send them.
func argumentsOf(raw string) json.RawMessage {
	trimmed := bytes.TrimSpace([]byte(raw))
	if len(trimmed) == 0 {
		return json.RawMessage("{}")
	}
	if trimmed[0] != '{' || !json.Valid(trimmed) {
		return nil
	}
	return trimmed
}

// quoted returns the first bytes of malformed arguments, as valid text.
func quoted(raw string) string {
	if len(raw) > maxQuoted {
		raw = raw[:maxQuoted] + "…"
	}
	return strings.ToValidUTF8(raw, "�")
}

// textOf returns the text of a tool's result.
func textOf(res *mcp.CallToolResult) string {
	var b strings.Builder
	for _, content := range res.Content {
		if t, ok := content.(*mcp.TextContent); ok {
			b.WriteString(t.Text)
		}
	}
	return b.String()
}

// toolsOf returns the session's tools, as the endpoint takes them.
func toolsOf(ctx context.Context, s *mcp.ClientSession) ([]llm.Tool, error) {
	var tools []llm.Tool
	for t, err := range s.Tools(ctx, nil) {
		if err != nil {
			return nil, err
		}
		parameters, err := json.Marshal(t.InputSchema)
		if err != nil {
			return nil, fmt.Errorf("the schema of the tool %s: %w", t.Name, err)
		}
		tools = append(tools, llm.Tool{Name: t.Name, Description: t.Description, Parameters: parameters})
	}
	return tools, nil
}

// estimate returns the tokens of what a request carries, as bytes / 4 rounded up, as every cap of the agent counts
// them (prompt.EstimateTokens): the messages and the tools' definitions, as JSON, close to the request's body.
func estimate(messages []llm.Message, tools []llm.Tool) int {
	// A request of strings and of tool schemas that json.Marshal made always marshals.
	raw, _ := json.Marshal(llm.Request{Messages: messages, Tools: tools})
	return (len(raw) + 3) / 4
}
