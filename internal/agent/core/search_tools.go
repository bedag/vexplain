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
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/bedag/vexplain/internal/agent/ledger"
	"github.com/bedag/vexplain/internal/agent/profile"
	"github.com/bedag/vexplain/internal/metrics"
)

const (
	// maxFound is the most tools that one search returns, and maxLoaded the most that a case loads.
	maxFound  = 5
	maxLoaded = 8
	// maxLoadedBytes is the most that the definitions of the tools that a case loads take, as the client lists them:
	// what the fit check sets aside for them, at 4 bytes a token.
	maxLoadedBytes = 4 * profile.SearchedToolsTokens
)

// toolName is the name of a tool that the core forwards to: <collector>__<operation>, in the characters that
// OpenAI-compatible endpoints allow in a tool's name, at most 64. No core tool has such a name, so a found tool never
// replaces one.
var toolName = regexp.MustCompile(`^[a-zA-Z0-9_-]+__[a-zA-Z0-9_-]+$`)

type searchToolsArgs struct {
	Query string `json:"query"`
}

// searchTools finds the forwarder's tools whose names and descriptions hold the most words of the query, at most 5,
// and loads them into the session, so that the runner lists them from its next request on. A case loads at most 8,
// whose definitions take at most 16000 bytes. A tool listing is never evidence, so its trust is External.
func (s *Session) searchTools(ctx context.Context, req *mcp.CallToolRequest, in searchToolsArgs) (
	*mcp.CallToolResult, any, error) {
	return s.call(ctx, searchTools, req.Params.Arguments, func(ctx context.Context) ([]byte, ledger.Trust, error) {
		ctx, cancel := context.WithTimeout(ctx, s.toolTimeout())
		defer cancel()
		tools, err := s.deps.Forwarder.Tools(ctx)
		if err != nil {
			return nil, "", err
		}
		var out strings.Builder
		left := 0
		for _, t := range match(tools, in.Query) {
			if !s.loaded[t.Name] {
				if len(s.loaded) >= maxLoaded {
					left++
					continue
				}
				if err := s.load(t); err != nil {
					fmt.Fprintf(&out, "%s can't be offered: %v\n", t.Name, err)
					continue
				}
			}
			fmt.Fprintf(&out, "%s: %s\nparameters: %s\n", t.Name, t.Description, t.InputSchema)
		}
		if left > 0 {
			fmt.Fprintf(&out, "%d more tools match, and a case loads at most %d.\n", left, maxLoaded)
		}
		if out.Len() == 0 {
			out.WriteString("No tool matches the query.\n")
		}
		return []byte(out.String()), ledger.External, nil
	}, nil), nil, nil
}

// match returns the tools that the query's words find in their names and descriptions, ignoring case: those with the
// most words first, then by name, at most maxFound. A tool whose name the core can't offer is never found.
func match(tools []Tool, query string) []Tool {
	words := strings.Fields(strings.ToLower(query))
	type scored struct {
		tool  Tool
		score int
	}
	var found []scored
	for _, t := range tools {
		if len(t.Name) > 64 || !toolName.MatchString(t.Name) {
			continue
		}
		text := strings.ToLower(t.Name + " " + t.Description)
		score := 0
		for _, w := range words {
			if strings.Contains(text, w) {
				score++
			}
		}
		if score > 0 {
			found = append(found, scored{t, score})
		}
	}
	slices.SortFunc(found, func(a, b scored) int {
		return cmp.Or(cmp.Compare(b.score, a.score), strings.Compare(a.tool.Name, b.tool.Name))
	})
	out := make([]Tool, 0, min(len(found), maxFound))
	for _, f := range found[:min(len(found), maxFound)] {
		out = append(out, f.tool)
	}
	return out
}

// load adds the tool to the session's server, as a tool whose calls the session forwards and records. The caller
// holds mu.
func (s *Session) load(t Tool) (err error) {
	// A function's definition, as an OpenAI-compatible endpoint takes it.
	definition, err := json.Marshal(struct {
		Name        string          `json:"name"`
		Description string          `json:"description"`
		Parameters  json.RawMessage `json:"parameters"`
	}{t.Name, t.Description, t.InputSchema})
	switch {
	case err != nil:
		return errors.New("its definition isn't JSON")
	case s.loadedBytes+len(definition) > maxLoadedBytes:
		return fmt.Errorf("the definitions of the tools that a case loads take at most %d bytes", maxLoadedBytes)
	}
	// The SDK panics on a tool that it refuses, such as one whose schema isn't an object, and a tool comes from a
	// collector, or from a foreign MCP server: such a tool is refused, and never stops the manager.
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("its definition is refused: %v", r)
		}
	}()
	name, fetches := t.Name, t.Fetches
	var note func(ledger.Entry) string
	if name == describeTool {
		note = s.describeNote
	}
	s.server.AddTool(&mcp.Tool{Name: name, Description: t.Description, InputSchema: t.InputSchema},
		func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args := req.Params.Arguments
			if name == describeTool {
				args = s.withAliases(args)
			}
			return s.call(ctx, name, args, func(ctx context.Context) ([]byte, ledger.Trust, error) {
				if !fetches {
					return s.forward(ctx, name, args)
				}
				reference, ok := s.trusted(args)
				if !ok {
					metrics.AgentToolRefusalsTotal.WithLabelValues(s.deps.Cluster, name, untrustedURL).Inc()
					return nil, "", fmt.Errorf("vexplain refuses the call: %s takes only a URL that a trusted result "+
						"of this case named, such as a reference of %s, as it is written there", name, describeTool)
				}
				// The reference as the trusted result wrote it is fetched, so nothing of the model's spelling leaves.
				fetchArgs, err := json.Marshal(map[string]string{"url": reference})
				if err != nil {
					return nil, "", err
				}
				return s.forward(ctx, name, fetchArgs)
			}, note), nil
		})
	s.loaded[name] = true
	s.loadedBytes += len(definition)
	return nil
}

// forward calls the tool through the forwarder within the profile's toolTimeoutSeconds. A call that takes longer is a
// tool error.
func (s *Session) forward(ctx context.Context, name string, args json.RawMessage) ([]byte, ledger.Trust, error) {
	ctx, cancel := context.WithTimeout(ctx, s.toolTimeout())
	defer cancel()
	out, trust, err := s.deps.Forwarder.Call(ctx, name, args)
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return nil, "", fmt.Errorf("%s didn't answer within the profile's toolTimeoutSeconds, %d", name,
			s.limits.ToolTimeoutSeconds)
	}
	return out, trust, err
}

// toolTimeout is how long a forwarded call may take: the profile's toolTimeoutSeconds.
func (s *Session) toolTimeout() time.Duration {
	return time.Duration(s.limits.ToolTimeoutSeconds) * time.Second
}
