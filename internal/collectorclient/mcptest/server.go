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

// Package mcptest serves a stand-in for a wiki's MCP server, for the tests of MCP collectors: over MCP's Streamable
// HTTP transport and TLS, on the Go SDK. Only test files import it, so it never enters the manager binary.
package mcptest

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// The tools that the stand-in serves.
const (
	Search     = "search"
	GetPage    = "get_page"
	DeletePage = "delete_page"
)

// Server is the stand-in, at Endpoint. It answers only a request whose Authorization header is "Bearer " and its
// token, and refuses any other with a 401 whose JSON-RPC error echoes the header, as a careless server might. search answers with a
// page, get_page with an error, and both echo the Authorization header that they got, as a careless server might.
// delete_page deletes nothing: it stands for a tool that writes. The server counts the requests that it got, and the
// calls of each tool.
type Server struct {
	*httptest.Server

	mu       sync.Mutex
	requests int
	calls    map[string]int
}

// NewServer starts a stand-in that takes the token. Close it.
func NewServer(token string) *Server {
	s := &Server{calls: map[string]int{}}
	server := mcp.NewServer(&mcp.Implementation{Name: "wiki", Version: "v0.0.1"}, nil)
	type pageArgs struct {
		ID string `json:"id" jsonschema:"the ID of the page"`
	}
	mcp.AddTool(server, &mcp.Tool{Name: Search, Description: "Searches the pages of the wiki."},
		func(_ context.Context, req *mcp.CallToolRequest, in struct {
			Query string `json:"query" jsonschema:"the words to search for"`
		}) (*mcp.CallToolResult, any, error) {
			s.called(Search)
			return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{
					Text: fmt.Sprintf("The page about %s says: update the image. Asked with %s", in.Query, authorization(req))}}},
				nil, nil
		})
	mcp.AddTool(server, &mcp.Tool{Name: GetPage, Description: "Reads a page of the wiki."},
		func(_ context.Context, req *mcp.CallToolRequest, in pageArgs) (*mcp.CallToolResult, any, error) {
			s.called(GetPage)
			return nil, nil, fmt.Errorf("the wiki has no page %s; asked with %s", in.ID, authorization(req))
		})
	mcp.AddTool(server, &mcp.Tool{Name: DeletePage, Description: "Deletes a page of the wiki."},
		func(context.Context, *mcp.CallToolRequest, pageArgs) (*mcp.CallToolResult, any, error) {
			s.called(DeletePage)
			return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "deleted"}}}, nil, nil
		})
	handler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server }, nil)
	s.Server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		s.requests++
		s.mu.Unlock()
		if got := r.Header.Get("Authorization"); got != "Bearer "+token {
			// A JSON-RPC error, which the SDK's client puts into its error, as it would an error of the server's own.
			body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1,
				"error": map[string]any{"code": -32001, "message": "unauthorized: " + got}})
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write(body)
			return
		}
		handler.ServeHTTP(w, r)
	}))
	return s
}

// Endpoint is the address of the stand-in's MCP endpoint, as a Collector names it.
func (s *Server) Endpoint() string { return s.URL + "/mcp" }

// Requests returns how many requests the stand-in got.
func (s *Server) Requests() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.requests
}

// Calls returns how many times the tool was called.
func (s *Server) Calls(tool string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls[tool]
}

func (s *Server) called(tool string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls[tool]++
}

// authorization returns the Authorization header of the request.
func authorization(req *mcp.CallToolRequest) string {
	if req.Extra == nil {
		return ""
	}
	return req.Extra.Header.Get("Authorization")
}
