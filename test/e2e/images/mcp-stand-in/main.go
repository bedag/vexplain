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

// Command mcp-stand-in is the MCP server of the e2e tests: a stand-in for a wiki's, on the Go SDK, over MCP's
// Streamable HTTP transport and TLS, so that the agent calls an MCP collector's tools on kind.
//
// It serves search, get_page and delete_page, which stands for a tool that writes and deletes nothing. It answers only
// a request whose Authorization header is "Bearer " and TOKEN, and logs each call of a tool by the tool's name, so that
// the specs see which tools were called. It serves on :8443 with the certificate and key in /tls.
package main

import (
	"context"
	"log"
	"net/http"
	"os"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type searchArgs struct {
	Query string `json:"query" jsonschema:"the words to search for"`
}

type pageArgs struct {
	ID string `json:"id" jsonschema:"the ID of the page"`
}

func main() {
	token := os.Getenv("TOKEN")
	server := mcp.NewServer(&mcp.Implementation{Name: "wiki", Version: "v0.0.1"}, nil)
	mcp.AddTool(server, &mcp.Tool{Name: "search", Description: "Searches the pages of the wiki."},
		func(_ context.Context, _ *mcp.CallToolRequest, in searchArgs) (*mcp.CallToolResult, any, error) {
			log.Print("Called the tool search")
			return text("The wiki's page about " + in.Query + " says: its team updates the image within a week."), nil, nil
		})
	mcp.AddTool(server, &mcp.Tool{Name: "get_page", Description: "Reads a page of the wiki."},
		func(_ context.Context, _ *mcp.CallToolRequest, in pageArgs) (*mcp.CallToolResult, any, error) {
			log.Print("Called the tool get_page")
			return text("The page " + in.ID + " is empty."), nil, nil
		})
	mcp.AddTool(server, &mcp.Tool{Name: "delete_page", Description: "Deletes a page of the wiki."},
		func(context.Context, *mcp.CallToolRequest, pageArgs) (*mcp.CallToolResult, any, error) {
			log.Print("Called the tool delete_page")
			return text("Deleted the page."), nil, nil
		})
	handler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server }, nil)
	log.Fatal(http.ListenAndServeTLS(":8443", "/tls/tls.crt", "/tls/tls.key",
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Authorization") != "Bearer "+token {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			handler.ServeHTTP(w, r)
		})))
}

// text returns an answer of the text.
func text(s string) *mcp.CallToolResult {
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: s}}}
}
