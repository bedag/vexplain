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

// Command scripted-model is the model of the e2e tests: an OpenAI-compatible endpoint over TLS that answers from a
// script, so that the agent judges cases on kind without a real model, and no token is spent.
//
// It lists the model "scripted". A chat request that offers tools gets a tool call:
//   - for a case file that names the digest in LOOP_ON, a search, every time, so that the case reaches its step limit;
//   - for any other case, a search first, and then the verdict affected, citing the search's result. When the search
//     loaded an MCP collector's tool search, it calls that tool, and then tries the collector's delete_page, which the
//     Collector's list leaves off, before the verdict.
//
// With HOLD_ON, a substring of a case file, and HOLD, a duration, it holds the answer to the first request of each case
// that names the substring for that long, so that a spec can act while a worker judges. It logs "Began a case of <the
// vulnerability and the manifest digest>" at each such request, which is how a spec counts the judgements of a case.
// At that request it also logs each guidance mark, e2e-guidance-mark- and a name, that the system prompt holds, which
// is how a spec sees that the agent got an investigation's guidance.
//
// A request without tools, the runner's final call at a limit, gets a summary. It serves on :8443 with the certificate
// and key in /tls.
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync/atomic"
	"time"
)

// model is the name of the model that the endpoint serves.
const model = "scripted"

// function names a tool, as a chat request offers it and as an assistant message calls it.
type function struct {
	Function struct {
		Name string `json:"name"`
	} `json:"function"`
}

// request is what the script reads of a chat request.
type request struct {
	Messages []struct {
		Role      string     `json:"role"`
		Content   *string    `json:"content"`
		ToolCalls []function `json:"tool_calls"`
	} `json:"messages"`
	Tools []function `json:"tools"`
}

// mcpSearch ends the name of an MCP collector's tool search, as the agent calls it: <collector>__search.
const mcpSearch = "__search"

// calls numbers the tool calls of the answers.
var calls atomic.Int64

// guidanceMark is a mark that a spec writes into an investigation's guidance.
var guidanceMark = regexp.MustCompile(`e2e-guidance-mark-[a-z0-9-]+`)

func main() {
	loopOn, holdOn := os.Getenv("LOOP_ON"), os.Getenv("HOLD_ON")
	hold, _ := time.ParseDuration(os.Getenv("HOLD"))
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/models", func(w http.ResponseWriter, _ *http.Request) {
		write(w, map[string]any{"data": []map[string]any{{"id": model}}})
	})
	mux.HandleFunc("POST /v1/chat/completions", func(w http.ResponseWriter, r *http.Request) {
		var req request
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if caseFile, first := req.firstOfCase(); first {
			log.Printf("Began a case of %s", caseName(caseFile))
			for _, mark := range guidanceMark.FindAllString(req.system(), -1) {
				log.Printf("The system prompt of a case of %s holds %s", caseName(caseFile), mark)
			}
			if holdOn != "" && strings.Contains(caseFile, holdOn) {
				time.Sleep(hold)
			}
		}
		write(w, completion(answer(req, loopOn)))
	})
	log.Fatal(http.ListenAndServeTLS(":8443", "/tls/tls.crt", "/tls/tls.key", mux))
}

// answer returns the assistant message that the script gives the request.
func answer(req request, loopOn string) map[string]any {
	if len(req.Tools) == 0 {
		return map[string]any{"role": "assistant", "content": "The search found the tools of the case (ev-1).\n\n" +
			"The answer of describe for the package would settle it."}
	}
	caseFile, searched := "", false
	for _, m := range req.Messages {
		switch {
		case m.Role == "user" && caseFile == "" && m.Content != nil:
			caseFile = *m.Content
		case m.Role == "tool":
			searched = true
		}
	}
	if (loopOn != "" && strings.Contains(caseFile, loopOn)) || !searched {
		return call("search_tools", `{"query": "describe a vulnerability or search the wiki"}`)
	}
	for _, t := range req.Tools {
		if search := t.Function.Name; strings.HasSuffix(search, mcpSearch) {
			if deletePage := strings.TrimSuffix(search, mcpSearch) + "__delete_page"; !req.called(search) {
				return call(search, `{"query": "brotli"}`)
			} else if !req.called(deletePage) {
				return call(deletePage, `{"id": "brotli"}`)
			}
		}
	}
	return call("submit_verdict", `{"status": "affected", "nextStep": "Update the image once a fixed version exists.",
		"summary": "The scripted model finds the image affected (ev-1).",
		"claims": [{"text": "The search found the tools of the case.", "evidence": ["ev-1"]}]}`)
}

// firstOfCase returns the case file, and whether the request is the first of its judgement: it offers tools, and no
// tool has answered yet.
func (req request) firstOfCase() (string, bool) {
	caseFile := ""
	for _, m := range req.Messages {
		switch {
		case m.Role == "user" && caseFile == "" && m.Content != nil:
			caseFile = *m.Content
		case m.Role == "tool":
			return caseFile, false
		}
	}
	return caseFile, len(req.Tools) > 0
}

// caseName returns the vulnerability and the manifest digest that a case file names, as <vulnerability>@<digest>. The
// user message may wrap the JSON in text, so it reads the two fields by pattern.
func caseName(caseFile string) string {
	field := func(name string) string {
		m := regexp.MustCompile(`"` + name + `":\s*"([^"]*)"`).FindStringSubmatch(caseFile)
		if m == nil {
			return ""
		}
		return m[1]
	}
	return field("vulnerabilityID") + "@" + field("manifestDigest")
}

// system returns the system prompt of the request.
func (req request) system() string {
	for _, m := range req.Messages {
		if m.Role == "system" && m.Content != nil {
			return *m.Content
		}
	}
	return ""
}

// called says whether an assistant message of the request called the tool.
func (req request) called(tool string) bool {
	for _, m := range req.Messages {
		for _, c := range m.ToolCalls {
			if c.Function.Name == tool {
				return true
			}
		}
	}
	return false
}

// call returns an assistant message that calls the tool with the arguments.
func call(name, arguments string) map[string]any {
	return map[string]any{"role": "assistant", "content": nil, "tool_calls": []map[string]any{{
		"id": fmt.Sprintf("call_%d", calls.Add(1)), "type": "function",
		"function": map[string]any{"name": name, "arguments": arguments},
	}}}
}

// completion returns a chat completion of the message.
func completion(message map[string]any) map[string]any {
	return map[string]any{"model": model,
		"choices": []map[string]any{{"index": 0, "message": message, "finish_reason": "stop"}},
		"usage":   map[string]any{"prompt_tokens": 100, "completion_tokens": 10}}
}

// write writes v as the JSON answer.
func write(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("Could not write an answer: %v", err)
	}
}
