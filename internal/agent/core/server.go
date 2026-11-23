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

// Package core is the agent's safety core: vexplain's own MCP server, one session per case (decision 0053). It serves
// the core tools, finds and forwards the other tools that the profile allows, records every call in the case's ledger
// and stores its whole output, and hands a submitted verdict to the validator. A runner drives the model and passes
// its tool calls to the session through the MCP Go SDK's in-memory transport, and never reports a tool's output
// itself.
//
// The core tools are search_evidence, read_evidence, search_tools, submit_verdict and submit_no_verdict, as the core
// prompt describes them. What the model sees of an output is bounded by the profile's toolResultMaxTokens, and it reads
// on a page at a time (decision 0055).
package core

import (
	"encoding/json"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/bedag/vexplain/internal/agent/prompt"
)

// The names of the core tools.
const (
	searchEvidence  = "search_evidence"
	readEvidence    = "read_evidence"
	searchTools     = "search_tools"
	submitVerdict   = "submit_verdict"
	submitNoVerdict = "submit_no_verdict"
)

// The input schemas of the core tools. Their names and values are those of the core prompt, and the fit check counts
// their size in prompt.CoreToolSchemaTokens.
var (
	searchEvidenceSchema = json.RawMessage(`{"type":"object","additionalProperties":false,"required":["name","query"],
"properties":{"name":{"type":"string","description":"The name of a piece of evidence of the case file."},
"query":{"type":"string","description":"Text that the lines contain, ignoring case. Separate several terms with |: a line that contains any of them matches."}}}`)
	readEvidenceSchema = json.RawMessage(`{"type":"object","additionalProperties":false,"required":["id"],
"properties":{"id":{"type":"string","pattern":"^ev-[0-9]+$","description":"The ledger ID of the result, such as ev-3."},
"page":{"type":"integer","minimum":1,"description":"The page to read. Without it, page 2."}}}`)
	searchToolsSchema = json.RawMessage(`{"type":"object","additionalProperties":false,"required":["query"],
"properties":{"query":{"type":"string","minLength":1,"description":"What the tool does, in a few words."}}}`)
	submitVerdictSchema = json.RawMessage(`{"type":"object","additionalProperties":false,
"required":["status","nextStep","summary","claims"],
"properties":{"status":{"type":"string","enum":["not_affected","affected","fixed","under_investigation"]},
"justification":{"type":"string","enum":["vulnerable_code_not_present"],"description":"For not_affected only."},
"nextStep":{"type":"string","minLength":1,"description":"What a person should do now."},
"summary":{"type":"string","minLength":1,"maxLength":2048,"description":"A few sentences that a person can act on."},
"claims":{"type":"array","minItems":1,"items":{"type":"object","additionalProperties":false,
"required":["text","evidence"],"properties":{"text":{"type":"string","minLength":1},
"evidence":{"type":"array","minItems":1,"items":{"type":"string","pattern":"^ev-[0-9]+$"},
"description":"The ledger IDs that support the claim."}}}}}}`)
	// The maxLengths of submit_no_verdict's why and established are maxWhy and maxEstablished.
	submitNoVerdictSchema = json.RawMessage(`{"type":"object","additionalProperties":false,
"required":["why","established","wouldSettle"],
"properties":{"why":{"type":"string","minLength":1,"maxLength":500,"description":"Why the case can't be settled."},
"established":{"type":"string","minLength":1,"maxLength":1000,
"description":"What you did establish, citing ledger IDs."},
"wouldSettle":{"type":"string","minLength":1,"maxLength":500,"description":"What evidence would settle the case."}}}`)
)

// newServer returns the MCP server of the session s, with the core tools.
func newServer(s *Session) *mcp.Server {
	server := mcp.NewServer(&mcp.Implementation{Name: "vexplain", Version: prompt.CoreVersion}, nil)
	mcp.AddTool(server, &mcp.Tool{Name: searchEvidence, InputSchema: searchEvidenceSchema,
		Description: "Search a piece of evidence of the case file by its name. Returns its lines of path = value that " +
			"contain query, at most 200."}, s.searchEvidence)
	mcp.AddTool(server, &mcp.Tool{Name: readEvidence, InputSchema: readEvidenceSchema,
		Description: "Read on in a tool result that was cut: a page of the result with the ledger ID."}, s.readEvidence)
	mcp.AddTool(server, &mcp.Tool{Name: searchTools, InputSchema: searchToolsSchema,
		Description: "Find more tools by what they do: at most 5, with their parameters, which you can call from your " +
			"next step on."}, s.searchTools)
	mcp.AddTool(server, &mcp.Tool{Name: submitVerdict, InputSchema: submitVerdictSchema,
		Description: "Submit your verdict, which ends the case."}, s.submitVerdict)
	mcp.AddTool(server, &mcp.Tool{Name: submitNoVerdict, InputSchema: submitNoVerdictSchema,
		Description: "End the case without a verdict, when the evidence can't settle it."}, s.submitNoVerdict)
	return server
}
