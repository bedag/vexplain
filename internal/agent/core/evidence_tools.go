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
	"context"
	"fmt"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/bedag/vexplain/internal/agent/ledger"
)

// maxEvidenceLines is the most lines that one search of the evidence returns.
const maxEvidenceLines = 200

type searchEvidenceArgs struct {
	Name  string `json:"name"`
	Query string `json:"query"`
}

// searchEvidence returns the lines of a piece of evidence of the case file that contain the query. The evidence is
// what collectors of vexplain delivered, so its output is of known trust.
func (s *Session) searchEvidence(ctx context.Context, req *mcp.CallToolRequest, in searchEvidenceArgs) (
	*mcp.CallToolResult, any, error) {
	return s.call(ctx, searchEvidence, req.Params.Arguments, func(context.Context) ([]byte, ledger.Trust, error) {
		lines, total, ok := s.file.Search(in.Name, in.Query, maxEvidenceLines)
		switch {
		case !ok:
			// The name isn't repeated: it is the model's, and the ledger keeps it with the arguments.
			return nil, "", fmt.Errorf("the case file holds no evidence of that name; it holds %s",
				strings.Join(s.file.Names(), ", "))
		case total == 0:
			return fmt.Appendf(nil, "No line of %s contains the query.\n", in.Name), ledger.Known, nil
		}
		out := strings.Join(lines, "\n") + "\n"
		if total > len(lines) {
			out += fmt.Sprintf("These are %d of %d matching lines: narrow the query to see others.\n", len(lines), total)
		}
		return []byte(out), ledger.Known, nil
	}, nil), nil, nil
}

type readEvidenceArgs struct {
	ID   string `json:"id"`
	Page int    `json:"page"`
}

// readEvidence returns a page of the output of a ledger entry: page 2 unless the model names one, since it was shown
// page 1. The page keeps the trust of the entry that it reads, so reading on never turns a foreign output into known
// evidence.
func (s *Session) readEvidence(ctx context.Context, req *mcp.CallToolRequest, in readEvidenceArgs) (
	*mcp.CallToolResult, any, error) {
	n := in.Page
	if n == 0 {
		n = 2
	}
	var pages int
	run := func(context.Context) ([]byte, ledger.Trust, error) {
		e, ok := s.ledger.Entry(in.ID)
		if !ok {
			return nil, "", fmt.Errorf("the ledger holds no entry %s", in.ID)
		}
		page, all, ok := s.ledger.Page(e, n)
		if !ok {
			return nil, "", fmt.Errorf("%s has %d pages, and no page %d", in.ID, all, n)
		}
		pages = all
		return page, e.Trust, nil
	}
	note := func(e ledger.Entry) string {
		if pages == 0 {
			return fmt.Sprintf("[ledger ID %s]", e.ID)
		}
		text := fmt.Sprintf("[ledger ID %s: page %d of %d of %s; claims cite %s.", e.ID, n, pages, in.ID, in.ID)
		if n < pages {
			text += fmt.Sprintf(" Read on with read_evidence(id: %q, page: %d).", in.ID, n+1)
		}
		return text + "]"
	}
	return s.call(ctx, readEvidence, req.Params.Arguments, run, note), nil, nil
}
