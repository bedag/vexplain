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

package core_test

import (
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/require"

	"github.com/bedag/vexplain/internal/agent/core"
	"github.com/bedag/vexplain/internal/agent/verdict"
)

// submitAtLimit calls submit_no_verdict as a runner does at a limit: with the limit in the request's _meta, which the
// model never writes.
func (f *fixture) submitAtLimit(t *testing.T, limit string, args map[string]any) *mcp.CallToolResult {
	t.Helper()
	res, err := f.client.CallTool(t.Context(), &mcp.CallToolParams{Name: "submit_no_verdict", Arguments: args,
		Meta: mcp.Meta{core.LimitMeta: limit}})
	require.NoError(t, err)
	return res
}

// At a limit, the runner passes the summary of the final call to submit_no_verdict, which ends the case with the limit
// as its reason. The summary is what the model wrote without tools, so it needn't cite the ledger.
func TestASummaryAtALimitEndsTheCaseWithTheLimitAsItsReason(t *testing.T) {
	f := start(t, options{evidence: longLines(t, 3)})
	_, failed := f.call(t, "search_evidence", search(contents, "000"))
	require.False(t, failed)
	summary := map[string]any{"why": "The case reached its limit of 15 model calls with tools (maxSteps).",
		"established": "The image installs libbrotli1.", "wouldSettle": "A fixed version."}

	res := f.submitAtLimit(t, "Lunch", summary)
	require.True(t, res.IsError, "a limit that the core doesn't know")
	require.Nil(t, f.session.Outcome().NoVerdict)

	res = f.submitAtLimit(t, verdict.ReasonMaxSteps, summary)
	require.False(t, res.IsError)
	require.Equal(t, true, res.Meta[core.EndedMeta], "the result says that the case has ended")
	require.Equal(t, &verdict.NoVerdict{Reason: verdict.ReasonMaxSteps, Why: summary["why"].(string),
		Established: summary["established"].(string), WouldSettle: summary["wouldSettle"].(string)},
		f.session.Outcome().NoVerdict)
}

func TestTheResultThatEndsTheCaseSaysSo(t *testing.T) {
	f := start(t, options{evidence: longLines(t, 3)})
	res, err := f.client.CallTool(t.Context(), &mcp.CallToolParams{Name: "search_evidence", Arguments: search(contents, "000")})
	require.NoError(t, err)
	require.Nil(t, res.Meta[core.EndedMeta])
	before := f.session.Outcome()
	_, failed := f.call(t, "search_evidence", search(contents, "001"))
	require.False(t, failed)
	require.Equal(t, 1, before.Ledger.Len(), "an outcome holds a copy of the ledger as it stood")
	require.Equal(t, 2, f.session.Outcome().Ledger.Len())

	res, err = f.client.CallTool(t.Context(), &mcp.CallToolParams{Name: "submit_verdict",
		Arguments: verdictOf("affected", "", "The image installs libbrotli1 1.0.9-2 (ev-1).", first)})
	require.NoError(t, err)
	require.False(t, res.IsError)
	require.Equal(t, true, res.Meta[core.EndedMeta])
}
