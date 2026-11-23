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
	"regexp"
	"slices"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	inventoryv1alpha1 "github.com/bedag/vexplain/api/inventory/v1alpha1"
	"github.com/bedag/vexplain/internal/agent/verdict"
	"github.com/bedag/vexplain/internal/text"
)

// The most characters of a no-verdict's why and established, as the schema of submit_no_verdict says, which gives
// wouldSettle 500. Together, with the words that join them, the three fit the 2048 characters of an Assessment's
// summary.
const (
	maxWhy         = 500
	maxEstablished = 1000
)

// The OpenVEX status and justification of the core prompt, in the API's spelling. The schema of submit_verdict allows
// no other value.
var (
	statuses = map[string]string{
		"not_affected":        string(inventoryv1alpha1.VEXStatusNotAffected),
		"affected":            string(inventoryv1alpha1.VEXStatusAffected),
		"fixed":               string(inventoryv1alpha1.VEXStatusFixed),
		"under_investigation": string(inventoryv1alpha1.VEXStatusUnderInvestigation),
	}
	justifications = map[string]string{
		"vulnerable_code_not_present": string(inventoryv1alpha1.VEXJustificationVulnerableCodeNotPresent),
	}
)

type claimArgs struct {
	Text     string   `json:"text"`
	Evidence []string `json:"evidence"`
}

type submitVerdictArgs struct {
	Status        string      `json:"status"`
	Justification string      `json:"justification"`
	NextStep      string      `json:"nextStep"`
	Summary       string      `json:"summary"`
	Claims        []claimArgs `json:"claims"`
}

// submitVerdict hands the verdict to the validator, and ends the case with it when the validator finds no problem. A
// verdict with problems comes back as a tool error that names them, so that the agent can repair it, once: a second
// rejection ends the case without a verdict, with the reason ValidatorRejected.
func (s *Session) submitVerdict(_ context.Context, _ *mcp.CallToolRequest, in submitVerdictArgs) (
	*mcp.CallToolResult, any, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.outcome.Verdict != nil || s.outcome.NoVerdict != nil {
		return failure("The case has ended: its outcome is submitted."), nil, nil
	}
	v := verdict.Verdict{Status: statuses[in.Status], Justification: justifications[in.Justification],
		Step: in.NextStep, Summary: in.Summary}
	for _, c := range in.Claims {
		v.Claims = append(v.Claims, verdict.Claim{Text: c.Text, Evidence: c.Evidence})
	}
	if problems := s.deps.Validator.Validate(v, s.ledger); len(problems) > 0 {
		var listed strings.Builder
		checks := make([]string, 0, len(problems))
		for _, p := range problems {
			fmt.Fprintf(&listed, "- %s: %s\n", p.Check, p.Message)
			checks = append(checks, p.Check)
		}
		s.rejections = append(s.rejections, checks)
		if len(s.rejections) == 1 {
			return failure("The verdict is rejected:\n" + listed.String() + "Repair it and submit it again, or call " +
				"submit_no_verdict. A second rejection ends the case without a verdict."), nil, nil
		}
		s.outcome.NoVerdict = &verdict.NoVerdict{Reason: verdict.ReasonValidatorRejected,
			Why:         text.CutChars("The validator rejected the verdict twice:\n"+listed.String(), maxWhy),
			Established: text.CutChars("The agent proposed "+in.Status+": "+v.Summary, maxEstablished),
			WouldSettle: "Evidence that passes the validator's checks that the rejection names.",
		}
		return ending(failure("The verdict is rejected again:\n" + listed.String() +
			"The case has ended without a verdict.")), nil, nil
	}
	s.outcome.Verdict = &v
	return ending(success("The verdict is recorded, and the case has ended.")), nil, nil
}

// ledgerID finds the ledger IDs that a text cites.
var ledgerID = regexp.MustCompile(`\bev-[0-9]+\b`)

type submitNoVerdictArgs struct {
	Why         string `json:"why"`
	Established string `json:"established"`
	WouldSettle string `json:"wouldSettle"`
}

// submitNoVerdict ends the case without a verdict. It takes the three parts that main design 6.6 asks for: why, what
// the agent established, citing the ledger entries that it rests on, and what would settle the case.
//
// A runner that ended the case at a limit passes the summary of its final call here, with the limit in the request's
// _meta (LimitMeta), which becomes the reason. That summary is what the model wrote without tools, so it need not cite
// the ledger: it is data to show, and a limit never ends in a verdict.
func (s *Session) submitNoVerdict(_ context.Context, req *mcp.CallToolRequest, in submitNoVerdictArgs) (
	*mcp.CallToolResult, any, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.outcome.Verdict != nil || s.outcome.NoVerdict != nil {
		return failure("The case has ended: its outcome is submitted."), nil, nil
	}
	for name, part := range map[string]string{"why": in.Why, "established": in.Established, "wouldSettle": in.WouldSettle} {
		if strings.TrimSpace(part) == "" {
			return failure(name + " is empty: say why, what you established and what would settle the case."), nil, nil
		}
	}
	if limit, at := req.Params.Meta[LimitMeta]; at {
		reason, _ := limit.(string)
		if !slices.Contains(verdict.Limits, reason) {
			return failure("The limit in _meta is none that the core knows."), nil, nil
		}
		s.outcome.NoVerdict = &verdict.NoVerdict{Reason: reason, Why: in.Why, Established: in.Established,
			WouldSettle: in.WouldSettle}
		return ending(success("The case has ended without a verdict.")), nil, nil
	}
	cited := ledgerID.FindAllString(in.Established, -1)
	if len(cited) == 0 {
		return failure("established cites no ledger ID: cite the entries, such as ev-1, that show what you established."),
			nil, nil
	}
	for _, id := range cited {
		if _, ok := s.ledger.Entry(id); !ok {
			return failure(fmt.Sprintf("established cites %s, which the ledger doesn't hold.", id)), nil, nil
		}
	}
	s.outcome.NoVerdict = &verdict.NoVerdict{Reason: verdict.ReasonGaveUp, Why: in.Why, Established: in.Established,
		WouldSettle: in.WouldSettle}
	return ending(success("The case has ended without a verdict.")), nil, nil
}
