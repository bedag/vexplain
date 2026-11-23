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

// Package verdict holds what the agent submits on a case, a verdict or no verdict, and the problems that the validator
// finds in a verdict (main design 6.6 and 6.7). It imports nothing of the agent's, so that the core, which takes the
// submissions, and the validator, which checks them, share it without importing each other.
package verdict

// ReasonGaveUp is the reason of a no-verdict that the agent submitted itself: it found that the evidence can't settle
// the case.
const ReasonGaveUp = "GaveUp"

// ReasonValidatorRejected is the reason of a no-verdict that the validator caused: it rejected the agent's verdict
// twice, after the one repair that the agent gets.
const ReasonValidatorRejected = "ValidatorRejected"

// The reasons of a no-verdict that a limit of the profile caused (main design 6.6): the runner ended the case at it.
const (
	// ReasonMaxSteps is the limit maxSteps: the model calls with tools that a case takes.
	ReasonMaxSteps = "MaxSteps"
	// ReasonMaxTokens is the limit maxTokens: the tokens that a case spends. A case ends at it when its next step and
	// the final call could pass it.
	ReasonMaxTokens = "MaxTokens"
	// ReasonTimeout is the limit timeoutSeconds: the time that a case takes.
	ReasonTimeout = "Timeout"
	// ReasonContextLimit is the model's context window: the next request, with the room for an answer, would no longer
	// fit in it.
	ReasonContextLimit = "ContextLimit"
)

// ReasonModelError is the reason of a no-verdict that the model's endpoint caused: a request of the case failed.
const ReasonModelError = "ModelError"

// Limits are the reasons of the limits, which a runner names when it passes a summary at a limit.
var Limits = []string{ReasonMaxSteps, ReasonMaxTokens, ReasonTimeout, ReasonContextLimit}

// Verdict is the agent's verdict on a case. It holds for every finding of the case. Its text comes from the model,
// and is data.
type Verdict struct {
	// Status is what the agent concluded, OpenVEX's status as the API spells it: Affected, UnderInvestigation,
	// NotAffected or Fixed.
	Status string
	// Justification says why the case is NotAffected, as the API spells OpenVEX's justification, such as
	// VulnerableCodeNotPresent. It is empty when the agent gave none.
	Justification string
	// Step is what a person should do now, in the agent's words, and Summary a few sentences that a person can act on
	// without reading the ledger.
	Step, Summary string
	// Claims are what the verdict rests on, each with the ledger entries that support it.
	Claims []Claim
}

// Claim is one statement of a verdict, and the IDs of the ledger entries that support it, such as ev-3.
type Claim struct {
	Text     string
	Evidence []string
}

// NoVerdict says why a case ended without a verdict. Its text comes from the model, and is data.
type NoVerdict struct {
	// Reason says what ended the case, such as ReasonGaveUp.
	Reason string
	// Why the case can't be settled, what the agent established, citing ledger IDs, and what would settle it.
	Why, Established, WouldSettle string
}

// Problem is what the validator found wrong with a verdict: the check that failed, and a message that the agent gets
// back to repair the verdict.
type Problem struct {
	Check, Message string
}
