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

// Package prompt holds the agent's system prompt (main design 6.6.1). The core is the operator's: the role, the tool
// contract, the evidence rules and the rule that "not affected" needs strong evidence, which the loop and the validator
// depend on. The guidance follows it, and an AgentProfile can replace the guidance shipped here with its own. The
// guidance of the case's Investigation comes last.
package prompt

import _ "embed"

// CoreVersion is the version of the core prompt, which every case records. A change of core.md needs a new version.
const CoreVersion = "v8"

// CoreToolSchemaTokens is the estimate of the tokens that the definitions of the five core tools take in every
// request: bytes / 4 of their names, descriptions and input schemas, as JSON. The core's tests check it against the
// tools that vexplain's MCP server lists, so a change of a tool's definition changes it too.
const CoreToolSchemaTokens = 696

// StepMaxTokens is the most that the model may answer in one step of a case: the max_tokens of each request with
// tools. The fit check counts it for every step, since each answer stays in the conversation.
const StepMaxTokens = 4096

var (
	//go:embed core.md
	core string
	//go:embed guidance.md
	guidance string
)

// Core returns the core prompt.
func Core() string { return core }

// Guidance returns the guidance that the operator ships, which a profile's guidance of the type Embedded uses.
func Guidance() string { return guidance }

// InvestigationGuidanceMaxBytes is the most that an investigation's guidance holds, in UTF-8 bytes, as its schema allows.
const InvestigationGuidanceMaxBytes = 4096

// System returns the system prompt of a case: the core, the profile's guidance, and the guidance of the case's
// investigation, under a heading of its own, when it has any.
func System(guidance, investigationGuidance string) string {
	system := core + "\n\n" + guidance
	if investigationGuidance != "" {
		system += "\n\n# This investigation's guidance\n\n" + investigationGuidance
	}
	return system
}

// EstimateTokens estimates the tokens of text as its bytes / 4, rounded up. Every cap of the agent counts tokens this
// way (phase 4 plan, decision 11), since the operator doesn't know the endpoint's tokenizer, and a byte count needs
// none. Rounding up keeps the estimate on the side of a worst case.
func EstimateTokens(text string) int { return (len(text) + 3) / 4 }
