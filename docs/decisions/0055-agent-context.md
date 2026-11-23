# 0055 The agent's context stays small: tools found by search, bounded results kept whole in the ledger, and limits that fit the model

- **Status:** Accepted on 2026-11-16. The decisions are the owner's, from the phase 4 discussion, and the owner accepted the write-up on 2026-11-16. On 2026-11-20 `describe` came to be listed from the first step ([phase 4's fixes](../design/2026-11-20-phase4-live-fixes.md), 2.3).
- **Date:** 2026-11-16
- **Refines:** the agent loop and its limits (main design 6.6, 6.6.1 and 6.6.2).
- **Design:** [the agent on image cases](../design/2026-11-16-agent-on-cases.md), sections 4.5 and 5.6.

## Context

- **Each case is its own conversation,** so context never builds up across cases. Within a case, a large SBOM, a long page or many tool definitions can still fill it.
- **The industry works in four layers:**
  1. tool definitions found by search (Anthropic's Tool Search Tool, Claude Code's deferred tools);
  2. bounded, paged results (Anthropic's guide to writing tools for agents, MCP's resource links);
  3. old results cleared past a threshold (Anthropic's context editing);
  4. a hard stop.
- **The model is on-prem,** so these live in vexplain's loop, not in a vendor's API.

## Decision

- **Layers 1, 2 and 4 now:**
  - the runner starts with the core tools and `search_tools`, and lists what a search finds;
  - every result goes whole into the ledger, and the model sees at most the profile's `toolResultMaxTokens`, with the ID to read on;
  - a limit ends the case with "no verdict" and a summary (0014).
- **The limits fit the model.** `ModelConfig` states `contextWindowTokens`. A profile whose worst case could pass it isn't `Ready`, and neither is one whose model's window is unknown.
- **Layer 3 later,** only if the replay shows cases ending with "no verdict: context limit".

## Consequences

- The worst case is plain arithmetic: the prompt, the case file, `maxSteps` results at their cap, and the reserved budget.
- The replay set measures tokens and steps per case before anything goes live.
- **Rejected:** sub-agents and code execution with MCP, for now.
