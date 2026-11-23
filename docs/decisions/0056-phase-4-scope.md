# 0056 Phase 4's scope: one existing MCP server, no auto-acceptance, dashboards after the agent; company knowledge is phase 5, and sandbox runs come after it

- **Status:** Accepted on 2026-11-16. The decisions are the owner's, from the phase 4 discussion, and the owner accepted the write-up on 2026-11-16.
- **Date:** 2026-11-16
- **Refines:** the phases of the main design (section 7) and 0050's order; 0005's configurable auto-acceptance, for phase 4; 0031's MCP collector.
- **Design:** [the agent on image cases](../design/2026-11-16-agent-on-cases.md), sections 1, 5.9, 5.10, 5.12 and 6.

## Context

- **Company knowledge,** from a wiki or a CMDB, guides the agent to more correct and more understandable answers. The owner rates it above sandbox runs.
- **MCP servers for wikis and CMDBs already exist.** The owner wants the tool path proven with one of them before vexplain builds anything of its own.
- **Auto-acceptance needs agreement rates,** which only reviews produce (main design 6.9).
- **Dashboards are best built on the agent's real output.**

## Decision

- **Phase 4 tests one existing MCP server** through an MCP collector (0031). vexplain builds no MCP server for company knowledge. The guidance says where company knowledge lives.
- **An MCP collector is a reference to a server:** its URL, headers from a Secret, and the server's tools that vexplain may call, as 0031 has it. The list is required, since vexplain calls tools unattended and such servers often serve write tools too. Whoever deploys the server answers for its privileges, and vexplain doesn't judge what a tool does. The list names tools without evidence types: the output is external evidence in phase 4 (owner, 2026-11-16).
- **No `ReviewPolicy` in phase 4.** Every agent "not affected" waits for a person.
- **The action metric and the dashboards come at the end of phase 4,** on the agent's real output.
- **Phase 5 designs company knowledge,** from what the live run shows. **Sandbox runs come after it.**
- **The model's smoke test runs at the start of the runner's task,** with the credentials the owner gives then, not before the plan (owner, 2026-11-16).
- **The live run comes after phase 4's build,** with the owner, as a task of its plan, with the cluster settings of phase 3a's fixes (owner, 2026-11-15). The action metric and the dashboards follow it, on its data.

## Consequences

- The design of phase 3a's fixes, section 4, said that phase 4's plan starts after the live run. The owner moved the run after phase 4.
- Symbol search, lookups per advisory source and clearing old tool results wait for their signals (design, section 9).
