# AGENTS.md

Instructions for AI coding agents, and for humans, working on vexplain. This file is tool-neutral on purpose: agent instructions live here, not in tool-specific files.

## Project

vexplain is a Kubernetes operator that turns the flood of vulnerability findings into a short, explained worklist:

- deterministic rules settle a finding only when the evidence makes the verdict highly likely, and each verdict lays out what it couldn't check
- an embedded LLM agent investigates the rest and proposes VEX statements
- people review what the agent proposes

| What | Where |
|---|---|
| Design (source of truth) | `docs/design/2026-10-29-vexplain-design.md` |
| Collectors, evidence and rules (extends the design) | `docs/design/2026-10-31-collectors-evidence-rules.md` |
| Decision records | `docs/decisions/` (index in its `README.md`) |
| Implementation plans, one per phase | `docs/plans/` |
| Architecture diagrams (from phase 7) | `docs/architecture/` |
| Measurements | `docs/measurements/` |

Before changing anything, read design sections 1, 5 and 6.1 and the decision index. For collectors, evidence, playbooks or rules, also read the design of collectors, evidence and rules.

## How work happens

- **Design first.** A change in behaviour or API goes into the design and a decision record before any code. A changed decision gets a note in its status line, or a new record that refines or supersedes it. Never rewrite a decision silently.
- **Plans.** Each phase has a plan in `docs/plans/`. Implement it task by task, test first. A task is done when its tests pass, it is committed and it has been reviewed. Don't implement anything without an approved plan.
- **Tests run on a local kind cluster.** `make test` uses envtest, and anything that needs a real cluster uses kind. Never run tests, tools or experiments against any other cluster, such as one from a developer's kubeconfig, unless the owner asks for it. Give the kind cluster its own kubeconfig file (`KUBECONFIG=<file>`), so a developer's kubeconfig is neither used nor changed.
- **Branches.** Never commit to `main`. Work on a feature branch and open a pull request.
- **Commits and pull requests.** Conventional Commits (`feat:`, `fix:`, `docs:`, `test:`, `chore:`), small and focused. No AI co-author trailers or attribution lines, in commits or in pull requests.
- **Diagrams** are Mermaid, inside the Markdown.

## Commands

These are available once the kubebuilder scaffold exists (phase 1, task 1):

| Command | Does |
|---|---|
| `make manifests generate` | Regenerate CRDs, RBAC and deepcopy code after changing API types or markers |
| `make lint` | golangci-lint, including kube-api-linter |
| `make test` | Unit and envtest tests |
| `make test-e2e` | End-to-end tests on a local kind cluster |

Run `make manifests generate && make lint && make test` before every commit.

## Code conventions

- **Layout:** Go with the kubebuilder multi-group layout, `api/<group>/v1alpha1` and `internal/controller/<group>`.
- **API groups** under `vexplain.bedag.ch`:
  - `config`: admin-owned kinds
  - `triage`: assessments and results
  - `inventory`: bulky, derived data
- **API rules** (design section 6.1):
  - the generated schema is the contract, and kube-api-linter must pass
  - optional fields by default; fields arrive with the phase that uses them
  - open enums instead of booleans; no floats in `spec`; units in field names
  - `metav1.Condition` with `observedGeneration`
  - strict validation with CEL from the start
- **RBAC only through `+kubebuilder:rbac` markers.** Markers can't generate bindings, so those live as YAML in `config/rbac`.
- **Hub and spoke stay separate** (decision 0021). Spoke code reaches hub state only through the shared interfaces, such as `inventory.Store`. Hub code never calls spoke code directly, so a hub-only deployment always stays possible.
- **Bulky data** is read and written only through its storage interface (decision 0004).

## Safety rules

These are not negotiable.

- **Read-only towards workloads:** get, list and watch only. Never write to analysed workloads, and never `exec` into pods.
- **Secret values** are never logged, emitted in status, events or metrics, or stored. Secret and environment-variable values are never sent to the LLM.
- **A false "not affected" is the worst possible error.** "Not affected" and `fixed` need strong, specific evidence; anything weaker is "unclear". A missing tool or collector must never move a verdict towards "not affected".
- **Hitting a limit means "no verdict"** with a summary, never a guess.

## Repository hygiene

The repository must not contain private data:

- no internal hostnames, URLs, or cluster, team or customer names
- no links to internal wikis, and no internal ticket or ADR numbers
- no model or vendor names from a specific deployment
- no figures from real platforms; real data exports stay outside the repository
- test fixtures use neutral names such as `cluster-a`, `team-a` and `artifacts.example`
