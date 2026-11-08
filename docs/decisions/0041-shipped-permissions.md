# 0041 Collectors ship their permissions; vexplain grants them under a ceiling and a deny list

- **Status:** Accepted on 2026-11-08 (decided by the owner). Running the granting identity inside the operator at first is the designer's call.
- **Date:** 2026-11-08
- **Refines:** "vexplain grants none" (the design of collectors, evidence and rules, section 5.9) and 0029.
- **Design:** [the collector model](../design/2026-11-08-collector-model.md), section 5.4.

## Context

- **Until now an admin granted each collector's RBAC by hand.** vexplain checked each declared permission with a SubjectAccessReview and reported `MissingPermissions`.
- **The trigger runtime reads for the collectors it serves** (0040), so it needs their kinds.
- **The owner's view:**
  - collectors ship their own ClusterRole, as many projects do;
  - the admin sets hard limits, which are detected when a collector is applied;
  - Secrets are denied by default, but the admin can change that;
  - a deny list keeps data from collectors as a second guard, and must not confuse admins.

## Decision

- **Shipped permissions.** The `Permissions` that a collector declares in `GetCapabilities` become RBAC that the `Collector` owns:
  - for triggered kinds, a ClusterRole labelled to aggregate into the trigger runtime's role;
  - for what the collector reads itself, a ClusterRole bound to its own service account, plus a Role in its own namespace.
- **The ceiling is the admin's hard limit.** It's an aggregated ClusterRole that the admin extends with labelled roles, as Crossplane does with `crossplane:allowed-provider-permissions`.
  - vexplain grants through an identity that holds exactly the ceiling. Kubernetes lets someone create a role only if they hold its permissions or have the `escalate` verb, so the API server refuses a role beyond the ceiling.
  - vexplain checks first. A collector that asks for more gets `Ready=False` with the reason `PermissionsNotAllowed`, which names the rules, and nothing is granted.
- **The deny list is a second guard.**
  - It sits in `OperatorConfig`, as RBAC rules with verbs. Deny wins over the ceiling, as an explicit deny does in AWS IAM.
  - The default is list and watch on Secrets.
  - It acts at one decision point, the grant. A collector only gets deliveries for the kinds in its own role, so deliveries follow from the grant.
  - The condition names which guard refused.
- **`MissingPermissions` stays,** for an admin who grants by hand.
- **The granting identity runs inside the operator at first.** Its own Deployment is an option for later.
- **Evidence never carries secret values.** For third-party collectors this is a contract: the SDK documents it, and the conformance suite tests it with canary values. Masking the values of delivered Secrets is deferred.

## Consequences

- **Installing a collector becomes one step,** within limits that the admin sets.
- **vexplain may create RBAC, but only within the ceiling,** which Kubernetes enforces.
- **RBAC has no deny rules,** so the default ceiling lists the kinds it allows. A collector for a new kind needs the admin to add that kind.
- **A grant made by hand, outside vexplain, is the RBAC admin's business.**
- **Rejected:**
  - granting with `escalate` and `bind`: vexplain could grant anything, and the limit would rest on vexplain's own logic;
  - a deny list that acts on deliveries and grants separately, which would confuse admins.
