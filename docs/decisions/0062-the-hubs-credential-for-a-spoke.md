# 0062 The hub's credential for a spoke: a narrow service account whose short-lived token the hub renews

- **Status:** Accepted on 2026-11-24. Proposed on 2026-11-23. The decision is the owner's, from the brainstorm of phase
  6 on 2026-11-23. The token's lifetime is the designer's call. Revised on 2026-11-24, before acceptance: the role reads
  the namespaces and writes no requests, since the hub scans every image itself (0066) and renders the spokes' reports
  (0065). Renewed tokens go into a Secret of the hub's own, so that a Secret applied again can't bring back an expired
  token. The owner accepted the write-up with the design on 2026-11-24.
- **Date:** 2026-11-23
- **Design:** [remote spokes](../design/2026-11-23-remote-spokes.md), sections 4.3 and 5.4.

## Context

- **When the hub pulls (0060), it holds a credential for each spoke.**
- **A credential that never expires** is what Argo CD and Karmada's push mode keep by default. Kubernetes no longer
  creates such service-account tokens by default.
- **Federated identity stores no secret at all:** the spoke's API server trusts the hub's own identity. That needs
  each spoke's API server to be configured, which vexplain can't do itself.

## Options considered

| Option | Costs |
|---|---|
| A long-lived token in a Secret | It never expires |
| **A narrow service account whose short-lived token is renewed (chosen)** | Renewal logic, and a token that expires if the hub is down for too long |
| Federated identity: cloud workload identity, Kubernetes' structured authentication configuration, the ClusterProfile API's credential plugins | Each spoke's API server must trust the hub |

## Decision

- **Each spoke's install creates a ServiceAccount for the hub** in the operator's namespace, with a role that grants
  only what the hub needs (design 5.4):
  - reads of vexplain's own records;
  - reads of the namespaces, for their labels and the cluster's identity;
  - its own `serviceaccounts/token`, and nothing else.
- **An admin puts the first token** into a Secret on the hub, with the API server's address and CA bundle. The hub
  never writes that Secret.
- **The hub renews the token at half its lifetime** through the spoke's TokenRequest API, and writes the new one into
  a Secret of its own, which the `Spoke` owns **[call]**. So a pipeline that applies the admin's Secret again doesn't
  bring back an expired token. A token lives 24 hours **[call]**.
- **A token that expires before the hub could renew it** marks the `Spoke` `TokenExpired`, and the admin puts a new
  bootstrap token into the admin's Secret.
- **One place in the code gets a spoke's token,** so federation can replace it later.

## Consequences

- **No credential lives longer than a day** without the hub renewing it.
- **Revoking access** means deleting the ServiceAccount, or its binding, on the spoke.
- **A stolen token can renew itself** until it is revoked, as with any credential that renews itself. Each renewal
  shows in the spoke's audit log.
- **Rejected:**
  - a long-lived token;
  - federation now, which would need each spoke's API server to be configured to trust the hub.

**Precedent:** Open Cluster Management's managed-serviceaccount add-on keeps a narrow service account's token on the
hub, and rotates it.
