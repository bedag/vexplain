# 0037 A collector's proxy comes from its runtime config, not from the operator

- **Status:** Accepted on 2026-11-07 (decided by the owner).
- **Date:** 2026-11-07
- **Refines:** 0030, by making the runtime config the only source of a collector's environment beyond vexplain's contract. It replaces decision 9 of the phase 2b plan, by which the deployer copied the manager's proxy variables into each collector's Deployment.
- **Design:** [collectors, evidence and rules](../design/2026-10-31-collectors-evidence-rules.md), section 5.8.

## Context

- **Phase 2b copied the manager's `HTTPS_PROXY`, `HTTP_PROXY` and `NO_PROXY`** into every collector's Deployment, unless its runtime config set them otherwise.
- **That gives every collector the operator's network settings,** whether they suit it or not, including a third party's collector, and with them any credentials that a proxy URL holds. A collector can't refuse them, and the admin who installs a collector doesn't see that it got them.
- **Crossplane keeps its core out of this.** A provider that needs a proxy gets it in its `DeploymentRuntimeConfig`, the kind that vexplain's runtime config follows. A provider that names no runtime config uses the one named `default`.
- **Scan Jobs aren't shaped by any runtime config:** a collector builds the pods it creates from its own settings, with the SDK's pod template (`sdk/podtemplate`). Where registries are reachable only through a proxy, those pods need one too.

## Decision

- **The operator passes none of its own environment to collectors.** The manager reads its proxy from its own environment, for its own requests, as 0013 and 0017 say.
- **A collector's proxy is its runtime config's.** An admin sets `HTTPS_PROXY`, `HTTP_PROXY` and `NO_PROXY` on the container `collector` in the `default` runtime config, for every collector that names none, or in a collector's own runtime config. A variable may come from a Secret in vexplain's namespace, so that a proxy's credentials stay out of the config.
- **Pods that a collector creates take environment variables from its settings,** through `sdk/podtemplate`. Each variable has a value or comes from a key of a Secret in the pod's namespace. The pod template refuses a variable that it sets itself.
- **vexplain's install sets no proxy.** It can't know one. The guide shows a runtime config with a proxy, and how to give the scanner's scan pods one.

## Consequences

- **An install that relied on the manager's proxy** must set it in the runtime configs: the matcher's, for its database updates, and `default` for the others that need it.
- **Each collector's network access is visible** in the runtime config that runs it.
- **Rejected:**
  - **Keeping the copy, with a switch to turn it off:** the default would still hand the operator's settings to every collector.
  - **A proxy field of vexplain's own on `CollectorRuntimeConfig`:** environment variables are how processes read a proxy, and the Deployment template already takes them.
