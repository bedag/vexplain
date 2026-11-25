# Remote spokes

One vexplain hub can serve other clusters, its spokes. This guide is for the admin who installs the hub and adds the spokes. The design is in [the design of remote spokes](design/2026-11-23-remote-spokes.md).

The hub pulls. A spoke collects in its own cluster and stores what it collects there. The hub reads it, copies it, and does all the judging: the scans, the rules, the playbooks, the cases and the agent. A spoke never calls the hub.

## The modes

The manager runs in one of three modes, set with `--mode` at start-up. A cluster keeps its mode while it runs.

| Mode | What it runs | Install |
|---|---|---|
| `HubAndSpoke` | Everything. This is the default, and what a single cluster needs. | `config/default` |
| `Hub` | The judging side, and the connection to the spokes. It runs no presence and no network reach of its own, and judges the copies of the spokes' records. | `config/hub` |
| `Spoke` | The presence and network-reach collectors, and the hub's read-only access. It runs no scanner, no agent, no rules and no playbooks. | `config/spoke` |

`config/hub` is `config/default` with `--mode=Hub`, minus the `workloads` and `network-reach` collectors. A hub that should also report on its own cluster stays `HubAndSpoke`.

Upgrade the hub first, then the spokes.

## Adding a spoke

1. **Install `config/spoke` on the spoke.** Name its cluster in its `OperatorConfig` (`clusterName`), and set its scope and owner attribution there too. They stay the spoke's collection boundary. The install creates the ServiceAccount `vexplain-hub` in `vexplain-system`, with the access in the next section.
2. **Create a token for it on the spoke**, valid for an hour:

   ```sh
   kubectl create token vexplain-hub -n vexplain-system --duration=1h
   ```

3. **On the hub, create the Secret** in `vexplain-system` with the keys `server` (the address of the spoke's API server), `ca.crt` (its CA bundle) and `token` (the token above):

   ```sh
   kubectl create secret generic cluster-a-credentials -n vexplain-system \
     --from-literal=server=https://cluster-a.example:6443 \
     --from-file=ca.crt=cluster-a-ca.crt \
     --from-literal=token="$TOKEN"
   ```

4. **On the hub, create the `Spoke`.** Its name is the cluster's name, as the spoke's `OperatorConfig` gives it. Its labels are the ones that the playbooks' cluster match reads. The hub sets them, and the spoke can't:

   ```yaml
   apiVersion: config.vexplain.bedag.ch/v1alpha1
   kind: Spoke
   metadata:
     name: cluster-a
   spec:
     labels:
       env: prod
     credentialsSecretRef:
       name: cluster-a-credentials
   ```

5. **Add a login for each registry of the spoke's images** to the scanner's `adminPullSecrets` on the hub, if the scanner has none for it yet. The hub scans every image, and the pull secrets of a spoke's workloads never leave the spoke. A registry that the hub can't reach fails visibly, in the image's facts, with the registry named.

The hub then records the cluster's identity, renews its token, and starts copying. The `Spoke` turns `Ready`. Check it with `kubectl get spoke cluster-a -o yaml`: the conditions `Connected`, `Synced` and `Ready`, `lastSyncTime`, `tokenExpirationTime`, and the spoke's collectors, as the hub last read them.

## What the hub may do on a spoke

The hub's role on the spoke grants this, and nothing else:

- get, list and watch on the namespaces, and on the `Collector`, `OperatorConfig`, `Evidence` and `ImageInventory` objects of vexplain;
- create on `serviceaccounts/token`, for the ServiceAccount `vexplain-hub` alone, to renew its token.

The hub reads no Secret, no workload, and writes no record. TLS is always verified against the `ca.crt`, and there is no way to skip it.

**To revoke the access,** delete the ServiceAccount `vexplain-hub`, or its bindings, on the spoke.

## The token

- The hub renews its token before it ends, into a Secret of its own, `spoke-<name>-token`, which the `Spoke` owns. It never writes your Secret, so a pipeline that applies your Secret again doesn't bring back an old token.
- The hub uses your token only while its own isn't usable: it has none, it expired, or the spoke refuses it.
- The hub's own token goes only to the server and the CA bundle that it was issued for. If the spoke's API server moves, or its CA is rotated, put a new token into your Secret.
- The hub compares the `ca.crt` as given. If you apply the Secret again with a `ca.crt` that differs only in white space or line endings, the hub sets its own token aside and uses yours. That is safe, and the hub then renews from yours.
- After you revoke the access, granting it again needs a new token. Create one as in step 2 and put it into your Secret. The hub picks it up once the spoke refuses its own.
- A token that ends before the hub could renew it, for example after a long outage of the hub, sets `Connected` to False with the reason `TokenExpired`. Put a new token into your Secret.
- The hub never logs or shows a token.

## Removing and reinstalling a spoke

- **Remove a spoke:** delete the `Spoke` on the hub. The hub then removes its copies of that cluster's records, and that cluster's counts and series, and its own token Secret. After that, uninstall vexplain on the spoke.
- **Reinstall a spoke** while its `Spoke` exists, with an uninstall that deletes vexplain's records, then a new install: the hub follows the uninstall and drops that cluster's copies as the spoke deletes its records. It copies them again once the new install's collectors run. In between, the cluster is missing from the cases and the metrics. An upgrade in place doesn't do this.
- **Turn a standalone install into a spoke:** uninstall it, install `config/spoke`, and add the cluster on the hub as above. Don't switch the mode in place: the old install's records stay behind, such as reports in the workloads' namespaces that show old verdicts. The uninstall also removes the install's reviews (`VexStatement`s), which live on the hub only.

## What the hub keeps

- **The copies** of a spoke's records live on the hub: its presence, its exposure, its collectors' reports and its namespaces' labels. Only what the spoke's collectors declare for the hub is copied.
- **A spoke that can't be reached** keeps its copies, unchanged, and its conditions say since when. Its cases and its series keep using them, so a cluster that can't be reached never reads as one that stopped running an image.
- **The remote series** are metrics only. The hub renders them for each spoke from the copies and its own state, and writes no report objects for a remote cluster. They carry the cluster's name: `vexplain_open_case`, `vexplain_findings`, `vexplain_funnel` and `vexplain_namespace_owner_info`. A remote cluster's workload owners see no reports for now. The SOC works from the hub, where the cases and the metrics cover every cluster.

## Limiting the scan Jobs

The hub's scan Jobs pull images for every cluster, so they need DNS and the registries, and nothing else. This NetworkPolicy, in `vexplain-system`, is an example for a CNI that enforces egress policies. Replace the addresses of `artifacts.example` and the DNS service with your own:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: scan-jobs-egress
  namespace: vexplain-system
spec:
  podSelector:
    matchExpressions:
    - key: vexplain.bedag.ch/scanner
      operator: Exists
  policyTypes:
  - Egress
  egress:
  - to:
    - namespaceSelector:
        matchLabels:
          kubernetes.io/metadata.name: kube-system
      podSelector:
        matchLabels:
          k8s-app: kube-dns
    ports:
    - port: 53
      protocol: UDP
    - port: 53
      protocol: TCP
  - to:
    - ipBlock:
        cidr: 192.0.2.10/32   # artifacts.example
    ports:
    - port: 443
      protocol: TCP
```
