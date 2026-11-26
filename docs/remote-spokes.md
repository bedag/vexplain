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

`config/hub` is `config/default` with `--mode=Hub`, minus the `workloads` and `network-reach` collectors. A hub that should also report on its own cluster stays `HubAndSpoke`. Install the hub like a spoke in step 1 below, with `DEPLOY_CONFIG=config/hub` and the images of the manager (`IMG`), the agent (`AGENT_IMG`) and the collectors that it runs (`SCANNER_IMG`, `VULNERABILITIES_IMG` and `ADVISORIES_IMG`). The hub's own `clusterName` must differ from the name of every `Spoke`, and no `Spoke`'s Secret may name the hub's own API server. The hub refuses a `Spoke` named like its own cluster, with the reason `NameInUse`, and one whose Secret reaches the hub's own cluster, with the reason `OwnCluster`: such a `Spoke` is `Connected` False and `Stalled`, and the hub copies nothing for it.

Upgrade the hub first, then the spokes.

## Adding a spoke

The hub's manager must reach each spoke's API server directly: the hub connects with no tunnel or proxy in between ([decision 0061](decisions/0061-direct-access-behind-one-seam.md)).

1. **Install `config/spoke` on the spoke,** with the images that the spoke runs, and give it the `OperatorConfig` that names its cluster:

   ```sh
   make deploy DEPLOY_CONFIG=config/spoke IMG=<manager image> \
     WORKLOADS_IMG=<workloads image> NETWORK_REACH_IMG=<network-reach image>
   ```

   ```yaml
   apiVersion: config.vexplain.bedag.ch/v1alpha1
   kind: OperatorConfig
   metadata:
     name: default
   spec:
     clusterName: cluster-a
   ```

   The `clusterName` must equal the name of the `Spoke` on the hub (step 4). Its scope and owner attribution stay the spoke's collection boundary. The install creates the ServiceAccount `vexplain-hub` in `vexplain-system`, with the access in the next section. Don't apply `config/samples/` to a spoke: its `OperatorConfig` sets `clusterName: local`, and `clusterName` can be changed, so the spoke would lose the name that the `Spoke` on the hub has for it.

2. **Create a token for the hub on the spoke,** valid for an hour, and keep the spoke's CA bundle:

   ```sh
   TOKEN=$(kubectl --context cluster-a create token vexplain-hub -n vexplain-system --duration=1h)
   ```

   The CA bundle is the `certificate-authority-data` of the spoke's kubeconfig, decoded from base64, or the key `ca.crt` of the ConfigMap `kube-root-ca.crt` in any namespace of the spoke. Keep it byte for byte, as the token section says.

3. **On the hub, create the Secret** in `vexplain-system` with the keys `server` (the address of the spoke's API server), `ca.crt` (the CA bundle) and `token` (the token). Write the token to a file first, and give it to `--from-file`, so that it stays out of the arguments of a process. The command creates the Secret, or replaces the one that exists, so use it again whenever you put in a new token:

   ```sh
   (umask 077; printf %s "$TOKEN" > cluster-a.token)
   kubectl create secret generic cluster-a-credentials -n vexplain-system \
     --from-literal=server=https://cluster-a.example:6443 \
     --from-file=ca.crt=cluster-a-ca.crt \
     --from-file=token=cluster-a.token \
     --dry-run=client -o yaml | kubectl apply -f -
   rm cluster-a.token
   ```

   Delete the token file afterwards, as above, and the `TOKEN` variable with it.

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

5. **Add a login for each registry of the spoke's images** on the hub, if the scanner has none for it yet. A login is a Secret of the type `kubernetes.io/dockerconfigjson` in `vexplain-system` on the hub, named in the scanner's `adminPullSecrets`, at most 16 ([how the scanner uses them](collectors.md)). The hub scans every image, and the pull secrets of a spoke's workloads never leave the spoke. A registry that the hub can't reach fails visibly, in the image's facts, with the registry named.

The hub then records the cluster's identity, renews its token, and starts copying. The `Spoke` turns `Ready`. Check it with `kubectl get spoke cluster-a -o yaml`: the conditions `Connected`, `Synced` and `Ready`, `lastSyncTime`, `tokenExpirationTime`, and the spoke's collectors, as the hub last read them.

## What the hub may do on a spoke

The hub's role on the spoke grants this, and nothing else:

- get, list and watch on the namespaces, and on the `Collector`, `OperatorConfig`, `Evidence` and `ImageInventory` objects of vexplain;
- create on `serviceaccounts/token`, for the ServiceAccount `vexplain-hub` alone, to renew its token.

The hub reads no Secret, no workload, and writes no record. TLS is always verified against the `ca.crt`, and there is no way to skip it.

**To revoke the access,** delete the ServiceAccount `vexplain-hub` on the spoke. That invalidates every token issued for it. Deleting only its bindings stops the access while they are gone, and invalidates no token: the hub's token, and any stolen copy, work again as soon as the bindings come back, for example when the spoke's install is applied again.

## The token

- The hub renews its token before it ends, into a Secret of its own, `spoke-<name>-token`, which the `Spoke` owns. It never writes your Secret, so a pipeline that applies your Secret again doesn't bring back an old token.
- The hub uses your token only while its own isn't usable: it has none, it expired, or the spoke refuses it.
- The hub's own token goes only to the server and the CA bundle that it was issued for. If the spoke's API server moves, or its CA is rotated, put a new token into your Secret, as in step 3.
- Keep the `ca.crt` byte for byte as you first gave it. The hub compares it as given, so a re-applied Secret whose `ca.crt` differs, even only in white space or line endings, sets the hub's own token aside. The hub then sends yours, and once yours has expired the spoke disconnects with `TokenExpired` until you put in a new one, as in step 3.
- After you revoke the access by deleting the ServiceAccount, granting it again needs a new token. Apply the spoke's install again, which brings the ServiceAccount back, then redo steps 2 and 3, which put the new token into your Secret. The hub picks it up once the spoke refuses its own.
- A token that ends before the hub could renew it, for example after a long outage of the hub, sets `Connected` to False with the reason `TokenExpired`. Put a new token into your Secret, as in step 3.
- The hub never logs or shows a token.

## Removing and reinstalling a spoke

- **Remove a spoke:** delete the `Spoke` on the hub. The hub then removes its copies of that cluster's records, and that cluster's counts and series, and its own token Secret. After that, uninstall vexplain on the spoke with `make undeploy DEPLOY_CONFIG=config/spoke`.
- **Reinstall a spoke** while its `Spoke` exists: `make undeploy DEPLOY_CONFIG=config/spoke`, then `make deploy DEPLOY_CONFIG=config/spoke` with the images, as in step 1. The uninstall deletes the CRDs with vexplain's records, among them the spoke's `OperatorConfig`, and the ServiceAccount `vexplain-hub`, so the spoke refuses the hub's token. Apply the `OperatorConfig` with the spoke's `clusterName` again, as in step 1, or the spoke names itself `local`. The hub drops that cluster's copies as the spoke deletes its records, and doesn't copy them again until you redo steps 2 and 3 after the new install, which replace your Secret's token: until then the cluster is missing from the cases and the metrics, and the `Spoke` ends at `TokenExpired` once your old token has expired. An upgrade in place does none of this.
- **Turn a standalone install into a spoke:** uninstall it with `make undeploy`, install `config/spoke`, and add the cluster on the hub as above. Don't switch the mode in place: the old install's records stay behind, such as reports in the workloads' namespaces that show old verdicts. The uninstall also removes the install's reviews (`VexStatement`s), which live on the hub only.

## What the hub keeps

- **The copies** of a spoke's records live on the hub: its presence, its exposure, its collectors' status and its namespaces' labels. Only what the spoke's collectors declare for the hub is copied.
- **A spoke that can't be reached** keeps its copies, unchanged, and its conditions say since when. Its cases and its series keep using them, so a cluster that can't be reached never reads as one that stopped running an image.
- **The remote series** are metrics only. The hub renders them for each spoke from the copies and its own state, and writes no report objects for a remote cluster. They carry the cluster's name: `vexplain_open_case`, `vexplain_findings`, `vexplain_funnel` and `vexplain_namespace_owner_info`. A remote cluster's workload owners see no reports for now. The SOC works from the hub, where the cases and the metrics cover every cluster.

## Limiting the scan Jobs

The hub's scan Jobs pull images for every cluster, so they need DNS and the registries, and little else. Registries that send blob downloads to storage or CDN hosts, registry mirrors, and a proxy for scan pods need egress to those addresses too. This NetworkPolicy, in `vexplain-system`, is an example for a CNI that enforces egress policies. Replace the addresses of `artifacts.example` and the DNS service with your own:

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
