# See cert-manager certificates from Kubernetes

cert-manager keeps renewing certificates in your clusters; certloom shows
them next to all your other certificates and warns when cert-manager gets
stuck: a certificate that is not ready, a renewal that is overdue, a failed
request, an issuer that is broken.

certloom only reads. A small agent in the cluster lists cert-manager objects
and sends them to the certloom server. It cannot read Secrets, so private
keys never leave the cluster, and it never changes anything.

This takes about ten minutes. Tested with kind (Kubernetes 1.32) and
cert-manager 1.17.

## What you need

- A certloom server. If you do not have one yet, do step 1 of
  [Monitor with OpenTofu](opentofu.md) first.
- A cluster with cert-manager, and `kubectl` with permission to create a
  namespace, a ClusterRole and a Deployment.
- Pods in the cluster can reach the certloom server on port **8444**.
  Nothing has to reach into the cluster.

## 1. Create an enrollment token

**On the certloom server** (with `CERTLOOM_SERVER`, `CERTLOOM_CA_FILE` and
`CERTLOOM_TOKEN` set as in [step 2 of the OpenTofu guide](opentofu.md#2-create-a-token-for-opentofu)):

```sh
certloom agent token --name k8s-prod
```

```
certloomenr_...
One-time token (expires 2026-11-23 14:40). On the target host run:
  certloom-agent enroll --server https://certloom.example.com:8444 --ca-hash sha256:24b5... --token-stdin
and paste the token below when prompted:
```

You need three things from it: the token (first line), the server address
and the `sha256:...` value. The token is valid for an hour.

## 2. Get the manifest and fill it in

```sh
v=0.1.0-rc.2     # the certloom version
curl -fsSLO https://raw.githubusercontent.com/alexandrosnt/certloom/v$v/deploy/kubernetes/agent.yaml
```

Open `agent.yaml` and change three places:

```yaml
  config.yaml: |
    server: https://certloom.example.com:8444   # 1. the server address from step 1
    state_dir: /var/lib/certloom-agent
    name: k8s-prod                               # 2. the name you gave the token
    targets: []
    kubernetes:
      cluster: prod                              #    and how this cluster is labeled in certloom
```

```yaml
          args: ["run", "--config", "/etc/certloom-agent/config.yaml",
                 "--enroll-token-file", "/var/run/certloom-agent/enroll/token",
                 "--ca-hash", "sha256:REPLACE"]  # 3. the sha256:... value from step 1
```

The manifest creates the `certloom-agent` namespace, a service account with
read-only access (`get` and `list` on cert-manager objects and Ingresses), a
small volume for the agent's identity, and the Deployment.

## 3. Deploy

```sh
kubectl apply -f agent.yaml
kubectl -n certloom-agent create secret generic certloom-agent-enroll --from-literal=token=certloomenr_...
kubectl -n certloom-agent rollout restart deployment certloom-agent
kubectl -n certloom-agent logs deploy/certloom-agent
```

```
{"level":"INFO","msg":"enrolled","agent_id":"agt_01m84a6pxw3pmpn753f3jeemv2"}
{"level":"INFO","msg":"certloom-agent running","agent_id":"agt_01m84a6pxw3pmpn753f3jeemv2","server":"https://certloom.example.com:8444","targets":0}
```

(The pod restarts until the Secret exists; that is expected.) The agent
enrolls once and keeps its identity on the volume. The token is now used up;
delete the Secret:

```sh
kubectl -n certloom-agent delete secret certloom-agent-enroll
```

Check that it really cannot read Secrets:

```sh
kubectl auth can-i get secrets --all-namespaces --as system:serviceaccount:certloom-agent:certloom-agent
```

```
no
```

## 4. See your certificates

certloom asks the agent for the cluster's certificates every 5 minutes. To
get the first list now, **on the certloom server**:

```sh
certloom agent inventory k8s-prod
certloom agent observations k8s-prod
```

```
Kubernetes certificates (cluster prod)
NAMESPACE  NAME      ISSUER                    READY  NOT_AFTER             RENEWAL
shop       shop-tls  ClusterIssuer/selfsigned  True   2027-02-21T13:40:41Z  2027-01-22T13:40:41Z

not listed: bundles: ... not available (HTTP 404)
```

("not listed: bundles" only means trust-manager is not installed.)

The certificates are also in the inventory with the source `kubernetes`, and
get the same expiry and key checks as everything else:

```sh
certloom inventory list
```

```
SHA256            NAME  EXPIRES           LEFT  KEY        SOURCE
efea26079d6e7863        2027-02-21 13:40  89d   RSA 2048   kubernetes
```

## What certloom warns about

These show up in `certloom findings` and go to your alert channels:

| Check | When |
|---|---|
| `k8s_certificate_not_ready` | A Certificate has been not Ready for more than an hour |
| `k8s_renewal_overdue` | cert-manager should have renewed more than an hour ago |
| `k8s_request_failed` | The request for the next certificate was denied or failed |
| `k8s_issuer_not_ready` | An Issuer or ClusterIssuer that a Certificate uses is not Ready |
| `k8s_bundle_not_synced` | A trust-manager Bundle is not synced |
| `expiry` and the other certificate checks | As for any certificate |

## More clusters

Repeat the guide with another `name` and `cluster` for each cluster. Run one
agent per cluster.

## If something goes wrong

| What you see | What to do |
|---|---|
| Logs say `enrollment rejected (401)` | The token was used or is older than an hour. Create a new one (step 1), replace the Secret, restart. |
| Logs say `pinned` or a certificate error | The `--ca-hash` in the Deployment does not match the server. Copy it again from `certloom agent token`. |
| Logs say `no such host` or `connection refused` | Pods cannot reach the certloom server on port 8444. Check DNS, network policies and firewalls. |
| `not listed: certificates ... forbidden` | The ClusterRole or its binding is missing. Apply `agent.yaml` again. |

More details: [runbooks/kubernetes.md](../runbooks/kubernetes.md).
