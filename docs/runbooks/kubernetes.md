# Runbook: observing cert-manager in Kubernetes

certloom does not issue certificates in Kubernetes: cert-manager does. An in-cluster
certloom-agent reads cert-manager and trust-manager objects so their certificates show up
in the inventory and failures raise findings (ADR-0023).

The agent only has `get` and `list` on Certificates, CertificateRequests, Issuers,
ClusterIssuers, Bundles and Ingresses. It cannot read Secrets or ConfigMaps: certificates
are taken from the CertificateRequest of each Certificate's current revision.

## 1. Deploy

```sh
docker build -f Dockerfile.agent -t certloom-agent:dev .   # push to your registry
certloom agent token --name k8s-prod                         # one-time token + CA hash
```

Edit `deploy/kubernetes/agent.yaml`: `server`, `name` and `cluster` in the ConfigMap,
`--ca-hash` and the image in the Deployment. Then:

```sh
kubectl apply -f deploy/kubernetes/agent.yaml
kubectl -n certloom-agent create secret generic certloom-agent-enroll --from-literal=token=<token>
kubectl -n certloom-agent rollout restart deployment certloom-agent
```

The agent enrolls on its first start and keeps its identity on the PVC. Delete the
token Secret afterwards; it is single-use anyway. Run one agent per cluster.

Check the permissions:

```sh
kubectl auth can-i get secrets --all-namespaces --as system:serviceaccount:certloom-agent:certloom-agent   # no
```

## 2. What is reported

Every 5 minutes (`kubernetes.interval_seconds`) the control plane asks for an inventory.
`certloom agent observations k8s-prod` shows it. Certificates with a CertificateRequest
still in the cluster are imported into the inventory (source `kubernetes`) and get the
usual expiry and key checks; a Certificate whose request was garbage-collected is shown
from its status only.

Findings (subject: the object):

| Check | When |
|---|---|
| `k8s_certificate_not_ready` | Ready=False for more than an hour |
| `k8s_renewal_overdue` | `renewalTime` passed more than an hour ago |
| `k8s_request_failed` | The request for the next revision was Denied or Failed |
| `k8s_issuer_not_ready` | An Issuer or ClusterIssuer used by a Certificate is not Ready |
| `k8s_bundle_not_synced` | A trust-manager Bundle is not Synced |

Findings of deleted objects resolve on the next inventory. If a kind cannot be listed
(CRD not installed, permission missing), it is named under "not listed" and its findings
are kept.
