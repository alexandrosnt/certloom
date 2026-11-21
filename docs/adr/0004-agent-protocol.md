# ADR-0004: Agent model and protocol (implemented in M2)

**Status:** Accepted (2026-11-21)

## Context
Local key generation, file deployment, service reload and local verification have to
happen next to the target. Target networks generally do not accept
inbound connections from a central system.

## Options considered
| Option | For | Against |
|---|---|---|
| **A. Agent dials out over mTLS; long-poll pull** | No inbound firewall rules; a separate identity per agent; works through proxies | Enrollment, rotation and revocation all have to be built |
| B. Control plane pushes over SSH/WinRM | No agent to install | A central store of host credentials; needs inbound access; one compromise reaches every host |
| C. Agent polls plain HTTPS with a bearer token | Simplest | Bearer tokens can be replayed; a weaker identity than mTLS |

## Decision
Option A.

1. **Enrollment.** An admin issues a one-time token (TTL <= 1 h, single use, scoped to one agent group). The agent generates its own key pair (ECDSA P-256 or Ed25519) and sends a CSR with the token. The control plane returns a short-lived client certificate (for example, 7 days) from an **internal agent CA**. That CA is separate from any customer PKI and only ever signs agent identities.
2. **Rotation.** The agent renews its identity certificate over the existing mTLS channel at about 50 % of its lifetime.
3. **Revocation.** The control plane keeps a deny-list of agent IDs and serials and checks it on every connection, so a revoked agent is refused immediately. The short certificate lifetime limits exposure if that check is ever bypassed.
4. **Tasks.** Each task is signed by the control plane's task-signing key (Ed25519) and bound to `agent_id`, `task_id`, `not_after`, a nonce, a per-target sequence number (ADR-0003), and one **capability** from the agent's local allowlist. Before acting, the agent checks the signature, the binding, the expiry, the sequence and the allowlist. **There is no task type that runs an arbitrary command.**
5. **Offline operation.** The agent persists accepted tasks and their results in a local embedded store (bbolt) and reports results when it reconnects. Results are idempotent by `task_id`.
6. **Autonomy while the control plane is down.** An agent may finish a task it has already accepted and may keep running its local verification probes. In M2 it does **not** start new issuance by itself. Pre-authorized renewals during an outage are an open question (risk R-03).

## Consequences
- The control plane holds the internal CA key, which can mint agent identities. It is therefore protected like a credential (ADR-0009), and its rotation procedure is documented.
- An agent never receives credentials for any other host.

## Verification
M2 tests:
- a replayed task is rejected;
- a task addressed to another agent is rejected;
- an expired task is rejected;
- a task carrying a stale sequence number is rejected;
- a revoked agent is refused;
- an agent that is offline for 1 h reconnects and reports each result exactly once.

## Implementation notes (M2, 2026-11-20)
- Transport is HTTPS + JSON long-poll over mutual TLS 1.3 (not gRPC): same per-agent identity, signed tasks and revocation; no protobuf toolchain.
- Offline autonomy is deliberately limited: agents never start issuance on their own while the control plane is unreachable; they finish and re-deliver accepted tasks.
- Trust bootstrap: the enrollment command carries the agent-CA SHA-256, which the agent pins on first contact.
