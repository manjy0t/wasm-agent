# What the four services do

For the shared-agent architecture and current flow, see [PORTABLE_AGENT.md](PORTABLE_AGENT.md).
The flow below describes the retained legacy benchmark profile.

The existing Wasm agent still decides whether its signed job and workload rule permit execution, then calls the restricted launch interface. Native host code creates the container and runs Wasmtime. The new APIs replace manual provisioning around that implementation.

```mermaid
sequenceDiagram
    participant U as Alice's client
    participant I as Identity VM
    participant M as Management VM
    participant E as TDX execution API
    participant A as Wasm agent and private worker
    participant F as File VM
    U->>I: 1. Register public key and proof of possession
    I-->>U: 2. Signed enrollment document
    U->>E: 3. Present document and prove key possession
    E->>I: 4. Check current user status
    E-->>U: 5. Enrollment accepted
    U->>M: 6. Signed request for published workload names
    M->>I: 7. Forward original signed approval request
    I-->>M: 8. Updated signed document
    M-->>U: 9. Return the permission document
    U->>E: 10. Enroll update and obtain current session
    U->>M: 11. Exact job signed by Alice
    M->>E: 12. Forward signed job and document
    E->>I: 13. Check current authorization and revocation
    E->>A: 14. Dispatch to Alice's broker and agent
    A->>F: 15. Broker downloads artifact on cache miss or bypass
    F-->>A: 16. Artifact bytes; worker verifies and compiles
    A-->>E: 17. Execute fresh instance and validate result
    E-->>M: 18. Result and execution timings
    M-->>U: 19. Completed response and management timings
```

Step 15 uses the native broker's network access. The user container has no network interface for contacting the file service. It requests approved artifact bytes through restricted local IPC. On a valid private code-cache hit, preparation is skipped, but authorization and fresh workload execution still occur.

## API endpoints

| Service | Endpoint | Purpose |
|---|---|---|
| Every role | `GET /health` | Service liveness; no attestation claim |
| Identity | `GET /v1/trust` | Signed issuer/public endpoint information |
| Identity | `GET /v1/workloads` | Published workload catalog |
| Identity | `POST /v1/register` | Register a public key with signed proof of possession |
| Identity | `POST /v1/renew` | Issue a current document to the same user key |
| Identity | `POST /v1/publish` | Operator publishes exact workloads and rules |
| Identity | `POST /v1/approve` | Validate the user's forwarded approval request |
| Identity | `GET /v1/status/<user>` | Signed current user status used by the services |
| Identity | `POST /v1/revoke` | Operator revokes a user |
| Files | `POST /v1/upload` | Operator uploads hash-addressed Wasm |
| Files | `GET /artifacts/<sha256>.wasm` | Download a public immutable artifact |
| Management | `GET /v1/workloads` | Fetch the published catalog |
| Management | `POST /v1/approve` | Relay the user's signed approval request |
| Management | `POST /v1/run` | Submit one signed job and wait for its result |
| Management | `POST /v1/result` | Owner-authenticated lookup after a lost response |
| Shared-agent management | `POST /v1/audit` | Signed, user-scoped view of collected audit history |
| Execution | `POST /v1/enroll` | Enroll a signed document and public key |
| Execution | `POST /v1/session` | Obtain the current broker epoch and execution mode |
| Execution | `POST /v1/run` | Independently authorize and execute the signed job |

The supplied client constructs signed request envelopes. It uses domain-separated Ed25519 signatures over canonical JSON, including destination, operation, subject, body, nonce and expiry. Execution tickets retain the existing `job_signing.py` protocol and bind user, artifact hash/size, rule hash, cache choice, job ID, nonce, worker audience, isolation and session epoch. Requests cannot ask the system to execute an arbitrary URL or shell command.

The shared-agent audit endpoint accepts a signed `audit` request containing
`document`, optional `job_id`, `after` (default 0) and `limit` (default 50, maximum
100). The identity document must match the request's user and public key. The
response contains signed records and `next_cursor`; it never returns another
user's events. See [AUDIT.md](AUDIT.md) for verification and recovery details.

## Keys and trust

| Key or document | Where it belongs | Purpose |
|---|---|---|
| User private key | User's laptop | Sign enrollment requests and exact jobs |
| Identity private key | Identity VM | Sign enrollment/authorization documents and status |
| Operator private key | Operator's laptop | Publish workloads and revoke users |
| TLS server private key | Its own VM | Authenticate that HTTPS endpoint |
| CA private key | Operator's laptop | Issue service certificates |
| Public CA and issuer fingerprint | Clients and services | Bootstrap trusted service/issuer identities |
| Signed enrollment document | User and services | Public, expiring grant bound to a user key |
| Broker routing tokens | Execution VM only | Authenticate gateway-to-local-broker calls |

There is no special TDX hardware token in this workflow. Local broker tokens are random software credentials; they do not prove TDX identity. The issuer key and TLS keys are separate. Signing a document does not encrypt it.

Enrollment documents last three hours. Signed API requests and jobs have short validity windows. The client refreshes documents and obtains current epochs through APIs. Revoked users cannot renew. Execution checks the issuer's current status on each admission; an unavailable issuer causes new execution requests to fail closed. This adds an identity-service round trip and is part of the measured system cost.

Per-user brokers preserve the existing Rust policies without a global policy reload. A user permission revision replaces that user's broker after its jobs drain. Other users keep their brokers and caches. The gateway limits simultaneous brokers and can evict an idle broker when capacity is needed. Eviction loses that user's volatile cache and changes its session epoch.

## What this protects, and its limits

- A copied enrollment document is insufficient without the user's private key. Management cannot change a signed job's user, artifact, cache choice or permissions without invalidating its signature.
- An enrolled malicious user still receives only published permissions and bounded resources. Their approved code runs inside Wasmtime, in their own container for the agent profile. Cached compiled code is private to that worker; workload linear memory is recreated for each job.
- The broker, Wasm helper and destination worker retain their own job checks. The execution API performs additional enrollment, current-revision and replay checks before dispatch.
- The execution gateway, native runtime, Docker and guest kernel remain trusted enforcement code. Containers share the guest kernel. TDX does not isolate one process from a compromised kernel inside the same confidential VM.
- Management can deny service, delay requests or misreport results and timings if compromised. There is no signed execution receipt or attestation proof here. Client checks catch wrong deterministic answers but are not proof that execution happened.
- A dishonest identity service can issue grants within the execution service's local ceilings. Its signing key is a trust root and must be protected. Real-person identity checking, key recovery, key rotation and Sybil resistance are not implemented by open key registration.
- Replay admission is persisted in each service's SQLite database. New jobs are not automatically retried after an uncertain network outcome. Already admitted jobs are not canceled by revocation.
- The file service publishes code openly; this is not private artifact storage. HTTPS authenticates the server and hash checks bind the bytes to approval. Workload data and code-cache isolation do not depend on a claim that each cache is separately encrypted.

Registration is bounded to 64 users, and the default execution pool has four active user brokers. The Python API servers bound connections and request sizes, but this remains a controlled benchmark service. Use a restricted source-IP firewall for the experiment. A public production service also needs operational monitoring, stronger abuse controls, certificate/key lifecycle management and a reviewed deployment model.

No device attestation is implemented or verified. `platform: IntelTdx` is local platform detection, and `attestation_verified: false` remains explicit.

## Agent lifecycle APIs (portable architecture)

All management-facing requests below use the existing signed-request format,
management audience, subject `management`, and **the management service's own
signing key**. User and publisher keys are rejected. `execution_url` must match
a configured target. The CLI runs on the management server; keys are not copied
to Alice/Bob's computer.

| POST endpoint | Signed operation | Body |
|---|---|---|
| `/v2/agents/status` | `agent-status` | `execution_url` |
| `/v2/agents/undeploy` | `agent-undeploy` | `execution_url`, `drain_seconds` (integer 0–60) |
| `/v2/agents/deploy` | `agent-deploy` | `execution_url` |

Management owns a durable retirement ID. Repeating undeployment continues that
ID; it never reruns a workload. Success includes the exact agent identity, final
signed drain proof and collected audit checkpoint. `draining` is incomplete,
`retiring` means the checkpoint is collected but cleanup acknowledgement remains,
and `undeployed` confirms runtime exit and private runtime-file removal. Status
reports both management's durable target state and execution's state.

Execution accepts `/v2/agent/drain` only over the attested encrypted channel. It
checks the current agent instance and retirement ID. Owner-signed execution
controls `/v2/agent/lifecycle-status`, `/v2/agent/retire` and `/v2/agent/resume` use
the execution audience and matching `agent-<action>` operation. Retirement
requires the exact identity and collected checkpoint from that drain; resume
requires that retirement's ID and confirmed cleanup. Ownership remains reserved.

See [PORTABLE_AGENT.md](PORTABLE_AGENT.md#management-controlled-undeployment) for
operator commands, timeout semantics and failure handling.
