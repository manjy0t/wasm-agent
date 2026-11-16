# One management-owned orchestration agent per VM

This is the `hal-managed-agent-v2` architecture. It uses the existing repository;
it does not build from or require the separately supplied original HAL repository.
Rebuild the runtime and use **`dist/orchestration-agent.wasm`**. The older
`dist/agent.wasm` remains the agent for the explicit legacy benchmark profile.

## Architecture decisions

1. Management and its Wasm agent are trusted. User workloads may be malicious.
2. Management's administrative provisioning installs the native Wasm runtime,
   ELASTIC TEE HAL, protected execution gateway and environment on each selected VM.
   The provisioner can run under management's administrative account; ordinary
   users have no SSH, deployment-signing or agent-selection authority.
3. Before sending the agent or its private configuration, management verifies fresh
   platform attestation against its approved measured-boot policy. The quote binds
   the capability manifest, intended agent/configuration hashes, VM identity,
   management owner, nonce, destination and encrypted-channel public key.
4. Each VM has one management owner and one active shared orchestration agent.
   Management can select among several separately provisioned execution VMs.
5. The shared agent requests one native broker per active user through HAL. A broker
   loads user workloads in that user's private gVisor sandbox; it never loads the shared agent.
   All of one user's workloads share this sandbox and its resource limits. Each job
   still gets a fresh Wasm Store with mandatory HAL permissions. See [GVISOR.md](GVISOR.md).
6. The Python execution gateway remains a protected loader and encrypted transport.
   The Rust runtime supplies native HAL operations and holds the non-exportable
   agent identity key. Management and the agent handle workload authorization.
7. Users keep their signing private keys. Their public keys and approved grants are
   delivered to the agent through the management-authenticated encrypted channel.
8. Management supplies the exact access policy with each workload launch. The
   Wasm agent checks the user's signature and policy, then requests native enforcement.
9. The native HAL binds every control operation to its current grant/job. It
   enforces permissions, scope, size, fuel, time and output limits. Workload imports
   also check their installed policy. A new policy cannot widen an existing Store.
10. An Ed25519 agent identity key is generated in the execution runtime after
    platform verification and agent loading. Management certifies its public key.
    Status and result proofs identify that agent instance, VM, owner and agent hash.
11. Service credentials are scoped and sent over the attested encrypted channel.
    File access tokens are per-user artifact grants and expire. They stay outside
    workload containers and never appear in a job result or public certificate.
12. The agent consumes native HAL functions; it cannot create missing host facilities
    by declaring new WIT imports. Intel TDX and AMD SNP need compatible installed
    backends and valid provider-specific evidence verification.

## Request flow

```mermaid
sequenceDiagram
    participant U as Alice / Bob
    participant I as Identity service
    participant M as Trusted management
    participant E as Execution gateway
    participant H as Native HAL + shared Wasm agent
    participant B as User broker
    participant W as Private user worker
    participant F as File server
    U->>I: Register public key; request approved functions
    I-->>U: Signed user document
    U->>M: Open session, prove key ownership
    M->>E: Signed challenge + required HAL world
    E-->>M: Bound capability manifest + fresh hardware evidence
    M->>M: Verify evidence, approved boot state and HAL compatibility
    M->>E: Encrypted agent + private configuration
    E->>H: Load exactly one shared agent
    H->>H: Generate agent identity key (private key stays here)
    H-->>M: Public identity + signed fresh acknowledgement
    M->>H: Management-signed agent identity certificate
    M->>F: Obtain scoped, expiring file access token
    M->>H: Encrypted user public key, grants and file credential
    H->>B: Agent calls HAL to launch this user's broker
    U->>M: Signed workload request
    M->>M: Check user, function, policy and destination
    M->>H: Encrypted job + exact workload policy
    H->>H: Agent verifies user signature and applies mandatory rights
    H->>B: HAL launches the authorized job
    B->>W: Run in this user's worker with pinned policy
    W->>B: Request approved artifact through private IPC
    B->>F: Authenticated download
    F-->>B: Immutable Wasm bytes
    B-->>W: Verified bytes; worker verifies again
    W->>W: Fresh Wasmtime Store; enforce every protected HAL call
    W-->>H: Result via user broker
    H->>H: Agent and native checks validate and commit result
    H-->>M: Agent-signed result over encrypted channel
    M->>M: Verify agent identity and job binding
    M-->>U: Result and timings
```

One shared Wasm Store handles decisions and completion checks. It releases the
Store lock while native brokers execute jobs, so different users can execute
concurrently. A user has a distinct broker epoch, cache and worker. Workloads in
one user's container share its OS process/kernel boundary; they receive fresh
Wasm Stores and separate artifact storage scopes. This does not claim a separate
VM or kernel for each workload, nor containment of every native runtime exploit.

## HAL extensions and mandatory enforcement

The shared agent's contract is `elastic:orchestration@1.1.0` in
`wit-orchestration/orchestration.wit`. The native runner checks both imports and
exports before loading it. Workloads retain `elastic:hal@0.1.0`.

| Agent operation | Native check / effect |
|---|---|
| `stop-user-brokers()` | Only during the owning management service’s drain, with no active jobs; requires confirmed broker/worker cleanup. |
| `launch-user-broker()` | Requires `broker.launch` and a current management grant; starts a fixed native binary with scoped credentials and public keys. |
| `apply-workload-policy(policy-json)` | Requires `workload.policy`; the policy must equal the management grant and the user-signed rule hash. |
| `launch-workload()` | Requires `workload.launch` and an already installed policy; dispatches only the bound user/job/artifact. |
| `commit-result()` | Requires `result.commit`; commits the native retained completion after agent validation. |
| Native identity proofs | Require `identity.sign`; the private key is held by the native runtime, not exported to workload guests. |

Management can narrow `agent_configuration.agent_permissions`. The default is
`broker.launch`, `workload.policy`, `workload.launch`, `result.commit`, `identity.sign`.
Unknown rights are refused. Identity signing is required to activate this profile.
These permissions are not workload permissions.

Workload rules allow `crypto`, `random`, `clock` and `storage` HAL services.
Other privileged HAL services (network sockets, inter-workload communication,
GPU, resource-management operations and guest attestation) remain denied.
Without a finer profile, platform metadata remains readable. HAL and WASI
clock/random calls now require the corresponding workload permission. Optional
operation profiles narrow these grants, remain bound to the signed rule, and are
reset for every fresh Store. No WASI directories, network authority, environment,
standard input/output or service secrets are inherited. See
[Agent decisions and workload access](WORKLOAD_ACCESS.md) for the responsibilities
of management, the agent, broker and native runtime.
Memory, fuel, timeout, output and storage quotas are separately enforced.

`Shared::execute` installs the mandatory user/artifact policy **before** Wasm
instantiation. Cached components get a fresh Store with the current policy on every
call. The native worker refuses managed execution without a rule. Updating a user
grant requires a new revision for changed rights, waits for that user's active work,
and replaces only that user's broker. It does not replace the shared agent.

This integrates enforcement into the actual runtime paths; it does not assume that
an unused enforcement library or a WIT declaration provides protection.

## VM ownership and agent identity

The gateway holds an exclusive VM runtime lock and persists `agent-owner.json`
in execution service state. It records a stable VM ID and the management public key.
The native runner separately locks the active-agent slot for its whole lifetime.
Deployment races cannot create a second runtime. A stopped process or expired
channel does not clear ownership. Another management key is refused even if it is
on the initial trusted-management list. Changing the owner is an explicit trusted
administrative reprovisioning operation, not an ordinary API request.

Re-attestation can open a new channel to the same agent and renew its certificate.
Its identity remains unchanged until that runtime restarts. A restart generates a
new identity key and instance; the stable VM ID/owner remain. Management checks a
fresh signed status proof before reusing its connection. It never automatically
replays a workload whose response was lost.

The identity certificate covers the VM ID, agent instance, agent hash, interface,
agent public key, management public key, issue time and expiry. It is a management
certificate backed by the attested loader channel, **not an Intel or AMD signature
on the agent public key**. The key itself never leaves the execution runtime.

The owner file and HAL service configuration must be protected by the approved
platform environment. Root administrative access can replace that environment;
these software locks do not protect against a trusted administrator rewriting it.
No user-device attestation is added.

## Attestation prerequisites

A quote's signature alone does not prove that the expected HAL software is running.
Management needs an approved image/boot measurement policy, and that boot chain must
actually authenticate the runtime, execution gateway and their configuration (for
example using measured, verified boot with an immutable/appraised runtime image).
The JSON `runtime_binding` declaration records that operator requirement; it cannot
create measured boot or prove an arbitrary mutable filesystem trustworthy.
The service never approves measurements just because the remote VM reports them.

Three verifier integrations are supported:

1. **Intel TDX and AMD SEV-SNP through Trustee:** `verifier: "trustee"` uses the
   private Trustee v0.22.0 Attestation Service. Management verifies the pinned
   ES256 signer, fresh EAR token, dedicated HAL policy, channel REPORT_DATA and
   approved platform measurements. SNP uses explicit minimum TCB components,
   not Intel's `UpToDate` label. See [TRUSTEE.md](TRUSTEE.md) for setup, supported
   SNP report/product limits and live acceptance requirements. Existing policies
   are not switched automatically.
2. **Direct Intel TDX:** `verifier: "intel-dcap"` invokes Intel's installed DCAP QVL in a
   bounded subprocess on management. Configure QPL/PCCS and current collateral
   there. Only `SGX_QL_QV_RESULT_OK` with unexpired collateral is accepted. This
   adapter decodes DCAP v4 / TDX 1.0 bodies; unsupported formats fail closed.
3. **Custom verifier:** `verifier: "external"` invokes a
   local, operator-selected verifier command. Its executable and supporting
   scripts/configuration must be hash-pinned. The adapter must validate the signed
   SNP report, the AMD endorsement chain, revocation/TCB and report format, then
   return the legacy adapter claims below. It remains available for reviewed
   custom backends. Trustee is the supplied integration for supported AMD SNP
   reports; its service and pinned report codec must be installed on management.

External verifier stdin:

```json
{"version":1,"evidence":{"platform":"amd-sev-snp","report_hex":"SIGNED_RAW_REPORT_HEX"}}
```

Required stdout, derived **only from successfully verified evidence**:

```json
{
  "verified": true,
  "platform": "amd-sev-snp",
  "evidence_sha256": "SHA256_OF_RAW_REPORT",
  "report_data": "128_LOWERCASE_HEX_CHARACTERS",
  "debug": false,
  "tcb_status": "UpToDate",
  "vmpl": 0,
  "measurements": {"measurement": "96_LOWERCASE_HEX_CHARACTERS"}
}
```

For TDX the measurement map instead contains `mrtd`, `rtmr0`, `rtmr1`, `rtmr2`,
`rtmr3`; VMPL is SNP-specific. The verifier must not echo expected values: they are
not supplied to it. Management independently compares its returned REPORTDATA and
measurements with the pending challenge and approved policy. A missing verifier,
unavailable collateral, malformed evidence or mismatch blocks deployment.

## Provision and activate

Run the administrative deployment command from management's provisioning environment,
or use an administrator's computer for the initial bootstrap. User credentials never
grant access to this provisioning command.

Create `state/tdx-attestation-policy.json` using your reviewed image measurements:

```json
{
  "version": 1,
  "platform": "intel-tdx",
  "runtime_binding": "approved-measured-boot",
  "lease_seconds": 10800,
  "verifier": "intel-dcap",
  "qvl_library": "/usr/lib/x86_64-linux-gnu/libsgx_dcap_quoteverify.so.1",
  "measurements": {
    "mrtd": "REPLACE_WITH_APPROVED_96_CHARACTER_HEX",
    "rtmr0": "REPLACE_WITH_APPROVED_96_CHARACTER_HEX",
    "rtmr1": "REPLACE_WITH_APPROVED_96_CHARACTER_HEX",
    "rtmr2": "REPLACE_WITH_APPROVED_96_CHARACTER_HEX",
    "rtmr3": "REPLACE_WITH_APPROVED_96_CHARACTER_HEX"
  }
}
```

These placeholders are deliberately invalid. Use the actual installed QVL path on
management. Do not use a current VM's unverified measurements as an automatic approval.

Create `state/portable-profile.json` (paths are relative to this file):

```json
{
  "version": 1,
  "platform": "intel-tdx",
  "managed_agent": "../dist/orchestration-agent.wasm",
  "attestation_policy": "tdx-attestation-policy.json",
  "agent_configuration": {}
}
```

Build the portable agent on a Rust build machine, or supply your own compatible
component. `build.py --agent-only --install-target` builds the two Wasm artifacts (use `orchestration-agent.wasm` here);
Windows API clients do not need a local native broker or Rust installation.

From the operator's PowerShell, with the same `$HalPython` used for the existing fleet:

```powershell
& $HalPython fleet.py deploy `
  --inventory state/fleet-inventory.json `
  --credentials state/fleet-tls `
  --ssh-key "$HOME/.ssh/id_ed25519" `
  --operator state/fleet-operator.json `
  --portable-profile state/portable-profile.json `
  --install-dependencies
```

This reuses a generated `state/fleet-tls/management-signing.json` across deployments,
provisions its public key to files/execution, copies the chosen agent only to
management, builds the generic runtime on execution and configures the new services.
It also installs/checks the fixed per-user gVisor runtime and runs real sandbox
acceptance tests. Management requires its capability in the fresh attestation
binding before provisioning the agent. Runtime configuration reports do not
replace verification of approved VM software measurements.
It does not install a vendor attestation verification stack or create an approved
measured-boot image. Configure those prerequisites first. HTTPS health checks only
show service readiness; Alice's first session exercises actual attestation.

User commands remain:

```powershell
& $HalPython fleet.py onboard --user alice --deployment state/fleet-tls/deployment.json --output state/alice.json --workloads all
& $HalPython fleet.py run --client state/alice.json --workload matrix-multiply --cache bypass
& $HalPython fleet.py run --client state/alice.json --workload matrix-multiply --cache reuse
& $HalPython fleet.py bench --client state/alice.json --workloads all --jobs 100 --concurrency 4 --cache reuse --output results/portable-agent
```

The updated client opens sessions through management automatically. After its first
verified session it records `require_attested_agent` and refuses a legacy downgrade.
Existing native comparison deployments remain an explicit legacy benchmark profile;
use a separate client configuration for that comparison. A new session recovers a
lost runtime by attesting and deploying again. Expired leases require opening a new
session; an already submitted job is never blindly replayed.

For a per-VM installation, `fleet.py configure-agent --config ... --profile ...`
preflights a role profile and `--apply` writes it. The automated installer supplies
these role profiles in `state/portable/profile.json` and restarts the services.

## Several execution VMs

The automated four-role inventory still provisions one execution VM. Management
can route to additional already-provisioned compatible VMs through
`execution_targets` in its `configure-agent` role profile. Each needs its own
HTTPS certificate and attestation policy, the same management signing public key,
its own persistent execution state and the same execution audience. On each extra
execution VM, set `execution_url` in its execution role profile to its own HTTPS URL.

Example additions to management's existing role profile (paths relative to that profile):

```json
{
  "execution_targets": [
    {"url": "https://EXECUTION_VM_1_IP", "attestation_policy": "tdx-policy-1.json"},
    {"url": "https://EXECUTION_VM_2_IP", "attestation_policy": "snp-policy-2.json"}
  ]
}
```

Apply with `fleet.py configure-agent --config state/fleet.json --profile
state/portable/profile.json --apply`, then restart management. Ordinary users
continue using the same management URL. Existing sessions keep their chosen VM;
new sessions prefer the target with fewer assigned users. A failed attestation or
unavailable target can be skipped during session setup. A submitted job is never
silently moved or retried on another VM. `execution_url` and `agent_identity` in
sessions/results identify the actual execution target.

## Mandatory agent audit trail

The native HAL launch and result-commit operations now persist signed audit
records before dispatch and acknowledgement. Management verifies and retains the
chain outside the execution VM. Workloads cannot write the audit trail or access
its signing key. The existing WIT signatures are unchanged; the runtime advertises
`audit_log: hal-agent-audit-v1`, which management requires before deployment.

Read the event flow, user commands, storage limits and recovery semantics in
[AUDIT.md](AUDIT.md). This is an identity-bound signed history, not continuous
hardware attestation. Legacy and native benchmark profiles remain separate.

## Migration and validation

An old `hal-managed-agent-v1` configuration must be migrated with
`deploy --portable-profile` or `configure-agent` before serving again. The new
runtime rejects the old agent world. Keep the existing management signing key,
user keys, TLS credentials and authorization database. Update the selected artifact
to `dist/orchestration-agent.wasm`; do not overwrite it with the legacy agent.
Rebuild the worker image too, because the native HAL changes apply there.

Run local implementation tests on a Mac/Linux build machine, not on Alice's
Windows API-only computer:

```sh
.venv/bin/python build.py --install-target
.venv/bin/python -B tests/run_architecture_checks.py
```

The shared-agent suite runs a real Wasm agent, real native user brokers and real
Wasm workloads over four local HTTP services. Hardware evidence and Docker are
explicit test fixtures. It checks ownership/restart, duplicate deployment, identity
certificates, encrypted channels, user signatures, policy changes, cache isolation,
concurrent users, HAL denial and target selection. It does not establish actual
TDX/SNP attestation or Docker containment on a cloud VM. Run the existing Docker
worker check and a real verified session on the target after deployment.

API changes: `/v2/agent/challenge`, `/deploy`, `/status`, `/activate`, `/enroll`,
and `/run` under the same `/v2/agent` prefix. All except challenge/deploy use the
attested encrypted channel. `/v2/access` on files issues scoped file credentials.
The public user API stays `onboard`, `run`, and `bench`.

## Management-controlled undeployment

Run these commands **on the management server**, from its repository directory,
using the service account (or `sudo`) that owns `state/fleet.json` and the
management signing key. Alice/Bob's client key and the publisher/operator key
cannot control agent deployment. Replace the URL with a configured target.

```sh
.venv/bin/python fleet.py agent-status --config state/fleet.json --execution-url https://192.0.2.30
.venv/bin/python fleet.py agent-undeploy --config state/fleet.json --execution-url https://192.0.2.30 --drain-seconds 30
.venv/bin/python fleet.py agent-status --config state/fleet.json --execution-url https://192.0.2.30
```

Undeployment follows this order:

1. Management durably disables new sessions and dispatch to that VM. The protected
   execution endpoint records the drain before forwarding it to the native runner.
2. The trusted Wasm agent stops admitting jobs. Native HAL also checks that state,
   including requests already waiting for an execution permit. Admitted jobs may
   finish; their result and audit checks remain mandatory.
3. Once jobs finish, the agent calls `stop-user-brokers()` through HAL. Every broker
   must exit successfully after removing its gVisor workers. A killed or failed
   broker is **not** treated as proof of successful cleanup. Compiled caches remain
   inside their worker isolation boundary and disappear with those workers.
4. The runtime appends the agent-signed `agent_drained` audit record. Management
   verifies and persists its checkpoint and waits for its outstanding job
   acknowledgements before authorizing retirement of that exact agent instance.
5. The execution service confirms the runner exited, removes its private tmpfs
   directory, and invalidates all agent channels. This removes runtime credential
   files; it is not a claim of forensic memory erasure. Durable audit records,
   approved artifacts, user identities and the permanent VM owner are retained.

`state: undeployed` is the successful result. The drain deadline is **0–60 seconds**
for waiting on jobs/acknowledgements; broker cleanup and runtime exit have separate
bounded waits. `state: draining` with `drain_timed_out: true` returns CLI exit code 2:
new work stays blocked, existing jobs are not killed or replayed, and undeployment
is incomplete. Run `agent-status`, then repeat **the same undeploy command** to
continue its existing retirement ID. A lost retirement response can also be
recovered this way, including after a management-service restart. This permission
to repeat an administrative retirement does **not** apply to workload submissions.

Audit persistence or cleanup failure leaves the target disabled. If the runtime
is already absent or a broker was killed, inspect service/container state; this
command cannot manufacture a clean-stop attestation or silently start a replacement.
No forced-cleanup or ownership-reset endpoint is exposed.

Only management can explicitly enable deployment again:

```sh
.venv/bin/python fleet.py agent-deploy --config state/fleet.json --execution-url https://192.0.2.30
```

This verifies the platform again before deploying, creates a new agent identity
and user sessions after a completed retirement, and starts with cold worker caches.
It never releases ownership to another management service. Ordinary user requests
cannot re-enable the target, even after service restart. With multiple targets,
management may open new sessions on other enabled, verified VMs; it does not retry
an already submitted job on another VM.

This feature uses `elastic:orchestration@1.1.0` and the
`drain-audit-retire-v1` capability. Rebuild the native runner, broker/worker image,
and `dist/orchestration-agent.wasm` together; review/update the pinned build and
attestation policy through the existing deployment procedure. Older agents/runners
are rejected rather than silently operating without drain support. The signed
checkpoint records trusted runtime cleanup observations, not independent hardware
attestation of each container or a cryptographic proof of workload correctness.

Local validation after building: `.venv/bin/python -B tests/test_agent_lifecycle.py`.
It runs real Wasm agents and native brokers with fixture hardware evidence and
in-process workers. The gVisor removal path still requires Linux acceptance testing
with the approved runtime and `tests/test_docker_workers.py`.
