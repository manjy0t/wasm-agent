# Audited native baseline and separate benchmark experiments

Use [START_HERE.md](START_HERE.md) for service prerequisites and
[benchmarks/README.md](benchmarks/README.md) for benchmark commands.

Keep the implementations in one repository. Their startup paths remain different:
the managed Wasm agent requests native broker creation through its HAL imports;
the native execution service starts the native brokers directly. Shared source
keeps workload definitions, authorization checks, collection and timing rules
reviewable together. Separate repositories would not isolate VM state or results.

## What changes

The new native profile is `hal-native-audited-v1`. It adds signed, persistent
execution events and management-side collection. The existing agent profile is
`hal-managed-agent-v2`. Historical, unaudited native results remain historical;
the new benchmark runner refuses to put legacy service responses into a new run.

| Property | Audited native | Managed agent |
|---|---|---|
| Broker creation | Native execution service / native host | Wasm agent requests creation through native HAL |
| Workload code reuse | Forbidden; download and prepare each request | `bypass` or `reuse`, recorded per batch |
| Workload instance | Fresh for each request | Fresh for each request, including cache hits |
| Local audit writer | Native Python execution gateway | Native Rust journal used by the agent HAL |
| Local persistence | SQLite WAL, `synchronous=FULL` | Append journal, `sync_all` |
| Local audit signature | Separate native service identity | Agent identity |
| Management collector | Signed-chain verification and durable SQLite commit | Same collector and durable SQLite commit |
| Success acknowledgement | Only after completion record is collected and checked | Same requirement |
| Isolation | In-process Wasm workload in the user's native broker | Per-user gVisor worker container |
| Attestation | No new attestation claim; `false` | Existing management verification remains required |

This compares full setups with auditing in both. It does **not** make their
isolation, authorization implementation, attestation or audit-writing overhead
identical. Do not describe the resulting difference as the cost of the agent alone.

## Native request and audit flow

1. The client signs its job. Management checks the current grant and admits the
   job once; the execution gateway independently checks authorization and replay.
2. Management first collects any outstanding native audit records, then persists
   `job_dispatch_requested` in its own signed journal.
3. The execution gateway persists a signed `job_accepted` record **before** calling
   the user's native broker. The gateway's audit key never goes into the broker.
4. The existing native broker downloads and prepares the workload, runs a fresh
   instance and returns its result. Native reuse is rejected by client, gateway
   and the existing Rust host. No native cache is opened or populated.
5. The gateway persists `result_committed`, including the result digest, job ID,
   user, artifact, rule digest, revision, outcome and cache status. It then signs
   the response with a reference to that record.
6. Management verifies the signed response, fetches the audit chain, verifies
   sequence numbers, hashes, signer, job scope and output digest, and commits the
   collected records. It persists `job_acknowledged` before returning success.
7. The client checks the receipt, execution profile and actual output. A failure
   or lost acknowledgement stays failed/unknown. No automatic job retry occurs.

The new native state directory holds `state.sqlite3` and its WAL, signed audit
events, collection checkpoints, replay records, results and benchmark leases.
Each broker has a separate directory and `broker.log`. Rejections are also stored
in the gateway's `audit_gateway` table. Audit events use allowlisted fields:
private keys, file tokens, request bodies and raw workload output are not logged.
Existing result storage still contains the requested output for the user.

Both writers fail closed when persistence is unavailable or full. There is no
automatic truncation of audit history to make a benchmark succeed. Back up the
SQLite database with its supported backup mechanism, or stop the service before
copying it; copying only a live database file can omit WAL records.

## Protecting experiment identity

- Every experiment and batch has a fresh UUID. Existing output directories cannot
  be reused or overwritten. Job IDs are unique and checked across the entire matrix.
- A management lease reserves the service for one experiment, across clients and
  users. Competing run/session requests and policy/deployment changes through that
  management service are blocked. An interrupted lease lasts at most six hours.
- A common `/run/hal-fleet-execution-profile.lock` prevents updated native and
  agent fleet services from running together on the same VM, even with different
  state directories. It is an operational guard, not protection against an admin
  starting unrelated binaries or old versions outside the managed services.
- Each state database is bound to its role and execution profile. Native setup
  creates fresh state and uses distinct service signing identities. It does not
  edit the agent configuration, replace user keys, or delete earlier state/results.
- The experiment pins workload hashes and rules, user/grant revision and limits,
  execution identity, host and service build hashes, management process identity,
  settings and actual runtime configuration. A change stops further submissions;
  already submitted jobs are drained and recorded. Session expiry/epoch changes
  are recorded separately; a runtime identity/build change cannot pass as renewal.
- `startup`, `warmup` and `measured` are explicit phases. Reuse warm-ups have their
  own directories. Their results are not counted in the measured throughput.
- Each finished batch has `integrity.json`, with hashes of `config.json`,
  `jobs.jsonl` and `summary.json`. `experiment.json` lists its batches and final
  state. Missing completion files, invalid rows or changed files cannot pass
  `benchmark-verify`. These file hashes detect accidental changes; they are not a
  signature against someone who can rewrite the entire result directory.

These safeguards prevent accidental mixing and detect the recorded changes.
They do not guarantee different numerical results, eliminate CPU/network noise,
or isolate an experiment from an administrator changing the machine out of band.
Use an otherwise idle VM and preserve every attempt, including failures. Do not
merge repeated copies of a batch into an analysis; batch UUIDs identify duplicates.

## Configure native services once

Update the code on **both** management and execution VMs before running the new
benchmarks. The client checks for the new benchmark protocol and build metadata.
Keep the original configurations and service state. The commands below are setup
instructions; running a benchmark does not deploy or switch services for you.

On the management VM, create a new native management key. On the execution VM,
create a new native audit key. Use the Python executable from your signing venv:

```sh
# Management VM
umask 077
.venv/bin/python fleet.py audit-key --output state/native-credentials/management-key.json

# Execution VM
umask 077
sudo .venv/bin/python fleet.py audit-key --output state/native-credentials/native-key.json
```

Copy only the native **public** key shown by the second command to management.
On management, certify that public key:

```sh
.venv/bin/python fleet.py native-audit-certificate \
  --management-key state/native-credentials/management-key.json \
  --native-public-key NATIVE_PUBLIC_KEY_HEX \
  --output state/native-credentials/native-certificate.json
```

The certificate is an operator-managed service identity, not a TDX quote. Its
default lifetime is 30 days. Transfer this public certificate to the execution VM
at the same relative path; keep its file permissions at `0600`. On execution,
the copied certificate and profile must belong to root, matching the execution
service and the key created with `sudo`. On management they belong to the
management service user. Do not transfer
either private key. The native `vm_id` is the audit stream's deployment identity,
not a hardware measurement.

Create `state/native-credentials/execution-profile.json` on execution:

```json
{
  "version": 1,
  "role": "execution",
  "native_key": "native-key.json",
  "native_certificate": "native-certificate.json",
  "management_public_key": "NATIVE_MANAGEMENT_PUBLIC_KEY_HEX"
}
```

Create `state/native-credentials/management-profile.json` on management:

```json
{
  "version": 1,
  "role": "management",
  "management_key": "management-key.json",
  "native_certificate": "native-certificate.json"
}
```

The profile files must also be private (`0600`). Generate separate configurations:

```sh
# Execution VM: uses the existing native binary path and reviewed runtime settings
sudo .venv/bin/python fleet.py configure-native-audit --config state/fleet.json \
  --profile state/native-credentials/execution-profile.json --output state/native/execution.json

# Management VM
.venv/bin/python fleet.py configure-native-audit --config state/fleet.json \
  --profile state/native-credentials/management-profile.json --output state/native/management.json
```

The new state directories are `state/native/execution-state` and
`state/native/management-state`. Source/build changes require review and new pins;
do not silently edit them during an experiment.

The Files service must authorize the new native management public key for scoped
artifact credentials. Use its existing `configure-agent` **files-role** profile:
keep the existing trusted management public keys and add the native management
public key to `trusted_management_keys`. Keep `protected_artifacts` enabled.
This changes artifact-service trust; it does not deploy a Wasm agent for native.

Stop/drain the existing management and execution services before switching.
For switching from management with a single command, use the one-time selector
setup in [MODE_SELECTION.md](MODE_SELECTION.md) instead of the standalone units
below. Both approaches use these same separate profiles and audit stores.

For standalone operation, start only one configuration on each VM. Generate
separate systemd units; this
also gives the management service permission to bind HTTPS port 443 without
changing the owner of its private key:

```sh
# Execution VM
sudo .venv/bin/python fleet.py unit --config state/native/execution.json > /tmp/hal-native-execution.service
sudo install -m 0644 /tmp/hal-native-execution.service /etc/systemd/system/hal-native-execution.service
sudo systemctl daemon-reload
sudo systemctl start hal-native-execution.service

# Management VM
.venv/bin/python fleet.py unit --config state/native/management.json > /tmp/hal-native-management.service
sudo install -m 0644 /tmp/hal-native-management.service /etc/systemd/system/hal-native-management.service
sudo systemctl daemon-reload
sudo systemctl start hal-native-management.service
```

Use distinct unit names and enable only the selected profile. Keep
the agent's original units/configuration to switch back. Do not use Docker prune,
delete audit databases, or copy native state over agent state.

The native baseline still refuses workloads with explicit access profiles it
does not implement. Choose the same supported workload artifacts and validation
rules for both setups; this audit change does not claim permission equivalence.

## Windows benchmark commands

These use your existing `$HalPython` and `$HalCases` variables. Create two client
profile files from the same existing user identity **once**, on the user's own
computer. The original client file and key are preserved; the new copies are
pinned to their intended execution architecture.

```powershell
& $HalPython fleet.py client-profile --client state/alice.json --mode native --output state/alice-native-audited.json
& $HalPython fleet.py client-profile --client state/alice.json --mode wasm --output state/alice-agent-audited.json

# On management: select native mode (or start the standalone native services).
$NativeResults = "results/native-audited-$([guid]::NewGuid().ToString())"
& $HalPython benchmarks/run_matrix.py --client state/alice-native-audited.json --workloads $HalCases --jobs 100 --repeats 3 --concurrencies 1,2,4 --expect-mode native --expect-isolation in-process --output $NativeResults
if ($LASTEXITCODE -ne 0) { throw "Native experiment failed; preserve the directory and inspect its records." }
& $HalPython fleet.py benchmark-verify --output "$NativeResults/r1-bypass-q1"

# On management: select agent mode and wait for ready before this block.
$AgentResults = "results/agent-audited-$([guid]::NewGuid().ToString())"
& $HalPython benchmarks/run_matrix.py --client state/alice-agent-audited.json --workloads $HalCases --jobs 100 --repeats 3 --concurrencies 1,2,4 --expect-mode wasm --expect-isolation per-user-container --output $AgentResults
if ($LASTEXITCODE -ne 0) { throw "Agent experiment failed; preserve the directory and inspect its records." }
& $HalPython fleet.py benchmark-verify --output "$AgentResults/r1-reuse-q1"
```

Native matrices contain only bypass batches. Agent matrices contain bypass and
reuse batches; select the agent's `reuse` **measured** batches for the requested
full-setup comparison. Verify every selected batch, not just the examples above.
Never combine the new audited native batches with the older native baseline.

To record a separate startup check, use `fleet.py bench ... --phase startup` and
a new output directory. If a client is interrupted, wait for outstanding jobs to
finish, then release its lease using the ID in `experiment.json`:

```powershell
& $HalPython fleet.py benchmark-release --client state/alice-native-audited.json --experiment-id EXPERIMENT_UUID
& $HalPython fleet.py audit --client state/alice-native-audited.json --limit 50
```

Do not resume or resubmit the interrupted experiment. Start a fresh UUID/directory.

## Timing and fair interpretation

The host timer still measures native broker work. Native audit persistence,
collection, proof checking and management logging occur before management returns
success, so they are included in management and client latency. Client timing ends
before local output/receipt validation. Batch wall time includes that validation,
job-record writes and final job-file synchronization, plus any session renewals.
Initial setup, benchmark lease acquisition, warm-ups and final summary/manifest
generation are outside the measured batch. Jobs/s is validated completed jobs
divided by batch wall seconds. Nested host, management and client timers are
reported separately and are not added together.

Run both profiles on matched hardware and client/network paths. Record CPU,
memory and concurrency constraints: the native broker does not gain a gVisor CPU
quota merely because the configuration contains container settings. Alternate
whole native and agent experiments to expose time-related drift. Report all
repeats, failures, cache misses and session renewals. Adding audit collection makes
this comparison closer; it does not remove the remaining architectural differences.

## Validation

Offline checks use real keys, signatures, authorization, protected artifact
grants, SQLite persistence and result validation with an injected broker:

```sh
.venv/bin/python -B tests/test_native_audit.py
.venv/bin/python -B tests/test_benchmark_guard.py
.venv/bin/python -B tests/test_benchmark_matrix.py
.venv/bin/python -B tests/test_benchmark_sessions.py
.venv/bin/python -B tests/test_mode_selection.py
.venv/bin/python -B tests/test_audit.py
```

After building locally, `tests/test_native_audit_live.py` exercises real HTTP and
the real Rust native host using temporary state. It requires permission to bind
loopback sockets. Existing native cache/limit checks remain in
`tests/test_native_baseline.py`; agent acceptance remains in
`tests/test_portable_agent.py` and the hardware deployment checks. No benchmark
performance numbers should be inferred from the offline tests.
