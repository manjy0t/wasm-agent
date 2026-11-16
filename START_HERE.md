# Start here

This checkout contains reusable source and individual administration commands.
It does not provision cloud VMs or carry over another installation's keys,
policies, clients or benchmark results.

## 1. Build and test on a development machine

Follow the build commands in [README.md](README.md), then
[TESTING.md](TESTING.md). This checks the implementation using temporary local
services and fixture evidence. A local test pass is not TEE attestation.

## 2. Prepare service machines

Use four service roles: identity, files, management and execution. Configure their
addresses, HTTPS certificates and network access using [FLEET.md](FLEET.md).
Only the execution role runs workload brokers. Native binaries must be built
for its CPU/OS. The agent profile also needs Linux, Docker and the approved
gVisor runtime described in [GVISOR.md](GVISOR.md).

Keep private files owned by the account that runs their service. The execution
service uses root for its privileged worker launcher; other services use their
dedicated service account. Never resolve a permissions error by making keys or
state world-writable.

## 3. Configure and activate the agent

Prepare a reviewed attestation policy for the execution VM and install its
verifier on management. Follow [TRUSTEE.md](TRUSTEE.md) for the Trustee adapter
or the direct-verifier requirements in [PORTABLE_AGENT.md](PORTABLE_AGENT.md).
Example policy measurements are deliberately invalid placeholders.

Configure the native execution base, protected file service and management-owned
agent artifact as described in [PORTABLE_AGENT.md](PORTABLE_AGENT.md). Then use
the management account to inspect and activate the configured target:

```sh
.venv/bin/python fleet.py agent-status \
  --config state/fleet.json --execution-url https://EXECUTION_VM

.venv/bin/python fleet.py agent-deploy \
  --config state/fleet.json --execution-url https://EXECUTION_VM
```

Replace `EXECUTION_VM` with the configured HTTPS address. Deployment requires
successful verification and available lifecycle state. An unfinished drain or
ownership conflict is an error to investigate, not a state file to delete.

## 4. Publish workloads and enroll a user

The operator publishes artifacts and their rules. Users register with identity,
obtain a signed grant and enroll it with management. Use the publication and
onboarding commands in [FLEET.md](FLEET.md). Original HAL-call fixtures and the
15 computational workloads are different workload sets; see
[benchmarks/README.md](benchmarks/README.md).

## 5. Run jobs and benchmarks

Use the enrolled client for the active profile:

```sh
.venv/bin/python fleet.py run \
  --client state/alice-agent.json --workload matrix-multiply --cache reuse
```

Run the matrix commands in [benchmarks/README.md](benchmarks/README.md). Keep each
attempt in a new results directory. Start with a single job before committing
to a long benchmark. Changing the client profile does not change the server mode.

## 6. Configure native mode separately when needed

Follow [NATIVE_AUDIT_BENCHMARKS.md](NATIVE_AUDIT_BENCHMARKS.md) for separate native
identities, certificates, service configurations and durable audit state. Native
mode executes Wasm workloads in native brokers, uses no worker containers and
forbids code-cache reuse. Its session does not claim verified agent attestation.

For controlled switching on a shared execution VM, configure the optional
[mode selector](MODE_SELECTION.md) only after both profiles are prepared.
Complete outstanding jobs, benchmark reservations and agent retirement before
switching. Keep the old audit records and result directories.
