# Agent security and cache update

**Signed user approvals:** [SIGNED_JOBS.md](SIGNED_JOBS.md) adds `--job-authorization`: immutable helper rules, user-held Ed25519 signing keys, exact-job binding, expiration and one-time execution checks repeated in the recipient container. Management forwards approvals and has no signing key. This is optional; the earlier token/allowlist profile described below remains available without that flag.

**Optional container boundary:** the new `--user-containers` mode gives each user a separate workload runtime and cache process inside Docker. The Wasm agent requests the container; the native broker authenticates the request and performs its creation. Follow [the container guide](containers/README.md) for that mode. The instructions and persistent-storage descriptions below cover the earlier in-process profile. Container mode uses volatile private storage and does not expose attestation devices.

The Wasm agent now has a policy to follow for each approved workload. The policy says which HAL interfaces the workload may call, how much work it may do, whether its compiled code may be cached, and what its result should look like. These new features are enabled by **`--agent-policy` in Wasm mode**. They build on the existing authenticated tenant isolation.

The agent is an actual `.wasm` component. It makes its cache decision and checks the returned result inside its sandbox. The native host performs the privileged work and checks the policy again. This second check matters: changing or breaking the Wasm agent must not give it permission to run another user's code or approve an invalid result.

These are benefits of this agent implementation, not a claim that native software cannot implement equivalent safeguards. The Wasm-specific architectural benefit is that the coordination code itself runs inside a separate, constrained sandbox. Wasm can interact with the host only through supplied imports; see [Wasmtime's security model](https://docs.wasmtime.dev/security.html).

## What changed

| Feature | What it does | Why it helps |
|---|---|---|
| Trusted workload policy | Matches the authenticated user, component filename and SHA-256 against an operator-owned allowlist | A job cannot choose its own permissions or replace the expected hash |
| Pinned agent | The policy contains the approved `agent.wasm` SHA-256; startup rejects a different file | Detects an accidental or unauthorized agent replacement when the policy remains trusted |
| Memory-only code cache | Retains verified, compiled code in the host's private user namespace; never reads or writes the persistent `.wasm` file cache | Avoids leaving downloaded workload files on disk in this profile |
| Cache expiry | A compiled entry expires after its configured lifetime; hits do not extend that lifetime | Limits how long prepared code is available for reuse |
| No-cache rule | A workload marked `disabled` always runs with bypass, even if the client requests reuse | The requesting client cannot relax the operator's retention rule |
| Per-workload HAL permissions | Enables only the chosen groups: crypto, random, clock or storage | A hashing workload can be denied storage and networking |
| Workload budgets | Sets memory, Wasm instruction fuel, execution deadline and maximum returned bytes for each workload | One workload can have tighter limits than another |
| Separate agent instances | Pools agent instances by authenticated user and workload hash | Different workload versions do not share an agent's Wasm memory |
| Worker recycling | Retires an agent instance after a configured number of jobs; errors discard it immediately | Bounds how long the coordinator's state survives |
| Result approval | The agent validates the output, then asks the host to commit its retained output after an independent check | An agent cannot replace output bytes or skip host validation |
| Decision trace | Returns policy hash, effective cache policy, result digest and ordered successful stages | Makes results easier to inspect and explain |

The five example workloads are unchanged. The current WIT version is **`elastic:job-agent@0.4.0`**, including the user-container imports; it affects the agent-to-host interface, not `elastic:hal/run@0.1.0`, which your workloads use.

## What happens when a job arrives

1. Management receives the case name and identifies the requesting user through their API token.
2. Management sends the workload's name, hash, size, job ID and requested cache mode using that user's execution token.
3. The execution host checks the token and both allowlists: the tenant policy and the agent workload policy. An unapproved workload is rejected before download or execution.
4. An agent instance for this user and workload receives the job and its constraints. It never receives the API tokens, file-server token, filesystem paths or arbitrary download URLs.
5. The Wasm agent chooses reuse or bypass. `cache: disabled` forces bypass. The host checks the choice before granting any preparation or execution operation.
6. For reuse, the host checks that user's compiled cache. An expired entry is a miss. If several jobs for the same user and workload arrive together, they can share one preparation.
7. On a miss, the host downloads the component from the configured file server, checks its exact size and SHA-256, and compiles the verified Wasm. The new profile never deserializes downloaded native machine code or writes a downloaded `.wasm` cache file.
8. The host creates a fresh workload Store, memory, HAL context and instance. It applies that workload's permitted HAL groups and resource budgets, then calls `run()`.
9. The output goes back into the Wasm agent. The agent checks its size and configured result rule.
10. The agent calls `commit-result`. The host checks its own retained result, records its digest, and marks the result committed. It does not accept replacement result bytes as an argument to this operation.
11. The agent returns the bytes. The host requires a successful commit and an exact match with the workload's output before returning success to management.
12. Management performs its existing catalog validation, stores the job's result and trace, and makes them available to the client.

This workflow still downloads **on demand**. It does not predict future jobs or download every workload at startup. It never caches a job's result to avoid executing that job: every accepted execution gets a fresh workload instance.

## What is private, and what is reused

| Item | Scope and lifetime |
|---|---|
| Agent Wasm memory | One user plus one workload hash; reused for at most `worker_max_jobs` successful jobs |
| Workload Wasm memory and globals | A fresh instance for every execution |
| Verified compiled code | User plus workload hash; held in native host memory until expiry, eviction or restart |
| Persistent workload data | User plus workload hash; available only when `storage` is granted |
| Job history and returned results | The user's management database |
| File-server credential | Native host only; never passed into the agent or workload |

The native host owns the compiled code cache. It is not placed inside the agent's linear memory. A fresh workload instance does not automatically create a private disk cache; the host's namespace checks provide that separation.

Two jobs for the same user and same workload version may share persistent application data if `storage` is permitted. Different users and different workload hashes use different storage directories. Restarting the host clears the new compiled cache but keeps that application data. Do not delete the entire `--cache-dir` to clear code: it also contains application storage.

The previous disk cache is not read by this profile. Existing files are not automatically deleted or migrated. A new state directory gives the profile its own storage tree; use the same new directory on later restarts if its application data should persist.

Expiry is measured with a monotonic clock starting when compilation finishes. Cache lookups remove expired entries immediately; a background sweep runs about once per second. A job that already acquired a component may finish using it after expiry. Expiry is a retention rule, not an emergency cancellation mechanism or secure memory erasure.

The tenant policy's `compiled_cache_entries` bounds cached entries. In this profile, `cache_bytes` also bounds their combined original artifact sizes. This is **not a hard bound on total native process memory**: compiled machine code, active jobs, the compiler and agent instances use additional memory. The global idle agent pool is limited to `max_inflight` instances. An evicted component can remain alive while an active job uses it.

## Build and configure

These steps assume the existing three-VM layout and already built workload files. They do not reinstall the OS, change TDX configuration, implement attestation or modify old benchmark results.

### 1. Build on the execution VM

Update the source folder, then build **both** artifacts:

```bash
cd ~/hal-on-demand
python3 build.py --install-target
```

Do not use `--host-only` for this update. Agents built against WIT 0.1.0 or 0.2.0 cannot be loaded by the new host. The new `dist/agent.wasm` is portable; `dist/hal-on-demand` must be built for the execution VM's OS and architecture.

### 2. Prepare credentials, if tenant bundles do not exist yet

On a trusted setup machine, with the correct `workloads.json`:

```bash
cd ~/hal-on-demand
python3 configure_tenants.py \
  --catalog workloads.json \
  --tenant alice \
  --tenant bob \
  --output state/agent-tenant-bundles
```

The output directory must be new. If you already have working tenant bundles, keep them and skip this step. The generated folders have different purposes:

| Generated folder | Destination |
|---|---|
| `execution/` | Execution VM: `~/hal-on-demand/state/tenant-config/` |
| `management/` | Management VM: `~/hal-on-demand/state/tenant-config/` |
| `file-server/` | File-server VM: `~/hal-on-demand/state/tenant-config/` |
| `clients/alice.token` | Alice's client machine only |
| `clients/bob.token` | Bob's client machine only |

Copy these folders through your existing secure file-transfer method. Keep directories private (`700`) and token files private (`600`). The file-server token in the execution bundle must match the file-server bundle. The management worker tokens must match the execution user tokens. Do not generate separate bundles independently on each VM.

### 3. Generate and review the agent policy on the execution VM

After the execution bundle has been copied and the agent has been built:

```bash
cd ~/hal-on-demand
python3 configure_agent.py \
  --tenant-policy state/tenant-config/policy.json \
  --catalog workloads.json \
  --agent dist/agent.wasm \
  --cache memory \
  --cache-ttl-seconds 300 \
  --output state/tenant-config/agent-policy.json
```

The helper creates a new file and refuses to overwrite an existing one. It copies expected result rules from the catalog, checks the catalog against the tenant artifact allowlist, and pins the newly built agent's hash. It recognizes the five existing benchmark cases; for additional workloads, write an explicit reviewed policy instead of guessing their permissions.

Default grants are `crypto` for the two hash workloads, `random` for random bytes, no optional HAL groups for platform information, and `clock` for the clock workload. Storage is denied to all five examples because they do not need it.

A workload entry looks like this; the helper fills in the real hashes:

```json
{
  "tenant": "alice",
  "component": "function3.wasm",
  "sha256": "<the approved function3 SHA-256>",
  "cache": "memory",
  "cache_ttl_ms": 300000,
  "hal_permissions": [],
  "memory_mib": 64,
  "fuel": 1000000000,
  "execution_timeout_ms": 5000,
  "max_output_bytes": 4096,
  "worker_max_jobs": 128,
  "validation": {"kind": "utf8_contains", "value": "IntelTdx|"}
}
```

Use `cache: disabled` to prohibit retaining that workload's code. Set `worker_max_jobs: 1` to instantiate a fresh agent for each job. This can cost more time; compiled workload reuse is controlled separately. Memory is a **per-Wasm-memory** limit, with the existing maximum of eight memories per workload Store. Fuel counts Wasm instructions; it does not measure CPU time spent inside native HAL functions. The execution deadline covers instantiation and execution after HAL initialization, not downloads or compilation; the outer host job deadline still covers the job pipeline.

Workload budgets may only narrow the host command-line limits. Unknown policy fields, invalid permissions, duplicate user/hash rules and excessive budgets are rejected at startup. Result rules support exact hex bytes, exact length, required UTF-8 text, a clock JSON shape, and `bounded` for size-only checks. Use a stronger rule when the result is predictable. A clock shape check does not prove the clock is trusted or fresh.

Policies load at startup. After reviewing a policy or credential change, stop the old host and restart it; editing a file does not hot-revoke running jobs. After rebuilding the agent, review and generate a new policy file containing its new digest. Never silently accept a digest mismatch.

### 4. Start the file server on its VM

Assuming the workload files are in `~/hal-on-demand/tests/workloads`:

```bash
cd ~/hal-on-demand
python3 server/file_server.py \
  --directory "$PWD/tests/workloads" \
  --bind 0.0.0.0 --port 8000 \
  --token-file "$PWD/state/tenant-config/file.token"
```

Use your real workload directory if different. An unauthenticated browser request now returns `401`; that is expected. The execution host supplies the file-server token.

### 5. Start the agent host on the TDX VM

```bash
cd ~/hal-on-demand
sudo env RAYON_NUM_THREADS=4 ./dist/hal-on-demand \
  --mode wasm --transport http \
  --agent "$PWD/dist/agent.wasm" \
  --listen 0.0.0.0:9100 \
  --token-file "$PWD/state/tenant-config/operator.token" \
  --tenant-policy "$PWD/state/tenant-config/policy.json" \
  --agent-policy "$PWD/state/tenant-config/agent-policy.json" \
  --file-server http://192.0.2.20:8000/ \
  --file-token-file "$PWD/state/tenant-config/file.token" \
  --cache-dir "$PWD/state/agent-secure" \
  --downloads 4 --compilers 3 --executions 7 --max-inflight 16
```

The port must match the file server. This command uses your existing benchmark topology. HTTP bearer tokens are not encrypted in transit: use a protected network/tunnel or an HTTPS reverse proxy for deployments where the network is not trusted. This update does not add TLS termination. Restrict access to the relevant VM addresses.

Wait for `status: ready`. Check that the configuration reports `agent_policy_enabled: true`, `code_cache_storage: memory-only` and `execution_mode: wasm`. Leave the process running.

### 6. Start management on the management VM

```bash
cd ~/hal-on-demand
python3 server/management.py \
  --bind 0.0.0.0 --port 9000 \
  --worker-url http://192.0.2.30:9100 \
  --catalog "$PWD/state/tenant-config/workloads.json" \
  --api-token-file "$PWD/state/tenant-config/api.token" \
  --agent-token-file "$PWD/state/tenant-config/worker.token" \
  --tenant-policy "$PWD/state/tenant-config/policy.json" \
  --state-dir "$PWD/state/management-agent-secure" \
  --dispatchers 2 --queue-size 128 --max-history 100000
```

Use the management bundle here, not the execution bundle. Operator tokens are for administrative statistics; submit jobs with a user's API token. The management server receives the policy decisions in each result; it does not choose the execution host's permissions.

### 7. Submit and benchmark from the management VM

In a second terminal, use Alice's client token copied to `state/alice-client.token`:

```bash
cd ~/hal-on-demand
python3 jobs.py \
  --url http://127.0.0.1:9000 \
  --token-file "$PWD/state/alice-client.token" \
  submit --case platform --cache reuse --wait
```

Submit it again. Expect `miss` followed by `hit` before expiry, `agent_result_validation: passed`, the applied `agent_security` settings, and a trace ending in `result_committed`. `preparation.stored: false` means no disk cache file was saved; a compiled in-memory entry may still be retained.

For 1,000 jobs with code reuse:

```bash
python3 jobs.py \
  --url http://127.0.0.1:9000 \
  --token-file "$PWD/state/alice-client.token" \
  bench --jobs 1000 --concurrency 2 --cache reuse --expect-mode wasm \
  --output "results/secure-agent-reuse-1000-$(date -u +%Y%m%dT%H%M%SZ)"
```

For 1,000 jobs that must download and compile on every execution:

```bash
python3 jobs.py \
  --url http://127.0.0.1:9000 \
  --token-file "$PWD/state/alice-client.token" \
  bench --jobs 1000 --concurrency 2 --cache bypass --expect-mode wasm \
  --output "results/secure-agent-bypass-1000-$(date -u +%Y%m%dT%H%M%SZ)"
```

The default tenant limit is four active jobs, so start at concurrency two. Raise that user's policy limit deliberately before testing higher concurrency. For a cold-cache reuse trial, restart the execution host first and use a new output directory. An earlier smoke test has already warmed its workload. For a warm-cache trial, keep the host running and record the hit/miss counts and expiry setting. Bypass neither reads nor replaces an existing cached entry; it does not require deleting the cache.

Compare repeated trials with the same security policy, concurrency, workload mix, compiler settings and cache mode. Record success rate, end-to-end latency, preparation time, execution time, throughput and memory. These safeguards do not imply a 50% performance improvement. Memory-cache hits save preparation work; extra policy checks and stricter recycling have their own costs.

## Boundaries that still matter

Platform information remains available. HAL network sockets, inter-workload messaging, GPU, resource allocation and events remain denied in this profile. HAL clock reads may be granted; blocking HAL sleep is denied. HAL crypto input and random-output buffers have a one-MiB bound. WASI clock/random calls now require the corresponding workload permission; managed workloads cannot subscribe to WASI timers. Optional finer permissions are described in [WORKLOAD_ACCESS.md](WORKLOAD_ACCESS.md). Guests receive no inherited filesystem directories, environment, stdio or network permissions.

Storage, when explicitly granted, uses the existing private user/workload directories and quotas. It is not encrypted on disk by this update. Memory-only caching avoids ordinary cache files; it does not promise that OS swap, crash dumps or a privileged administrator can never expose memory. The native host, kernel, operator policy files and runtime remain trusted.

Policy hashes, agent hashes and result digests support reproducibility and inspection. They are not signed attestation evidence. The decision trace is included in the ordinary management result; it is not a tamper-proof audit log. `attestation_verified` remains `false`, as requested. Result checks do not roll back storage writes or other effects that occurred before validation failed.

## Local verification

After building, run:

```bash
python3 -B tests/validate_agent.py \
  --output "validation/agent-security-$(date -u +%Y%m%dT%H%M%SZ)"
```

This runs the existing regression suites, agent policy and private worker integration tests, and Rust host enforcement tests. It starts temporary services on localhost and private Unix sockets, and uses real `agent.wasm` and the five workload components with a synthetic HAL. It saves logs and binary hashes. It does not connect to your cloud VMs or test Docker isolation or TDX hardware/attestation.

The suite checks expiry, private caches, worker recycling, denied HAL calls,
output rejection, quotas and policy/agent mismatches. Rust tests exercise host
imports independently of the agent's own checks. Run the tests against the build
you intend to deploy and preserve the new report locally. These software checks
are not a security audit or a TDX performance result.
