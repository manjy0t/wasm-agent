# First HTTP test without a Wasm agent

Use this updated package. Earlier copies did not have `--mode native`, `--transport http`, or management `--worker-url`.

There are three VMs. The benchmark client can run in a second terminal on the management VM.

```text
Client --HTTP job request--> Management VM
                                 |
                                 | HTTP: filename, expected SHA-256, size
                                 v
                         TDX execution VM
                                 |
                                 +-- HTTP download from file-server VM
                                 +-- verify bytes
                                 +-- compile with Wasmtime
                                 +-- execute workload through the HAL
                                 +-- return result to management
```

In this case the execution program does not open, compile, or instantiate `agent.wasm`. The management server still needs an execution endpoint on the TDX VM: it cannot execute a remote workload by serving HTTP on its own. That endpoint is the native `hal-on-demand` program using the HAL runtime library. The requested workload is still a Wasm component.

Nothing is prefetched. Every `bypass` job downloads and compiles its workload after the request arrives. The native process and engine remain running. This is a new management-driven baseline, not the old experiment that launched a new runtime process for each sample. There is no attestation exchange.

## 1. Copy and extract the updated package

The current source archive is `hal-on-demand-native-uncached-source.tar.gz`. On the execution VM, extract it into a new directory so existing state and results stay separate:

```bash
cd ~
mkdir -p hal-native-uncached
tar -xzf hal-on-demand-native-uncached-source.tar.gz -C hal-native-uncached
cd ~/hal-native-uncached/hal-on-demand
```

The archive does not contain a native executable. Build it on the execution VM in step 4. It contains the five portable workload components. It excludes tokens, state and benchmark results. The commands below use `~/hal-on-demand` as the project directory: substitute your extracted project path if it differs. Management and file-server code have not changed in this update, so their existing installations can stay in use.

Use the actual reachable private IPs of your VMs in the commands below:

| Variable | Example only | Machine |
|---|---|---|
| `FILE_IP` | `10.0.0.20` | File server |
| `EXEC_IP` | `10.0.0.30` | TDX execution VM |
| `MANAGEMENT_IP` | `10.0.0.10` | Management server |

Allow file-server TCP port 8000 from the execution VM, execution TCP port 9100 from the management VM, and management TCP port 9000 from the client. The application protocol on all three connections in this guide is HTTP. Use a controlled private network; these example listeners do not terminate TLS. Keep the same network placement for the later agent comparison.

## 2. Create matching credentials

On the management VM:

```bash
cd ~/hal-on-demand
python3 init_state.py
ls -l state/api.token state/agent.token
```

The paths contain `/`, not `?`. The initializer keeps existing tokens. `api.token` authorizes the client to management. The file named `agent.token` is the existing shared credential for management to execution; that filename does not enable an agent.

Copy only the execution credential to the execution VM. Replace the IP and SSH username:

```bash
EXEC_IP=10.0.0.30
VM_USER=your_vm_login
ssh "$VM_USER@$EXEC_IP" 'mkdir -p ~/hal-on-demand/state && chmod 700 ~/hal-on-demand/state'
scp state/agent.token "$VM_USER@$EXEC_IP:hal-on-demand/state/agent.token"
ssh "$VM_USER@$EXEC_IP" 'chmod 600 ~/hal-on-demand/state/agent.token'
```

The management and execution copies must be identical. Do not generate unrelated credentials independently on both machines. If the client runs on a fourth VM, securely copy management's `api.token` to that client as well.

## 3. Start the file server on the file-server VM

```bash
cd ~/hal-on-demand
FILE_IP=10.0.0.20
EXEC_IP=10.0.0.30

python3 server/file_server.py \
  --directory tests/workloads \
  --bind "$FILE_IP" --port 8000 \
  --allow-client "$EXEC_IP"
```

Leave it running. This process only serves the workload files. It does not run them. If traffic passes through NAT, the allow-list must match the source address the server sees.

## 4. Build and start direct execution on the TDX VM

Rust/rustup and the VM's TDX kernel/device setup are assumed to be installed already. If build libraries are missing, install these:

```bash
sudo apt-get update
sudo apt-get install -y build-essential pkg-config cmake libssl-dev libtss2-dev python3
```

Build the updated native program:

```bash
cd ~/hal-on-demand
python3 build.py --host-only
./dist/hal-on-demand --help
```

`--host-only` does not compile the Wasm agent or require its Rust Wasm target. The executable includes the HAL runtime and Wasmtime.

Start the HTTP execution endpoint:

```bash
FILE_IP=10.0.0.20
EXEC_IP=10.0.0.30

sudo env RAYON_NUM_THREADS=4 ./dist/hal-on-demand \
  --mode native \
  --transport http \
  --listen "$EXEC_IP:9100" \
  --token-file "$PWD/state/agent.token" \
  --file-server "http://$FILE_IP:8000/" \
  --cache-dir "$PWD/state/native-storage-01" \
  --downloads 4 \
  --compilers 2 \
  --compiler-threads 4 \
  --executions 4 \
  --max-inflight 16 \
  --compile-opt-level speed \
  --execution-timeout-secs 5 \
  --job-timeout-secs 120 \
  --workload-memory-mib 64 \
  --workload-fuel 1000000000 \
  --max-output-bytes 4096
```

Wait for `status: ready`. The startup JSON must show `execution_mode: native`, `agent_kind: none`, `agent_sha256: null`, and `transport: http`. On the TDX VM the detected platform should identify Intel TDX. Do not add `--allow-non-tee`; that option is only for development software tests.

The current no-agent profile is `native-optimized-uncached-v1`. It accepts only `--cache bypass` jobs. It downloads and compiles each application independently. The service reuses its Wasmtime engine, linker and HTTP connections. Each execution creates and then drops its own Store, HAL context and workload instance. Multiple jobs can proceed together within the configured limits.

The configuration must report `runtime_reused: true`, `workload_instance_reused: false`, `code_cache_storage: disabled`, `execution_limits_enabled: true`, and the download/compiler/execution limits you selected. Only `compiled-cache-entries` and `disk-cache-bytes` are inactive in native mode. No native request can use cached workload bytes, reuse compiled workload code, or wait on another job's preparation instead of doing its own.

Fuel, per-memory growth limits, runtime table/instance limits, execution and job deadlines, and output limits remain active. Downloads have size/time limits and every workload's bytes must match the expected digest and size. These limits do not replace OS process/container isolation or cap every allocation in a native host library. A compilation already running can finish after its request times out; its compiler slot remains occupied until the work actually ends.

`--compiler-threads 4` gives workload compilation a dedicated pool of four threads shared by the two compilation slots. It is a total thread budget, not four threads per job. This setting takes precedence over the legacy global Rayon pool for workload compilation. Match these settings on the agent side for a controlled comparison; the update does not change your running agent configuration.

The commands in this guide are the existing single-user setup. For multiple users, retain the matching `--tenant-policy` files on management and execution using `configure_tenants.py --help` and the local test examples in `tests/test_tenants.py`. Identity comes from an authenticated credential, not a client-supplied username. That policy scopes permitted artifacts, admission and storage by user and workload hash. Do not pass `--agent-policy`, `--user-containers` or `--job-authorization` to native mode: those profiles remain on the agent side.

`--cache-dir` is retained as the application-state directory name when `--tenant-policy` is enabled. This mode does not read, overwrite, delete or populate old workload caches. Without a tenant policy it does not use that directory.

## 5. Start management on the management VM

```bash
cd ~/hal-on-demand
MANAGEMENT_IP=10.0.0.10
EXEC_IP=10.0.0.30

python3 server/management.py \
  --bind "$MANAGEMENT_IP" --port 9000 \
  --worker-url "http://$EXEC_IP:9100" \
  --catalog workloads.json \
  --worker-token-file "$PWD/state/agent.token" \
  --api-token-file "$PWD/state/api.token" \
  --state-dir "$PWD/state/management-native-http-01" \
  --dispatchers 8 --queue-size 256
```

`--worker-url` selects HTTP dispatch to the execution VM. It replaces the older TCP dispatch configured with `--agent-host` and `--agent-port`. Management reads the selected workload's hash and size from its catalog and sends those with the job. It does not download the Wasm file itself.

Leave management running. Use a second terminal on that VM for the next steps.

## 6. Submit one initial HTTP test

```bash
cd ~/hal-on-demand
MANAGEMENT_IP=10.0.0.10

python3 jobs.py \
  --url "http://$MANAGEMENT_IP:9000" \
  --token-file "$PWD/state/api.token" \
  submit --case sha256-abc --cache bypass --wait
```

`jobs.py` is an HTTP client; it does not start or act as the Wasm agent. It submits one job and waits for the management API to return its result.

Expected result:

```json
{
  "status": "completed",
  "response": {
    "result_validation": "passed",
    "execution_mode": "native",
    "dispatch_transport": "http",
    "agent": {
      "execution_mode": "native",
      "agent_kind": "none",
      "agent_sha256": null,
      "cache_status": "bypass",
      "result": {
        "bytes": 32,
        "hex": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
      }
    }
  }
}
```

This is an excerpt, not the full response. `response.agent` is a legacy JSON field name retained for compatibility with the earlier recorder; in native mode it contains the direct execution result. `agent_kind: none` and the null agent hash identify the no-agent path. The hash above is the workload's SHA-256 result for the string `abc`; it is separate from the downloaded component's integrity hash.

To use `curl` instead of the Python client:

```bash
TOKEN=$(cat state/api.token)

curl --fail-with-body --silent --show-error \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"case":"sha256-abc","cache":"bypass"}' \
  "http://$MANAGEMENT_IP:9000/v1/jobs" > first-job.json

JOB_ID=$(python3 -c 'import json; print(json.load(open("first-job.json"))["job_id"])')

curl --fail-with-body --silent --show-error \
  -H "Authorization: Bearer $TOKEN" \
  "http://$MANAGEMENT_IP:9000/v1/jobs/$JOB_ID?wait=20" | python3 -m json.tool
```

If the status remains `queued` or `running`, repeat only the final GET. Do not POST another job merely to check progress. The GET returns as soon as that job finishes, up to a 20-second wait. Repeated POSTs without a pinned job ID create new jobs.

## 7. Record the no-agent HTTP benchmark

For 100 executions of each of the five cases, serially:

```bash
python3 jobs.py \
  --url "http://$MANAGEMENT_IP:9000" \
  --token-file "$PWD/state/api.token" \
  bench --jobs 500 --concurrency 1 \
  --cache bypass --expect-mode native \
  --output results/native-http-bypass-01
```

Every job downloads, verifies, compiles, and executes. There is no artifact or compiled-code cache. The engine persists; each workload instance and Store are fresh. `--expect-mode native` detects an accidentally selected agent endpoint and fails the benchmark rather than labeling it a no-agent result. `reuse` requests are rejected with a message to use `--cache bypass`.

Inspect the files:

```bash
cat results/native-http-bypass-01/status.json
cat results/native-http-bypass-01/summary.csv
```

Look for `completed: 500`, `failed_or_unknown: 0`, `execution_modes: {"native": 500}`, and 500 `bypass` jobs. The CSV has 100 samples per case. All durations are in milliseconds. Use `client_observed_ms` for client-to-result latency, `management_total_ms` for management processing, and `host_request_ms` for execution-side handling. Preparation download/compile metrics explain where time went. They are nested timers, so do not add every metric together. Throughput is successful jobs divided by the whole batch duration.

To measure concurrent requests, use a different output folder:

```bash
python3 jobs.py \
  --url "http://$MANAGEMENT_IP:9000" \
  --token-file "$PWD/state/api.token" \
  bench --jobs 500 --concurrency 8 \
  --cache bypass --expect-mode native \
  --output results/native-http-bypass-concurrent-01
```

These are closed-loop trials: each client slot submits its next request after receiving the previous result. Management dispatchers and host download/compile/execution slots bound the work in progress. Preparation of one job can overlap execution of another. The host reports `busy` if global or user admission limits are exhausted. Existing result directories are never overwritten.

For a successful, otherwise idle batch of N bypass jobs, the operator `/v1/stats` counters must increase by N downloads, N compilations and N executions. `compiled_entries` and `shared_preparations` stay zero. Results report `runtime_reused: true` and `workload_instance_reused: false`. Use counter differences if a smoke test ran beforehand. `--record-host-stats` can audit an isolated single-user run; tenant credentials cannot read host-wide operator statistics.

## Later comparison with the Wasm agent

The Wasm agent's existing configuration, caching, runtime reuse, parallelism, limits, policies, signed authorization and container workers are unchanged. Start it using its existing instructions and a separate state directory. The management process and HTTP client work with either mode. For agent measurements, retain your previous management dispatcher settings as well. Use a new management state directory if you want its accumulated counts isolated; benchmark result files are already separate.

Compare these explicitly named experiments:

| Purpose | Native mode | Wasm-agent mode |
|---|---|---|
| Matched execution without workload caching | `bypass`, persistent engine, bounded concurrency | `bypass`, same compilation/concurrency/limits |
| Uncached execution versus cached agent system | `bypass`, persistent engine, bounded concurrency | `reuse`, report cold or warm state |

For the first row, match the VM resources, workloads, network placement, authenticated-user policy, compilation settings, limits and request concurrency. If the agent also uses containers or signed-job checks, report those extra boundaries as part of the comparison. The second row includes the benefit of caching and cannot attribute its whole speedup to the Wasm coordinator. For an agent reuse trial starting empty, follow that profile's cache reset instructions. Repeat both sides several times, alternate their order, and record the effective configuration and executable hashes. No percentage improvement is guaranteed. Existing results still describe the builds that produced them.
