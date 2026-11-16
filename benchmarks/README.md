# Workloads and benchmarks

The managed agent and audited native profiles both persist signed execution
events and collect them at management. Their remaining architectural costs
differ; a comparison measures the full setups, not the cost of Wasm alone.

Each workload is a separate compiled Wasm component. It performs deterministic computation in the guest and returns a small checksum or digest. Python reference implementations calculate expected answers independently; the build checks native Rust answers against them. The fleet integration test also executes all 15 actual Wasm components and checks their answers.

| Workload | Work performed |
|---|---|
| `matrix-multiply` | Multiply two 96 by 96 integer matrices |
| `integer-sort` | Sort 32,768 generated integers and checksum the result |
| `prime-sieve` | Find primes up to 500,000 and return count and sum |
| `dijkstra` | Shortest paths over 384 vertices with eight edges per vertex |
| `floyd-warshall` | All-pairs shortest paths over 96 vertices |
| `knapsack` | Dynamic programming for 200 items and capacity 20,000 |
| `edit-distance` | Compare two generated strings of length 1,024 |
| `kmeans` | Cluster 4,096 integer points into eight clusters for 12 iterations |
| `nbody-integer` | Run a deterministic 128-body, 30-step integer toy simulation |
| `image-convolution` | Apply a 5 by 5 filter to a 256 by 256 generated image |
| `pagerank` | Perform 30 fixed-point iterations over a 512-vertex graph |
| `json-aggregation` | Serialize, parse and aggregate 12,000 records into 64 groups |
| `rle-roundtrip` | Compress and decompress 65,536 bytes and verify the round trip |
| `merkle-tree` | Hash 1,024 leaves of 1 KiB and build a SHA-256 Merkle tree |
| `pbkdf2-sha256` | Derive 32 bytes with 10,000 HMAC-SHA-256 iterations |

The simulation is a benchmark, not a scientific model. The PBKDF2 iteration count is a fixed test size, not a password-storage recommendation. All inputs are generated inside the component because the current launch ABI has no application-input argument. These guest computations measure different work from the earlier tiny HAL-call benchmarks.

Source: `guest/src/lib.rs`; reference: `reference.py`; build: `build.py`; outputs: `artifacts/manifest.json` and hash-named `.wasm` files. Build on the operator machine with:

```bash
python3 benchmarks/build.py --install-target
```

Then publish and onboard using [FLEET.md](../FLEET.md).

## Original HAL-call fixtures

`../tests/workloads/function0.wasm` through `function4.wasm` are the original
SHA-256, SHA-512, random, platform and clock fixtures. `../workloads.json`
records their sizes, hashes and result checks for the local test harness.
It is not a fleet publication manifest. Fleet catalog names and platform-specific
expected outputs must match the operator-approved publication. Do not assume
that a `platform-amd` or `platform-intel` catalog entry already exists.

## Before a benchmark

Build and deploy matching code deliberately. Publish the selected workloads,
register the user and approve their grant. Check that management and execution
serve the intended agent or audited-native profile; changing a client JSON file
does not switch services. Keep machine load, client/network path, CPU limits and
workload rules documented. Do not run setup or tests during measurement.

Create a separate client file for each profile from the existing enrolled key:

```sh
.venv/bin/python fleet.py client-profile --client state/alice.json \
  --mode wasm --output state/alice-agent.json

.venv/bin/python fleet.py client-profile --client state/alice.json \
  --mode native --output state/alice-native.json
```

These files preserve the user identity and pin the expected execution architecture.
They refuse to overwrite existing output files. Use a new output path if needed.

## Agent reuse matrix

With agent services active and `state/alice-agent.json` enrolled:

```sh
.venv/bin/python benchmarks/run_matrix.py \
  --client state/alice-agent.json --workloads all \
  --jobs 150 --repeats 3 --concurrencies 1,2,4 \
  --cache reuse --expect-mode wasm --expect-isolation per-user-container \
  --output "results/agent-reuse-$(date -u +%Y%m%dT%H%M%SZ)"
```

This runs nine measured batches: three repeats at each of three concurrency
levels. Each batch has 150 total jobs, cycling through the selected workloads.
For exactly 15 workloads, each function runs ten times per batch and 90 times
across the matrix. `all` means all workloads in that client's approved grant;
use an explicit comma-separated list when comparing a fixed suite.

Each reuse batch has a separate warm-up with one job per selected workload.
Normal reuse includes later misses or session renewal if they occur. Add
`--fully-warmed` only when you want a separate all-hit protocol: it preserves the
warmed session and requires every measured job to hit, with no session renewal.
It does not extend the workload's cache TTL. Preserve an attempt that fails
this requirement rather than removing its slow jobs.

## Native matrix

After separately configuring and activating audited native services:

```sh
.venv/bin/python benchmarks/run_matrix.py \
  --client state/alice-native.json --workloads all \
  --jobs 150 --repeats 3 --concurrencies 1,2,4 \
  --cache bypass --expect-mode native --expect-isolation in-process \
  --output "results/native-$(date -u +%Y%m%dT%H%M%SZ)"
```

Native reuse is forbidden. Native mode still executes Wasm workloads; it omits
the Wasm orchestration agent and worker containers. The matrix has nine measured
batches and does not add reuse warm-ups.

To measure one function, replace `--workloads all` with its approved name, such
as `--workloads matrix-multiply`. That function then runs 1,350 measured jobs.
Use a separate output directory for each single-function or mixed-suite attempt.
The runner refuses to reuse an existing matrix directory.

## Startup and cache comparison

To record startup separately, run `fleet.py bench` with `--phase startup` and
one job per selected workload before the matrix. For one agent workload:

```sh
.venv/bin/python fleet.py bench \
  --client state/alice-agent.json --workloads matrix-multiply \
  --jobs 1 --concurrency 1 --cache reuse --phase startup \
  --expect-mode wasm --expect-isolation per-user-container \
  --output "results/agent-startup-$(date -u +%Y%m%dT%H%M%SZ)"
```

For an agent bypass/reuse comparison, use `--cache both` in the matrix. That
produces 18 measured batches for three repeats and three concurrency levels.
The runner changes batch order across repeats. This compares code reuse inside
the same agent architecture. An agent/native comparison measures different
full setups; auditing in both does not equalize isolation or resource limits.

## Evidence and timing

Every batch saves `config.json`, `jobs.jsonl`, `summary.json` and `integrity.json`.
The matrix also saves `matrix-protocol.json`, `matrix.json` and `experiment.json`.
Warm-ups have their own directories and phase labels. Benchmark reservations,
build/profile pins, unique job IDs and evidence checks detect recorded changes
or competing managed requests. They do not exclude unrelated machine or network
load, or an administrator changing infrastructure outside the service.

The runner stops on a failed or unknown job and retains the attempt. It does not
retry jobs. A lost response can mean the server processed the request; do not
blindly resubmit it. Check reservations and job state before beginning a new run.

Verify a completed batch before using it:

```sh
.venv/bin/python fleet.py benchmark-verify \
  --output results/YOUR_RUN/r1-reuse-q1
```

Use `r1-bypass-q1` for native. Verify all selected batches, inspect the experiment's
completion/reservation-release state and report failed attempts as well.

- **Host time:** preparation, function execution and other work in the host request.
- **Management time:** admission, dispatch, response handling and audit work in that scope.
- **Client latency:** local request preparation/signing through response receipt and parsing,
  before local output and receipt checks.
- **Batch wall time:** job scheduling, requests, local result validation and job-record
  persistence, including session renewal during the batch.
- **Jobs/s:** successfully completed and validated jobs divided by batch wall seconds.

Client, management and host timers overlap; do not add them together. Initial
session setup, lease acquisition, separately recorded startup/warm-up jobs and
final summary generation are outside the measured batch. Report those costs
separately when describing cold-start or total experiment cost.

The generated computation rules use a five-minute cache TTL. Attestation lease
length is a separate policy setting. Expiry, broker replacement and eviction can
remove prepared code, so inspect actual hit/miss counts and session generations.
A warm-up is not a guarantee that later requests hit. The ordinary scheduler
pauses submissions, drains in-flight jobs and renews near session expiry; its
renewal time is included in batch wall time.

Use the median of repeated batch throughputs when reporting a typical rate;
retain the spread. Do not average per-batch percentiles and label the result as a
pooled percentile. Use individual job records for pooled latency statistics.
A batch's elapsed time divided by its job count is not per-request latency when
requests overlap. `compare_cache.py --help` describes the additional per-workload
comparison tool.
