# Windows user and operator computer

The shared management-owned agent architecture (`hal-managed-agent-v2`) is available. See
[PORTABLE_AGENT.md](PORTABLE_AGENT.md) for the attestation prerequisites and the
`deploy --portable-profile` command. Existing VM configurations keep their legacy
profile until explicitly migrated. Select `dist/orchestration-agent.wasm` for this architecture. The client commands below remain supported.

Use native Windows PowerShell with Python 3.13. The four Google VMs still run Linux; the execution VM still uses Intel TDX and Docker. Windows runs the signing client, benchmarks, publication and SSH installer. WSL, Docker Desktop and a local Rust host are not needed for those operations.

## 1. Prepare PowerShell once

Put this repository in your own local user folder, for example `$env:USERPROFILE\Documents\hal-on-demand`. Open PowerShell there:

```powershell
Set-Location "$env:USERPROFILE\Documents\hal-on-demand"
py -3.13 -m venv .venv-windows
$HalPython = ".\.venv-windows\Scripts\python.exe"
& $HalPython -m pip install -r requirements-signing.txt
```

Use a Windows Python installation. A `.venv` copied from a Mac/Linux computer cannot run on Windows; `.venv-windows` keeps it separate. No environment activation or PowerShell execution-policy change is needed. In a new terminal, set `$HalPython` again after changing to the repository folder.

Dependencies include `pywin32` only on Windows. Private keys are created with an explicit, protected Windows DACL for the current account, SYSTEM and Administrators. Reads check ownership and ACLs on the opened file. This replaces Unix `chmod` checks; it does not disable key protection. Use a filesystem that supports Windows ACLs, normally NTFS.

## 2. Connect to an existing deployment

For a new user, the operator provides two **public** bootstrap files:

```text
state\fleet-tls\deployment.json
state\fleet-tls\ca.pem
```

Keep them together. Enrollment, permissions, job signing and session refresh then use APIs. The client resolves the adjacent CA when an older `deployment.json` still contains a Mac/Linux path. New deployment descriptors use `ca.pem` relative to the descriptor. TLS verification and the identity signing-key fingerprint remain checked.

Register Alice and request every published workload:

```powershell
& $HalPython fleet.py onboard --user alice --deployment state/fleet-tls/deployment.json --output state/alice.json --workloads all
```

For Bob, substitute `--user bob --output state/bob.json`. Existing client files are reused without generating another key. Moving an existing Alice account requires Alice's original private client file through a trusted transfer; making a new key cannot take over the registered name. An ordinary Bob client does not need Alice's key, the operator key or any CA/server private key.

If the public CA is kept elsewhere, supply its local path explicitly:

```powershell
& $HalPython fleet.py onboard --user alice --deployment state/fleet-tls/deployment.json --ca-file "$env:USERPROFILE\Documents\HAL certificates\ca.pem" --output state/alice.json --workloads all
```

## 3. Normal user commands

List the published catalog, request additional permissions, or refresh the document:

```powershell
& $HalPython fleet.py catalog --client state/alice.json
& $HalPython fleet.py approve --client state/alice.json --workloads matrix-multiply,dijkstra
& $HalPython fleet.py renew --client state/alice.json
```

Run a function with bypass, then reuse twice:

```powershell
& $HalPython fleet.py run --client state/alice.json --workload matrix-multiply --cache bypass
& $HalPython fleet.py run --client state/alice.json --workload matrix-multiply --cache reuse
& $HalPython fleet.py run --client state/alice.json --workload matrix-multiply --cache reuse
```

Check `status`, `client_result_validation` and actual `cache_status`. The first reuse can be a miss; every invocation still executes a fresh workload instance. Runs acquire the current session automatically.

Retrieve an existing recorded result without submitting another job:

```powershell
& $HalPython fleet.py result --client state/alice.json --job-id "PASTE-THE-JOB-ID"
```

For the shared agent deployment, inspect your signed audit history:

```powershell
& $HalPython fleet.py audit --client state/alice.json
& $HalPython fleet.py audit --client state/alice.json --job-id "PASTE-THE-JOB-ID"
```

This reads collected history without submitting another job. Use `--after` with
the returned `next_cursor` for the next page. See [AUDIT.md](AUDIT.md) for what the
signatures establish and how unknown outcomes are handled.

Separate enrollment steps are available if you do not use `onboard`. Only use `client-init` for a new client file:

```powershell
& $HalPython fleet.py client-init --user alice --deployment state/fleet-tls/deployment.json --output state/alice.json
& $HalPython fleet.py register --client state/alice.json
& $HalPython fleet.py approve --client state/alice.json --workloads all
```

## 4. Benchmark and read results

Create a unique output parent; each individual batch creates its own new directory:

```powershell
$HalResults = Join-Path $PWD ("results/windows-" + [DateTime]::UtcNow.ToString("yyyyMMddTHHmmssfffZ"))
New-Item -ItemType Directory -Path $HalResults | Out-Null
& $HalPython fleet.py bench --client state/alice.json --workloads matrix-multiply --jobs 100 --concurrency 1 --cache bypass --output "$HalResults/matrix-bypass"
& $HalPython fleet.py bench --client state/alice.json --workloads matrix-multiply --jobs 1 --concurrency 1 --cache reuse --output "$HalResults/matrix-warmup"
& $HalPython fleet.py bench --client state/alice.json --workloads matrix-multiply --jobs 100 --concurrency 1 --cache reuse --output "$HalResults/matrix-reuse"
```

For repeated mixed-workload tests at concurrency 1, 2, 4 and 8, with bypass and reuse:

```powershell
& $HalPython benchmarks/run_matrix.py --client state/alice.json --workloads all --jobs 150 --repeats 3 --output "$HalResults/agent-matrix"
```

`--jobs` is the total in each batch, shared across selected functions. The matrix saves reuse warm-ups separately. Preserve misses and failed/unknown jobs in the analysis. Keep the client machine/location the same across comparisons; moving the load generator from a Mac to Windows can change client timings.

Read the summary and per-function records:

```powershell
Get-Content -Raw "$HalResults/matrix-reuse/summary.json" | ConvertFrom-Json | Format-List
Get-Content "$HalResults/matrix-reuse/jobs.jsonl" | ForEach-Object { $_ | ConvertFrom-Json } | Select-Object case,status,client_observed_ms
```

`config.json` captures the profile, `jobs.jsonl` keeps full records, and `summary.json` gives batch throughput and timing distributions. `case` identifies the function. Client, management and host times overlap; do not add them.

For native mode, first have the operator configure both management and execution
using [NATIVE_AUDIT_BENCHMARKS.md](NATIVE_AUDIT_BENCHMARKS.md). If the optional
selector is installed, use [MODE_SELECTION.md](MODE_SELECTION.md) to switch.
Changing a client profile does not switch the running services. Once native mode
is ready, use its client profile for these commands:

```powershell
& $HalPython fleet.py run --client state/alice.json --workload matrix-multiply --cache bypass --expect-mode native --expect-isolation in-process
& $HalPython benchmarks/run_matrix.py --client state/alice.json --workloads all --jobs 150 --repeats 3 --expect-mode native --expect-isolation in-process --output "$HalResults/native-matrix"
```

Restore the execution service to `wasm` before agent tests. Native mode accepts only bypass. The two profiles retain their existing different isolation/resource boundaries.

## 5. Operator: automatic deployment from Windows

Skip this section if your four services are already deployed and you are only using them. Ordinary user calls require no SSH. Deployment uses the Windows OpenSSH client and builds Rust/Docker on the Linux execution VM.

Check that the Windows **OpenSSH Client** optional feature is installed:

```powershell
ssh -V
```

If missing, install that feature through Windows Settings. For an encrypted SSH key, the optional Windows `ssh-agent` service can retain its unlocked key. Start/enable that service through an elevated terminal if needed, then use `ssh-add` from your own account. Without an agent, SSH can prompt repeatedly for the passphrase.

For a new deployment, copy/edit the inventory and create the operator key and TLS files once. Keep existing state when continuing your current deployment:

```powershell
New-Item -ItemType Directory -Force state | Out-Null
if (-not (Test-Path state/fleet-inventory.json)) { Copy-Item examples/fleet-inventory.example.json state/fleet-inventory.json }
notepad state/fleet-inventory.json
if (-not (Test-Path state/fleet-operator.json)) { & $HalPython fleet.py operator-key --output state/fleet-operator.json }
if (-not (Test-Path state/fleet-tls)) { & $HalPython fleet.py certificates --inventory state/fleet-inventory.json --output state/fleet-tls }
```

Use the four real static external IPv4 addresses and SSH users. The network requirements in [FLEET.md](FLEET.md) apply: HTTPS from the client and the VMs, plus restricted SSH for deployment. Update the client source range if the Windows computer has a different public address.

Choose the SSH key on this Windows computer, then deploy:

```powershell
$HalSshKey = Join-Path $env:USERPROFILE ".ssh/google-cloud-ssh-key"
ssh-add $HalSshKey
& $HalPython fleet.py deploy --inventory state/fleet-inventory.json --credentials state/fleet-tls --ssh-key $HalSshKey --operator state/fleet-operator.json --install-dependencies
```

The installer packages source with Linux paths/modes, transfers each VM's TLS material, runs Linux builds and starts systemd services. It does not upload the operator key or CA private key. The source package excludes local virtual environments, state and results. Re-running deployment is a maintenance operation: finish running jobs first.

Build the computational workload artifacts using `benchmarks/build.py` on a Rust build machine, then publish their manifest through APIs:

```powershell
& $HalPython fleet.py publish --operator state/fleet-operator.json --deployment state/fleet-tls/deployment.json --manifest benchmarks/artifacts/manifest.json
```

The five original HAL-call fixtures are retained for local tests; publishing them requires an operator-approved fleet manifest with the correct platform result. Users request new grants using `approve`. Existing published workload names are immutable; changed artifacts need a new name.

Other operator commands:

```powershell
& $HalPython fleet.py network-check --inventory state/fleet-inventory.json --credentials state/fleet-tls --ssh-key $HalSshKey
& $HalPython fleet.py package --output source-for-linux.tar.gz
```

If intentionally revoking Bob:

```powershell
& $HalPython fleet.py revoke --operator state/fleet-operator.json --deployment state/fleet-tls/deployment.json --user bob
```

Server commands `init`, `serve`, `unit` and `trust-build` run on the Linux VMs, normally through `deploy`. They now report an explanatory error when invoked locally on Windows. The legacy `deployment.py`/`jobs.py` workflow and native Windows execution of the Rust/TDX host are outside this client compatibility update.

## 6. Validate or troubleshoot

Run the portable client tests on Windows; they need no Rust, Docker, running fleet or production keys:

```powershell
& $HalPython -B tests/test_fleet_client_portability.py
& $HalPython fleet.py --help
```

On Windows the test suite exercises real private-file ACL creation/replacement and rejection of a file readable by Everyone. It also covers key reuse, CA relocation, Linux archive metadata and CLI publish/onboard/run/benchmark/result workflows with simulated execution. It does not claim to test TDX or run real Wasm in that fixture.

If an imported private file fails its ACL check, use that file's **Properties > Security > Advanced** to make your Windows account its owner and allow only that account, SYSTEM and Administrators. Do not grant Everyone access to get past an error. The CLI does not silently rewrite permissions on imported credentials. Existing `.venv/bin/python` paths and Bash backslash line continuations belong to macOS/Linux; use the PowerShell commands above.

Implementation references: [pywin32](https://pypi.org/project/pywin32/312/) supplies the native ACL/handle APIs; [Microsoft CreateFile documentation](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew) describes the security attributes and reparse-point behavior used here.
