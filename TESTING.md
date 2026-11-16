# Testing

Run commands from the repository root. Tests create temporary identities and
state. They do not need an existing operator key or cloud inventory.

## Build prerequisites

```sh
.venv/bin/python build.py --install-target

.venv/bin/python benchmarks/build.py --install-target
```

The build checks that both agent components link against their native hosts.
The workload build compares native Rust answers with independent Python
implementations. Both use the pinned Rust/WASI version in
`hal_fleet/build_toolchain.py`.

## Local architecture and API checks

```sh
.venv/bin/python -B tests/run_architecture_checks.py

.venv/bin/python -B tests/run_trustee_checks.py
```

The architecture runner checks the shared agent, native audit path, lifecycle,
authorization, benchmark evidence, profile changes, TLS creation and source
packaging. It then runs Rust host, agent-policy and workload-HAL tests. Its Cargo
tests use `--offline`, so dependencies must already be cached. The Trustee runner
also checks the SNP codec and policy contract; it accepts `--offline` when those
dependencies are cached.

Both runners accept `--toolchain NAME` for an installed Rustup alias, but verify
that it resolves to the required Rust version. An arbitrary newer `stable`
compiler is not accepted.

Local integration checks bind loopback ports and launch child processes. Some
filesystem checks require POSIX behavior; native Windows ACL checks run only on
Windows. Platform-specific skips are not proof that those platforms passed.

For a focused check without building native artifacts:

```sh
.venv/bin/python -B tests/test_build.py

.venv/bin/python -B tests/test_fleet_tls.py

.venv/bin/python -B tests/test_benchmark_guard.py

.venv/bin/python -B tests/test_benchmark_matrix.py
```

Other useful suites include `tests/test_system.py`, `tests/test_tenants.py`,
`tests/test_authorization.py`, `tests/test_native_baseline.py` and
`tests/test_compare_cache.py`. The first four require built artifacts.

## Linux worker acceptance

Prepare Docker, the fixed gVisor runtime and the worker image using
[GVISOR.md](GVISOR.md) and [containers/README.md](containers/README.md).
On an otherwise idle Linux test VM, after building the host and workload artifacts:

```sh
sudo "$PWD/.venv/bin/python" -B tests/test_docker_workers.py \
  --image hal-user-worker:local
```

This suite creates and removes its own worker containers. It checks separate
workers/caches, restricted mounts, namespaces, resource limits, fresh execution
and concurrent startup. It uses synthetic HAL metadata, so it establishes
worker behavior rather than real hardware attestation. Do not run it during a
performance benchmark.

## TEE acceptance

Real Intel TDX or AMD SEV-SNP verification needs a suitable VM, its reviewed
measurement policy, the configured verifier and endorsement/collateral access.
On that deployment, verify agent activation and a fresh attested user session,
submit an approved job, inspect the audit evidence, and complete controlled
retirement. Exercise policy denial and cross-user isolation before using it for
published results. See [PORTABLE_AGENT.md](PORTABLE_AGENT.md) and
[TRUSTEE.md](TRUSTEE.md).

Fixture tests, successful HTTPS health checks and JSON configuration reports
cannot establish that a cloud VM matches its approved TEE baseline.
