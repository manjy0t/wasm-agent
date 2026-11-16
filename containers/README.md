# Per-user workload workers

The managed agent profile uses Docker with the fixed gVisor runtime
`hal-gvisor`. Each user's native broker controls that user's worker. The shared
VM agent requests broker operations through the extended HAL; it is not copied
into every workload container.

A worker holds prepared code for its user. Each job creates a fresh Wasm
instance with the approved workload's HAL permissions and resource limits.
Different functions for the same user share the worker's native isolation
boundary. Other users have separate workers and caches.

## Build the worker image

On the Linux execution/build machine, first build the host and agents using the
root README. Prepare Docker and the approved runtime using [GVISOR.md](../GVISOR.md).
Then run the image builder from the repository root:

```sh
sudo "$PWD/.venv/bin/python" -m hal_fleet.worker_image \
  --root "$PWD" --image hal-user-worker:local
```

The Dockerfile builds the Linux host with its libraries rather than copying a
Mac executable or a binary linked against an incompatible host libc. The builder
checks the immutable image ID, Linux/amd64 platform, non-root user and entrypoint,
and probes the image before promoting its local tag. It does not prune Docker
or reset another installation's state.

The implementation requires the local rootful Docker daemon. A remote daemon,
rootless Docker and user-namespace remapping are not supported by the launcher.
The production runtime fails if its gVisor configuration differs; it does not
fall back to the default Docker runtime.

## Worker restrictions

- gVisor's Sentry handles the worker's operating-system calls.
- General network access is disabled. The worker receives only its private IPC
  and approved configuration mounts.
- The worker runs as an unprivileged user, with capabilities dropped and
  privilege escalation disabled.
- System files are read-only. Writes are limited to approved private temporary areas.
- CPU, memory, process count and temporary storage are bounded.
- The launcher checks the image, ownership, mounts, namespaces, runtime and limits
  before dispatching the first job.

Management credentials, artifact-service credentials, other users' directories,
Docker control sockets and TEE devices are not mounted in the worker. Platform
metadata supplied by the broker is not independent hardware evidence.

These controls complement workload-specific HAL policies. gVisor limits native
worker access to the host; the restricted HAL decides which operations a particular
Wasm invocation may request. The VM kernel, launcher, native broker and runtime
remain trusted. See [WORKLOAD_ACCESS.md](../WORKLOAD_ACCESS.md) and
[PORTABLE_AGENT.md](../PORTABLE_AGENT.md) for those boundaries.

## Lifetime and failure behavior

Removing a worker loses its compiled-code cache and private tmpfs data. Broker
shutdown attempts to remove its workers; abrupt termination or daemon failure
can leave cleanup incomplete. Use the managed retirement protocol and inspect
actual process/container state rather than assuming that an absent agent proves
successful cleanup.

An IPC failure after dispatch may mean that a workload ran but its response was
lost. It is recorded as failed or unknown; jobs are not automatically replayed.
The benchmark records startup, acquisition, preparation and execution fields.
Use [benchmarks/README.md](../benchmarks/README.md) for the current timing scopes.

## Validate on Linux

After building the workload fixtures and installing the runtime:

```sh
sudo "$PWD/.venv/bin/python" -m hal_fleet.gvisor check

sudo "$PWD/.venv/bin/python" -B tests/test_docker_workers.py \
  --image hal-user-worker:local --signed-jobs
```

These tests use real workers and synthetic HAL platform metadata. They check
containment and signed-job behavior, not actual TDX/SNP evidence. Run a verified
session on the intended TEE deployment separately. Do not run acceptance tests
at the same time as a performance benchmark.
