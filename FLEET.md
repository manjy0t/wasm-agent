# Service deployment and user commands

The fleet has four roles:

| Role | Responsibility |
|---|---|
| Identity | User registration, workload catalog, signed authorization grants and revocation |
| Files | Immutable workload artifacts and scoped artifact access |
| Management | User-facing requests, attestation/deployment decisions, dispatch, audit collection and benchmark reservations |
| Execution | HTTPS execution gateway, native runner and brokers on the workload VM |

Use Linux service machines. Agent execution requires the configured confidential
platform and Docker/gVisor worker isolation. The other roles need Python; the
chosen attestation verifier and SNP codec run on management. The operator/client
can run on Mac, Linux or Windows.

## Prepare an existing inventory

This repository does not create cloud instances. Give each service a stable
address and restrict network access to the required clients and services.
`fleet.py deploy` currently expects four separate IPv4 addresses. Routine requests
use HTTPS; internal broker ports and the Docker socket remain local.

```sh
python3 -m venv .venv

.venv/bin/python -m pip install -r requirements-signing.txt

mkdir -p state

cp examples/fleet-inventory.example.json state/fleet-inventory.json
```

Edit the copy with your addresses and SSH users. The `192.0.2.*` addresses in the
example are documentation placeholders. Allow identity, files, management and
execution to reach their required HTTPS peers; laptop connectivity alone does
not establish service-to-service connectivity.

Create the operator key and private service CA once:

```sh
.venv/bin/python fleet.py operator-key --output state/fleet-operator.json

.venv/bin/python fleet.py certificates \
  --inventory state/fleet-inventory.json --output state/fleet-tls
```

These commands refuse to overwrite existing keys. Keep the operator signing key
and CA private key on the operator machine. Deployment distributes each service's
own TLS key and the public CA. Clients validate the CA and service name; do not
disable certificate verification.

## Install the native base and configure the agent profile

Prepare the reviewed attestation policy and portable deployment profile using
[PORTABLE_AGENT.md](PORTABLE_AGENT.md). The verifier must already be available
on management; [TRUSTEE.md](TRUSTEE.md) describes that adapter. Agent deployment
requires the native base, gVisor runtime and approved environment.
Example policy measurements are deliberately invalid placeholders.

For an operator-managed four-VM installation, the generic CLI can copy source,
build the native base and install service units on the existing inventory:

```sh
.venv/bin/python fleet.py deploy \
  --inventory state/fleet-inventory.json \
  --credentials state/fleet-tls \
  --ssh-key "$HOME/.ssh/id_ed25519" \
  --operator state/fleet-operator.json \
  --portable-profile state/portable-profile.json
```

This is an explicit maintenance operation. It can stop/restart services and build
execution artifacts; drain jobs first. The optional `--install-dependencies`
flag allows its dependency installation commands. Omitting it does not turn
`deploy` into a read-only command. It still installs the supplied application.
It neither provisions cloud VMs nor selects trusted boot measurements.

TLS certificates are validated before copying. Invalid, expired or incomplete
certificates cause an error; this source distribution does not automatically
repair or reissue them. Generated leaf certificates last 90 days and the CA one
year. Plan certificate renewal separately.

For individually managed machines, use `fleet.py init --help`,
`fleet.py configure-agent --help` and `fleet.py unit --help` to prepare role
configuration and service units. [PORTABLE_AGENT.md](PORTABLE_AGENT.md) explains
the required profiles and trust bindings. Generate units as the account that owns
the configuration; execution's privileged launcher uses root.
Keep private files owned by their service account with mode `0600`. Do not make
keys or state world-writable to resolve a permissions error.

The service names are `hal-fleet-identity`, `hal-fleet-files`,
`hal-fleet-management` and `hal-fleet-execution`. Inspect the relevant VM with:

```sh
systemctl status hal-fleet-management.service --no-pager

journalctl -u hal-fleet-management.service -n 50 --no-pager
```

Substitute the relevant role. HTTPS `/health` establishes service liveness, not
agent readiness or attestation.

The installer writes public endpoints and the identity signing-key fingerprint
to `state/fleet-tls/deployment.json`. Keep the public `ca.pem` with that file when
moving the client bootstrap to another machine. Do not replace its identity
fingerprint with one obtained through an untrusted channel.

## Activate the configured agent

On the management VM, as the account that owns its configuration, inspect the
target and request attested deployment:

```sh
.venv/bin/python fleet.py agent-status \
  --config state/fleet.json --execution-url https://EXECUTION_VM

.venv/bin/python fleet.py agent-deploy \
  --config state/fleet.json --execution-url https://EXECUTION_VM
```

Replace `EXECUTION_VM` with the configured HTTPS address. Deployment requires
successful verification and available lifecycle state. Investigate an unfinished
drain or ownership conflict; do not delete ownership state to bypass it.

## Publish workloads

Build the 15 computational workloads locally, then publish their manifest:

```sh
.venv/bin/python benchmarks/build.py --install-target

.venv/bin/python fleet.py publish \
  --operator state/fleet-operator.json \
  --deployment state/fleet-tls/deployment.json \
  --manifest benchmarks/artifacts/manifest.json
```

The publication contains exact artifact hashes, sizes, validation rules and
resource permissions. Artifacts use immutable SHA-256 filenames. Changing an
existing workload's content requires a new catalog name. Users select approved
catalog entries; they do not grant themselves new HAL permissions.

## Register, approve and run

On the user's machine:

```sh
.venv/bin/python fleet.py onboard \
  --user alice --deployment state/fleet-tls/deployment.json \
  --output state/alice.json --workloads all

.venv/bin/python fleet.py run \
  --client state/alice.json --workload matrix-multiply --cache reuse
```

`onboard` creates or reuses the local user key, registers it, requests the selected
catalog workloads and enrolls the signed authorization update. Reusing a username
requires its existing key. A revoked identity needs an explicit administrative
decision; generating a different key is not a recovery mechanism.

Bob runs onboarding with his own username and output path. Share only the public
bootstrap, never another user's private client file or operator credentials.
Approval and cache reuse do not bypass per-job authorization.

Use [benchmarks/README.md](benchmarks/README.md) for new benchmark directories,
mode-specific commands and result interpretation. Set up the audited native
profile using [NATIVE_AUDIT_BENCHMARKS.md](NATIVE_AUDIT_BENCHMARKS.md) before
benchmarking native mode. A client profile cannot switch server configurations.
