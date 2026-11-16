"""One-time deployment helpers. User enrollment never uses SSH or copies keys."""
import datetime
import getpass
import io
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import tarfile
import tempfile
import time
from .common import Transport, atomic_json, digest, parse, public, key_from_hex, read_private, require
from .local_files import read_regular, write_private
from .build_toolchain import RUST_TOOLCHAIN

ROLES = ('identity', 'files', 'execution', 'management')


def inventory(path):
    value = parse(Path(path).read_text(encoding='utf-8-sig'))
    require(set(value['vms']) == set(ROLES), 'Inventory must have identity, files, execution and management VMs')
    for role, vm in value['vms'].items():
        require(isinstance(ipaddress.ip_address(vm['ip']), ipaddress.IPv4Address),
                'Use a static external IPv4 address for each VM')
        require(re.fullmatch(r'[a-z_][a-z0-9_-]*', vm['ssh_user']), 'Invalid SSH user')
        if 'hostname' in vm:
            from .tls_certificates import service_names
            service_names(vm)
    require(len({vm['ip'] for vm in value['vms'].values()}) == 4, 'Use four separate VM addresses')
    return value


def secret_bytes(path, data):
    write_private(path, data, exclusive=True)


def certificates(inventory_path, output):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
    from .tls_certificates import add_key_extensions, service_names
    info = inventory(inventory_path)
    output = Path(output)
    output.mkdir(parents=True, mode=0o700, exist_ok=False)
    now = datetime.datetime.now(datetime.timezone.utc)
    ca = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'HAL private service CA')])
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(ca.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True))
    cert = add_key_extensions(cert, ca.public_key(), ca.public_key(), ca=True).sign(ca, hashes.SHA256())
    secret_bytes(output / 'ca-key.pem', ca.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                       serialization.NoEncryption()))
    secret_bytes(output / 'ca.pem', cert.public_bytes(serialization.Encoding.PEM))
    for role, vm in info['vms'].items():
        key = ec.generate_private_key(ec.SECP256R1())
        leaf = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, role)]))
            .issuer_name(name).public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=5)).not_valid_after(now + datetime.timedelta(days=90))
            .add_extension(x509.SubjectAlternativeName(service_names(vm)), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False))
        leaf = add_key_extensions(leaf, key.public_key(), ca.public_key(), ca=False).sign(ca, hashes.SHA256())
        secret_bytes(output / (role + '.key'), key.private_bytes(serialization.Encoding.PEM,
                     serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        secret_bytes(output / (role + '.crt'), leaf.public_bytes(serialization.Encoding.PEM))
    atomic_json(output / 'inventory.json', info, exclusive=True)
    return dict(ca_file=str(output / 'ca.pem'), server_certificates_valid_days=90,
                note='Keep ca-key.pem on the operator laptop. Only the public ca.pem goes to clients.')




SOURCE_DIRS = {'src', 'guest', 'orchestrator', 'wit-orchestration', 'wit', 'vendor', 'server', 'tests', 'hal_fleet', 'benchmarks', 'containers', 'examples', 'tools'}
EXCLUDED = {'target', 'state', 'results', 'validation', '__pycache__', '.git', '.venv', '.venv-signing', 'reviewed', 'tls'}


def source_files(root):
    for directory, dirs, names in os.walk(root):
        here = Path(directory)
        dirs[:] = sorted(d for d in dirs if d not in EXCLUDED and not d.startswith('.venv')
                         and not (here / d).is_symlink() and (here != root or d in SOURCE_DIRS))
        for name in sorted(names):
            file = here / name
            if not file.is_file() or file.is_symlink():
                continue
            relative = file.relative_to(root)
            if len(relative.parts) == 1 and file.suffix not in ('.py', '.md', '.txt', '.toml', '.lock') and file.name not in ('.gitignore', '.dockerignore', 'workloads.json', '.gitattributes'):
                continue
            if file.suffix in ('.token', '.pem', '.key', '.pyc') or name in ('.DS_Store', '.aws-snp-install.lock'):
                continue
            yield file, relative


def package(root, output):
    root = Path(root)
    output = Path(output).resolve()
    require(not output.exists(), 'Choose a new archive name')
    output.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(output, 'x:gz') as archive:
        for file, relative in source_files(root):
            # Archives are extracted by Linux even when built on Windows. Never
            # inherit NTFS-derived 0666 key/source permissions or backslashes.
            mode = 0o755 if file.suffix == '.sh' else 0o644
            add_archive_file(archive, file, 'hal-on-demand/' + relative.as_posix(), mode)
    return dict(archive=str(output), bytes=output.stat().st_size, sha256=digest(output.read_bytes()))


def source_unpack_command(destination):
    """Extract uploaded sources with fresh mtimes so Cargo notices changes.

    Archive entries have a normalized (zero) mtime. Restoring it over an existing
    Cargo target directory can make changed Rust/WIT sources look older than the
    compiled artifacts. -m uses extraction time without deleting build caches.
    Use this for sources only; credential/configuration archives are separate.
    """
    destination = shlex.quote(str(destination))
    return 'umask 077; mkdir -p -- ' + destination + ' && tar -xzmf - -C ' + destination


def add_archive_file(archive, path, name, mode=0o600, private=False):
    data = read_regular(path, private=private, maximum=32 * 1024 * 1024)
    entry = tarfile.TarInfo(name)
    entry.size, entry.mode = len(data), mode
    archive.addfile(entry, io.BytesIO(data))


def systemd_unit(root, config_path, config):
    root, config_path = Path(root).resolve(), Path(config_path).resolve()
    require(config['role'] in ROLES, 'Invalid service role')

    def line(value):
        value = str(value)
        require(not any(ord(c) < 32 or ord(c) == 127 for c in value),
                'Service paths must not contain control characters')
        return value.replace('%', '%%')

    # WorkingDirectory is a path setting, not an argument list: surrounding
    # quotes become part of the path. Only ExecStart uses argument quoting.
    directory = line(root)
    require('\\' not in directory and directory == directory.strip(),
            'Service directory must not contain backslashes or trailing whitespace')

    def q(value):
        return '"' + line(value).replace('\\', '\\\\').replace('"', '\\"').replace('$', '$$') + '"'

    execution = config['role'] == 'execution'
    user = 'root' if config['role'] == 'execution' else getpass.getuser()
    return '\n'.join([
        '[Unit]', 'Description=HAL fleet ' + config['role'],
        'After=network-online.target' + (' docker.service' if execution else ''),
        'Wants=network-online.target', '', '[Service]', 'Type=simple', 'User=' + user,
        'WorkingDirectory=' + directory,
        # Preserve the venv executable path; resolving its symlink loses the venv.
        'ExecStart=' + ' '.join(q(v) for v in [sys.executable, root / 'fleet.py', 'serve', '--config', config_path]),
        'Restart=on-failure', 'RestartSec=3', 'TimeoutStopSec=30', 'KillMode=mixed', 'UMask=0077',
        # Non-execution roles bind HTTPS 443 without running as root.
        *(['AmbientCapabilities=CAP_NET_BIND_SERVICE', 'CapabilityBoundingSet=CAP_NET_BIND_SERVICE',
           'NoNewPrivileges=true', 'PrivateTmp=true'] if not execution else []),
        '', '[Install]', 'WantedBy=multi-user.target', ''])


def install_service(ssh, role, unit, service_name=None):
    """Check the unit with the VM's systemd before replacing its installed unit."""
    require(role in ROLES, 'Invalid service role')
    service = service_name or 'hal-fleet-' + role + '.service'
    require(re.fullmatch(r'hal-[a-z0-9-]+-' + role + r'\.service', service), 'Invalid service name')
    command = '\n'.join([
        'set -eu', 'umask 077',
        'hal_unit_stage=$(mktemp -d /tmp/hal-fleet-unit.XXXXXXXX)',
        "trap 'rm -rf -- \"$hal_unit_stage\"' EXIT",
        'cat > "$hal_unit_stage/' + service + '"',
        'sudo systemd-analyze verify "$hal_unit_stage/' + service + '"',
        'sudo install -m 0644 -- "$hal_unit_stage/' + service + '" /etc/systemd/system/' + service,
        'sudo systemctl daemon-reload',
        'sudo systemctl enable ' + service,
        'if ! sudo systemctl restart ' + service + '; then',
        '  sudo systemctl --no-pager --full status ' + service + ' || true',
        '  exit 1', 'fi',
    ])
    try:
        ssh(role, command, data=unit.encode())
    except subprocess.CalledProcessError as exc:
        raise ValueError('Service validation or startup failed for ' + service +
                         ' on the ' + role + ' VM. See the systemd output above. '
                         'Fix the reported error and rerun deploy with the same keys and configuration.') from exc


def remote_command(info, ssh_key, role, command, data=None, capture=False):
    vm = info['vms'][role]
    args = ['ssh', '-i', str(Path(ssh_key).expanduser().resolve()),
            '-o', 'StrictHostKeyChecking=accept-new', '-o', 'ConnectTimeout=10',
            vm['ssh_user'] + '@' + vm['ip'], command]
    try:
        result = subprocess.run(args, input=data, stdout=subprocess.PIPE if capture else None, check=True)
    except FileNotFoundError as exc:
        raise ValueError('OpenSSH client was not found. On Windows enable the OpenSSH Client optional feature '
                         'and check ssh -V in PowerShell; see WINDOWS.md.') from exc
    except subprocess.CalledProcessError as exc:
        raise ValueError('Remote command failed on the ' + role + ' VM (' + vm['ip'] +
                         '), exit status ' + str(exc.returncode) + '. See the remote error above. '
                         'Deployment stopped; keep your existing keys and configuration.') from exc
    return result.stdout.decode('utf-8') if capture else None


def identity_network_check(ssh, role, identity_url, ca_pem):
    probe = Path(__file__).with_name('network_probe.py').read_text(encoding='utf-8')
    settings = json.dumps(dict(url=identity_url, ca_pem=ca_pem, timeout=5)).encode()
    result = parse(ssh(role, 'python3 -c ' + shlex.quote(probe), data=settings, capture=True))
    require(isinstance(result, dict) and type(result.get('ok')) is bool, 'Invalid network probe response')
    return dict(result, source_role=role, destination=identity_url + '/v1/trust')


def network_check(inventory_path, credentials, ssh_key, from_role=None):
    info = inventory(inventory_path)
    credentials = Path(credentials)
    require(parse((credentials / 'inventory.json').read_text(encoding='utf-8-sig')) == info, 'Certificates belong to a different VM inventory')
    ca_pem = (credentials / 'ca.pem').read_text()
    identity_url = 'https://' + info['vms']['identity']['ip']

    def ssh(role, command, data=None, capture=False):
        return remote_command(info, ssh_key, role, command, data, capture)

    checks = []
    for role in ([from_role] if from_role else ('files', 'execution', 'management')):
        print('Checking ' + role + ' VM -> ' + identity_url + ':443', flush=True, file=sys.stderr)
        checks.append(identity_network_check(ssh, role, identity_url, ca_pem))
    return dict(ok=all(row['ok'] for row in checks), checks=checks,
                vm_source_ranges=[vm['ip'] + '/32' for vm in info['vms'].values()],
                note='Read-only check; no jobs submitted or service state changed. If a check times out, '
                     'check TCP 443 ingress to identity from these VM source ranges, VM egress, and OS firewalls. '
                     'Keep your laptop source range allowed too. TLS failures require checking the CA/certificate.')


def deploy(root, inventory_path, credentials, ssh_key, operator_path, install_dependencies, portable_profile=None):
    """Run only when the operator explicitly invokes deploy. No passwords in argv."""
    info = inventory(inventory_path)
    credentials, ssh_key = Path(credentials).resolve(), Path(ssh_key).expanduser().resolve()
    require(parse((credentials / 'inventory.json').read_text(encoding='utf-8-sig')) == info, 'Certificates belong to a different VM inventory')
    operator = key_from_hex(read_private(operator_path)['private_key'])
    portable = None
    if portable_profile:
        from .portable_install import prepare
        portable = prepare(portable_profile, credentials)

    from .tls_certificates import validate
    validate(info, credentials)
    endpoints = {r: 'https://' + info['vms'][r]['ip'] for r in ROLES}
    prefix = 'hal-fleet'
    transport = Transport(timeout=15, ca_file=str(credentials / 'ca.pem'))
    with tempfile.TemporaryDirectory(prefix='hal-package-') as temp:
        bundle = Path(temp) / 'source.tar.gz'
        package(root, bundle)

        def ssh(role, command, data=None, capture=False):
            return remote_command(info, ssh_key, role, command, data, capture)

        fingerprint = None
        for role in ROLES:
            print('Installing ' + role + ' on ' + info['vms'][role]['ip'], flush=True)
            if role != 'identity':
                # Catch inter-VM HTTPS failures before copying/installing/building
                # this role. Laptop reachability does not establish VM reachability.
                check = identity_network_check(ssh, role, endpoints['identity'], (credentials / 'ca.pem').read_text())
                require(check['ok'], role + ' VM (' + info['vms'][role]['ip'] + ') cannot read ' +
                        check['destination'] + ': ' + check.get('error_kind', '') + ': ' + check.get('error', '') +
                        '. No job was submitted. Check identity TCP 443 ingress from ' + info['vms'][role]['ip'] +
                        '/32, VM egress/OS firewall, and TLS certificates. Keep existing keys and configuration.',
                        502, 'network_check_failed')
            ssh(role, source_unpack_command(prefix), bundle.read_bytes())
            base = prefix + '/hal-on-demand'
            if install_dependencies:
                ssh(role, 'sudo apt-get update')
                packages = 'python3-venv python3-pip ca-certificates'
                if role == 'execution':
                    packages += ' build-essential pkg-config cmake libssl-dev libtss2-dev docker.io curl'
                ssh(role, 'sudo apt-get install -y ' + packages)
            ssh(role, 'cd ' + base + ' && python3 -m venv .venv && .venv/bin/python -m pip install -r requirements-signing.txt')
            memory = io.BytesIO()
            with tarfile.open(fileobj=memory, mode='w:gz') as archive:
                for name in ('ca.pem', role + '.key', role + '.crt'):
                    add_archive_file(archive, credentials / name, name, private=name.endswith('.key'))
            ssh(role, 'cd ' + base + ' && umask 077 && mkdir -p tls && tar -xzf - -C tls', memory.getvalue())
            py = '.venv/bin/python fleet.py'
            sudo = 'sudo ' if role == 'execution' else ''
            if role == 'execution':
                # A running Linux executable cannot be overwritten by build.py.
                # Stop this deployment only; leave older experiments alone.
                ssh(role, 'if sudo systemctl cat hal-fleet-execution.service >/dev/null 2>&1; '
                    'then sudo systemctl stop hal-fleet-execution.service; fi')
                # Reuse an existing rustup installation; install it only if explicitly requested.
                if install_dependencies:
                    ssh(role, "test -x \"$HOME/.cargo/bin/rustup\" || "
                        "(curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal "
                        "--default-toolchain " + RUST_TOOLCHAIN + ")")
                    ssh(role, 'sudo systemctl enable --now docker')
                ssh(role, 'cd ' + base + ' && sudo .venv/bin/python -m hal_fleet.gvisor setup'
                    + (' --install-dependencies' if install_dependencies else ''))
                ssh(role, 'cd ' + base + ' && PATH="$HOME/.cargo/bin:$PATH" .venv/bin/python build.py --install-target')
                ssh(role, 'cd ' + base + ' && sudo .venv/bin/python -B hal_fleet/worker_image.py')
                # --help verifies image loading, but not config mounts or private
                # IPC. Exercise real signed jobs under the service's 0077 umask
                # before activating the execution API. Tests own all their state.
                ssh(role, 'cd ' + base + ' && sudo .venv/bin/python -B tests/test_docker_workers.py '
                    '--image hal-user-worker:local --signed-jobs')
            command = [*(['sudo'] if role == 'execution' else []), '.venv/bin/python', 'fleet.py', 'init',
                '--role', role, '--listen', '0.0.0.0:443', '--identity-url', endpoints['identity'],
                '--ca-file', 'tls/ca.pem', '--tls-cert', 'tls/' + role + '.crt', '--tls-key', 'tls/' + role + '.key']
            if role == 'identity':
                command += ['--operator-public-key', public(operator)]
                for dest in ('management', 'execution', 'files'):
                    command += ['--' + dest + '-url', endpoints[dest]]
            else:
                command += ['--issuer-sha256', fingerprint]
            ssh(role, 'cd ' + base + ' && if ! ' + sudo + 'test -f state/fleet.json; then ' + shlex.join(command) + '; fi')
            if role == 'execution':
                # Explicit deploy rebuilt operator-selected local code, so record its new pins once.
                ssh(role, 'cd ' + base + ' && sudo .venv/bin/python fleet.py trust-build --apply')
            if portable and role != 'identity':
                from .portable_install import install_role
                install_role(ssh, role, base, portable)
            unit = ssh(role, 'cd ' + base + ' && ' + sudo + py + ' unit', capture=True)
            install_service(ssh, role, unit)
            deadline = time.monotonic() + 45
            while True:
                try:
                    transport.call(endpoints[role], '/health')
                    break
                except Exception as exc:
                    require(time.monotonic() < deadline, 'HTTPS health check failed for ' + role + ': ' + str(exc) +
                            '. Check TCP 443 firewall and systemd logs.')
                    time.sleep(1)
            if role == 'identity':
                from .common import DOCUMENT_DOMAIN, verify
                # The CA authenticates this endpoint; pin the separate authorization signing key too.
                envelope = transport.call(endpoints['identity'], '/v1/trust')
                candidate = parse(envelope['payload'])
                trust = verify(candidate['identity_public_key'], DOCUMENT_DOMAIN, envelope)
                require(trust['operator_public_key'] == public(operator) and trust['endpoints'] == endpoints,
                        'Existing deployment has a different publisher or endpoints')
                fingerprint = digest(bytes.fromhex(trust['identity_public_key']))
        # Relative to deployment.json, so the public client bootstrap can move
        # between operator/user computers without embedding a Windows/Mac path.
        capabilities = transport.call(endpoints['management'], '/v1/capabilities')
        architecture = capabilities['execution_architecture']
        require(not portable or architecture == 'hal-managed-agent-v2', 'Management did not activate the portable agent profile')
        result = dict(endpoints=endpoints, issuer_sha256=fingerprint, ca_file='ca.pem',
                      source_sha256=digest(bundle.read_bytes()), execution_architecture=architecture)
        atomic_json(credentials / 'deployment.json', result)
        return result
