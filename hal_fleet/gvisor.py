"""Install/check the fixed per-user sandbox on the Linux execution VM only.

The native launcher embeds the same profile and refuses any other runtime.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile

SPEC = Path(__file__).resolve().parents[1] / 'src/gvisor-runtime.json'
DOCKER = ['/usr/bin/docker', '--host', 'unix:///var/run/docker.sock']
DAEMON = Path('/etc/docker/daemon.json')


def profile():
    return json.loads(SPEC.read_text())


def command(args, timeout=60):
    try:
        result = subprocess.run(args, check=True, capture_output=True, text=True,
                                timeout=timeout, env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin'})
        return result.stdout.strip()
    except subprocess.CalledProcessError as exc:
        raise ValueError('Sandbox setup/check failed: ' + ' '.join(args[:3]) + ': '
                         + (exc.stderr or exc.stdout or str(exc))[-3000:].strip()) from exc
    except subprocess.TimeoutExpired as exc:
        raise ValueError('Sandbox setup/check timed out: ' + ' '.join(args[:3])) from exc


def runtime_entry():
    spec = profile()
    return {key: spec[key] for key in ('path', 'runtimeArgs')}


def validate_info(info):
    spec = profile()
    actual = info.get('Runtimes', {}).get(spec['runtime'], {})
    if any(actual.get(key) != value for key, value in runtime_entry().items()):
        raise ValueError('Required hal-gvisor runtime is missing or misconfigured. Run '
                         'sudo .venv/bin/python -m hal_fleet.gvisor setup on the execution VM; no fallback is allowed.')
    if info.get('OSType') != 'linux':
        raise ValueError('gVisor workers require a Linux Docker daemon')


def check():
    if sys.platform != 'linux':
        raise ValueError('gVisor runs on the Linux execution VM, not the client computer')
    spec = profile()
    binary = Path(spec['path'])
    metadata = binary.stat()
    if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0
            or metadata.st_mode & 0o022 or not os.access(binary, os.X_OK)):
        raise ValueError('runsc must be a root-owned executable, not writable by other users')
    version = command([str(binary), *spec['runtimeArgs'], '--version'])
    if not version.startswith('runsc version '):
        raise ValueError('Unexpected runsc version response')
    info = json.loads(command([*DOCKER, 'info', '--format={{json .}}']))
    validate_info(info)
    # Configuration/software identity, not proof of a successful sandbox boot or
    # an independently hardware-measured runsc binary. Deployment runs real jobs.
    return dict(profile=spec, configuration_checked=True, version=version,
                runsc_sha256=hashlib.sha256(binary.read_bytes()).hexdigest())


def merged_config(existing):
    if not isinstance(existing, dict) or not isinstance(existing.get('runtimes', {}), dict):
        raise ValueError('Docker daemon configuration must contain a runtimes object')
    result = dict(existing)
    runtimes = dict(existing.get('runtimes', {}))
    name = profile()['runtime']
    if name in runtimes and runtimes[name] != runtime_entry():
        raise ValueError('Existing hal-gvisor registration conflicts with the required profile. '
                         'Review it explicitly; other runtimes and the Docker default are not changed.')
    runtimes[name] = runtime_entry()
    result['runtimes'] = runtimes
    return result


def write_atomic(path, data, mode=0o644):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix='.' + path.name + '-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as output:
            output.write(data)
            output.flush()
            os.fchmod(output.fileno(), mode)
            os.fsync(output.fileno())
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def configure_daemon(path=DAEMON):
    path = Path(path)
    if path.is_symlink() or (path.exists() and not path.is_file()):
        raise ValueError('Refusing to replace a non-regular Docker configuration')
    before = path.read_bytes() if path.exists() else None
    existing = json.loads(before) if before is not None else {}
    updated = merged_config(existing)
    if updated == existing:
        return check()
    if command([*DOCKER, 'ps', '--quiet', '--filter', 'label=hal.broker']):
        raise ValueError('Stop active HAL execution services before changing the sandbox runtime')
    data = (json.dumps(updated, indent=2) + '\n').encode()
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='hal-docker-validate-', dir=path.parent) as folder:
        candidate = Path(folder) / 'daemon.json'
        candidate.write_bytes(data)
        daemon = shutil.which('dockerd', path='/usr/sbin:/usr/bin:/sbin:/bin')
        if not daemon:
            raise ValueError('dockerd is not installed')
        command([daemon, '--validate', '--config-file', str(candidate)])
    backup = None
    mode = stat.S_IMODE(path.stat().st_mode) if before is not None else 0o644
    if before is not None:
        fd, name = tempfile.mkstemp(prefix='daemon.json.hal-backup-', dir=path.parent)
        with os.fdopen(fd, 'wb') as output:
            output.write(before)
        backup = name
    if path.is_symlink() or (path.read_bytes() if path.exists() else None) != before:
        raise ValueError('Docker configuration changed during validation; retry after reviewing the change')
    write_atomic(path, data, mode)
    try:
        command(['/usr/bin/systemctl', 'reload', 'docker'])
        result = check()
    except Exception as exc:
        # Never replace an operator's concurrent edit during rollback.
        if path.read_bytes() != data:
            raise ValueError('Docker configuration changed concurrently; automatic rollback refused. '
                             'Original backup: ' + str(backup)) from exc
        if before is None:
            path.unlink()
        else:
            write_atomic(path, before, mode)
        try:
            command(['/usr/bin/systemctl', 'reload', 'docker'])
        except Exception as rollback:
            raise ValueError('Restored Docker configuration, but reload failed: ' + str(rollback)) from exc
        raise
    return dict(result, docker_configuration_changed=True, backup=backup)


def install_package():
    # Use the official signed repository: modern runsc also needs gvisor-bin
    # sidecars. Downloading just a standalone runsc binary is insufficient.
    command(['/usr/bin/apt-get', 'update'], timeout=900)
    command(['/usr/bin/apt-get', 'install', '-y', 'ca-certificates', 'curl', 'gnupg'], timeout=900)
    architecture = command(['/usr/bin/dpkg', '--print-architecture'])
    if architecture not in ('amd64', 'arm64'):
        raise ValueError('Unsupported gVisor package architecture: ' + architecture)
    with tempfile.TemporaryDirectory(prefix='hal-gvisor-key-') as folder:
        source, key = Path(folder) / 'archive.key', Path(folder) / 'archive.gpg'
        command(['/usr/bin/curl', '--proto', '=https', '--tlsv1.2', '--fail', '--silent',
                 '--show-error', '--location', '--output', str(source), 'https://gvisor.dev/archive.key'])
        command(['/usr/bin/gpg', '--batch', '--yes', '--dearmor', '--output', str(key), str(source)])
        write_atomic('/usr/share/keyrings/gvisor-archive-keyring.gpg', key.read_bytes())
    entry = ('deb [arch=' + architecture + ' signed-by=/usr/share/keyrings/gvisor-archive-keyring.gpg] '
             'https://storage.googleapis.com/gvisor/releases release main\n')
    write_atomic('/etc/apt/sources.list.d/hal-gvisor.list', entry.encode())
    command(['/usr/bin/apt-get', 'update'], timeout=900)
    command(['/usr/bin/apt-get', 'install', '-y', 'runsc'], timeout=900)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('setup', 'check'))
    parser.add_argument('--install-dependencies', action='store_true')
    args = parser.parse_args()
    if args.action == 'check':
        if args.install_dependencies:
            parser.error('--install-dependencies is only valid with setup')
        result = check()
    else:
        if sys.platform != 'linux' or os.geteuid() != 0:
            raise ValueError('Run setup with sudo on the Linux execution VM')
        if args.install_dependencies:
            if command([*DOCKER, 'ps', '--quiet', '--filter', 'label=hal.broker']):
                raise ValueError('Stop active HAL execution services before upgrading runsc')
            install_package()
        elif not Path(profile()['path']).is_file():
            raise ValueError('runsc is missing; use setup --install-dependencies to install it')
        result = configure_daemon()
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError) as exc:
        print('Error: ' + str(exc), file=sys.stderr)
        sys.exit(1)
