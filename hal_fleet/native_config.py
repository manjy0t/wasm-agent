"""Create a separate native configuration without rewriting any agent state."""
import copy
from pathlib import Path
import secrets
import time
from .common import atomic_json, digest, key_from_hex, public, read_private, require, sign
from .native_audit import PROFILE, CERT_DOMAIN, identity_from_certificate


def service_digest(root=None):
    root = Path(root) if root else Path(__file__).resolve().parents[1]
    files = sorted((root / 'hal_fleet').glob('*.py')) + [root / 'fleet.py']
    from .common import canonical
    return digest(canonical({p.relative_to(root).as_posix(): digest(p.read_bytes()) for p in files}).encode())


def issue_certificate(management_key, native_public_key, output, days=30):
    from .common import SHA
    require(isinstance(native_public_key, str) and SHA.fullmatch(native_public_key), 'Invalid native public key')
    require(type(days) is int and 1 <= days <= 365, 'Certificate lifetime must be 1..365 days')
    key = key_from_hex(read_private(management_key)['private_key'])
    now = int(time.time())
    identity = dict(profile=PROFILE, public_key=native_public_key, management_key=public(key),
                    vm_id=secrets.token_hex(32), instance=secrets.token_hex(32))
    cert = sign(key, CERT_DOMAIN, dict(version=1, kind='native-identity', identity=identity,
                                     issued_unix=now, expires_unix=now + days * 86400))
    atomic_json(Path(output), cert, exclusive=True)
    return dict(certificate=str(output), identity=identity, attestation_verified=False)


def configure(config_path, profile_path, output):
    config_path, profile_path, output = map(lambda p: Path(p).resolve(), (config_path, profile_path, output))
    config, profile = read_private(config_path), read_private(profile_path)
    role = config['role']
    require(role in ('execution', 'management') and profile.get('version') == 1 and profile.get('role') == role,
            'Native audit profile must match execution or management role')
    require(output != config_path and not output.exists(), 'Use a new native config path; existing profiles are never overwritten')
    state = output.parent / (output.stem + '-state')
    old_state = Path(config['state_dir']).resolve()
    require(not state.exists() and state != old_state and old_state not in state.parents and state not in old_state.parents,
            'Use a fresh native state directory separate from existing state')
    require(config.get('tls_cert') and config.get('tls_key')
            and all(url.startswith('https://') for url in config['trust']['endpoints'].values()), 'Native audited services require HTTPS')
    def local(name):
        path = Path(profile[name])
        return str(path.resolve() if path.is_absolute() else (profile_path.parent / path).resolve())
    certificate = read_private(local('native_certificate'))
    updated = copy.deepcopy(config)
    # Agent deployment channels and credential paths do not belong to native state.
    for name in ('runner', 'runner_sha256', 'managed_agent', 'managed_agent_sha256', 'agent_runtime_dir',
                 'agent_configuration', 'attestation_policy', 'execution_targets', 'trusted_management_keys'):
        updated.pop(name, None)
    updated.update(execution_architecture=PROFILE, state_dir=str(state), native_certificate=local('native_certificate'),
                   service_sha256=service_digest())
    if role == 'execution':
        key = key_from_hex(read_private(local('native_key'))['private_key'])
        owner = profile['management_public_key']
        require(owner not in config.get('trusted_management_keys', []), 'Use a distinct native management signing identity')
        identity = identity_from_certificate(certificate, owner)['identity']
        require(identity['public_key'] == public(key), 'Native certificate/key mismatch')
        require(Path(config['binary']).is_file(), 'Build the native host before configuring')
        updated.update(mode='native', native_key=local('native_key'), management_public_key=owner,
                       binary_sha256=digest(Path(config['binary']).read_bytes()), test_in_process=False)
        if 'settings' in profile:
            from .policy import SETTINGS
            require(isinstance(profile['settings'], dict) and set(profile['settings']) <= set(SETTINGS), 'Unknown runtime settings')
            updated['settings'] = dict(config.get('settings', SETTINGS), **profile['settings'])
    else:
        key = key_from_hex(read_private(local('management_key'))['private_key'])
        if config.get('execution_architecture') == 'hal-managed-agent-v2' and config.get('management_key'):
            require(public(key) != public(key_from_hex(read_private(config['management_key'])['private_key'])),
                    'Use a distinct native management signing identity')
        identity = identity_from_certificate(certificate, public(key))['identity']
        updated['management_key'] = local('management_key')
    cert = identity_from_certificate(certificate, identity['management_key'])
    require(cert['issued_unix'] <= time.time() + 5 < cert['expires_unix'], 'Native certificate expired or not yet valid')
    # Validate all inputs before creating anything. No live services are restarted.
    state.mkdir(parents=True, mode=0o700, exist_ok=False)
    atomic_json(output, updated, exclusive=True)
    return dict(config=str(output), state_dir=str(state), execution_architecture=PROFILE,
                native_identity=identity, cache='bypass', attestation_verified=False)
