"""Explicit migration of service configuration; existing identity/user keys stay intact."""
import copy
from pathlib import Path
from .attested_channel import ABI, PROTOCOL, MAX_AGENT, validate_policy
from .common import SHA, atomic_json, digest, key_from_hex, parse, public, read_private, require
from .policy import SETTINGS


def configure(config_path, profile_path, apply=False):
    config_path, profile_path = Path(config_path), Path(profile_path)
    config = parse(config_path.read_text())
    profile = parse(profile_path.read_text())
    require(profile.get('version') == 1 and profile.get('role') == config['role'], 'Profile role/version mismatch')
    updated = copy.deepcopy(config)
    role = config['role']
    require(config.get('tls_cert') and config.get('tls_key')
            and all(url.startswith('https://') for url in config['trust']['endpoints'].values()),
            'Portable deployment requires HTTPS on all four services')
    def local(name):
        value = Path(profile[name])
        return value.resolve() if value.is_absolute() else (profile_path.parent / value).resolve()
    if role in ('execution', 'files'):
        keys = profile.get('trusted_management_keys')
        require(isinstance(keys, list) and 1 <= len(keys) <= 32 and all(isinstance(k, str) and SHA.fullmatch(k) for k in keys),
                'Supply trusted management public keys')
        updated['trusted_management_keys'] = keys
    if role == 'execution':
        require(profile.get('platform') in ('intel-tdx', 'amd-sev-snp'), 'Choose the actual confidential platform')
        if 'execution_url' in profile:
            from urllib.parse import urlsplit
            endpoint = urlsplit(profile['execution_url'])
            require(endpoint.scheme == 'https' and endpoint.hostname and not endpoint.username and not endpoint.password
                    and endpoint.path in ('', '/') and not endpoint.query and not endpoint.fragment, 'Invalid execution URL')
            updated['execution_url'] = profile['execution_url'].rstrip('/')
        runner = local('runner')
        require(runner.is_file(), 'Build hal-agent-runner first')
        updated.update(execution_architecture=PROTOCOL, platform=profile['platform'], mode='wasm',
                       runner=str(runner), runner_sha256=digest(runner.read_bytes()), allow_non_tee=False,
                       test_in_process=False, agent_runtime_dir=profile.get('agent_runtime_dir', '/run/hal-agents'))
        updated.setdefault('settings', SETTINGS)
        updated.setdefault('max_active_users', 4)
        if 'max_active_users' in profile:
            require(type(profile['max_active_users']) is int and 1 <= profile['max_active_users'] <= 64, 'User broker limit must be 1..64')
            updated['max_active_users'] = profile['max_active_users']
        updated.setdefault('container_image', 'hal-user-worker:local')
    elif role == 'management':
        agent, key, policy = local('managed_agent'), local('management_key'), local('attestation_policy')
        raw = agent.read_bytes()
        require(raw.startswith(b'\0asm') and len(raw) <= MAX_AGENT, 'Invalid management-supplied Wasm agent')
        public(key_from_hex(read_private(key)['private_key']))
        validate_policy(parse(policy.read_text()))
        targets = profile.get('execution_targets')
        if targets is not None:
            from urllib.parse import urlsplit
            require(isinstance(targets, list) and 1 <= len(targets) <= 32, 'Supply 1..32 execution targets')
            prepared = []
            for entry in targets:
                require(set(entry) == {'url', 'attestation_policy'}, 'Each target needs URL and attestation policy')
                url = urlsplit(entry['url'])
                require(url.scheme == 'https' and url.hostname and not url.username and not url.password
                        and url.path in ('', '/') and not url.query and not url.fragment, 'Invalid execution URL')
                target_policy = Path(entry['attestation_policy'])
                if not target_policy.is_absolute():
                    target_policy = (profile_path.parent / target_policy).resolve()
                validate_policy(parse(target_policy.read_text()))
                prepared.append(dict(url=entry['url'].rstrip('/'), attestation_policy=str(target_policy)))
            require(len({t['url'] for t in prepared}) == len(prepared), 'Duplicate execution targets')
            updated['execution_targets'] = prepared
        updated.update(execution_architecture=PROTOCOL, managed_agent=str(agent), managed_agent_sha256=digest(raw),
                       management_key=str(key), attestation_policy=str(policy),
                       agent_configuration=profile.get('agent_configuration', {}))
    elif role == 'files':
        updated['protected_artifacts'] = True
    else:
        require(False, 'Identity service does not need a portable-agent profile')
    if apply:
        atomic_json(config_path, updated)
    return dict(role=role, applied=apply, execution_architecture=updated.get('execution_architecture'),
                interface=ABI if role != 'files' else None, protected_artifacts=updated.get('protected_artifacts'),
                config=str(config_path))
