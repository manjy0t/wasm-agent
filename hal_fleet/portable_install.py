"""Operator-side bootstrap for portable agents over the existing SSH installer."""
import io
import json
from pathlib import Path
import shlex
import tarfile
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from .attested_channel import MAX_AGENT, validate_policy
from .common import atomic_json, parse, private_hex, public, key_from_hex, read_private, require


def prepare(path, credentials):
    path = Path(path).resolve()
    profile = parse(path.read_text(encoding='utf-8-sig'))
    require(profile.get('version') == 1 and profile.get('platform') in ('intel-tdx', 'amd-sev-snp'), 'Invalid portable deployment profile')
    def local(name):
        value = Path(profile[name])
        return value if value.is_absolute() else path.parent / value
    policy = validate_policy(parse(local('attestation_policy').read_text()))
    require(policy['platform'] == profile['platform'], 'Verifier policy and execution platform differ')
    agent = local('managed_agent').read_bytes()
    require(agent.startswith(b'\0asm') and len(agent) <= MAX_AGENT, 'Build the management agent before deploying')
    key_path = Path(credentials) / 'management-signing.json'
    if not key_path.exists():
        key = Ed25519PrivateKey.generate()
        atomic_json(key_path, dict(private_key=private_hex(key), public_key=public(key)), exclusive=True)
    key = read_private(key_path)
    public_key = public(key_from_hex(key['private_key']))
    return dict(platform=profile['platform'], policy=policy, agent=agent, key=key,
                public_key=public_key, agent_configuration=profile.get('agent_configuration', {}))


def install_role(ssh, role, base, setup):
    profile = dict(version=1, role=role)
    files = {}
    if role in ('files', 'execution'):
        profile['trusted_management_keys'] = [setup['public_key']]
    if role == 'files':
        pass
    elif role == 'execution':
        profile.update(platform=setup['platform'], runner='../../dist/hal-agent-runner', agent_runtime_dir='/run/hal-agents')
    elif role == 'management':
        profile.update(management_key='management-signing.json', managed_agent='agent.wasm',
                       attestation_policy='attestation-policy.json', agent_configuration=setup['agent_configuration'])
        files.update({'management-signing.json': setup['key'], 'attestation-policy.json': setup['policy'], 'agent.wasm': setup['agent']})
    else:
        raise ValueError('Unexpected portable service role')
    files['profile.json'] = profile
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode='w:gz') as archive:
        for name, value in files.items():
            raw = value if isinstance(value, bytes) else (json.dumps(value, indent=2) + '\n').encode()
            entry = tarfile.TarInfo(name)
            entry.size, entry.mode = len(raw), 0o600
            archive.addfile(entry, io.BytesIO(raw))
    # Only management receives its signing key, private agent config and policy.
    # The execution VM receives agent bytes and credentials later through attestation.
    sudo = 'sudo ' if role == 'execution' else ''
    command = 'cd ' + shlex.quote(base) + ' && ' + sudo + "sh -c 'umask 077; mkdir -p state/portable; tar -xzf - -C state/portable'"
    ssh(role, command, buffer.getvalue())
    ssh(role, 'cd ' + shlex.quote(base) + ' && ' + sudo +
        '.venv/bin/python fleet.py configure-agent --config state/fleet.json --profile state/portable/profile.json --apply')
