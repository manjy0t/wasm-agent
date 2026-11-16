#!/usr/bin/env python3
"""Provision public execution rules and separate private client signing configs.

Run on an operator-controlled machine. This creates a NEW directory only. It
never changes services, existing keys, tokens, or results. Do not copy the private
client configs to management, file server, broker, or worker containers.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
from job_signing import rule_digest


def write_new(path, value):
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'w') as stream:
        json.dump(value, stream, indent=2)
        stream.write('\n')


def generate(tenant_policy, agent_policy, catalog, audience, isolation, ttl, output):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,199}', audience):
        raise ValueError('audience must be a safe deployment name, e.g. intel-worker-1')
    if not 1 <= ttl <= 300 or isolation not in ('in-process', 'per-user-container'):
        raise ValueError('invalid ticket lifetime or isolation')
    tenants = json.loads(Path(tenant_policy).read_text())['tenants']
    rules = json.loads(Path(agent_policy).read_text())['workloads']
    cases = {c['artifact']: c for c in json.loads(Path(catalog).read_text())['cases']}
    prepared = []
    for tenant in tenants:
        name = tenant['id']
        if not re.fullmatch(r'[a-z0-9][a-z0-9_.-]{0,63}', name):
            raise ValueError('invalid user name')
        workloads = []
        for artifact in tenant['artifacts']:
            rule = next(r for r in rules if r['tenant'] == name and r['component'] == artifact['component'])
            case = cases[artifact['component']]
            if (rule['sha256'] != artifact['sha256'] or case['sha256'] != artifact['sha256']
                    or case['artifact_bytes'] != artifact['artifact_bytes']):
                raise ValueError('agent rule, tenant policy and catalog disagree')
            workloads.append(dict(component=artifact['component'], sha256=artifact['sha256'],
                artifact_bytes=artifact['artifact_bytes'], rule_sha256=rule_digest(rule),
                case=case['name'], cache_allowed=rule['cache'] == 'memory'))
        key = Ed25519PrivateKey.generate()
        public = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
        private = key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()).hex()
        prepared.append((name, public, private, workloads))
    output = Path(output)
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    (output / 'execution-public').mkdir(mode=0o700)
    (output / 'clients-private').mkdir(mode=0o700)
    users = []
    for name, public, private, workloads in prepared:
        users.append(dict(tenant=name, public_key=public,
            workloads=[{k: v for k, v in w.items() if k not in ('case', 'cache_allowed')} for w in workloads]))
        write_new(output / 'clients-private' / (name + '.json'), dict(version=1, tenant=name,
            public_key=public, private_key=private, audience=audience, isolation=isolation,
            max_ttl_seconds=ttl, workloads=workloads))
    write_new(output / 'execution-public/job-authorization.json', dict(version=1, audience=audience,
        isolation=isolation, max_ttl_seconds=ttl, users=users))
    return output


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--tenant-policy', type=Path, required=True)
    p.add_argument('--agent-policy', type=Path, required=True)
    p.add_argument('--catalog', type=Path, default=Path('workloads.json'))
    p.add_argument('--audience', required=True)
    p.add_argument('--isolation', choices=('per-user-container', 'in-process'), default='per-user-container')
    p.add_argument('--ttl-seconds', type=int, default=120)
    p.add_argument('--output-dir', type=Path, required=True)
    args = p.parse_args()
    try:
        output = generate(args.tenant_policy, args.agent_policy, args.catalog, args.audience,
                          args.isolation, args.ttl_seconds, args.output_dir)
    except ImportError:
        p.error('install requirements-signing.txt in a virtual environment on the provisioning/client machine')
    print('Public execution policy:', output / 'execution-public/job-authorization.json')
    print('Private client configs:', output / 'clients-private')
    print('Keep private configs with their individual users. Do not give them to the dispatcher or execution host.')


if __name__ == '__main__':
    main()
