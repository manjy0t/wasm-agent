#!/usr/bin/env python3
"""Create separate deployment bundles; never replace existing credentials or state."""
import argparse
import json
import os
from pathlib import Path
import secrets
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent / 'server'))
from management import load_catalog, NAME


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--catalog', default='workloads.json', type=Path)
    p.add_argument('--tenant', action='append', required=True)
    p.add_argument('--output', required=True, type=Path)
    args = p.parse_args()
    if (not 1 <= len(args.tenant) <= 64 or len(set(args.tenant)) != len(args.tenant)
            or any(not NAME.fullmatch(t) or len(t) > 64 or t == 'legacy' or t != t.lower() for t in args.tenant)):
        p.error('provide unique lowercase tenant IDs (1..64 characters), excluding legacy')
    cases = load_catalog(args.catalog)
    # Fail on an existing directory, even if it is empty. Rerunning never rotates tokens accidentally.
    args.output.mkdir(mode=0o700, parents=True, exist_ok=False)
    for folder in ('management', 'execution', 'file-server', 'clients'):
        (args.output / folder).mkdir(mode=0o700)

    def write(path, content):
        path = args.output / path
        with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'w') as stream:
            stream.write(content + '\n')

    admin_api, admin_worker, file_token = (secrets.token_hex(32) for _ in range(3))
    write('management/api.token', admin_api)
    write('management/worker.token', admin_worker)
    write('execution/operator.token', admin_worker)
    write('execution/file.token', file_token)
    write('file-server/file.token', file_token)
    workers, managers = [], []
    artifacts = [{'component': c['artifact'], 'sha256': c['sha256'], 'artifact_bytes': c['artifact_bytes']}
                 for c in cases.values()]
    for tenant in args.tenant:
        api_token, worker_token = secrets.token_hex(32), secrets.token_hex(32)
        write(f'clients/{tenant}.token', api_token)
        write(f'management/{tenant}-api.token', api_token)
        write(f'management/{tenant}-worker.token', worker_token)
        write(f'execution/{tenant}.token', worker_token)
        workers.append(dict(id=tenant, token_file=f'{tenant}.token', artifacts=artifacts,
                            cache_bytes=268435456, compiled_cache_entries=16,
                            storage_bytes=16777216, storage_entries=1024, max_inflight=4))
        managers.append(dict(id=tenant, api_token_file=f'{tenant}-api.token',
                             worker_token_file=f'{tenant}-worker.token', cases=list(cases)))
    write('execution/policy.json', json.dumps(dict(version=1, tenants=workers), indent=2))
    write('management/policy.json', json.dumps(dict(version=1, tenants=managers), indent=2))
    write('management/workloads.json', json.dumps(dict(cases=list(cases.values())), indent=2))
    print('Created deployment bundles in', args.output)
    print('Copy only the matching bundle to each VM. Give clients only their own client token.')
    print('Operator credentials inspect statistics; tenant credentials submit and read their own jobs.')


if __name__ == '__main__':
    main()
