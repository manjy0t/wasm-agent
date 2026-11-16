#!/usr/bin/env python3
"""Generate a reviewable Wasm-agent policy for an existing execution tenant bundle.

Creates a new file only. Does not rotate tokens, start services or change results.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--tenant-policy', type=Path, required=True)
    parser.add_argument('--catalog', type=Path, default=Path('workloads.json'))
    parser.add_argument('--agent', type=Path, default=Path('dist/agent.wasm'))
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--cache', choices=('memory', 'disabled'), default='memory')
    parser.add_argument('--cache-ttl-seconds', type=int, default=300)
    args = parser.parse_args()
    if not 1 <= args.cache_ttl_seconds <= 86400:
        parser.error('cache TTL must be 1..86400 seconds')
    tenants = json.loads(args.tenant_policy.read_text())['tenants']
    cases = json.loads(args.catalog.read_text())['cases']
    catalog = {c['artifact']: c for c in cases}
    groups = {'sha256-abc': ['crypto'], 'sha512-abc': ['crypto'], 'random-32': ['random'],
              'platform': [], 'clock': ['clock']}
    rows = []
    for tenant in tenants:
        for artifact in tenant['artifacts']:
            case = catalog[artifact['component']]
            if (case['sha256'] != artifact['sha256'] or case['artifact_bytes'] != artifact['artifact_bytes']):
                parser.error('catalog differs from tenant artifact allowlist')
            if case['name'] not in groups:
                parser.error('unknown workload: create an explicit policy instead of guessing its permissions')
            rows.append(dict(tenant=tenant['id'], component=artifact['component'], sha256=artifact['sha256'],
                cache=args.cache, cache_ttl_ms=args.cache_ttl_seconds * 1000,
                hal_permissions=groups[case['name']], memory_mib=64, fuel=1000000000,
                execution_timeout_ms=5000, max_output_bytes=4096, worker_max_jobs=128,
                validation=case['validation']))
    policy = dict(version=1, agent_sha256=hashlib.sha256(args.agent.read_bytes()).hexdigest(), workloads=rows)
    with os.fdopen(os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'w') as stream:
        json.dump(policy, stream, indent=2)
        stream.write('\n')
    print('Created agent policy:', args.output)
    print('Review permissions, limits and expected outputs. Build the guest and host together before deployment.')


if __name__ == '__main__':
    main()
