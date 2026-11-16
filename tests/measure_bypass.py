#!/usr/bin/env python3
"""Local software-only comparison of compilation settings with real Wasm jobs.

This uses a synthetic HAL on loopback. It is not a TDX/SNP performance test.
All profiles download and compile every job, and use fresh workload instances.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import sys

from test_system import ROOT, SystemTest, jobs


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--jobs', type=int, default=200)
    parser.add_argument('--repeats', type=int, default=3)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--profile-set', choices=('compilation', 'cpu', 'pool-control'), default='compilation',
                        help='CPU set compares dedicated pools against the legacy host, without caching')
    args = parser.parse_args()
    # (mode, optimization, within-component parallelism, pool threads, compiling jobs)
    if args.profile_set == 'pool-control':
        profiles = [(mode, 'none', 'true', threads, 3)
                    for mode in ('wasm', 'native') for threads in (None, 6)]
    elif args.profile_set == 'cpu':
        profiles = [('wasm', 'speed', 'true', None, 3), ('wasm', 'none', 'true', None, 3),
                    ('wasm', 'none', 'true', 2, 1), ('wasm', 'none', 'true', 2, 3),
                    ('wasm', 'none', 'true', 4, 1), ('wasm', 'none', 'true', 4, 3),
                    ('wasm', 'none', 'true', 6, 1), ('wasm', 'none', 'true', 6, 3),
                    ('native', 'none', 'true', 4, 3), ('native', 'none', 'true', 6, 3)]
    else:
        profiles = [(mode, opt, parallel, None, 3) for mode, opt, parallel in
                    [('wasm', 'speed', 'true'), ('wasm', 'none', 'true'),
                     ('wasm', 'none', 'false'), ('native', 'none', 'false'),
                     ('native', 'none', 'true'), ('native', 'speed', 'true')]]
    if args.jobs < 5 or args.repeats < 1 or args.jobs * args.repeats * len(profiles) > 90000:
        parser.error('use at least 5 jobs, 1 repeat, and at most 90000 total jobs')
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    rayon_threads = 6 if args.profile_set == 'pool-control' else 4
    os.environ['RAYON_NUM_THREADS'] = str(rayon_threads)
    report = {
        'software_test_only': True, 'hardware_tee_tested': False,
        'platform': platform.platform(), 'machine': platform.machine(),
        'logical_cpus': os.cpu_count(), 'started_utc': datetime.now(timezone.utc).isoformat(),
        'jobs_per_trial': args.jobs, 'client_concurrency': 6,
        'profile_set': args.profile_set, 'downloads': 4, 'executions': 7, 'max_inflight': 16,
        'file_server_delay_seconds': 0, 'rayon_num_threads': rayon_threads,
        'note': 'Loopback with fresh hosts and empty caches; HTTP connections reused in every profile. '
                'No warmup jobs excluded. This cannot predict a TDX percentage improvement.',
        'artifacts': {name: hashlib.sha256((ROOT / 'dist' / name).read_bytes()).hexdigest()
                      for name in ('agent.wasm', 'hal-on-demand')},
        'trials': [],
    }
    # Reverse the ordering across repetitions to reduce simple order bias.
    fixture = SystemTest()
    fixture.setUp()
    try:
        fixture.files.delay = 0
        for repeat in range(args.repeats):
            order = profiles if repeat % 2 == 0 else list(reversed(profiles))
            for mode, opt, parallel, threads, compilers in order:
                fixture.stop(fixture.host)
                pool_args = ['--compiler-threads', str(threads)] if threads is not None else []
                fixture.start_agent('--mode', mode, '--transport', 'http',
                                    '--compile-opt-level', opt, '--parallel-compilation', parallel,
                                    '--compilers', str(compilers), '--executions', '7', *pool_args)
                manager = fixture.start_manager('--dispatchers', '8', '--max-history', '100000')
                name = f'{repeat + 1:02d}-{mode}-{opt}-parallel-{parallel}'
                if args.profile_set != 'compilation':
                    name += f'-pool-{threads or "legacy"}-jobs-{compilers}'
                destination = output / name
                try:
                    subprocess.run([
                        sys.executable, '-B', str(ROOT / 'jobs.py'), '--url', fixture.api,
                        '--token-file', str(fixture.root / 'api.token'), 'bench',
                        '--jobs', str(args.jobs), '--concurrency', '6', '--cache', 'bypass',
                        '--expect-mode', mode, '--expect-compile-opt-level', opt,
                        '--record-host-stats',
                        '--output', str(destination),
                    ], cwd=ROOT, check=True, timeout=max(120, args.jobs * 2))
                    stats = fixture.stats()
                    if (any(stats[k] != args.jobs for k in ('downloads', 'compiles', 'executions'))
                            or stats['compiled_entries'] != 0 or stats['shared_preparations'] != 0
                            or list((fixture.root / 'cache').glob('*.wasm'))):
                        raise RuntimeError(f'bypass invariant failed: {stats}')
                    verification = {'native_statistics': stats,
                                    'host': jobs.api(fixture.worker_url, fixture.token, '/v1/stats'),
                                    'no_workload_cache_files': True, 'hardware_tee_tested': False}
                    (destination / 'verification.json').write_text(json.dumps(verification, indent=2) + '\n')
                    report['trials'].append(dict(name=name, mode=mode, compile_opt_level=opt,
                        parallel_compilation=parallel == 'true',
                        compiler_threads=threads, compilers=compilers,
                        effective_configuration=verification['host']['configuration'],
                        status=json.loads((destination / 'status.json').read_text())))
                    (output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
                finally:
                    fixture.stop(manager)
    finally:
        fixture.tearDown()
    print('Software-only report:', output / 'report.json')


if __name__ == '__main__':
    main()
