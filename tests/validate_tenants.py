#!/usr/bin/env python3
"""Run the tenant update's local checks and save reproducible reports.

Build dist/hal-on-demand first with build.py. Integration tests bind localhost
ports and use synthetic HAL mode; no cloud VM or attestation is tested here.
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

ROOT = Path(__file__).resolve().parents[1]


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--target-dir', type=Path, default=ROOT / 'target')
    args = p.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    env = os.environ.copy()
    env.update(PYTHONDONTWRITEBYTECODE='1', RAYON_NUM_THREADS='4', HAL_TEST_RESULTS_DIR=str(output))
    commands = [[sys.executable, '-B', 'tests/test_system.py', '--keep-results'],
                [sys.executable, '-B', 'tests/test_tenants.py']]
    tool = lambda n: subprocess.check_output(['rustup', 'which', '--toolchain', 'stable', n], text=True).strip()
    env.update(RUSTC=tool('rustc'), RUSTDOC=tool('rustdoc'), RUSTUP_TOOLCHAIN='stable')
    if sys.platform == 'darwin':
        env['DYLD_FALLBACK_LIBRARY_PATH'] = str(Path(env['RUSTC']).parent.parent / 'lib') + ':/usr/local/lib:/usr/lib'
    commands.append([tool('cargo'), 'test', '--release', '--locked', '--offline', '--target-dir',
                     str(args.target_dir.resolve()), '--bin', 'hal-on-demand'])
    report = dict(timestamp_utc=datetime.now(timezone.utc).isoformat(), machine=platform.machine(),
                  platform=platform.platform(), hardware_tee_tested=False, attestation_verified=False,
                  host_sha256=hashlib.sha256((ROOT / 'dist/hal-on-demand').read_bytes()).hexdigest(), checks=[])
    for name, command in zip(('legacy-integration', 'tenant-integration', 'native-tests'), commands):
        print('Running', name, flush=True)
        done = subprocess.run(command, cwd=ROOT, env=env, capture_output=True, text=True)
        (output / f'{name}.txt').write_text(done.stdout + done.stderr)
        report['checks'].append(dict(name=name, command=command, exit_code=done.returncode))
        print(name, 'passed' if done.returncode == 0 else 'FAILED', flush=True)
        if done.returncode:
            print((done.stdout + done.stderr)[-6000:], flush=True)
    report['passed'] = all(c['exit_code'] == 0 for c in report['checks'])
    (output / 'validation.json').write_text(json.dumps(report, indent=2) + '\n')
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    sys.exit(main())
