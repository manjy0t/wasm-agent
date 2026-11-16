#!/usr/bin/env python3
"""Local Mac/Linux validation after both builds; no VM access or deployment keys."""
import argparse
import os
from pathlib import Path
import subprocess
import sys
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from hal_fleet.build_toolchain import RUST_TOOLCHAIN, rust_environment

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--toolchain', default=RUST_TOOLCHAIN)
    args = parser.parse_args()
    cargo, env, _ = rust_environment(args.toolchain, wasm=False, offline=True)
    for script in ('test_build.py', 'test_fleet_tls.py', 'test_trustee.py', 'test_audit.py', 'test_native_audit.py',
                   'test_benchmark_guard.py', 'test_benchmark_matrix.py', 'test_benchmark_sessions.py', 'test_mode_selection.py', 'test_native_audit_live.py',
                   'test_gvisor.py', 'test_access_profiles.py', 'test_portable_agent.py', 'test_agent_lifecycle.py', 'test_fleet.py', 'test_fleet_client_portability.py',
                   'test_fleet_install.py', 'test_fleet_worker_image.py'):
        print('\nChecking ' + script, flush=True)
        subprocess.run([sys.executable, '-B', str(ROOT/'tests'/script)], cwd=ROOT, check=True)
    target = os.environ.get('HAL_TEST_TARGET_DIR', str(ROOT/'target'))
    print('\nChecking native host and agent HAL boundaries', flush=True)
    subprocess.run([cargo, 'test', '--release', '--locked', '--offline', '--target-dir', target], cwd=ROOT, env=env, check=True)
    print('\nChecking reusable profile core', flush=True)
    subprocess.run([cargo, 'test', '-p', 'hal-access-profile', '--release', '--locked', '--offline',
                    '--target-dir', target], cwd=ROOT, env=env, check=True)
    print('\nChecking agent policy bindings', flush=True)
    subprocess.run([cargo, 'test', '--manifest-path', str(ROOT/'orchestrator/Cargo.toml'),
                    '--release', '--locked', '--offline', '--target-dir', str(Path(target)/'agent-tests')], cwd=ROOT, env=env, check=True)
    print('\nChecking mandatory workload HAL rights', flush=True)
    subprocess.run([cargo, 'test', '-p', 'hal-runtime', '--release', '--locked', '--offline',
                    '--target-dir', target, '--lib', 'access_tests'], cwd=ROOT, env=env, check=True)

if __name__ == '__main__':
    main()
