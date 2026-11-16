#!/usr/bin/env python3
"""Trustee adapter + pinned SNP codec/Rego tests, without VMs or deployment keys."""
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
    parser.add_argument('--offline', action='store_true')
    args = parser.parse_args()
    cargo, env, _ = rust_environment(args.toolchain, wasm=False, offline=args.offline)
    subprocess.run([sys.executable, '-B', 'tests/test_trustee.py'], cwd=ROOT, check=True)
    env['HAL_TEST_PYTHON'] = sys.executable
    subprocess.run([cargo, *(['--offline'] if args.offline else []), 'test', '--locked', '--manifest-path',
                    'tools/trustee-snp-codec/Cargo.toml'], cwd=ROOT, env=env, check=True)


if __name__ == '__main__':
    main()
