#!/usr/bin/env python3
"""Build 15 separate components and check native outputs against Python references."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
from reference import NAMES, reference

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from hal_fleet.build_toolchain import RUST_TOOLCHAIN, rust_environment


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--offline', action='store_true')
    parser.add_argument('--install-target', action='store_true')
    parser.add_argument('--toolchain', default=RUST_TOOLCHAIN)
    args = parser.parse_args()
    cargo, env, _ = rust_environment(args.toolchain, install=args.install_target, offline=args.offline)
    base = [cargo, '--offline'] if args.offline else [cargo]
    manifest = ROOT / 'benchmarks/guest/Cargo.toml'
    common = ['--manifest-path', str(manifest), '--release', '--locked', '--target-dir', str(ROOT / 'target/benchmarks')]
    expected = [reference(i) for i in range(15)]
    native = subprocess.check_output([*base, 'run', *common, '--example', 'reference_check'], env=env, text=True)
    if native.splitlines() != expected:
        for i, (got, want) in enumerate(zip(native.splitlines(), expected)):
            if got != want:
                print(f'{NAMES[i]} mismatch: Rust={got!r}; Python={want!r}', file=sys.stderr)
        raise SystemExit('Independent reference checks failed')
    output = ROOT / 'benchmarks/artifacts'
    output.mkdir(exist_ok=True)
    rows = []
    for index, name in enumerate(NAMES):
        print(f'Building {index+1}/15: {name}', flush=True)
        env['HAL_WORKLOAD_INDEX'] = str(index)
        subprocess.run([*base, 'build', *common, '--target', 'wasm32-wasip2'], env=env, check=True)
        raw = (ROOT / 'target/benchmarks/wasm32-wasip2/release/hal_benchmark_workload.wasm').read_bytes()
        sha = hashlib.sha256(raw).hexdigest()
        component = sha + '.wasm'
        (output / component).write_bytes(raw)
        rule = dict(component=component, cache='memory', cache_ttl_ms=300000, hal_permissions=[], memory_mib=64,
                    fuel=1000000000, execution_timeout_ms=5000, max_output_bytes=4096, worker_max_jobs=128,
                    validation=dict(kind='hex', value=expected[index].encode().hex()))
        rows.append(dict(name=name, component=component, sha256=sha, artifact_bytes=len(raw), rule=rule))
    (output / 'manifest.json').write_text(json.dumps(dict(version=1, workloads=rows), indent=2) + '\n')
    (output / 'expected.json').write_text(json.dumps(dict(zip(NAMES, expected)), indent=2) + '\n')
    print('Built 15 components; all native outputs match independent Python implementations.')
    print('Run tests/test_fleet.py to validate the components inside the actual Wasm host.')


if __name__ == '__main__':
    main()
