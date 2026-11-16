#!/usr/bin/env python3
"""Build the Wasm agent and native host with one rustup toolchain."""
import argparse
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
from hal_fleet.build_toolchain import RUST_TOOLCHAIN, rust_environment

ROOT = Path(__file__).resolve().parent


@contextmanager
def atomic_output(destination):
    """Replace one completed artifact without opening the old file for writing.

    Previous installations can leave root-owned or read-only files in dist.
    Replacement requires write access to dist, not to the old artifact. Keeping
    the staging file on the same filesystem also preserves the old file if
    copying fails and avoids truncating an executable used by another process.
    """
    destination = Path(destination)
    with tempfile.TemporaryDirectory(prefix='.hal-build-', dir=destination.parent) as folder:
        staged = Path(folder) / destination.name
        yield staged
        os.replace(staged, destination)


def copy_artifact(source, destination):
    with atomic_output(destination) as staged:
        shutil.copy2(source, staged)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--toolchain', default=RUST_TOOLCHAIN,
                   help='Rust toolchain name or alias resolving to ' + RUST_TOOLCHAIN)
    p.add_argument('--install-target', action='store_true', help='install the pinned compiler and WASI target if missing')
    p.add_argument('--offline', action='store_true')
    p.add_argument('--host-only', action='store_true', help='build only the native host; no Wasm agent target needed')
    p.add_argument('--agent-only', action='store_true', help='build only the portable management agent')
    p.add_argument('--target-dir', type=Path, default=ROOT / 'target')
    args = p.parse_args()
    if args.agent_only and args.host_only:
        p.error('--agent-only and --host-only are mutually exclusive')
    cargo, env, version = rust_environment(args.toolchain, install=args.install_target,
                                            wasm=not args.host_only, offline=args.offline)
    def run(command):
        print('+', ' '.join(map(str, command)), flush=True)
        subprocess.run(list(map(str, command)), cwd=ROOT, env=env, check=True)
    options = ['--release', '--locked'] + (['--offline'] if args.offline else [])
    target = args.target_dir.resolve()
    (ROOT / 'dist').mkdir(exist_ok=True)
    if not args.host_only:
        run([cargo, 'build', '--manifest-path', ROOT / 'guest/Cargo.toml', '--target-dir', target / 'guest',
             '--target', 'wasm32-wasip2', *options])
        wasm = target / 'guest/wasm32-wasip2/release/hal_on_demand_guest.wasm'
        copy_artifact(wasm, ROOT / 'dist/agent.wasm')
    if not args.host_only:
        run([cargo, 'build', '--manifest-path', ROOT / 'orchestrator/Cargo.toml', '--target-dir', target / 'guest',
             '--target', 'wasm32-wasip2', *options])
        copy_artifact(target / 'guest/wasm32-wasip2/release/hal_orchestration_agent.wasm', ROOT / 'dist/orchestration-agent.wasm')
    if not args.agent_only:
        run([cargo, 'build', '--manifest-path', ROOT / 'Cargo.toml', '--target-dir', target,
             '--bin', 'hal-on-demand', '--bin', 'hal-agent-runner', *options])
        copy_artifact(target / 'release/hal-on-demand', ROOT / 'dist/hal-on-demand')
        copy_artifact(target / 'release/hal-agent-runner', ROOT / 'dist/hal-agent-runner')
    if not args.agent_only:
        # Check the actual component imports/exports, not just a version string.
        # Setup must stop here, before the expensive Docker build, on mismatch.
        for host, agent in (('hal-on-demand', 'agent.wasm'),
                            ('hal-agent-runner', 'orchestration-agent.wasm')):
            if (ROOT / 'dist' / agent).exists():
                run([ROOT / 'dist' / host, '--check-agent', ROOT / 'dist' / agent])
    manifest = {name: {'bytes': (ROOT / 'dist' / name).stat().st_size,
                      'sha256': hashlib.sha256((ROOT / 'dist' / name).read_bytes()).hexdigest()}
                for name in ('agent.wasm', 'orchestration-agent.wasm', 'hal-on-demand', 'hal-agent-runner') if (ROOT / 'dist' / name).exists()}
    manifest['rustc'] = version
    with atomic_output(ROOT / 'dist/build.json') as staged:
        staged.write_text(json.dumps(manifest, indent=2) + '\n', encoding='utf-8')
    built = ('agent.wasm', 'orchestration-agent.wasm') if args.agent_only else (('hal-on-demand', 'hal-agent-runner') if args.host_only else ('agent.wasm', 'orchestration-agent.wasm', 'hal-on-demand', 'hal-agent-runner'))
    print('Built ' + ', '.join('dist/' + name for name in built), flush=True)


if __name__ == '__main__':
    main()
