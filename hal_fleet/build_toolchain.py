"""One tested Rust/WASI toolchain for hosts, agents and benchmark components."""
import os
from pathlib import Path
import subprocess
import sys


# Cargo.lock pins dependencies, not the WASI imports emitted by Rust's sysroot.
# Newer WASI functions may not exist in our pinned Wasmtime 25.0.3 linker.
RUST_TOOLCHAIN = '1.98.1'
WASM_TARGET = 'wasm32-wasip2'


def rust_environment(toolchain=RUST_TOOLCHAIN, *, install=False, wasm=True, offline=False):
    def run(command):
        print('+', ' '.join(command), flush=True)
        subprocess.run(command, check=True)

    def tool(name):
        return subprocess.check_output(
            ['rustup', 'which', '--toolchain', toolchain, name], text=True,
            stderr=subprocess.PIPE).strip()

    try:
        rustc = tool('rustc')
    except subprocess.CalledProcessError:
        if not install or offline:
            raise SystemExit('Rust ' + RUST_TOOLCHAIN + ' is required. Run build.py --install-target '
                             'with network access to install the compatible compiler and WASI target.') from None
        run(['rustup', 'toolchain', 'install', toolchain, '--profile', 'minimal', '--no-self-update'])
        rustc = tool('rustc')
    version = subprocess.check_output([rustc, '--version'], text=True).strip()
    if version.split()[:2] != ['rustc', RUST_TOOLCHAIN]:
        raise SystemExit('Incompatible compiler: ' + version + '. This runtime requires Rust '
                         + RUST_TOOLCHAIN + '; newer WASI imports may not link. Use the default '
                         '--toolchain ' + RUST_TOOLCHAIN + ' with --install-target.')
    if install and wasm:
        installed = subprocess.check_output(
            ['rustup', 'target', 'list', '--installed', '--toolchain', toolchain], text=True).splitlines()
        if WASM_TARGET not in installed:
            if offline:
                raise SystemExit('The ' + WASM_TARGET + ' target is missing; install it without --offline first.')
            run(['rustup', 'target', 'add', WASM_TARGET, '--toolchain', toolchain])
    env = os.environ.copy()
    env.update(RUSTC=rustc, RUSTDOC=tool('rustdoc'), RUSTUP_TOOLCHAIN=toolchain)
    env.pop('CARGO_TARGET_DIR', None)
    if sys.platform == 'darwin':
        env['DYLD_FALLBACK_LIBRARY_PATH'] = str(Path(rustc).parent.parent / 'lib') + ':' + env.get(
            'DYLD_FALLBACK_LIBRARY_PATH', '/usr/local/lib:/usr/lib')
    return tool('cargo'), env, version
