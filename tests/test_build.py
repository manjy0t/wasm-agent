#!/usr/bin/env python3
"""Artifact publication regressions; Cargo is stubbed, files are real."""
from contextlib import redirect_stdout
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import build
from hal_fleet import build_toolchain

RUST_VERSION = 'rustc ' + build_toolchain.RUST_TOOLCHAIN + ' (test fixture)'


class ArtifactPublicationTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='hal-build-test-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.dist = self.root / 'dist'
        self.dist.mkdir()
        self.source = self.root / 'compiled'
        self.source.write_bytes(b'complete new executable')
        self.source.chmod(0o755)
        self.destination = self.dist / 'hal-on-demand'
        self.destination.write_bytes(b'previous executable')

    def test_read_only_artifact_is_replaced_with_executable_permissions(self):
        self.destination.chmod(0o555)
        build.copy_artifact(self.source, self.destination)
        self.assertEqual(self.destination.read_bytes(), self.source.read_bytes())
        if os.name == 'posix':
            self.assertEqual(stat.S_IMODE(self.destination.stat().st_mode), 0o755)
        self.assertEqual(list(self.dist.iterdir()), [self.destination])

    def test_existing_reader_keeps_previous_complete_artifact(self):
        with self.destination.open('rb') as previous:
            build.copy_artifact(self.source, self.destination)
            self.assertEqual(previous.read(), b'previous executable')
        self.assertEqual(self.destination.read_bytes(), self.source.read_bytes())

    def test_copy_failure_preserves_previous_artifact_and_cleans_staging(self):
        def fail_copy(source, destination):
            Path(destination).write_bytes(b'incomplete new executable')
            raise OSError('simulated disk full')

        with patch.object(build.shutil, 'copy2', side_effect=fail_copy):
            with self.assertRaisesRegex(OSError, 'disk full'):
                build.copy_artifact(self.source, self.destination)
        self.assertEqual(self.destination.read_bytes(), b'previous executable')
        self.assertEqual(list(self.dist.iterdir()), [self.destination])

    def test_failed_replace_preserves_previous_artifact_and_cleans_staging(self):
        with patch.object(build.os, 'replace', side_effect=PermissionError('replacement denied')):
            with self.assertRaises(PermissionError):
                build.copy_artifact(self.source, self.destination)
        self.assertEqual(self.destination.read_bytes(), b'previous executable')
        self.assertEqual(list(self.dist.iterdir()), [self.destination])

    @unittest.skipUnless(os.name == 'posix', 'Unix link semantics')
    def test_symlink_destination_is_replaced_without_modifying_its_target(self):
        outside = self.root / 'unrelated-file'
        outside.write_bytes(b'keep unchanged')
        self.destination.unlink()
        self.destination.symlink_to(outside)
        build.copy_artifact(self.source, self.destination)
        self.assertFalse(self.destination.is_symlink())
        self.assertEqual(outside.read_bytes(), b'keep unchanged')
        self.assertEqual(self.destination.read_bytes(), self.source.read_bytes())

    @unittest.skipUnless(sys.platform == 'linux', 'Linux executable replacement')
    def test_running_executable_can_be_replaced_without_truncating_it(self):
        shutil.copy2('/bin/sleep', self.destination)
        process = subprocess.Popen(['sleep', '30'], executable=str(self.destination))
        try:
            build.copy_artifact(Path('/bin/echo'), self.destination)
            self.assertIsNone(process.poll())
            value = subprocess.check_output(['echo', 'new executable'], executable=str(self.destination), text=True)
            self.assertEqual(value.strip(), 'new executable')
        finally:
            process.terminate()
            process.wait(timeout=5)


class BuildCommandTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='hal-build-command-test-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        (self.root / 'dist').mkdir()
        self.sources = {
            'agent.wasm': 'target/guest/wasm32-wasip2/release/hal_on_demand_guest.wasm',
            'orchestration-agent.wasm': 'target/guest/wasm32-wasip2/release/hal_orchestration_agent.wasm',
            'hal-on-demand': 'target/release/hal-on-demand',
            'hal-agent-runner': 'target/release/hal-agent-runner',
        }
        for name, relative in self.sources.items():
            source = self.root / relative
            source.parent.mkdir(parents=True, exist_ok=True)
            source.write_bytes(('new ' + name).encode())
            source.chmod(0o644 if name.endswith('.wasm') else 0o755)
            installed = self.root / 'dist' / name
            installed.write_bytes(('old ' + name).encode())
            installed.chmod(0o444)
        manifest = self.root / 'dist/build.json'
        manifest.write_text('{"previous": true}\n')
        manifest.chmod(0o444)

    def run_build(self, *arguments, run_effect=None, version=RUST_VERSION):
        def output(command, **kwargs):
            if command[:3] == ['rustup', 'target', 'list']:
                return 'wasm32-wasip2\n'
            return ('/fake/' + command[-1]) if command[0] == 'rustup' else version

        with patch.object(build, 'ROOT', self.root), \
                patch.object(sys, 'argv', ['build.py', *arguments]), \
                patch.object(build.subprocess, 'check_output', side_effect=output), \
                patch.object(build.subprocess, 'run', side_effect=run_effect) as run, redirect_stdout(io.StringIO()):
            build.main()
        manifest = json.loads((self.root / 'dist/build.json').read_text())
        self.assertEqual(manifest['rustc'], RUST_VERSION)
        for name in self.sources:
            data = (self.root / 'dist' / name).read_bytes()
            self.assertEqual(manifest[name], dict(bytes=len(data), sha256=hashlib.sha256(data).hexdigest()))
        self.assertFalse(list((self.root / 'dist').glob('.hal-build-*')))
        return [call.args[0] for call in run.call_args_list]

    def test_full_build_replaces_read_only_outputs_and_manifest(self):
        commands = self.run_build()
        self.assertEqual(commands[-2:], [
            [str(self.root / 'dist/hal-on-demand'), '--check-agent', str(self.root / 'dist/agent.wasm')],
            [str(self.root / 'dist/hal-agent-runner'), '--check-agent', str(self.root / 'dist/orchestration-agent.wasm')],
        ])
        for name, source in self.sources.items():
            self.assertEqual((self.root / 'dist' / name).read_bytes(), (self.root / source).read_bytes())

    def test_host_only_build_preserves_existing_agent_artifacts(self):
        self.run_build('--host-only')
        for name in self.sources:
            prefix = 'old ' if name.endswith('.wasm') else 'new '
            self.assertEqual((self.root / 'dist' / name).read_bytes(), (prefix + name).encode())

    def test_agent_only_build_preserves_existing_native_artifacts(self):
        commands = self.run_build('--agent-only')
        self.assertFalse(any('--check-agent' in command for command in commands))
        for name in self.sources:
            prefix = 'new ' if name.endswith('.wasm') else 'old '
            self.assertEqual((self.root / 'dist' / name).read_bytes(), (prefix + name).encode())

    def test_incompatible_compiler_stops_before_building_or_replacing_any_artifact(self):
        commands = []
        with self.assertRaisesRegex(SystemExit, 'Incompatible compiler'):
            self.run_build('--toolchain', 'stable', version='rustc 1.100.0 (fixture)',
                           run_effect=lambda command, **kwargs: commands.append(command))
        self.assertEqual(commands, [])
        for name in self.sources:
            self.assertEqual((self.root / 'dist' / name).read_bytes(), ('old ' + name).encode())
        self.assertEqual(json.loads((self.root / 'dist/build.json').read_text()), {'previous': True})

    def test_linker_rejection_does_not_publish_a_successful_build_manifest(self):
        def reject(command, **kwargs):
            if '--check-agent' in command:
                raise subprocess.CalledProcessError(1, command)
        with self.assertRaises(subprocess.CalledProcessError):
            self.run_build(run_effect=reject)
        self.assertEqual(json.loads((self.root / 'dist/build.json').read_text()), {'previous': True})


class ToolchainTest(unittest.TestCase):
    def output(self, command, **kwargs):
        if command[:3] == ['rustup', 'target', 'list']:
            return 'wasm32-wasip2\n'
        if command[0] == 'rustup':
            return '/fake/' + command[-1]
        return RUST_VERSION

    def test_default_compiler_and_docker_builder_share_the_exact_pin(self):
        with patch.object(build_toolchain.subprocess, 'check_output', side_effect=self.output) as output:
            cargo, env, version = build_toolchain.rust_environment()
        self.assertEqual(cargo, '/fake/cargo')
        self.assertEqual(env['RUSTUP_TOOLCHAIN'], build_toolchain.RUST_TOOLCHAIN)
        self.assertEqual(version, RUST_VERSION)
        self.assertEqual(output.call_args_list[0].args[0],
                         ['rustup', 'which', '--toolchain', build_toolchain.RUST_TOOLCHAIN, 'rustc'])
        self.assertIn('ARG RUST_IMAGE=rust:' + build_toolchain.RUST_TOOLCHAIN + '-bookworm',
                      (ROOT / 'containers/Dockerfile').read_text())

    def test_fresh_machine_installs_compiler_before_resolving_cargo_and_target(self):
        events = []
        def output(command, **kwargs):
            events.append(command)
            if len(events) == 1:
                raise subprocess.CalledProcessError(1, command)
            if command[:3] == ['rustup', 'target', 'list']:
                return 'x86_64-unknown-linux-gnu\n'
            return self.output(command, **kwargs)
        with patch.object(build_toolchain.subprocess, 'check_output', side_effect=output), \
                patch.object(build_toolchain.subprocess, 'run', side_effect=lambda cmd, **kw: events.append(cmd)), \
                redirect_stdout(io.StringIO()):
            build_toolchain.rust_environment(install=True)
        self.assertEqual(events[1][:4], ['rustup', 'toolchain', 'install', build_toolchain.RUST_TOOLCHAIN])
        target = ['rustup', 'target', 'add', 'wasm32-wasip2', '--toolchain', build_toolchain.RUST_TOOLCHAIN]
        self.assertIn(target, events)
        self.assertGreater(events.index(['rustup', 'which', '--toolchain', build_toolchain.RUST_TOOLCHAIN, 'cargo']), 1)

    def test_offline_never_installs_a_missing_compiler(self):
        with patch.object(build_toolchain.subprocess, 'check_output',
                          side_effect=subprocess.CalledProcessError(1, ['rustup'])), \
                patch.object(build_toolchain.subprocess, 'run') as run:
            with self.assertRaisesRegex(SystemExit, 'is required'):
                build_toolchain.rust_environment(install=True, offline=True)
        run.assert_not_called()

    def test_missing_target_offline_cannot_trigger_a_download(self):
        def output(command, **kwargs):
            return '' if command[:3] == ['rustup', 'target', 'list'] else self.output(command, **kwargs)
        with patch.object(build_toolchain.subprocess, 'check_output', side_effect=output), \
                patch.object(build_toolchain.subprocess, 'run') as run:
            with self.assertRaisesRegex(SystemExit, 'target is missing'):
                build_toolchain.rust_environment(install=True, offline=True)
        run.assert_not_called()

    def test_installed_pinned_compiler_and_target_need_no_network(self):
        with patch.object(build_toolchain.subprocess, 'check_output', side_effect=self.output), \
                patch.object(build_toolchain.subprocess, 'run') as run:
            build_toolchain.rust_environment(install=True, offline=True)
        run.assert_not_called()


if __name__ == '__main__':
    unittest.main(verbosity=2)
