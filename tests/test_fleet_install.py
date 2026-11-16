#!/usr/bin/env python3
"""Installer regressions. No SSH connections, sudo, or deployed keys are used."""
import os
from pathlib import Path
import shutil
import shlex
import subprocess
import sys
import tarfile
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from hal_fleet.common import Error
from hal_fleet.install import ROLES, install_service, package, source_unpack_command, systemd_unit


@unittest.skipUnless(os.name == 'posix' and shutil.which('tar'), 'Source upload uses the VM POSIX shell and tar')
class SourceUploadTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='hal-source-upload-test-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / 'source'
        (self.source / 'wit').mkdir(parents=True)
        (self.source / 'wit/agent.wit').write_text('elastic:job-agent@0.4.0')
        # Exercise shell quoting as well as the normal relative deployment path.
        self.destination = self.root / "remote path's $name; literal"
        self.deployed = self.destination / 'hal-on-demand'

    def archive(self, name):
        path = self.root / (name + '.tar.gz')
        package(self.source, path)
        return path

    def unpack(self, archive, command=None):
        subprocess.run(['/bin/sh', '-c', command or source_unpack_command(self.destination)],
                       input=archive.read_bytes(), capture_output=True, check=True)

    def test_redeployment_updates_source_times_and_preserves_state_and_build_cache(self):
        archive = self.archive('first')
        with tarfile.open(archive) as bundle:
            self.assertEqual(bundle.getmember('hal-on-demand/wit/agent.wit').mtime, 0)
        self.unpack(archive)
        sentinels = ('state/identity.key', 'tls/server.key', 'target/keep-build-cache')
        for relative in sentinels:
            path = self.deployed / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b'keep existing bytes')
        (self.source / 'wit/agent.wit').write_text('elastic:job-agent@0.5.0')
        started = time.time()
        self.unpack(self.archive('second'))
        deployed_wit = self.deployed / 'wit/agent.wit'
        self.assertEqual(deployed_wit.read_text(), 'elastic:job-agent@0.5.0')
        self.assertGreaterEqual(deployed_wit.stat().st_mtime, started - 1)
        for relative in sentinels:
            self.assertEqual((self.deployed / relative).read_bytes(), b'keep existing bytes')

    @unittest.skipUnless(shutil.which('rustup'), 'Needs an installed stable Rust toolchain; no downloads or dependencies')
    def test_cargo_rebuilds_changed_wit_after_upload_over_existing_build(self):
        (self.source / 'src').mkdir()
        (self.source / 'src/main.rs').write_text('fn main() { print!("{}", include_str!("../wit/agent.wit")); }\n')
        (self.source / 'Cargo.toml').write_text(
            '[package]\nname = "hal-upload-fixture"\nversion = "0.1.0"\nedition = "2021"\n[workspace]\n')
        self.unpack(self.archive('first'))
        target = self.deployed / 'target'
        env = dict(os.environ, CARGO_TARGET_DIR=str(target))
        command = ['rustup', 'run', 'stable', 'cargo', 'build', '--offline', '--release', '--quiet']

        def build_and_read():
            result = subprocess.run(command, cwd=self.deployed, env=env, capture_output=True, text=True, timeout=60)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            return subprocess.check_output([str(target / 'release/hal-upload-fixture')], text=True)

        self.assertEqual(build_and_read(), 'elastic:job-agent@0.4.0')
        (self.source / 'wit/agent.wit').write_text('elastic:job-agent@0.5.0')
        changed = self.archive('changed')
        # Reproduce the bug: new contents with the archive's 1970 timestamp are
        # incorrectly reused by Cargo's mtime freshness check.
        self.unpack(changed, 'tar -xzf - -C ' + shlex.quote(str(self.destination)))
        self.assertEqual((self.deployed / 'wit/agent.wit').read_text(), 'elastic:job-agent@0.5.0')
        self.assertEqual(build_and_read(), 'elastic:job-agent@0.4.0')
        # Allow for tar/filesystems with one-second timestamp resolution.
        time.sleep(1.05)
        self.unpack(changed)
        self.assertEqual(build_and_read(), 'elastic:job-agent@0.5.0')


class UnitGenerationTest(unittest.TestCase):
    def test_working_directory_is_absolute_and_unquoted_with_literal_specifiers(self):
        root = Path('/tmp/hal test %h $HOME')
        for role in ROLES:
            with self.subTest(role=role):
                unit = systemd_unit(root, root/'state/fleet.json', {'role': role})
                directory = next(line for line in unit.splitlines() if line.startswith('WorkingDirectory='))
                self.assertEqual(directory, 'WorkingDirectory=' + str(root.resolve()).replace('%', '%%'))
                self.assertNotIn('WorkingDirectory="', unit)
                self.assertEqual('docker.service' in unit, role == 'execution')
                self.assertEqual('User=root\n' in unit, role == 'execution' or os.getuid() == 0)

    def test_execstart_quotes_arguments_and_preserves_the_virtual_environment(self):
        root = Path('/tmp/hal test %h $HOME')
        venv = str(root / '.venv/bin/python')
        with patch('hal_fleet.install.sys.executable', venv):
            unit = systemd_unit(root, root/'state/fleet.json', {'role': 'identity'})
        command = next(line for line in unit.splitlines() if line.startswith('ExecStart='))
        self.assertTrue(command.startswith('ExecStart="/tmp/hal test %%h $$HOME/.venv/bin/python" '))
        self.assertIn('"serve" "--config"', command)
        self.assertIn('/state/fleet.json"', command)

    def test_service_paths_cannot_inject_unit_lines_or_continuations(self):
        for root in ('/tmp/hal\nUser=root', '/tmp/hal\rUser=root', '/tmp/hal\\', '/tmp/hal '):
            with self.subTest(root=root), self.assertRaises(Error):
                systemd_unit(Path(root), Path('/tmp/config.json'), {'role': 'identity'})
        with self.assertRaises(Error):
            systemd_unit(Path('/tmp/hal'), Path('/tmp/hal\nRestart=always'), {'role': 'identity'})

    @unittest.skipUnless(sys.platform == 'linux' and shutil.which('systemd-analyze'),
                         'The real systemd parser is only available on Linux; deploy checks it on each VM')
    def test_linux_systemd_accepts_fixed_unit_and_rejects_previous_quoted_directory(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)/'hal test %h $HOME'
            root.mkdir()
            (root/'fleet.py').write_text('pass\n')
            path = Path(folder)/'hal-fleet-identity.service'
            unit = systemd_unit(root, root/'state/fleet.json', {'role': 'identity'})
            path.write_text(unit)
            fixed = subprocess.run(['systemd-analyze', 'verify', str(path)], capture_output=True, text=True)
            self.assertEqual(fixed.returncode, 0, fixed.stdout + fixed.stderr)
            directory = next(line for line in unit.splitlines() if line.startswith('WorkingDirectory='))
            path.write_text(unit.replace(directory, 'WorkingDirectory="' + directory.split('=', 1)[1] + '"'))
            previous = subprocess.run(['systemd-analyze', 'verify', str(path)], capture_output=True, text=True)
            self.assertNotEqual(previous.returncode, 0)
            self.assertIn('WorkingDirectory', previous.stderr)


class UnitInstallationTest(unittest.TestCase):
    # Run the actual generated POSIX shell command, replacing only privileged
    # commands with a test function. Files and logs stay in a temporary directory.
    SHELL_STUB = r'''
sudo() {
  printf '%s\n' "$*" >> "$HAL_INSTALL_TEST_LOG"
  case "$1" in
    systemd-analyze)
      printf '%s\n' "$3" > "$HAL_INSTALL_TEST_STAGE"
      cp "$3" "$HAL_INSTALL_TEST_VERIFIED"
      return "$HAL_INSTALL_TEST_VERIFY_STATUS"
      ;;
    install)
      cp "$5" "$HAL_INSTALL_TEST_INSTALLED"
      ;;
    systemctl)
      if [ "$2" = restart ]; then
        return "$HAL_INSTALL_TEST_RESTART_STATUS"
      fi
      ;;
    *) return 99 ;;
  esac
}
'''

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='hal-install-test-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.env = dict(os.environ, HAL_INSTALL_TEST_VERIFY_STATUS='0', HAL_INSTALL_TEST_RESTART_STATUS='0')
        for name in ('LOG', 'STAGE', 'VERIFIED', 'INSTALLED'):
            self.env['HAL_INSTALL_TEST_' + name] = str(self.root/name.lower())
        (self.root/'installed').write_text('previous unit\n')
        self.unit = systemd_unit(self.root, self.root/'config.json', {'role': 'identity'})

    def ssh(self, role, command, data):
        self.assertEqual(role, 'identity')
        subprocess.run(['/bin/sh', '-c', self.SHELL_STUB + command], input=data, env=self.env,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)

    def assert_stage_removed(self):
        staged = Path((self.root/'stage').read_text().strip())
        self.assertEqual(staged.name, 'hal-fleet-identity.service')
        self.assertFalse(staged.parent.exists(), 'Temporary unit directory was not removed')

    def test_invalid_unit_keeps_existing_unit_and_never_restarts_service(self):
        self.env['HAL_INSTALL_TEST_VERIFY_STATUS'] = '1'
        with self.assertRaisesRegex(ValueError, 'Service validation or startup failed'):
            install_service(self.ssh, 'identity', self.unit)
        self.assertEqual((self.root/'installed').read_text(), 'previous unit\n')
        log = (self.root/'log').read_text().splitlines()
        self.assertEqual(len(log), 1)
        self.assertTrue(log[0].startswith('systemd-analyze verify '))
        self.assert_stage_removed()

    def test_validated_unit_is_installed_then_enabled_and_restarted(self):
        install_service(self.ssh, 'identity', self.unit)
        self.assertEqual((self.root/'verified').read_text(), self.unit)
        self.assertEqual((self.root/'installed').read_text(), self.unit)
        log = (self.root/'log').read_text().splitlines()
        self.assertTrue(log[0].startswith('systemd-analyze verify '))
        self.assertTrue(log[1].startswith('install -m 0644 -- '))
        self.assertEqual(log[2:], ['systemctl daemon-reload', 'systemctl enable hal-fleet-identity.service',
                                   'systemctl restart hal-fleet-identity.service'])
        self.assert_stage_removed()

    def test_startup_failure_reports_status_and_cleans_staging_directory(self):
        self.env['HAL_INSTALL_TEST_RESTART_STATUS'] = '1'
        with self.assertRaisesRegex(ValueError, 'rerun deploy with the same keys'):
            install_service(self.ssh, 'identity', self.unit)
        self.assertIn('systemctl --no-pager --full status hal-fleet-identity.service', (self.root/'log').read_text())
        self.assert_stage_removed()


if __name__ == '__main__':
    unittest.main(verbosity=2)
