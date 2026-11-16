#!/usr/bin/env python3
"""Runtime selection and transactional Docker configuration; no Docker/root needed."""
import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from hal_fleet import gvisor


class SandboxTest(unittest.TestCase):
    def test_missing_default_or_modified_runtime_is_rejected(self):
        info = {'OSType': 'linux', 'Runtimes': {'hal-gvisor': gvisor.runtime_entry()}}
        gvisor.validate_info(info)
        for entry in ({}, {'runc': {}}, {'runsc': gvisor.runtime_entry()}):
            with self.assertRaises(ValueError):
                gvisor.validate_info(dict(info, Runtimes=entry))
        for key, value in [('path', '/usr/bin/runc'), ('runtimeArgs', ['--platform=kvm']),
                           ('runtimeArgs', gvisor.runtime_entry()['runtimeArgs'] + ['--host-uds=none'])]:
            altered = copy.deepcopy(info)
            altered['Runtimes']['hal-gvisor'][key] = value
            with self.assertRaises(ValueError):
                gvisor.validate_info(altered)

    def test_merge_preserves_other_runtimes_default_and_options(self):
        original = {'default-runtime': 'runc', 'log-driver': 'json-file',
                    'runtimes': {'another': {'path': '/opt/other/runtime'}}, 'live-restore': True}
        merged = gvisor.merged_config(original)
        self.assertEqual(merged['default-runtime'], original['default-runtime'])
        self.assertEqual(merged['runtimes']['another'], original['runtimes']['another'])
        self.assertEqual(merged['runtimes']['hal-gvisor'], gvisor.runtime_entry())
        self.assertNotIn('hal-gvisor', original['runtimes'])
        self.assertEqual(gvisor.merged_config(merged), merged)
        with self.assertRaisesRegex(ValueError, 'conflicts'):
            gvisor.merged_config({'runtimes': {'hal-gvisor': {'path': '/usr/bin/runc'}}})

    def test_install_uses_package_including_sidecars_and_signed_repository(self):
        calls, files = [], {}
        def run(args, **kwargs):
            calls.append(args)
            if args[0].endswith('dpkg'):
                return 'amd64'
            if args[0].endswith('gpg'):
                Path(args[args.index('--output') + 1]).write_bytes(b'test-key')
            return ''
        with patch.object(gvisor, 'command', side_effect=run), patch.object(gvisor, 'write_atomic',
                side_effect=lambda p, b: files.update({str(p): b})):
            gvisor.install_package()
        self.assertIn(['/usr/bin/apt-get', 'install', '-y', 'runsc'], calls)
        self.assertIn(b'signed-by=/usr/share/keyrings/gvisor-archive-keyring.gpg',
                      files['/etc/apt/sources.list.d/hal-gvisor.list'])
        self.assertFalse(any('chmod' in c or 'restart' in c for c in calls))


class ConfigurationTest(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.path = Path(temp.name) / 'daemon.json'
        self.original = b'{"log-driver":"json-file","default-runtime":"runc"}\n'
        self.path.write_bytes(self.original)
        self.calls = []
        self.commands = patch.object(gvisor, 'command', side_effect=self.command)
        self.commands.start()
        self.addCleanup(self.commands.stop)
        binary = patch.object(gvisor.shutil, 'which', return_value='/usr/sbin/dockerd')
        binary.start()
        self.addCleanup(binary.stop)

    def command(self, args, **kwargs):
        self.calls.append(args)
        return ''

    def test_validation_then_atomic_install_reload_check_and_idempotence(self):
        with patch.object(gvisor, 'check', return_value={'configuration_checked': True}):
            result = gvisor.configure_daemon(self.path)
            self.assertEqual(Path(result['backup']).read_bytes(), self.original)
            gvisor.configure_daemon(self.path)
        self.assertEqual(sum('--validate' in c for c in self.calls), 1)
        self.assertEqual(sum('reload' in c for c in self.calls), 1)
        config = json.loads(self.path.read_text())
        self.assertEqual(config['default-runtime'], 'runc')
        self.assertEqual(config['runtimes']['hal-gvisor'], gvisor.runtime_entry())

    def test_failed_post_reload_check_restores_exact_previous_configuration(self):
        with patch.object(gvisor, 'check', side_effect=ValueError('runtime missing')):
            with self.assertRaisesRegex(ValueError, 'runtime missing'):
                gvisor.configure_daemon(self.path)
        self.assertEqual(self.path.read_bytes(), self.original)
        self.assertEqual(sum('reload' in c for c in self.calls), 2)

    def test_validation_failure_makes_no_changes(self):
        with patch.object(gvisor, 'command', side_effect=['', ValueError('bad config')]):
            with self.assertRaisesRegex(ValueError, 'bad config'):
                gvisor.configure_daemon(self.path)
        self.assertEqual(self.path.read_bytes(), self.original)

    def test_live_workers_and_conflicts_do_not_modify_config(self):
        with patch.object(gvisor, 'command', return_value='active-container'):
            with self.assertRaisesRegex(ValueError, 'Stop active'):
                gvisor.configure_daemon(self.path)
        self.assertEqual(self.path.read_bytes(), self.original)

    def test_concurrent_operator_edit_is_not_lost_during_rollback(self):
        def fail():
            self.path.write_text('{"operator-change":true}')
            raise ValueError('check failed')
        with patch.object(gvisor, 'check', side_effect=fail):
            with self.assertRaisesRegex(ValueError, 'concurrently'):
                gvisor.configure_daemon(self.path)
        self.assertEqual(json.loads(self.path.read_text()), {'operator-change': True})

    def test_first_install_failure_removes_only_new_config(self):
        self.path.unlink()
        with patch.object(gvisor, 'check', side_effect=ValueError('runtime missing')):
            with self.assertRaises(ValueError):
                gvisor.configure_daemon(self.path)
        self.assertFalse(self.path.exists())

    def test_operator_edit_during_validation_is_not_overwritten(self):
        def edit(args, **kwargs):
            if '--validate' in args:
                self.path.write_text('{"operator-change":true}')
            return ''
        with patch.object(gvisor, 'command', side_effect=edit):
            with self.assertRaisesRegex(ValueError, 'changed during validation'):
                gvisor.configure_daemon(self.path)
        self.assertEqual(json.loads(self.path.read_text()), {'operator-change': True})


if __name__ == '__main__':
    unittest.main(verbosity=2)
