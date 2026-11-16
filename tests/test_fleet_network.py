#!/usr/bin/env python3
"""Connection diagnostics and read-only deployment checks; no deployed keys."""
import http.client
import json
from pathlib import Path
import shlex
import ssl
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from hal_fleet.common import (DOCUMENT_DOMAIN, Error, Transport, atomic_json, private_hex, public, sign)
from hal_fleet.http_server import make_server
from hal_fleet.install import (ROLES, certificates, deploy, identity_network_check, network_check, remote_command)
from hal_fleet.network_probe import probe_identity


class TransportDiagnosticTest(unittest.TestCase):
    def test_read_only_failure_names_destination_and_cause_without_claiming_job_submission(self):
        connection = Mock()
        connection.request.side_effect = TimeoutError('timed out')
        transport = Transport()
        with patch('hal_fleet.common.http.client.HTTPConnection', return_value=connection):
            with self.assertRaises(Error) as raised:
                transport.call('http://127.0.0.1:1234', '/v1/trust')
        self.assertEqual(raised.exception.code, 'connection_failed')
        self.assertIn('GET http://127.0.0.1:1234/v1/trust', str(raised.exception))
        self.assertIn('TimeoutError: timed out', str(raised.exception))
        self.assertNotIn('may have run', str(raised.exception))
        connection.request.assert_called_once()
        connection.close.assert_called_once()
        self.assertEqual(transport.local.connections, {})

    def test_submitted_request_is_not_retried_or_reported_as_definitely_unprocessed(self):
        connection = Mock()
        connection.getresponse.side_effect = http.client.RemoteDisconnected('connection closed')
        transport = Transport()
        with patch('hal_fleet.common.http.client.HTTPConnection', return_value=connection):
            with self.assertRaises(Error) as raised:
                transport.call('http://127.0.0.1:1234', '/v1/run', {'private_input': 'do-not-log'}, token='secret-token')
        self.assertEqual(raised.exception.code, 'outcome_unknown')
        self.assertIn('may have been processed', str(raised.exception))
        self.assertNotIn('do-not-log', str(raised.exception))
        self.assertNotIn('secret-token', str(raised.exception))
        connection.request.assert_called_once()
        connection.close.assert_called_once()

    def test_certificate_failure_is_identified_and_verification_is_not_disabled(self):
        connection = Mock()
        connection.request.side_effect = ssl.SSLCertVerificationError('certificate verify failed')
        with patch('hal_fleet.common.http.client.HTTPSConnection', return_value=connection) as factory:
            with self.assertRaises(Error) as raised:
                Transport().call('https://127.0.0.1:1234', '/v1/trust')
        self.assertEqual(raised.exception.code, 'connection_failed')
        self.assertIn('SSLCertVerificationError', str(raised.exception))
        context = factory.call_args.kwargs['context']
        self.assertTrue(context.check_hostname)
        self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)

    def test_probe_reports_timeout_and_refuses_plain_http(self):
        connection = Mock()
        connection.request.side_effect = TimeoutError('timed out')
        with patch('hal_fleet.network_probe.ssl.create_default_context'), \
                patch('hal_fleet.network_probe.http.client.HTTPSConnection', return_value=connection):
            result = probe_identity('https://192.0.2.10', 'test-ca')
        self.assertFalse(result['ok'])
        self.assertEqual(result['error_kind'], 'TimeoutError')
        connection.request.assert_called_once()
        self.assertFalse(probe_identity('http://192.0.2.10', 'test-ca')['ok'])

    def test_ssh_error_identifies_role_without_dumping_command_or_input(self):
        info = {'vms': {'files': {'ssh_user': 'tester', 'ip': '192.0.2.20'}}}
        failure = subprocess.CalledProcessError(255, ['ssh', 'sensitive-command'])
        with patch('hal_fleet.install.subprocess.run', side_effect=failure):
            with self.assertRaises(ValueError) as raised:
                remote_command(info, '/tmp/test-key', 'files', 'sensitive-command', b'secret-input')
        self.assertIn('files VM (192.0.2.20)', str(raised.exception))
        self.assertNotIn('sensitive-command', str(raised.exception))
        self.assertNotIn('secret-input', str(raised.exception))


class NetworkWorkflowTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='hal-network-test-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.info = dict(vms={role: dict(ip='192.0.2.' + str(i+10), ssh_user='tester') for i, role in enumerate(ROLES)})
        self.inventory = self.root/'inventory.json'
        atomic_json(self.inventory, self.info)
        self.credentials = self.root/'tls'
        certificates(self.inventory, self.credentials)

    def test_standalone_check_needs_only_public_ca_and_returns_failure_and_source_ranges(self):
        # Delete test private TLS keys: this command must work without them.
        for key in self.credentials.glob('*.key'):
            key.unlink()
        (self.credentials/'ca-key.pem').unlink()
        calls = []

        def remote(info, key, role, command, data=None, capture=False):
            calls.append(role)
            settings = json.loads(data)
            self.assertEqual(set(settings), {'url', 'ca_pem', 'timeout'})
            self.assertIn('BEGIN CERTIFICATE', settings['ca_pem'])
            self.assertEqual(settings['timeout'], 5)
            self.assertTrue(capture)
            self.assertEqual(shlex.split(command)[:2], ['python3', '-c'])
            return json.dumps({'ok': False, 'error_kind': 'TimeoutError', 'error': 'timed out'})

        before = sorted(str(p.relative_to(self.root)) for p in self.root.rglob('*'))
        with patch('hal_fleet.install.remote_command', side_effect=remote):
            result = network_check(self.inventory, self.credentials, '/tmp/ssh-key', 'files')
        self.assertFalse(result['ok'])
        self.assertEqual(calls, ['files'])
        self.assertEqual(len(result['vm_source_ranges']), 4)
        self.assertEqual(result['checks'][0]['destination'], 'https://192.0.2.10/v1/trust')
        self.assertEqual(before, sorted(str(p.relative_to(self.root)) for p in self.root.rglob('*')))

    def test_deploy_stops_before_installing_a_role_that_cannot_reach_identity(self):
        operator, issuer = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
        operator_path = self.root/'operator.json'
        atomic_json(operator_path, {'private_key': private_hex(operator)})
        repo = self.root/'repo'
        repo.mkdir()
        (repo/'fleet.py').write_text('# packaging fixture\n')
        endpoints = {r: 'https://' + self.info['vms'][r]['ip'] for r in ROLES}
        trust = dict(identity_public_key=public(issuer), operator_public_key=public(operator), endpoints=endpoints)
        transport = Mock()
        transport.call.side_effect = [{'status': 'ready'}, sign(issuer, DOCUMENT_DOMAIN, trust)]
        remote = Mock(return_value='[Service]\nWorkingDirectory=/tmp/hal\n')
        failure = dict(ok=False, destination=endpoints['identity']+'/v1/trust', error_kind='TimeoutError', error='timed out')
        with patch('hal_fleet.install.Transport', return_value=transport), \
                patch('hal_fleet.install.remote_command', remote), \
                patch('hal_fleet.install.identity_network_check', return_value=failure):
            with self.assertRaises(Error) as raised:
                deploy(repo, self.inventory, self.credentials, '/tmp/ssh-key', operator_path, False)
        self.assertEqual(raised.exception.code, 'network_check_failed')
        self.assertIn('files VM (192.0.2.11)', str(raised.exception))
        self.assertIn('TimeoutError: timed out', str(raised.exception))
        self.assertTrue(remote.call_args_list)
        self.assertTrue(all(call.args[2] == 'identity' for call in remote.call_args_list))


class ProbeTLSTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='hal-probe-tls-')
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        info = dict(vms={role: dict(ip='127.0.0.' + str(i+1), ssh_user='tester') for i, role in enumerate(ROLES)})
        atomic_json(root/'inventory.json', info)
        certificates(root/'inventory.json', root/'tls')
        certificates(root/'inventory.json', root/'untrusted')
        self.ca = (root/'tls/ca.pem').read_text()
        self.wrong_ca = (root/'untrusted/ca.pem').read_text()
        self.requests = []
        requests = self.requests

        class App:
            config = {'role': 'identity'}

            def handle(self, method, path, body):
                requests.append((method, path, body))
                return {'payload': '{}', 'signature': 'fixture'}

        self.server = make_server(dict(listen='127.0.0.1:0', tls_cert=str(root/'tls/identity.crt'),
                                      tls_key=str(root/'tls/identity.key')), App())
        threading.Thread(target=self.server.serve_forever, kwargs={'poll_interval': .01}, daemon=True).start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.url = 'https://127.0.0.1:' + str(self.server.server_port)

    def test_real_tls_probe_is_read_only_and_rejects_wrong_ca(self):
        result = probe_identity(self.url, self.ca)
        self.assertTrue(result['ok'], result)
        self.assertTrue(result['tls_verified'])
        rejected = probe_identity(self.url, self.wrong_ca)
        self.assertFalse(rejected['ok'])
        self.assertEqual(rejected['error_kind'], 'SSLCertVerificationError')
        self.assertEqual(self.requests, [('GET', '/v1/trust', None)])

    def test_probe_runs_without_installed_repo_or_signing_dependencies(self):
        def ssh(role, command, data=None, capture=False):
            # -I -S disables user paths/site packages, including cryptography.
            code = shlex.split(command)[2]
            result = subprocess.run([sys.executable, '-I', '-S', '-c', code], input=data,
                                    capture_output=True, check=True)
            return result.stdout.decode()

        result = identity_network_check(ssh, 'files', self.url, self.ca)
        self.assertTrue(result['ok'], result)
        self.assertEqual(self.requests, [('GET', '/v1/trust', None)])


if __name__ == '__main__':
    unittest.main(verbosity=2)
