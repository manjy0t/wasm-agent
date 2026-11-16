#!/usr/bin/env python3
"""Trustee contract/rejection tests. Signed fixture tokens are NOT TEE evidence."""
import base64
import copy
import io
import json
from pathlib import Path
import ssl
import sys
import tempfile
import time
import threading
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from hal_fleet.common import Error, canonical, digest, parse
from hal_fleet.attested_channel import binding_hash, validate_policy, verify_evidence
from hal_fleet import trustee
from hal_fleet.trustee_policy import render, main as generate_policy


class TrusteeTest(unittest.TestCase):
    def setUp(self):
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.pem = self.key.public_key().public_bytes(serialization.Encoding.PEM,
                   serialization.PublicFormat.SubjectPublicKeyInfo).decode()
        self.policy = dict(version=1, platform='intel-tdx', runtime_binding='approved-measured-boot', lease_seconds=300,
            measurements={k: 'a' * 96 for k in trustee.TDX_FIELDS}, verifier='trustee',
            trustee=dict(release='0.22.0', url='http://127.0.0.1:8080', signer_public_key_pem=self.pem,
                         issuer='test-hal-as', policy_id='hal-test-tdx'))
        self.binding = dict(challenge='fresh-test-only', recipient_key='a' * 64, agent_sha256='b' * 64)
        self.raw = b'fixture-quote-not-hardware-evidence'
        self.expected = binding_hash(self.binding)
        self.evidence = dict(platform='intel-tdx', report_hex=self.raw.hex())

    def payload(self, tee='tdx'):
        if tee == 'tdx':
            claims = dict(quote=dict(header={'tee_type': '81000000', 'vendor_id': '939a7233f79c4ca9940a0db3957f0607'},
                          body={v: self.policy['measurements'][k] for k, v in trustee.TDX_FIELDS.items()}),
                          td_attributes={'debug': False}, tcb_status='UpToDate', collateral_expiration_status='0')
        else:
            claims = dict(measurement='a' * 96, chip_id='b' * 128, policy_debug_allowed=False, policy_migrate_ma=False,
                          **{'reported_tcb_' + k: v for k, v in self.policy['snp_minimum_tcb'].items()})
        vector = {'hardware': 2, 'configuration': 2, 'executables': 3, 'instance-identity': 0,
                  'file-system': 0, 'runtime-opaque': 0, 'storage-opaque': 0, 'sourced-data': 0}
        appraisal = {'ear.status': 'affirming', 'ear.appraisal-policy-id': self.policy['trustee']['policy_id'],
                     'ear.trustworthiness-vector': vector, 'hal.policy-binding': trustee.policy_binding(self.policy),
                     'ear.veraison.annotated-evidence': {tee: claims, 'report_data': self.expected,
                          'runtime_data_claims': None, 'init_data': '0' * 64, 'init_data_claims': None}}
        return {'iss': 'test-hal-as', 'eat_profile': trustee.PROFILE, 'iat': int(time.time()),
                'exp': int(time.time()) + 300, 'submods': {'cpu0': appraisal}}

    def token(self, payload=None, header=None, key=None, raw_payload=None):
        header = header if header is not None else {'alg': 'ES256', 'typ': 'JWT'}
        payload = payload if payload is not None else self.payload()
        message = trustee.b64url(canonical(header).encode()) + '.' + trustee.b64url(
            raw_payload if raw_payload is not None else canonical(payload).encode())
        r, s = decode_dss_signature((key or self.key).sign(message.encode(), ec.ECDSA(hashes.SHA256())))
        return message + '.' + trustee.b64url(r.to_bytes(32, 'big') + s.to_bytes(32, 'big'))

    def verify(self, token):
        with mock.patch('hal_fleet.trustee._post', return_value=token):
            return verify_evidence(self.policy, self.evidence, self.binding)

    def snp(self):
        # Shape-correct, unsigned fixture; only the mock verifier accepts it.
        self.raw = bytes(1184)
        self.evidence['report_hex'] = self.raw.hex()
        self.policy.update(platform='amd-sev-snp', measurements={'measurement': 'a' * 96},
                           snp_product='Genoa', snp_minimum_tcb=dict(bootloader=3, tee=0, snp=22, microcode=100))
        self.policy['trustee']['snp_codec'] = dict(path='/trusted/codec', sha256='c' * 64)
        self.policy['trustee']['policy_id'] = 'hal-test-snp'
        self.evidence['platform'] = 'amd-sev-snp'
        return dict(evidence={'attestation_report': {'fixture': True}, 'cert_chain': None}, product='Genoa',
                    vmpl=0, chip_id='b' * 128, report_data=self.expected)

    def test_tdx_token_and_rest_request_preserve_binding(self):
        with mock.patch('hal_fleet.trustee._post', return_value=self.token()) as send:
            result = verify_evidence(self.policy, self.evidence, self.binding)
        self.assertTrue(result['verified'])
        self.assertEqual(result['tcb'], {'status': 'UpToDate'})
        self.assertEqual(result['evidence_sha256'], digest(self.raw))
        body = send.call_args.args[1]
        self.assertEqual(body['policy_ids'], ['hal-test-tdx'])
        request = body['verification_requests'][0]
        self.assertEqual(request['tee'], 'tdx')
        encoded = parse(trustee.unb64url(request['evidence']))
        self.assertEqual(base64.b64decode(encoded['quote'], validate=True), self.raw)
        self.assertEqual(trustee.unb64url(request['runtime_data']['raw']), bytes.fromhex(self.expected))

    def test_three_hour_session_still_requires_a_fresh_short_lived_appraisal(self):
        self.policy['lease_seconds'] = 10800
        self.assertIs(validate_policy(self.policy), self.policy)
        self.assertTrue(self.verify(self.token())['verified'])
        payload = self.payload()
        payload['exp'] = payload['iat'] + 301
        with self.assertRaisesRegex(Error, 'token lifetime'):
            self.verify(self.token(payload))

    def test_unpinned_signer_and_header_key_substitution_fail(self):
        other = ec.generate_private_key(ec.SECP256R1())
        with self.assertRaises(Error):
            self.verify(self.token(key=other, header={'alg': 'ES256', 'jwk': {'attacker': 'key'}}))
        # An embedded JWK is ignored even when the token itself is correctly signed.
        self.assertTrue(self.verify(self.token(header={'alg': 'ES256', 'jwk': {'ignored': True}}))['verified'])

    def test_algorithm_confusion_extensions_and_unsigned_tokens_fail(self):
        for header in ({'alg': 'none'}, {'alg': 'HS256'}, {'alg': 'RS256'}, {'alg': 'ES256', 'crit': []},
                       {'alg': 'ES256', 'b64': False}, {'alg': 'ES256', 'jku': 'https://attacker'},
                       {'alg': 'ES256', 'x5u': 'https://attacker'}):
            with self.subTest(header=header), self.assertRaises(Error):
                self.verify(self.token(header=header))

    def test_mutated_payload_or_signature_is_rejected(self):
        valid = self.token().split('.')
        changed = copy.deepcopy(valid)
        changed[1] = trustee.b64url(b'{}')
        with self.assertRaises(Error): self.verify('.'.join(changed))
        valid[2] = trustee.b64url(b'\0' * 64)
        with self.assertRaises(Error): self.verify('.'.join(valid))

    def test_token_times_and_identity_are_checked(self):
        now = int(time.time())
        changes = [dict(exp=now-1), dict(iat=now-50), dict(iat=now+30), dict(exp=now+301),
                   dict(iat=True), dict(exp=None), dict(nbf=now+30), dict(iss='other'), dict(eat_profile='legacy')]
        for change in changes:
            with self.subTest(change=change), self.assertRaises(Error):
                self.verify(self.token(dict(self.payload(), **change)))

    def test_no_policy_downgrade_or_unrelated_cpu_appraisal(self):
        changes = [{'ear.status': 'warning'}, {'ear.status': 'contraindicated'},
                   {'ear.appraisal-policy-id': 'default'}, {'hal.policy-binding': '0' * 64},
                   {'ear.trustworthiness-vector': {'hardware': 2}}]
        for change in changes:
            payload = self.payload()
            payload['submods']['cpu0'].update(change)
            with self.subTest(change=change), self.assertRaises(Error): self.verify(self.token(payload))
        payload = self.payload()
        payload['submods']['cpu1'] = payload['submods']['cpu0']
        with self.assertRaises(Error): self.verify(self.token(payload))

    def test_rejected_tdx_appraisal_names_changed_measurements_without_approving_them(self):
        original = copy.deepcopy(self.policy)
        payload = self.payload()
        appraisal = payload['submods']['cpu0']
        appraisal['ear.status'] = 'contraindicated'
        appraisal['ear.trustworthiness-vector'].update(hardware=97, configuration=36, executables=33)
        body = appraisal['ear.veraison.annotated-evidence']['tdx']['quote']['body']
        body.update(rtmr_1='b' * 96, rtmr_2='c' * 96)
        with self.assertRaisesRegex(Error, 'approved measurement checks failed: rtmr1, rtmr2') as caught:
            self.verify(self.token(payload))
        self.assertEqual(caught.exception.code, 'attestation_failed')
        self.assertEqual(self.policy, original)
        self.assertNotIn('b' * 96, str(caught.exception))

    def test_rejected_appraisal_with_matching_measurements_still_fails(self):
        payload = self.payload()
        payload['submods']['cpu0']['ear.status'] = 'contraindicated'
        with self.assertRaisesRegex(Error, 'status=contraindicated') as caught:
            self.verify(self.token(payload))
        self.assertNotIn('measurement checks failed', str(caught.exception))

    def test_measurement_diagnostics_require_authenticated_pinned_policy(self):
        for mutation in ('signer', 'policy-id', 'policy-binding'):
            payload = self.payload()
            appraisal = payload['submods']['cpu0']
            appraisal['ear.status'] = 'contraindicated'
            if mutation == 'policy-id':
                appraisal['ear.appraisal-policy-id'] = 'default'
            if mutation == 'policy-binding':
                appraisal['hal.policy-binding'] = '0' * 64
            key = ec.generate_private_key(ec.SECP256R1()) if mutation == 'signer' else self.key
            with self.subTest(mutation=mutation), mock.patch.object(trustee, '_measurement_mismatches') as details:
                with self.assertRaises(Error):
                    self.verify(self.token(payload, key=key))
                details.assert_not_called()

    def test_rejected_incomplete_claims_keep_a_bounded_error(self):
        for annotated in (None, [], {'tdx': None}, {'tdx': {'quote': []}}, {'tdx': {'quote': {'body': None}}}):
            payload = self.payload()
            appraisal = payload['submods']['cpu0']
            appraisal.update({'ear.status': 'unsafe\n' + 'x' * 10000, 'ear.veraison.annotated-evidence': annotated})
            with self.subTest(annotated=annotated), self.assertRaisesRegex(Error, 'status=unknown') as caught:
                self.verify(self.token(payload))
            self.assertLess(len(str(caught.exception)), 100)

    def test_rejected_snp_appraisal_names_measurement_mismatch(self):
        snp = self.snp()
        payload = self.payload('snp')
        appraisal = payload['submods']['cpu0']
        appraisal['ear.status'] = 'contraindicated'
        appraisal['ear.veraison.annotated-evidence']['snp']['measurement'] = 'b' * 96
        with mock.patch('hal_fleet.trustee._snp_evidence', return_value=snp), mock.patch(
                'hal_fleet.trustee._post', return_value=self.token(payload)), self.assertRaisesRegex(
                    Error, 'approved measurement checks failed: measurement'):
            verify_evidence(self.policy, self.evidence, self.binding)

    def test_wrong_channel_nonce_recipient_agent_and_platform_fail(self):
        token = self.token()
        for change in (dict(challenge='old'), dict(recipient_key='0'*64), dict(agent_sha256='0'*64)):
            with self.subTest(change=change), mock.patch('hal_fleet.trustee._post', return_value=token), self.assertRaises(Error):
                verify_evidence(self.policy, self.evidence, dict(self.binding, **change))
        payload = self.payload()
        ann = payload['submods']['cpu0']['ear.veraison.annotated-evidence']
        ann['snp'] = ann.pop('tdx')
        with self.assertRaises(Error): self.verify(self.token(payload))

    def test_tdx_debug_tcb_expired_collateral_and_measurement_fail(self):
        for field, value in [('td_attributes', {'debug': True}), ('td_attributes', None),
                             ('tcb_status', 'OutOfDate'), ('collateral_expiration_status', '1')]:
            payload = self.payload()
            payload['submods']['cpu0']['ear.veraison.annotated-evidence']['tdx'][field] = value
            with self.subTest(field=field), self.assertRaises(Error): self.verify(self.token(payload))
        for field in trustee.TDX_FIELDS.values():
            payload = self.payload()
            payload['submods']['cpu0']['ear.veraison.annotated-evidence']['tdx']['quote']['body'][field] = '0' * 96
            with self.subTest(field=field), self.assertRaises(Error): self.verify(self.token(payload))

    def test_duplicate_nonfinite_malformed_oversized_claims_fail(self):
        for raw in (b'{"iss":"a","iss":"b"}', b'{"iat":NaN}', b'[]', b'null'):
            with self.subTest(raw=raw), self.assertRaises(Error): self.verify(self.token(raw_payload=raw))
        for token in ('', 'a.b', 'a.b.c.d', 'a.b.c', 'x' * (trustee.MAX_TOKEN + 1)):
            with self.subTest(length=len(token)), self.assertRaises(Error): self.verify(token)

    def test_snp_accepts_componentwise_tcb_without_fabricating_intel_status(self):
        snp = self.snp()
        with mock.patch('hal_fleet.trustee._snp_evidence', return_value=snp), mock.patch(
                'hal_fleet.trustee._post', return_value=self.token(self.payload('snp'))) as send:
            result = verify_evidence(self.policy, self.evidence, self.binding)
        self.assertTrue(result['verified'])
        self.assertEqual(result['tcb'], self.policy['snp_minimum_tcb'])
        self.assertNotIn('status', result['tcb'])
        self.assertEqual(send.call_args.args[1]['verification_requests'][0]['tee'], 'snp')

    def test_aws_vlek_certificate_is_sent_to_trustee_without_changing_report(self):
        import struct
        import uuid
        snp = self.snp()
        report = bytearray(self.raw)
        struct.pack_into('<I', report, 0x48, 4)  # VLEK, still an unsigned fixture.
        self.raw = bytes(report)
        self.evidence['report_hex'] = self.raw.hex()
        certificate = b'fixture-certificate-not-valid'
        table = (struct.pack('<16sII', uuid.UUID('a8074bc2-a25a-483e-aae6-39c045a0b8a1').bytes,
                             48, len(certificate)) + bytes(24) + certificate)
        self.evidence['certificates_hex'] = table.hex()
        with mock.patch('hal_fleet.trustee._snp_evidence', return_value=snp) as codec, mock.patch(
                'hal_fleet.trustee._post', return_value=self.token(self.payload('snp'))) as send:
            result = verify_evidence(self.policy, self.evidence, self.binding)
        codec.assert_called_once_with(self.policy['trustee'], self.raw)
        evidence = parse(trustee.unb64url(send.call_args.args[1]['verification_requests'][0]['evidence']))
        self.assertEqual(evidence['cert_chain'], [{'cert_type': 'VLEK', 'data': list(certificate)}])
        self.assertEqual(result['evidence_sha256'], digest(self.raw))
        # A well-formed certificate table is never itself a successful appraisal.
        with mock.patch('hal_fleet.trustee._snp_evidence', return_value=snp), mock.patch(
                'hal_fleet.trustee._post', side_effect=Error('AMD signature rejected')), self.assertRaises(Error):
            verify_evidence(self.policy, self.evidence, self.binding)
        self.evidence.pop('certificates_hex')
        with mock.patch('hal_fleet.trustee._snp_evidence', return_value=snp), mock.patch('hal_fleet.trustee._post') as send:
            with self.assertRaisesRegex(Error, 'VLEK certificate'):
                verify_evidence(self.policy, self.evidence, self.binding)
        send.assert_not_called()

    def test_extra_endorsements_cannot_be_attached_to_tdx(self):
        with self.assertRaises(Error):
            verify_evidence(self.policy, dict(self.evidence, certificates_hex='00'), self.binding)

    def test_snp_debug_migration_minimums_and_report_misrouting_fail(self):
        snp = self.snp()
        changes = [('policy_debug_allowed', True), ('policy_migrate_ma', True), ('measurement', '0'*96),
                   ('chip_id', '0'*128), ('reported_tcb_microcode', 99), ('reported_tcb_bootloader', 2),
                   ('reported_tcb_tee', False), ('reported_tcb_snp', None)]
        with mock.patch('hal_fleet.trustee._snp_evidence', return_value=snp):
            for key, value in changes:
                payload = self.payload('snp')
                payload['submods']['cpu0']['ear.veraison.annotated-evidence']['snp'][key] = value
                with self.subTest(key=key), self.assertRaises(Error): self.verify(self.token(payload))

    def test_snp_bad_codec_vmpl_product_binding_fail_before_as(self):
        snp = self.snp()
        for change in (dict(vmpl=1), dict(vmpl=False), dict(product='Milan'), dict(report_data='0'*128)):
            with self.subTest(change=change), mock.patch('hal_fleet.trustee._snp_evidence', return_value=dict(snp, **change)), mock.patch(
                    'hal_fleet.trustee._post') as send, self.assertRaises(Error):
                verify_evidence(self.policy, self.evidence, self.binding)
            send.assert_not_called()
        with mock.patch('hal_fleet.trustee.Path.read_bytes', return_value=b'changed'), mock.patch(
                'hal_fleet.attested_channel.bounded_command') as execute, self.assertRaises(Error):
            verify_evidence(self.policy, self.evidence, self.binding)
        execute.assert_not_called()

    def test_policy_requires_vendor_thresholds_and_pinned_release(self):
        for change in (dict(release='latest'), dict(policy_id='default'), dict(signer_public_key_pem=''),
                       dict(url='http://trustee.example'), dict(url='https://u:p@trustee.example'),
                       dict(url='https://trustee.example/attestation'), dict(extra='typo')):
            p = copy.deepcopy(self.policy)
            p['trustee'].update(change)
            with self.subTest(change=change), self.assertRaises(Error): validate_policy(p)
        self.snp()
        for change in (dict(snp_minimum_tcb={}), dict(snp_product='Turin')):
            with self.subTest(change=change), self.assertRaises(Error): validate_policy(dict(self.policy, **change))

    def test_http_rejects_redirect_unavailable_and_oversized_response(self):
        for status, data in ((302, b''), (500, b'private detail'), (200, b'x'*(trustee.MAX_TOKEN+1))):
            response = mock.Mock(status=status)
            response.read.return_value = data
            connection = mock.Mock()
            connection.getresponse.return_value = response
            with mock.patch('hal_fleet.trustee.http.client.HTTPConnection', return_value=connection), self.assertRaises(Error):
                trustee._post(self.policy['trustee'], {})
            self.assertEqual(connection.request.call_count, 1)
            connection.close.assert_called_once()

    def test_tls_connection_uses_verified_context_and_never_falls_back(self):
        config = dict(self.policy['trustee'], url='https://trustee.example')
        with mock.patch('hal_fleet.trustee.http.client.HTTPSConnection', side_effect=OSError('certificate failure')), mock.patch(
                'hal_fleet.trustee.http.client.HTTPConnection') as insecure, self.assertRaises(Error):
            trustee._post(config, {})
        insecure.assert_not_called()

    def test_actual_https_request_and_signed_response_with_private_ca(self):
        # A local AS-shaped fixture, not a hardware verifier. Exercise the wire,
        # TLS trust, signed response and management integration together.
        from http.server import BaseHTTPRequestHandler, HTTPServer
        from hal_fleet.install import certificates, ROLES
        token = self.token()
        requests = []
        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                requests.append((self.path, parse(self.rfile.read(int(self.headers['Content-Length'])))))
                raw = token.encode()
                self.send_response(200)
                self.send_header('Content-Length', str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)
            def log_message(self, *args):
                pass
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            inventory = {'vms': {role: {'ip': '127.0.0.' + str(i + 1), 'ssh_user': 'fixture'}
                                 for i, role in enumerate(ROLES)}}
            (root/'inventory.json').write_text(canonical(inventory))
            certificates(root/'inventory.json', root/'tls')
            identity_ip = inventory['vms']['identity']['ip']
            server = HTTPServer((identity_ip, 0), Handler)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(root/'tls/identity.crt', root/'tls/identity.key')
            server.socket = context.wrap_socket(server.socket, server_side=True)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                config = self.policy['trustee']
                config.update(url='https://' + identity_ip + ':' + str(server.server_address[1]),
                              ca_pem=(root/'tls/ca.pem').read_text())
                result = verify_evidence(self.policy, self.evidence, self.binding)
                self.assertTrue(result['verified'])
                self.assertEqual(requests[0][0], '/attestation')
                self.assertEqual(requests[0][1]['policy_ids'], ['hal-test-tdx'])
                del config['ca_pem']
                with self.assertRaises(Error): verify_evidence(self.policy, self.evidence, self.binding)
                self.assertEqual(len(requests), 1)  # Untrusted TLS never reaches POST.
            finally:
                server.shutdown()
                thread.join(timeout=5)
                server.server_close()

    def test_policy_generator_preserves_approved_inputs_and_wont_overwrite(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = dict(self.policy, verifier='intel-dcap', qvl_library='/example/qvl')
            original.pop('trustee')
            (root/'approved.json').write_text(canonical(original))
            (root/'public.pem').write_text(self.pem)
            args = ['--policy', str(root/'approved.json'), '--signer-public-key', str(root/'public.pem'),
                    '--output', str(root/'generated')]
            with mock.patch('sys.stdout', new=io.StringIO()): self.assertEqual(generate_policy(args), 0)
            policy = parse((root/'generated/attestation-policy.json').read_text())
            self.assertEqual(policy['measurements'], original['measurements'])
            self.assertNotIn('qvl_library', policy)
            upload = parse((root/'generated/policy-upload.json').read_text())
            self.assertEqual(upload['policy_id'], policy['trustee']['policy_id'] + '_cpu')
            self.assertEqual(trustee.unb64url(upload['policy']).decode(), render(policy))
            with mock.patch('sys.stderr', new=io.StringIO()): self.assertEqual(generate_policy(args), 1)
            self.assertEqual(parse((root/'approved.json').read_text()), original)

    def test_source_package_includes_codec_and_excludes_built_tools(self):
        from hal_fleet.install import source_files
        paths = {str(relative) for _, relative in source_files(ROOT)}
        self.assertIn('tools/trustee-snp-codec/Cargo.toml', paths)
        self.assertIn('tools/trustee-snp-codec/src/main.rs', paths)
        self.assertIn('hal_fleet/trustee.py', paths)
        self.assertFalse(any('target/' in path for path in paths))


if __name__ == '__main__':
    unittest.main(verbosity=2)
