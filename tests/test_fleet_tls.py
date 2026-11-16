#!/usr/bin/env python3
"""Strict TLS certificate tests, using temporary keys only."""
import datetime
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import ExtensionOID
from hal_fleet.common import Error, atomic_json
from hal_fleet.install import ROLES, certificates
from hal_fleet import tls_certificates


# Exercise Python 3.13's actual default client context without binding sockets or
# requiring cryptography in the subprocess. MemoryBIO still performs a real TLS
# handshake and certificate verification with the selected Python/OpenSSL.
HANDSHAKE = '''
import json, ssl, sys
settings = json.load(sys.stdin)
assert sys.version_info >= (3, 13), "Use Python 3.13 or later for this regression"
client_ctx = ssl.create_default_context(cafile=settings["ca"])
assert client_ctx.verify_flags & ssl.VERIFY_X509_STRICT, "Strict default required"
assert client_ctx.check_hostname and client_ctx.verify_mode == ssl.CERT_REQUIRED
server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
server_ctx.load_cert_chain(settings["cert"], settings["key"])
ci, co, si, so = [ssl.MemoryBIO() for _ in range(4)]
client = client_ctx.wrap_bio(ci, co, server_hostname=settings["ip"])
server = server_ctx.wrap_bio(si, so, server_side=True)
done = [False, False]
try:
    for _ in range(50):
        for i, peer in enumerate((client, server)):
            if not done[i]:
                try:
                    peer.do_handshake()
                    done[i] = True
                except ssl.SSLWantReadError:
                    pass
        if co.pending:
            si.write(co.read())
        if so.pending:
            ci.write(so.read())
        if all(done):
            print(json.dumps({"ok": True, "openssl": ssl.OPENSSL_VERSION}))
            break
    else:
        raise RuntimeError("TLS handshake did not complete")
except ssl.SSLCertVerificationError as error:
    print(json.dumps({"ok": False, "error": str(error), "openssl": ssl.OPENSSL_VERSION}))
'''


class CertificateTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='hal-cert-test-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.info = dict(vms={role: dict(ip='192.0.2.' + str(i + 10), ssh_user='tester')
                              for i, role in enumerate(ROLES)})
        self.inventory = self.root / 'inventory.json'
        atomic_json(self.inventory, self.info)
        self.tls = self.root / 'tls'
        certificates(self.inventory, self.tls)
        self.ca_key = serialization.load_pem_private_key((self.tls / 'ca-key.pem').read_bytes(), None)

    def snapshot(self):
        return {str(p.relative_to(self.tls)): p.read_bytes() for p in self.tls.rglob('*') if p.is_file()}

    def cert(self, name):
        return x509.load_pem_x509_certificate((self.tls / name).read_bytes())

    def rewrite(self, name, omit=(), add=(), expired=False):
        cert = self.cert(name)
        start, end = cert.not_valid_before_utc, cert.not_valid_after_utc
        if expired:
            end = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1)
            start = end - datetime.timedelta(days=90)
        builder = (x509.CertificateBuilder().subject_name(cert.subject).issuer_name(cert.issuer)
                   .public_key(cert.public_key()).serial_number(cert.serial_number)
                   .not_valid_before(start).not_valid_after(end))
        for extension in cert.extensions:
            if extension.oid not in omit:
                builder = builder.add_extension(extension.value, extension.critical)
        for value, critical in add:
            builder = builder.add_extension(value, critical)
        (self.tls / name).write_bytes(builder.sign(self.ca_key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM))


    def openssl(self):
        candidates = [shutil.which('openssl'), '/opt/homebrew/opt/openssl@3/bin/openssl']
        for candidate in candidates:
            if candidate and Path(candidate).exists():
                result = subprocess.run([candidate, 'version'], capture_output=True, text=True, check=True)
                if result.stdout.startswith('OpenSSL 3.'):
                    return candidate
        self.skipTest('OpenSSL 3 is required for the strict chain verifier regression')

    def verify_strict(self, executable, role):
        return subprocess.run([executable, 'verify', '-x509_strict', '-purpose', 'sslserver',
                               '-verify_ip', self.info['vms'][role]['ip'], '-CAfile', str(self.tls / 'ca.pem'),
                               str(self.tls / (role + '.crt'))], capture_output=True, text=True)

    def test_new_certificates_pass_openssl3_strict_verification_for_all_four_ips(self):
        executable = self.openssl()
        for role in ROLES:
            with self.subTest(role=role):
                result = self.verify_strict(executable, role)
                self.assertEqual(result.returncode, 0, result.stderr)


    def test_python313_default_tls_handshake_and_hostname_validation(self):
        candidates = [os.environ.get('HAL_TLS_TEST_PYTHON'), shutil.which('python3.13'),
                      shutil.which('python3.14'), sys.executable]
        executable = None
        for candidate in candidates:
            if not candidate:
                continue
            result = subprocess.run([candidate, '-I', '-S', '-c',
                'import ssl, sys; sys.exit(0 if sys.version_info >= (3, 13) and '
                'ssl.create_default_context().verify_flags & ssl.VERIFY_X509_STRICT else 1)'],
                capture_output=True)
            if result.returncode == 0:
                executable = candidate
                break
        if not executable:
            self.skipTest('Python 3.13+ with strict defaults is required; set HAL_TLS_TEST_PYTHON')

        def handshake(role='identity', ip=None):
            settings = dict(ca=str(self.tls / 'ca.pem'), cert=str(self.tls / (role + '.crt')),
                            key=str(self.tls / (role + '.key')), ip=ip or self.info['vms'][role]['ip'])
            result = subprocess.run([executable, '-I', '-S', '-c', HANDSHAKE], input=json.dumps(settings),
                                    capture_output=True, text=True, check=True)
            return json.loads(result.stdout)

        for role in ROLES:
            self.assertTrue(handshake(role)['ok'])
        self.assertFalse(handshake(ip='192.0.2.200')['ok'], 'IP validation must remain enabled')

    def test_validation_is_read_only_and_accepts_generated_certificates(self):
        before = self.snapshot()
        tls_certificates.validate(self.info, self.tls)
        self.assertEqual(before, self.snapshot())

    def test_validation_rejects_missing_extensions_without_rewriting_files(self):
        self.rewrite('identity.crt', omit=[ExtensionOID.AUTHORITY_KEY_IDENTIFIER])
        before = self.snapshot()
        with self.assertRaisesRegex(Error, 'missing strict X.509 extensions'):
            tls_certificates.validate(self.info, self.tls)
        self.assertEqual(before, self.snapshot())

    def test_validation_rejects_expiry_and_wrong_inventory(self):
        info = json.loads(json.dumps(self.info))
        info['vms']['identity']['ip'] = '192.0.2.200'
        with self.assertRaisesRegex(Error, 'unexpected subjectAltName'):
            tls_certificates.validate(info, self.tls)
        self.rewrite('identity.crt', expired=True)
        with self.assertRaisesRegex(Error, 'expired or not yet valid'):
            tls_certificates.validate(self.info, self.tls)


if __name__ == '__main__':
    unittest.main(verbosity=2)
