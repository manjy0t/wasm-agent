"""Strict X.509 metadata and read-only validation of fleet certificates."""
import datetime
import ipaddress
import re
from pathlib import Path

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID

from .common import Error, require
from .local_files import read_regular


def service_names(vm):
    """Keep IP clients working; optionally authenticate AWS split-horizon DNS."""
    names = [x509.IPAddress(ipaddress.ip_address(vm['ip']))]
    if 'hostname' in vm:
        hostname = vm['hostname']
        require(isinstance(hostname, str) and len(hostname) <= 253
                and all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label)
                        for label in hostname.split('.')) and '.' in hostname,
                'Invalid service TLS hostname')
        names.append(x509.DNSName(hostname))
    return names


def key_extensions(public_key, issuer_public_key, ca):
    # Python 3.13 enables OpenSSL strict verification by default. In particular,
    # a v3 CA needs an SKI and issued certificates need a noncritical AKI.
    return [
        (x509.SubjectKeyIdentifier.from_public_key(public_key), False),
        (x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_public_key), False),
        (x509.KeyUsage(digital_signature=True, content_commitment=False,
                       key_encipherment=False, data_encipherment=False, key_agreement=False,
                       key_cert_sign=ca, crl_sign=ca, encipher_only=False, decipher_only=False), True),
    ]


def add_key_extensions(builder, public_key, issuer_public_key, ca):
    for extension, critical in key_extensions(public_key, issuer_public_key, ca):
        builder = builder.add_extension(extension, critical=critical)
    return builder


def _read_file(path, private=False):
    try:
        return read_regular(path, private=private, maximum=65536)
    except ValueError as exc:
        raise Error(str(exc)) from exc




def _required_extension(cert, expected, critical, name):
    try:
        actual = cert.extensions.get_extension_for_oid(expected.oid)
    except x509.ExtensionNotFound as exc:
        raise ValueError(name + ': missing required ' + expected.oid._name + '; no certificates changed') from exc
    require(actual.value == expected and actual.critical == critical,
            name + ': unexpected ' + expected.oid._name + '; no certificates changed')


def _validate(certs, info):
    """Validate the fleet profile without changing names, trust or validity."""
    now = datetime.datetime.now(datetime.timezone.utc)
    ca = certs['ca.pem']
    require(ca.subject == ca.issuer, 'Fleet CA must be self-issued')
    for name, cert in certs.items():
        require(cert.version == x509.Version.v3, name + ': expected an X.509 v3 certificate')
        require(cert.not_valid_before_utc <= now < cert.not_valid_after_utc,
                name + ': certificate is expired or not yet valid')
        public_key = cert.public_key()
        require(isinstance(public_key, ec.EllipticCurvePublicKey) and isinstance(public_key.curve, ec.SECP256R1),
                name + ': expected the fleet P-256 key type')
        try:
            cert.verify_directly_issued_by(ca)
        except (ValueError, TypeError, InvalidSignature) as exc:
            raise ValueError(name + ': signature does not match the existing CA; no certificates changed') from exc
        is_ca = name == 'ca.pem'
        _required_extension(cert, x509.BasicConstraints(ca=is_ca, path_length=0 if is_ca else None), True, name)
        if is_ca:
            _required_extension(cert, key_extensions(public_key, ca.public_key(), True)[2][0], True, name)
        else:
            role = name[:-4]
            _required_extension(cert, x509.SubjectAlternativeName(service_names(info['vms'][role])), False, name)
            _required_extension(cert, x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), False, name)


def _missing_extensions(cert, issuer, is_ca, name):
    missing = []
    for expected, critical in key_extensions(cert.public_key(), issuer.public_key(), is_ca):
        try:
            actual = cert.extensions.get_extension_for_oid(expected.oid)
        except x509.ExtensionNotFound:
            missing.append((expected, critical))
            continue
        require(actual.value == expected and actual.critical == critical,
                name + ': conflicting ' + expected.oid._name + '; no certificates changed')
    return missing


def validate(info, credentials):
    """Require complete, current TLS certificates; never rewrite credentials."""
    credentials = Path(credentials)
    names = ['ca.pem'] + [role + '.crt' for role in info['vms']]
    certs = {name: x509.load_pem_x509_certificate(_read_file(credentials / name))
             for name in names}
    _validate(certs, info)
    for name, cert in certs.items():
        require(not _missing_extensions(cert, certs['ca.pem'], name == 'ca.pem', name),
                name + ': missing strict X.509 extensions; supply valid certificates')
