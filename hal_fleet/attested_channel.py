"""Fresh attestation binding and an authenticated deployment/job channel.

Only management calls the verifier. A remote `verified` flag is never evidence.
An external verifier is trusted management-side code, selected and hash-pinned by
an operator. It must validate vendor signatures, endorsements, revocation/TCB and
return claims from that verified evidence, not from the request's expected values.
"""
import base64
import hashlib
import os
from pathlib import Path
import subprocess
import tempfile
import time
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from .common import Error, canonical, digest, parse, require
from .lifetimes import MAX_SESSION_SECONDS

ABI = 'elastic:orchestration@1.1.0'
PROTOCOL = 'hal-managed-agent-v2'
MAX_AGENT = 8 * 1024 * 1024
MAX_MESSAGE = 20 * 1024 * 1024
DOMAIN = b'hal-managed-agent-v2\x00'


def encode(raw):
    return base64.b64encode(raw).decode('ascii')


def decode(value, maximum=MAX_MESSAGE):
    require(isinstance(value, str) and len(value) <= ((maximum + 2) // 3) * 4, 'Encoded message too large', 413)
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, TypeError) as exc:
        raise Error('Invalid base64') from exc
    require(len(raw) <= maximum, 'Decoded message too large', 413)
    return raw


def public_hex(key):
    return key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()


def binding_hash(binding):
    return hashlib.sha512(DOMAIN + canonical(binding).encode()).hexdigest()


def derive(key, peer, binding):
    try:
        secret = key.exchange(X25519PublicKey.from_public_bytes(bytes.fromhex(peer)))
    except (ValueError, TypeError) as exc:
        raise Error('Invalid channel public key', 403) from exc
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=bytes.fromhex(binding_hash(binding)),
                info=DOMAIN + b'channel').derive(secret)


def seal(key, binding, operation, value):
    nonce = os.urandom(12)
    aad = DOMAIN + canonical({'binding': binding, 'operation': operation}).encode()
    return {'nonce': encode(nonce), 'ciphertext': encode(AESGCM(key).encrypt(nonce, canonical(value).encode(), aad))}


def unseal(key, binding, operation, message):
    require(isinstance(message, dict) and set(message) == {'nonce', 'ciphertext'}, 'Invalid channel envelope')
    nonce, ciphertext = decode(message['nonce'], 12), decode(message['ciphertext'])
    require(len(nonce) == 12, 'Invalid channel nonce')
    aad = DOMAIN + canonical({'binding': binding, 'operation': operation}).encode()
    try:
        raw = AESGCM(key).decrypt(nonce, ciphertext, aad)
    except Exception as exc:
        raise Error('Channel authentication failed', 403, 'channel_rejected') from exc
    result = parse(raw)
    require(isinstance(result, dict), 'Expected encrypted object')
    return result


def bounded_command(argv, data, timeout=30, maximum=1024 * 1024):
    """No shell, bounded input/output, and no verifier/collector stderr in APIs."""
    require(isinstance(argv, list) and argv and all(isinstance(x, str) for x in argv), 'Invalid adapter command')
    try:
        with tempfile.TemporaryFile() as output:
            process = subprocess.run(argv, input=canonical(data).encode(), stdout=output,
                                     stderr=subprocess.DEVNULL, timeout=timeout, check=False)
            require(process.returncode == 0, 'Attestation adapter rejected evidence or is unavailable', 503,
                    'attestation_failed')
            require(output.tell() <= maximum, 'Attestation adapter output too large', 503)
            output.seek(0)
            return parse(output.read(maximum + 1))
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise Error('Attestation adapter unavailable or timed out', 503, 'attestation_failed') from exc


def validate_requirements(policy):
    """Validate reference requirements before an attestation backend is configured."""
    require(isinstance(policy, dict), 'Attestation policy must be a JSON object')
    require(policy.get('version') == 1, 'Attestation policy version must be 1')
    platform = policy.get('platform')
    require(platform in ('intel-tdx', 'amd-sev-snp'), 'Choose intel-tdx or amd-sev-snp')
    measurements = policy.get('measurements')
    fields = {'mrtd', 'rtmr0', 'rtmr1', 'rtmr2', 'rtmr3'} if platform == 'intel-tdx' else {'measurement'}
    require(isinstance(measurements, dict) and set(measurements) == fields,
            'Pin the complete approved platform measurement set')
    import re
    require(all(isinstance(v, str) and re.fullmatch('[0-9a-f]{96}', v) for v in measurements.values()),
            'Measurements must be 48-byte lowercase hex values')
    require(policy.get('runtime_binding') == 'approved-measured-boot',
            'Approve a measured boot chain that authenticates the HAL runtime and its configuration')
    require(type(policy.get('lease_seconds')) is int and 60 <= policy['lease_seconds'] <= MAX_SESSION_SECONDS,
            f'Lease must be 60..{MAX_SESSION_SECONDS} seconds')
    return policy


def validate_policy(policy):
    validate_requirements(policy)
    platform = policy['platform']
    if policy.get('verifier') == 'intel-dcap':
        require(platform == 'intel-tdx' and Path(policy.get('qvl_library', '')).is_absolute(), 'Configure an absolute Intel QVL library path')
    elif policy.get('verifier') == 'trustee':
        from .trustee import validate
        validate(policy)
    else:
        require(policy.get('verifier') == 'external', 'Choose trustee, intel-dcap or an external vendor verifier')
        argv = policy.get('verifier_argv')
        pins = policy.get('verifier_files')
        require(isinstance(argv, list) and argv and Path(argv[0]).is_absolute() and isinstance(pins, dict)
                and argv[0] in pins, 'Pin the absolute verifier executable and any scripts/configuration it loads')
    return policy


def verify_evidence(policy, evidence, binding):
    validate_policy(policy)
    expected = binding_hash(binding)
    require(isinstance(evidence, dict) and set(evidence) in
            ({'platform', 'report_hex'}, {'platform', 'report_hex', 'certificates_hex'}), 'Invalid raw evidence')
    require(evidence['platform'] == policy['platform'], 'Unexpected confidential platform', 403)
    certificates = b''
    try:
        require(isinstance(evidence['report_hex'], str) and len(evidence['report_hex']) <= 2 * 1024 * 1024, 'Evidence too large')
        raw = bytes.fromhex(evidence['report_hex'])
        if 'certificates_hex' in evidence:
            from .snp_certificates import MAX_CERTIFICATES
            require(policy['platform'] == 'amd-sev-snp', 'Only SNP evidence carries a certificate table')
            require(isinstance(evidence['certificates_hex'], str)
                    and len(evidence['certificates_hex']) <= 2 * MAX_CERTIFICATES, 'SNP certificates too large')
            certificates = bytes.fromhex(evidence['certificates_hex'])
    except ValueError as exc:
        raise Error('Invalid raw evidence') from exc
    require(raw, 'Empty attestation evidence', 403)
    if policy['verifier'] == 'intel-dcap':
        import sys
        claims = bounded_command([sys.executable, '-B', '-m', 'hal_fleet.dcap', policy['qvl_library']],
                                 {'report_hex': raw.hex()}, timeout=30)
    elif policy['verifier'] == 'trustee':
        from .trustee import verify
        claims = verify(policy, raw, expected, certificates=certificates)
    else:
        for filename, pin in policy['verifier_files'].items():
            try:
                actual = digest(Path(filename).read_bytes())
            except OSError as exc:
                raise Error('Trusted verifier file is unavailable', 503, 'attestation_failed') from exc
            require(actual == pin, 'Trusted verifier file changed', 503, 'attestation_failed')
        claims = bounded_command(policy['verifier_argv'], {'version': 1, 'evidence': evidence}, timeout=30)
    # Never use execution's platform/measurement/hash claims in place of these.
    require(claims.get('verified') is True and claims.get('platform') == policy['platform']
            and claims.get('evidence_sha256') == digest(raw), 'Evidence verification failed', 403, 'attestation_failed')
    require(claims.get('report_data') == expected, 'Attestation challenge or recipient key mismatch', 403)
    tcb_ok = claims.get('tcb_accepted') is True if policy['verifier'] == 'trustee' else claims.get('tcb_status') == 'UpToDate'
    require(claims.get('debug') is False and tcb_ok, 'Unacceptable debug/TCB state', 403)
    require(claims.get('measurements') == policy['measurements'], 'Platform measurements differ from approved policy', 403)
    if policy['platform'] == 'amd-sev-snp':
        require(claims.get('vmpl') == 0, 'SNP report must describe VMPL 0', 403)
    result = {'verified': True, 'platform': claims['platform'], 'evidence_sha256': digest(raw),
              'policy_sha256': digest(canonical(policy).encode()), 'verified_unix': int(time.time())}
    if policy['verifier'] == 'trustee':
        result.update(verifier='trustee', verifier_release=claims['verifier_release'],
                      appraisal_policy=policy['trustee']['policy_id'], tcb=claims['tcb'])
    return result

CERT_DOMAIN = b'HAL-AGENT-CERTIFICATE-v1\0'
PROOF_DOMAIN = b'HAL-AGENT-PROOF-v1\0'
AGENT_RIGHTS = ['broker.launch', 'workload.policy', 'workload.launch', 'result.commit', 'identity.sign']
