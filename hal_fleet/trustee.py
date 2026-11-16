"""Management-side adapter for Trustee v0.22.0 REST AS and ES256 EAR tokens.

Trustee verifies vendor evidence. Management independently checks the signed
appraisal, its approved measurements/TCB policy and our complete channel binding.
No remote JWKS, header-supplied key, sample verifier or legacy token is trusted.
"""
import base64
import http.client
import ipaddress
from pathlib import Path
import re
import ssl
import time
from urllib.parse import urlsplit

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from .common import Error, canonical, digest, parse, require

RELEASE = '0.22.0'
PROFILE = 'tag:github.com,2024:confidential-containers/Trustee'
MAX_TOKEN = 1024 * 1024
TCB_FIELDS = ('bootloader', 'tee', 'snp', 'microcode')
TDX_FIELDS = {'mrtd': 'mr_td', 'rtmr0': 'rtmr_0', 'rtmr1': 'rtmr_1', 'rtmr2': 'rtmr_2', 'rtmr3': 'rtmr_3'}


def reject(condition, message):
    require(condition, message, 403, 'attestation_failed')


def b64url(raw):
    return base64.urlsafe_b64encode(raw).decode('ascii').rstrip('=')


def unb64url(value):
    reject(isinstance(value, str) and re.fullmatch(r'[A-Za-z0-9_-]+', value) is not None,
           'Invalid Trustee token encoding')
    try:
        raw = base64.b64decode(value + '=' * (-len(value) % 4), altchars=b'-_', validate=True)
    except ValueError as exc:
        raise Error('Invalid Trustee token encoding', 403, 'attestation_failed') from exc
    reject(b64url(raw) == value, 'Noncanonical Trustee token encoding')
    return raw


def _endpoint(value):
    require(isinstance(value, str), 'Trustee URL is required')
    try:
        url = urlsplit(value)
        port = url.port
    except ValueError as exc:
        raise Error('Invalid Trustee URL') from exc
    require(url.hostname and not url.username and not url.password and not url.query and not url.fragment
            and url.path in ('', '/') and (port is None or 1 <= port <= 65535), 'Invalid Trustee URL')
    loopback = False
    try:
        loopback = ipaddress.ip_address(url.hostname).is_loopback
    except ValueError:
        pass
    require(url.scheme == 'https' or (url.scheme == 'http' and loopback),
            'Trustee requires HTTPS, except for a literal loopback address on management')
    return url


def _public_key(pem):
    require(isinstance(pem, str) and len(pem) <= 4096, 'Pin the Trustee public signing key in PEM format')
    try:
        key = serialization.load_pem_public_key(pem.encode('ascii'))
    except (ValueError, TypeError, UnicodeError) as exc:
        raise Error('Invalid Trustee public signing key') from exc
    require(isinstance(key, ec.EllipticCurvePublicKey) and isinstance(key.curve, ec.SECP256R1),
            'Trustee v0.22.0 requires an ES256 / P-256 signing public key')
    return key


def validate_snp_requirements(policy):
    require(policy.get('snp_product') in ('Milan', 'Genoa'),
            'This SNP policy supports Milan/Genoa VCEK or VLEK reports; other products need a reviewed claim policy')
    minimum = policy.get('snp_minimum_tcb')
    require(isinstance(minimum, dict) and set(minimum) == set(TCB_FIELDS)
            and all(type(v) is int and 0 <= v <= 255 for v in minimum.values()),
            'Set all four approved SNP minimum TCB components explicitly')


def validate(policy):
    config = policy.get('trustee')
    required = {'release', 'url', 'signer_public_key_pem', 'issuer', 'policy_id'}
    require(isinstance(config, dict) and required <= set(config)
            and set(config) <= required | {'ca_pem', 'snp_codec'}, 'Invalid Trustee configuration fields')
    require(config['release'] == RELEASE, 'This adapter requires Trustee v0.22.0')
    _endpoint(config['url'])
    _public_key(config['signer_public_key_pem'])
    require(isinstance(config['issuer'], str) and 1 <= len(config['issuer']) <= 128, 'Pin the Trustee token issuer')
    require(isinstance(config['policy_id'], str) and re.fullmatch(r'hal-[a-z0-9-]{1,64}', config['policy_id']),
            'Use a dedicated hal-... appraisal policy, not the default/sample policy')
    if 'ca_pem' in config:
        require(isinstance(config['ca_pem'], str) and len(config['ca_pem']) <= 65536, 'Invalid Trustee TLS CA')
        try:
            ssl.create_default_context(cadata=config['ca_pem'])
        except (ValueError, ssl.SSLError) as exc:
            raise Error('Invalid Trustee TLS CA') from exc
    if policy['platform'] == 'amd-sev-snp':
        validate_snp_requirements(policy)
        codec = config.get('snp_codec')
        require(isinstance(codec, dict) and set(codec) == {'path', 'sha256'}
                and isinstance(codec['path'], str) and Path(codec['path']).is_absolute()
                and isinstance(codec['sha256'], str) and re.fullmatch('[0-9a-f]{64}', codec['sha256']),
                'Pin the absolute management-side SNP codec executable and SHA-256')
    else:
        require('snp_codec' not in config, 'SNP codec does not apply to a TDX policy')
    return policy


def security_requirements(policy):
    result = dict(platform=policy['platform'], measurements=policy['measurements'],
                  runtime_binding=policy['runtime_binding'], schema='hal-trustee-v0.22.0-v1')
    if policy['platform'] == 'amd-sev-snp':
        result.update(snp_product=policy['snp_product'], snp_minimum_tcb=policy['snp_minimum_tcb'])
    return result


def policy_binding(policy):
    return digest(canonical(security_requirements(policy)).encode())


def _snp_evidence(config, raw):
    # Use the SAME sev codec revision as Trustee. It only translates the raw
    # report, never verifies it. Vendor verification still happens in Trustee.
    from .attested_channel import bounded_command
    codec = config['snp_codec']
    try:
        actual = digest(Path(codec['path']).read_bytes())
    except OSError as exc:
        raise Error('Trustee SNP codec unavailable; build it on management', 503, 'attestation_failed') from exc
    reject(actual == codec['sha256'], 'Trustee SNP codec changed')
    result = bounded_command([codec['path']], {'report_hex': raw.hex()}, timeout=10)
    reject(isinstance(result, dict) and isinstance(result.get('evidence'), dict), 'Invalid SNP codec result')
    return result


def _post(config, body):
    url = _endpoint(config['url'])
    connection = None
    try:
        if url.scheme == 'https':
            connection = http.client.HTTPSConnection(url.hostname, url.port, timeout=30,
                context=ssl.create_default_context(cadata=config.get('ca_pem')))
        else:
            connection = http.client.HTTPConnection(url.hostname, url.port, timeout=30)
        connection.request('POST', '/attestation', canonical(body).encode(),
                           {'Content-Type': 'application/json', 'Accept': 'text/plain', 'Connection': 'close'})
        response = connection.getresponse()
        # No redirect, fallback verifier or retry. Do not return backend internals.
        reject(response.status == 200, 'Trustee rejected evidence or is unavailable')
        token = response.read(MAX_TOKEN + 1)
        reject(0 < len(token) <= MAX_TOKEN, 'Invalid Trustee token size')
        return token.decode('ascii')
    except (OSError, http.client.HTTPException, UnicodeError) as exc:
        raise Error('Trustee connection or TLS verification failed', 503, 'attestation_failed') from exc
    finally:
        if connection is not None:
            connection.close()


def _measurement_mismatches(policy, appraisal):
    """Name failed measurement checks in authenticated evidence, never approve it.

    A rejected EAR may contain incomplete claims. Diagnostics must not turn a
    policy rejection into a parsing exception or print arbitrary claim contents.
    """
    annotated = appraisal.get('ear.veraison.annotated-evidence')
    if not isinstance(annotated, dict):
        return []
    tee = 'tdx' if policy['platform'] == 'intel-tdx' else 'snp'
    claims = annotated.get(tee)
    if not isinstance(claims, dict):
        return []
    if tee == 'tdx':
        quote = claims.get('quote')
        body = quote.get('body') if isinstance(quote, dict) else None
        if not isinstance(body, dict):
            return []
        return [key for key, field in TDX_FIELDS.items() if body.get(field) != policy['measurements'][key]]
    return ['measurement'] if claims.get('measurement') != policy['measurements']['measurement'] else []


def verify_token(config, token, started, *, policy=None):
    reject(isinstance(token, str) and 0 < len(token) <= MAX_TOKEN, 'Invalid Trustee token size')
    parts = token.split('.')
    reject(len(parts) == 3, 'Expected a signed Trustee EAR JWT')
    header = parse(unb64url(parts[0]))
    reject(isinstance(header, dict) and header.get('alg') == 'ES256'
           and not any(k in header for k in ('crit', 'b64', 'jku', 'x5u')),
           'Unsupported Trustee token signature header')
    # Trustee embeds a JWK. It is NEVER a trust anchor: use the configured key.
    signature = unb64url(parts[2])
    reject(len(signature) == 64, 'Invalid ES256 signature length')
    r, s = int.from_bytes(signature[:32], 'big'), int.from_bytes(signature[32:], 'big')
    try:
        _public_key(config['signer_public_key_pem']).verify(encode_dss_signature(r, s),
            (parts[0] + '.' + parts[1]).encode('ascii'), ec.ECDSA(hashes.SHA256()))
    except (InvalidSignature, ValueError) as exc:
        raise Error('Trustee token signature rejected', 403, 'attestation_failed') from exc
    claims = parse(unb64url(parts[1]))
    reject(isinstance(claims, dict) and claims.get('iss') == config['issuer']
           and claims.get('eat_profile') == PROFILE, 'Unexpected Trustee issuer or token profile')
    now = int(time.time())
    issued, expires = claims.get('iat'), claims.get('exp')
    reject(type(issued) is int and type(expires) is int and started - 5 <= issued <= now + 5
           and now < expires and 0 < expires - issued <= 300, 'Stale or invalid Trustee token lifetime')
    if 'nbf' in claims:
        reject(type(claims['nbf']) is int and claims['nbf'] <= now, 'Trustee token is not yet valid')
    submods = claims.get('submods')
    reject(isinstance(submods, dict) and set(submods) == {'cpu0'}, 'Expected one CPU appraisal')
    appraisal = submods['cpu0']
    reject(isinstance(appraisal, dict), 'Missing Trustee CPU appraisal')
    reject(appraisal.get('ear.appraisal-policy-id') == config['policy_id'],
           'Trustee appraisal policy differs from the requested policy')
    if appraisal.get('ear.status') != 'affirming':
        status = appraisal.get('ear.status')
        status = status if status in ('none', 'warning', 'contraindicated') else 'unknown'
        message = 'Trustee appraisal rejected (status=' + status + ')'
        # Signature, issuer, freshness and policy ID have already been checked.
        # Explain a genuine rejection without trusting evidence as new reference
        # values or accepting matching measurements in lieu of an affirming EAR.
        if policy is not None and appraisal.get('hal.policy-binding') == policy_binding(policy):
            mismatches = _measurement_mismatches(policy, appraisal)
            if mismatches:
                message += ': approved measurement checks failed: ' + ', '.join(mismatches)
                message += '. Review boot changes against the approved baseline; do not adopt reported values automatically'
        reject(False, message)
    vector = appraisal.get('ear.trustworthiness-vector')
    expected = {'hardware': 2, 'configuration': 2, 'executables': 3,
                'instance-identity': 0, 'file-system': 0, 'runtime-opaque': 0, 'storage-opaque': 0, 'sourced-data': 0}
    reject(isinstance(vector, dict) and vector == expected and all(type(v) is int for v in vector.values()),
           'Trustee did not affirm the required hardware, boot image and configuration checks')
    return appraisal


def verify(policy, raw, expected, certificates=b''):
    validate(policy)
    config = policy['trustee']
    tee = 'tdx' if policy['platform'] == 'intel-tdx' else 'snp'
    snp = None
    if tee == 'tdx':
        evidence = {'quote': base64.b64encode(raw).decode('ascii')}
    else:
        snp = _snp_evidence(config, raw)
        reject(snp.get('product') == policy['snp_product'] and type(snp.get('vmpl')) is int and snp['vmpl'] == 0
               and snp.get('report_data') == expected, 'Unexpected SNP product, VMPL or report binding')
        evidence = snp['evidence']
        # AWS shared-tenancy SNP uses VLEK, delivered by the extended report.
        # These bytes are untrusted until Trustee verifies the AMD chain and
        # report signature. Keep raw REPORTDATA and all signed bytes unchanged.
        from .snp_certificates import chain_for_report
        try:
            evidence = dict(evidence, cert_chain=chain_for_report(raw, certificates))
        except ValueError as exc:
            reject(False, str(exc))
    body = {'verification_requests': [{'tee': tee, 'evidence': b64url(canonical(evidence).encode()),
             'runtime_data': {'raw': b64url(bytes.fromhex(expected))}}], 'policy_ids': [config['policy_id']]}
    started = int(time.time())
    appraisal = verify_token(config, _post(config, body), started, policy=policy)
    reject(appraisal.get('hal.policy-binding') == policy_binding(policy), 'Trustee approved policy binding differs')
    annotated = appraisal.get('ear.veraison.annotated-evidence')
    reject(isinstance(annotated, dict) and annotated.get('report_data') == expected,
           'Attestation challenge or recipient key mismatch')
    reject(set(annotated) == {tee, 'report_data', 'runtime_data_claims', 'init_data', 'init_data_claims'}
           and isinstance(annotated.get(tee), dict), 'Unexpected Trustee evidence claims')
    claims = annotated[tee]
    if tee == 'tdx':
        quote = claims.get('quote', {})
        reject(isinstance(quote, dict) and isinstance(quote.get('body'), dict)
               and isinstance(quote.get('header'), dict), 'Missing verified TDX quote claims')
        reject(quote['header'].get('tee_type') == '81000000'
               and quote['header'].get('vendor_id') == '939a7233f79c4ca9940a0db3957f0607', 'Unexpected TDX quote type')
        attributes = claims.get('td_attributes')
        reject(isinstance(attributes, dict) and attributes.get('debug') is False
               and claims.get('tcb_status') == 'UpToDate' and claims.get('collateral_expiration_status') == '0',
               'Unacceptable TDX debug, TCB or collateral state')
        measurements = {key: quote['body'].get(field) for key, field in TDX_FIELDS.items()}
        tcb = {'status': 'UpToDate'}
    else:
        reject(claims.get('policy_debug_allowed') is False and claims.get('policy_migrate_ma') is False,
               'SNP debug or migration-agent policy rejected')
        reject(claims.get('chip_id') == snp.get('chip_id'), 'SNP report and Trustee chip identity differ')
        minimum = policy['snp_minimum_tcb']
        tcb = {field: claims.get('reported_tcb_' + field) for field in TCB_FIELDS}
        reject(all(type(value) is int and minimum[field] <= value <= 255 for field, value in tcb.items()),
               'SNP firmware is below the approved minimum TCB')
        measurements = {'measurement': claims.get('measurement')}
    reject(measurements == policy['measurements'], 'Platform measurements differ from approved policy')
    result = dict(verified=True, platform=policy['platform'], report_data=expected, debug=False,
                  measurements=measurements, tcb_accepted=True, tcb=tcb,
                  evidence_sha256=digest(raw), verifier='trustee', verifier_release=RELEASE)
    if tee == 'snp':
        # The pinned SNP verifier explicitly verifies VMPL == 0; the codec also
        # checks it in the exact bytes sent. Trustee does not emit a VMPL claim.
        result['vmpl'] = snp['vmpl']
    return result
