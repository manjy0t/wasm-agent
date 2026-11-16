"""Client-side Ed25519 approval. Never import a signing key into management.

The client pins its own workload metadata; the relay cannot choose what is signed.
Only this optional client path needs the cryptography Python package.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import time

DOMAIN = b'HAL-JOB-TICKET-v1\0'
HEX64 = re.compile(r'[0-9a-f]{64}\Z')


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False)


def rule_digest(rule):
    # This field set is shared with Rule::authorization_value in agent_policy.rs.
    fields = ('component', 'cache', 'cache_ttl_ms', 'hal_permissions', 'memory_mib',
              'fuel', 'execution_timeout_ms', 'max_output_bytes', 'worker_max_jobs', 'validation')
    bound = {k: rule[k] for k in fields}
    if 'access_profile' in rule:
        bound['access_profile'] = rule['access_profile']
    return hashlib.sha256(canonical(bound).encode()).hexdigest()


class Signer:
    def __init__(self, path, epoch):
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
            from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
        except ImportError as error:
            raise ValueError('signed jobs need cryptography on the client: install requirements-signing.txt in a virtual environment') from error
        if not isinstance(epoch, str) or not HEX64.fullmatch(epoch):
            raise ValueError('supply the current execution host authorization epoch (64 lowercase hex characters)')
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd) as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
                raise ValueError('signing config must be a private regular file owned by the client user (chmod 600)')
            data = stream.read(1024 * 1024 + 1)
            if len(data) > 1024 * 1024:
                raise ValueError('signing config too large')
        config = json.loads(data)
        if config['version'] != 1 or not 1 <= config['max_ttl_seconds'] <= 300:
            raise ValueError('invalid signing config')
        self.key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(config['private_key']))
        if self.key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex() != config['public_key']:
            raise ValueError('signing key does not match approved public key')
        self.config, self.epoch = config, epoch
        self.cases = {row['case']: row for row in config['workloads']}
        self.descriptor = {k: config[k] for k in ('tenant', 'audience', 'isolation', 'public_key', 'max_ttl_seconds')}
        self.descriptor['epoch'] = epoch

    def ticket(self, case, cache, job_id):
        row = self.cases.get(case)
        if row is None:
            raise ValueError('case is not in the client-approved signing config')
        if cache not in ('bypass', 'reuse') or (cache == 'reuse' and not row['cache_allowed']):
            raise ValueError('cache request is not allowed by the client signing config')
        now = int(time.time())
        claims = dict(version=1, tenant=self.config['tenant'], audience=self.config['audience'],
            epoch=self.epoch, job_id=job_id, nonce=secrets.token_hex(32), operation='run',
            component=row['component'], sha256=row['sha256'], artifact_bytes=row['artifact_bytes'],
            cache=cache, rule_sha256=row['rule_sha256'], isolation=self.config['isolation'],
            input='none', issued_unix=now, expires_unix=now + self.config['max_ttl_seconds'])
        payload = canonical(claims)
        return dict(payload=payload, signature=self.key.sign(DOMAIN + payload.encode()).hex())
