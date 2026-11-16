"""Signed agent history and the management collector. Never store request bodies."""
import time
from .common import Error, canonical, digest, parse, public, require, sign, verify

FORMAT = 'hal-agent-audit-v1'
DOMAIN = b'HAL-AGENT-AUDIT-v1\0'
MANAGEMENT_DOMAIN = b'HAL-MANAGEMENT-AUDIT-v1\0'
CERT_DOMAIN = b'HAL-AGENT-CERTIFICATE-v1\0'
ZERO = '0' * 64


def checked_record(record, management_key, vm_id=None, sequence=None, previous=None):
    require(isinstance(record, dict) and set(record) == {'payload', 'signature', 'hash'}, 'Invalid audit record', 403)
    untrusted = parse(record['payload'])
    certificate = verify(management_key, CERT_DOMAIN, untrusted.get('certificate'), 8192)
    identity = certificate.get('identity', {})
    require(certificate.get('version') == 1 and certificate.get('kind') == 'agent-identity'
            and identity.get('management_key') == management_key, 'Audit certificate mismatch', 403)
    entry = verify(identity.get('public_key'), DOMAIN, {k: record[k] for k in ('payload', 'signature')}, 8192)
    require(entry.get('format') == FORMAT and entry.get('vm_id') == identity.get('vm_id')
            and entry.get('agent_instance') == identity.get('instance'), 'Audit identity mismatch', 403)
    timestamp = entry.get('timestamp_unix')
    require(type(timestamp) is int and certificate['issued_unix'] <= timestamp + 5
            and timestamp < certificate['expires_unix'], 'Audit record outside certificate lifetime', 403)
    require(record['hash'] == digest(DOMAIN + record['payload'].encode()), 'Audit hash mismatch', 403)
    if vm_id is not None:
        require(entry['vm_id'] == vm_id, 'Audit VM mismatch', 403)
    if sequence is not None:
        require(entry['sequence'] == sequence and entry['previous_hash'] == previous,
                'Audit gap, fork or rollback', 409, 'audit_integrity_failed')
    require(isinstance(entry.get('data'), dict), 'Invalid audit event')
    return entry


def checked_management_record(record, key):
    value = verify(key, MANAGEMENT_DOMAIN, {k: record[k] for k in ('payload', 'signature')}, 8192)
    require(record['hash'] == digest(MANAGEMENT_DOMAIN + record['payload'].encode())
            and value.get('format') == 'hal-management-audit-v1', 'Management audit hash mismatch', 403)
    return value


class AuditStore:
    def __init__(self, database, key, maximum=200000, *, record_checker=checked_record,
                 record_source='agent', verification_key=None):
        self.db, self.key, self.public_key = database, key, verification_key or public(key)
        self.record_checker, self.record_source = record_checker, record_source
        require(type(maximum) is int and 1000 <= maximum <= 5000000, 'Invalid audit record limit')
        self.maximum = maximum
        with self.db.lock:
            self.db.connection.execute('PRAGMA synchronous=FULL')
            self.db.connection.executescript('''
              CREATE TABLE IF NOT EXISTS audit_records (
                id INTEGER PRIMARY KEY AUTOINCREMENT, stream TEXT NOT NULL, sequence INTEGER NOT NULL,
                hash TEXT NOT NULL, tenant TEXT, user_key TEXT, job_id TEXT, record TEXT NOT NULL,
                UNIQUE(stream,sequence));
              CREATE INDEX IF NOT EXISTS audit_user ON audit_records(tenant,user_key,id);
              CREATE TABLE IF NOT EXISTS audit_heads (stream TEXT PRIMARY KEY, sequence INTEGER, hash TEXT);
              CREATE TABLE IF NOT EXISTS audit_targets (target TEXT PRIMARY KEY, vm_id TEXT NOT NULL);
            ''')
            self.verify_integrity()

    def head(self, stream):
        with self.db.lock:
            row = self.db.connection.execute('SELECT sequence,hash FROM audit_heads WHERE stream=?', (stream,)).fetchone()
            return dict(sequence=row[0], hash=row[1]) if row else dict(sequence=0, hash=ZERO)

    def verify_integrity(self):
        heads = {}
        for stream, sequence, hash_value, raw in self.db.connection.execute(
                'SELECT stream,sequence,hash,record FROM audit_records ORDER BY stream,sequence'):
            previous = heads.get(stream, (0, ZERO))
            record = parse(raw)
            if stream == 'management':
                entry = checked_management_record(record, self.public_key)
            else:
                entry = self.record_checker(record, self.public_key, stream)
            require(sequence == previous[0] + 1 and entry['sequence'] == sequence
                    and entry['previous_hash'] == previous[1] and record['hash'] == hash_value,
                    'Stored audit history is damaged', 503, 'audit_integrity_failed')
            heads[stream] = (sequence, hash_value)
        saved = {r[0]: (r[1], r[2]) for r in self.db.connection.execute('SELECT stream,sequence,hash FROM audit_heads')}
        require(heads == saved, 'Audit checkpoint/history mismatch', 503, 'audit_integrity_failed')

    def capacity(self, count=1, admission=False):
        used = self.db.connection.execute('SELECT count(*) FROM audit_records').fetchone()[0]
        reserve = 128 if admission else 0
        require(used + count + reserve <= self.maximum, 'Audit storage full; new jobs are blocked', 503, 'audit_unavailable')

    def _insert(self, stream, record, entry):
        data = entry['data']
        self.db.connection.execute('INSERT INTO audit_records(stream,sequence,hash,tenant,user_key,job_id,record) '
            'VALUES(?,?,?,?,?,?,?)', (stream, entry['sequence'], record['hash'], data.get('tenant'),
                data.get('user_key'), data.get('job_id'), canonical(record)))
        self.db.connection.execute('INSERT OR REPLACE INTO audit_heads VALUES(?,?,?)',
                                   (stream, entry['sequence'], record['hash']))

    def event(self, event, data, admission=False):
        # Callers pass only explicit allowlisted fields, never credentials/errors/bodies.
        try:
            with self.db.lock, self.db.connection:
                self.capacity(admission=admission)
                head = self.head('management')
                value = dict(format='hal-management-audit-v1', sequence=head['sequence'] + 1,
                    previous_hash=head['hash'], timestamp_unix=int(time.time()), event=event, data=data)
                record = sign(self.key, MANAGEMENT_DOMAIN, value)
                require(len(record['payload'].encode()) <= 8192, 'Audit record too large')
                record['hash'] = digest(MANAGEMENT_DOMAIN + record['payload'].encode())
                self._insert('management', record, value)
                return record
        except Error:
            raise
        except Exception as exc:
            raise Error('Audit persistence failed; success cannot be acknowledged', 503, 'audit_unavailable') from exc

    def bind_target(self, target, vm_id):
        with self.db.lock, self.db.connection:
            old = self.db.connection.execute('SELECT vm_id FROM audit_targets WHERE target=?', (target,)).fetchone()
            require(old is None or old[0] == vm_id, 'Execution VM identity changed; review audit continuity',
                    409, 'audit_integrity_failed')
            self.db.connection.execute('INSERT OR IGNORE INTO audit_targets VALUES(?,?)', (target, vm_id))

    def ingest(self, vm_id, page):
        try:
            with self.db.lock, self.db.connection:
                records = page['records']
                require(isinstance(records, list) and len(records) <= 64, 'Invalid audit page')
                self.capacity(len(records))
                head = self.head(vm_id)
                for record in records:
                    entry = self.record_checker(record, self.public_key, vm_id, head['sequence'] + 1, head['hash'])
                    self._insert(vm_id, record, entry)
                    head = dict(sequence=entry['sequence'], hash=record['hash'])
                require(page['checkpoint'] == dict(vm_id=vm_id, **head), 'Audit checkpoint mismatch', 403)
                return head
        except Error:
            raise
        except Exception as exc:
            raise Error('Audit collection could not be persisted', 503, 'audit_unavailable') from exc

    def contains(self, reference):
        with self.db.lock:
            row = self.db.connection.execute('SELECT hash FROM audit_records WHERE stream=? AND sequence=?',
                (reference['vm_id'], reference['sequence'])).fetchone()
            return row is not None and row[0] == reference['hash']

    def check_completion(self, reference, metadata, result):
        with self.db.lock:
            row = self.db.connection.execute('SELECT record FROM audit_records WHERE stream=? AND sequence=?',
                (reference['vm_id'], reference['sequence'])).fetchone()
            require(row is not None, 'Completion audit record missing', 503, 'audit_unavailable')
            record = parse(row[0])
            entry = self.record_checker(record, self.public_key, reference['vm_id'])
            data = entry['data']
            outcome = 'unknown' if result.get('execution_outcome') == 'unknown' else 'completed' if result['status'] == 'ok' else 'failed'
            require(record['hash'] == reference['hash'] and entry['event'] == 'result_committed'
                    and all(data.get(k) == metadata[k] for k in ('tenant', 'user_key', 'job_id', 'artifact_sha256'))
                    and data.get('outcome') == outcome, 'Completion audit scope mismatch', 403, 'audit_integrity_failed')
            if outcome == 'completed':
                require(data.get('result_sha256') == digest(bytes.fromhex(result['result']['hex'])),
                        'Completion audit digest mismatch', 403, 'audit_integrity_failed')

    def user_page(self, tenant, user_key, after=0, limit=50, job_id=None):
        require(type(after) is int and after >= 0 and type(limit) is int and 1 <= limit <= 100, 'Invalid audit pagination')
        require(job_id is None or isinstance(job_id, str) and 1 <= len(job_id) <= 128, 'Invalid audit job ID')
        with self.db.lock:
            query = 'SELECT id,stream,record FROM audit_records WHERE tenant=? AND user_key=? AND id>?'
            args = [tenant, user_key, after]
            if job_id is not None:
                query += ' AND job_id=?'; args.append(job_id)
            rows = self.db.connection.execute(query + ' ORDER BY id LIMIT ?', (*args, limit)).fetchall()
            items = []
            for cursor, stream, raw in rows:
                record = parse(raw)
                entry = (checked_management_record(record, self.public_key) if stream == 'management'
                         else self.record_checker(record, self.public_key, stream))
                require(entry['data'].get('tenant') == tenant and entry['data'].get('user_key') == user_key,
                        'Audit index does not match signed identity', 503, 'audit_integrity_failed')
                items.append(dict(cursor=cursor, source='management' if stream == 'management' else self.record_source, record=record))
            return dict(records=items, next_cursor=rows[-1][0] if rows else after, management_public_key=self.public_key)


class BoundaryLog:
    """Local gateway rejections before an agent can authenticate/sign them.

    Explicitly operational records, not agent-signed or hardware-attested evidence.
    No caller-controlled identities, credentials, request bodies or exception text.
    """
    def __init__(self, database):
        self.db = database
        with self.db.lock, self.db.connection:
            self.db.connection.execute('CREATE TABLE IF NOT EXISTS audit_gateway '
                                       '(id INTEGER PRIMARY KEY, created INTEGER, operation TEXT, reason TEXT)')

    def rejected(self, operation, reason):
        try:
            with self.db.lock, self.db.connection:
                count = self.db.connection.execute('SELECT count(*) FROM audit_gateway').fetchone()[0]
                require(count < 100000, 'Gateway audit storage full', 503, 'audit_unavailable')
                self.db.connection.execute('INSERT INTO audit_gateway(created,operation,reason) VALUES(?,?,?)',
                    (int(time.time()), operation, reason))
        except Error:
            raise
        except Exception as exc:
            raise Error('Gateway audit persistence unavailable', 503, 'audit_unavailable') from exc
