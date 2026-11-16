import hashlib
import http.client
import json
import re
import secrets
import sqlite3
import ssl
import threading
import time
import weakref
from urllib.parse import urlsplit
from .local_files import read_regular, write_private

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption

REQUEST_DOMAIN = b'HAL-FLEET-REQUEST-v1\0'
DOCUMENT_DOMAIN = b'HAL-FLEET-DOCUMENT-v1\0'
NAME = re.compile(r'[a-z0-9][a-z0-9_-]{0,47}\Z')
SHA = re.compile(r'[0-9a-f]{64}\Z')


class Error(Exception):
    def __init__(self, message, status=400, code='invalid_request'):
        super().__init__(message)
        self.status, self.code = status, code


def require(condition, message, status=400, code='invalid_request'):
    if not condition:
        raise Error(message, status, code)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False)


def parse(data):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, 'Duplicate JSON field')
            result[key] = value
        return result
    try:
        return json.loads(data, object_pairs_hook=pairs,
                          parse_constant=lambda _: (_ for _ in ()).throw(Error('Invalid JSON number')))
    except (ValueError, UnicodeError) as exc:
        raise Error('Invalid JSON') from exc


def digest(data):
    return hashlib.sha256(data).hexdigest()


def public(key):
    return key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()


def private_hex(key):
    return key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()).hex()


def key_from_hex(value):
    require(isinstance(value, str) and SHA.fullmatch(value), 'Invalid private key')
    return Ed25519PrivateKey.from_private_bytes(bytes.fromhex(value))


def sign(key, domain, value):
    payload = canonical(value)
    return {'payload': payload, 'signature': key.sign(domain + payload.encode()).hex()}


def verify(key, domain, envelope, maximum=1024 * 1024):
    require(isinstance(envelope, dict) and set(envelope) == {'payload', 'signature'}, 'Invalid signed envelope', 401)
    payload, signature = envelope['payload'], envelope['signature']
    require(isinstance(payload, str) and len(payload.encode()) <= maximum, 'Signed document too large', 413)
    require(isinstance(key, str) and SHA.fullmatch(key) and isinstance(signature, str)
            and re.fullmatch(r'[0-9a-f]{128}', signature), 'Invalid signature encoding', 401)
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(key)).verify(bytes.fromhex(signature), domain + payload.encode())
    except (ValueError, InvalidSignature) as exc:
        raise Error('Signature rejected', 401, 'signature_rejected') from exc
    value = parse(payload)
    require(isinstance(value, dict), 'Expected signed JSON object')
    return value


def request(key, audience, operation, subject, body):
    now = int(time.time())
    return sign(key, REQUEST_DOMAIN, dict(version=1, audience=audience, operation=operation,
        subject=subject, public_key=public(key), issued_unix=now, expires_unix=now + 120,
        nonce=secrets.token_hex(32), body=body))


def verify_request(envelope, audience, operation, database, maximum=1024 * 1024):
    require(isinstance(envelope, dict) and isinstance(envelope.get('payload'), str), 'Signed request required', 401)
    require(len(envelope['payload'].encode()) <= maximum, 'Request too large', 413)
    untrusted = parse(envelope['payload'])
    require(isinstance(untrusted, dict), 'Invalid request', 401)
    value = verify(untrusted.get('public_key'), REQUEST_DOMAIN, envelope, maximum)
    require(set(value) == {'version', 'audience', 'operation', 'subject', 'public_key',
            'issued_unix', 'expires_unix', 'nonce', 'body'}, 'Unexpected request fields')
    now = int(time.time())
    require(value['version'] == 1 and value['audience'] == audience and value['operation'] == operation,
            'Wrong request destination or operation', 403)
    require(isinstance(value['subject'], str) and NAME.fullmatch(value['subject']), 'Invalid user name')
    require(type(value['issued_unix']) is int and type(value['expires_unix']) is int
            and value['issued_unix'] <= now + 5 and now < value['expires_unix']
            and 0 < value['expires_unix'] - value['issued_unix'] <= 120, 'Request expired or not yet valid', 401)
    require(isinstance(value['nonce'], str) and SHA.fullmatch(value['nonce']) and isinstance(value['body'], dict),
            'Invalid request fields')
    database.consume('request:' + audience + ':' + value['public_key'], value['nonce'])
    return value


def atomic_json(path, value, exclusive=False):
    data = (json.dumps(value, indent=2, allow_nan=False) + '\n').encode()
    write_private(path, data, exclusive=exclusive)


def read_private(path):
    try:
        return parse(read_regular(path, private=True).decode('utf-8-sig'))
    except ValueError as exc:
        raise Error(str(exc)) from exc


class Database:
    """Small persistent control state; all changes and replay admission are atomic."""
    def __init__(self, path):
        self.lock = threading.RLock()
        self.connection = sqlite3.connect(path, check_same_thread=False)
        self.connection.execute('PRAGMA journal_mode=WAL')
        self.connection.executescript('''
          CREATE TABLE IF NOT EXISTS records (kind TEXT, name TEXT, value TEXT, PRIMARY KEY(kind,name));
          CREATE TABLE IF NOT EXISTS used (scope TEXT, nonce TEXT, created INTEGER, PRIMARY KEY(scope,nonce));
        ''')
        self.connection.commit()

    def get(self, kind, name, default=None):
        with self.lock:
            row = self.connection.execute('SELECT value FROM records WHERE kind=? AND name=?', (kind, name)).fetchone()
            return parse(row[0]) if row else default

    def put(self, kind, name, value):
        with self.lock, self.connection:
            self.connection.execute('INSERT OR REPLACE INTO records VALUES (?,?,?)', (kind, name, canonical(value)))

    def all(self, kind):
        with self.lock:
            return [parse(r[0]) for r in self.connection.execute('SELECT value FROM records WHERE kind=? ORDER BY name', (kind,))]

    def consume(self, scope, nonce):
        with self.lock, self.connection:
            # Retain a day's requests, far longer than the 120-second request lifetime.
            self.connection.execute('DELETE FROM used WHERE created < ?', (int(time.time()) - 86400,))
            count = self.connection.execute('SELECT count(*) FROM used').fetchone()[0]
            require(count < 200000, 'Replay ledger full; wait for expiry', 429)
            try:
                self.connection.execute('INSERT INTO used VALUES (?,?,?)', (scope, nonce, int(time.time())))
            except sqlite3.IntegrityError as exc:
                raise Error('Request already used', 409, 'replay') from exc

    def close(self):
        self.connection.close()


def origin(url, allow_http=False):
    p = urlsplit(url)
    require(p.scheme in ('http', 'https') and p.hostname and not p.username and not p.password
            and p.path in ('', '/') and not p.query and not p.fragment, 'Expected an HTTP(S) origin URL')
    require(p.scheme == 'https' or p.hostname in ('localhost', '127.0.0.1', '::1') or allow_http,
            'Use HTTPS; --allow-http is only for an isolated benchmark network')
    return url.rstrip('/')


class Transport:
    """One persistent connection per thread/origin. Never retry a submitted job."""
    def __init__(self, timeout=180, ca_file=None):
        self.timeout, self.ca_file = timeout, ca_file
        self.local = threading.local()
        self.all_connections = weakref.WeakSet()
        self.lock = threading.Lock()

    def close_thread(self):
        for conn, _ in getattr(self.local, 'connections', {}).values():
            conn.close()
        self.local.connections = {}

    def close(self):
        with self.lock:
            for conn in list(self.all_connections):
                conn.close()
        self.close_thread()

    def call(self, base, path, body=None, token=None, maximum=24 * 1024 * 1024):
        p = urlsplit(base)
        require(p.scheme in ('http', 'https') and p.hostname and path.startswith('/'), 'Invalid endpoint')
        connections = getattr(self.local, 'connections', None)
        if connections is None:
            connections = self.local.connections = Connections()
        key = (p.scheme, p.hostname, p.port)
        entry = connections.get(key)
        if entry and time.monotonic() - entry[1] >= 5:
            entry[0].close()
            connections.pop(key, None)
            entry = None
        conn = entry[0] if entry else None
        if conn is None:
            if p.scheme == 'https':
                conn = http.client.HTTPSConnection(p.hostname, p.port, timeout=self.timeout,
                    context=ssl.create_default_context(cafile=self.ca_file))
            else:
                conn = http.client.HTTPConnection(p.hostname, p.port, timeout=self.timeout)
            connections[key] = (conn, time.monotonic())
            with self.lock:
                self.all_connections.add(conn)
        headers = {'Accept': 'application/json', 'Content-Type': 'application/json'}
        if token:
            headers['Authorization'] = 'Bearer ' + token
        data = canonical(body).encode() if body is not None else None
        try:
            conn.request('POST' if body is not None else 'GET', path, body=data, headers=headers)
            response = conn.getresponse()
            raw = response.read(maximum + 1)
            require(len(raw) <= maximum, 'Service response exceeds size limit', 502)
            result = parse(raw)
            if not 200 <= response.status < 300:
                raise Error(result.get('error', 'Service request failed'), response.status, result.get('code', 'upstream'))
            connections[key] = (conn, time.monotonic())
            return result
        except (OSError, http.client.HTTPException) as exc:
            conn.close()
            connections.pop(key, None)
            host = '[' + p.hostname + ']' if ':' in p.hostname else p.hostname
            endpoint = p.scheme + '://' + host + (':' + str(p.port) if p.port else '') + path.split('?', 1)[0]
            detail = type(exc).__name__ + ': ' + str(exc).replace('\n', ' ').replace('\r', ' ')[:240]
            if body is None:
                raise Error('GET ' + endpoint + ' failed (' + detail + '). This read-only request did not submit a job.',
                            502, 'connection_failed') from exc
            raise Error('POST ' + endpoint + ' failed (' + detail + '). '
                        'The request may have been processed. Do not automatically retry it.',
                        502, 'outcome_unknown') from exc
        except Exception:
            conn.close()
            connections.pop(key, None)
            raise


def milliseconds(start):
    return (time.perf_counter() - start) * 1000


class Connections(dict):
    def __del__(self):
        for conn, _ in self.values():
            conn.close()
