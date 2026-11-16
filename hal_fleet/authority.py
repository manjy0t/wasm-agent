import time
from .common import (DOCUMENT_DOMAIN, NAME, Database, Error, canonical, digest, key_from_hex,
                     public, read_private, require, sign, verify_request)
from .policy import LIMITS, workload
from .lifetimes import ENROLLMENT_SECONDS


class Authority:
    def __init__(self, config, database):
        self.config, self.db = config, database
        self.key = key_from_hex(read_private(config['identity_key'])['private_key'])
        require(public(self.key) == config['trust']['identity_public_key'], 'Identity key changed; fix the trusted configuration')

    def user(self, req):
        row = self.db.get('user', req['subject'])
        require(row is not None and row['active'] and row['public_key'] == req['public_key'], 'User not registered or revoked', 403)
        return row

    def issue(self, row):
        now = int(time.time())
        return sign(self.key, DOCUMENT_DOMAIN, dict(version=1, kind='enrollment',
            issuer=self.config['trust']['issuer'], audience=self.config['trust']['execution_audience'],
            subject=row['name'], public_key=row['public_key'], revision=row['revision'],
            issued_unix=now, expires_unix=now + ENROLLMENT_SECONDS, limits=LIMITS, workloads=row['workloads']))

    def handle(self, method, path, body):
        trust = self.config['trust']
        if method == 'GET' and path == '/v1/trust':
            return sign(self.key, DOCUMENT_DOMAIN, trust)
        if method == 'GET' and path == '/v1/workloads':
            return {'workloads': self.db.all('workload')}
        if method == 'GET' and path.startswith('/v1/status/'):
            name = path[len('/v1/status/'):]
            require(NAME.fullmatch(name), 'Invalid user name')
            row = self.db.get('user', name)
            now = int(time.time())
            return sign(self.key, DOCUMENT_DOMAIN, dict(kind='user-status', subject=name,
                issuer=trust['issuer'], active=bool(row and row['active']), revision=row['revision'] if row else 0,
                public_key=row['public_key'] if row else None, issued_unix=now, expires_unix=now + 5))
        require(method == 'POST', 'Endpoint not found', 404)
        if path == '/v1/register':
            req = verify_request(body, trust['issuer'], 'register', self.db)
            require(not req['body'], 'Registration does not accept permission overrides')
            with self.db.lock:
                row = self.db.get('user', req['subject'])
                if row:
                    row = self.user(req)
                else:
                    require(len(self.db.all('user')) < self.config.get('max_users', 64), 'Registration capacity reached', 429)
                    # Self-service verifies ownership of a key, not a real-world human identity.
                    row = dict(name=req['subject'], public_key=req['public_key'], active=True, revision=1, workloads=[])
                    self.db.put('user', row['name'], row)
                return {'document': self.issue(row)}
        if path == '/v1/renew':
            req = verify_request(body, trust['issuer'], 'renew', self.db)
            return {'document': self.issue(self.user(req))}
        if path == '/v1/approve':
            # Management forwards this exact user signature; it cannot add permissions.
            req = verify_request(body, trust['management_audience'], 'approve', self.db)
            names = req['body'].get('workloads')
            require(set(req['body']) == {'workloads'} and isinstance(names, list) and 1 <= len(names) <= 128
                    and all(isinstance(n, str) and NAME.fullmatch(n) for n in names), 'Choose catalog workload names')
            with self.db.lock:
                row = self.user(req)
                approved = {w['name']: w for w in row['workloads']}
                for name in names:
                    item = self.db.get('workload', name)
                    require(item is not None, 'Workload has not been approved by the operator: ' + name, 403)
                    approved[name] = item
                require(len(approved) <= 128, 'Too many workload grants')
                values = sorted(approved.values(), key=lambda w: w['name'])
                require(len({w['sha256'] for w in values}) == len(values),
                        'Each artifact can have only one approved name/rule per user', 409)
                if row['workloads'] != values:
                    row['workloads'], row['revision'] = values, row['revision'] + 1
                    self.db.put('user', row['name'], row)
                return {'document': self.issue(row)}
        if path in ('/v1/publish', '/v1/revoke'):
            operation = path.rsplit('/', 1)[1]
            req = verify_request(body, trust['issuer'], operation, self.db)
            require(req['public_key'] == trust['operator_public_key'], 'Operator approval required', 403)
            if operation == 'publish':
                rows = req['body'].get('workloads')
                require(set(req['body']) == {'workloads'} and isinstance(rows, list) and 1 <= len(rows) <= 128, 'Invalid catalog update')
                rows = [workload(r) for r in rows]
                require(len({r['name'] for r in rows}) == len(rows), 'Duplicate workload name')
                with self.db.lock:
                    for item in rows:
                        old = self.db.get('workload', item['name'])
                        require(old is None or old == item, 'Workload names are immutable; publish a new version name', 409)
                    for item in rows:
                        self.db.put('workload', item['name'], item)
                return {'published': [r['name'] for r in rows]}
            name = req['body'].get('user')
            require(isinstance(name, str) and NAME.fullmatch(name), 'Invalid user')
            with self.db.lock:
                row = self.db.get('user', name)
                require(row is not None, 'Unknown user', 404)
                row['active'], row['revision'] = False, row['revision'] + 1
                self.db.put('user', name, row)
            return {'revoked': name}
        raise Error('Endpoint not found', 404)
