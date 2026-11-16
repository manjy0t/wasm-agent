#!/usr/bin/env python3
"""Audit signatures, durable collection, tenant privacy and rollback checks."""
import copy
from pathlib import Path
import sys
import tempfile
import time
import unittest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from hal_fleet.audit import AuditStore, BoundaryLog, CERT_DOMAIN, DOMAIN, FORMAT, ZERO, checked_record
from hal_fleet.common import Database, Error, canonical, digest, parse, public, sign


class AuditTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.path = Path(temporary.name) / 'audit.sqlite3'
        self.db = Database(self.path)
        self.addCleanup(self.db.close)
        self.owner, self.agent = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
        self.identity = dict(vm_id='a'*64, public_key=public(self.agent), management_key=public(self.owner),
                             instance='b'*64, agent_sha256='c'*64)
        self.now = int(time.time())
        self.cert = sign(self.owner, CERT_DOMAIN, dict(version=1, kind='agent-identity', identity=self.identity,
                         issued_unix=self.now-60, expires_unix=self.now+60))
        self.store = AuditStore(self.db, self.owner)

    def record(self, sequence=1, previous=ZERO, tenant='alice', event='job_accepted', **data):
        value = dict(format=FORMAT, vm_id=self.identity['vm_id'], sequence=sequence, previous_hash=previous,
                     agent_instance=self.identity['instance'], timestamp_unix=self.now, event=event, certificate=self.cert,
                     data=dict(tenant=tenant, user_key=tenant+'-key', job_id='job-one', artifact_sha256='d'*64, **data))
        record = sign(self.agent, DOMAIN, value)
        record['hash'] = digest(DOMAIN + record['payload'].encode())
        return record

    def page(self, *records):
        entry = parse(records[-1]['payload'])
        head = dict(vm_id=self.identity['vm_id'], sequence=entry['sequence'], hash=records[-1]['hash'])
        return dict(records=list(records), checkpoint=head, tip=head)

    def test_signature_scope_and_hash_tampering_are_rejected(self):
        record = self.record()
        checked_record(record, public(self.owner), self.identity['vm_id'], 1, ZERO)
        for field in ('signature', 'hash'):
            changed = dict(record, **{field: '0'*len(record[field])})
            with self.assertRaises(Error):
                checked_record(changed, public(self.owner))
        changed = dict(record, payload=record['payload'].replace('alice', 'bob'))
        with self.assertRaises(Error):
            checked_record(changed, public(self.owner))
        with self.assertRaises(Error):
            checked_record(record, public(Ed25519PrivateKey.generate()))
        with self.assertRaises(Error):
            checked_record(record, public(self.owner), 'wrong-vm', 1, ZERO)

    def test_collection_and_checkpoint_survive_reopen(self):
        one = self.record(); two = self.record(2, one['hash'], event='result_committed', outcome='completed')
        self.store.ingest(self.identity['vm_id'], self.page(one, two))
        other = Database(self.path)
        try:
            reopened = AuditStore(other, self.owner)
            self.assertEqual(reopened.head(self.identity['vm_id'])['sequence'], 2)
            self.assertTrue(reopened.contains(self.page(two)['checkpoint']))
        finally:
            other.close()

    def test_gap_fork_and_duplicate_do_not_advance_checkpoint(self):
        one = self.record()
        self.store.ingest(self.identity['vm_id'], self.page(one))
        for bad in (one, self.record(3, one['hash']), self.record(2, ZERO)):
            with self.assertRaises(Error):
                self.store.ingest(self.identity['vm_id'], self.page(bad))
            self.assertEqual(self.store.head(self.identity['vm_id'])['hash'], one['hash'])

    def test_invalid_batch_rolls_back_records_and_anchor_together(self):
        one = self.record(); two = self.record(2, one['hash'])
        two['signature'] = '0'*128
        with self.assertRaises(Error):
            self.store.ingest(self.identity['vm_id'], self.page(one, two))
        self.assertEqual(self.store.head(self.identity['vm_id'])['sequence'], 0)
        self.assertEqual(self.store.user_page('alice', 'alice-key')['records'], [])
        page = self.page(one); page['checkpoint']['hash'] = 'f'*64
        with self.assertRaises(Error):
            self.store.ingest(self.identity['vm_id'], page)
        self.assertEqual(self.store.head(self.identity['vm_id'])['sequence'], 0)

    def test_user_history_and_pagination_exclude_other_users_and_keys(self):
        one = self.record(); two = self.record(2, one['hash'], tenant='bob')
        three = self.record(3, two['hash'])
        self.store.ingest(self.identity['vm_id'], self.page(one, two, three))
        first = self.store.user_page('alice', 'alice-key', limit=1)
        second = self.store.user_page('alice', 'alice-key', after=first['next_cursor'])
        self.assertEqual(len(first['records']), 1); self.assertEqual(len(second['records']), 1)
        self.assertEqual(self.store.user_page('alice', 'bob-key')['records'], [])
        self.assertEqual(self.store.user_page('alice', 'alice-key', job_id='absent')['records'], [])
        for limit in (0, 101, True):
            with self.assertRaises(Error): self.store.user_page('alice', 'alice-key', limit=limit)

    def test_modified_database_or_index_is_detected(self):
        record = self.record()
        self.store.ingest(self.identity['vm_id'], self.page(record))
        with self.db.connection:
            self.db.connection.execute("UPDATE audit_records SET tenant='bob',user_key='bob-key'")
        with self.assertRaisesRegex(Error, 'index'):
            self.store.user_page('bob', 'bob-key')
        with self.db.connection:
            self.db.connection.execute('DELETE FROM audit_records')
        with self.assertRaisesRegex(Error, 'checkpoint'):
            AuditStore(self.db, self.owner)

    def test_old_certificates_remain_verifiable_for_historical_records(self):
        self.now -= 1000
        self.cert = sign(self.owner, CERT_DOMAIN, dict(version=1, kind='agent-identity', identity=self.identity,
                         issued_unix=self.now-60, expires_unix=self.now+60))
        checked_record(self.record(), public(self.owner))
        self.now += 1000
        with self.assertRaisesRegex(Error, 'lifetime'):
            checked_record(self.record(), public(self.owner))

    def test_completion_must_match_job_and_result_bytes(self):
        record = self.record(event='result_committed', outcome='completed', result_sha256=digest(b'correct'))
        page = self.page(record); self.store.ingest(self.identity['vm_id'], page)
        data = parse(record['payload'])['data']
        result = dict(status='ok', result={'hex': b'correct'.hex()})
        self.store.check_completion(page['checkpoint'], data, result)
        with self.assertRaisesRegex(Error, 'digest'):
            self.store.check_completion(page['checkpoint'], data, dict(status='ok', result={'hex': '00'}))
        with self.assertRaisesRegex(Error, 'scope'):
            self.store.check_completion(page['checkpoint'], dict(data, job_id='different'), result)

    def test_capacity_fails_closed_without_overwriting_old_history(self):
        self.store.maximum = 129
        self.store.event('job_dispatch_requested', {'tenant': 'alice'}, admission=True)
        with self.assertRaisesRegex(Error, 'full'):
            self.store.event('job_dispatch_requested', {'tenant': 'alice'}, admission=True)
        self.assertEqual(self.store.head('management')['sequence'], 1)
        self.store.event('job_acknowledged', {'tenant': 'alice'})
        self.assertEqual(self.store.head('management')['sequence'], 2)

    def test_vm_identity_cannot_reset_a_target_history(self):
        self.store.bind_target('https://execution', 'vm-one')
        self.store.bind_target('https://execution', 'vm-one')
        with self.assertRaisesRegex(Error, 'identity changed'):
            self.store.bind_target('https://execution', 'vm-two')

    def test_gateway_rejections_are_separate_operational_records(self):
        boundary = BoundaryLog(self.db)
        boundary.rejected('/v2/agent/deploy', 'signature_rejected')
        self.assertEqual(self.db.connection.execute('SELECT operation,reason FROM audit_gateway').fetchone(),
                         ('/v2/agent/deploy', 'signature_rejected'))
        self.assertEqual(self.store.user_page('alice', 'alice-key')['records'], [])


if __name__ == '__main__':
    unittest.main(verbosity=2)
