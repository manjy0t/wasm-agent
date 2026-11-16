"""Real signatures, authorization, persistence and collection; injected broker only.

No hardware attestation, sockets or Wasm execution is claimed by these offline tests.
"""
import base64
import copy
import json
from pathlib import Path
import secrets
import sys
import tempfile
import threading
import time
import unittest
import uuid
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from hal_fleet.authority import Authority
from hal_fleet.audit import checked_record
from hal_fleet.benchmark_guard import BenchmarkGate, Experiment, verify_batch
from hal_fleet.benchmark_state import bind_state, execution_slot
from hal_fleet.client import Client, benchmark
from hal_fleet.common import (Database, Error, atomic_json, digest, parse, private_hex, public, request, sign)
from hal_fleet.native_audit import (PROFILE, DOMAIN, FORMAT, NativeExecution, NativeManagement, NativeJournal, checked_native_record)
from hal_fleet.native_config import configure, issue_certificate, service_digest
from hal_fleet.policy import SETTINGS
from hal_fleet.services import Files
from job_signing import DOMAIN as JOB_DOMAIN, rule_digest


class NativeAuditTest(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.operator, self.issuer, self.manager_key, self.native_key = [Ed25519PrivateKey.generate() for _ in range(4)]
        self.apps, self.dbs, self.brokers = {}, {}, {}
        self.executions = 0
        self.artifact, self.answer = b'\0asm0000', b'audited native result'
        self.trust = dict(version=1, issuer='hal-identity', management_audience='hal-management',
            execution_audience='native-test', files_audience='hal-files', identity_public_key=public(self.issuer),
            operator_public_key=public(self.operator), endpoints={role: 'https://' + role for role in ('identity', 'files', 'execution', 'management')})
        for name, key in (('identity', self.issuer), ('management', self.manager_key), ('native', self.native_key)):
            atomic_json(self.root / (name + '-key.json'), dict(private_key=private_hex(key)))
        cert_path = self.root / 'native-certificate.json'
        issue_certificate(self.root / 'management-key.json', public(self.native_key), cert_path)
        test = self

        class Route:
            def call(self, base, path, body=None, token=None, **kwargs):
                if base in test.brokers:
                    broker = test.brokers[base]
                    test.assertEqual(token, broker.token)
                    test.assertEqual(body['cache'], 'bypass')
                    test.assertNotIn('job_ticket', body)
                    data = test.apps['files'].handle_http('GET', '/artifacts/' + body['component'], None,
                        {'Authorization': 'Bearer ' + broker.config['file_token']})
                    test.assertEqual(digest(data), body['sha256'])
                    test.executions += 1
                    return dict(status='ok', job_id=body['job_id'], tenant=broker.document['subject'],
                        sha256=body['sha256'], host_sha256=broker.config['binary_sha256'], execution_mode='native', cache_policy='bypass', cache_status='bypass',
                        workload_instance_reused=False, configuration=dict(workload_isolation='in-process', compile_opt_level='speed', code_cache_storage='disabled'),
                        timings_ms=dict(host_request=1), result=dict(hex=test.answer.hex(), bytes=len(test.answer)))
                role = base.removeprefix('https://')
                return test.apps[role].handle('POST' if body is not None else 'GET', path, body)

            def close(self):
                pass

        class BrokerFixture:
            def __init__(self, config, document, transport):
                self.config, self.document = config, copy.deepcopy(document)
                self.epoch, self.token = secrets.token_hex(32), secrets.token_hex(32)
                self.url = 'broker:' + secrets.token_hex(8)
                self.process = Mock(poll=lambda: None)
                self.semaphore = threading.BoundedSemaphore(document['limits']['max_inflight'])
                self.active, self.last_used, self.startup_ms = 0, time.monotonic(), 1
                test.brokers[self.url] = self

            def close(self):
                test.brokers.pop(self.url, None)

        self.transport = Route()
        self.configs = {}
        for role in ('identity', 'files', 'execution', 'management'):
            state = self.root / role
            state.mkdir(mode=0o700)
            db = Database(state / 'state.sqlite3')
            self.addCleanup(db.close)
            self.dbs[role] = db
            config = dict(role=role, trust=self.trust, state_dir=str(state), **{r + '_url': u for r, u in self.trust['endpoints'].items()})
            self.configs[role] = config
            if role == 'identity':
                config['identity_key'] = str(self.root / 'identity-key.json')
                app = Authority(config, db)
            elif role == 'files':
                config.update(protected_artifacts=True, trusted_management_keys=[public(self.manager_key)])
                app = Files(config, db)
            else:
                config.update(execution_architecture=PROFILE, native_certificate=str(cert_path), service_sha256=service_digest())
                if role == 'execution':
                    config.update(mode='native', agent_sha256='0'*64, binary_sha256='a'*64,
                        settings=SETTINGS, native_key=str(self.root/'native-key.json'), management_public_key=public(self.manager_key))
                    app = NativeExecution(config, db, self.transport, broker_factory=BrokerFixture)
                    self.addCleanup(app.close)
                else:
                    config['management_key'] = str(self.root / 'management-key.json')
                    app = BenchmarkGate(NativeManagement(config, db, self.transport))
            self.apps[role] = app
        sha = digest(self.artifact)
        self.workload = dict(name='fixture', component=sha + '.wasm', sha256=sha, artifact_bytes=len(self.artifact),
            rule=dict(component=sha + '.wasm', cache='memory', cache_ttl_ms=300000, hal_permissions=['crypto'],
                memory_mib=64, fuel=1000000000, execution_timeout_ms=5000, max_output_bytes=4096, worker_max_jobs=128,
                validation=dict(kind='hex', value=self.answer.hex())))
        self.apps['files'].handle('POST', '/v1/upload', request(self.operator, self.trust['files_audience'], 'upload', 'operator',
            dict(sha256=sha, wasm_base64=base64.b64encode(self.artifact).decode())))
        self.apps['identity'].handle('POST', '/v1/publish', request(self.operator, self.trust['issuer'], 'publish', 'operator',
            dict(workloads=[self.workload])))
        self.client = self.new_client('alice')
        self.client.register()
        self.client.approve(['fixture'])

    def new_client(self, name):
        path = self.root / (name + '.json')
        atomic_json(path, dict(user=name, private_key=private_hex(Ed25519PrivateKey.generate()), trust=self.trust,
                              required_execution_architecture=PROFILE))
        client = Client(path)
        client.transport.close()
        client.transport = self.transport
        return client

    def run_job(self):
        self.client.open_session()
        return self.client.job('fixture', 'bypass', 'native', 'in-process')

    def test_success_requires_two_durable_copies_and_verified_receipt(self):
        result = self.run_job()
        self.assertEqual(result['status'], 'completed', result)
        self.assertEqual(result['client_result_validation'], 'passed')
        self.assertFalse(result['attestation_verified'])
        response = result['response']['agent']
        self.assertTrue(response['audit_collected'])
        self.assertEqual(response['execution_architecture'], PROFILE)
        journal, store = self.apps['execution'].journal, self.apps['management'].audit
        self.assertTrue(journal.contains(response['audit']))
        self.assertTrue(store.contains(response['audit']))
        page = self.client.audit(job_id=result['job_id'])
        self.assertTrue(page['record_signatures_verified'])
        self.assertEqual({row['source'] for row in page['records']}, {'native', 'management'})
        self.assertEqual([r['event'] for r in page['records'] if r['source'] == 'native'], ['job_accepted', 'result_committed'])
        for db in self.dbs.values():
            if db in (self.dbs['execution'], self.dbs['management']):
                self.assertEqual(db.connection.execute('PRAGMA synchronous').fetchone()[0], 2)
        raw = canonical_audit(self.dbs['execution'])
        for secret in (self.answer.decode(), self.configs['execution']['native_key'], private_hex(self.native_key)):
            self.assertNotIn(secret, raw)

    def test_native_reuse_rejected_before_execution(self):
        self.client.open_session()
        with self.assertRaisesRegex(Error, 'cache bypass'):
            self.client.job('fixture', 'reuse', 'native', 'in-process')
        with self.assertRaisesRegex(Error, 'forbids cache reuse'):
            benchmark(self.client, ['fixture'], 2, 1, 'reuse', self.root/'reuse', 'native', 'in-process')
        with self.assertRaises(Error):
            self.apps['execution'].handle('POST', '/v1/run', {})
        self.assertEqual(self.executions, 0)

    def test_signed_reuse_is_rejected_by_management_and_execution(self):
        session = self.client.open_session()
        now, job_id = int(time.time()), str(uuid.uuid4())
        w = self.workload
        claims = dict(version=1, tenant='alice', audience=session['audience'], epoch=session['epoch'],
            job_id=job_id, nonce=secrets.token_hex(32), operation='run', component=w['component'], sha256=w['sha256'],
            artifact_bytes=w['artifact_bytes'], cache='reuse', rule_sha256=rule_digest(w['rule']),
            isolation='in-process', input='none', issued_unix=now, expires_unix=now + 120)
        job = dict(protocol=1, job_id=job_id, component=w['component'], sha256=w['sha256'],
                   artifact_bytes=w['artifact_bytes'], cache='reuse', job_ticket=sign(self.client.key, JOB_DOMAIN, claims))
        body = dict(document=self.client.document, job=job, isolation='in-process')
        result = self.apps['management'].handle('POST', '/v1/run', body)
        self.assertEqual(result['status'], 'unknown')
        self.assertIn('bypass', result['error'])
        with self.assertRaisesRegex(Error, 'bypass'):
            self.apps['management'].call_native('run', request=body, challenge=job_id)
        self.assertEqual(self.executions, 0)

    def test_native_journal_reopen_and_tamper_detection(self):
        self.run_job()
        old = self.apps['execution'].journal
        other = Database(self.root/'execution/state.sqlite3')
        self.addCleanup(other.close)
        reopened = NativeJournal(other, self.native_key, old.certificate, public(self.manager_key))
        self.assertEqual(reopened.head(old.identity['vm_id']), old.head(old.identity['vm_id']))
        page = reopened.page(0, '0'*64)
        record = page['records'][0]
        with self.assertRaises(Error):
            checked_record(record, public(self.manager_key))  # Native is never labelled as agent evidence.
        with self.assertRaises(Error):
            checked_native_record(dict(record, hash='0'*64), public(self.manager_key))
        with self.assertRaises(Error):
            reopened.page(1, 'f'*64)
        with other.connection:
            other.connection.execute('DELETE FROM audit_records WHERE sequence=1')
        with self.assertRaises(Error):
            NativeJournal(other, self.native_key, old.certificate, public(self.manager_key))

    def test_local_persistence_failure_blocks_execution_and_is_sticky(self):
        self.client.open_session()
        journal = self.apps['execution'].journal
        with patch.object(journal, '_insert', side_effect=OSError('disk full')):
            result = self.client.job('fixture', 'bypass', 'native', 'in-process')
        self.assertEqual(result['status'], 'unknown', result)
        self.assertTrue(journal.failed)
        self.assertEqual(self.executions, 0)
        with self.assertRaises(Error):
            journal.append('job_accepted', {})

    def test_collection_failure_after_execution_never_reports_success_or_retries(self):
        self.client.open_session()
        store = self.apps['management'].audit
        original = store.ingest
        def fail_completion(vm, page):
            if any(parse(r['payload'])['event'] == 'result_committed' for r in page['records']):
                raise Error('collector disk full', 503, 'audit_unavailable')
            return original(vm, page)
        with patch.object(store, 'ingest', side_effect=fail_completion):
            result = self.client.job('fixture', 'bypass', 'native', 'in-process')
        self.assertEqual(result['status'], 'unknown', result)
        self.assertEqual(self.executions, 1)
        self.assertIn('Do not resubmit', result['error'])

    def test_local_completion_commit_failure_keeps_outcome_unknown(self):
        self.client.open_session()
        journal = self.apps['execution'].journal
        insert = journal._insert
        def fail_completion(stream, record, entry):
            if entry['event'] == 'result_committed':
                raise OSError('disk unavailable')
            return insert(stream, record, entry)
        with patch.object(journal, '_insert', side_effect=fail_completion):
            result = self.client.job('fixture', 'bypass', 'native', 'in-process')
        self.assertEqual(result['status'], 'unknown', result)
        self.assertEqual(self.executions, 1)
        self.assertTrue(journal.failed)
        self.assertNotIn('result_committed', canonical_audit(self.dbs['execution']))

    def test_user_audit_scope_and_signed_result_tampering(self):
        alice = self.run_job()
        bob = self.new_client('bob')
        bob.register(); bob.approve(['fixture']); bob.open_session()
        self.assertEqual(bob.audit(job_id=alice['job_id'])['records'], [])
        self.client.open_session()
        old_call = self.client.call
        def tamper(role, path, body=None):
            value = old_call(role, path, body)
            if path == '/v1/run':
                value['response']['agent']['native_result_proof']['signature'] = '0'*128
            return value
        with patch.object(self.client, 'call', side_effect=tamper):
            result = self.client.job('fixture', 'bypass', 'native', 'in-process')
        self.assertEqual(result['status'], 'failed')

    def test_unique_experiments_and_verified_output_no_overwrite(self):
        first = benchmark(self.client, ['fixture'], 4, 2, 'bypass', self.root/'first', 'native', 'in-process')
        second = benchmark(self.client, ['fixture'], 2, 1, 'bypass', self.root/'second', 'native', 'in-process')
        self.assertEqual(first['completed'], 4, first)
        self.assertNotEqual(first['experiment_id'], second['experiment_id'])
        self.assertNotEqual(first['batch_id'], second['batch_id'])
        self.assertTrue(verify_batch(self.root/'first')['verified'])
        with self.assertRaises(FileExistsError):
            benchmark(self.client, ['fixture'], 1, 1, 'bypass', self.root/'first', 'native', 'in-process')
        path = self.root/'first/jobs.jsonl'
        path.write_text(path.read_text().replace('completed', 'failed', 1))
        with self.assertRaisesRegex(Error, 'file changed'):
            verify_batch(self.root/'first')

    def test_lease_blocks_other_clients_and_duplicate_experiment_ids(self):
        folder = self.root/'lease'; folder.mkdir()
        with Experiment(self.client, ['fixture'], 'native', 'in-process', folder) as experiment:
            self.client.open_session()
            other = Client(self.client.path); other.transport.close(); other.transport = self.transport
            with self.assertRaisesRegex(Error, 'reserved'):
                other.open_session()
            with self.assertRaisesRegex(Error, 'active'):
                self.apps['management'].control(self.client.signed('management', 'benchmark', dict(
                    document=self.client.document, action='acquire', experiment_id=experiment.id)))
        with self.assertRaisesRegex(Error, 'already used'):
            self.apps['management'].control(self.client.signed('management', 'benchmark', dict(
                document=self.client.document, action='acquire', experiment_id=experiment.id)))

    def test_profile_change_during_session_refresh_rejected(self):
        folder = self.root/'pin'; folder.mkdir()
        with Experiment(self.client, ['fixture'], 'native', 'in-process', folder) as experiment:
            session = self.client.open_session()
            experiment.session(session)
            for mutate in (lambda s: s['build'].update(host_sha256='f'*64),
                           lambda s: s['native_identity'].update(instance='e'*64),
                           lambda s: s['settings'].update(executions=1)):
                changed = copy.deepcopy(session); mutate(changed)
                with self.assertRaisesRegex(Error, 'changed'):
                    experiment.session(changed)

    def test_duplicate_job_records_stop_batch_and_are_not_usable(self):
        original = self.client.job
        previous = []
        def duplicate(*args):
            if previous:
                return copy.deepcopy(previous[0])
            row = original(*args); previous.append(copy.deepcopy(row)); return row
        with patch.object(self.client, 'job', side_effect=duplicate):
            summary = benchmark(self.client, ['fixture'], 5, 1, 'bypass', self.root/'duplicate', 'native', 'in-process')
        self.assertTrue(summary['contamination_detected'])
        self.assertEqual(summary['not_submitted'], 3)
        self.assertFalse(summary['valid_for_comparison'])
        with self.assertRaises(Error):
            verify_batch(self.root/'duplicate')

    def test_state_and_vm_locks_prevent_profile_reuse(self):
        db = Database(self.root/'fresh.sqlite3'); self.addCleanup(db.close)
        native = self.configs['execution']
        bind_state(native, db)
        with self.assertRaisesRegex(Error, 'another execution profile'):
            bind_state(dict(native, execution_architecture='hal-managed-agent-v2', mode='wasm'), db)
        slot = execution_slot(self.root/'vm.lock')
        try:
            with self.assertRaisesRegex(Error, 'owns this VM'):
                execution_slot(self.root/'vm.lock')
        finally:
            slot.close()
        execution_slot(self.root/'vm.lock').close()

    def test_configuration_creates_fresh_state_without_touching_agent_config(self):
        binary = self.root/'host'; binary.write_bytes(b'host fixture')
        base = dict(self.configs['execution'], mode='wasm', execution_architecture='hal-managed-agent-v2',
                    binary=str(binary), tls_cert='certificate', tls_key='key')
        base_path, profile = self.root/'base.json', self.root/'profile.json'
        atomic_json(base_path, base)
        atomic_json(profile, dict(version=1, role='execution', native_key=str(self.root/'native-key.json'),
            native_certificate=str(self.root/'native-certificate.json'), management_public_key=public(self.manager_key)))
        before = base_path.read_bytes()
        result = configure(base_path, profile, self.root/'new/native.json')
        self.assertEqual(base_path.read_bytes(), before)
        self.assertNotEqual(result['state_dir'], base['state_dir'])
        self.assertEqual(result['cache'], 'bypass')
        with self.assertRaises(Error):
            configure(base_path, profile, self.root/'new/native.json')


def canonical_audit(database):
    return '\n'.join(r[0] for r in database.connection.execute('SELECT record FROM audit_records'))


if __name__ == '__main__':
    unittest.main(verbosity=2)
