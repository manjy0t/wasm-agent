"""Local acceptance with real HTTP, Rust host and original SHA workload.

Requires build.py outputs and permission to bind loopback sockets. All keys,
databases, artifacts and results are temporary; no deployment is contacted.
NON_TEE_TEST_ONLY is inherited from the existing local fleet fixture.
"""
from pathlib import Path
import unittest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import test_fleet as legacy
from hal_fleet.benchmark_guard import BenchmarkGate, verify_batch
from hal_fleet.client import benchmark
from hal_fleet.common import atomic_json, private_hex, public
from hal_fleet.native_audit import NativeExecution, NativeManagement, PROFILE
from hal_fleet.native_config import issue_certificate, service_digest


class NativeAuditLiveTest(unittest.TestCase):
    setUpClass = classmethod(legacy.FleetTest.setUpClass.__func__)
    tearDown = legacy.FleetTest.tearDown
    client = legacy.FleetTest.client
    publish = legacy.FleetTest.publish
    api = legacy.FleetTest.api
    ready = legacy.FleetTest.ready

    def setUp(self):
        legacy.FleetTest.setUp(self)
        manager, native = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
        manager_path, native_path, cert = [self.root/name for name in ('native-manager.json', 'native-key.json', 'native-cert.json')]
        atomic_json(manager_path, dict(private_key=private_hex(manager)))
        atomic_json(native_path, dict(private_key=private_hex(native)))
        issue_certificate(manager_path, public(native), cert)
        self.apps['files'].config.update(protected_artifacts=True, trusted_management_keys=[public(manager)])
        execution = self.apps['execution']
        execution.close()
        execution.config.update(mode='native', execution_architecture=PROFILE, native_certificate=str(cert),
            native_key=str(native_path), management_public_key=public(manager), service_sha256=service_digest())
        self.apps['execution'] = NativeExecution(execution.config, execution.db, self.transport)
        self.servers['execution'].app = self.apps['execution']
        management = self.apps['management']
        management.config.update(execution_architecture=PROFILE, native_certificate=str(cert), management_key=str(manager_path),
                                 service_sha256=service_digest())
        self.apps['management'] = BenchmarkGate(NativeManagement(management.config, management.db, self.transport))
        self.servers['management'].app = self.apps['management']

    def test_real_native_host_audited_completion(self):
        self.ready()
        row = self.alice.job('hash-fixture', 'bypass', 'native', 'in-process')
        self.assertEqual(row['status'], 'completed', row)
        result = row['response']['agent']
        self.assertEqual(result['agent_kind'], 'none')
        self.assertEqual(result['cache_status'], 'bypass')
        self.assertEqual(result['configuration']['code_cache_storage'], 'disabled')
        self.assertTrue(result['audit_collected'])
        self.assertTrue(self.alice.audit(job_id=row['job_id'])['record_signatures_verified'])
        broker = self.apps['execution'].brokers['alice']
        stats = self.transport.call(broker.url, '/v1/stats', token=(broker.root/'operator.token').read_text().strip())
        self.assertEqual(stats['stats']['compiled_entries'], 0)
        self.assertEqual(stats['stats']['compiles'], 1)
        self.assertTrue((broker.root/'broker.log').is_file())

    def test_real_native_batch_is_unique_validated_and_verifiable(self):
        self.ready()
        folder = self.root/'native-benchmark'
        summary = benchmark(self.alice, ['hash-fixture'], 8, 2, 'bypass', folder, 'native', 'in-process')
        self.assertEqual(summary['completed'], 8, summary)
        self.assertEqual(summary['cache_status_counts'], {'bypass': 8})
        self.assertTrue(verify_batch(folder)['verified'])
        self.assertEqual(summary['timings_ms']['host']['count'], 8)


if __name__ == '__main__':
    unittest.main(verbosity=2)
