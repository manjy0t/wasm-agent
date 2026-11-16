#!/usr/bin/env python3
"""Offline benchmark analysis: real files, independently calculated expectations."""
import csv
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from contextlib import redirect_stdout


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('compare_cache', ROOT / 'benchmarks/compare_cache.py')
analysis = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(analysis)


class CacheComparisonTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def batch(self, name, cache, times, cases=('matrix-multiply',), mutate=None):
        folder = self.root / name
        folder.mkdir()
        config = dict(jobs=len(times), concurrency=1, cache=cache, cases=list(cases),
                      transport='synchronous-http-keepalive', setup_included=False,
                      client_signing_included=True, endpoints={'management': 'https://example.invalid'},
                      attestation_verified=True,
                      session=dict(mode='wasm', isolation='per-user-container', settings={'compiler_threads': 2}))
        rows = []
        for index, value in enumerate(times):
            case = cases[index % len(cases)]
            rows.append(dict(trial_index=index, case=case, job_id=name + str(index), status='completed',
                client_result_validation='passed', client_observed_ms=value,
                timings_ms={'management_total': value / 2},
                response={'agent': dict(job_id=name + str(index), sha256=case, execution_mode='wasm',
                    cache_policy=cache, cache_status='hit' if cache == 'reuse' else 'bypass',
                    host_sha256='host-version-1', agent_sha256='agent-version-1',
                    configuration={'workload_isolation': 'per-user-container', 'compile_opt_level': 'speed'},
                    timings_ms={'host_request': value / 4}, container={'startup_ms': 0})}))
        if mutate:
            mutate(config, rows)
        completed = sum(r.get('status') == 'completed' for r in rows)
        summary = dict(requested=config['jobs'], completed=completed,
                       failed_or_unknown=config['jobs'] - completed, batch_wall_ms=sum(times))
        for file, data in [('config.json', config), ('summary.json', summary)]:
            (folder / file).write_text(json.dumps(data))
        (folder / 'jobs.jsonl').write_text(''.join(json.dumps(r) + '\n' for r in rows))
        return folder

    def compare(self, reuse, bypass):
        return analysis.compare(reuse, bypass)

    def test_new_results_cannot_skip_the_integrity_check(self):
        reuse = self.batch('reuse-new', 'reuse', [50], mutate=lambda config, rows: config.update(experiment_id='new-run'))
        with self.assertRaisesRegex(ValueError, 'provenance rejected'):
            analysis.load_batch(reuse, 'reuse')

    def test_damaged_seal_is_not_treated_as_a_legacy_batch(self):
        reuse = self.batch('reuse-new', 'reuse', [50])
        (reuse / 'integrity.json').write_text(json.dumps({'schema': 'unexpected'}))
        with self.assertRaisesRegex(ValueError, 'provenance rejected'):
            analysis.load_batch(reuse, 'reuse')

    def test_per_function_medians_nearest_rank_p95_and_misses_are_included(self):
        cases = ('matrix-multiply', 'clock')
        bypass = self.batch('bypass', 'bypass', [100, 10, 200, 20, 300, 30, 400, 40], cases)
        def miss(config, rows):
            rows[4]['response']['agent']['cache_status'] = 'miss'
        reuse = self.batch('reuse', 'reuse', [50, 20, 60, 40, 300, 60, 70, 80], cases, miss)
        report = self.compare(reuse, bypass)
        self.assertTrue(report['comparable'])
        rows = {r['workload']: r for r in report['workloads']}
        matrix = rows['matrix-multiply']['metrics_ms']['client']
        self.assertEqual(matrix['bypass']['median'], 250)
        self.assertEqual(matrix['reuse']['median'], 65)
        self.assertEqual(matrix['median_reduction_percent'], 74)
        self.assertEqual(matrix['p95_reduction_percent'], 25)
        self.assertEqual(rows['clock']['metrics_ms']['client']['median_reduction_percent'], -100)
        self.assertEqual(rows['matrix-multiply']['reuse']['cache_status_counts'], {'hit': 3, 'miss': 1})
        self.assertAlmostEqual(report['throughput_increase_percent'], (1100 / 680 - 1) * 100)
        self.assertTrue(any('non-hit' in w for w in report['warnings']))

    def test_failures_and_missing_rows_are_visible_and_suppress_percentages(self):
        bypass = self.batch('bypass', 'bypass', [100, 100, 100])
        def failed(config, rows):
            rows[1] = dict(trial_index=1, case='matrix-multiply', status='unknown', error='Session expired')
            rows.pop()
        reuse = self.batch('reuse', 'reuse', [50, 50, 50], mutate=failed)
        report = self.compare(reuse, bypass)
        row = report['workloads'][0]
        self.assertFalse(report['comparable'])
        self.assertEqual(row['reuse']['failed_or_unknown'], 1)
        self.assertEqual(row['reuse']['missing'], 1)
        self.assertIsNone(row['metrics_ms']['client']['median_reduction_percent'])
        self.assertIsNone(report['throughput_increase_percent'])

    def test_profile_artifact_or_compiler_change_prevents_a_cache_only_comparison(self):
        bypass = self.batch('bypass', 'bypass', [100])
        for field, value in [('sha256', 'different-artifact'), ('host_sha256', 'new-build'),
                             ('configuration', {'compile_opt_level': 'none'})]:
            with self.subTest(field=field):
                def change(config, rows):
                    rows[0]['response']['agent'][field] = value
                reuse = self.batch('reuse-' + field, 'reuse', [50], mutate=change)
                report = self.compare(reuse, bypass)
                self.assertFalse(report['comparable'])
                self.assertTrue(any(field in issue for issue in report['workloads'][0]['issues']))
                self.assertIsNone(report['workloads'][0]['metrics_ms']['host']['median_reduction_percent'])

    def test_different_concurrency_or_transport_is_not_silently_compared(self):
        bypass = self.batch('bypass', 'bypass', [100])
        for field, value in [('concurrency', 4), ('transport', 'status-polling')]:
            def change(config, rows):
                config[field] = value
            reuse = self.batch('reuse-' + field, 'reuse', [50], mutate=change)
            self.assertFalse(self.compare(reuse, bypass)['comparable'])

    def test_different_user_or_grant_revision_is_not_silently_compared(self):
        bypass = self.batch('bypass', 'bypass', [100])
        for field, value in [('tenant', 'bob'), ('revision', 9)]:
            def change(config, rows):
                config['session'][field] = value
            reuse = self.batch('reuse-' + field, 'reuse', [50], mutate=change)
            self.assertFalse(self.compare(reuse, bypass)['comparable'])

    def test_missing_nonfinite_and_boolean_timings_are_never_replaced_with_zero(self):
        bypass = self.batch('bypass', 'bypass', [100])
        for index, value in enumerate([None, float('nan'), float('inf'), True, -1]):
            def change(config, rows):
                rows[0]['client_observed_ms'] = value
            reuse = self.batch('reuse-' + str(index), 'reuse', [50], mutate=change)
            row = self.compare(reuse, bypass)['workloads'][0]
            self.assertIsNone(row['metrics_ms']['client']['reuse'])
            self.assertIsNone(row['metrics_ms']['client']['median_reduction_percent'])
            self.assertFalse(row['comparable'])

    def test_zero_duration_does_not_produce_division_by_zero_or_invent_a_percentage(self):
        def zero(config, rows):
            rows[0]['response']['agent']['timings_ms']['host_request'] = 0
        bypass = self.batch('bypass', 'bypass', [100], mutate=zero)
        reuse = self.batch('reuse', 'reuse', [50], mutate=zero)
        row = self.compare(reuse, bypass)['workloads'][0]
        self.assertTrue(row['comparable'])
        self.assertEqual(row['metrics_ms']['client']['median_reduction_percent'], 50)
        self.assertIsNone(row['metrics_ms']['host']['median_reduction_percent'])

    def test_corrupt_json_duplicate_trials_and_inconsistent_summary_are_detected(self):
        bypass = self.batch('bypass', 'bypass', [100, 100])
        reuse = self.batch('reuse', 'reuse', [50, 50])
        jobs = reuse / 'jobs.jsonl'
        original = jobs.read_text()
        jobs.write_text(original + original.splitlines()[0] + '\n')
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            self.compare(reuse, bypass)
        jobs.write_text(original + '{broken')
        with self.assertRaisesRegex(ValueError, 'invalid JSON'):
            self.compare(reuse, bypass)
        jobs.write_text(original)
        summary = json.loads((reuse / 'summary.json').read_text())
        summary['completed'] = 999
        (reuse / 'summary.json').write_text(json.dumps(summary))
        self.assertFalse(self.compare(reuse, bypass)['comparable'])
        (reuse / 'summary.json').unlink()
        self.assertFalse(self.compare(reuse, bypass)['comparable'])

    def test_duplicate_job_ids_wrong_modes_and_unvalidated_success_are_detected(self):
        bypass = self.batch('bypass', 'bypass', [100, 100])
        def duplicate(config, rows):
            rows[1]['job_id'] = rows[0]['job_id']
        reuse = self.batch('duplicate', 'reuse', [50, 50], mutate=duplicate)
        with self.assertRaisesRegex(ValueError, 'duplicate job ID'):
            self.compare(reuse, bypass)
        def native(config, rows):
            config['session']['mode'] = 'native'
        reuse = self.batch('native', 'reuse', [50, 50], mutate=native)
        with self.assertRaisesRegex(ValueError, 'expected an agent'):
            self.compare(reuse, bypass)
        def invalid(config, rows):
            rows[0].pop('client_result_validation')
        reuse = self.batch('unvalidated', 'reuse', [50, 50], mutate=invalid)
        self.assertFalse(self.compare(reuse, bypass)['comparable'])

    def test_reports_do_not_read_warmups_or_overwrite_existing_files(self):
        bypass = self.batch('bypass', 'bypass', [100, 200])
        reuse = self.batch('reuse', 'reuse', [50, 100])
        warmup = self.root / 'reuse-warmup'
        warmup.mkdir()
        (warmup / 'jobs.jsonl').write_text('deliberately invalid warm-up fixture')
        original = {p: p.read_bytes() for p in self.root.rglob('*') if p.is_file()}
        output = self.root / 'report'
        arguments = ['--reuse', str(reuse), '--bypass', str(bypass), '--output', str(output)]
        with redirect_stdout(io.StringIO()) as stream:
            self.assertEqual(analysis.main(arguments), 0)
        self.assertIn('50.00', stream.getvalue())
        with (output / 'comparison.csv').open() as file:
            rows = list(csv.DictReader(file))
        self.assertEqual(len(rows), 3)
        self.assertEqual({r['metric'] for r in rows}, {'client', 'management', 'host'})
        self.assertEqual(float(rows[0]['median_reduction_percent']), 50)
        for path, before in original.items():
            self.assertEqual(path.read_bytes(), before)
        report_before = (output / 'comparison.json').read_bytes()
        with self.assertRaises(FileExistsError):
            analysis.write_report({}, output)
        self.assertEqual((output / 'comparison.json').read_bytes(), report_before)

    def test_invalid_comparison_saves_counts_and_exits_nonzero(self):
        bypass = self.batch('bypass', 'bypass', [100])
        def failed(config, rows):
            rows[0]['status'] = 'failed'
        reuse = self.batch('reuse', 'reuse', [50], mutate=failed)
        output = self.root / 'report'
        with redirect_stdout(io.StringIO()):
            status = analysis.main(['--reuse', str(reuse), '--bypass', str(bypass), '--output', str(output)])
        self.assertEqual(status, 2)
        saved = json.loads((output / 'comparison.json').read_text())
        self.assertFalse(saved['comparable'])
        self.assertEqual(saved['workloads'][0]['reuse']['failed_or_unknown'], 1)


if __name__ == '__main__':
    unittest.main(verbosity=2)
