#!/usr/bin/env python3
"""Compare two explicit fleet.py bench batches, per function, without submitting jobs."""
import argparse
from collections import Counter
import csv
import hashlib
import json
import math
from pathlib import Path
import statistics
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


METRICS = {
    'client': ('client_observed_ms',),
    'management': ('timings_ms', 'management_total'),
    'host': ('response', 'agent', 'timings_ms', 'host_request'),
}
SESSION_FIELDS = ('tenant', 'revision', 'audience', 'mode', 'isolation', 'settings', 'execution_architecture',
                  'interface', 'audit_log', 'agent_sha256', 'attestation_verified', 'build', 'workload_configuration')
AGENT_FIELDS = ('tenant', 'sha256', 'artifact_bytes', 'execution_mode', 'host_sha256',
                'agent_sha256', 'platform', 'non_tee_test_mode', 'configuration',
                'agent_security', 'execution_architecture', 'attestation_verified')


def at(value, path):
    for key in path:
        if not isinstance(value, dict):
            return None
        value = value.get(key)
    return value


def number(value):
    return type(value) in (int, float) and math.isfinite(value) and value >= 0


def distribution(values):
    if not values:
        return None
    values = sorted(values)
    return dict(count=len(values), median=statistics.median(values),
                p95=values[math.ceil(.95 * len(values)) - 1],
                minimum=values[0], maximum=values[-1])


def reduction(bypass, reuse):
    return 100 * (bypass - reuse) / bypass if bypass > 0 else None


def read_json(path):
    value = json.loads(path.read_text(encoding='utf-8-sig'))
    if not isinstance(value, dict):
        raise ValueError(str(path) + ': expected a JSON object')
    return value


def load_batch(directory, cache):
    directory = Path(directory).resolve()
    config = read_json(directory / 'config.json')
    if 'experiment_id' in config or (directory / 'integrity.json').exists():
        from hal_fleet.benchmark_guard import verify_batch
        from hal_fleet.common import Error
        try:
            verify_batch(directory)
        except (Error, OSError, KeyError) as exc:
            raise ValueError(str(directory) + ': benchmark provenance rejected: ' + str(exc)) from exc
    cases, jobs = config.get('cases'), config.get('jobs')
    if (not isinstance(cases, list) or not cases
            or not all(isinstance(c, str) and c for c in cases)
            or len(set(cases)) != len(cases) or type(jobs) is not int or jobs < len(cases)):
        raise ValueError(str(directory) + ': invalid cases/jobs, or not every case was scheduled')
    if config.get('cache') != cache or at(config, ('session', 'mode')) != 'wasm':
        raise ValueError(str(directory) + ': expected an agent ' + cache + ' batch')
    if type(config.get('concurrency')) is not int or config['concurrency'] < 1:
        raise ValueError(str(directory) + ': invalid concurrency')
    expected = Counter(cases[i % len(cases)] for i in range(jobs))
    groups = {case: dict(expected=expected[case], observed=0, completed=0,
                         statuses=Counter(), cache_status_counts=Counter(),
                         container_startups=0, issues=[], profile_values={},
                         values={metric: [] for metric in METRICS}) for case in cases}
    seen, job_ids = set(), set()
    digest = hashlib.sha256()
    with (directory / 'jobs.jsonl').open('rb') as stream:
        for line_number, raw in enumerate(stream, 1):
            digest.update(raw)
            try:
                row = json.loads(raw)
            except ValueError as exc:
                raise ValueError(f'{directory}/jobs.jsonl:{line_number}: invalid JSON; batch may be interrupted') from exc
            if not isinstance(row, dict):
                raise ValueError(f'{directory}/jobs.jsonl:{line_number}: expected an object')
            index, case = row.get('trial_index'), row.get('case')
            if (type(index) is not int or not 0 <= index < jobs or index in seen
                    or case != cases[index % len(cases)]):
                raise ValueError(f'{directory}/jobs.jsonl:{line_number}: duplicate or inconsistent trial/case')
            seen.add(index)
            job_id = row.get('job_id')
            if job_id is not None:
                if not isinstance(job_id, str) or not job_id or job_id in job_ids:
                    raise ValueError(f'{directory}/jobs.jsonl:{line_number}: invalid or duplicate job ID')
                job_ids.add(job_id)
            group = groups[case]
            group['observed'] += 1
            status = row.get('status') if isinstance(row.get('status'), str) else 'missing-status'
            group['statuses'][status] += 1
            if status != 'completed':
                continue
            group['completed'] += 1
            if row.get('client_result_validation') != 'passed':
                group['issues'].append('A completed job lacks passed client validation')
            agent = at(row, ('response', 'agent'))
            if not isinstance(agent, dict):
                agent = {}
            if not agent.get('sha256') or agent.get('execution_mode') != 'wasm':
                group['issues'].append('A completed job lacks an artifact digest or agent execution mode')
            if job_id is None or agent.get('job_id') != job_id:
                group['issues'].append('A completed job has inconsistent job IDs')
            actual_cache = agent.get('cache_status')
            if actual_cache not in (('bypass',) if cache == 'bypass' else ('hit', 'miss', 'shared')):
                group['issues'].append('Unexpected actual cache status')
            if agent.get('cache_policy') != cache:
                group['issues'].append('Response cache policy differs from the requested policy')
            group['cache_status_counts'][str(actual_cache)] += 1
            startup = at(agent, ('container', 'startup_ms'))
            group['container_startups'] += int(number(startup) and startup > 0)
            for field in AGENT_FIELDS:
                encoded = json.dumps(agent.get(field), sort_keys=True, allow_nan=False)
                group['profile_values'].setdefault(field, set()).add(encoded)
            for metric, path in METRICS.items():
                value = at(row, path)
                if number(value):
                    group['values'][metric].append(value)
                else:
                    group['issues'].append('Missing or invalid ' + metric + ' timing')
    issues = []
    summary_path = directory / 'summary.json'
    summary = read_json(summary_path) if summary_path.exists() else {}
    completed = sum(g['completed'] for g in groups.values())
    if not summary:
        issues.append('summary.json is missing; this batch may not have finished')
    elif (summary.get('requested') != jobs or summary.get('completed') != completed
          or summary.get('failed_or_unknown') != jobs - completed):
        issues.append('Saved summary counts do not match config.json and jobs.jsonl')
    wall = summary.get('batch_wall_ms')
    if not number(wall) or wall <= 0:
        issues.append('Missing or invalid batch wall time')
        wall = None
    for group in groups.values():
        group['missing'] = group['expected'] - group['observed']
        group['failed_or_unknown'] = group['observed'] - group['completed']
        if group['missing']:
            group['issues'].append('Missing scheduled jobs')
        if group['failed_or_unknown']:
            group['issues'].append('Failed or unknown jobs')
        group['issues'] = sorted(set(group['issues']))
        group['timings_ms'] = {m: distribution(v) for m, v in group.pop('values').items()}
    return dict(path=str(directory), jobs_sha256=digest.hexdigest(), config=config,
                issues=issues, groups=groups, batch_wall_ms=wall,
                completed=completed, failed_or_missing=jobs - completed,
                completed_jobs_per_second=completed * 1000 / wall if wall else None)


def compare(reuse_directory, bypass_directory):
    reuse, bypass = load_batch(reuse_directory, 'reuse'), load_batch(bypass_directory, 'bypass')
    problems = []
    if ('experiment_id' in reuse['config']) != ('experiment_id' in bypass['config']):
        problems.append('Legacy and provenance-checked benchmark populations must stay separate')
    for name, batch in [('reuse', reuse), ('bypass', bypass)]:
        problems.extend(name + ': ' + issue for issue in batch['issues'])
    for field in ('jobs', 'concurrency', 'cases', 'transport', 'client_signing_included',
                  'setup_included', 'endpoints', 'attestation_verified'):
        if reuse['config'].get(field) != bypass['config'].get(field):
            problems.append('Batch configuration differs: ' + field)
    for field in SESSION_FIELDS:
        if at(reuse['config'], ('session', field)) != at(bypass['config'], ('session', field)):
            problems.append('Execution session configuration differs: ' + field)
    rows, warnings = [], []
    for case in sorted(set(reuse['groups']) | set(bypass['groups'])):
        r, b = reuse['groups'].get(case), bypass['groups'].get(case)
        issues = list(problems)
        if r is None or b is None:
            issues.append('Workload is absent from one batch')
        else:
            for label, group in [('reuse', r), ('bypass', b)]:
                issues.extend(label + ': ' + issue for issue in group['issues'])
            for field in AGENT_FIELDS:
                left, right = r['profile_values'].get(field, set()), b['profile_values'].get(field, set())
                if len(left) != 1 or len(right) != 1 or left != right:
                    issues.append('Workload/build/execution configuration differs: ' + field)
        comparable = not issues
        metrics = {}
        for metric in METRICS:
            rd = r['timings_ms'][metric] if r else None
            bd = b['timings_ms'][metric] if b else None
            metrics[metric] = dict(bypass=bd, reuse=rd,
                median_reduction_percent=reduction(bd['median'], rd['median']) if comparable and bd and rd else None,
                p95_reduction_percent=reduction(bd['p95'], rd['p95']) if comparable and bd and rd else None)
        details = {}
        for label, group in [('reuse', r), ('bypass', b)]:
            details[label] = {k: v for k, v in group.items() if k not in ('profile_values', 'timings_ms', 'issues')} if group else None
        rows.append(dict(workload=case, comparable=comparable, issues=sorted(set(issues)),
                         metrics_ms=metrics, **details))
        if r and r['cache_status_counts'].get('hit', 0) != r['completed']:
            warnings.append(case + ': reuse includes non-hit results; all completed jobs remain in the statistics')
        if (r and r['container_startups']) or (b and b['container_startups']):
            warnings.append(case + ': measured jobs include container startup')
        if (r and r['completed'] < 100) or (b and b['completed'] < 100):
            warnings.append(case + ': fewer than 100 completed samples per batch; treat p95 as preliminary')
    comparable = bool(rows) and all(row['comparable'] for row in rows)
    throughput = None
    if comparable and bypass['completed_jobs_per_second'] > 0:
        throughput = 100 * (reuse['completed_jobs_per_second'] / bypass['completed_jobs_per_second'] - 1)
    batches = {}
    for label, batch in [('reuse', reuse), ('bypass', bypass)]:
        batches[label] = {k: v for k, v in batch.items() if k not in ('groups', 'issues')}
    return dict(comparable=comparable, batches=batches, workloads=rows,
                throughput_increase_percent=throughput, warnings=warnings,
                notes=[
                    'Positive latency reduction means reuse is faster; negative means reuse is slower.',
                    'Latency reduction = 100 * (bypass - reuse) / bypass; zero baselines yield null.',
                    'Statistics include all completed reuse jobs, including misses and shared preparation.',
                    'Client, management and host durations overlap and must not be added.',
                    'p95 uses the nearest-rank observation. These are descriptive results, not causal proof.',
                    'Only the two named batch directories are read; sibling warm-up directories are excluded.',
                    'Attestation/validation values are recorded claims; this offline script does not reverify receipts.',
                ])


def write_report(report, directory):
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=False)
    (directory / 'comparison.json').write_text(json.dumps(report, indent=2, allow_nan=False) + '\n', encoding='utf-8')
    columns = ['workload', 'metric', 'comparable', 'bypass_count', 'reuse_count',
               'bypass_median_ms', 'reuse_median_ms', 'median_reduction_percent',
               'bypass_p95_ms', 'reuse_p95_ms', 'p95_reduction_percent',
               'reuse_hits', 'reuse_misses', 'reuse_shared', 'bypass_failed_or_missing',
               'reuse_failed_or_missing', 'issues']
    with (directory / 'comparison.csv').open('w', encoding='utf-8', newline='') as stream:
        writer = csv.DictWriter(stream, fieldnames=columns)
        writer.writeheader()
        for row in report['workloads']:
            for metric, values in row['metrics_ms'].items():
                b, r = values['bypass'] or {}, values['reuse'] or {}
                counts = (row['reuse'] or {}).get('cache_status_counts', {})
                writer.writerow(dict(workload=row['workload'], metric=metric, comparable=row['comparable'],
                    bypass_count=b.get('count', 0), reuse_count=r.get('count', 0),
                    bypass_median_ms=b.get('median'), reuse_median_ms=r.get('median'),
                    median_reduction_percent=values['median_reduction_percent'],
                    bypass_p95_ms=b.get('p95'), reuse_p95_ms=r.get('p95'),
                    p95_reduction_percent=values['p95_reduction_percent'],
                    reuse_hits=counts.get('hit', 0), reuse_misses=counts.get('miss', 0), reuse_shared=counts.get('shared', 0),
                    bypass_failed_or_missing=(row['bypass']['expected'] - row['bypass']['completed']) if row['bypass'] else None,
                    reuse_failed_or_missing=(row['reuse']['expected'] - row['reuse']['completed']) if row['reuse'] else None,
                    issues='; '.join(row['issues'])))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--reuse', type=Path, required=True, help='Measured reuse batch directory (not its warm-up)')
    parser.add_argument('--bypass', type=Path, required=True, help='Measured bypass batch directory')
    parser.add_argument('--output', type=Path, required=True, help='New directory for comparison.csv and comparison.json')
    args = parser.parse_args(argv)
    try:
        report = compare(args.reuse, args.bypass)
        write_report(report, args.output)
    except (OSError, ValueError, TypeError) as exc:
        print('Error: ' + str(exc), file=sys.stderr)
        return 1
    print('All times are milliseconds. Positive reductions mean reuse is faster.')
    print(f'{"Workload":<21} {"Bypass/client":>14} {"Reuse/client":>14} {"Client %":>10} {"Mgmt %":>10} {"Host %":>10} {"Hits/jobs":>11}')
    def fmt(value):
        return f'{value:.2f}' if value is not None else 'n/a'
    for row in report['workloads']:
        metrics = row['metrics_ms']
        b, r = metrics['client']['bypass'] or {}, metrics['client']['reuse'] or {}
        counts = row['reuse'] or {}
        hits = str(counts.get('cache_status_counts', {}).get('hit', 0)) + '/' + str(counts.get('completed', 0))
        print(f'{row["workload"]:<21} {fmt(b.get("median")):>14} {fmt(r.get("median")):>14} '
              f'{fmt(metrics["client"]["median_reduction_percent"]):>10} '
              f'{fmt(metrics["management"]["median_reduction_percent"]):>10} '
              f'{fmt(metrics["host"]["median_reduction_percent"]):>10} {hits:>11}')
        if row['issues']:
            print('  Not comparable: ' + '; '.join(row['issues']))
    print('Batch throughput increase (%): ' + fmt(report['throughput_increase_percent']))
    for warning in report['warnings']:
        print('Note: ' + warning)
    print('Saved: ' + str(args.output / 'comparison.csv'))
    print('Saved: ' + str(args.output / 'comparison.json'))
    return 0 if report['comparable'] else 2


if __name__ == '__main__':
    sys.exit(main())
