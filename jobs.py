#!/usr/bin/env python3
"""Submit jobs, inspect results, or run a continuous bounded-concurrency trial."""
import argparse
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
import csv
import json
import math
from pathlib import Path
import statistics
import sys
import time
from urllib.request import Request, urlopen
import uuid

TERMINAL = {'completed', 'failed', 'unknown'}


def api(base, token, path, body=None):
    data = None if body is None else json.dumps(body).encode()
    request = Request(base.rstrip('/') + path, data=data,
                      headers={'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json'})
    with urlopen(request, timeout=30) as response:
        return json.load(response)


def run_job(base, token, case, policy, timeout=300, wait_seconds=20, job_id=None, signer=None):
    start = time.perf_counter()
    job_id = job_id or str(uuid.uuid4())
    body = {'job_id': job_id, 'case': case, 'cache': policy}
    if signer is not None:
        body['job_ticket'] = signer.ticket(case, policy, job_id)
    record = api(base, token, '/v1/jobs', body)
    while record['status'] not in TERMINAL:
        if time.perf_counter() - start > timeout:
            raise TimeoutError(f'job {job_id} still pending; query its status; do not automatically replay it')
        remaining = timeout - (time.perf_counter() - start)
        record = api(base, token, '/v1/jobs/' + job_id + '?wait=' + str(min(wait_seconds, max(0, remaining))))
    record['client_observed_ms'] = (time.perf_counter() - start) * 1000
    return record


def percentile(values, p):
    values = sorted(values)
    position = (len(values) - 1) * p
    low = math.floor(position)
    high = math.ceil(position)
    return values[low] + (values[high] - values[low]) * (position - low)


def host_batch_metrics(before, after, rows, policy):
    """Audit one host across a batch; CPU belongs to the process, not one job."""
    errors = []
    if not before or not after or before.get('status') != 'ok' or after.get('status') != 'ok':
        return {'valid': False, 'errors': ['host statistics unavailable'], 'before': before, 'after': after}
    for key in ('instance', 'host_sha256', 'agent_sha256', 'execution_mode', 'configuration'):
        if before.get(key) != after.get(key):
            errors.append(f'host {key} changed during the batch')
    for label, snapshot in [('before', before), ('after', after)]:
        compiler = snapshot.get('stats', {}).get('compiler', {})
        if snapshot.get('requests_inflight') != 0 or compiler.get('occupied_slots') != 0:
            errors.append(f'host was not idle {label} the batch')
    for row in rows:
        host = (row.get('response') or {}).get('agent') or {}
        if row['status'] != 'completed':
            continue
        if (host.get('host_instance') != before.get('instance')
                or host.get('host_sha256') != before.get('host_sha256')
                or host.get('configuration') != before.get('configuration')
                or host.get('execution_mode') != before.get('execution_mode')):
            errors.append('a completed job used a different host or configuration')
            break
    deltas = {}
    for key in ('downloads', 'compiles', 'executions', 'shared_preparations'):
        first, last = before.get('stats', {}).get(key), after.get('stats', {}).get(key)
        if isinstance(first, int) and isinstance(last, int):
            deltas[key] = last - first
        else:
            errors.append(f'missing host counter {key}')
    completed = sum(r['status'] == 'completed' for r in rows)
    if policy == 'bypass' and completed == len(rows):
        if any(deltas.get(k) != completed for k in ('downloads', 'compiles', 'executions')):
            errors.append('expected exactly one download, compile and execution per bypass job; '
                          'other clients or unfinished work may have affected this batch')
        if deltas.get('shared_preparations') != 0:
            errors.append('bypass batch unexpectedly shared preparation')
    resources = {}
    first, last = before.get('process_resources', {}), after.get('process_resources', {})
    span = after.get('uptime_ms', 0) - before.get('uptime_ms', 0)
    if first.get('available') and last.get('available') and span > 0:
        cpu = sum(last[k] - first[k] for k in ('user_cpu_ms', 'system_cpu_ms'))
        resources = {'host_cpu_ms': cpu, 'host_snapshot_interval_ms': span,
                     'average_cpu_cores_used': cpu / span,
                     'host_cpu_ms_per_completed_job': cpu / completed if completed else None,
                     'host_lifetime_peak_rss_mib': last['peak_rss_mib'],
                     'scope': 'native execution host including Wasm agent and compilation; '
                              'excludes management, file server and benchmark client; '
                              'snapshot interval includes small gaps around the timed batch'}
    else:
        errors.append('process resource statistics unavailable')
    return {'valid': not errors, 'errors': errors, 'counter_deltas': deltas,
            'resources': resources, 'before': before, 'after': after}


def benchmark(args, token):
    signer = getattr(args, 'signer', None)
    cases = args.cases.split(',') if args.cases else api(args.url, token, '/v1/cases')['cases']
    if not cases or any(not case for case in cases):
        raise ValueError('choose at least one case')
    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=False)
    (output / 'config.json').write_text(json.dumps({
        'url': args.url, 'cases': cases, 'jobs': args.jobs, 'concurrency': args.concurrency,
        'cache': args.cache, 'wait_seconds': args.wait_seconds, 'expected_mode': args.expect_mode,
        'expected_compile_opt_level': args.expect_compile_opt_level,
        'expected_isolation': args.expect_isolation,
        'record_host_stats': args.record_host_stats,
        'job_authorization': signer.descriptor if signer else None,
        'client_signing_included_in_batch_time': signer is not None,
        'model': 'closed-loop; each client sends its next job after receiving the previous result',
        'prefetch': False, 'attestation': False, 'started_unix': time.time(),
        'cache_state': 'not reset by this script; use a new host/cache directory for a cold run',
    }, indent=2) + '\n')
    before = api(args.url, token, '/v1/worker-stats') if args.record_host_stats else None
    if args.record_host_stats:
        (output / 'host-before.json').write_text(json.dumps(before, indent=2) + '\n')
        if before.get('configuration', {}).get('workload_isolation') == 'per-user-container':
            raise ValueError('--record-host-stats measures only the broker process and is not valid for container workers; '
                             'omit this flag and record Docker/cgroup resource statistics separately')
        if before.get('status') != 'ok' or not before.get('process_resources', {}).get('available'):
            raise ValueError('host does not provide resource statistics; update the host before this trial')
        if (before.get('requests_inflight') != 0
                or before.get('stats', {}).get('compiler', {}).get('occupied_slots') != 0):
            raise ValueError('host is still processing work; let existing jobs finish before benchmarking')
    def one(i):
        case = cases[i % len(cases)]
        job_id = f'trial-{uuid.uuid4()}'
        try:
            row = run_job(args.url, token, case, args.cache, args.timeout, args.wait_seconds, job_id, signer)
            worker = (row.get('response') or {}).get('agent', {})
            actual = worker.get('execution_mode')
            isolation = worker.get('configuration', {}).get('workload_isolation')
            if signer and row['status'] == 'completed':
                proof = worker.get('job_authorization', {})
                if not (proof.get('verified') is True and proof.get('helper_checked') is True
                        and proof.get('broker_checked') is True and proof.get('epoch') == signer.epoch
                        and proof.get('tenant') == signer.config['tenant']
                        and (isolation != 'per-user-container' or proof.get('worker_checked') is True)):
                    row.update(job_status='completed', status='authorization_mismatch',
                               error='execution did not report the required signed-job checks')
            if args.expect_isolation and row['status'] == 'completed' and isolation != args.expect_isolation:
                row.update(job_status='completed', status='isolation_mismatch',
                           error=f'expected {args.expect_isolation}, received {isolation}; job did execute')
            if args.expect_mode and row['status'] == 'completed' and actual != args.expect_mode:
                row.update(job_status='completed', status='mode_mismatch',
                           error=f'expected {args.expect_mode}, received {actual}; job did execute')
            level = worker.get('configuration', {}).get('compile_opt_level')
            if args.expect_compile_opt_level and row['status'] == 'completed' and level != args.expect_compile_opt_level:
                row.update(job_status='completed', status='configuration_mismatch',
                           error=f'expected compiler optimization {args.expect_compile_opt_level}, received {level}')
            if args.cache == 'bypass' and row['status'] == 'completed':
                preparation = worker.get('preparation', {})
                if not (worker.get('cache_status') == 'bypass'
                        and worker.get('preparation_work_owner') is True
                        and preparation.get('source') == 'download'
                        and preparation.get('stored') is False
                        and 'compile' in preparation.get('work_ms', {})):
                    row.update(job_status='completed', status='policy_mismatch',
                               error='bypass result did not report an independent download and compilation without storage')
        except Exception as error:
            row = {'job_id': job_id, 'status': 'client_error', 'error': str(error)}
        row.update(trial_index=i, case=case)
        return row
    start = time.perf_counter()
    rows = []
    with (output / 'jobs.jsonl').open('w') as log, ThreadPoolExecutor(max_workers=args.concurrency) as pool:
        futures = [pool.submit(one, i) for i in range(args.jobs)]
        for future in as_completed(futures):
            row = future.result()
            rows.append(row)
            log.write(json.dumps(row) + '\n')
            log.flush()
    elapsed = time.perf_counter() - start
    host_report = None
    if args.record_host_stats:
        try:
            after = api(args.url, token, '/v1/worker-stats')
        except Exception as error:
            after = {'error': str(error)}
        host_report = host_batch_metrics(before, after, rows, args.cache)
        (output / 'host-resources.json').write_text(json.dumps(host_report, indent=2) + '\n')
    groups = defaultdict(list)
    cache_counts = Counter()
    for row in rows:
        if row['status'] != 'completed':
            continue
        response = row['response']
        agent = response['agent']
        state = agent['cache_status']
        cache_counts[state] += 1
        metrics = {'client_observed_ms': row['client_observed_ms']}
        metrics.update({k + '_ms': v for k, v in response['timings_ms'].items()})
        metrics.update({k + '_ms': v for k, v in agent['timings_ms'].items()})
        container = agent.get('container', {})
        if container:
            metrics['container_startup_ms'] = container['startup_ms']
            metrics.update({'container_worker_' + k + '_ms': v
                            for k, v in container.get('worker_timings_ms', {}).items()})
        # Shared preparation timing is deliberately not multiplied by the number
        # of waiters. Its one owner is recorded for explanation, not throughput.
        if agent.get('preparation_work_owner'):
            metrics.update({'preparation_' + k + '_ms': v
                            for k, v in agent['preparation']['work_ms'].items()})
        for metric, value in metrics.items():
            groups[(row['case'], 'all', metric)].append(value)
            groups[(row['case'], state, metric)].append(value)
    with (output / 'summary.csv').open('w', newline='') as stream:
        writer = csv.writer(stream)
        writer.writerow(['case', 'cache_status', 'metric', 'n', 'mean', 'median', 'p95', 'p99', 'min', 'max', 'stdev'])
        for (case, state, metric), values in sorted(groups.items()):
            writer.writerow([case, state, metric, len(values), statistics.mean(values), statistics.median(values),
                             percentile(values, .95), percentile(values, .99), min(values), max(values),
                             statistics.stdev(values) if len(values) > 1 else 0])
    statuses = Counter(row['status'] for row in rows)
    modes = Counter((row.get('response') or {}).get('agent', {}).get('execution_mode', 'unknown') for row in rows)
    isolations = Counter((row.get('response') or {}).get('agent', {}).get('configuration', {}).get(
        'workload_isolation', 'unknown') for row in rows)
    compiler_levels = Counter((row.get('response') or {}).get('agent', {}).get('configuration', {}).get(
        'compile_opt_level', 'unknown') for row in rows)
    connection_reuse = Counter(str((row.get('response') or {}).get('dispatch_connection_reused', 'unknown')).lower()
                               for row in rows)
    result = {'requested': args.jobs, 'completed': statuses['completed'],
              'failed_or_unknown': args.jobs - statuses['completed'], 'statuses': dict(statuses),
              'cache_status_counts': dict(cache_counts), 'execution_modes': dict(modes), 'batch_wall_ms': elapsed * 1000,
              'workload_isolations': dict(isolations),
              'compile_opt_levels': dict(compiler_levels), 'dispatch_connection_reuse_counts': dict(connection_reuse),
              'completed_jobs_per_second': statuses['completed'] / elapsed,
              'attestation_verified': False}
    if signer:
        result['signed_job_checks_reported'] = sum((r.get('response') or {}).get('agent', {}).get(
            'job_authorization', {}).get('verified') is True for r in rows if r['status'] == 'completed')
    if host_report is not None:
        result['host_audit_passed'] = host_report['valid']
        result['host_resource_summary'] = host_report.get('resources', {})
    (output / 'status.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))
    return 0 if result['failed_or_unknown'] == 0 and (host_report is None or host_report['valid']) else 1


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--url', default='http://127.0.0.1:9000')
    p.add_argument('--token-file', required=True)
    p.add_argument('--signing-config', type=Path, help='private user config, kept outside management')
    p.add_argument('--authorization-epoch', help='current execution host session from operator /v1/stats')
    sub = p.add_subparsers(dest='command', required=True)
    submit = sub.add_parser('submit')
    submit.add_argument('--case', required=True)
    submit.add_argument('--cache', choices=('reuse', 'bypass'), default='reuse')
    submit.add_argument('--job-id')
    submit.add_argument('--wait', action='store_true')
    submit.add_argument('--timeout', type=float, default=300)
    status = sub.add_parser('status')
    status.add_argument('job_id')
    sub.add_parser('stats')
    bench = sub.add_parser('bench')
    bench.add_argument('--jobs', type=int, default=100)
    bench.add_argument('--concurrency', type=int, default=8)
    bench.add_argument('--cases', help='comma-separated case names; defaults to the catalog')
    bench.add_argument('--cache', choices=('reuse', 'bypass'), default='reuse')
    bench.add_argument('--expect-mode', choices=('native', 'wasm'),
                       help='fail the trial if completed jobs used a different execution mode')
    bench.add_argument('--expect-isolation', choices=('in-process', 'per-user-container'),
                       help='fail the trial if jobs used a different isolation boundary')
    bench.add_argument('--expect-compile-opt-level', choices=('none', 'speed', 'speed-and-size'),
                       help='fail the trial if the execution host used a different compiler setting')
    bench.add_argument('--record-host-stats', action='store_true',
                       help='capture execution-host CPU, lifetime peak RSS and download/compile counters; requires updated management and host')
    bench.add_argument('--output', required=True)
    bench.add_argument('--timeout', type=float, default=300)
    bench.add_argument('--wait-seconds', type=float, default=20,
                       help='server-side result wait; returns immediately on completion')
    args = p.parse_args()
    if bool(args.signing_config) != bool(args.authorization_epoch):
        p.error('--signing-config and --authorization-epoch must be supplied together')
    args.signer = None
    if args.signing_config:
        from job_signing import Signer
        args.signer = Signer(args.signing_config, args.authorization_epoch)
    token = Path(args.token_file).read_text().strip()
    if args.command == 'bench':
        if not (1 <= args.jobs <= 100000 and 1 <= args.concurrency <= 128 and 0 < args.wait_seconds <= 20 and args.timeout > 0):
            p.error('invalid benchmark limits')
        return benchmark(args, token)
    if args.command == 'submit':
        if args.wait:
            result = run_job(args.url, token, args.case, args.cache, args.timeout, job_id=args.job_id, signer=args.signer)
        else:
            body = {'case': args.case, 'cache': args.cache}
            body['job_id'] = args.job_id or str(uuid.uuid4())
            if args.signer:
                body['job_ticket'] = args.signer.ticket(args.case, args.cache, body['job_id'])
            result = api(args.url, token, '/v1/jobs', body)
    elif args.command == 'status':
        result = api(args.url, token, '/v1/jobs/' + args.job_id)
    else:
        result = api(args.url, token, '/v1/stats')
    print(json.dumps(result, indent=2))
    return int(result.get('status') in ('failed', 'unknown'))


if __name__ == '__main__':
    sys.exit(main())
