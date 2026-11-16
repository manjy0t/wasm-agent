#!/usr/bin/env python3
"""Run repeated 100-job concurrency/cache batches through the four-VM APIs."""
import argparse
from collections import Counter
from contextlib import contextmanager, nullcontext
import copy
import json
from pathlib import Path
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from hal_fleet.client import Client, SESSION_JOB_RESERVE_SECONDS, benchmark
from hal_fleet.common import Error, atomic_json, digest, require
from hal_fleet.policy import certificate
from hal_fleet.benchmark_guard import Experiment


# These are admission margins, not longer credential/attestation lifetimes.
# The existing client still drains and refreshes before its 150-second reserve.
WARMUP_BUDGET_SECONDS = 30
MEASUREMENT_BUDGET_SECONDS = 90
WARMUP_MINIMUM_SECONDS = SESSION_JOB_RESERVE_SECONDS + MEASUREMENT_BUDGET_SECONDS + WARMUP_BUDGET_SECONDS


class WarmCacheClient(Client):
    """Keep one verified session across warm-up and its measured reuse batch."""

    def __init__(self, path):
        super().__init__(path)
        self._warming = False
        self._warmed_session = None

    @contextmanager
    def warming(self):
        self._warming = True
        try:
            yield
        finally:
            self._warming = False

    def signed(self, role, operation, body):
        if self._warming and role == 'management' and operation == 'session':
            require('minimum_validity_seconds' in body,
                    'Fully warmed measurement requires management minimum-session-validity support')
            body = dict(body, minimum_validity_seconds=WARMUP_MINIMUM_SECONDS)
        return super().signed(role, operation, body)

    def keep_warmed_session(self):
        self._warmed_session = copy.deepcopy(self.session)

    def open_session(self):
        warmed, self._warmed_session = self._warmed_session, None
        if warmed is not None:
            require(self.session == warmed, 'Session changed after warm-up; no measured job submitted')
            require(warmed['expires_unix'] > time.time() + SESSION_JOB_RESERVE_SECONDS + MEASUREMENT_BUDGET_SECONDS,
                    'Too little session lifetime remains after warm-up; no measured job submitted. '
                    'Warm-up evidence retained; no jobs retried.')
            # Reuse once. Per-job signature, policy, attestation-expiry and
            # receipt checks remain in Client.job and the services.
            return self.session
        session = super().open_session()
        require(session.get('execution_architecture') == 'hal-managed-agent-v2'
                and session.get('attestation_verified') is True
                and session.get('mode') == 'wasm' and session.get('isolation') == 'per-user-container',
                'Fully warmed measurement requires the verified agent profile')
        if self._warming:
            require(session['expires_unix'] > time.time() + WARMUP_MINIMUM_SECONDS,
                    'Session is too short for warm-up and measurement; no warm-up job submitted')
        return session


def concurrency_levels(value):
    try:
        levels = tuple(int(part) for part in value.split(','))
    except ValueError:
        levels = ()
    if not levels or len(levels) != len(set(levels)) or not set(levels) <= {1, 2, 4}:
        raise argparse.ArgumentTypeError('Choose unique concurrency levels from 1,2,4')
    return levels


def cache_policies(mode, selection=None):
    require(selection in (None, 'both', 'bypass', 'reuse'), 'Invalid cache selection')
    require(mode != 'native' or selection in (None, 'bypass'), 'Native benchmark requires cache bypass')
    if selection in ('bypass', 'reuse'):
        return (selection,)
    return ('bypass',) if mode == 'native' else ('bypass', 'reuse')


def matrix_plan(repeats, mode, concurrencies=(1, 2, 4), cache=None):
    selected = cache_policies(mode, cache)
    orders = ((1, 2, 4), (4, 2, 1), (2, 1, 4))
    for repeat in range(1, repeats + 1):
        policies = ('bypass',) if mode == 'native' else (('bypass', 'reuse') if repeat % 2 else ('reuse', 'bypass'))
        for concurrency in orders[(repeat - 1) % len(orders)]:
            if concurrency not in concurrencies:
                continue
            for cache in policies:
                if cache in selected:
                    yield repeat, concurrency, cache


def require_success(summary, folder, label):
    if summary['failed_or_unknown'] == 0:
        return
    failures = Counter()
    if summary.get('session_refresh_error'):
        failures['Session refresh: ' + summary['session_refresh_error']] = summary.get('not_submitted', 0)
    path = folder / 'jobs.jsonl'
    with path.open(encoding='utf-8') as stream:
        for line in stream:
            row = json.loads(line)
            if row.get('status') == 'completed':
                continue
            response = row.get('response') or {}
            agent = response.get('agent') or {}
            reason = row.get('error') or response.get('error') or agent.get('error') or row.get('status', 'unknown')
            failures[str(reason)[:500]] += 1
    details = json.dumps(dict(failures.most_common(5)), ensure_ascii=True)
    raise Error(f'{label} failed: {summary["completed"]}/{summary["requested"]} completed, '
                f'{summary["failed_or_unknown"]} failed/unknown. Errors: {details}. '
                f'Results retained in {path}. No jobs retried; remaining batches were not run.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--client', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--jobs', type=int, default=100)
    parser.add_argument('--repeats', type=int, default=3)
    parser.add_argument('--concurrencies', type=concurrency_levels, default=(1, 2, 4),
                        help='comma-separated subset of 1,2,4 (default: all)')
    parser.add_argument('--workloads', default='all')
    parser.add_argument('--cache', choices=('both', 'bypass', 'reuse'),
                        help='policies to measure (default: both for agent, bypass for native)')
    parser.add_argument('--expect-mode', choices=('wasm', 'native'), default='wasm')
    parser.add_argument('--expect-isolation', choices=('per-user-container', 'in-process'), default='per-user-container')
    parser.add_argument('--fully-warmed', action='store_true',
                        help='agent only: renew before warm-up, preserve its session for measurement, require all hits')
    args = parser.parse_args()
    require(1 <= args.repeats <= 20 and 1 <= args.jobs <= 100000, 'Invalid repeat/job count')
    require(not args.fully_warmed or (args.expect_mode == 'wasm' and args.expect_isolation == 'per-user-container'),
            '--fully-warmed requires the per-user-container agent profile')
    policies = cache_policies(args.expect_mode, args.cache)
    args.output.mkdir(parents=True, exist_ok=False)
    atomic_json(args.output / 'matrix-protocol.json', dict(
        fully_warmed=args.fully_warmed, cache_policies=list(policies), matrix_script_sha256=digest(Path(__file__).read_bytes()),
        warmup_minimum_validity_seconds=WARMUP_MINIMUM_SECONDS if args.fully_warmed else None,
        measurement_reserve_seconds=SESSION_JOB_RESERVE_SECONDS + MEASUREMENT_BUDGET_SECONDS if args.fully_warmed else None),
        exclusive=True)
    client = WarmCacheClient(args.client) if args.fully_warmed else Client(args.client)
    summaries = []
    try:
        client.renew()
        doc = certificate(client.document, client.config)
        approved = [w['name'] for w in doc['workloads']]
        cases = approved if args.workloads == 'all' else args.workloads.split(',')
        require(cases and len(cases) == len(set(cases)) and set(cases) <= set(approved),
                'Choose unique approved workloads')
        with Experiment(client, cases, args.expect_mode, args.expect_isolation, args.output) as experiment:
            for repeat, concurrency, cache in matrix_plan(args.repeats, args.expect_mode, args.concurrencies, args.cache):
                label = f'r{repeat}-{cache}-q{concurrency}'
                if cache == 'reuse':
                    with client.warming() if args.fully_warmed else nullcontext():
                        warmup = benchmark(client, cases, len(cases), 1, 'reuse', args.output / (label + '-warmup'),
                                           args.expect_mode, args.expect_isolation, experiment=experiment, phase='warmup')
                    require_success(warmup, args.output / (label + '-warmup'), label + ' warm-up')
                    if args.fully_warmed:
                        client.keep_warmed_session()
                print('Running ' + label, flush=True)
                summary = benchmark(client, cases, args.jobs, concurrency, cache, args.output / label,
                                    args.expect_mode, args.expect_isolation, experiment=experiment)
                summaries.append(dict(label=label, repeat=repeat, concurrency=concurrency, cache=cache, **summary))
                atomic_json(args.output / 'matrix.json', summaries)
                print(json.dumps(summaries[-1], indent=2), flush=True)
                require_success(summary, args.output / label, label)
                if args.fully_warmed and cache == 'reuse':
                    require(summary['cache_status_counts'] == {'hit': args.jobs}
                            and summary.get('session_refresh_count') == 0,
                            f'{label} was not fully warmed or changed session during measurement. '
                            f'Preserve {args.output / label} for separate analysis. '
                            'No jobs retried; remaining batches were not run.')
    finally:
        client.transport.close()
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (Error, OSError, ValueError) as exc:
        print('Error: ' + str(exc), file=sys.stderr)
        sys.exit(1)
