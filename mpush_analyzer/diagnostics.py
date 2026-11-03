"""V4.3 single-Agent Job diagnostics and observation-based performance.

This module reads sanitized event streams only. It neither changes analyses nor
connects to an Agent/database. Missing observations are not zero or proof of a
stopped process. All intervals are KST, half-open, with explicit bounded samples.
"""
from __future__ import annotations

from bisect import bisect_left, bisect_right
from dataclasses import dataclass
from datetime import timedelta
import math
from pathlib import Path
from statistics import median
from typing import Any

from .dashboard_data import events_iter
from .investigation import (Distribution, Window, instant, iso, job_name, number,
                            quality, reference)

MAX_GROUPS = 300
MAX_RECORDS = 100_000
MAX_STREAM_RECORDS = 50_000
MAX_DETAILS = 100
MAX_BUCKETS = 600
STEPS = ('select', 'file', 'socket', 'http_in', 'http_out', 'db')
NOTE = ('기록 공백·RUNNING 반복·긴 소요시간은 관측 징후입니다. '
        '실제 실행 누락, 프로세스 종료, DB Lock 또는 네트워크 장애를 확정하지 않습니다.')


@dataclass(frozen=True)
class DiagnosticPolicy:
    spike_ratio: float = 3.0
    absolute_delay_seconds: float = 10.0
    minimum_baseline_samples: int = 5
    running_repeat_count: int = 3

    def validate(self) -> None:
        if (number(self.spike_ratio, 100) is None or self.spike_ratio < 1 or
                number(self.absolute_delay_seconds, 86400) is None or
                self.absolute_delay_seconds <= 0 or
                type(self.minimum_baseline_samples) is not int or
                not 5 <= self.minimum_baseline_samples <= 1000 or
                type(self.running_repeat_count) is not int or
                not 2 <= self.running_repeat_count <= 1000):
            raise ValueError('지연 배율·절대 시간·기준 표본·RUNNING 반복 기준을 확인하세요.')


def _cadence(rows: list[dict]) -> float | None:
    points = sorted({r['t'] for r in rows if r['type'] == 'job_run'})
    deltas = [(b-a).total_seconds() for a, b in zip(points, points[1:]) if b > a]
    if len(deltas) < 4:
        return None
    value = median(deltas)
    return value if value > 0 and sum(.5*value <= d <= 1.5*value for d in deltas)/len(deltas) >= .75 else None


def _collect(case: Path, manifest: dict, window: Window, bucket_seconds: int,
             thresholds: dict, policy: DiagnosticPolicy) -> dict:
    bounds = window.bounds()
    width = max(bucket_seconds, math.ceil(window.seconds/MAX_BUCKETS))
    groups: dict[str, Any] = {}
    streams: dict[tuple, Any] = {}
    budget = [250_000]
    retained = undated = unlisted = 0
    tails: dict[str, Any] = {}
    for event in events_iter(case, manifest):
        t = instant(event.get('occurred_at'))
        if t is None:
            undated += 1
            continue
        fid = event['file_id']
        if fid not in tails or t > tails[fid]['t']:
            tails[fid] = {'t': t, 'ref': reference(event)}
        if not bounds[0] <= t < bounds[1]:
            continue
        typ = event.get('event_type')
        d = event.get('details')
        d = d if isinstance(d, dict) else {}
        name = job_name(d.get('job_name'))
        if typ not in {'job_run', 'job_running_skip'} or not name:
            continue
        if name not in groups and len(groups) >= MAX_GROUPS:
            raise ValueError('Job 종류가 300개를 초과했습니다. 조사 구간을 좁혀 주세요.')
        g = groups.setdefault(name, {'name': name, 'records': 0, 'complete_records': 0,
            'incomplete_records': 0, 'running_skips': 0, 'targets': 0, 'target_samples': 0,
            'paired_targets': 0, 'paired_seconds': 0., 'paired_samples': 0,
            'duration': Distribution(budget), 'steps': {s: Distribution(budget) for s in STEPS},
            'buckets': {}, 'evidence': [], 'delays': [], 'delay_count': 0})
        ref = reference(event)
        if len(g['evidence']) < MAX_DETAILS:
            g['evidence'].append(ref)
        complete = event.get('status') == 'complete'
        if typ == 'job_running_skip':
            g['running_skips'] += 1
        else:
            g['records'] += 1
            g['complete_records'] += complete
            g['incomplete_records'] += not complete
        elapsed = number(d.get('duration_seconds'), 1e6) if complete else None
        target = number(d.get('target_count'), 1e9) if complete else None
        if target is not None and int(target) != target:
            target = None
        if typ == 'job_run' and complete:
            g['duration'].add(elapsed)
            if target is not None:
                g['targets'] += target
                g['target_samples'] += 1
            if target is not None and elapsed is not None and elapsed > 0:
                g['paired_targets'] += target
                g['paired_seconds'] += elapsed
                g['paired_samples'] += 1
            steps = d.get('steps_seconds')
            steps = steps if isinstance(steps, dict) else {}
            for s in STEPS:
                g['steps'][s].add(number(steps.get(s), 1e6))
            b = int((t-bounds[0]).total_seconds()//width)
            bucket = g['buckets'].setdefault(b, {'records': 0, 'targets': 0,
                'target_samples': 0, 'seconds': 0., 'duration_samples': 0, 'maximum': None})
            bucket['records'] += 1
            if target is not None:
                bucket['targets'] += target
                bucket['target_samples'] += 1
            if elapsed is not None:
                bucket['seconds'] += elapsed
                bucket['duration_samples'] += 1
                bucket['maximum'] = max(bucket['maximum'] or 0, elapsed)
            threshold, basis = thresholds.get(name, (policy.absolute_delay_seconds, 'absolute'))
            if elapsed is not None and elapsed > threshold:
                g['delay_count'] += 1
                if len(g['delays']) < MAX_DETAILS:
                    g['delays'].append({'seconds': elapsed, 'threshold': threshold, 'basis': basis, 'ref': ref})
        if typ == 'job_run' and not complete:
            continue
        key = (fid, name)
        stream = streams.setdefault(key, {'rows': [], 'omitted': 0})
        if retained < MAX_RECORDS and len(stream['rows']) < MAX_STREAM_RECORDS:
            stream['rows'].append({'t': t, 'type': typ, 'ref': ref})
            retained += 1
        else:
            stream['omitted'] += 1
            unlisted += 1
    for g in groups.values():
        g['delay_threshold'], g['delay_basis'] = thresholds.get(g['name'], (policy.absolute_delay_seconds, 'absolute'))
        g['duration'] = g['duration'].summary()
        g['steps'] = {s: v.summary() for s, v in g['steps'].items() if v.count}
        g['targets'] = g['targets'] if g['target_samples'] else None
        g['window_target_rate'] = g['targets']/window.seconds if g['targets'] is not None else None
        g['execution_target_rate'] = g['paired_targets']/g['paired_seconds'] if g['paired_seconds'] else None
        g['longest_observed_stage'] = max(g['steps'], key=lambda s:g['steps'][s]['mean']) if g['steps'] else None
        g['delay_details_omitted'] = g['delay_count']-len(g['delays'])
        buckets = []
        for b in range(math.ceil(window.seconds/width)):
            span = min(width, window.seconds-b*width)
            v = g['buckets'].get(b)
            buckets.append({'at': iso(bounds[0]+timedelta(seconds=b*width)), 'seconds': span,
                'records': v['records'] if v else None,
                'targets': v['targets'] if v and v['target_samples'] else None,
                'target_rate': v['targets']/span if v and v['target_samples'] else None,
                'duration_mean': v['seconds']/v['duration_samples'] if v and v['duration_samples'] else None,
                'duration_max': v['maximum'] if v else None})
        g['buckets'] = buckets
    for stream in streams.values():
        stream['rows'].sort(key=lambda r:(r['t'], r['ref']['line_start']))
    return {'groups': groups, 'streams': streams, 'tails': tails, 'undated': undated,
            'omitted_records': unlisted, 'bucket_seconds': width}


def _baseline_cadences(collected: dict) -> dict:
    values: dict[str, list] = {}
    unavailable = set()
    for (_, name), stream in collected['streams'].items():
        if stream['omitted']:
            unavailable.add(name)
            continue
        value = _cadence(stream['rows'])
        if value is not None:
            values.setdefault(name, []).append(value)
    result = {}
    for name, items in values.items():
        value = median(items)
        if name not in unavailable and all(.8*value <= item <= 1.2*value for item in items):
            result[name] = value
    return result


def diagnose_jobs(case: Path, manifest: dict, window: Window, *,
                  baseline_case: Path | None = None, baseline_manifest: dict | None = None,
                  baseline_window: Window | None = None, same_agent_confirmed: bool = False,
                  bucket_seconds: int = 60, policy: DiagnosticPolicy | None = None) -> dict:
    """Compare observed records, retaining all aggregate counts but bounded details."""
    policy = policy or DiagnosticPolicy()
    policy.validate()
    window.bounds()
    if type(bucket_seconds) is not int or bucket_seconds not in (60, 300):
        raise ValueError('집계 단위는 60초 또는 300초입니다.')
    baseline = None
    if any(x is not None for x in (baseline_case, baseline_manifest, baseline_window)):
        if baseline_case is None or baseline_manifest is None or baseline_window is None or same_agent_confirmed is not True:
            raise ValueError('정상 기준 자료와 동일 Agent·비교 조건 확인이 필요합니다.')
        if abs(window.seconds-baseline_window.seconds) > .001:
            raise ValueError('기준/조사 구간 길이는 같아야 합니다.')
        a, b = window.bounds(), baseline_window.bounds()
        if case.resolve() == baseline_case.resolve() and max(a[0], b[0]) < min(a[1], b[1]):
            raise ValueError('같은 분석의 기준/조사 구간이 겹칩니다.')
        baseline = _collect(baseline_case, baseline_manifest, baseline_window, bucket_seconds, {}, policy)
    thresholds = {}
    if baseline:
        for name, g in baseline['groups'].items():
            d = g['duration']
            if d['samples'] >= policy.minimum_baseline_samples and d['p95'] is not None:
                thresholds[name] = (max(policy.absolute_delay_seconds, d['p95']*policy.spike_ratio), 'baseline_p95')
    current = _collect(case, manifest, window, bucket_seconds, thresholds, policy)
    cadence = _baseline_cadences(baseline) if baseline else {}
    diagnostics = {}
    for name in set(current['groups']) | (set(baseline['groups']) if baseline else set()):
        now = current['groups'].get(name)
        before = baseline['groups'].get(name) if baseline else None
        diagnostics[name] = {'name': name, 'current': now, 'baseline': before,
            'cadence_seconds': cadence.get(name), 'cadence_basis': 'baseline' if name in cadence else None,
            'gaps': [], 'gap_count': 0, 'running_clusters': [], 'running_cluster_count': 0,
            'sequence_records_omitted': 0, 'gap_evaluated_streams': 0, 'status': 'observed' if now else 'not_observed',
            'p95_ratio': (now['duration']['p95']/before['duration']['p95']
                          if now and before and before['duration']['p95'] and now['duration']['p95'] is not None else None)}
    completed_by_job = {}
    for (_, name), stream in current['streams'].items():
        if not stream['omitted']:
            completed_by_job.setdefault(name, []).extend(r['t'] for r in stream['rows'] if r['type'] == 'job_run')
    for points in completed_by_job.values():
        points.sort()
    for (fid, name), stream in current['streams'].items():
        d = diagnostics[name]
        d['sequence_records_omitted'] += stream['omitted']
        if stream['omitted']:
            continue  # A retained prefix cannot establish the entire sequence.
        rows = stream['rows']
        period = cadence.get(name) or _cadence(rows)
        basis = 'baseline' if name in cadence else 'current_observed'
        if period and not d['cadence_seconds']:
            d['cadence_seconds'], d['cadence_basis'] = period, basis
        completed = [r for r in rows if r['type'] == 'job_run']
        threshold = max(3*period, period+5) if period else None
        if threshold and len(completed) >= 2:
            d['gap_evaluated_streams'] += 1
            for a, b in zip(completed, completed[1:]):
                gap = (b['t']-a['t']).total_seconds()
                if gap <= threshold:
                    continue
                d['gap_count'] += 1
                if len(d['gaps']) < MAX_DETAILS:
                    d['gaps'].append({'file_id': fid, 'start': iso(a['t']), 'end': iso(b['t']),
                        'seconds': gap, 'threshold': threshold, 'basis': basis,
                        'interval_slots_estimate': max(0, math.ceil(gap/period)-1),
                        'before_ref': a['ref'], 'after_ref': b['ref']})
        cluster: list = []
        def finish_cluster() -> None:
            if len(cluster) >= policy.running_repeat_count:
                d['running_cluster_count'] += 1
                if len(d['running_clusters']) < MAX_DETAILS:
                    d['running_clusters'].append({'count': len(cluster), 'start': iso(cluster[0]['t']),
                        'end': iso(cluster[-1]['t']), 'seconds': (cluster[-1]['t']-cluster[0]['t']).total_seconds(),
                        'refs': [cluster[0]['ref'], cluster[-1]['ref']]})
            cluster.clear()
        for row in rows:
            if row['type'] == 'job_run':
                finish_cluster()
            else:
                completions = completed_by_job.get(name, [])
                completed_between = bool(cluster) and bisect_right(completions, cluster[-1]['t']) < bisect_left(completions, row['t'])
                if cluster and ((row['t']-cluster[-1]['t']).total_seconds() > max((period or 10)*2, 60) or completed_between):
                    finish_cluster()
                cluster.append(row)
        finish_cluster()
    collection = instant(manifest.get('collected_at'))
    completeness = {f['file_id']: f['completeness'] for f in manifest['files']}
    for d in diagnostics.values():
        d['tail_observation'] = None
        completed = [r for (fid, name), stream in current['streams'].items() if name == d['name']
                     for r in stream['rows'] if r['type'] == 'job_run']
        last = max(completed, key=lambda r:r['t']) if completed else None
        period = (cadence.get(d['name']) or _cadence(current['streams'][(last['ref']['file_id'], d['name'])]['rows'])) if last else None
        if collection and last and period and not d['sequence_records_omitted']:
            end = min(window.bounds()[1], collection)
            seconds = (end-last['t']).total_seconds()
            threshold = max(3*period, period+5)
            if seconds > threshold:
                source_full = all(completeness.get(fid) == 'full' for fid, name in current['streams'] if name == d['name'])
                d['tail_observation'] = {'last_completed': iso(last['t']), 'observed_until': iso(end),
                    'seconds': seconds, 'threshold': threshold, 'basis': 'baseline' if d['name'] in cadence else 'current_observed',
                    'full_sources': source_full, 'ref': last['ref'],
                    'meaning': '입력된 수집시각/조사 종료까지 후속 완료 미관측. 실제 Job 중단/종료 시각은 확정하지 않습니다.'}
        n = d['current']
        if n and (d['gap_count'] or d['running_cluster_count'] or n['delay_count'] or (d['tail_observation'] and d['tail_observation']['full_sources'])):
            d['status'] = 'attention'
        elif n and (d['sequence_records_omitted'] or not n['duration']['samples']):
            d['status'] = 'insufficient'
    warnings = []
    if quality(manifest)['nonfull_files'] or baseline and quality(baseline_manifest)['nonfull_files']:
        warnings.append('부분/완전성 미확인 로그가 포함됩니다. 공백·처리량 비교는 제출 자료 범위에 한정됩니다.')
    if current['omitted_records'] or baseline and baseline['omitted_records']:
        warnings.append('순서 분석 상한 초과: 해당 파일·Job의 공백/반복군 판정을 보류했습니다. 집계값과 표본 제한을 구별하세요.')
    if not baseline:
        warnings.append('정상 기준이 없습니다. 상대 급증 대신 절대 지연 기준과 현재 관측 주기를 사용합니다.')
    collection = instant(manifest.get('collected_at'))
    tails = [{'file_id': fid, 'last_observed': iso(x['t']), 'collected_at': iso(collection),
              'seconds_to_collection': (collection-x['t']).total_seconds() if collection else None,
              'ref': x['ref']} for fid, x in sorted(current['tails'].items())]
    return {'jobs': [diagnostics[n] for n in sorted(diagnostics)], 'window': {'start': iso(window.bounds()[0]), 'end': iso(window.bounds()[1]), 'seconds': window.seconds},
        'baseline_window': {'start': iso(baseline_window.bounds()[0]), 'end': iso(baseline_window.bounds()[1])} if baseline else None,
        'policy': dict(vars(policy)), 'bucket_seconds': current['bucket_seconds'], 'tails': tails,
        'coverage': quality(manifest), 'undated_excluded': current['undated'], 'warnings': warnings,
        'note': NOTE, 'performance_note': '대상 건수/구간초 및 대상 건수/동일 실행시간은 관측 처리율이며 성공 TPS·고유 메시지 수·실제 적체량이 아닙니다.'}


def backlog_observations(items: list[dict], *, comparable: bool = False) -> dict:
    """Validate numeric, user-attested snapshots; never infer queue from log counts."""
    if not isinstance(items, list) or len(items) > 200:
        raise ValueError('대기량 관측값은 최대 200개입니다.')
    points = {}
    for item in items:
        if not isinstance(item, dict) or set(item) != {'at', 'count'}:
            raise ValueError('대기량 관측은 시각과 숫자 건수만 입력하세요.')
        t, count = instant(item['at']), item['count']
        if t is None or type(count) is not int or not 0 <= count <= 1_000_000_000:
            raise ValueError('대기량 시각과 0~10억 정수 건수를 확인하세요.')
        if t in points and points[t] != count:
            raise ValueError('같은 시각에 서로 다른 대기량이 있습니다.')
        points[t] = count
    result = []
    previous = None
    for t, count in sorted(points.items()):
        seconds = (t-previous[0]).total_seconds() if previous else None
        change = count-previous[1] if previous and comparable is True else None
        result.append({'at': iso(t), 'count': count, 'change': change,
                       'net_change_per_second': change/seconds if change is not None and seconds else None})
        previous = t, count
    return {'rows': result, 'latest': result[-1]['count'] if result else None,
            'comparable': comparable is True, 'source': '담당자 입력 · 세션 한정 · DB 자동 조회 없음',
            'note': '동일 서비스·동일 조회 조건을 확인한 관측값만 비교합니다. 순증감은 처리속도·유입률·해소 예정시각이 아닙니다.'}
