"""Diagnose empty input and build an explicit, disposable local reparse view.

Existing raw files, manifests, inquiries, reports and event snapshots are never
changed. A manual date applies only to files without any saved date authority.
"""
from __future__ import annotations

from collections import Counter
import copy
from datetime import date, time, timedelta
from pathlib import Path
import tempfile

from .dashboard_data import events_iter
from .intake import detect_text_encoding
from .investigation import Window, instant, iso, job_name, number
from .parsers import parse_by_kind
from .parsers.common import ClockResolver
from .permissions import private_path
from .pipeline import (_get_manifest, _safe_source, _read_numbered, _sort_key,
                       _write_jsonlines, _merged_chunks, CHUNK_SIZE, PARSER_REVISION)
from .time_utils import job_time_fields

LOG_KINDS = {'job', 'debug', 'info', 'err', 'dbwrap'}


def inspect_input(case: Path, manifest: dict, window: Window | None = None) -> dict:
    """Bounded, structural provenance only. No raw log or customer identifier."""
    bounds = window.bounds() if window else None
    files = {f['file_id']: {'file_id': f['file_id'], 'kind': f['kind'],
        'size_bytes': f['size_bytes'], 'lines': f['line_count'],
        'date': f.get('date_hint') or manifest.get('reference_date'),
        'encoding': f['encoding'], 'records': 0, 'dated': 0, 'undated': 0,
        'jobs': 0, 'jobs_in_window': 0, 'complete_jobs': 0,
        'first': None, 'last': None} for f in manifest['files']}
    counts = Counter()
    read_error = None
    try:
        for event in events_iter(case, manifest):
            row = files[event['file_id']]
            row['records'] += 1
            counts['records'] += 1
            t = instant(event.get('occurred_at'))
            d = event.get('details')
            is_job = event.get('event_type') == 'job_run' and isinstance(d, dict) and job_name(d.get('job_name'))
            row['jobs'] += bool(is_job)
            counts['jobs'] += bool(is_job)
            if t is None:
                row['undated'] += 1
                counts['undated'] += 1
                continue
            row['dated'] += 1
            counts['dated'] += 1
            stamp = iso(t)
            row['first'] = min(row['first'], stamp) if row['first'] else stamp
            row['last'] = max(row['last'], stamp) if row['last'] else stamp
            inside = bounds is None or bounds[0] <= t < bounds[1]
            if inside:
                counts['in_window'] += 1
                if is_job:
                    row['jobs_in_window'] += 1
                    counts['jobs_in_window'] += 1
                    if event.get('status') == 'complete':
                        row['complete_jobs'] += 1
                        counts['complete_jobs'] += 1
    except (ValueError, OSError, TypeError, KeyError):
        # Do not expose malformed raw JSON or internal paths in diagnostics.
        read_error = '저장된 이벤트를 읽을 수 없습니다. 원본 재해석으로 확인하세요.'
    hints = []
    for f in manifest['files']:
        if f['kind'] not in LOG_KINDS or not f['size_bytes']:
            continue
        anchor = f.get('date_hint') or manifest.get('reference_date')
        if not anchor:
            continue
        start = instant(anchor+'T00:00:00')
        if start is None:
            continue
        end = start + timedelta(days=1)
        try:
            first = time.fromisoformat(f.get('first_time_hint') or '')
            last = time.fromisoformat(f.get('last_time_hint') or '')
            lo = start.replace(hour=first.hour, minute=first.minute, second=first.second, microsecond=first.microsecond)
            hi = start.replace(hour=last.hour, minute=last.minute, second=last.second, microsecond=last.microsecond)
            if hi < lo:
                if first.hour >= 20 and last.hour <= 4:
                    hi += timedelta(days=1)
                else:
                    lo, hi = start, end-timedelta(seconds=1)
            start, end = lo, hi+timedelta(seconds=1)
        except ValueError:
            pass
        hints.extend([start, end])
    for row in files.values():
        if row['first']:
            hints.extend([instant(row['first']), instant(row['last'])+timedelta(seconds=1)])
    default = {'start': '', 'end': '', 'capped': False}
    if hints:
        lo = min(hints).replace(second=0, microsecond=0)
        hi = max(hints)
        capped = hi-lo > timedelta(days=31)
        if capped:
            lo = hi-timedelta(days=31)
        default = {'start': iso(lo), 'end': iso(hi), 'capped': capped}
    reasons = []
    if read_error:
        reasons.append({'code': 'snapshot_unreadable', 'message': read_error})
    if not any(f['kind'] == 'job' and f['size_bytes'] for f in manifest['files']):
        reasons.append({'code': 'no_job_file', 'message': 'Job 요약 로그가 없습니다. debug/결과 로그만으로 Job 처리량을 만들지 않습니다.'})
    if counts['records'] == 0:
        reasons.append({'code': 'no_parsed_events', 'message': '파일은 등록됐지만 저장된 인식 이벤트는 0건입니다. Job 자료라면 원본 재해석을 실행하세요. 메시지 전용 로그는 메시지 결과 추적에서 별도 원본 조회가 가능합니다.'})
    elif counts['undated']:
        reasons.append({'code': 'undated_events', 'message': f"날짜가 없는 이벤트 {counts['undated']:,}건은 시간 구간 집계에서 제외됩니다. 조회 시작일 입력만으로는 날짜가 부여되지 않습니다."})
    if counts['jobs'] and not counts['jobs_in_window'] and bounds:
        reasons.append({'code': 'jobs_outside_window', 'message': f"저장된 Job {counts['jobs']:,}건 중 현재 조회 구간에 포함된 날짜 있는 Job은 0건입니다. 로그 범위로 맞추기 또는 날짜 기준을 확인하세요."})
    if counts['records'] and not counts['jobs']:
        reasons.append({'code': 'no_job_events', 'message': '인식 이벤트는 있으나 Job 실행 요약은 없습니다. 메시지 로그는 별도 원본 조회로 확인할 수 있습니다.'})
    if counts['jobs_in_window'] and not counts['complete_jobs']:
        reasons.append({'code': 'incomplete_jobs', 'message': 'Job 기록은 있지만 대상·소요시간을 갖춘 완료 요약이 없습니다. 불완전 기록을 성공 처리량 0으로 해석하지 마세요.'})
    if default['capped']:
        reasons.append({'code': 'range_capped', 'message': '제공 자료가 31일을 넘어 최근 31일을 기본 조회합니다. 이전 날짜는 구간을 직접 지정하세요.'})
    return {'files': list(files.values()), 'counts': dict(counts), 'default_window': default,
            'reasons': reasons, 'read_error': read_error, 'parser_revision': PARSER_REVISION}


class DiagnosticView:
    """Own a private temporary event stream until session replacement/cleanup."""
    def __init__(self, temporary, event_case: Path, manifest: dict, encoding_changes: list):
        self.temporary = temporary
        self.event_case = event_case
        self.manifest = manifest
        self.encoding_changes = encoding_changes
        self.parser_revision = PARSER_REVISION

    def close(self) -> None:
        self.temporary.cleanup()


def _file_encoding(path: Path) -> str:
    def chunks():
        with path.open('rb') as stream:
            while chunk := stream.read(131072):
                yield chunk
    return detect_text_encoding(chunks)


def reparse_view(case: Path, *, anchor_date: date | None = None,
                 date_confirmed: bool = False) -> DiagnosticView:
    """Manual local read; never save corrected dates/encodings to the original."""
    source_manifest = _get_manifest(case)
    manifest = copy.deepcopy(source_manifest)
    if anchor_date is not None:
        if type(anchor_date) is not date or date_confirmed is not True:
            raise ValueError('날짜 없는 로그의 실제 기준 날짜를 확인해야 합니다.')
        if source_manifest.get('reference_date'):
            raise ValueError('기존 기준 날짜를 덮어쓰지 않습니다. 날짜 보정이 필요하면 자료를 새로 가져오세요.')
        manifest['reference_date'] = anchor_date.isoformat()
    temp = tempfile.TemporaryDirectory(prefix='mpush-diagnostic-view-')
    root = Path(temp.name)
    private_path(root, directory=True)
    target = root/source_manifest['analysis_id']
    target.mkdir()
    private_path(target, directory=True)
    changes, chunks, batch = [], [], []
    try:
        def flush():
            if batch:
                batch.sort(key=_sort_key)
                path = target/f'chunk_{len(chunks):05d}.jsonl'
                _write_jsonlines(path, batch)
                chunks.append(path)
                batch.clear()
        for original, source in zip(source_manifest['files'], manifest['files']):
            if source['kind'] not in LOG_KINDS:
                continue
            origin = _safe_source(case, original)
            actual = _file_encoding(origin)
            if actual != source['encoding']:
                changes.append({'file_id': source['file_id'], 'before': source['encoding'], 'after': actual})
                source['encoding'] = actual
            codec = 'utf-8' if actual == 'utf-8-replace' else actual
            day = source.get('date_hint') or manifest.get('reference_date')
            resolver = ClockResolver(date.fromisoformat(day) if day else None)
            stats = {'lines_read': 0, 'decode_replacement_lines': 0, 'oversized_lines': 0}
            for raw in parse_by_kind(source['kind'], _read_numbered(origin, codec, stats)):
                occurred, quality = resolver.normalize(raw.clock)
                details = dict(raw.data)
                if raw.kind == 'job_run':
                    details.update(job_time_fields(occurred, raw.data))
                batch.append({'schema_version': '1.0', 'event_id': f"{source['file_id']}_{raw.start_line:09d}",
                    'file_id': source['file_id'], 'log_kind': source['kind'], 'line_start': raw.start_line,
                    'line_end': raw.end_line, 'clock': raw.clock, 'occurred_at': occurred,
                    'time_quality': quality, 'time_date_source': 'filename_hint' if source.get('date_hint') else 'reference_date' if day else 'unknown',
                    'event_type': raw.kind, 'status': raw.status, 'details': details})
                if len(batch) >= CHUNK_SIZE:
                    flush()
            _safe_source(case, original)
        flush()
        merged = _merged_chunks(chunks, target)
        merged.replace(target/'events.jsonl')
        return DiagnosticView(temp, target, manifest, changes)
    except Exception:
        temp.cleanup()
        raise
