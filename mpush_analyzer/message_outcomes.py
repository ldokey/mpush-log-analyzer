"""Explicit message outcomes, distinct from request acceptance and stage markers.

Only the documented SEND_RESULT_CODE1/2 fields in result-received records are
interpreted. SQL literals, arbitrary bodies, missing identity and unknown codes
never become a delivery success. Original and fallback legs stay independent.
"""
from __future__ import annotations

from collections import Counter
from datetime import date
from pathlib import Path
import re
import secrets

from .investigation import Window, instant, iso, quality
from .message_trace import fields, raw_records, stage_codes, _alias, VALID_ID
from .parsers.common import ClockResolver
from .pipeline import _get_manifest, _safe_source

MAX_MESSAGES = 5000
MAX_EVENTS = 20000
MAX_MESSAGE_EVIDENCE = 50
RESULT_FIELDS = re.compile(r'''(?<![A-Za-z0-9_])['"]?(SEND_RESULT_CODE1|SEND_RESULT_CODE2|BACKUP_PROCESS_CODE)['"]?\s*[:=]\s*(?:['"]([^'"\r\n]{0,64})['"]|([A-Za-z0-9_-]{1,64})(?=$|[\s,;)}\]]))''', re.I)
BODY_FIELD = re.compile(r'''\b(?:SEND_MESSAGE|BACKUP_MESSAGE|MESSAGE_BODY|MESSAGE_TEXT|MESSAGE|CONTENT|BODY|TEXT|SUBJECT|SQL_TEXT|QUERY_TEXT)\b\s*['"]?\s*[:=]''', re.I)
RESULT_MARKER = re.compile(r'결과\s*수신(?:\s*완료)?|수신(?:한|된)\s*결과|서버에서\s*받은\s*결과|\bresult(?:\s+data)?\s+received\b|\breceived\s+(?:delivery\s+)?result\b', re.I)
SQL_MARKER = re.compile(r'\b(?:SELECT|UPDATE|INSERT|DELETE|MERGE|WHERE|PSTMT)\b', re.I)
SAFE_RESULT_CODE = re.compile(r'(?:OK|FAIL|ERROR|[A-Z]{0,3}[0-9]{1,8})\Z')
PENDING = {'', '-', 'NULL', 'NONE', 'UNKNOWN', 'PENDING', 'WAIT', 'N/A'}
STAGE_LABELS = {'claim': 'DB 선점', 'file': '파일 생성', 'tcp': 'TCP 전송',
                'accepted': '요청 수락', 'result': '결과 수신', 'db_transfer': 'DB 이관'}
STATUS_LABELS = {
    'original_success': '원 발송 성공', 'fallback_success': '문자 대체 성공',
    'final_failure': '최종 실패 관측', 'original_failure_unresolved': '원 발송 실패·대체 미확인',
    'accepted_unresolved': '요청 수락·결과 미확인', 'stage_failure_unresolved': '단계 실패·최종 미확인',
    'conflict': '결과 충돌·검토 필요', 'unknown': '결과 미확인',
}
OP_MARKERS = {
    'claim': r'선점|claim(?:ed)?\s+message',
    'file': r'파일\s*생성|file\s+(?:creat(?:ed|ion)|generation)',
    'tcp': r'파일\s*전송|tcp\s+(?:send|sent)',
    'accepted': r'요청\s*수락|accepted',
    'result': r'결과\s*수신|result\s+(?:data\s+)?received',
    'db_transfer': r'(?:로그\s*테이블|결과)\s*이관|db\s+transfer',
}


def _result_fields(text: str) -> tuple[dict[str, set[str]], set[str]]:
    values: dict[str, set[str]] = {}
    unknown, matched = set(), set()
    for m in RESULT_FIELDS.finditer(text):
        key = m.group(1).upper()
        matched.add(key)
        raw = (m.group(2) if m.group(2) is not None else m.group(3)).strip().upper()
        if raw in PENDING:
            continue
        if key == 'BACKUP_PROCESS_CODE':
            if raw in {'000', '001', '003'}:
                values.setdefault(key, set()).add(raw)
            else:
                unknown.add(key)
        elif SAFE_RESULT_CODE.fullmatch(raw):
            bucket = values.setdefault(key, set())
            if len(bucket) < 12:
                bucket.add(raw)
            elif raw not in bucket:
                unknown.add(key)
        else:
            unknown.add(key)
    for key in ('SEND_RESULT_CODE1', 'SEND_RESULT_CODE2', 'BACKUP_PROCESS_CODE'):
        if re.search(r'\b'+key+r'\b', text, re.I) and key not in matched:
            unknown.add(key)
    return values, unknown


def _received(text: str) -> bool:
    incomplete = re.search(r'(?:결과\s*수신|result(?:\s+data)?\s+received)\s*(?:실패|오류|불가|시작|예정|대기|요청|중|failed|failure|pending|start)', text, re.I)
    negated = re.search(r'(?:no|not|never)\s+(?:delivery\s+)?result(?:\s+data)?\s+received|result(?:\s+data)?\s+(?:not|never)\s+received', text, re.I)
    return bool(RESULT_MARKER.search(text)) and not incomplete and not negated


def _leg(codes: set[str], unknown: bool) -> dict:
    if len(codes) > 1:
        state = 'conflict'
    elif unknown:
        state = 'unknown'
    elif codes == {'OK'}:
        state = 'success'
    elif codes:
        state = 'failure'
    else:
        state = 'unobserved'
    return {'state': state, 'codes': sorted(codes),
            'meaning': 'OK=성공; 유효 비OK=실패 관측. 상세 실패 사유는 별도 코드 명세 확인.'}


def _operation_states(text: str, values: dict, sql: bool) -> dict:
    if sql:
        return {}
    stages = set(stage_codes(text, values))
    if RESULT_MARKER.search(text):
        stages.add('result')
    result = {}
    for stage, marker in OP_MARKERS.items():
        if stage not in stages and not re.search(marker, text, re.I):
            continue
        failed = bool(re.search(r'(?:'+marker+r')[^\n]{0,24}(?:실패|failed|failure|오류|not\s+complete)', text, re.I))
        done = bool(re.search(r'(?:'+marker+r')\s*(?:완료|성공|complete(?:d)?|success(?:ful)?)\b', text, re.I))
        if stage == 'file' and re.search(r'\bfile\s+created\b', text, re.I):
            done = True
        if stage == 'result':
            done = _received(text)
        if stage == 'accepted':
            done = values.get('RESPONSE_CODE') == 'S' and not bool(re.search(r'not\s+accepted|수락\s*(?:실패|거절)|요청\s*실패', text, re.I))
        result[stage] = 'failed' if failed else 'completed' if done else 'marker'
    return result


def trace_outcomes(case: Path, window: Window, *, message: str = '', service: str = '',
                   salt: bytes | None = None, limit: int = MAX_EVENTS,
                   anchor_date: date | None = None, date_confirmed: bool = False,
                   redetect_encoding: bool = False) -> dict:
    if type(limit) is not int or not 1 <= limit <= MAX_EVENTS:
        raise ValueError('결과 추적 표시 상한을 확인하세요.')
    if not isinstance(message, str) or message and not VALID_ID.fullmatch(message):
        raise ValueError('메시지 식별값 형식을 확인하세요.')
    if not isinstance(service, str) or service and not VALID_ID.fullmatch(service):
        raise ValueError('서비스 식별값 형식을 확인하세요.')
    salt = secrets.token_bytes(32) if salt is None else salt
    if not isinstance(salt, bytes) or len(salt) != 32:
        raise ValueError('추적 가명화 키 형식을 확인하세요.')
    manifest = _get_manifest(case)
    if anchor_date is not None:
        if type(anchor_date) is not date or date_confirmed is not True or manifest.get('reference_date'):
            raise ValueError('날짜 없는 로그에 적용할 기준 날짜 확인이 필요합니다.')
        manifest['reference_date'] = anchor_date.isoformat()
    if type(redetect_encoding) is not bool:
        raise ValueError('인코딩 재확인 옵션이 올바르지 않습니다.')
    bounds = window.bounds()
    groups, events = {}, []
    evidence_count = 0
    stats = Counter()
    for f in manifest['files']:
        if f['kind'] not in {'job', 'info', 'err', 'debug', 'dbwrap'}:
            continue
        path = _safe_source(case, f)
        encoding = f['encoding']
        if redetect_encoding:
            from .diagnostics_input import _file_encoding
            encoding = _file_encoding(path)
        codec = 'utf-8' if encoding == 'utf-8-replace' else encoding
        hint = f.get('date_hint') or manifest.get('reference_date')
        resolver = ClockResolver(date.fromisoformat(hint) if hint else None)
        for block, clock, truncated in raw_records(path, codec):
            stats['total_records'] += 1
            occurred, _ = resolver.normalize(clock)
            point = instant(occurred)
            if point is None:
                stats['undated_records'] += 1
                continue
            stats['dated_records'] += 1
            if not bounds[0] <= point < bounds[1]:
                stats['outside_window_records'] += 1
                continue
            stats['scanned_records'] += 1
            text = '\n'.join(line for _, line in block)
            if 'MESSAGE_SEQNO' not in text.upper():
                continue
            stats['candidate_records'] += 1
            if truncated:
                stats['oversized_records'] += 1
                continue
            vals, ambiguous = fields(text)
            if ambiguous or BODY_FIELD.search(text) or len(set(re.findall(r'\bNO_ID_(-?\d+)=', text))) > 1:
                stats['ambiguous_or_payload_records'] += 1
                continue
            msg, svc = vals.get('MESSAGE_SEQNO'), vals.get('SERVICE_SEQNO')
            if not msg or not svc:
                stats['missing_identity_records'] += 1
                continue
            if message and msg != message or service and svc != service:
                stats['search_excluded_records'] += 1
                continue
            key = _alias(salt, 'message', svc+'\0'+msg)
            if key not in groups:
                if len(groups) >= MAX_MESSAGES:
                    stats['message_limit_records'] += 1
                    continue
                groups[key] = {'message': key, 'service': _alias(salt, 'service', svc),
                    'records': 0, 'first': iso(point), 'last': iso(point), 'primary_codes': set(),
                    'fallback_codes': set(), 'backup_policies': set(), 'result_unknown': False,
                    'primary_unknown': False, 'fallback_unknown': False, 'policy_unknown': False,
                    'result_observations': 0, 'stage_states': {s:set() for s in STAGE_LABELS},
                    'request_times': [], 'result_times': [], 'request_count': 0, 'result_count': 0,
                    'evidence': [], 'event_indexes': [], 'job_types': set(), 'code_limit': False}
            g = groups[key]
            g['records'] += 1
            g['first'], g['last'] = min(g['first'], iso(point)), max(g['last'], iso(point))
            sql = f['kind'] == 'dbwrap' or bool(SQL_MARKER.search(text))
            operations = _operation_states(text, vals, sql)
            codes, unknown = _result_fields(text)
            received = not sql and _received(text)
            if sql:
                stats['sql_predicate_records'] += 1
            else:
                g['backup_policies'].update(codes.get('BACKUP_PROCESS_CODE', set()))
                g['policy_unknown'] |= 'BACKUP_PROCESS_CODE' in unknown
            if received:
                g['result_observations'] += 1
                g['result_unknown'] |= bool(unknown)
                g['primary_unknown'] |= 'SEND_RESULT_CODE1' in unknown
                g['fallback_unknown'] |= 'SEND_RESULT_CODE2' in unknown
                for name, field in [('primary_codes', 'SEND_RESULT_CODE1'), ('fallback_codes', 'SEND_RESULT_CODE2')]:
                    for code in codes.get(field, set()):
                        if len(g[name]) < 12:
                            g[name].add(code)
                        elif code not in g[name]:
                            g['code_limit'] = True
            for stage, state in operations.items():
                g['stage_states'][stage].add(state)
            stages = set(stage_codes(text, vals)) if not sql else set()
            if 'request' in stages:
                g['request_count'] += 1
                if len(g['request_times']) < 2:
                    g['request_times'].append(iso(point))
            if received:
                g['result_count'] += 1
                if len(g['result_times']) < 2:
                    g['result_times'].append(iso(point))
            job_type = vals.get('JOB_TYPE') if vals.get('JOB_TYPE') in {'R00', 'B00'} else 'unknown'
            g['job_types'].add(job_type)
            ref = {'file_id': f['file_id'], 'line_start': block[0][0], 'line_end': block[-1][0], 'occurred_at': iso(point)}
            if len(g['evidence']) < MAX_MESSAGE_EVIDENCE and evidence_count < MAX_EVENTS:
                evidence_count += 1
                g['evidence'].append(ref)
            if len(events) < limit:
                g['event_indexes'].append(len(events))
                events.append({'message': key, 'service': g['service'], 'job_type': job_type,
                    'stages': operations,
                    'primary_codes': sorted(codes.get('SEND_RESULT_CODE1', set())) if received else [],
                    'fallback_codes': sorted(codes.get('SEND_RESULT_CODE2', set())) if received else [],
                    'basis': 'sql_excluded' if sql else 'result_received' if received else 'stage_marker', 'ref': ref})
            else:
                stats['event_details_omitted'] += 1
        _safe_source(case, f)  # Detect a source changed during the scan.
    output = []
    totals = Counter()
    for g in groups.values():
        # Unknown fields do not erase an independent, explicit outcome on the other leg.
        primary = _leg(g.pop('primary_codes'), g['primary_unknown'])
        fallback = _leg(g.pop('fallback_codes'), g['fallback_unknown'])
        if g['code_limit'] or primary['state'] == 'conflict' or fallback['state'] == 'conflict' or len(g['backup_policies']) > 1:
            status = 'conflict'
        elif primary['state'] == 'success':
            status = 'original_success'
        elif fallback['state'] == 'success':
            status = 'fallback_success'
        elif primary['state'] == 'failure' and (fallback['state'] == 'failure' or (g['backup_policies'] == {'003'} and not g['policy_unknown'] and fallback['state'] == 'unobserved')):
            status = 'final_failure'
        elif primary['state'] == 'failure':
            status = 'original_failure_unresolved'
        elif 'completed' in g['stage_states']['accepted']:
            status = 'accepted_unresolved'
        elif any('failed' in states for states in g['stage_states'].values()):
            status = 'stage_failure_unresolved'
        else:
            status = 'unknown'
        stages = {}
        for stage, states in g.pop('stage_states').items():
            stages[stage] = ('mixed' if 'failed' in states and 'completed' in states else
                             'failed' if 'failed' in states else 'completed' if 'completed' in states else
                             'marker' if states else 'unobserved')
        elapsed = None
        if g['request_count'] == g['result_count'] == 1:
            elapsed = (instant(g['result_times'][0])-instant(g['request_times'][0])).total_seconds()
            if elapsed < 0:
                elapsed = None
        g.pop('request_times'); g.pop('result_times')
        g['backup_policies'] = sorted(g['backup_policies'])
        g['job_types'] = sorted(g['job_types'])
        g.update({'primary': primary, 'fallback': fallback, 'status': status, 'status_label': STATUS_LABELS[status],
            'stages': stages, 'request_to_result_seconds': elapsed,
            'evidence_omitted': g['records']-len(g['evidence']),
            'final_delivery_confirmed': status in {'original_success', 'fallback_success'}})
        totals[status] += 1
        output.append(g)
    success = totals['original_success']+totals['fallback_success']
    denominator = success+totals['final_failure']
    return {'groups': sorted(output, key=lambda g:(g['first'], g['message'])), 'events': events,
        'summary': {'unique_messages': len(output), 'success': success, 'failure': totals['final_failure'],
            'conflict': totals['conflict'], 'unresolved': len(output)-success-totals['final_failure']-totals['conflict'],
            'classifiable_messages': denominator, 'observed_success_percent': 100*success/denominator if denominator else None,
            'by_status': dict(totals)}, 'coverage': dict(stats), 'source_quality': quality(manifest),
        'window': {'start': iso(bounds[0]), 'end': iso(bounds[1])},
        'population_limited': bool(stats['message_limit_records']),
        'empty_reasons': ([] if output else [
            '조회는 완료됐지만 연결 가능한 메시지는 0건입니다. 아래 제외 건수를 확인하세요.',
            f"전체 레코드 {stats['total_records']:,}건 / 날짜 없음 {stats['undated_records']:,}건 / 구간 밖 {stats['outside_window_records']:,}건 / 식별 후보 {stats['candidate_records']:,}건 / 검색 조건 제외 {stats['search_excluded_records']:,}건",
            '조회 구간·날짜·식별값이 같은 레코드에 있는지 확인하세요. 결과 미관측은 실패 0건이나 성공 0건을 확정하지 않습니다.']),
        'note': '명시적인 결과 수신의 SEND_RESULT_CODE1/2만 판정합니다. OK=성공이며 요청 수락 S·SEND_FLAG·SQL 조건값은 최종 결과가 아닙니다. '
                '원 발송과 대체 결과를 분리하며 성공률은 판정 가능한 고유 메시지의 관측 비율입니다. 미관측은 실패가 아닙니다.'}
