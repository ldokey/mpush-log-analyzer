"""Actionable single-Agent view over sanitized events; never deletes evidence."""
from __future__ import annotations
from collections import Counter
from pathlib import Path
import math

from .dashboard_data import events_iter
from .investigation import instant, iso, number, reference, Window
from .error_semantics import describe_error

MAX_GROUPS=300
MAX_ROWS=500
MAX_REFS=40


def classify(event: dict, *, slow_sql_ms: float=1000, slow_job_seconds: float=10) -> str:
    d=event.get('details');d=d if isinstance(d,dict) else {}
    typ=event.get('event_type');complete=event.get('status')=='complete'
    if typ=='log_error':return 'error'
    if typ in {'job_running_skip','job_abnormal_skip'}:return 'skip'
    if typ=='sql_execution':
        ms=number(d.get('laptime_ms'),1e10)
        if d.get('outcome')=='failed':return 'db_failed'
        if not complete:return 'db_incomplete'
        if ms is not None and ms>=slow_sql_ms:return 'db_slow'
        if d.get('sql_operation')=='SELECT' and d.get('outcome')=='select_completed' and ms is not None:
            return 'routine_select'
        return 'db_other'  # writes and unknown row counts are not thrown away
    if typ=='job_run':
        seconds=number(d.get('duration_seconds'),1e9)
        if not complete:return 'job_incomplete'
        if seconds is not None and seconds>=slow_job_seconds:return 'job_slow'
        if d.get('target_count')==0 and type(d.get('target_count')) is int:return 'zero_target_job'
        return 'job_completed'
    if typ=='healthcheck_result' and d.get('target_action')=='no_action':return 'routine_healthcheck'
    if typ in {'agent_exit','agent_started','agent_starting'}:return 'lifecycle'
    if typ=='cns_response' and d.get('response_code')!='S':return 'request_error'
    return 'other'


LABELS={'db_failed':'DB 실행 실패','db_incomplete':'DB 완료 여부 미확인','db_slow':'DB 실행 지연',
        'db_other':'DB 기타 실행','job_incomplete':'Job 요약 불완전','job_slow':'Job 처리시간 증가',
        'job_completed':'작업대상 있는 Job 완료','zero_target_job':'대상 0건 Job 완료',
        'routine_select':'빠른 SELECT 완료','routine_healthcheck':'정상 헬스체크 응답',
        'skip':'Job 실행 건너뜀','lifecycle':'기동·종료 기록','request_error':'요청 오류 응답','other':'기타 기록'}
HIDDEN={'routine_select','zero_target_job','routine_healthcheck','job_completed','other'}


def focus_summary(case: Path, manifest: dict, window: Window | None, *, slow_sql_ms=1000., slow_job_seconds=10.) -> dict:
    for value in (slow_sql_ms,slow_job_seconds):
        if type(value) not in (int,float) or not math.isfinite(value) or value<=0:raise ValueError('양의 지연 기준이 필요합니다.')
    bounds=window.bounds() if window else None;counts=Counter();errors={};rows=[];rows_total=0;omitted_groups=0;legacy=0;undated=0
    for event in events_iter(case,manifest):
        t=instant(event.get('occurred_at'))
        if t is None:
            undated+=1
            if bounds:continue
        if bounds and not bounds[0]<=t<bounds[1]:continue
        cat=classify(event,slow_sql_ms=slow_sql_ms,slow_job_seconds=slow_job_seconds);counts[cat]+=1
        d=event.get('details');d=d if isinstance(d,dict) else {};ref=reference(event)
        if cat=='error':
            semantic=describe_error(d)
            if 'operation_codes' not in d:legacy+=1
            key=(semantic['code'],semantic['operation'],tuple(semantic['ports']),semantic['chain'])
            if key not in errors:
                if len(errors)>=MAX_GROUPS:omitted_groups+=1;continue
                errors[key]={**semantic,'id':f'error_{len(errors)+1}','count':0,'first':iso(t),'last':iso(t),'refs':[]}
            g=errors[key];g['count']+=1;g['first']=min(g['first'],iso(t)) if t and g['first'] else iso(t) or g['first'];g['last']=max(g['last'],iso(t)) if t and g['last'] else iso(t) or g['last']
            if len(g['refs'])<MAX_REFS:g['refs'].append(ref)
        if cat not in HIDDEN and cat!='error':
            rows_total+=1
            if len(rows)<MAX_ROWS:
                name=d.get('job_name')
                from .investigation import job_name
                label=describe_error(d)['title'] if cat=='error' else LABELS.get(cat,'관측 기록')
                if cat=='skip':label='ABNORMAL 상태로 실행 건너뜀' if event['event_type']=='job_abnormal_skip' else 'RUNNING 상태로 실행 건너뜀'
                rows.append({'category':cat,'label':label,'job':job_name(name),
                    'seconds':number(d.get('duration_seconds'),1e9),'milliseconds':number(d.get('laptime_ms'),1e10),
                    'targets':number(d.get('target_count'),1e9),'ref':ref})
    return {'errors':sorted(errors.values(),key=lambda g:(g['classification']!='observed',-g['count'],g['first'] or '')),
        'counts':dict(counts),'error_records':counts['error'],'attention_rows':rows,'attention_total':rows_total,
        'attention_omitted':max(0,rows_total-len(rows)),'groups_omitted':omitted_groups,
        'legacy_error_records':legacy,'undated_excluded':undated,
        'folded_records':sum(counts[c] for c in HIDDEN),'folded_selects':counts['routine_select'],
        'slow_or_failed':sum(counts[c] for c in ['db_failed','db_slow','job_slow','job_incomplete','db_incomplete']),
        'thresholds':{'sql_ms':slow_sql_ms,'job_seconds':slow_job_seconds},
        'note':'빠른 정상 SELECT를 기본 목록에서 접습니다. select completed만으로 반환행 0건을 판단하지 않습니다. 원본과 전체 이벤트는 보존됩니다.'}
