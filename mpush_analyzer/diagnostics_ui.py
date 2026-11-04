"""Stitch-derived desktop component integrated into the existing Streamlit app.

Private local labels are passed separately and never enter the export payload.
The browser can request only server-selected evidence, not arbitrary file paths.
"""
from __future__ import annotations

import copy
from datetime import date, timedelta
import hashlib
import json
from pathlib import Path
import re
import secrets
from typing import Any

import streamlit as st
import streamlit.components.v1 as components

from .diagnostics import DiagnosticPolicy, diagnose_jobs, backlog_observations
from .investigation import Window, instant, iso, population
from .message_outcomes import trace_outcomes
from .pipeline import _get_manifest, PARSER_REVISION
from .diagnostics_input import inspect_input, reparse_view
from .support_store import ui_file_label, case_title

WEB_ROOT = Path(__file__).with_name('diagnostics_web')
_component = components.declare_component('mpush_diagnostics_v43', path=str(WEB_ROOT))
MAX_REFERENCES = 20_000


def source_signature(case: Path, manifest: dict) -> str:
    """Invalidate session views on manifest, event or raw-file metadata changes.

Actual raw scans and evidence reads additionally perform the existing SHA check.
"""
    paths = [case/'manifest.json', case/'events.jsonl', case/'analysis_result.json']
    raw = case/'raw'
    if raw.is_symlink():
        raise ValueError('원본 폴더 링크는 허용되지 않습니다.')
    if raw.is_dir():
        paths += sorted(raw.iterdir())
    stat = []
    for path in paths:
        if path.is_symlink():
            raise ValueError('분석 자료 링크는 허용되지 않습니다.')
        if not path.exists():
            stat.append([path.name, None, None])
            continue
        s = path.stat()
        stat.append([path.name, s.st_size, s.st_mtime_ns])
    return hashlib.sha256(json.dumps([PARSER_REVISION, str(case.resolve()), manifest, stat], sort_keys=True).encode()).hexdigest()


def make_payload(jobs: dict, messages: dict | None, backlog: dict) -> dict:
    data = copy.deepcopy({'jobs': jobs, 'messages': messages, 'backlog': backlog})
    # Baseline evidence belongs to another analysis; do not relabel it as current.
    for job in data['jobs'].get('jobs', []):
        before = job.get('baseline')
        if before:
            before.pop('evidence', None)
            before.pop('delays', None)
    references, seen = [], set()
    def add(ref: Any) -> None:
        if not isinstance(ref, dict):
            return
        values = ref.get('file_id'), ref.get('line_start'), ref.get('line_end'), ref.get('occurred_at')
        if (values not in seen and len(references) < MAX_REFERENCES and isinstance(values[0], str)
                and type(values[1]) is int and type(values[2]) is int and 1 <= values[1] <= values[2]):
            references.append({k:ref.get(k) for k in ('file_id', 'line_start', 'line_end', 'occurred_at')})
            seen.add(values)
    for j in data['jobs'].get('jobs', []):
        c = j.get('current') or {}
        for x in c.get('delays', []): add(x['ref'])
        for x in j.get('gaps', []): add(x['before_ref']); add(x['after_ref'])
        for x in j.get('running_clusters', []):
            for ref in x['refs']: add(ref)
        if j.get('tail_observation'): add(j['tail_observation']['ref'])
        for ref in c.get('evidence', []): add(ref)
    if messages:
        for g in messages['groups']:
            for ref in g['evidence']: add(ref)
    data['references'] = references
    data['revision'] = hashlib.sha256(json.dumps(data,sort_keys=True,allow_nan=False).encode()).hexdigest()[:24]
    return data


def validate_action(value: Any, payload: dict) -> dict | None:
    if value is None:
        return None
    if not isinstance(value, dict) or value.get('revision') != payload['revision']:
        raise ValueError('화면 자료가 변경되었습니다. 최신 결과에서 다시 선택하세요.')
    if not isinstance(value.get('nonce'), str) or not re.fullmatch(r'[0-9a-f-]{36}', value['nonce']):
        raise ValueError('화면 요청 형식이 올바르지 않습니다.')
    kind = value.get('action')
    if kind in {'configure', 'configure_messages'}:
        return {'action': kind, 'nonce': value['nonce']}
    if kind == 'evidence':
        index = value.get('index')
        if type(index) is not int or not 0 <= index < len(payload['references']):
            raise ValueError('서버가 제공한 근거만 조회할 수 있습니다.')
        return {'action': kind, 'nonce': value['nonce'], 'ref': payload['references'][index]}
    if kind == 'backlog':
        if type(value.get('comparable')) is not bool:
            raise ValueError('대기량 비교 조건을 확인하세요.')
        row = {'at': value.get('at'), 'count': value.get('count')}
        backlog_observations([row])
        return {'action': kind, 'nonce': value['nonce'], 'row': row, 'comparable': value['comparable']}
    raise ValueError('허용되지 않은 화면 동작입니다.')


def _defaults(case: Path, manifest: dict) -> tuple[str, str]:
    window = inspect_input(case, manifest)['default_window']
    return window['start'], window['end']


def _clear_window_state(prefix: str) -> None:
    # Called before condition widgets are instantiated in the current run.
    for suffix in ('_config', '_lo', '_hi', '_base', '_base_lo', '_base_hi', '_confirmed'):
        st.session_state.pop(prefix+suffix, None)
    st.session_state.pop('_v43_job_cache', None)
    st.session_state.pop('_v43_trace_cache', None)


def render_diagnostics(case: Path, manifest: dict, result: dict) -> None:
    prefix = 'v43_'+case.name
    try:
        original_signature = source_signature(case, manifest)
    except (ValueError, OSError):
        st.error('원본 자료 경로를 안전하게 확인할 수 없습니다. 원본 폴더·파일과 접근 권한을 확인하세요.')
        return
    cached_view = st.session_state.get('_v43_recovery_view')
    if cached_view and cached_view[0] != original_signature:
        cached_view[1].close()
        st.session_state.pop('_v43_recovery_view', None)
        cached_view = None
    view = cached_view[1] if cached_view else None
    event_case, effective = (view.event_case, view.manifest) if view else (case, manifest)
    signature = hashlib.sha256(json.dumps([original_signature, effective, bool(view)], sort_keys=True).encode()).hexdigest()
    cached_profile = st.session_state.get('_v43_input_profile')
    if not cached_profile or cached_profile[0] != signature:
        profile = inspect_input(event_case, effective)
        st.session_state['_v43_input_profile'] = (signature, profile)
    else:
        profile = cached_profile[1]
    old_snapshot = not view and result.get('metrics', {}).get('parser_revision') != PARSER_REVISION
    st.caption('V4.3.1 입력 보정본 · Stitch 데스크톱 · 원본·기존 분석·문의 데이터 보존')
    with st.expander('자료 인식 상태 · 원본 재해석', expanded=old_snapshot or not profile['counts'].get('jobs') or bool(profile['counts'].get('undated'))):
        st.caption(f"등록 파일 {len(manifest['files'])}개 / 인식 이벤트 {profile['counts'].get('records',0):,}건 / Job {profile['counts'].get('jobs',0):,}건 / 날짜 없는 이벤트 {profile['counts'].get('undated',0):,}건")
        st.dataframe([{'파일':ui_file_label(case,f['file_id'],manifest), '유형':f['kind'], '줄 수':f['lines'],
            '인식 이벤트':f['records'], 'Job':f['jobs'], '날짜 없는 이벤트':f['undated'],
            '기준 날짜':f['date'] or '미지정', '인코딩':f['encoding'],
            '인식 시작':f['first'] or '미확인', '인식 끝':f['last'] or '미확인'} for f in profile['files']], hide_index=True, use_container_width=True)
        if old_snapshot:
            st.info('이전에 저장된 판독 결과입니다. 코드 업데이트만으로 기존 이벤트 파일이 다시 만들어지지는 않습니다. 값이 빠졌다면 원본 재해석을 실행하세요.')
        for reason in profile['reasons']:
            st.warning(reason['message'])
        anchor = st.date_input('날짜 없는 로그의 기준 날짜 (선택)', value=None, key=prefix+'_anchor_date')
        date_confirmed = st.checkbox('선택한 날짜가 날짜 없는 로그의 실제 발생 기준일임을 확인했습니다.', key=prefix+'_anchor_confirmed')
        st.caption('조회 시작/종료 날짜는 필터입니다. 날짜가 빠진 로그에 날짜를 부여하려면 위 기준 날짜를 확인하고 원본 재해석을 실행하세요. 파일명에 저장된 날짜는 덮어쓰지 않습니다.')
        if st.button('원본 재해석 (기존 분석 보존)', key=prefix+'_reparse', type='primary'):
            try:
                with st.spinner('원본 해시 검증 · 현재 판독기로 임시 분석 생성 중...'):
                    fresh = reparse_view(case, anchor_date=anchor, date_confirmed=date_confirmed)
                if view:
                    view.close()
                st.session_state['_v43_recovery_view'] = (original_signature, fresh)
                _clear_window_state(prefix)
                st.rerun()
            except (ValueError, OSError):
                st.error('재해석하지 못했습니다. 날짜 확인 체크, 원본 파일 무결성·권한을 확인하세요. 기존 분석은 변경하지 않았습니다.')
        if profile['default_window']['start'] and st.button('로그 범위로 맞추기', key=prefix+'_fit_range'):
            _clear_window_state(prefix)
            st.rerun()
        if view:
            st.success('현재 화면은 원본을 다시 읽은 임시 분석입니다. 기존 저장 결과와 원본은 변경하지 않았습니다.')
            if view.encoding_changes:
                st.caption('인코딩 재확인: '+', '.join(f"{x['file_id']} {x['before']} → {x['after']}" for x in view.encoding_changes))
    initial = st.session_state.get(prefix+'_config')
    if initial is None:
        w = profile['default_window']
        initial = {'lo': w['start'], 'hi': w['end'], 'base': None, 'base_lo': '', 'base_hi': '',
                   'confirmed': False, 'ratio': 3.0, 'minimum': 10.0, 'repeat': 3, 'bucket': 60}
    else:
        initial = dict(initial)
    from .lifecycle import list_cases
    available = list_cases(case.parent)
    if case not in available:
        available.insert(0, case)
    with st.expander('조사 조건 · 정상 기준 비교', expanded=st.session_state.get(prefix+'_open_config', not bool(initial['lo']))):
        with st.form(prefix+'_conditions'):
            a,b=st.columns(2)
            lo=a.text_input('조사 시작 (KST, 포함)', value=initial['lo'], key=prefix+'_lo')
            hi=b.text_input('조사 종료 (KST, 미포함)', value=initial['hi'], key=prefix+'_hi')
            options=[None]+available
            selected_base=Path(initial['base']) if initial.get('base') else None
            base=st.selectbox('정상 기준 분석 (선택)', options,
                index=options.index(selected_base) if selected_base in options else 0,
                format_func=lambda x:'기준 구간 사용 안 함' if x is None else case_title(x), key=prefix+'_base')
            a,b=st.columns(2)
            base_lo=a.text_input('기준 시작 (KST, 포함)', value=initial['base_lo'], key=prefix+'_base_lo')
            base_hi=b.text_input('기준 종료 (KST, 미포함)', value=initial['base_hi'], key=prefix+'_base_hi')
            confirmed=st.checkbox('동일 Agent이며 두 구간의 수집 조건을 비교할 수 있음을 확인했습니다.',
                                   value=initial['confirmed'],key=prefix+'_confirmed')
            st.caption('비교 시 같은 길이의 구간을 사용합니다. 같은 분석의 겹치는 구간은 정상 기준으로 적용하지 않습니다.')
            a,b,c,d=st.columns(4)
            ratio=a.number_input('P95 급증 배율',min_value=1.,max_value=100.,value=initial['ratio'],key=prefix+'_ratio')
            minimum=b.number_input('절대 지연 하한 (초)',min_value=.1,max_value=86400.,value=initial['minimum'],key=prefix+'_minimum')
            repeat=c.number_input('RUNNING 반복 기준 (회)',min_value=2,max_value=1000,value=initial['repeat'],step=1,key=prefix+'_repeat')
            bucket=d.selectbox('시간 집계', [60,300],index=0 if initial['bucket']==60 else 1,
                               format_func=lambda x:f'{x//60}분',key=prefix+'_bucket')
            apply=st.form_submit_button('진단 조건 적용',type='primary')
        if apply:
            initial={'lo':lo,'hi':hi,'base':str(base) if base else None,'base_lo':base_lo,'base_hi':base_hi,
                     'confirmed':confirmed,'ratio':ratio,'minimum':minimum,'repeat':repeat,'bucket':bucket}
            st.session_state[prefix+'_config']=initial
    if not initial['lo'] or not initial['hi']:
        st.info('날짜 있는 인식 자료가 없습니다. 위 자료 인식 상태에서 기준 날짜를 확인하고 원본 재해석을 실행하세요. 오늘 날짜나 조회 시작일을 자동 적용하지 않습니다.')
        return
    try:
        window=Window(initial['lo'],initial['hi']);window.bounds()
        baseline_case=Path(initial['base']) if initial['base'] else None
        baseline_manifest=_get_manifest(baseline_case) if baseline_case else None
        base_sig=source_signature(baseline_case,baseline_manifest) if baseline_case else None
        if baseline_case and baseline_case.resolve() == case.resolve() and view:
            baseline_case, baseline_manifest = event_case, effective
        identity=hashlib.sha256(json.dumps([signature,base_sig,initial],sort_keys=True).encode()).hexdigest()
        cached=st.session_state.get('_v43_job_cache')
        if cached is None or cached[0]!=identity:
            data=diagnose_jobs(event_case,effective,window,baseline_case=baseline_case,baseline_manifest=baseline_manifest,
                baseline_window=Window(initial['base_lo'],initial['base_hi']) if baseline_case else None,
                same_agent_confirmed=initial['confirmed'],bucket_seconds=initial['bucket'],
                policy=DiagnosticPolicy(initial['ratio'],initial['minimum'],5,initial['repeat']))
            data['input_diagnostics'] = inspect_input(event_case, effective, window)
            data['warnings'] = list(dict.fromkeys(data['warnings'] + [r['message'] for r in data['input_diagnostics']['reasons']]))
            st.session_state['_v43_job_cache']=(identity,data)
        else:
            data=cached[1]
    except (ValueError,OSError,KeyError) as exc:
        st.error(str(exc));return
    trace_id=hashlib.sha256(json.dumps([signature,window.start,window.end]).encode()).hexdigest()
    trace_cache=st.session_state.get('_v43_trace_cache')
    messages=trace_cache[1] if trace_cache and trace_cache[0]==trace_id else None
    if trace_cache and trace_cache[0]!=trace_id:
        st.session_state.pop('_v43_trace_cache',None)
    with st.expander('메시지 원본 조회 · 로컬 검색',expanded=st.session_state.get(prefix+'_open_messages',False)):
        with st.form(prefix+'_message_query'):
            a,b=st.columns(2)
            service=a.text_input('SERVICE_SEQNO (선택)',max_chars=64,key=prefix+'_service')
            message=b.text_input('MESSAGE_SEQNO (선택)',max_chars=64,key=prefix+'_message')
            consent=st.checkbox('해시 검증한 원본 로그를 로컬에서 읽어 메시지 결과를 조회합니다.',key=prefix+'_trace_consent')
            scan=st.form_submit_button('메시지 결과 조회',type='primary')
        st.caption('식별값이 명시된 레코드만 연결합니다. 본문·SQL·식별값은 새 요약에 포함하지 않습니다. 조회 구간은 위에서 적용한 구간입니다.')
        if scan:
            if not consent:
                st.warning('원본 조회 동의가 필요합니다.')
            else:
                try:
                    salt=st.session_state.setdefault('_v43_trace_salt',secrets.token_bytes(32))
                    messages=trace_outcomes(case,window,message=message.strip(),service=service.strip(),salt=salt,
                        anchor_date=date.fromisoformat(effective['reference_date']) if view and effective.get('reference_date') and not manifest.get('reference_date') else None,
                        date_confirmed=bool(view), redetect_encoding=bool(view))
                    st.session_state['_v43_trace_cache']=(trace_id,messages)
                except (ValueError,OSError,KeyError) as exc:
                    messages=None;st.session_state.pop('_v43_trace_cache',None);st.error(str(exc))
    points=st.session_state.get(prefix+'_backlog_points',[])
    comparable=st.session_state.get(prefix+'_backlog_comparable',False)
    backlog=backlog_observations(points,comparable=comparable)
    payload=make_payload(data,messages,backlog)
    payload['input_scope'] = trace_id
    payload['revision'] = hashlib.sha256((payload['revision']+trace_id).encode()).hexdigest()[:24]
    labels={f['file_id']:ui_file_label(case,f['file_id'],manifest) for f in manifest['files']}
    value=_component(payload=payload,local_labels=labels,key=prefix+'_component',default=None)
    if value and isinstance(value,dict) and value.get('nonce')!=st.session_state.get(prefix+'_last_action'):
        try:
            event=validate_action(value,payload)
            st.session_state[prefix+'_last_action']=event['nonce']
            if event['action']=='configure':
                st.session_state[prefix+'_open_config']=True;st.rerun()
            elif event['action']=='configure_messages':
                st.session_state[prefix+'_open_messages']=True;st.rerun()
            elif event['action']=='backlog':
                updated=points+[event['row']]
                validated=backlog_observations(updated,comparable=event['comparable'])
                st.session_state[prefix+'_backlog_points']=[{'at':r['at'],'count':r['count']} for r in validated['rows']]
                st.session_state[prefix+'_backlog_comparable']=event['comparable'];st.rerun()
            elif event['action']=='evidence':
                st.session_state[prefix+'_selected_evidence']=(trace_id,event['ref'])
        except (ValueError,OSError) as exc:
            st.session_state[prefix+'_last_action']=value.get('nonce');st.warning(str(exc))
    selected=st.session_state.get(prefix+'_selected_evidence')
    if selected and selected[0]==trace_id:
        st.markdown('#### 선택한 근거의 마스킹 원문')
        from .source_view import excerpt
        try:
            ref=selected[1]
            encoding = next((f['encoding'] for f in effective['files'] if f['file_id'] == ref['file_id']), None) if view else None
            preview=excerpt(case,ref['file_id'],ref['line_start'],ref['line_end'],encoding_override=encoding)
            st.caption(ui_file_label(case,ref['file_id'],manifest)+' · '+preview['notice'])
            st.code('\n'.join(f"{r['line']:>6}  {r['text']}" for r in preview['lines']),language='text')
        except (ValueError,OSError) as exc:
            st.warning(str(exc))
    with st.expander('비식별 요약 다운로드 · 화면 안내'):
        export={k:payload[k] for k in ('jobs','messages','backlog')}
        st.download_button('비식별 진단 JSON 저장',json.dumps(export,ensure_ascii=False,indent=2),
            file_name='mpush-diagnostics-v4.3.json',mime='application/json',key=prefix+'_download')
        st.caption('원본 파일명·고객사명·Redmine 주소는 내보내지 않습니다. 대기량 관측은 현재 세션에만 있으므로 필요하면 다운로드하세요.')
