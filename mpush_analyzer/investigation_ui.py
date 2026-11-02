"""V4.2 focused investigation UI; source observations and hypotheses stay apart."""
from __future__ import annotations
from datetime import timedelta
import hashlib
import json
from pathlib import Path
import secrets

import pandas as pd
import streamlit as st

from .investigation import (Window, instant, iso, population, quality, timeline,
                            exception_groups, continuity, job_spans, window_stats, compare_windows)
from .investigation_guidance import guidance, reply_draft
from .investigation_reference import (read_observations, save_observations, parse_xml_reference, MAX_XML)
from .message_trace import trace_messages, STAGES
from .pipeline import _get_manifest
from .lifecycle import list_cases
from .support_store import ui_file_label, ui_rows, case_title, read_context

MODES=('장애 구간 타임라인','예외 원인 체인','정상·장애 비교','주기·기록 중단',
       '메시지별 추적','추가 증거·회신 초안','운영 관측·선택 참고')


def signature(case: Path, manifest: dict, *parts) -> str:
    event_file=case/'events.jsonl'
    state=event_file.stat()
    raw=json.dumps([case.name,manifest,state.st_mtime_ns,state.st_size,parts],sort_keys=True,default=str)
    return hashlib.sha256(raw.encode()).hexdigest()[:20]


def cached(case, manifest, slot, args, fn):
    """Session-only bounded by one payload per feature; no raw logs/IDs stored."""
    key='inv_cache_'+case.name+'_'+slot
    identity=signature(case,manifest,*args)
    stored=st.session_state.get(key)
    if stored is None or stored[0]!=identity:
        value=fn();st.session_state[key]=(identity,value)
    return st.session_state[key][1]


def evidence_view(case: Path, manifest: dict, refs: list[dict], namespace: str):
    if not refs:return
    valid=[];seen=set()
    for r in refs:
        key=(r.get('file_id'),r.get('line_start'),r.get('line_end'))
        if key not in seen and key[0] in {f['file_id'] for f in manifest['files']}:
            seen.add(key);valid.append(r)
    if not valid:return
    chosen=st.selectbox('확인할 원본 근거',valid,format_func=lambda r:
        f"{ui_file_label(case,r['file_id'],manifest)} · {r.get('occurred_at') or '시각 미확인'} · {r['line_start']}–{r['line_end']}행",
        key=namespace+'_evidence')
    if st.checkbox('이 근거의 마스킹 원문 보기',key=namespace+'_preview'):
        from dashboard_ui import _preview
        _preview(case,chosen,namespace=namespace+'_raw')


def _window(case,manifest):
    overall=cached(case,manifest,'population',[],lambda:population(case,manifest))
    first=instant(overall['first']);last=instant(overall['last'])
    start=iso(first.replace(second=0,microsecond=0)) if first else ''
    finish=iso(min(last+timedelta(seconds=1),instant(start)+timedelta(days=31))) if first and last else ''
    active=st.session_state.get('inv_window_active_'+case.name)
    if active:start,finish=active.start,active.end
    with st.form('inv_window_'+case.name):
        a,b=st.columns(2)
        lo=a.text_input('조사 시작 (KST, 포함)',value=start)
        hi=b.text_input('조사 종료 (KST, 미포함)',value=finish)
        submitted=st.form_submit_button('조사 구간 적용',type='primary')
    st.caption('구간은 [시작, 종료)입니다. 날짜 미확인 기록은 기간 계산에서 제외하며 자동으로 오늘 날짜를 붙이지 않습니다.')
    key='inv_window_active_'+case.name
    if submitted or key not in st.session_state:
        try:
            candidate=Window(lo,hi);candidate.bounds()
            st.session_state[key]=candidate
        except ValueError as exc:
            if submitted:st.error(str(exc))
            return None
    return st.session_state.get(key)


def render_timeline(case,manifest,window):
    st.markdown('### 5종 로그 통합 장애 구간')
    kinds=st.multiselect('타임라인 로그 종류',sorted({'err','info','job','dbwrap','debug'}),default=[],key='inv_kinds_'+case.name)
    page=int(st.number_input('타임라인 페이지',min_value=1,value=1,step=1,key='inv_page_'+case.name+str(window)))
    result=cached(case,manifest,'timeline',[window,page,kinds],lambda:timeline(case,manifest,window,page=page,kinds=tuple(kinds)))
    st.caption(f"조건 일치 {result['total']:,}건 · {result['pages']}페이지 · 날짜 미확인 제외 {result['undated_excluded']:,}건")
    if result['bins']:
        points=pd.DataFrame(result['bins']).melt(id_vars=['시각'],var_name='로그 종류',value_name='관측수')
        points=points[points['관측수']>0]
        spec={'mark':{'type':'circle'},'encoding':{
            'x':{'field':'시각','type':'temporal','title':'시각 (KST 표기는 표에서 확인)'},
            'y':{'field':'로그 종류','type':'nominal','scale':{'domain':['info','err','job','debug','dbwrap']}},'size':{'field':'관측수','type':'quantitative'},
            'tooltip':[{'field':'시각','type':'temporal'},{'field':'로그 종류'},{'field':'관측수'}]}}
        st.vega_lite_chart(points,spec,width='stretch')
        st.caption(f"위 그림은 {result['bucket_seconds']}초 단위의 이벤트 밀도입니다. 아래는 개별 사건이며 점의 부재가 장애를 뜻하지 않습니다.")
    display=ui_rows(case,manifest,result['rows'])
    if display:
        columns=['시각','로그 유형','유형','Job','처리시간(초)','DB시간(ms)','주요 정보','근거 파일','줄번호']
        st.dataframe(pd.DataFrame(display).reindex(columns=columns),hide_index=True,width='stretch')
        chosen=st.selectbox('상세 조사할 이벤트',list(range(len(display))),
            format_func=lambda i:f"{display[i]['시각']} · {display[i]['유형']} · {display[i]['줄번호']}",key='inv_event_'+case.name+str(window)+str(page))
        from .workbench_ui import _detail
        _detail(case,manifest,display[chosen],key='inv_detail_'+case.name+str(page)+str(chosen))
    spans=cached(case,manifest,'spans',[window],lambda:job_spans(case,manifest,window))
    st.markdown('#### Job 실행 구간과 단계별 시간')
    if spans['spans']:
        rows=[{'Job':x['job'],'시작':x['start'],'완료':x['end'],'시작 근거':x['start_basis'],
               '소요(초)':x['seconds'],'SELECT(초)':x['steps']['select'],'DB(초)':x['steps']['db'],
               'SOCKET(초)':x['steps']['socket'],'파일':ui_file_label(case,x['ref']['file_id'],manifest)} for x in spans['spans']]
        st.dataframe(rows,hide_index=True,width='stretch')
        chart=pd.DataFrame(rows)
        st.vega_lite_chart(chart,{'mark':'bar','encoding':{'x':{'field':'시작','type':'temporal'},
            'x2':{'field':'완료'},'y':{'field':'Job','type':'nominal'},
            'tooltip':[{'field':'Job'},{'field':'소요(초)'},{'field':'시작 근거'}]}},width='stretch')
    st.caption(spans['note'])
    if spans['omitted'] or spans['overlap_omitted']:st.warning('구간/중첩 표시 상한에 도달했습니다. 기간을 좁히세요.')
    if spans['overlaps']:
        st.dataframe([{'Job 1':x['left'],'Job 2':x['right'],'중첩 시작':x['start'],'중첩 끝':x['end']} for x in spans['overlaps']],hide_index=True,width='stretch')
        evidence_view(case,manifest,[r for x in spans['overlaps'][:20] for r in (x['left_ref'],x['right_ref'])],'inv_overlap_'+case.name)


def render_chains(case,manifest,window):
    st.markdown('### 예외 스택 · 원인 체인 · 반복 기록')
    data=cached(case,manifest,'chains',[window],lambda:exception_groups(case,manifest,window))
    st.caption(data['note'])
    if data['legacy_records']:
        st.warning(f"이전 분석 형식의 오류 {data['legacy_records']}건은 전체 체인이 저장되지 않았습니다. 내보내기·관리에서 원본 검증 후 재분석하면 새 파서로 갱신됩니다.")
    if not data['groups']:
        st.info('구간 내 구조화 오류 기록이 없습니다. 원본 오류 부재를 보장하지 않습니다.');return
    st.dataframe([{'원인 체인':g['chain'],'반복 기록':g['count'],'최초':g['first'],'최종':g['last'],
        '명시 Job':', '.join(g['jobs']) or '미기록','파일':ui_file_label(case,g['file_id'],manifest),
        '잘린 스택':g['truncated_records']} for g in data['groups']],hide_index=True,width='stretch')
    if data['unaggregated_records']:st.warning('체인 그룹 상한으로 집계되지 않은 기록이 있습니다. 구간을 좁히세요.')
    selected=st.selectbox('조사할 예외 체인',data['groups'],format_func=lambda g:g['chain']+' · '+str(g['count'])+'회',key='inv_chain_'+case.name)
    st.caption('→는 로그의 Caused by 관계입니다. 최하위 예외가 실제 운영 장애 원인을 확정하는 것은 아닙니다.')
    if selected['evidence_omitted']:st.caption(f"대표 근거 100개 상한으로 {selected['evidence_omitted']}개는 여기서 생략했습니다. 전체 이벤트에서 조회하세요.")
    evidence_view(case,manifest,selected['evidence'],'inv_chain_ref_'+case.name)


def render_compare(case,manifest,window):
    st.markdown('### 정상 기준 구간과 장애 조사 구간 비교')
    candidates=list_cases(case.parent)
    base=st.selectbox('정상 기준 분석 작업',candidates,format_func=case_title,key='inv_baseline_'+case.name)
    default_start=iso(instant(window.start)-timedelta(days=1));default_end=iso(instant(window.end)-timedelta(days=1))
    with st.form('inv_compare_form_'+case.name):
        start=st.text_input('기준 구간 시작 (KST)',value=default_start)
        end=st.text_input('기준 구간 종료 (KST)',value=default_end)
        confirm=st.checkbox('같은 Agent이며 비교 가능한 수집 범위인지 확인했습니다.')
        submitted=st.form_submit_button('동일 길이 구간 비교')
    key='inv_comparison_'+case.name
    bmanifest=_get_manifest(base)
    baseline_signature=signature(base,bmanifest)
    identity=signature(case,manifest,window,str(base),baseline_signature,start,end,confirm)
    if submitted:
        try:
            bmanifest=_get_manifest(base)
            result=compare_windows(case,manifest,window,base,bmanifest,Window(start,end),same_agent_confirmed=confirm)
            st.session_state[key]=(identity,result)
        except (ValueError,OSError) as exc:
            st.session_state.pop(key,None);st.error(str(exc))
    saved=st.session_state.get(key)
    if not saved or saved[0]!=identity:return
    result=saved[1]
    st.info(result['note'])
    for text in result['warnings']:st.warning(text)
    st.dataframe(result['rows'],hide_index=True,width='stretch')
    st.dataframe([{'구간':name,'오류 기록':data['error_records'],'관측 이벤트':data['events'],
                   '날짜 미확인 제외':data['unknown_time_excluded'],'기간(초)':data['window_seconds']}
                  for name,data in [('기준',result['baseline']),('조사',result['investigation'])]],hide_index=True,width='stretch')
    stages=[]
    for period,data in [('기준',result['baseline']),('조사',result['investigation'])]:
        for g in data['groups']:
            for step,values in g['steps'].items():
                stages.append({'구간':period,'Job':g['name'],'단계':step,'표본':values['samples'],
                    '평균(초)':values['mean'],'P95(초)':values['p95'],'최대(초)':values['max'],
                    '누적 시간(초)':values['total']})
    if stages:st.dataframe(stages,hide_index=True,width='stretch')
    st.caption('P50/P95는 전체 표본을 보관한 경우만 표시합니다. 보관 상한 초과 시 계산 불가로 남기며 평균·최댓값과 표본 수는 따로 유지합니다.')
    st.caption(result['investigation']['note'])


def render_continuity(case,manifest,window):
    st.markdown('### 주기 변화 · RUNNING · 마지막 관측 · 종료 기록')
    data=cached(case,manifest,'continuity',[window],lambda:continuity(case,manifest,window))
    st.info(data['note'])
    observed=read_observations(case)
    if observed:
        st.dataframe([{'근거 출처':'담당자 입력(로그 자동판정 아님)',
            'PID 관측':{'unknown':'미확인','alive':'실행 중','not_running':'미실행'}[observed['pid_status']],
            'PID 확인 시각':observed['pid_checked_at'],'재시작 확인':observed['restart_confirmed'],
            '재시작 시각':observed['restarted_at']}],hide_index=True,width='stretch')
    st.markdown('#### 파일별 마지막 정규화 이벤트와 실제 수집시각 (전체 자료 범위)')
    st.caption('원본의 모든 텍스트 행이 정규화 이벤트는 아닙니다. 아래 시각은 인식된 이벤트 기준입니다.')
    st.dataframe([{'파일':ui_file_label(case,x['file_id'],manifest),'마지막 관측':x['last_observed'],
                   '수집시각':x['collected_at'],'차이(초)':x['seconds_to_collection'],'시각 역전':x['collection_conflict']}
                  for x in data['tails']],hide_index=True,width='stretch')
    st.markdown('#### 관측 간격 기준과 긴 공백 (선택 구간)')
    if data['streams']:
        st.dataframe([{'파일':ui_file_label(case,x['file_id'],manifest),'관측 종류':x['stream'],
            '보관 표본':x['records'],'관측 중앙 간격(초)':x['observed_median_interval'],
            '등록 주기(초)':x['configured_interval'],'긴 공백 기준(초)':x['threshold_seconds'],
            '기준 근거':x['reference_basis']} for x in data['streams']],hide_index=True,width='stretch')
    if data['gaps']:
        st.dataframe([{'파일':ui_file_label(case,g['file_id'],manifest),'관측 종류':g['stream'],
            '직전 시각':g['from'],'다음 시각':g['to'],'간격(초)':g['seconds'],'판별 기준(초)':g['threshold']} for g in data['gaps']],hide_index=True,width='stretch')
        evidence_view(case,manifest,[r for g in data['gaps'][:20] for r in (g['before_ref'],g['after_ref'])],'inv_gap_'+case.name)
    else:st.caption('현재 기준에서 표시할 긴 공백이 없거나 주기 표본이 부족합니다. 정상이라는 뜻은 아닙니다.')
    if data['running_skips']:st.dataframe([{'Job':k,'RUNNING 실행 건너뜀':v} for k,v in data['running_skips'].items()],hide_index=True)
    st.markdown('#### 예약과 기동·종료 기록 (조사 구간 밖 기록도 별도 표시)')
    if data['schedules']:
        st.dataframe([{'Job':x['job'],'예약 표현식':x['cron'],'일일 예약시각':x['daily'],
                       '단순 주기(초)':x['interval'],'예약 등록 관측':x['ref']['occurred_at']} for x in data['schedules']],hide_index=True,width='stretch')
    if data['lifecycle']:
        st.dataframe([{'기록':x['event'],'실제 기록 시각':x['ref']['occurred_at'],
                       '파일':ui_file_label(case,x['ref']['file_id'],manifest)} for x in data['lifecycle']],hide_index=True,width='stretch')
        evidence_view(case,manifest,[x['ref'] for x in data['lifecycle']],'inv_lifecycle_'+case.name)
    if data['unprocessed_records'] or data['unlisted']:st.warning('일부 관측이 표시/집계 한도에 도달했습니다. 더 짧은 기간을 조회하세요.')


def render_trace(case,manifest,window):
    st.markdown('### 메시지별 관측 단계 추적 (선택 실행)')
    st.caption('같은 레코드에 SERVICE_SEQNO와 MESSAGE_SEQNO가 명시돼야 연결합니다. SQL ? 바인드 순서·인접 시간·다른 Agent는 추측해 연결하지 않습니다.')
    with st.form('inv_trace_form_'+case.name):
        message=st.text_input('MESSAGE_SEQNO 필터 (선택, 로컬 입력만)',type='password')
        service=st.text_input('SERVICE_SEQNO 필터 (선택, 로컬 입력만)',type='password')
        consent=st.checkbox('해시 검증된 로컬 원본에서 식별 필드와 단계 표지를 조회합니다.')
        run=st.form_submit_button('메시지 흐름 조회')
    key='inv_trace_result_'+case.name
    if run:
        st.session_state.pop(key,None)
        if not consent:st.warning('원본 읽기 확인이 필요합니다.')
        else:
            try:
                with st.spinner('선택 기간의 명시 식별값·단계 관측 중...'):
                    data=trace_messages(case,window,message=message,service=service)
                st.session_state[key]=(signature(case,manifest,window,message,service),data)
            except (ValueError,OSError) as exc:st.error(str(exc))
    saved=st.session_state.get(key)
    if not saved or saved[0]!=signature(case,manifest,window,message,service):return
    data=saved[1];st.info(data['note'])
    st.dataframe([{'항목':k,'기록 수':v} for k,v in data['coverage'].items()],hide_index=True)
    if data['omitted_records']:st.warning('메시지/표시 상한을 초과했습니다. 기간 또는 식별값 필터를 좁히세요.')
    if not data['groups']:
        st.info('연결 가능한 명시 식별값이 없습니다. 없는 단계를 생성하지 않았습니다.');return
    labels=dict(STAGES)
    st.dataframe([{'메시지 가명':g['message'],'서비스 가명':g['service'],'관측 기록':g['records'],
        'JOB_TYPE':', '.join(g['job_types']),'관측 시작':g['first'],'관측 끝':g['last'],
        '미관측 단계':', '.join(labels[x] for x in g['missing_stages']),
        '요청→결과 관측 간격(초)':g['request_to_result_seconds'],'최종 배송':'미확인'} for g in data['groups']],
        hide_index=True,width='stretch')
    chosen=st.selectbox('조회할 메시지 가명',data['groups'],format_func=lambda g:g['message'],key='inv_trace_select_'+case.name)
    events=[e for e in data['events'] if e['message']==chosen['message']]
    st.dataframe([{'시각':e['ref']['occurred_at'],'관측 표지':', '.join(labels.get(s,s) for s in e['stages']),
        '관측 성격':e['observation_basis'],'실패 표지 동반':e['failure_marker'],'JOB_TYPE':e['job_type'],'SEND_FLAG(의미 미확정)':e['send_flag'],
        '응답 코드':e['response_code'],'파일':ui_file_label(case,e['ref']['file_id'],manifest),
        '행':f"{e['ref']['line_start']}–{e['ref']['line_end']}"} for e in events],hide_index=True,width='stretch')
    st.caption('단계 표지가 보인다는 뜻이지 해당 단계의 성공·완료를 보장하지 않습니다. 재시도·중복 기록을 자동으로 단일 전송에 합치지 않습니다.')
    evidence_view(case,manifest,chosen['evidence'],'inv_trace_ref_'+case.name)


def render_guidance(case,manifest,window):
    st.markdown('### 관측 사실 · 가능 원인 · 추가 증거 · 회신 초안')
    stats=cached(case,manifest,'stats',[window],lambda:window_stats(case,manifest,window))
    chains=cached(case,manifest,'chains',[window],lambda:exception_groups(case,manifest,window))
    cadence=cached(case,manifest,'continuity',[window],lambda:continuity(case,manifest,window))
    spans=cached(case,manifest,'spans',[window],lambda:job_spans(case,manifest,window))
    packet=guidance(stats,chains,cadence,spans,manifest)
    for field,label in [('facts','관측 사실'),('possible_causes','가능 원인 (확정 아님)'),('additional_evidence','필요한 추가 증거'),('limitations','판정 한계')]:
        st.markdown('#### '+label)
        st.dataframe([{'내용':x} for x in packet[field]],hide_index=True,width='stretch')
    evidence_view(case,manifest,packet['evidence'],'inv_guide_ref_'+case.name)
    with st.expander('읽기 전용 점검 예시 — 프로그램은 실행하지 않음'):
        st.warning('운영체제·DBMS·스키마·권한과 조회 부하를 확인한 담당자가 판단하세요. 쿼리의 잔존 건수는 곧 적체/최종 배송 건수가 아닙니다.')
        for item in packet['read_only_examples']:
            st.caption(item['목적']);st.code(item['예시'])
    if st.checkbox('회신 초안의 근거·비식별 범위·표현을 검토합니다.',key='inv_reply_review_'+case.name):
        draft=reply_draft(packet)
        st.code(draft,language=None)
        st.download_button('검토용 회신 초안 TXT',draft.encode('utf-8'),file_name='investigation_reply_draft.txt',key='inv_reply_download_'+case.name)
        st.caption('Redmine·이메일·외부 AI로 자동 발송하지 않습니다.')


def render_reference(case,manifest):
    st.markdown('### 운영 관측과 선택 참고자료')
    try:doc=read_observations(case)
    except ValueError as exc:st.error(str(exc));return
    # A form retains its captured revision rather than overwriting newer edits.
    key='inv_observations_'+case.name
    if st.button('저장된 운영 관측 새로고침',key='inv_obs_reload_'+case.name):
        st.session_state.pop(key,None);st.rerun()
    if key not in st.session_state:st.session_state[key]=doc
    saved=st.session_state[key]
    with st.form('inv_observations_form_'+case.name+'_'+str(saved.get('revision',0))):
        statuses={'unknown':'미확인','alive':'실행 중 관측','not_running':'미실행 관측'}
        pid=st.selectbox('PID 상태 (담당자 확인)',list(statuses),format_func=lambda k:statuses[k],index=list(statuses).index(saved.get('pid_status','unknown')))
        checked=st.text_input('PID 확인 시각',value=saved.get('pid_checked_at') or '')
        restart=st.checkbox('재시작 사실을 확인했습니다.',value=saved.get('restart_confirmed',False))
        restart_at=st.text_input('재시작 시각',value=saved.get('restarted_at') or '')
        versions=['unknown','3.2','3.3','2.8-reference']
        version=st.selectbox('추가 참고 버전',versions,index=versions.index(saved.get('reference_version','unknown')))
        note=st.text_area('담당자 관측 메모 (로컬 전용)',value=saved.get('operator_note',''),max_chars=3000)
        submit=st.form_submit_button('운영 관측 저장')
    if submit:
        try:
            updated=save_observations(case,{'pid_status':pid,'pid_checked_at':checked,'restart_confirmed':restart,
                'restarted_at':restart_at,'reference_version':version,'operator_note':note},expected_revision=saved.get('revision',0))
        except (ValueError,OSError) as exc:st.error(str(exc))
        else:st.session_state[key]=updated;st.success('로컬 관측 기록에 저장했습니다. 자동 원인 판정에는 사용하지 않습니다.')
    st.info('2.8은 참고 표시만 제공합니다. 전용 파서·현장 호환성 검증 완료를 뜻하지 않습니다. XML과 2.8 자료 없이도 타임라인·비교·문의 기능을 사용할 수 있습니다.')
    config=manifest.get('config_summary') or {}
    st.markdown('#### agent.ini의 안전한 설정과 관측 범위')
    st.dataframe([{'항목':'debug 설정','값':str((config.get('agent') or {}).get('debug_enabled'))},
                  {'항목':'HA 사용 설정','값':str((config.get('ha') or {}).get('enabled'))},
                  {'항목':'DBMS','값':(config.get('dbms') or {}).get('type','미제공')}],hide_index=True)
    if (config.get('agent') or {}).get('debug_enabled') is False:
        st.caption('제공된 설정은 debug=false입니다. 현재 로그와 동일한 배포 시점인지 확인하세요. debug 로그가 없다는 것만으로 비정상이라 판단하지 않습니다.')
    optional=st.file_uploader('XML 참고자료 (선택, UTF-8, 512KiB 이하)',type=['xml'],key='inv_xml_'+case.name)
    if optional is not None and st.button('XML 참고 정보 확인',key='inv_xml_parse_'+case.name):
        try:
            if optional.size>MAX_XML:raise ValueError('XML 선택 참고 크기는 512KiB 이하입니다.')
            parsed=parse_xml_reference(optional.getvalue());st.session_state['inv_xml_result_'+case.name]=(getattr(optional,'file_id',None),optional.size,parsed)
        except ValueError as exc:
            st.session_state.pop('inv_xml_result_'+case.name,None);st.warning(str(exc))
    saved_xml=st.session_state.get('inv_xml_result_'+case.name)
    parsed=(saved_xml[2] if optional is not None and saved_xml and saved_xml[:2]==(getattr(optional,'file_id',None),optional.size) else None)
    if parsed:
        st.caption(parsed['note']);st.caption('XML SHA-256: '+parsed['sha256'])
        if parsed['schedules']:st.dataframe(parsed['schedules'],hide_index=True,width='stretch')
        if parsed['debug_flags']:st.dataframe(parsed['debug_flags'],hide_index=True)
        if parsed['ha_mentions_in_comments']:st.warning('HA Job 이름이 XML 주석에 나타납니다. 다른 활성 설정이 있는지 확인해야 하며 HA 미동작을 확정하지 않습니다.')
        if not parsed['schedules'] and not parsed['debug_flags']:st.info('지원하는 예약/debug 참고 항목을 찾지 못했습니다. 핵심 로그 분석은 계속 사용할 수 있습니다.')
        st.caption('선택 XML은 이 브라우저 세션에서만 참고하며 원문·비밀번호·서버 주소를 저장하지 않습니다.')
    from .investigation_reference import crosscheck_config
    selected_window=st.session_state.get('inv_window_active_'+case.name)
    cadence=(cached(case,manifest,'continuity',[selected_window],lambda:continuity(case,manifest,selected_window))
             if selected_window else {'schedules':[]})
    st.markdown('#### 설정과 로그 관측 교차 확인')
    st.dataframe(crosscheck_config(manifest,cadence,parsed),hide_index=True,width='stretch')


def render_investigation(case,manifest,result):
    if st.session_state.get('inv_cache_active_case')!=case.name:
        for key in list(st.session_state):
            if key.startswith(('inv_cache_','inv_trace_result_')):
                del st.session_state[key]
        st.session_state['inv_cache_active_case']=case.name
    st.markdown('## 장애 조사 워크벤치 · V4.2')
    try:
        ctx=read_context(case)
        st.text(case_title(case)+' · Agent '+(ctx.get('agent') or '구분 미확인'))
        q=quality(manifest);st.caption(q['version_note'])
        st.caption('수집시각: '+(q['collected_at'] or '미제공')+' · 완전성 제한 파일 '+str(len(q['nonfull_files']))+'개')
        if q['missing_kinds']:st.caption('미제공 로그 유형: '+', '.join(q['missing_kinds']))
        mode=st.selectbox('장애 조사 기능',MODES,key='inv_mode_'+case.name)
        if mode=='운영 관측·선택 참고':render_reference(case,manifest);return
        window=_window(case,manifest)
        if window is None:
            st.info('기간이 확정되지 않았습니다. 기준 날짜·수집 범위를 확인하고 조사 구간을 입력하세요.');return
        st.caption('적용 구간: '+window.start+' ≤ 시각 < '+window.end)
        handlers={'장애 구간 타임라인':render_timeline,'예외 원인 체인':render_chains,'정상·장애 비교':render_compare,
                  '주기·기록 중단':render_continuity,'메시지별 추적':render_trace,'추가 증거·회신 초안':render_guidance}
        handlers[mode](case,manifest,window)
    except (ValueError,OSError) as exc:
        st.error(str(exc))
