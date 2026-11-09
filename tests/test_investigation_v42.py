"""Notion A-E scenarios use synthetic inputs only; no operational connections."""
from datetime import date
import json
from pathlib import Path
import pytest

from mpush_analyzer.intake import Upload, inspect_uploads
from mpush_analyzer.storage import save_intake
from mpush_analyzer.runner import run_complete_analysis
from mpush_analyzer.pipeline import _get_manifest
from mpush_analyzer.parsers import parse_by_kind
from mpush_analyzer.exception_chain import chain_label, safe_chain
from mpush_analyzer.investigation import (Window, instant, timeline, window_stats, compare_windows,
    job_spans, exception_groups, continuity, quality, Distribution, daily_time, periodic_interval)
from mpush_analyzer.message_trace import trace_messages
from mpush_analyzer.investigation_reference import (parse_xml_reference, save_observations, read_observations)
from mpush_analyzer.investigation_guidance import guidance, reply_draft

DAY=date(2026,11,2)
W=Window('2026-11-02T10:00:00','2026-11-02T10:20:00')
CHAIN='''10:12:00[001] java.sql.SQLTimeoutException: SYNTHETIC_PRIVATE_PROSE JOB_NAME=SEND_REAL_FILE_IMAGE
  at synthetic.customer.Module.run(Module.java:123)
Caused by: com.mysql.jdbc.CommunicationsException: Communications link failure SYNTHETIC_PRIVATE_DB
  at synthetic.customer.Pool.get(Pool.java:4)
Caused by: java.net.SocketTimeoutException: connect timed out SYNTHETIC_PRIVATE_ENDPOINT
  at synthetic.customer.Net.connect(Net.java:1)
'''


def fixture(tmp_path,logs,*,reference=DAY,collected='2026-11-02T12:00:00',version='3.3',partial=()):
    uploads=[Upload(name,raw.encode() if isinstance(raw,str) else raw,
                    completeness='partial' if name in partial else 'full') for name,raw in logs]
    case,manifest=save_intake(inspect_uploads(uploads),tmp_path/'workspace',reference_date=reference,
                              collected_at=collected,agent_version=version)
    result,matches,_=run_complete_analysis(case,knowledge_root=tmp_path/'knowledge')
    return case,manifest,result,matches


def job(name='SEND_REAL_FILE_IMAGE',clock='10:12:00.000',duration=20.,targets=100,steps=None):
    stamp=clock.replace('.', '[')+']';step=''
    for key,value in (steps or {'SELECT':duration}).items():step+=f'{stamp} ## {key} 시간(초.0f) : {value}초\n'
    return (f'{stamp}\n## {name} 작업\n{stamp} ## 작업대상건수 : {targets}\n'+step+
            f'{stamp} ## 소요시간(초.0f) : {duration}초\n')


def heartbeat(times=('10:00:00','10:00:10','10:00:20','10:00:30','10:02:00','10:02:10','10:02:20')):
    return '\n'.join(f'{t}[000] 헬스 체크 결과 : {{"TARGET":"Nothing"}}' for t in times)+'\n'


def assert_no_private(obj):
    blob=json.dumps(obj,ensure_ascii=False)
    for token in ('SYNTHETIC_PRIVATE_PROSE','SYNTHETIC_PRIVATE_DB','SYNTHETIC_PRIVATE_ENDPOINT','synthetic.customer'):
        assert token not in blob


@pytest.mark.parametrize('kind',['err','debug','info'])
def test_A_explicit_three_level_chain_is_one_error(kind):
    records=list(parse_by_kind(kind,enumerate(CHAIN.splitlines(),1)))
    assert len(records)==1
    details=records[0].data
    assert [n['class'] for n in details['exception_chain']]==['SQLTimeoutException','CommunicationsException','SocketTimeoutException']
    assert [n['relation'] for n in details['exception_chain']]==['root','cause','cause']
    assert [n['line'] for n in details['exception_chain']]==[1,3,5]
    assert details['job_names']==['SEND_REAL_FILE_IMAGE']
    assert 'connect_timeout' in details['reason_codes']
    assert records[0].start_line==1 and records[0].end_line==6
    assert_no_private(details)


def test_A_chain_repetitions_not_counted_as_three_errors(tmp_path):
    case,manifest,_,_=fixture(tmp_path,[('err.log',CHAIN+CHAIN.replace('10:12:00','10:13:00'))])
    group=exception_groups(case,manifest,W)
    assert group['records']==2 and len(group['groups'])==1
    assert group['groups'][0]['count']==2
    assert group['groups'][0]['first'].startswith('2026-11-02T10:12:00')
    assert group['groups'][0]['last'].startswith('2026-11-02T10:13:00')
    assert_no_private(group)


def test_error_header_and_timestamped_causes_stay_single():
    text='10:12:00[001] ERROR failure\njava.sql.SQLTimeoutException: fixture\n10:12:00[001] Caused by: java.net.SocketTimeoutException: connect timed out\n'
    for kind in ('err','debug','info'):
        events=list(parse_by_kind(kind,enumerate(text.splitlines(),1)))
        assert len(events)==1 and len(events[0].data['exception_chain'])==2


def test_new_exception_block_is_not_invented_cause():
    text=CHAIN+'java.lang.IllegalStateException: separate stack\n at pkg.A.run(A.java:2)\n'
    events=list(parse_by_kind('err',enumerate(text.splitlines(),1)))
    assert len(events)==2 and events[1].clock is None
    assert events[1].data['exception_chain'][0]['relation']=='root'


def test_suppressed_distinct_relation_and_oversized_chain():
    text='10:00:00[000] java.lang.RuntimeException: fixture\n Suppressed: java.io.IOException: fixture\n'
    ev=list(parse_by_kind('err',enumerate(text.splitlines(),1)))[0]
    assert ev.data['exception_chain'][1]['relation']=='suppressed'
    assert 'suppressed' in chain_label(ev.data)
    longtext='10:00:00[000] java.lang.RuntimeException: fixture\n'+('Caused by: java.io.IOException: fixture\n'*30)
    data=list(parse_by_kind('err',enumerate(longtext.splitlines(),1)))[0].data
    assert len(data['exception_chain'])==24 and data['chain_truncated'] is True
    assert data['chain_omitted_nodes']==7


def test_safe_chain_rejects_invalid_types_and_positions():
    details={'exception_chain':[{'class':'UNKNOWN_LABEL','relation':'cause','line':1},
        {'class':'SocketTimeoutException','relation':'root','line':-1},
        {'class':'IOException','relation':'unsupported','line':2}]}
    assert safe_chain(details)==[]


@pytest.mark.parametrize('start,end',[
 ('invalid','2026-11-02T10:00'),('2026-11-02T10:00','2026-11-02T10:00'),
 ('2026-11-02T11:00','2026-11-02T10:00'),('2026-11-02T10:00','2027-11-02T10:00'),
 ('2026-11-02T25:00','2026-11-03T10:00'),
])
def test_invalid_windows(start,end):
    with pytest.raises(ValueError):Window(start,end).bounds()


def test_window_timezone_half_open_and_midnight(tmp_path):
    case,m,_,_=fixture(tmp_path,[('debug.log',heartbeat(('23:59:59','00:00:00','00:00:01')))])
    rows=timeline(case,m,Window('2026-11-02T23:59:59+09:00','2026-11-03T00:00:01+09:00'))['rows']
    assert len(rows)==2 and rows[1]['시각'].startswith('2026-11-03')
    assert instant('2026-11-02T01:00:00Z')==instant('2026-11-02T10:00:00+09:00')
    assert timeline(case,m,Window('2026-11-02T14:59:59Z','2026-11-02T15:00:01Z'))['total']==2


def test_timeline_all_types_and_paging(tmp_path):
    from test_incident_evidence_v2 import SYNTHETIC_DB
    case,m,_,_=fixture(tmp_path,[('job.log',job()),('dbwrap.log',SYNTHETIC_DB),('err.log',CHAIN),
                                 ('debug.log',heartbeat()),('info.log','10:00:00[000] Started\n')])
    result=timeline(case,m,W,page_size=25)
    assert {x['로그 유형'] for x in result['rows']}=={'job','dbwrap','err','debug','info'}
    times=[instant(x['시각']) for x in result['rows']];assert times==sorted(times)
    assert timeline(case,m,W,kinds=('err',))['total']==1
    assert timeline(case,m,W,page=100)['rows']==[]
    assert_no_private(result)


def test_undated_not_assigned_today(tmp_path):
    case,m,_,_=fixture(tmp_path,[('debug.log',heartbeat())],reference=None)
    result=timeline(case,m,W)
    assert result['total']==0 and result['undated_excluded']==7
    assert quality(m)['undated_files']==['file_01']


def test_B_receive70_send20_overlap_not_lock(tmp_path):
    text=job('HA_RECEIVE_RESULT','10:12:10.000',70,10,{'DB':70})+job('SEND_REAL_FILE_IMAGE','10:12:00.000',20,10,{'SELECT':20})
    case,m,_,_=fixture(tmp_path,[('job.log',text)])
    result=job_spans(case,m,W)
    assert len(result['spans'])==2 and len(result['overlaps'])==1
    assert result['overlaps'][0]['start'].startswith('2026-11-02T10:11:40')
    assert result['overlaps'][0]['end'].startswith('2026-11-02T10:12:00')
    assert '확정 근거가 아닙니다' in result['note']
    assert all(x['start_basis']=='소요시간 역산(추정)' for x in result['spans'])


def test_C_pid_and_partial_evidence_separate(tmp_path):
    text=job('SEND_REAL_FILE_IMAGE','10:12:00.000',54.076)+job('HA_RECEIVE_RESULT','10:14:00.000',85.477,steps={'DB':85.477})
    case,m,_,_=fixture(tmp_path,[('job.log',text),('debug.log',heartbeat()),('dbwrap.log','')],partial=('dbwrap.log',))
    stats=window_stats(case,m,W)
    assert sorted(g['duration']['max'] for g in stats['groups'])==[54.076,85.477]
    data=continuity(case,m,W)
    assert any(x['seconds']==90 for x in data['gaps'])
    obs=save_observations(case,{'pid_status':'alive','pid_checked_at':'2026-11-02T10:15:00',
        'restart_confirmed':True,'restarted_at':'2026-11-02T10:16:00','operator_note':'SYNTHETIC_PRIVATE_NOTE'},expected_revision=0)
    assert obs['pid_status']=='alive' and 'SYNTHETIC_PRIVATE_NOTE' not in json.dumps(stats)
    assert stats['coverage']['nonfull_files']==['file_03']
    assert '확정하지' in data['note']


def test_D_daily_schedule_versus_later_exit(tmp_path):
    info='00:00:00[000] *DailyBatchJob 은 0 0 1 * * ? 으로 예약 되었습니다.\n11:21:00[000] Agent Exited\n'
    case,m,_,_=fixture(tmp_path,[('info.log',info),('job.log',job(clock='01:00:00.000',duration=1))])
    result=continuity(case,m,Window('2026-11-02T00:50','2026-11-02T01:10'))
    assert result['schedules'][0]['daily']=='01:00:00'
    assert result['lifecycle'][0]['ref']['occurred_at'].startswith('2026-11-02T11:21:00')
    assert result['lifecycle'][0]['event']=='agent_exit'
    assert result['tails'][1]['last_observed'].startswith('2026-11-02T01:00:00')


def test_periodic_interval_known_subset():
    assert periodic_interval('*/10 * * * * ?')==10
    assert periodic_interval('0 */5 * * * ?')==300
    assert periodic_interval('0 0 */2 * * ?')==7200
    assert periodic_interval('*/7 * * * * ?') is None
    assert periodic_interval('0 0 1 * * ?') is None
    assert daily_time('0 0 1 * * ?')=='01:00:00'
    assert daily_time('0 0 1 * * MON') is None


def test_distribution_exact_quantile_and_budget():
    values=Distribution()
    for x in (1,2,3,4):values.add(x)
    report=values.summary()
    assert report['mean']==2.5 and report['p50']==2.5 and report['p95']==3.85
    budget=[2];one=Distribution(budget);two=Distribution(budget)
    for x in (10,20,30):one.add(x)
    two.add(40)
    assert one.summary()['p95'] is None and one.summary()['mean']==20
    assert two.summary()['p50'] is None and two.summary()['max']==40
    values.add(float('nan'));values.add(True)
    assert values.summary()['samples']==4


def test_compare_same_length_missing_is_not_zero(tmp_path):
    base,bm,_,_=fixture(tmp_path,[('job.log',job(duration=2)+job(clock='10:14:00.000',duration=4))])
    case,m,_,_=fixture(tmp_path,[('job.log',job(duration=20)+job(clock='10:14:00.000',duration=40)+job('HA_RECEIVE_RESULT','10:15:00.000',70))])
    with pytest.raises(ValueError):compare_windows(case,m,W,base,bm,W,same_agent_confirmed=False)
    with pytest.raises(ValueError):compare_windows(case,m,W,base,bm,Window(W.start,'2026-11-02T10:01:00'),same_agent_confirmed=True)
    result=compare_windows(case,m,W,base,bm,W,same_agent_confirmed=True)
    send=next(x for x in result['rows'] if x['Job/SQL']=='SEND_REAL_FILE_IMAGE')
    assert send['P95 배율']==10 and send['기준 평균']==3 and send['조사 평균']==30
    receive=next(x for x in result['rows'] if x['Job/SQL']=='HA_RECEIVE_RESULT')
    assert receive['기준 기록'] is None and receive['조사 기록']==1


def test_empty_comparison_and_target_rate_limits(tmp_path):
    case,m,_,_=fixture(tmp_path,[('job.log',job(targets=200))])
    result=compare_windows(case,m,W,case,m,Window('2026-11-01T10:00','2026-11-01T10:20'),same_agent_confirmed=True)
    assert result['warnings'] and result['baseline']['groups']==[]
    assert result['investigation']['groups'][0]['targets_per_window_second']==round(200/1200,6)
    assert '성공 TPS' in result['investigation']['note']


def test_collection_time_conflict(tmp_path):
    case,m,_,_=fixture(tmp_path,[('debug.log',heartbeat())],collected='2026-11-02T09:00:00')
    assert continuity(case,m,W)['tails'][0]['collection_conflict'] is True


def trace_log():
    return '''09:30:00[000] 발송 요청 MESSAGE_SEQNO=MSG_A SERVICE_SEQNO=SVC_A JOB_TYPE=R00 SEND_FLAG=N
09:30:01[000] 선점 MESSAGE_SEQNO=MSG_A SERVICE_SEQNO=SVC_A JOB_TYPE=R00
09:30:02[000] 파일 생성 MESSAGE_SEQNO=MSG_A SERVICE_SEQNO=SVC_A
09:30:03[000] 암호화 MESSAGE_SEQNO=MSG_A SERVICE_SEQNO=SVC_A
09:30:04[000] tcp send MESSAGE_SEQNO=MSG_A SERVICE_SEQNO=SVC_A
09:30:05[000] RESPONSE_CODE=S MESSAGE_SEQNO=MSG_A SERVICE_SEQNO=SVC_A
09:30:15[000] 결과 수신 MESSAGE_SEQNO=MSG_A SERVICE_SEQNO=SVC_A SEND_FLAG=Y
09:30:16[000] 결과 이관 MESSAGE_SEQNO=MSG_A SERVICE_SEQNO=SVC_A
10:00:00[000] 발송 요청 MESSAGE_SEQNO=MSG_B SERVICE_SEQNO=SVC_A JOB_TYPE=B00
12:19:00[000] RESPONSE_CODE=S MESSAGE_SEQNO=MSG_B SERVICE_SEQNO=SVC_A
'''


def test_E_message_observations_not_delivery_or_backlog(tmp_path):
    case,m,_,_=fixture(tmp_path,[('debug.log',trace_log())])
    before=(case/'events.jsonl').read_bytes()
    result=trace_messages(case,Window('2026-11-02T09:30','2026-11-02T12:20'),salt=b'x'*32)
    assert len(result['groups'])==2
    full=next(g for g in result['groups'] if g['records']==8)
    assert full['missing_stages']==[] and full['request_to_result_seconds']==15
    assert all(g['final_delivery_confirmed'] is False for g in result['groups'])
    assert result['observations_by_job_type']['R00']==2 and result['observations_by_job_type']['B00']==1
    for secret in ('MSG_A','MSG_B','SVC_A'):assert secret not in json.dumps(result)
    assert (case/'events.jsonl').read_bytes()==before
    other=trace_messages(case,Window('2026-11-02T09:30','2026-11-02T12:20'),salt=b'y'*32)
    assert other['groups'][0]['message']!=result['groups'][0]['message']


def test_trace_composite_identity_and_missing_service(tmp_path):
    text='''10:00:00[000] 발송 요청 MESSAGE_SEQNO=SAME SERVICE_SEQNO=ONE
10:00:01[000] 결과 수신 MESSAGE_SEQNO=SAME SERVICE_SEQNO=TWO
10:00:02[000] MESSAGE_SEQNO=SAME RESPONSE_CODE=S
'''
    case,_,_,_=fixture(tmp_path,[('debug.log',text)])
    result=trace_messages(case,W,salt=b'x'*32)
    assert len(result['groups'])==2 and result['coverage']['missing_identity_records']==1
    assert all(g['request_to_result_seconds'] is None for g in result['groups'])


def test_trace_ambiguous_payload_and_bind_values_not_guessed(tmp_path):
    text='''10:00:00[000] MESSAGE_SEQNO=A MESSAGE_SEQNO=B SERVICE_SEQNO=X
10:00:01[000] BODY="MESSAGE_SEQNO=A SERVICE_SEQNO=X RESPONSE_CODE=S"
10:00:02[000] PSTMT.EQ parameters MESSAGE_SEQNO=? SERVICE_SEQNO=?
10:00:03[000] MESSAGE_SEQNO=A SERVICE_SEQNO=X RESPONSE_CODE=S failed
'''
    case,_,_,_=fixture(tmp_path,[('debug.log',text)])
    result=trace_messages(case,W)
    assert result['coverage']['ambiguous_records']==2
    assert result['unsupported_bind_records']==1 and len(result['groups'])==1
    assert result['groups'][0]['stages']==['acceptance_conflict']
    assert 'accepted' in result['groups'][0]['missing_stages']


def test_trace_filters_and_oversized_records(tmp_path):
    case,_,_,_=fixture(tmp_path,[('debug.log','10:00:00[000] MESSAGE_SEQNO=A SERVICE_SEQNO=X '+('z'*18000))])
    result=trace_messages(case,W)
    assert result['coverage']['oversized_records_skipped']==1 and result['groups']==[]
    with pytest.raises(ValueError):trace_messages(case,W,message='has spaces')
    with pytest.raises(ValueError):trace_messages(case,W,service='unsupported.character')


def test_trace_repeated_requests_no_arbitrary_latency(tmp_path):
    text='''10:00:00[000] 발송 요청 MESSAGE_SEQNO=A SERVICE_SEQNO=X
10:00:01[000] 발송 요청 MESSAGE_SEQNO=A SERVICE_SEQNO=X
10:00:02[000] 결과 수신 MESSAGE_SEQNO=A SERVICE_SEQNO=X
'''
    case,_,_,_=fixture(tmp_path,[('debug.log',text)])
    result=trace_messages(case,W,limit=1)
    assert result['omitted_records']==2 and result['groups'][0]['request_to_result_seconds'] is None
    assert result['groups'][0]['records']==3


def test_xml_optional_allowlisted_fields():
    data=b'''<?xml version="1.0" encoding="UTF-8"?><settings>
    <job name="DailyBatchJob" cron="0 0 1 * * ?"/>
    <property name="debug" value="false"/>
    <credential>SYNTHETIC_PRIVATE_PROSE</credential><endpoint>SYNTHETIC_PRIVATE_ENDPOINT</endpoint>
    <!-- AGENT_HA_CHECK reference -->
    </settings>'''
    parsed=parse_xml_reference(data)
    assert parsed['schedules'][0]['daily']=='01:00:00'
    assert parsed['debug_flags'][0]['enabled'] is False
    assert parsed['ha_mentions_in_comments']==1
    assert_no_private(parsed)


@pytest.mark.parametrize('data',[
 b'<!DOCTYPE x><x/>',b'<!ENTITY example "synthetic"><x/>',
 '<x>test</x>'.encode('utf-16'),b'<x>',b'<a>'*30+b'</a>'*30,
 b'<x>'+b'a'*5000+b'</x>',b'',
])
def test_unsupported_xml_rejected(data):
    with pytest.raises(ValueError):parse_xml_reference(data)


def test_xml_and_28_never_required_private_cas(tmp_path):
    case,m,_,_=fixture(tmp_path,[('job.log',job())],version='auto')
    assert quality(m)['version']=='auto' and timeline(case,m,W)['total']==1
    assert read_observations(case)=={}
    with pytest.raises(ValueError):save_observations(case,{'pid_status':'alive'},expected_revision=0)
    one=save_observations(case,{'reference_version':'2.8-reference'},expected_revision=0)
    assert one['reference_version']=='2.8-reference'
    with pytest.raises(ValueError,match='변경'):save_observations(case,{},expected_revision=0)
    assert _get_manifest(case)['agent_version']=='auto'
    from mpush_analyzer.lifecycle import delete_case
    delete_case(case,confirmation=case.name,workspace=case.parent)
    assert not case.exists()


def test_guidance_reply_keeps_facts_and_hypotheses_separate(tmp_path):
    case,m,_,_=fixture(tmp_path,[('job.log',job()),('err.log',CHAIN),('debug.log',heartbeat())])
    packet=guidance(window_stats(case,m,W),exception_groups(case,m,W),continuity(case,m,W),job_spans(case,m,W),m)
    assert packet['possible_causes'] and packet['additional_evidence']
    assert_no_private(packet)
    draft=reply_draft(packet)
    for section in ('관측 사실','원인 확정 아님','추가 확인','해석 한계'):assert section in draft
    assert '자동 생성 초안' in draft
    assert all(x['예시'].startswith(('ps ','ss ','SELECT ')) for x in packet['read_only_examples'])


def element(app,kind,label):
    return next(x for x in getattr(app,kind) if x.label==label)


def assert_app(app):
    assert not app.exception,[x.message for x in app.exception]


def test_investigation_screens_without_optional_xml(tmp_path):
    from streamlit.testing.v1 import AppTest
    from mpush_analyzer.investigation_ui import MODES
    case,m,_,_=fixture(tmp_path,[('job.log',job()),('err.log',CHAIN),('debug.log',heartbeat())])
    script=f'''from pathlib import Path
from mpush_analyzer.dashboard_data import read_result_bundle
from mpush_analyzer.workbench_ui import render_workbench
case=Path({str(case)!r})
manifest,result,matches=read_result_bundle(case)
render_workbench(case,manifest,result,matches)
'''
    app=AppTest.from_string(script,default_timeout=45).run();assert_app(app)
    app=element(app,'radio','분석 메뉴').set_value('장애 조사').run();assert_app(app)
    assert not app.error,[x.value for x in app.error]
    for mode in MODES[1:]:
        app=element(app,'selectbox','장애 조사 기능').set_value(mode).run();assert_app(app)
        assert not app.error,(mode,[x.value for x in app.error])


def test_trace_ui_consent_and_pseudonyms(tmp_path):
    from streamlit.testing.v1 import AppTest
    case,m,_,_=fixture(tmp_path,[('debug.log',trace_log()),('job.log',job(clock='09:30:00.000'))])
    script=f'''from pathlib import Path
from mpush_analyzer.investigation_ui import render_trace
from mpush_analyzer.pipeline import _get_manifest
from mpush_analyzer.investigation import Window
case=Path({str(case)!r})
render_trace(case,_get_manifest(case),Window('2026-11-02T09:30','2026-11-02T12:20'))
'''
    app=AppTest.from_string(script,default_timeout=40).run();assert_app(app)
    app=element(app,'button','메시지 흐름 조회').click().run();assert_app(app)
    assert app.warning
    element(app,'checkbox','해시 검증된 로컬 원본에서 식별 필드와 단계 표지를 조회합니다.').check()
    app=element(app,'button','메시지 흐름 조회').click().run();assert_app(app)
    assert any('message_' in x.value.to_string() for x in app.dataframe)
    assert all('MSG_A' not in x.value.to_string() for x in app.dataframe)


def test_optional_xml_crosscheck_not_runtime_claim():
    from mpush_analyzer.investigation_reference import crosscheck_config
    from mpush_analyzer.config_ini import parse_agent_ini
    config=parse_agent_ini('[AGENT]\ndebug=false\n[DBMS]\ntype=mysql\n')
    assert config['agent']['debug_enabled'] is False
    manifest={'files':[],'config_summary':config}
    parsed=parse_xml_reference(b'<config><job name="DAILY_BATCH_JOB" cron="0 0 1 * * ?"/></config>')
    rows=crosscheck_config(manifest,{'schedules':[{'job':'DAILY_BATCH_JOB','cron':'0 0 2 * * ?'}]},parsed)
    assert rows[-1]['해석'].startswith('복수/다른')
    assert crosscheck_config(manifest,{'schedules':[]})


def test_ui_comparison_runs_and_observations_save(tmp_path):
    from streamlit.testing.v1 import AppTest
    case,m,_,_=fixture(tmp_path,[('job.log',job())])
    script=f'''from pathlib import Path
from mpush_analyzer.pipeline import _get_manifest
from mpush_analyzer.investigation_ui import render_compare, render_reference
from mpush_analyzer.investigation import Window
case=Path({str(case)!r})
m=_get_manifest(case)
render_compare(case,m,Window('2026-11-02T10:00','2026-11-02T10:20'))
render_reference(case,m)
'''
    app=AppTest.from_string(script,default_timeout=40).run();assert_app(app)
    element(app,'text_input','기준 구간 시작 (KST)').set_value('2026-11-02T10:00')
    element(app,'text_input','기준 구간 종료 (KST)').set_value('2026-11-02T10:20')
    element(app,'checkbox','기준 시간대를 정상 구간으로 비교할 수 있음을 확인했습니다.').check()
    app=element(app,'button','동일 길이 구간 비교').click().run();assert_app(app)
    assert any('P95 배율' in table.value.columns for table in app.dataframe)
    element(app,'selectbox','PID 상태 (담당자 확인)').set_value('alive')
    element(app,'text_input','PID 확인 시각').set_value('2026-11-02T10:10:00')
    app=element(app,'button','운영 관측 저장').click().run();assert_app(app)
    assert read_observations(case)['pid_status']=='alive'


def test_sql_response_literal_does_not_become_acceptance(tmp_path):
    text="10:00:00[000] SELECT MESSAGE_SEQNO='A', SERVICE_SEQNO='X' WHERE RESPONSE_CODE='S'\n"
    case,m,_,_=fixture(tmp_path,[('dbwrap.log',text)])
    result=trace_messages(case,W)
    assert len(result['events'])==1
    assert result['events'][0]['stages']==['identifier_observed']
    assert result['events'][0]['observation_basis'].startswith('SQL')
    assert 'accepted' in result['groups'][0]['missing_stages']


def test_previous_analysis_requests_reanalysis_for_chain(tmp_path):
    case,m,_,_=fixture(tmp_path,[('err.log',CHAIN)])
    event_path=case/'events.jsonl'
    values=[json.loads(line) for line in event_path.read_text().splitlines()]
    for item in values:item['details'].pop('exception_chain',None)
    event_path.write_text('\n'.join(json.dumps(x) for x in values)+'\n')
    result=exception_groups(case,m,W)
    assert result['legacy_records']==1
    assert result['groups'][0]['chain']=='SQLTimeoutException'


def test_global_continuity_budget_explicitly_reports_omitted(tmp_path,monkeypatch):
    import mpush_analyzer.investigation as module
    case,m,_,_=fixture(tmp_path,[('debug.log',heartbeat())])
    monkeypatch.setattr(module,'MAX_CONTINUITY_RECORDS',3)
    result=continuity(case,m,W)
    assert result['streams'][0]['records']==3 and result['unprocessed_records']==4


def test_repeated_message_query_does_not_mutate_original(tmp_path):
    case,m,_,_=fixture(tmp_path,[('debug.log',trace_log())])
    original=case/'raw'/m['files'][0]['storage_name']
    before=original.read_bytes()
    one=trace_messages(case,Window('2026-11-02T09:30','2026-11-02T12:20'),message='MSG_A',service='SVC_A')
    assert len(one['groups'])==1
    assert original.read_bytes()==before
