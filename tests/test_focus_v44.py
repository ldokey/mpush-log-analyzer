"""Single-Agent simplification acceptance. Synthetic data, customer formats only."""
from datetime import date
from pathlib import Path
import hashlib
import json
import uuid

import pytest
from mpush_analyzer.parsers import parse_by_kind
from mpush_analyzer.error_semantics import describe_error
from mpush_analyzer.focus_analysis import focus_summary, classify
from mpush_analyzer.debug_lookup import search_debug, json_records
from mpush_analyzer.investigation import Window
from test_investigation_v42 import fixture, W, job

STACK='''10:12:00[012] [HttpClientTemplate] Connection execute error occured: Connect to synthetic.example.invalid:80 [synthetic.example.invalid/192.0.2.10] failed: connect timed out
10:12:00[013] devon.core.exception.LSysException: SYNTH_PRIVATE_BODY
 at agent.common.util.HttpClientTemplate.exchange2(HttpClientTemplate.java:261)
 at agent.common.util.WebServiceUtil.httpClientToTSMSHealthCheck(WebServiceUtil.java:324)
 at agent.jobs.biz.ServerConfCheckBiz.confCheck(ServerConfCheckBiz.java:32)
 at agent.jobs.agent.ServerConfCheckJob.runJob(ServerConfCheckJob.java:53)
Caused by: org.apache.http.conn.ConnectTimeoutException: Connect to synthetic.example.invalid:80 failed: connect timed out
 at org.apache.http.impl.conn.DefaultHttpClientConnectionOperator.connect(DefaultHttpClientConnectionOperator.java:134)
Caused by: java.net.SocketTimeoutException: connect timed out
 at java.net.PlainSocketImpl.socketConnect(Native Method)
 ... 14 more
'''
TABLE='''10:12:00[412] RESPONSE_CODE : S>>>>>>>>> [LMultiData Result]------------------------
|{index}|messageSeqno|serviceSeqno|fileName|DB_MSG_TBL|SCHEMA|resendFlag|messageType|
----------------------
| 0 | SYNTH_M | SYNTH_S | SYNTH_PRIVATE_FILE |SYNTH_PRIVATE_TABLE|SYNTH_PRIVATE_SCHEMA|N|R00|
----------------------
[Total Row Size ] = 1
'''


def lookup(tmp_path,text,**kwargs):
    c,m,_,_=fixture(tmp_path,[('20261102debug.log',text)])
    return search_debug(c,W,message='SYNTH_M',salt=b'x'*32,**kwargs)


@pytest.mark.parametrize('kind',['err','debug','info'])
def test_uploaded_stack_shape_gets_actionable_title_and_workflow(kind):
    rows=list(parse_by_kind(kind,enumerate(STACK.splitlines(),1)))
    assert len(rows)==1
    d=rows[0].data;summary=describe_error(d)
    assert summary['title']=='헬스체크 중 서버 연결 시간 초과'
    assert summary['ports']==[80] and summary['operation']=='설정 확인·헬스체크'
    assert '80번 포트' in summary['fact']
    assert summary['deepest_exception']=='SocketTimeoutException'
    assert 'LSysException' in summary['chain'] and 'ConnectTimeoutException' in summary['chain']
    assert '확정' in summary['limit'] and '방화벽' in summary['check']
    assert 'SYNTH_PRIVATE' not in json.dumps(d) and '192.0.2.10' not in json.dumps(d)
    assert rows[0].start_line==1 and rows[0].end_line==11


@pytest.mark.parametrize('text,code',[
 ('Connection execute error occured: Connect to target.invalid:80 failed: connect timed out','connect_timeout'),
 ('java.net.SocketTimeoutException: Read timed out','read_timeout'),
 ('java.net.SocketTimeoutException: connect timed out','connect_timeout'),
 ('org.apache.http.conn.ConnectionPoolTimeoutException: Timeout waiting for connection from pool','pool_timeout'),
 ('java.net.ConnectException: Connection refused','connection_refused'),
 ('java.net.UnknownHostException: hidden.invalid','dns_failure'),
 ('javax.net.ssl.SSLHandshakeException: certificate verify failed','tls_failure'),
 ('java.sql.SQLException: ORA-00060 deadlock detected','db_deadlock'),
 ('java.sql.SQLException: ORA-01017 private credential','db_auth'),
 ('java.sql.SQLSyntaxErrorException: hidden query','db_syntax'),
 ('java.lang.OutOfMemoryError: Java heap space','memory_exhausted'),
 ('java.io.IOException: No space left on device','disk_full'),
 ('java.io.IOException: Permission denied','permission_denied'),
 ('java.net.SocketTimeoutException: unknown context','unclassified'),
 ('devon.core.exception.LSysException: generic wrapper','unclassified'),
])
def test_reason_categories_do_not_collapse_to_unspecified(text,code):
    rows=list(parse_by_kind('err',[(1,'10:12:00[000] '+text)]))
    assert len(rows)==1 and describe_error(rows[0].data)['code']==code


def test_unrelated_error_after_delay_not_attached():
    raw=STACK.splitlines()[0]+'\n'+STACK[STACK.index('10:12:00[013]'):].replace('10:12:00[013]','10:12:03[013]')
    rows=list(parse_by_kind('err',enumerate(raw.splitlines(),1)))
    assert len(rows)==2


def test_repeated_error_group_and_noise_are_separate(tmp_path):
    db=''.join(f'10:11:{i:02d}[000]\nNO_ID_{i}=PSTMT.EQ Laptime : 3\nNO_ID_{i}=SELECT SOME_COLUMN FROM SYNTH_TABLE\nNO_ID_{i}=Result : select completed.\n' for i in range(10))
    c,m,_,_=fixture(tmp_path,[('err.log',STACK+STACK.replace('10:12:00','10:13:00')),('dbwrap.log',db),('job.log',job(duration=.2,targets=0)+job(clock='10:14:00.000',duration=20,targets=0))])
    s=focus_summary(c,m,W)
    assert len(s['errors'])==1 and s['error_records']==2
    assert s['errors'][0]['count']==2 and s['folded_selects']==10
    assert s['counts']['zero_target_job']==1 and s['counts']['job_slow']==1
    assert s['slow_or_failed']==1 and '반환행 0건' in s['note']
    assert len(s['attention_rows'])==1


@pytest.mark.parametrize('details,status,expected',[
 ({'sql_operation':'SELECT','outcome':'select_completed','laptime_ms':1},'complete','routine_select'),
 ({'sql_operation':'SELECT','outcome':'select_completed','laptime_ms':1000},'complete','db_slow'),
 ({'sql_operation':'SELECT','outcome':'failed','laptime_ms':1},'complete','db_failed'),
 ({'sql_operation':'UPDATE','outcome':'rows_affected','affected_rows':0,'laptime_ms':1},'complete','db_other'),
 ({'sql_operation':'SELECT','outcome':'unknown','laptime_ms':1},'complete','db_other'),
 ({'sql_operation':'SELECT','outcome':'select_completed','laptime_ms':None},'complete','db_other'),
 ({'sql_operation':'SELECT','outcome':'select_completed','laptime_ms':1},'incomplete','db_incomplete'),
])
def test_sql_folding_keeps_failures_delays_unknown_and_writes(details,status,expected):
    assert classify({'event_type':'sql_execution','status':status,'details':details})==expected


@pytest.mark.parametrize('value',[-1,0,True,float('nan'),float('inf')])
def test_threshold_validation(tmp_path,value):
    c,m,_,_=fixture(tmp_path,[('job.log',job())])
    with pytest.raises(ValueError):focus_summary(c,m,W,slow_sql_ms=value)


def test_lmultidata_acceptance_table_not_final_success(tmp_path):
    out=lookup(tmp_path,TABLE,service='SYNTH_S')
    assert out['total_matches']==1 and out['formats']=={'table':1}
    r=out['rows'][0]
    assert r['request_accepted'] and not r['result_received'] and not r['final_result_eligible']
    assert r['status']=='request_accepted' and r['header_line']==2 and r['ref']['line_start']==4
    assert not any(x in json.dumps(out) for x in ['SYNTH_M','SYNTH_S','SYNTH_PRIVATE'])


@pytest.mark.parametrize('key',['MESSAGE_SEQNO','messageSeqno','message_seqno'])
def test_native_identifiers_and_optional_service(tmp_path,key):
    out=lookup(tmp_path,f'10:12:00[000] [{key} : SYNTH_M]\n',service='SYNTH_S')
    assert out['total_matches']==1
    assert out['rows'][0]['service_scope']=='unconfirmed' and out['rows'][0]['service'] is None
    assert not out['rows'][0]['final_result_eligible']


def test_confirmed_service_mismatch_excluded_missing_service_kept(tmp_path):
    raw=TABLE+'10:12:01[000] MESSAGE_SEQNO=SYNTH_M\n'
    out=lookup(tmp_path,raw,service='OTHER_SERVICE')
    assert out['total_matches']==1 and out['coverage']['service_mismatch']==1
    assert out['rows'][0]['service_scope']=='unconfirmed'


def test_agent_message_identifier_never_conflated(tmp_path):
    raw='10:12:00[000] AGENT_MESSAGE_SEQNO=SYNTH_M SERVICE_SEQNO=SYNTH_S\n'
    assert lookup(tmp_path,raw)['total_matches']==0
    assert lookup(tmp_path/'agent',raw,identifier_field='AGENT_MESSAGE_SEQNO')['total_matches']==1


def test_json_with_payload_keeps_only_outer_identity_and_result(tmp_path):
    raw='10:12:00[123] 결과 수신 완료 '+json.dumps({'messageSeqno':'SYNTH_M','serviceSeqno':'SYNTH_S','SEND_RESULT_CODE1':'OK','SEND_MESSAGE':'SELECT MESSAGE_SEQNO=FORGED_ID result received SEND_RESULT_CODE1=OK SYNTH_PRIVATE_BODY'})+'\n'
    out=lookup(tmp_path,raw)
    assert out['total_matches']==1 and out['rows'][0]['primary']['state']=='success'
    assert out['rows'][0]['final_result_eligible']
    assert 'SYNTH_PRIVATE' not in json.dumps(out) and 'FORGED_ID' not in json.dumps(out)


@pytest.mark.parametrize('raw',[
 '10:12:00[000] {"BODY":"MESSAGE_SEQNO=SYNTH_M SERVICE_SEQNO=SYNTH_S result received SEND_RESULT_CODE1=OK"}\n',
 '10:12:00[000] BODY="MESSAGE_SEQNO=SYNTH_M SERVICE_SEQNO=SYNTH_S result received SEND_RESULT_CODE1=OK"\n',
 '10:12:00[000] {"CONTENT":{"MESSAGE_SEQNO":"SYNTH_M","SERVICE_SEQNO":"SYNTH_S"}}\n',
 '10:12:00[000] SELECT MESSAGE_SEQNO=SYNTH_M SERVICE_SEQNO=SYNTH_S WHERE SEND_RESULT_CODE1=OK\n',
 '10:12:00[000] MESSAGE_SEQNO=SYNTH_M MESSAGE_SEQNO=OTHER SERVICE_SEQNO=SYNTH_S\n',
 '10:12:00[000] {"MESSAGE_SEQNO":"SYNTH_M","MESSAGE_SEQNO":"OTHER","SERVICE_SEQNO":"SYNTH_S"}\n',
 '10:12:00[000] {"messageSeqno":"SYNTH_M","MESSAGE_SEQNO":"OTHER","SERVICE_SEQNO":"SYNTH_S"}\n',
])
def test_payload_sql_ambiguous_not_a_false_match(tmp_path,raw):
    assert lookup(tmp_path,raw)['total_matches']==0


def test_json_body_cannot_invent_result_context(tmp_path):
    raw='10:12:00[000] '+json.dumps({'MESSAGE_SEQNO':'SYNTH_M','SERVICE_SEQNO':'SYNTH_S','SEND_RESULT_CODE1':'OK','BODY':'result received'})+'\n'
    r=lookup(tmp_path,raw)['rows'][0]
    assert not r['result_received'] and not r['final_result_eligible']


def test_long_table_after_200_rows_remains_searchable(tmp_path):
    raw='10:12:00[123] RESPONSE_CODE : S>>>> [LMultiData Result]\n|{index}|messageSeqno|serviceSeqno|\n'+''.join(f'|{i}|SYNTH_{i}|SYNTH_S|\n' for i in range(1000))+'|1000|SYNTH_M|SYNTH_S|\n[Total Row Size ] = 1001\n'
    out=lookup(tmp_path,raw)
    assert out['total_matches']==1 and out['rows'][0]['ref']['line_start']==1003


def test_table_empty_service_preserved(tmp_path):
    raw='10:12:00[123] [LMultiData Result]\n|{index}|messageSeqno|serviceSeqno|\n|0|SYNTH_M||\n'
    out=lookup(tmp_path,raw,service='SYNTH_S')
    assert out['total_matches']==1 and out['rows'][0]['service_scope']=='unconfirmed'


def test_invalid_or_shifted_table_does_not_pair_wrong_values(tmp_path):
    raw='10:12:00[123] [LMultiData Result]\n|{index}|messageSeqno|serviceSeqno|\n|0|SYNTH_M|SYNTH_S|EXTRA|\n'
    assert lookup(tmp_path,raw)['total_matches']==0


def test_request_acceptance_and_result_evidence_remain_distinct(tmp_path):
    raw=TABLE+'10:12:02[000] 결과 수신 완료 MESSAGE_SEQNO=SYNTH_M SERVICE_SEQNO=SYNTH_S SEND_RESULT_CODE1=E101 SEND_RESULT_CODE2=OK\n'
    out=lookup(tmp_path,raw)
    assert out['total_matches']==2
    assert out['rows'][0]['status']=='request_accepted'
    assert out['rows'][1]['status']=='result_success' and out['rows'][1]['primary']['state']=='failure'


def test_conflicting_outcomes_not_last_value_wins(tmp_path):
    raw='10:12:01[000] 결과 수신 완료 MESSAGE_SEQNO=SYNTH_M SERVICE_SEQNO=SYNTH_S SEND_RESULT_CODE1=OK\n10:12:02[000] 결과 수신 완료 MESSAGE_SEQNO=SYNTH_M SERVICE_SEQNO=SYNTH_S SEND_RESULT_CODE1=E101\n'
    out=lookup(tmp_path,raw)
    assert out['conflicting_messages']==1 and out['total_matches']==2


def test_dbwrap_excluded_secondary_opt_in(tmp_path):
    raw='10:12:01[000] MESSAGE_SEQNO=SYNTH_M SERVICE_SEQNO=SYNTH_S\n'
    c,m,_,_=fixture(tmp_path,[('dbwrap.log',raw),('info.log',raw+'10:12:02[000] Started\n')])
    assert search_debug(c,W,message='SYNTH_M')['total_matches']==0
    s=search_debug(c,W,message='SYNTH_M',include_secondary=True)
    assert s['total_matches']==1 and s['sources']==['file_02']


def test_clock_only_message_found_without_guessing_date(tmp_path):
    raw='10:12:00[000] messageSeqno : SYNTH_M\n'
    c,m,_,_=fixture(tmp_path,[('debug.log',raw)],reference=None)
    r=search_debug(c,None,message='SYNTH_M')
    assert r['total_matches']==1 and r['rows'][0]['undated'] and r['rows'][0]['ref']['occurred_at'] is None
    assert search_debug(c,W,message='SYNTH_M',include_undated=False)['total_matches']==0


def test_bounds_and_display_limit_are_explicit(tmp_path):
    raw=''.join(f'10:12:{i:02d}[000] messageSeqno : SYNTH_M\n' for i in range(10))
    out=lookup(tmp_path,raw,limit=3)
    assert out['total_matches']==10 and len(out['rows'])==3 and out['omitted']==7


def test_source_hash_verified_before_and_after_search(tmp_path):
    c,m,_,_=fixture(tmp_path,[('debug.log',TABLE)])
    before={str(p.relative_to(c)):hashlib.sha256(p.read_bytes()).hexdigest() for p in c.rglob('*') if p.is_file()}
    search_debug(c,W,message='SYNTH_M')
    assert before=={str(p.relative_to(c)):hashlib.sha256(p.read_bytes()).hexdigest() for p in c.rglob('*') if p.is_file()}
    p=next((c/'raw').iterdir());p.write_bytes(p.read_bytes()+b'changed')
    with pytest.raises(ValueError):search_debug(c,W,message='SYNTH_M')


@pytest.mark.parametrize('kw',[{'message':''},{'message':'../x'},{'service':'a b'},{'identifier_field':'MESSAGE_ID'},{'include_secondary':'true'},{'limit':True},{'limit':0},{'salt':b'x'}])
def test_search_argument_validation(tmp_path,kw):
    c,m,_,_=fixture(tmp_path,[('debug.log',TABLE)])
    with pytest.raises(ValueError):search_debug(c,W,**({'message':'SYNTH_M'}|kw))


def test_focus_payload_has_authorized_error_and_lookup_references(tmp_path):
    from mpush_analyzer.diagnostics_ui import make_payload,validate_action
    from mpush_analyzer.diagnostics import diagnose_jobs,backlog_observations
    c,m,_,_=fixture(tmp_path,[('err.log',STACK),('debug.log',TABLE),('job.log',job())])
    p=make_payload(diagnose_jobs(c,m,W),None,backlog_observations([]),focus=focus_summary(c,m,W),lookup=search_debug(c,W,message='SYNTH_M'))
    assert any(r['file_id']=='file_01' for r in p['references'])
    assert any(r['file_id']=='file_02' and r['line_start']==2 for r in p['references'])
    assert 'SYNTH_PRIVATE' not in json.dumps(p)
    event={'action':'all_evidence','revision':p['revision'],'nonce':str(uuid.uuid4())}
    assert validate_action(event,p)['action']=='all_evidence'


def test_stitch_focus_css_is_exactly_preserved():
    root=Path(__file__).resolve().parents[1]
    p=json.loads((root/'docs/STITCH_V4_4_PROVENANCE.json').read_text())
    raw=(root/'mpush_analyzer/diagnostics_web/focus-design.css').read_bytes()
    assert hashlib.sha256(raw).hexdigest()==p['sources']['focus']['css_sha256']
    assert p['device']=='DESKTOP'


def test_first_page_is_upload_and_other_pages_are_lazy(monkeypatch):
    from streamlit.testing.v1 import AppTest
    import mpush_analyzer.support_ui as support
    import mpush_analyzer.dashboard_data as data
    def must_not_run(*a,**k):raise AssertionError('Unselected page was executed')
    monkeypatch.setattr(support,'render_support',must_not_run)
    monkeypatch.setattr(data,'read_result_bundle',must_not_run)
    at=AppTest.from_file(str(Path(__file__).resolve().parents[1]/'app.py'),default_timeout=60).run()
    assert not at.exception,[e.message for e in at.exception]
    nav=next(x for x in at.radio if x.label=='업무 단계')
    assert nav.value=='1 자료 가져오기' and nav.options==['1 자료 가져오기','2 분석 결과','3 문의·기록','4 내보내기']
    assert len(at.get('file_uploader'))==1
    assert not any(x.label=='Agent 구분 (필수)' for x in at.text_input)


def test_new_default_analysis_has_no_external_baseline_or_agent_selector(tmp_path,monkeypatch):
    from streamlit.testing.v1 import AppTest
    import mpush_analyzer.lifecycle as lifecycle
    import mpush_analyzer.diagnostics_ui as ui
    c,m,_,_=fixture(tmp_path,[('err.log',STACK),('debug.log',TABLE),('job.log',job())])
    seen={};monkeypatch.setattr(lifecycle,'list_cases',lambda _:[c]);monkeypatch.setattr(ui,'_component',lambda **kw:seen.update(kw))
    at=AppTest.from_file(str(Path(__file__).resolve().parents[1]/'app.py'),default_timeout=60).run()
    at=next(x for x in at.radio if x.label=='업무 단계').set_value('2 분석 결과').run()
    assert not at.exception,[e.message for e in at.exception]
    assert seen['payload']['focus']['errors'][0]['title']=='헬스체크 중 서버 연결 시간 초과'
    assert not any(x.label=='정상 기준 분석 (선택)' for x in at.selectbox)
    assert not any(x.label=='분석 메뉴' for x in at.radio)
    next(x for x in at.text_input if x.label=='MESSAGE_SEQNO (필수)').set_value('SYNTH_M')
    next(x for x in at.text_input if x.label=='SERVICE_SEQNO (선택)').set_value('SYNTH_S')
    next(x for x in at.checkbox if x.label=='원본을 로컬에서 읽어 메시지 번호를 검색합니다.').check()
    at=next(x for x in at.button if x.label=='debug에서 찾기').click().run()
    assert not at.exception,[e.message for e in at.exception]
    assert seen['payload']['lookup']['total_matches']==1


def test_masked_error_evidence_displays_connection_reason_not_endpoint():
    from mpush_analyzer.source_view import masked_line
    text,masked=masked_line(STACK.splitlines()[0])
    assert masked and '서버 연결 시간 초과' in text and '80번 포트' in text
    assert 'synthetic.example.invalid' not in text and '192.0.2.10' not in text


def test_legacy_ui_no_ha_or_external_baseline_controls():
    source=(Path(__file__).resolve().parents[1]/'mpush_analyzer/investigation_ui.py').read_text()
    assert "st.selectbox('정상 기준 분석 작업'" not in source
    assert "'항목':'HA 사용 설정'" not in source


@pytest.mark.parametrize('payload',[
 '10:12:00[000] SEND_MESSAGE="java.net.SocketTimeoutException: connect timed out"',
 '10:12:00[000] {"MESSAGE_SEQNO":"SYNTH_M","BODY":"LSysException connect timed out"}',
])
def test_message_body_does_not_create_false_error(payload):
    from mpush_analyzer.exception_chain import has_exception
    from mpush_analyzer.error_semantics import observed_semantics
    assert not has_exception(payload)
    assert not observed_semantics([(1,payload)])['reason_codes']


def test_failure_before_payload_is_not_lost():
    from mpush_analyzer.exception_chain import chain_details
    d=chain_details([(1,'10:12:00[000] java.net.SocketTimeoutException: connect timed out BODY="Read timed out secret"')])
    assert d['reason_codes']==['connect_timeout']


def test_many_errors_do_not_hide_later_slow_job(tmp_path,monkeypatch):
    import mpush_analyzer.focus_analysis as mod
    monkeypatch.setattr(mod,'MAX_ROWS',2)
    c,m,_,_=fixture(tmp_path,[('err.log',STACK*10),('job.log',job(clock='10:15:00.000',duration=20))])
    result=focus_summary(c,m,W)
    assert result['error_records']==10
    assert len(result['attention_rows'])==1 and result['attention_rows'][0]['category']=='job_slow'
