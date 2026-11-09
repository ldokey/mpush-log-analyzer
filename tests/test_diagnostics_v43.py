"""V4.3 regression and negative cases. All input is synthetic, isolated by tmp_path."""
from datetime import timedelta
import copy
import hashlib
import json
from pathlib import Path
import uuid

import pytest

from mpush_analyzer.diagnostics import diagnose_jobs, DiagnosticPolicy, backlog_observations
from mpush_analyzer.investigation import Window, instant, iso
from mpush_analyzer.message_outcomes import trace_outcomes, _result_fields
from test_investigation_v42 import fixture, job, W

BASE=Window('2026-11-02T09:40:00','2026-11-02T10:00:00')
NAME='SEND_REAL_FILE_IMAGE'
SALT=b'x'*32


def line(text,clock='10:01:00',msg='SYNTH_MESSAGE_1',svc='SYNTH_SERVICE_1'):
    return f'{clock}[000] MESSAGE_SEQNO={msg} SERVICE_SEQNO={svc} {text}\n'


def trace(tmp_path,text,**kwargs):
    case,m,_,_=fixture(tmp_path,[('debug.log',text)])
    return trace_outcomes(case,W,salt=SALT,**kwargs)


def events_case(tmp_path,events,**kwargs):
    case,m,_,_=fixture(tmp_path,[('job.log',job())],**kwargs)
    rows=[]
    for i,e in enumerate(events,1):
        e=copy.deepcopy(e);e.setdefault('file_id','file_01');e.setdefault('event_id',f'e{i}');e.setdefault('log_kind','job')
        e.setdefault('line_start',i);e.setdefault('line_end',i);e.setdefault('status','complete')
        rows.append(json.dumps(e))
    (case/'events.jsonl').write_text('\n'.join(rows)+'\n' if rows else '')
    return case,m


def ev(seconds=0,kind='job_run',duration=1,target=10,name=NAME,file_id='file_01',**details):
    return {'occurred_at':iso(instant('2026-11-02T10:00:00')+timedelta(seconds=seconds)),
            'event_type':kind,'file_id':file_id,
            'details':{'job_name':name,'duration_seconds':duration,'target_count':target,**details}}


def baseline_pair(tmp_path):
    base,bm=events_case(tmp_path/'base',[ev(i*10-1200,duration=2) for i in range(6)])
    now,nm=events_case(tmp_path/'now',[ev(i,duration=40 if i==100 else 2) for i in [0,10,20,30,40,100]])
    return now,nm,base,bm


def test_baseline_period_gap_and_spike(tmp_path):
    now,nm,base,bm=baseline_pair(tmp_path)
    r=diagnose_jobs(now,nm,W,baseline_case=base,baseline_manifest=bm,baseline_window=BASE,same_agent_confirmed=True)
    d=r['jobs'][0]
    assert d['cadence_seconds']==10 and d['cadence_basis']=='baseline'
    assert d['gap_count']==1 and d['gaps'][0]['seconds']==60
    assert d['gaps'][0]['interval_slots_estimate']==5
    assert d['current']['delay_count']==1 and d['current']['delay_basis']=='baseline_p95'
    assert d['current']['delay_threshold']==10
    assert d['status']=='attention' and r['window']['start'].endswith('+09:00')


def test_running_cluster_split_by_completed_record(tmp_path):
    rows=[ev(i,kind='job_running_skip') for i in [0,10,20]]+[ev(25)]+[ev(i,kind='job_running_skip') for i in [30,40]]
    case,m=events_case(tmp_path,rows)
    d=diagnose_jobs(case,m,W)['jobs'][0]
    assert d['current']['running_skips']==5 and d['running_cluster_count']==1
    assert d['running_clusters'][0]['count']==3


def test_no_baseline_absolute_delay_not_spike(tmp_path):
    case,m=events_case(tmp_path,[ev(duration=20)])
    d=diagnose_jobs(case,m,W)['jobs'][0]
    assert d['current']['delay_basis']=='absolute' and d['gap_evaluated_streams']==0
    assert d['p95_ratio'] is None


def test_small_baseline_not_used_for_relative_spike(tmp_path):
    a,am=events_case(tmp_path/'a',[ev(-1200,duration=1)])
    b,bm=events_case(tmp_path/'b',[ev(duration=20)])
    r=diagnose_jobs(b,bm,W,baseline_case=a,baseline_manifest=am,baseline_window=BASE,same_agent_confirmed=True)
    assert r['jobs'][0]['current']['delay_basis']=='absolute'


@pytest.mark.parametrize('mode',['unconfirmed','missing','unequal','overlap'])
def test_baseline_comparison_guard(tmp_path,mode):
    case,m=events_case(tmp_path,[ev()])
    args={'baseline_case':case,'baseline_manifest':m,'baseline_window':BASE,'same_agent_confirmed':True}
    if mode=='unconfirmed':args['same_agent_confirmed']=False
    if mode=='missing':args['baseline_manifest']=None
    if mode=='unequal':args['baseline_window']=Window(BASE.start,'2026-11-02T09:50:00')
    if mode=='overlap':args['baseline_window']=W
    with pytest.raises(ValueError):diagnose_jobs(case,m,W,**args)


def test_no_cross_file_gap(tmp_path):
    case,m,_,_=fixture(tmp_path,[('job.log',job()),('other_job.log',job(duration=2))])
    rows=[ev(i) for i in range(0,60,10)]+[ev(i,file_id='file_02') for i in range(600,660,10)]
    for i,e in enumerate(rows,1):e.update({'line_start':i,'line_end':i,'status':'complete','log_kind':'job'})
    (case/'events.jsonl').write_text(''.join(json.dumps(e)+'\n' for e in rows))
    d=diagnose_jobs(case,m,W)['jobs'][0]
    assert d['gap_count']==0 and d['gap_evaluated_streams']==2


def test_truncated_sequence_is_not_reported_complete(tmp_path,monkeypatch):
    import mpush_analyzer.diagnostics as mod
    monkeypatch.setattr(mod,'MAX_RECORDS',4)
    case,m=events_case(tmp_path,[ev(i) for i in [0,10,20,30,40,200]])
    r=diagnose_jobs(case,m,W);d=r['jobs'][0]
    assert d['current']['records']==6 and d['sequence_records_omitted']==2
    assert d['gap_evaluated_streams']==0 and r['warnings']


def test_percentile_cap_never_uses_prefix_as_population(tmp_path,monkeypatch):
    import mpush_analyzer.investigation as mod
    monkeypatch.setattr(mod,'MAX_SAMPLES',3)
    case,m=events_case(tmp_path,[ev(i,duration=i+1) for i in range(5)])
    d=diagnose_jobs(case,m,W)['jobs'][0]['current']['duration']
    assert d['samples']==5 and d['mean']==3 and d['max']==5
    assert d['p95'] is None and d['percentiles_unavailable']


def test_throughput_uses_same_valid_pairs_not_mean(tmp_path):
    rows=[ev(0,duration=1,target=100),ev(10,duration=9,target=90),ev(20,duration=None,target=1000),ev(30,duration=0,target=200),ev(40,duration=3,target=None)]
    case,m=events_case(tmp_path,rows);c=diagnose_jobs(case,m,W)['jobs'][0]['current']
    assert c['execution_target_rate']==19
    assert c['targets']==1390 and c['window_target_rate']==1390/1200
    assert c['paired_samples']==2 and c['paired_seconds']==10


@pytest.mark.parametrize('bad',[None,-1,True,float('nan'),float('inf'),'100',1.5])
def test_invalid_target_values_not_counted(tmp_path,bad):
    case,m=events_case(tmp_path,[ev(target=bad)])
    c=diagnose_jobs(case,m,W)['jobs'][0]['current']
    assert c['targets'] is None and c['execution_target_rate'] is None


def test_bucket_missing_vs_recorded_zero_and_last_span(tmp_path):
    case,m=events_case(tmp_path,[ev(0,target=0),ev(80,target=100)])
    r=diagnose_jobs(case,m,Window(W.start,'2026-11-02T10:01:30'))
    buckets=r['jobs'][0]['current']['buckets']
    assert buckets[0]['target_rate']==0 and buckets[1]['seconds']==30 and buckets[1]['target_rate']==100/30
    wider=diagnose_jobs(case,m,W)['jobs'][0]['current']['buckets']
    assert wider[2]['target_rate'] is None


def test_bucket_adapts_for_31days(tmp_path):
    case,m=events_case(tmp_path,[ev()])
    r=diagnose_jobs(case,m,Window('2026-11-01T00:00','2026-12-02T00:00'))
    assert len(r['jobs'][0]['current']['buckets'])<=600 and r['bucket_seconds']>60


def test_baseline_only_job_is_missing_not_zero(tmp_path):
    a,am=events_case(tmp_path/'a',[ev(-1200)])
    b,bm=events_case(tmp_path/'b',[ev(name='RECEIVE_RESULT')])
    r=diagnose_jobs(b,bm,W,baseline_case=a,baseline_manifest=am,baseline_window=BASE,same_agent_confirmed=True)
    d=next(d for d in r['jobs'] if d['name']==NAME)
    assert d['current'] is None and d['status']=='not_observed'


def test_empty_unknown_time_and_partial(tmp_path):
    e=ev();e['occurred_at']=None
    case,m=events_case(tmp_path,[e],partial=('job.log',))
    r=diagnose_jobs(case,m,W)
    assert not r['jobs'] and r['undated_excluded']==1 and r['coverage']['nonfull_files']


def test_half_open_timezone_and_invalid_range(tmp_path):
    case,m=events_case(tmp_path,[ev(0),ev(1200)])
    r=diagnose_jobs(case,m,Window('2026-11-02T01:00:00Z','2026-11-02T01:20:00Z'))
    assert r['jobs'][0]['current']['records']==1
    with pytest.raises(ValueError):diagnose_jobs(case,m,Window('2026-11-01T00:00','2027-01-01T00:00'))


@pytest.mark.parametrize('kw',[{'spike_ratio':float('nan')},{'spike_ratio':0},{'absolute_delay_seconds':0},{'running_repeat_count':True},{'minimum_baseline_samples':1}])
def test_invalid_policy(kw):
    with pytest.raises(ValueError):DiagnosticPolicy(**kw).validate()


@pytest.mark.parametrize('text,status',[
 ('result received SEND_RESULT_CODE1=OK','original_success'),
 ('result received SEND_RESULT_CODE1=1000','original_failure_unresolved'),
 ('result received SEND_RESULT_CODE1=E101 BACKUP_PROCESS_CODE=003','final_failure'),
 ('result received SEND_RESULT_CODE1=E101 SEND_RESULT_CODE2=OK','fallback_success'),
 ('result received SEND_RESULT_CODE1=E101 SEND_RESULT_CODE2=E102','final_failure'),
 ('RESPONSE_CODE=S SEND_FLAG=Y','accepted_unresolved'),
 ('SEND_RESULT_CODE1=OK','unknown'),
 ('result received SEND_RESULT_CODE1=PENDING','unknown'),
 ('결과 수신 완료 SEND_RESULT_CODE1=OK SEND_RESULT_CODE2=NULL','original_success'),
 ('result received SEND_RESULT_CODE1=ODD_PRIVATE_PROSE SEND_RESULT_CODE2=OK','fallback_success'),
 ('result received SEND_RESULT_CODE1=E101 SEND_RESULT_CODE2=ODD_PRIVATE_PROSE BACKUP_PROCESS_CODE=003','original_failure_unresolved'),
 ('result received SEND_RESULT_CODE1=E101 BACKUP_PROCESS_CODE=UNKNOWN_POLICY','original_failure_unresolved'),
 ('file creation failed','stage_failure_unresolved'),
 ('결과 수신 실패 SEND_RESULT_CODE1=OK','stage_failure_unresolved'),
 ('결과 수신 시작 SEND_RESULT_CODE1=OK','unknown'),
])
def test_message_outcome_semantics(tmp_path,text,status):
    r=trace(tmp_path,line(text));g=r['groups'][0]
    assert g['status']==status
    assert 'SYNTH_MESSAGE_1' not in json.dumps(r) and 'SYNTH_SERVICE_1' not in json.dumps(r)
    assert 'ODD_PRIVATE_PROSE' not in json.dumps(r) and 'UNKNOWN_POLICY' not in json.dumps(r)


def test_conflicts_and_pending_resolution(tmp_path):
    r=trace(tmp_path,line('result received SEND_RESULT_CODE1=OK')+line('result received SEND_RESULT_CODE1=E101','10:02:00'))
    assert r['summary']['conflict']==1 and r['summary']['observed_success_percent'] is None
    r=trace(tmp_path/'p',line('result received SEND_RESULT_CODE1=PENDING')+line('result received SEND_RESULT_CODE1=OK','10:02:00'))
    assert r['summary']['success']==1


@pytest.mark.parametrize('payload',[
 'SELECT MESSAGE_SEQNO=ABC SERVICE_SEQNO=XYZ WHERE SEND_RESULT_CODE1=OK result received',
 'SEND_MESSAGE="MESSAGE_SEQNO=ABC SERVICE_SEQNO=XYZ result received SEND_RESULT_CODE1=OK"',
 'BODY="MESSAGE_SEQNO=ABC SERVICE_SEQNO=XYZ result received SEND_RESULT_CODE1=OK"',
 'MESSAGE_SEQNO=ABC MESSAGE_SEQNO=OTHER SERVICE_SEQNO=XYZ result received SEND_RESULT_CODE1=OK',
 'MESSAGE_SEQNO=ABC result received SEND_RESULT_CODE1=OK',
])
def test_sql_payload_ambiguous_missing_never_success(tmp_path,payload):
    r=trace(tmp_path,'10:01:00[000] '+payload+'\n')
    assert r['summary']['success']==0


def test_dbwrap_result_literal_not_delivery(tmp_path):
    case,_,_,_=fixture(tmp_path,[('dbwrap.log',line('result received SEND_RESULT_CODE1=OK'))])
    r=trace_outcomes(case,W,salt=SALT)
    assert not r['summary']['success'] and r['coverage']['sql_predicate_records']==1


def test_services_identity_and_filters(tmp_path):
    text=line('result received SEND_RESULT_CODE1=OK',svc='SYNTH_A')+line('result received SEND_RESULT_CODE1=OK','10:02:00',svc='SYNTH_B')
    r=trace(tmp_path,text)
    assert r['summary']['unique_messages']==2 and len({g['service'] for g in r['groups']})==2
    assert trace(tmp_path/'f',text,service='SYNTH_A')['summary']['unique_messages']==1


def test_duplicate_observations_not_double_messages(tmp_path):
    r=trace(tmp_path,line('result received SEND_RESULT_CODE1=OK')*2)
    assert r['summary']['success']==1 and r['groups'][0]['result_count']==2


def test_latency_only_unique_request_result(tmp_path):
    text=line('send request')+line('result received SEND_RESULT_CODE1=OK','10:02:00')
    assert trace(tmp_path,text)['groups'][0]['request_to_result_seconds']==60
    assert trace(tmp_path/'d',text+line('send request','10:03:00'))['groups'][0]['request_to_result_seconds'] is None


def test_stage_mix_and_missing_not_failed(tmp_path):
    text=line('file creation completed')+line('file creation failed','10:02:00')
    g=trace(tmp_path,text)['groups'][0]
    assert g['stages']['file']=='mixed' and g['stages']['claim']=='unobserved'


def test_truncated_raw_record_not_inferred(tmp_path):
    text=line('result received SEND_RESULT_CODE1=OK '+('Z'*20000))
    r=trace(tmp_path,text)
    assert not r['summary']['success'] and r['coverage']['oversized_records']>=1


def test_outcomes_detail_limit_keeps_aggregate(tmp_path):
    r=trace(tmp_path,''.join(line('result received SEND_RESULT_CODE1=OK',msg=f'SYNTH_{i}') for i in range(6)),limit=2)
    assert r['summary']['success']==6 and len(r['events'])==2 and r['coverage']['event_details_omitted']==4


def test_message_group_cap_explicit(tmp_path,monkeypatch):
    import mpush_analyzer.message_outcomes as mod
    monkeypatch.setattr(mod,'MAX_MESSAGES',2)
    r=trace(tmp_path,''.join(line('result received SEND_RESULT_CODE1=OK',msg=f'SYNTH_{i}') for i in range(4)))
    assert r['population_limited'] and r['summary']['unique_messages']==2


def test_raw_unchanged_and_hash_tampering_rejected(tmp_path):
    case,_,_,_=fixture(tmp_path,[('debug.log',line('result received SEND_RESULT_CODE1=OK'))])
    before={str(p.relative_to(case)):hashlib.sha256(p.read_bytes()).hexdigest() for p in case.rglob('*') if p.is_file()}
    trace_outcomes(case,W,salt=SALT)
    assert before=={str(p.relative_to(case)):hashlib.sha256(p.read_bytes()).hexdigest() for p in case.rglob('*') if p.is_file()}
    raw=next((case/'raw').iterdir());raw.write_bytes(raw.read_bytes()+b'changed')
    with pytest.raises(ValueError):trace_outcomes(case,W,salt=SALT)


@pytest.mark.parametrize('args',[{'message':'../../x'},{'service':True},{'limit':0},{'limit':True},{'salt':b'x'}])
def test_invalid_trace_arguments(tmp_path,args):
    case,_,_,_=fixture(tmp_path,[('debug.log',line('RESPONSE_CODE=S'))])
    with pytest.raises(ValueError):trace_outcomes(case,W,**args)


def test_backlog_confirmed_change_not_eta():
    items=[{'at':'2026-11-02T10:00:00','count':100},{'at':'2026-11-02T10:01:00','count':40}]
    r=backlog_observations(items,comparable=True)
    assert r['rows'][1]['net_change_per_second']==-1 and 'eta' not in r
    assert backlog_observations(items)['rows'][1]['change'] is None
    assert len(backlog_observations(items+items)['rows'])==2


@pytest.mark.parametrize('items',[
 [{'at':'bad','count':10}], [{'at':'2026-11-02T10:00','count':True}],
 [{'at':'2026-11-02T10:00','count':-1}], [{'at':'2026-11-02T10:00','count':1.5}],
 [{'at':'2026-11-02T10:00','count':0,'sql':'secret'}],
 [{'at':'2026-11-02T10:00','count':0},{'at':'2026-11-02T10:00','count':1}],
 [{'at':'2026-11-02T10:00','count':0}]*201,
])
def test_backlog_validation(items):
    with pytest.raises(ValueError):backlog_observations(items)


def test_payload_no_foreign_baseline_refs_and_action_boundary(tmp_path):
    from mpush_analyzer.diagnostics_ui import make_payload,validate_action
    a,am,b,bm=baseline_pair(tmp_path)
    jobs=diagnose_jobs(a,am,W,baseline_case=b,baseline_manifest=bm,baseline_window=BASE,same_agent_confirmed=True)
    payload=make_payload(jobs,None,backlog_observations([]))
    assert 'evidence' not in payload['jobs']['jobs'][0]['baseline']
    request={'action':'evidence','revision':payload['revision'],'nonce':str(uuid.uuid4()),'index':0}
    assert validate_action(request,payload)['ref']==payload['references'][0]
    for mutation in [{'index':-1},{'index':True},{'revision':'old'},{'action':'delete'},{'nonce':'bad'}]:
        with pytest.raises(ValueError):validate_action(request|mutation,payload)


def test_stitch_assets_offline_and_exact_source_css():
    root=Path(__file__).resolve().parents[1]
    manifest=json.loads((root/'docs/STITCH_V4_3_PROVENANCE.json').read_text())
    source=(root/'mpush_analyzer/diagnostics_web/stitch-design.js').read_text().split('window.MPUSH_STITCH = ',1)[1].rstrip(';\n')
    designs=json.loads(source)
    for name in ('jobs','messages','performance'):
        assert hashlib.sha256(designs[name]['css'].encode()).hexdigest()==manifest['screens'][name]['css_sha256']
        assert '<header class="app-header">' in designs[name]['header']
    html=(root/'mpush_analyzer/diagnostics_web/index.html').read_text()
    assert 'https://' not in html and 'Content-Security-Policy' in html


def test_new_navigation_and_native_message_consent(tmp_path,monkeypatch):
    from streamlit.testing.v1 import AppTest
    import mpush_analyzer.lifecycle as lifecycle
    import mpush_analyzer.diagnostics_ui as ui
    case,m,_,_=fixture(tmp_path,[('job.log',job()),('debug.log',line('result received SEND_RESULT_CODE1=OK','10:12:00'))])
    seen={}
    def component(**kwargs):seen.update(kwargs);return None
    monkeypatch.setattr(ui,'_component',component)
    monkeypatch.setattr(lifecycle,'list_cases',lambda _: [case])
    app=AppTest.from_file(str(Path(__file__).resolve().parents[1]/'app.py'),default_timeout=60).run()
    from ui_steps import open_analysis
    app=open_analysis(app)
    assert not app.exception,[x.message for x in app.exception]
    assert seen['payload']['lookup'] is None
    app=next(b for b in app.button if b.label=='debug에서 찾기').click().run()
    assert not app.exception and seen['payload']['lookup'] is None
    next(x for x in app.text_input if x.label=='MESSAGE_SEQNO (필수)').set_value('SYNTH_MESSAGE_1')
    next(x for x in app.checkbox if '원본을 로컬에서' in x.label).check()
    app=next(b for b in app.button if b.label=='debug에서 찾기').click().run()
    assert not app.exception,[x.message for x in app.exception]
    assert seen['payload']['lookup'] is not None, {'errors':[e.value for e in app.error],'warnings':[e.value for e in app.warning],'checks':[(x.label,x.value) for x in app.checkbox]}
    assert seen['payload']['lookup']['total_matches']==1
    assert seen['payload']['lookup']['rows'][0]['primary']['state']=='success'
    serialized=json.dumps(seen['payload'],ensure_ascii=False)
    assert 'SYNTH_MESSAGE_1' not in serialized


def test_trailing_completion_gap_uses_collection_not_wall_clock(tmp_path):
    case,m=events_case(tmp_path,[ev(i) for i in range(0,60,10)],collected='2026-11-02T10:03:00')
    d=diagnose_jobs(case,m,W)['jobs'][0]
    tail=d['tail_observation']
    assert tail['seconds']==130 and tail['observed_until']=='2026-11-02T10:03:00.000+09:00'
    assert tail['full_sources'] and d['status']=='attention'
    m['collected_at']=None
    assert diagnose_jobs(case,m,W)['jobs'][0]['tail_observation'] is None


def test_partial_tail_not_a_confirmed_interruption(tmp_path):
    case,m=events_case(tmp_path,[ev(i) for i in range(0,60,10)],partial=('job.log',))
    d=diagnose_jobs(case,m,W)['jobs'][0]
    assert d['tail_observation'] and not d['tail_observation']['full_sources']
    assert d['status']!='attention'


def test_running_sequence_split_by_other_log_completion(tmp_path):
    case,m,_,_=fixture(tmp_path,[('job.log',job()),('debug.log',line('RESPONSE_CODE=S'))])
    rows=[ev(i,kind='job_running_skip',file_id='file_02') for i in (0,10,20,30)]+[ev(15)]
    for i,e in enumerate(rows,1):e.update({'line_start':i,'line_end':i,'status':'complete','log_kind':'debug' if e['file_id']=='file_02' else 'job'})
    (case/'events.jsonl').write_text(''.join(json.dumps(e)+'\n' for e in rows))
    d=diagnose_jobs(case,m,W)['jobs'][0]
    assert d['current']['running_skips']==4 and d['running_cluster_count']==0


def test_no_result_received_negation_never_success(tmp_path):
    assert trace(tmp_path,line('no result received SEND_RESULT_CODE1=OK'))['summary']['success']==0


def test_result_code_set_is_bounded():
    values,unknown=_result_fields(' '.join(f'SEND_RESULT_CODE1=E{i}' for i in range(100)))
    assert len(values['SEND_RESULT_CODE1'])==12 and 'SEND_RESULT_CODE1' in unknown


def test_empty_salt_not_silently_replaced(tmp_path):
    case,_,_,_=fixture(tmp_path,[('debug.log',line('RESPONSE_CODE=S'))])
    with pytest.raises(ValueError):trace_outcomes(case,W,salt=b'')


def test_invalid_action_no_filesystem_or_backlog_mutation(tmp_path):
    from mpush_analyzer.diagnostics_ui import make_payload,validate_action
    c,m=events_case(tmp_path,[ev()]);payload=make_payload(diagnose_jobs(c,m,W),None,backlog_observations([]))
    req={'action':'backlog','revision':payload['revision'],'nonce':str(uuid.uuid4()),'at':'2026-11-02T10:00','count':True,'comparable':True}
    with pytest.raises(ValueError):validate_action(req,payload)
    req.update(count=1,comparable='true')
    with pytest.raises(ValueError):validate_action(req,payload)
    req.update(action='evidence',index='../../private')
    with pytest.raises(ValueError):validate_action(req,payload)


def test_source_signature_invalidates_changed_raw_and_rejects_link(tmp_path):
    from mpush_analyzer.diagnostics_ui import source_signature
    case,m=events_case(tmp_path,[ev()]);before=source_signature(case,m)
    raw=next((case/'raw').iterdir());data=raw.read_bytes();raw.write_bytes(data+b'changed')
    assert source_signature(case,m)!=before
    target=tmp_path/'outside.log';target.write_bytes(data);raw.unlink();raw.symlink_to(target)
    with pytest.raises(ValueError):source_signature(case,m)


def test_package_includes_static_stitch_runtime():
    import tomllib
    root=Path(__file__).resolve().parents[1]
    cfg=tomllib.loads((root/'pyproject.toml').read_text())
    assert set(cfg['tool']['setuptools']['package-data']['mpush_analyzer'])=={'diagnostics_web/*.html','diagnostics_web/*.css','diagnostics_web/*.js'}
