"""Empty-screen regressions: real-format variants, synthetic values, no customers."""
from datetime import date
import hashlib
import json
from pathlib import Path

import pytest
from mpush_analyzer.intake import Upload, inspect_uploads, _date_hint
from mpush_analyzer.parsers import parse_by_kind
from mpush_analyzer.pipeline import PARSER_REVISION
from mpush_analyzer.diagnostics import diagnose_jobs
from mpush_analyzer.diagnostics_input import inspect_input, reparse_view
from mpush_analyzer.diagnostics_ui import _defaults
from mpush_analyzer.message_outcomes import trace_outcomes
from mpush_analyzer.investigation import Window
from test_investigation_v42 import fixture, job, W, DAY


def prefixed_job(clock='10:12:00.000', target='2', duration='0.286'):
    stamp=clock.replace('.', '[')+']'
    return f'''{stamp} ## SEND_REAL_FILE_IMAGE 작업
{stamp} ## 작업대상건수 : {target}
{stamp} ## SELECT 시간(초.0f) : 0.011초
{stamp} ## FILE 시간(초.0f) : 0.178초
{stamp} ## SOCKET 시간(초.0f) : 0.097초
{stamp} ## 소요시간(초.0f) : {duration}초
'''


def hashes(case):
    return {str(p.relative_to(case)):hashlib.sha256(p.read_bytes()).hexdigest() for p in case.rglob('*') if p.is_file()}


@pytest.mark.parametrize('raw',[prefixed_job(),job(duration=.286,targets=2)])
def test_both_header_layouts_produce_real_metrics(tmp_path,raw):
    c,m,r,_=fixture(tmp_path,[('20261102job.log',raw)],reference=None)
    assert r['metrics']['parser_revision']==PARSER_REVISION
    j=diagnose_jobs(c,m,W)['jobs'][0]['current']
    assert j['records']==1 and j['targets']==2 and j['duration']['p95']==.286


def test_timestamped_header_does_not_merge_adjacent_jobs(tmp_path):
    raw=prefixed_job()+prefixed_job('10:13:00.000',target='7',duration='3.5')
    c,m,r,_=fixture(tmp_path,[('job.log',raw)])
    j=diagnose_jobs(c,m,W)['jobs'][0]['current']
    assert j['records']==2 and j['targets']==9 and j['duration']['max']==3.5
    assert j['evidence'][0]['line_end']<j['evidence'][1]['line_start']


@pytest.mark.parametrize('prefix',['BODY="','INFO message says: ','23:99:00[000] '])
def test_header_not_found_inside_payload(prefix):
    raw=prefix+'## SEND_REAL_FILE_IMAGE 작업\n10:12:00[000] ## 작업대상건수 : 1\n10:12:00[000] ## 소요시간(초.0f) : 1초\n'
    assert not list(parse_by_kind('job',enumerate(raw.splitlines(),1)))


@pytest.mark.parametrize('target,expected',[('1,234',1234),('0',0),('-1',None),('1.5',None),('1,23',None)])
def test_target_token_not_silently_truncated(target,expected):
    rows=list(parse_by_kind('job',enumerate(prefixed_job(target=target).splitlines(),1)))
    assert rows[0].data['target_count']==expected


@pytest.mark.parametrize('duration,expected',[('1.0E-3',.001),('-0.5',None),('1e999',None),('0',0.)])
def test_duration_token_finite_and_complete(duration,expected):
    rows=list(parse_by_kind('job',enumerate(prefixed_job(duration=duration).splitlines(),1)))
    assert rows[0].data['duration_seconds']==expected


@pytest.mark.parametrize('filename',['20261102job.log','2026110210job.log','202611021025job.log','job_2026-11-02_10.log','job_20261102-1025.log'])
def test_hourly_and_daily_filename_date(filename):
    inspected=inspect_uploads([Upload(filename,prefixed_job().encode())])[0]
    assert inspected.date_hint=='2026-11-02' and inspected.kind=='job'


@pytest.mark.parametrize('filename',['job_20261302.log','job_2026110225.log','job_2026110212345678.log'])
def test_invalid_filename_not_truncated_to_valid_date(filename):
    assert _date_hint(filename) is None


@pytest.mark.parametrize('encoding',['utf-8','utf-8-sig','cp949'])
def test_multibyte_boundary_does_not_misclassify_encoding(encoding):
    # First sample ends inside a multibyte character; all content is valid text.
    bom=b'\xef\xbb\xbf' if encoding=='utf-8-sig' else b''
    codec='utf-8' if encoding=='utf-8-sig' else encoding
    raw=bom+b'A'*(131071-len(bom))+'가'.encode(codec)+b'\n'+prefixed_job().encode(codec)
    item=inspect_uploads([Upload('20261102job.log',raw)])[0]
    assert item.encoding==encoding


def test_cp949_after_long_ascii_preamble_is_detected():
    raw=b'ASCII HEADER\n'*12000+prefixed_job().encode('cp949')
    assert inspect_uploads([Upload('20261102job.log',raw)])[0].encoding=='cp949'


def test_known_date_raw_only_message_gets_default_window(tmp_path):
    raw='10:12:00[000] MESSAGE_SEQNO=SYNTH_A SERVICE_SEQNO=SYNTH_B result received SEND_RESULT_CODE1=OK\n'
    c,m,r,_=fixture(tmp_path,[('20261102debug.log',raw)],reference=None)
    assert r['metrics']['events_total']==0
    lo,hi=_defaults(c,m)
    assert lo and hi
    t=trace_outcomes(c,Window(lo,hi))
    assert t['summary']['success']==1
    p=inspect_input(c,m)
    assert 'no_parsed_events' in {x['code'] for x in p['reasons']}


def test_default_range_includes_raw_messages_after_normalized_event(tmp_path):
    raw='09:00:00[000] 헬스 체크 결과 : {"TARGET":"Nothing"}\n10:12:00[000] MESSAGE_SEQNO=SYNTH_A SERVICE_SEQNO=SYNTH_B result received SEND_RESULT_CODE1=OK\n'
    c,m,r,_=fixture(tmp_path,[('20261102debug.log',raw)],reference=None)
    lo,hi=_defaults(c,m)
    assert hi>'2026-11-02T10:12:00'
    assert trace_outcomes(c,Window(lo,hi))['summary']['success']==1


def test_missing_date_explained_and_manual_filter_not_fake_anchor(tmp_path):
    c,m,_,_=fixture(tmp_path,[('job.log',prefixed_job())],reference=None)
    assert diagnose_jobs(c,m,W)['jobs']==[]
    p=inspect_input(c,m,W)
    assert p['counts']['jobs']==1 and p['counts']['undated']==1
    assert 'undated_events' in {x['code'] for x in p['reasons']}
    assert _defaults(c,m)==('','')


def test_explicit_date_reparse_restores_values_without_mutating_case(tmp_path):
    c,m,_,_=fixture(tmp_path,[('job.log',prefixed_job())],reference=None)
    before=hashes(c)
    view=reparse_view(c,anchor_date=DAY,date_confirmed=True)
    try:
        d=diagnose_jobs(view.event_case,view.manifest,W)
        assert d['jobs'][0]['current']['targets']==2
        assert view.manifest['reference_date']=='2026-11-02' and m['reference_date'] is None
        assert hashes(c)==before
    finally:
        directory=view.event_case
        view.close()
        assert not directory.exists()


def test_old_empty_snapshot_is_recovered_not_overwritten(tmp_path):
    c,m,_,_=fixture(tmp_path,[('20261102job.log',prefixed_job())],reference=None)
    (c/'events.jsonl').write_text('')
    before=hashes(c)
    view=reparse_view(c)
    try:
        assert len(diagnose_jobs(view.event_case,view.manifest,W)['jobs'])==1
        assert hashes(c)==before and inspect_input(c,m)['counts'].get('jobs',0)==0
    finally:view.close()


def test_corrupt_snapshot_profile_does_not_crash_and_reparse_recovers(tmp_path):
    c,m,_,_=fixture(tmp_path,[('20261102job.log',prefixed_job())],reference=None)
    (c/'events.jsonl').write_text('{invalid JSON SYNTHETIC_PRIVATE_VALUE}')
    p=inspect_input(c,m)
    assert p['read_error'] and 'SYNTHETIC_PRIVATE_VALUE' not in json.dumps(p)
    view=reparse_view(c)
    try:assert inspect_input(view.event_case,view.manifest)['counts']['jobs']==1
    finally:view.close()


def test_encoding_recovery_does_not_change_saved_metadata(tmp_path):
    c,m,_,_=fixture(tmp_path,[('20261102job.log',prefixed_job().encode('cp949'))],reference=None)
    m['files'][0]['encoding']='utf-8'
    (c/'manifest.json').write_text(json.dumps(m,ensure_ascii=False))
    (c/'events.jsonl').write_text('')
    before=hashes(c);view=reparse_view(c)
    try:
        assert view.manifest['files'][0]['encoding']=='cp949' and view.encoding_changes
        assert diagnose_jobs(view.event_case,view.manifest,W)['jobs'][0]['current']['targets']==2
        assert hashes(c)==before
    finally:view.close()


@pytest.mark.parametrize('anchor,confirmed',[(DAY,False),('2026-11-02',True)])
def test_date_override_requires_explicit_confirmed_date(tmp_path,anchor,confirmed):
    c,m,_,_=fixture(tmp_path,[('job.log',prefixed_job())],reference=None)
    with pytest.raises(ValueError):reparse_view(c,anchor_date=anchor,date_confirmed=confirmed)


def test_existing_reference_date_never_overwritten(tmp_path):
    c,m,_,_=fixture(tmp_path,[('job.log',prefixed_job())])
    with pytest.raises(ValueError):reparse_view(c,anchor_date=date(2026,11,3),date_confirmed=True)


def test_filename_date_authority_wins_over_optional_anchor(tmp_path):
    c,m,_,_=fixture(tmp_path,[('20261102job.log',prefixed_job())],reference=None)
    view=reparse_view(c,anchor_date=date(2026,11,3),date_confirmed=True)
    try:assert len(diagnose_jobs(view.event_case,view.manifest,W)['jobs'])==1
    finally:view.close()


def test_message_manual_anchor_is_also_applied_with_consent(tmp_path):
    raw='10:12:00[000] MESSAGE_SEQNO=SYNTH_A SERVICE_SEQNO=SYNTH_B result received SEND_RESULT_CODE1=OK\n'
    c,m,_,_=fixture(tmp_path,[('debug.log',raw)],reference=None)
    none=trace_outcomes(c,W)
    assert none['summary']['unique_messages']==0 and none['coverage']['undated_records']==1 and none['empty_reasons']
    assert trace_outcomes(c,W,anchor_date=DAY,date_confirmed=True)['summary']['success']==1
    with pytest.raises(ValueError):trace_outcomes(c,W,anchor_date=DAY)


def test_message_outside_window_and_search_exclusion_are_distinct(tmp_path):
    raw='10:12:00[000] MESSAGE_SEQNO=SYNTH_A SERVICE_SEQNO=SYNTH_B result received SEND_RESULT_CODE1=OK\n'
    c,m,_,_=fixture(tmp_path,[('20261102debug.log',raw)],reference=None)
    r=trace_outcomes(c,Window('2026-11-02T11:00:00','2026-11-02T11:20:00'))
    assert r['coverage']['outside_window_records']==1 and r['empty_reasons']
    r=trace_outcomes(c,W,message='SYNTH_OTHER')
    assert r['coverage']['search_excluded_records']==1 and r['empty_reasons']


def test_window_exclusion_diagnostic(tmp_path):
    c,m,_,_=fixture(tmp_path,[('20261102job.log',prefixed_job())],reference=None)
    r=inspect_input(c,m,Window('2026-11-03T10:00:00','2026-11-03T10:20:00'))
    assert r['counts']['jobs']==1 and r['counts'].get('jobs_in_window',0)==0
    assert 'jobs_outside_window' in {x['code'] for x in r['reasons']}


def test_abnormal_skip_is_not_ignored_or_counted_running(tmp_path):
    raw="10:12:00[000] -- Can't execute task in ABNORMAL state :: SEND_REAL_FILE_IMAGE --\n"
    c,m,r,_=fixture(tmp_path,[('20261102debug.log',raw)],reference=None)
    d=diagnose_jobs(c,m,W)['jobs'][0]
    assert d['current']['abnormal_skips']==1 and d['current']['running_skips']==0
    assert d['current']['records']==0 and d['status']=='attention'


def test_source_tampering_blocks_recovery(tmp_path):
    c,m,_,_=fixture(tmp_path,[('job.log',prefixed_job())])
    raw=next((c/'raw').iterdir());raw.write_bytes(raw.read_bytes()+b'changed')
    before=hashes(c)
    with pytest.raises(ValueError):reparse_view(c)
    assert hashes(c)==before


def test_ui_old_zero_snapshot_reparse_shows_metrics(tmp_path,monkeypatch):
    from streamlit.testing.v1 import AppTest
    import mpush_analyzer.diagnostics_ui as ui
    import mpush_analyzer.lifecycle as lifecycle
    c,m,r,_=fixture(tmp_path,[('20261102job.log',prefixed_job())],reference=None)
    (c/'events.jsonl').write_text('')
    before=hashes(c);seen={}
    monkeypatch.setattr(ui,'_component',lambda **kw:seen.update(kw))
    monkeypatch.setattr(lifecycle,'list_cases',lambda _: [c])
    code=f"from pathlib import Path\nfrom mpush_analyzer.diagnostics_ui import render_diagnostics\nfrom mpush_analyzer.pipeline import _get_manifest\nc=Path({str(c)!r})\nrender_diagnostics(c,_get_manifest(c),{{}})\n"
    at=AppTest.from_string(code,default_timeout=60).run()
    assert not at.exception and seen['payload']['jobs']['jobs']==[]
    at=next(b for b in at.button if b.label=='원본 재해석 (기존 분석 보존)').click().run()
    assert not at.exception,[e.message for e in at.exception]
    assert seen['payload']['jobs']['jobs'][0]['current']['targets']==2
    assert hashes(c)==before
    at.session_state['_v43_recovery_view'][1].close()


def test_ui_no_date_then_explicit_date_recovery(tmp_path,monkeypatch):
    from streamlit.testing.v1 import AppTest
    import mpush_analyzer.diagnostics_ui as ui
    import mpush_analyzer.lifecycle as lifecycle
    c,m,r,_=fixture(tmp_path,[('job.log',prefixed_job())],reference=None)
    seen={};monkeypatch.setattr(ui,'_component',lambda **kw:seen.update(kw));monkeypatch.setattr(lifecycle,'list_cases',lambda _: [c])
    code=f"from pathlib import Path\nfrom mpush_analyzer.diagnostics_ui import render_diagnostics\nfrom mpush_analyzer.pipeline import _get_manifest\nc=Path({str(c)!r})\nrender_diagnostics(c,_get_manifest(c),{{}})\n"
    at=AppTest.from_string(code,default_timeout=60).run()
    assert not at.exception and seen['payload']['jobs']['jobs']==[]
    next(d for d in at.date_input if '날짜 없는' in d.label).set_value(DAY)
    next(c for c in at.checkbox if '실제 발생 기준일' in c.label).check()
    at=next(b for b in at.button if b.label=='원본 재해석 (기존 분석 보존)').click().run()
    assert not at.exception,[e.message for e in at.exception]
    assert seen['payload']['jobs']['jobs'][0]['current']['targets']==2
    at.session_state['_v43_recovery_view'][1].close()


@pytest.mark.parametrize('tps,expected',[('1e-3건',.001),('-1건',None),('1,234건',None),('12.5건',12.5),('1e999건',None)])
def test_reported_tps_does_not_parse_a_prefix(tps,expected):
    raw=prefixed_job()+f'10:12:00[000] ## 초당 작업 건수 : {tps}\n'
    rows=list(parse_by_kind('job',enumerate(raw.splitlines(),1)))
    assert rows[0].data['reported_tps']==expected


def test_huge_comma_target_does_not_crash():
    raw=prefixed_job(target='1'+',111'*1600)
    rows=list(parse_by_kind('job',enumerate(raw.splitlines(),1)))
    assert rows[0].data['target_count'] is None


def test_recovered_encoding_applies_to_masked_evidence(tmp_path):
    from mpush_analyzer.source_view import excerpt
    c,m,_,_=fixture(tmp_path,[('20261102job.log',prefixed_job().encode('cp949'))],reference=None)
    m['files'][0]['encoding']='utf-8';(c/'manifest.json').write_text(json.dumps(m))
    view=reparse_view(c)
    try:
        before=hashes(c)
        preview=excerpt(c,'file_01',1,6,encoding_override=view.manifest['files'][0]['encoding'])
        assert any('작업대상건수 : 2' in x['text'] for x in preview['lines'])
        assert hashes(c)==before
        with pytest.raises(ValueError):excerpt(c,'file_01',1,6,encoding_override='unicode_escape')
    finally:view.close()


def test_abnormal_visible_in_general_event_and_signal_views(tmp_path):
    from mpush_analyzer.workbench_data import project_event, SIGNAL_TYPES
    raw="10:12:00[000] Can't execute task in ABNORMAL state :: SEND_REAL_FILE_IMAGE\n"
    c,m,_,_=fixture(tmp_path,[('20261102debug.log',raw)],reference=None)
    event=json.loads((c/'events.jsonl').read_text().splitlines()[0])
    assert project_event(event,m)['유형']=='ABNORMAL 건너뜀'
    assert event['event_type'] in SIGNAL_TYPES
