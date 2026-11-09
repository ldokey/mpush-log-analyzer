"""V4.1 inquiry workspace: synthetic data, private provenance and bounded imports."""
from __future__ import annotations
from datetime import date
from dataclasses import replace
import gzip
import hashlib
from io import BytesIO
import json
from pathlib import Path
import stat
import tarfile
import zipfile

import pytest

from mpush_analyzer.intake import Upload, inspect_uploads, supported_log_name, _date_hint
from mpush_analyzer.source_import import (Source, inspect_source, load_candidates,
    scan_folder, issue_folders, safe_member, read_candidate, _bounded_read)
from mpush_analyzer.support_store import (redmine_ref, save_issue, get_issue, list_issues,
    link_analysis, read_context, set_context, ui_file_label, ui_rows, case_title,
    write_json, folder_hint, CONTEXT_FILE, issue_path)
from mpush_analyzer.support_service import (import_analysis, restore_names,
    create_knowledge_draft, attach_existing)
from mpush_analyzer.pipeline import _get_manifest
from mpush_analyzer.runner import run_complete_analysis
from mpush_analyzer.storage import save_intake
from mpush_analyzer.ai_brief_v2 import build_ai_exports
from mpush_analyzer.report import build_exports
from mpush_analyzer.workbench_data import query_events, EventQuery
from test_incident_evidence_v2 import SYNTHETIC_JOB, SYNTHETIC_DB, SYNTHETIC_DEBUG

BASE = 'https://support.example.invalid/redmine'


def zip_bytes(entries, compression=zipfile.ZIP_DEFLATED):
    handle = BytesIO()
    with zipfile.ZipFile(handle, 'w', compression=compression) as archive:
        for name, data in entries:
            archive.writestr(name, data)
    return handle.getvalue()


def tar_bytes(entries, *, mode='w:gz', root_entry=False):
    handle = BytesIO()
    with tarfile.open(fileobj=handle, mode=mode) as archive:
        if root_entry:
            folder = tarfile.TarInfo('.')
            folder.type = tarfile.DIRTYPE
            archive.addfile(folder)
        for name, data in entries:
            entry = tarfile.TarInfo(name)
            entry.size = len(data)
            archive.addfile(entry, BytesIO(data))
    return handle.getvalue()


def inputs():
    return [
        Upload('20261102job.log', SYNTHETIC_JOB.encode(), 'full', origin='#12345_SYNTH_CUSTOMER/logs.zip!/A1/20261102job.log'),
        Upload('20261102dbwrap.log', SYNTHETIC_DB.encode(), 'full', origin='#12345_SYNTH_CUSTOMER/logs.zip!/A1/20261102dbwrap.log'),
        Upload('20261102debug.log', SYNTHETIC_DEBUG.encode(), 'full', origin='#12345_SYNTH_CUSTOMER/logs.zip!/A1/20261102debug.log'),
    ]


def new_analysis(tmp_path, **overrides):
    options = dict(same_agent=True, agent='A1', reference='#12345', base_url=BASE,
                   customer='SYNTH_CUSTOMER', title='지연 문의 합성 테스트', problem='INTERNAL_ONLY_NOT_FOR_AI',
                   reference_date=date(2026,11,2), knowledge_root=tmp_path/'knowledge')
    options.update(overrides)
    return import_analysis(inputs(), tmp_path/'workspace', **options)


def test_redmine_id_and_url_same_identity():
    a = redmine_ref('#12345', BASE)
    b = redmine_ref(BASE + '/issues/12345/')
    assert a == b
    assert a['url'] == BASE + '/issues/12345'
    assert redmine_ref('12345')['key'] != a['key']
    assert redmine_ref('12345', 'https://other.example.invalid')['key'] != a['key']
    assert folder_hint('#12345_테스트 고객사') == {'number':'12345','customer':'테스트 고객사'}


@pytest.mark.parametrize('value', [
    '', '0', '#0', '001', '-2', 'abc', 'javascript:alert(1)', 'file:///issues/12',
    'https://user:secret@example.invalid/issues/12', BASE+'/issues/12?api_key=abc',
    BASE+'/issues/12#fragment', BASE+'/../issues/12', BASE+'/issues/no',
    'http://example.invalid:99999/issues/12', 'https://example.invalid/%2e/issues/12',
])
def test_redmine_invalid_refs_rejected(value):
    with pytest.raises(ValueError): redmine_ref(value)


def test_issue_cas_state_and_history(tmp_path):
    ws = tmp_path/'workspace'; ref = redmine_ref('12345', BASE)
    one = save_issue(ws, ref, {'customer':'테스트','title':'문의','problem':'지연'}, expected_revision=0)
    two = save_issue(ws, ref, {'observations':'SQL 처리시간 증가'}, expected_revision=1)
    assert two['revision'] == 2 and two['problem'] == '지연'
    assert len(two['history']) == 2
    with pytest.raises(ValueError, match='새로고침'):
        save_issue(ws, ref, {'problem':'stale'}, expected_revision=1)
    with pytest.raises(ValueError, match='검증'):
        save_issue(ws, ref, {'status':'해결 확인'}, expected_revision=2)
    three = save_issue(ws, ref, {'status':'해결 확인','actions':'조치 실시','verification':'재시험 통과'}, expected_revision=2)
    assert three['status'] == '해결 확인'
    assert list_issues(ws)[0]['key'] == ref['key']
    assert issue_path(ws,ref['key']).stat().st_mode & 0o077 == 0


def test_issue_wrong_path_and_symlink_refused(tmp_path):
    with pytest.raises(ValueError): get_issue(tmp_path,'../private')
    real = tmp_path/'real'; real.mkdir()
    link = tmp_path/'linked'; link.symlink_to(real, target_is_directory=True)
    with pytest.raises(ValueError): save_issue(link,redmine_ref('12'),{},expected_revision=0)


def test_import_connects_idempotently_and_preserves_existing_notes(tmp_path):
    case, reused = new_analysis(tmp_path)
    assert not reused
    manifest = _get_manifest(case)
    doc = get_issue(case.parent, redmine_ref('12345',BASE)['key'])
    saved = save_issue(case.parent,doc,{'actions':'IMPORTANT_RECORDED_ACTION'},expected_revision=doc['revision'])
    again, reused = new_analysis(tmp_path, problem='must not replace existing issue')
    assert reused and again == case
    doc = get_issue(case.parent,saved['key'])
    assert len(doc['analyses']) == 1 and doc['actions'] == 'IMPORTANT_RECORDED_ACTION'
    other, reused = new_analysis(tmp_path,agent='A2')
    assert other != case and not reused
    assert len(get_issue(case.parent,saved['key'])['analyses']) == 2
    assert '#12345' in case_title(case) and 'SYNTH_CUSTOMER' in case_title(case)
    assert len(manifest['files']) == 3


def test_same_agent_confirmation_required(tmp_path):
    with pytest.raises(ValueError): new_analysis(tmp_path,same_agent=False)
    with pytest.raises(ValueError): new_analysis(tmp_path,agent='')
    assert not (tmp_path/'workspace').exists()


def test_private_names_do_not_enter_events_reports_ai_or_csv(tmp_path):
    case,_ = new_analysis(tmp_path)
    manifest = _get_manifest(case)
    result,matches,_ = run_complete_analysis(case,knowledge_root=tmp_path/'knowledge')
    local = ui_file_label(case,'file_01',manifest)
    assert 'SYNTH_CUSTOMER' in local and 'logs.zip!/A1/' in local
    assert manifest['files'][0]['storage_name'] == 'job_01.log'
    assert 'SYNTH_CUSTOMER' not in json.dumps(manifest)
    rows = query_events(case,manifest,EventQuery(),page_size=25)['rows']
    before = json.dumps(rows,ensure_ascii=False)
    mapped = ui_rows(case,manifest,rows)
    assert 'SYNTH_CUSTOMER' in json.dumps(mapped,ensure_ascii=False)
    assert json.dumps(rows,ensure_ascii=False) == before
    exports = {**build_exports(result,matches,manifest), **build_ai_exports(case,manifest,result,matches)}
    all_data = list(exports.values()) + [(case/'events.jsonl').read_bytes(),before.encode()]
    for data in all_data:
        for forbidden in ('SYNTH_CUSTOMER','INTERNAL_ONLY_NOT_FOR_AI',BASE,'logs.zip'):
            assert forbidden.encode() not in data
    assert (case/CONTEXT_FILE).stat().st_mode & 0o077 == 0


def test_legacy_name_restore_requires_hash_match(tmp_path):
    inspected = inspect_uploads(inputs())
    case,manifest = save_intake(inspected,tmp_path/'workspace',reference_date=date(2026,11,2))
    before = (case/'manifest.json').read_bytes()
    assert '원본명 미보관' in ui_file_label(case,'file_01',manifest)
    with pytest.raises(ValueError,match='SHA-256'):
        restore_names(case,[Upload('20261102job.log',b'WRONG_CONTENT')])
    assert restore_names(case,inputs()) == 3
    assert '20261102job.log' in ui_file_label(case,'file_01',manifest)
    assert (case/'manifest.json').read_bytes() == before


def test_wrong_hash_in_sidecar_cannot_relabel_file(tmp_path):
    case,_ = new_analysis(tmp_path)
    doc = read_context(case);doc['sources']['file_01']['sha256'] = '0'*64
    write_json(case/CONTEXT_FILE,doc)
    assert '원본명 미보관' in ui_file_label(case,'file_01',_get_manifest(case))


def test_existing_analysis_cannot_reassign_issue(tmp_path):
    case,_ = new_analysis(tmp_path)
    second = save_issue(case.parent,redmine_ref('54321',BASE),{},expected_revision=0)
    with pytest.raises(ValueError,match='자동으로 바꾸지'):
        attach_existing(case,second,agent='A1')


def test_delete_analysis_keeps_issue_record(tmp_path):
    from mpush_analyzer.lifecycle import delete_case
    case,_ = new_analysis(tmp_path)
    key=read_context(case)['issue_key']
    delete_case(case,confirmation=case.name,workspace=case.parent)
    assert not case.exists()
    assert get_issue(case.parent,key)['analyses'][0]['analysis_id'] == case.name


def test_zip_inventory_read_unicode_and_duplicate_content(tmp_path):
    data=zip_bytes([('A1/2026-11-02_debug.log',SYNTHETIC_DEBUG.encode()),
                    ('A2/2026-11-02_debug.log',SYNTHETIC_DEBUG.encode()),
                    ('안내.pdf',b'not a log'),('nested.zip',b'do not expand')])
    candidates, notices = inspect_source(Source('support.zip',content=data))
    assert len(candidates) == 2 and len(notices) == 2
    assert len({x.group for x in candidates}) == 2
    loaded = load_candidates(candidates)
    assert 'A1/' in loaded[0].origin and 'A2/' in loaded[1].origin
    inspected = inspect_uploads(loaded)
    assert inspected[1].duplicate_of == 1
    assert inspected[0].date_hint == '2026-11-02'


@pytest.mark.parametrize('name', ['../debug.log','/debug.log','C:/debug.log',
    'A/../../debug.log','..\\debug.log','A/debug.log:stream','A/NUL.log','A/\x01debug.log'])
def test_zip_unsafe_paths_blocked(name):
    with pytest.raises(ValueError):
        inspect_source(Source('bad.zip',content=zip_bytes([(name,b'fake')])) )


def test_zip_links_duplicates_and_corruption_rejected():
    f=BytesIO()
    with zipfile.ZipFile(f,'w') as z:
        info=zipfile.ZipInfo('debug.log');info.create_system=3
        info.external_attr=(stat.S_IFLNK|0o777)<<16
        z.writestr(info,'/elsewhere')
    with pytest.raises(ValueError,match='링크'):
        inspect_source(Source('link.zip',content=f.getvalue()))
    with pytest.raises(ValueError,match='중복'):
        inspect_source(Source('dup.zip',content=zip_bytes([('DEBUG.log',b'a'),('debug.log',b'b')])))
    with pytest.raises(ValueError):
        inspect_source(Source('bad.zip',content=b'not a zip'))


def test_archive_limits_without_large_allocations(monkeypatch):
    import mpush_analyzer.source_import as module
    monkeypatch.setattr(module,'MAX_SINGLE_FILE',50)
    with pytest.raises(ValueError):
        inspect_source(Source('big.zip',content=zip_bytes([('debug.log',b'x'*51)])))
    monkeypatch.setattr(module,'MAX_SINGLE_FILE',10000)
    monkeypatch.setattr(module,'MAX_ENTRIES',1)
    with pytest.raises(ValueError):
        inspect_source(Source('many.zip',content=zip_bytes([('debug.log',b'a'),('job.log',b'b')])))
    with pytest.raises(ValueError,match='실제 크기'):
        _bounded_read(BytesIO(b'a'*51),50)


def test_zip_bomb_ratio_blocked():
    data=zip_bytes([('debug.log',b'0'*(3*1024**2))])
    with pytest.raises(ValueError,match='압축률'):
        inspect_source(Source('bomb.zip',content=data))


@pytest.mark.parametrize('label,mode',[('logs.tar','w'),('logs.tar.gz','w:gz'),('logs.tgz','w:gz')])
def test_tar_formats_and_gzip_read(label,mode):
    contents=tar_bytes([('A1/debug.log',SYNTHETIC_DEBUG.encode())],mode=mode)
    candidates,notices=inspect_source(Source(label,content=contents))
    assert not notices and len(candidates)==1
    assert load_candidates(candidates)[0].content == SYNTHETIC_DEBUG.encode()
    candidates,_=inspect_source(Source('debug.log.gz',content=gzip.compress(SYNTHETIC_DEBUG.encode())))
    assert load_candidates(candidates)[0].content == SYNTHETIC_DEBUG.encode()


def test_tar_symlink_hardlink_and_device_blocked():
    for typ in (tarfile.SYMTYPE,tarfile.LNKTYPE,tarfile.CHRTYPE):
        f=BytesIO()
        with tarfile.open(fileobj=f,mode='w') as archive:
            item=tarfile.TarInfo('debug.log');item.type=typ;item.linkname='../outside'
            archive.addfile(item)
        with pytest.raises(ValueError,match='링크|장치'):
            inspect_source(Source('bad.tar',content=f.getvalue()))


def test_scan_selected_inquiry_only_and_detect_file_change(tmp_path):
    root=tmp_path/'고객사 문의 파일';root.mkdir()
    a=root/'#12345_테스트';a.mkdir()
    b=root/'#54321_다른 문의';b.mkdir()
    source=a/'debug_2026-11-02.log';source.write_bytes(SYNTHETIC_DEBUG.encode())
    (a/'memo.pdf').write_bytes(b'not read')
    (b/'bad.zip').write_bytes(b'invalid but should never be inspected')
    assert [x['number'] for x in issue_folders(root)] == ['54321','12345']
    found,notes=scan_folder(root,a.name)
    assert len(found)==1 and len(notes)==1
    original_hash=hashlib.sha256(source.read_bytes()).hexdigest()
    assert load_candidates(found)[0].content == source.read_bytes()
    assert hashlib.sha256(source.read_bytes()).hexdigest()==original_hash
    source.write_bytes(source.read_bytes()+b'CHANGED')
    with pytest.raises(ValueError,match='변경'):
        load_candidates(found)
    with pytest.raises(ValueError):scan_folder(root,'../outside')


def test_folder_symlink_not_read(tmp_path):
    root=tmp_path/'root';root.mkdir();case=root/'#12_test';case.mkdir()
    other=tmp_path/'outside';other.mkdir();(other/'debug.log').write_bytes(b'do not read')
    (case/'linked').symlink_to(other,target_is_directory=True)
    found,notes=scan_folder(root,case.name)
    assert not found and any('링크' in n for n in notes)


@pytest.mark.parametrize('name', ['debug.log.1','debug.log_002','debug.log.2026-11-02','debug_2026-11-02.log','dbwrap_20261102.log'])
def test_rotations_and_dates_supported(name):
    assert supported_log_name(name)
    if '2026' in name: assert _date_hint(name)=='2026-11-02'


def curated():
    return dict(title='합성 지연 사례 확인',symptoms='SQL 처리시간 증가',cause='데이터베이스 대기 가능성',
                actions='추가 근거 확보',verification='시험 로그를 재확인함',checks='동시 실행 세션 확인',
                signals=['DB_SQL_DELAY'],reviewed_private=True)


def test_knowledge_draft_linked_not_approved_and_idempotent(tmp_path):
    from mpush_analyzer.case_library import read_case_draft, read_approved_cases
    case,_=new_analysis(tmp_path);key=read_context(case)['issue_key']
    result=create_knowledge_draft(case.parent,key,knowledge_root=tmp_path/'knowledge',**curated())
    again=create_knowledge_draft(case.parent,key,knowledge_root=tmp_path/'knowledge',**curated())
    assert again==result
    draft=read_case_draft(result['case_id'],result['revision'],root=tmp_path/'knowledge')
    assert draft['review']['state']=='draft'
    assert {'type':'redmine','id':'#12345'} in draft['references']
    assert read_approved_cases(root=tmp_path/'knowledge')[0]==[]
    for secret in ('SYNTH_CUSTOMER','INTERNAL_ONLY_NOT_FOR_AI',BASE):
        assert secret not in json.dumps(draft,ensure_ascii=False)


def test_knowledge_sensitive_values_and_auto_approval_blocked(tmp_path):
    case,_=new_analysis(tmp_path);key=read_context(case)['issue_key']
    for overrides in ({'reviewed_private':False},{'actions':'password=secret'},{'verified_solution':True},
                      {'symptoms':'고객 연락처 010-1234-5678'},{'signals':[]}):
        args={**curated(),**overrides}
        with pytest.raises(ValueError):create_knowledge_draft(case.parent,key,knowledge_root=tmp_path/'knowledge',**args)


def _widget(app, kind, label):
    return next(x for x in getattr(app,kind) if x.label == label)


def _assert_app(app):
    assert not app.exception, [x.message for x in app.exception]


def test_support_editor_ui_saves_and_detects_stale_edit(tmp_path):
    from streamlit.testing.v1 import AppTest
    ws=tmp_path/'workspace';ref=redmine_ref('12345',BASE)
    initial=save_issue(ws,ref,{'customer':'TEST_CUSTOMER','title':'UI 합성 문의'},expected_revision=0)
    script=f"from pathlib import Path\nfrom mpush_analyzer.support_ui import render_support\nrender_support(Path({str(tmp_path)!r}))\n"
    app=AppTest.from_string(script,default_timeout=30).run();_assert_app(app)
    _widget(app,'text_area','실제로 적용한 조치').set_value('UI_CHANGE_ACTION')
    app=_widget(app,'button','문의·해결 기록 저장').click().run();_assert_app(app)
    saved=get_issue(ws,ref['key']);assert saved['actions']=='UI_CHANGE_ACTION'
    external=save_issue(ws,ref,{'observations':'EXTERNAL_EDIT'},expected_revision=saved['revision'])
    _widget(app,'text_area','실제로 적용한 조치').set_value('STALE_ACTION')
    app=_widget(app,'button','문의·해결 기록 저장').click().run();_assert_app(app)
    assert any('새로고침' in x.value for x in app.error)
    assert get_issue(ws,ref['key'])['actions']=='UI_CHANGE_ACTION'


def test_folder_ui_full_inventory_selection_import_flow(tmp_path, monkeypatch):
    from streamlit.testing.v1 import AppTest
    import mpush_analyzer.support_ui as ui
    root=tmp_path/'customer_root';folder=root/'#12345_TEST_CUSTOMER';folder.mkdir(parents=True)
    (folder/'20261102job.log').write_bytes(SYNTHETIC_JOB.encode())
    write_json(tmp_path/'workspace/import_settings.private.json',{'root':str(root),'base_url':BASE})
    # Prevent the UI integration test from reading the developer's knowledge library.
    real_import=ui.import_analysis
    def isolated(*args,**kwargs):
        return real_import(*args,knowledge_root=tmp_path/'knowledge',**kwargs)
    monkeypatch.setattr(ui,'import_analysis',isolated)
    script=f"from pathlib import Path\nfrom mpush_analyzer.support_ui import render_intake\nrender_intake(Path({str(tmp_path)!r}))\n"
    app=AppTest.from_string(script,default_timeout=30).run();_assert_app(app)
    app=_widget(app,'radio','자료 입력 방식').set_value('등록 폴더에서 선택').run();_assert_app(app)
    app=_widget(app,'button','문의 폴더 목록 새로고침').click().run();_assert_app(app)
    app=_widget(app,'button','이 문의의 로그·압축 목록 확인').click().run();_assert_app(app)
    assert len(_widget(app,'multiselect','같은 Agent의 분석 파일 선택').value)==1
    app=_widget(app,'button','선택 파일 읽기·분류').click().run();_assert_app(app)
    assert _widget(app,'text_input','Redmine 번호 또는 이슈 링크 (선택)').value=='12345'
    assert _widget(app,'text_input','고객사').value=='TEST_CUSTOMER'
    assert not any(x.label=='Agent 구분 (필수)' for x in app.text_input)
    _widget(app,'checkbox','선택한 파일들이 같은 Agent 인스턴스의 자료임을 확인했습니다.').check()
    app=_widget(app,'button','분석 시작').click().run();_assert_app(app)
    from mpush_analyzer.lifecycle import list_cases
    cases=list_cases(tmp_path/'workspace');assert len(cases)==1
    assert read_context(cases[0])['issue_key']==redmine_ref('12345',BASE)['key']
    assert 'TEST_CUSTOMER' in ui_file_label(cases[0],'file_01',_get_manifest(cases[0]))
    assert (folder/'20261102job.log').read_bytes()==SYNTHETIC_JOB.encode()


def test_workbench_displays_local_names_but_download_uses_safe_rows(tmp_path):
    from streamlit.testing.v1 import AppTest
    case,_=new_analysis(tmp_path)
    script=f'''from pathlib import Path
from mpush_analyzer.dashboard_data import read_result_bundle
from mpush_analyzer.workbench_ui import render_workbench
case=Path({str(case)!r})
manifest,result,matches=read_result_bundle(case)
render_workbench(case,manifest,result,matches)
'''
    app=AppTest.from_string(script,default_timeout=40).run();_assert_app(app)
    app=_widget(app,'radio','분석 메뉴').set_value('전체 이벤트').run();_assert_app(app)
    tables=[x.value for x in app.dataframe]
    assert any('SYNTH_CUSTOMER' in frame.to_string() for frame in tables)
    assert not app.error


def test_tar_root_directory_header_is_supported():
    data=tar_bytes([('./A1/debug.log',SYNTHETIC_DEBUG.encode())],root_entry=True)
    candidates,_=inspect_source(Source('logs.tgz',content=data))
    assert len(candidates)==1
    assert load_candidates(candidates)[0].content == SYNTHETIC_DEBUG.encode()


def test_tampered_issue_link_cannot_escape_workspace(tmp_path):
    doc=save_issue(tmp_path,redmine_ref('12345'),{},expected_revision=0)
    doc['analyses']=[{'analysis_id':'../../outside','agent':'A1','at':'x'}]
    write_json(issue_path(tmp_path,doc['key']),doc)
    with pytest.raises(ValueError,match='분석 ID'):get_issue(tmp_path,doc['key'])


def test_rotation_logs_end_to_end(tmp_path):
    case,reused=import_analysis([Upload('debug.log.1',SYNTHETIC_DEBUG.encode(),'full')],
        tmp_path/'workspace',same_agent=True,agent='A1',reference_date=date(2026,11,2),
        knowledge_root=tmp_path/'knowledge')
    manifest=_get_manifest(case)
    assert manifest['files'][0]['storage_name']=='debug_01.log'
    assert 'debug.log.1' in ui_file_label(case,'file_01',manifest)
    result=json.loads((case/'analysis_result.json').read_text())
    assert result['metrics']['events_total']>0


def test_tar_metadata_budget_limits_overread():
    from mpush_analyzer.source_import import _ReadBudget
    stream=_ReadBudget(BytesIO(b'x'*100),50)
    assert len(stream.read(40))==40
    with pytest.raises(ValueError,match='메타데이터'):stream.read(30)


def test_identical_log_bytes_on_different_dates_are_not_deduplicated(tmp_path):
    raw=SYNTHETIC_DEBUG.encode()
    entries=[Upload('debug_2026-11-01.log',raw,'full'),Upload('debug_2026-11-02.log',raw,'full')]
    inspected=inspect_uploads(entries)
    assert all(x.duplicate_of is None for x in inspected)
    case,_=import_analysis(entries,tmp_path/'workspace',same_agent=True,agent='A1',
        knowledge_root=tmp_path/'knowledge')
    manifest=_get_manifest(case)
    assert len(manifest['files'])==2
    assert '2026-11-01' in ui_file_label(case,'file_01',manifest)
    assert '2026-11-02' in ui_file_label(case,'file_02',manifest)
    from mpush_analyzer.dashboard_data import events_iter
    dates={e['occurred_at'][:10] for e in events_iter(case,manifest) if e['occurred_at']}
    assert dates=={'2026-11-01','2026-11-02'}


def test_filename_date_participates_in_analysis_reuse_key(tmp_path):
    raw=SYNTHETIC_DEBUG.encode()
    a,_=import_analysis([Upload('debug_2026-11-01.log',raw,'full')],tmp_path/'workspace',
                        same_agent=True,agent='A1',knowledge_root=tmp_path/'knowledge')
    b,reused=import_analysis([Upload('debug_2026-11-02.log',raw,'full')],tmp_path/'workspace',
                        same_agent=True,agent='A1',knowledge_root=tmp_path/'knowledge')
    assert a != b and not reused


def test_full_app_inquiry_to_dashboard_navigation(tmp_path, monkeypatch):
    from streamlit.testing.v1 import AppTest
    import mpush_analyzer.case_library as library
    real_list=library.list_case_summaries
    monkeypatch.setattr(library,'list_case_summaries',lambda *,state='inbox',root=None: real_list(state=state,root=root or tmp_path/'knowledge'))
    case,_=new_analysis(tmp_path)
    source=(Path(__file__).resolve().parents[1]/'app.py').read_text()
    source=source.replace('APP_ROOT = Path(__file__).resolve().parent',f'APP_ROOT = Path({str(tmp_path)!r})')
    app=AppTest.from_string(source,default_timeout=60).run();_assert_app(app)
    app=_widget(app,'radio','업무 단계').set_value('3 문의·기록').run();_assert_app(app)
    app=_widget(app,'button','이 분석을 대시보드에 선택').click().run();_assert_app(app)
    assert _widget(app,'selectbox','분석 작업 선택').value==case
    assert not any(x.label=='관리할 분석 작업' for x in app.selectbox)
    app=_widget(app,'radio','업무 단계').set_value('4 내보내기').run();_assert_app(app)
    assert _widget(app,'selectbox','관리할 분석 작업').value==case
