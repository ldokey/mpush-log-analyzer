"""Inquiry-first UI, safe folder/archive intake and curated knowledge workflow."""
from __future__ import annotations
from dataclasses import replace
from pathlib import Path
import hashlib
import streamlit as st

from .intake import KINDS, Upload, inspect_uploads, validate_upload_limits
from .lifecycle import list_cases
from .source_import import Source, inspect_source, issue_folders, load_candidates, scan_folder
from .support_store import (STATES, case_title, folder_hint, get_issue, internal_note,
                            list_issues, read_context, read_json, redmine_ref,
                            save_issue, write_json)
from .support_service import attach_existing, create_knowledge_draft, import_analysis, restore_names

LABELS = {'problem': '문의 내용·증상', 'observations': '로그에서 확인한 사실·근거',
          'cause': '원인 후보·확인된 원인(구별해서 기록)', 'actions': '실제로 적용한 조치',
          'verification': '검증 방법·조치 후 결과', 'next_steps': '미확인 사항·다음 조치'}


def _key(value) -> str:
    return hashlib.sha256(repr(value).encode()).hexdigest()[:16]


def _settings(workspace: Path) -> dict:
    value = read_json(workspace / 'import_settings.private.json', {})
    if not isinstance(value, dict): raise ValueError('폴더 연결 설정 형식이 잘못됐습니다.')
    return value


def _connected_folders(workspace: Path) -> tuple[str, dict]:
    settings = _settings(workspace)
    with st.expander('고객사 문의 폴더·Redmine 연결 설정', expanded=not bool(settings)):
        root_text = st.text_input('고객사 문의 루트 폴더', value=settings.get('root', ''),
                                 placeholder='Z:\\...\\고객사 문의 파일', key='support_root')
        base = st.text_input('Redmine 기본 주소 (번호만 입력할 때 사용)', value=settings.get('base_url', ''),
                             placeholder='https://redmine.example.invalid/redmine', key='support_base')
        st.caption('현재 앱이 실행되는 PC의 경로입니다. 원본 폴더는 읽기만 하며, 번호/링크를 저장해도 Redmine 서버에 접속하지 않습니다.')
        if st.button('연결 설정 저장', key='support_settings_save'):
            try:
                if root_text.strip(): issue_folders(Path(root_text.strip()))
                if base.strip(): redmine_ref('1', base.strip())
                write_json(workspace / 'import_settings.private.json',
                           {'root': root_text.strip(), 'base_url': base.strip().rstrip('/')})
            except (ValueError, OSError) as exc:
                st.error(str(exc))
            else:
                st.success('이 PC의 로컬 설정에 저장했습니다.')
    return root_text.strip(), {'base_url': base.strip()}


def render_intake(app_root: Path) -> None:
    workspace = app_root / 'workspace'
    st.subheader('문의 자료 가져오기 · 로그 및 압축 파일')
    st.caption('분석·문의 저장 위치: ' + str(workspace))
    st.caption('프로그램과 분석 저장소는 개인 로컬 디스크에서 실행하세요. 등록한 NAS 문의 폴더는 원본 읽기용입니다.')
    st.caption('선택한 자료만 읽습니다. 원본 이동·삭제·덮어쓰기 없이 분석용 사본을 로컬에 보관합니다.')
    try:
        root_text, settings = _connected_folders(workspace)
    except (ValueError, OSError) as exc:
        st.error(str(exc)); return
    mode = st.radio('자료 입력 방식', ['파일·압축 업로드', '등록 폴더에서 선택'], horizontal=True, key='support_input_mode')
    hint = {}; context = ''
    if mode == '등록 폴더에서 선택':
        st.caption('#번호_고객사 이름의 바로 아래 문의 폴더를 찾습니다. 전체 드라이브나 다른 문의의 로그 내용은 자동으로 읽지 않습니다.')
        if st.button('문의 폴더 목록 새로고침', key='support_folders_refresh'):
            try:
                folders = issue_folders(Path(root_text))
                st.session_state['support_folder_list'] = (root_text, folders)
            except (ValueError, OSError) as exc:
                st.session_state.pop('support_folder_list', None); st.error(str(exc))
        found = st.session_state.get('support_folder_list')
        if not found or found[0] != root_text:
            st.info('루트 경로를 저장하고 문의 폴더 목록을 새로고침하세요.'); return
        query = st.text_input('폴더 검색 — 문의 번호 또는 고객사', key='support_folder_search')
        folders = [x for x in found[1] if query.casefold() in x['folder'].casefold()]
        if not folders:
            st.info('검색 조건에 맞는 #번호_고객사 폴더가 없습니다.'); return
        choice = st.selectbox('문의 폴더', folders, format_func=lambda x: x['folder'], key='support_folder_pick')
        hint = choice
        context = _key((mode, root_text, choice['folder']))
        if st.button('이 문의의 로그·압축 목록 확인', key='support_folder_scan'):
            try:
                candidates, notices = scan_folder(Path(root_text), choice['folder'])
            except (ValueError, OSError) as exc:
                st.session_state.pop('support_inventory', None); st.error(str(exc))
            else:
                st.session_state['support_inventory'] = (context, candidates, notices)
                st.session_state['support_ref'] = hint['number']
                st.session_state['support_customer'] = hint['customer']
                st.session_state.pop('support_loaded', None)
    else:
        uploads = st.file_uploader('로그·ZIP·TAR·TGZ·GZ 파일 선택', accept_multiple_files=True,
                                   key='support_files', help='회전 로그 .log.1도 선택 가능합니다. 지원하지 않는 파일은 목록에서 이유를 표시합니다.')
        context = _key((mode, [(f.name, f.size, getattr(f, 'file_id', None)) for f in uploads or []]))
        if uploads and st.button('업로드 자료 목록 확인', key='support_upload_scan'):
            try:
                validate_upload_limits([f.size for f in uploads])
                candidates = []; notices = []
                for uploaded in uploads:
                    found_items, skipped = inspect_source(Source(uploaded.name, content=uploaded.getvalue()))
                    candidates += found_items; notices += skipped
                    if len(candidates) > 2000: raise ValueError('분석 후보 2,000개 한도를 초과했습니다.')
                st.session_state['support_inventory'] = (context, candidates, notices)
                st.session_state.pop('support_loaded', None)
            except (ValueError, OSError) as exc:
                st.session_state.pop('support_inventory', None); st.error(str(exc))
    inventory = st.session_state.get('support_inventory')
    if not inventory or inventory[0] != context:
        st.caption('목록 확인을 먼저 실행하세요. 압축 파일은 원본 폴더에 풀지 않습니다.'); return
    _, candidates, notices = inventory
    if notices:
        with st.expander(f'제외·주의 항목 {len(notices)}개', expanded=True):
            st.text('\n'.join(notices[:100]))
            if len(notices) > 100: st.caption('앞의 100개만 표시했습니다.')
    if not candidates:
        st.info('분석 가능한 로그 후보가 없습니다.'); return
    st.dataframe([{'파일/압축 내부 경로': c.label, '자료 묶음': c.group,
                   '크기(MiB)': f'{c.size / 1024**2:,.3f}' if c.size is not None else '해제 시 확인',
                   '형식': c.mode} for c in candidates], hide_index=True, width='stretch')
    groups = sorted({c.group for c in candidates})
    group = st.selectbox('자료 묶음 선택 (경로 기준, Agent 자동 판정 아님)', ['직접 선택'] + groups,
                         index=1 if len(groups) == 1 else 0, key='support_group_' + context)
    offered = [c for c in candidates if group == '직접 선택' or c.group == group]
    selected = st.multiselect('같은 Agent의 분석 파일 선택', offered,
                              default=offered if len(groups) == 1 and len(offered) <= 30 else [],
                              format_func=lambda c: c.label, key='support_selected_' + context + _key(group))
    selection_id = _key((context, [c.key for c in selected]))
    st.caption('서버 A1/A2나 서로 다른 Agent가 섞이면 분리해서 분석하세요. 설정 파일은 분석 1회당 하나만 허용합니다.')
    if st.button('선택 파일 읽기·분류', key='support_prepare'):
        try:
            payloads = load_candidates(selected)
            inspected = inspect_uploads(payloads)
            st.session_state['support_loaded'] = (selection_id, payloads, inspected)
        except (ValueError, OSError) as exc:
            st.session_state.pop('support_loaded', None); st.error(str(exc))
    loaded = st.session_state.get('support_loaded')
    if not loaded or loaded[0] != selection_id: return
    _, payloads, inspected = loaded
    st.markdown('#### 파일 분류 및 분석 범위')
    st.dataframe([{'원본/압축 경로': x.upload.origin or x.upload.name, '유형': x.kind,
                   '날짜 근거': x.date_hint or '없음', '처음 시각(표본)': x.first_time_hint or '-',
                   '마지막 시각(표본)': x.last_time_hint or '-', '줄 수': x.line_count,
                   '중복': f'{x.duplicate_of}번과 동일(저장 제외)' if x.duplicate_of else '-'} for x in inspected],
                  hide_index=True, width='stretch')
    missing = {'job','debug','dbwrap','err'} - {x.kind for x in inspected}
    if missing: st.caption('미제공 로그 종류: ' + ', '.join(sorted(missing)) + ' — 필요 여부는 문의 증상에 따라 확인하세요.')
    for x in inspected:
        for warning in x.warnings: st.warning(f'{x.label}: {warning}')
    st.markdown('#### 문의 정보')
    reference = st.text_input('Redmine 번호 또는 이슈 링크 (선택)', key='support_ref', placeholder='#12345 또는 https://…/issues/12345')
    customer = st.text_input('고객사', key='support_customer', max_chars=240)
    title = st.text_input('문의 제목', key='support_title', max_chars=240)
    problem = st.text_area('접수된 증상·문의', key='support_problem', max_chars=12000)
    if reference:
        try:
            ref = redmine_ref(reference, settings.get('base_url', ''))
            st.caption('연결할 문의: #' + ref['number'] + (' · ' + ref['base_url'] if ref['base_url'] else ' · 서버 미지정'))
            if get_issue(workspace, ref['key']): st.info('기존 문의에 분석 자료를 추가합니다. 기존 해결 메모는 덮어쓰지 않습니다.')
        except ValueError as exc: st.error(str(exc))
    with st.form('support_analysis_options_' + selection_id):
        agent = st.text_input('Agent 구분 (필수)', placeholder='예: A1 / 수집일 또는 서버별 식별명', max_chars=120)
        version = st.selectbox('Agent 버전', ['auto', '3.2', '3.3'])
        reference_date = st.date_input('로그 기준 날짜 (파일명에 날짜가 없을 때)', value=None)
        collected = st.text_input('실제 로그 수집 시각 (선택)', placeholder='2026-11-02 14:00')
        prepared = []
        for index, x in enumerate(inspected):
            with st.expander(x.upload.origin or x.label):
                a, b = st.columns(2)
                completeness = a.selectbox('원본 완전성', ['unknown','full','partial'],
                    format_func=lambda v: {'unknown':'미확인','full':'원본 전체','partial':'일부 추출'}[v], key=f'com_{selection_id}_{index}')
                kind = b.selectbox('로그 유형 보정', ['auto', *KINDS], key=f'kind_{selection_id}_{index}')
                prepared.append(replace(x.upload, completeness=completeness, override_kind=None if kind == 'auto' else kind))
        same = st.checkbox('선택한 파일들이 같은 Agent 인스턴스의 자료임을 확인했습니다.')
        submitted = st.form_submit_button('문의에 연결하고 분석', type='primary')
    if submitted:
        try:
            with st.spinner('원본 검증 · 로컬 저장 · 문의 연결 · 로그 분석 중...'):
                case, reused = import_analysis(prepared, workspace, same_agent=same, agent=agent,
                    reference=reference, base_url=settings.get('base_url',''), customer=customer,
                    title=title, problem=problem, agent_version=version, reference_date=reference_date,
                    collected_at=collected.strip() or None)
        except (ValueError, OSError) as exc:
            st.error(str(exc))
        except Exception:
            st.error('분석 중 오류가 발생했습니다. 저장된 원본은 내보내기·관리에서 확인 후 재분석하세요.')
        else:
            st.session_state['support_pending_analysis'] = case.name
            st.session_state['support_last_message'] = ('동일 자료·설정의 기존 분석을 재사용했습니다. ' if reused else '새 분석을 완료했습니다. ') + '분석 대시보드에서 확인하세요.'
            st.session_state.pop('support_loaded', None)
            st.rerun()


def _issue_editor(workspace: Path, doc: dict, app_root: Path) -> None:
    key = doc['key']; snap_key = 'issue_editor_snapshot_' + key
    if st.button('저장된 기록 새로고침 (미저장 입력 초기화)', key='reload_' + key):
        st.session_state.pop(snap_key, None); st.rerun()
    if snap_key not in st.session_state: st.session_state[snap_key] = doc
    snap = st.session_state[snap_key]
    if snap['revision'] != doc['revision']:
        st.warning('저장된 기록이 변경됐습니다. 현재 편집 내용을 보존한 뒤 새로고침하세요. 이전 버전으로 덮어쓰지 않습니다.')
    st.text(f"#{doc['number']} | {doc['customer']} | {doc['title']}")
    if doc.get('url'):
        st.link_button('Redmine 이슈 열기', doc['url'])
        if doc['url'].startswith('http://'): st.caption('HTTP 링크입니다. 앱은 로그인·API 키를 저장하거나 전송하지 않습니다.')
    with st.form('issue_edit_' + key + '_' + str(snap['revision'])):
        fields = {}
        fields['customer'] = st.text_input('고객사', value=snap.get('customer',''), max_chars=240)
        fields['title'] = st.text_input('문의 제목', value=snap.get('title',''), max_chars=240)
        fields['status'] = st.selectbox('진행 상태 (로컬 관리용)', STATES, index=STATES.index(snap['status']))
        for field, label in LABELS.items():
            fields[field] = st.text_area(label, value=snap.get(field,''), max_chars=12000, height=120)
        saved = st.form_submit_button('문의·해결 기록 저장', type='primary')
    if saved:
        try:
            updated = save_issue(workspace, doc, fields, expected_revision=snap['revision'])
        except (ValueError, OSError) as exc: st.error(str(exc))
        else:
            st.session_state[snap_key] = updated
            st.success('저장했습니다. Redmine 서버에는 전송하지 않았습니다.'); st.rerun()
    st.markdown('#### 연결된 분석 자료')
    links = doc.get('analyses', [])
    if links:
        rows = [{'Agent': a['agent'], '분석 ID': a['analysis_id'],
                 '보관 상태': '보관됨' if (workspace / a['analysis_id']).is_dir() else '삭제·이동됨',
                 '연결 시각': a['at']} for a in links]
        st.dataframe(rows, hide_index=True, width='stretch')
        valid = [a for a in links if (workspace / a['analysis_id']).is_dir()]
        if valid:
            selected = st.selectbox('열어볼 연결 분석', valid, format_func=lambda a: f"{a['agent']} · {a['analysis_id'][-8:]}", key='linked_' + key)
            if st.button('이 분석을 대시보드에 선택', key='open_linked_' + key):
                st.session_state['support_pending_analysis'] = selected['analysis_id']; st.rerun()
    else: st.caption('아직 연결된 분석이 없습니다. 자료 가져오기에서 같은 문의 번호를 입력하세요.')
    with st.expander('기존 V4 분석을 이 문의에 연결'):
        available = [p for p in list_cases(workspace) if not read_context(p).get('issue_key')]
        if available:
            chosen = st.selectbox('기존 분석', available, format_func=case_title, key='attach_case_' + key)
            agent = st.text_input('기존 분석의 Agent 구분', key='attach_agent_' + key)
            if st.button('선택 분석 연결', key='attach_' + key):
                try:
                    if not agent.strip(): raise ValueError('Agent 구분을 입력하세요.')
                    attach_existing(chosen, doc, agent=agent)
                except (ValueError, OSError) as exc: st.error(str(exc))
                else:
                    st.session_state.pop(snap_key, None); st.rerun()
        else: st.caption('연결되지 않은 기존 분석이 없습니다.')
    with st.expander('Redmine 답변용 내부 기록 — 외부 AI용 아님'):
        st.warning('고객사명·업무 메모가 포함되는 내부 자료입니다. 일반 AI 분석 자료와 다르며 자동 전송하지 않습니다.')
        if st.checkbox('내부 공유 범위와 내용을 확인했습니다.', key='note_review_' + key):
            text = internal_note(doc)
            st.code(text, language=None)
            st.download_button('내부 답변 TXT 받기', text.encode('utf-8'), file_name=f"issue_{doc['number']}_internal.txt", key='note_dl_' + key)
    with st.expander('재사용할 해결 사례 작성 · 비식별 검토 대기로 등록'):
        st.caption('아래 내용은 직접 비식별로 정리하세요. 위의 고객사 메모·원본 파일명·서버 URL을 자동 복사하지 않습니다.')
        from .case_contract import load_schema
        allowed = [x['code'] for x in load_schema('signal_catalog.json')['signals']]
        with st.form('curate_' + key):
            values = {
                'title': st.text_input('비식별 사례 제목 (5자 이상)', max_chars=180),
                'symptoms': st.text_area('재사용할 증상 (항목별 한 줄)'),
                'cause': st.text_area('원인 설명 (확인되지 않았으면 후보로)'),
                'actions': st.text_area('조치 방법 (항목별 한 줄)'),
                'verification': st.text_area('검증 근거 (항목별 한 줄)'),
                'checks': st.text_area('다음 점검 항목 (항목별 한 줄)'),
                'signals': st.multiselect('매칭할 로그 신호', allowed),
                'confirmed_cause': st.checkbox('원인을 근거로 확인했습니다.'),
                'verified_solution': st.checkbox('실제 조치 후 해결 여부를 검증했습니다.'),
                'reviewed_private': st.checkbox('개인정보·고객사 식별정보·인증정보를 제거했습니다.'),
            }
            curate = st.form_submit_button('해결 사례 검토 대기에 등록')
        if curate:
            try:
                link = create_knowledge_draft(workspace, key, knowledge_root=app_root / 'knowledge', **values)
            except (ValueError, OSError) as exc: st.error(str(exc))
            else:
                st.session_state.pop(snap_key, None)
                st.success(link['case_id'] + ' 검토 대기 등록. 사례 라이브러리에서 별도로 승인해야 검색에 사용됩니다.')
    if doc.get('knowledge_links'):
        from .case_library import list_case_summaries
        summaries = list_case_summaries(root=app_root/'knowledge', state='inbox') + list_case_summaries(root=app_root/'knowledge', state='approved')
        lookup = {(x['case_id'], x['revision']): x for x in summaries}
        st.dataframe([{'사례 ID': x['case_id'], '버전': x['revision'],
                       '검토 상태': lookup.get((x['case_id'],x['revision']),{}).get('review_state','파일 확인 필요')}
                      for x in doc['knowledge_links']], hide_index=True, width='stretch')
    with st.expander('변경 이력 (최근 200회)'):
        st.dataframe(doc.get('history',[]), hide_index=True, width='stretch')


def render_support(app_root: Path) -> None:
    workspace = app_root / 'workspace'
    st.subheader('고객 문의 · 조사 · 조치 · 해결 검증')
    st.caption('Redmine 번호로 자료와 해결 기록을 묶습니다. 분석의 관측 사실과 담당자의 원인 판단·조치를 구분하세요.')
    try:
        settings = _settings(workspace)
        issues = list_issues(workspace)
    except (ValueError, OSError) as exc:
        st.error(str(exc)); return
    with st.expander('문의만 먼저 등록 (로그 없이도 가능)'):
        with st.form('new_support_issue'):
            reference = st.text_input('Redmine 번호/링크', max_chars=1200)
            customer = st.text_input('고객사명', max_chars=240)
            title = st.text_input('문의 제목/요약', max_chars=240)
            problem = st.text_area('문제/증상', max_chars=12000)
            create = st.form_submit_button('문의 등록')
        if create:
            try:
                ref = redmine_ref(reference, settings.get('base_url',''))
                existing = get_issue(workspace, ref['key'])
                if not existing:
                    save_issue(workspace, ref, {'customer':customer,'title':title,'problem':problem}, expected_revision=0)
                st.session_state['active_issue_key'] = ref['key']; st.rerun()
            except (ValueError, OSError) as exc: st.error(str(exc))
    query = st.text_input('문의 검색 — 번호·고객사·제목·증상', key='support_issue_search')
    state = st.selectbox('상태 필터', ['전체', *STATES], key='support_status_filter')
    visible = [d for d in issues if (state == '전체' or d['status'] == state)
               and query.casefold() in ' '.join(d.get(f,'') for f in ('number','customer','title','problem')).casefold()]
    if not visible:
        st.info('검색 조건에 맞는 문의가 없습니다. 문의를 등록하거나 자료 가져오기를 진행하세요.'); return
    st.dataframe([{'번호':'#'+d['number'], '고객사':d['customer'], '문의':d['title'], '상태':d['status'],
                   '분석 자료':len(d['analyses']), '해결 사례':len(d.get('knowledge_links',[])),
                   '변경 시각':d['updated_at']} for d in visible], hide_index=True, width='stretch')
    preferred = st.session_state.get('active_issue_key')
    idx = next((i for i,d in enumerate(visible) if d['key'] == preferred),0)
    doc = st.selectbox('열어볼 문의', visible, index=idx,
                       format_func=lambda d: f"#{d['number']} · {d['customer']} · {d['title']} · {d.get('base_url') or '서버 미지정'}",
                       key='support_issue_pick')
    _issue_editor(workspace, doc, app_root)


def render_name_restore(case: Path) -> None:
    with st.expander('기존 분석 원본 파일명 복구 — SHA-256 일치 파일만'):
        st.caption('이전 버전은 원본명을 보관하지 않았습니다. 당시와 내용이 동일한 로그를 다시 선택하면 원본을 덮어쓰지 않고 이름만 연결합니다.')
        files = st.file_uploader('원본명 복구용 로그 파일', accept_multiple_files=True, key='restore_'+case.name)
        if st.button('원본 해시 대조 후 이름 연결', key='restore_go_'+case.name):
            try:
                validate_upload_limits([x.size for x in files or []])
                count = restore_names(case, [Upload(x.name, x.getvalue(), origin=x.name) for x in files])
            except (ValueError, OSError) as exc: st.error(str(exc))
            else: st.success(f'{count}개 파일의 원본명을 복구했습니다. 분석 대시보드를 새로고침하세요.')
