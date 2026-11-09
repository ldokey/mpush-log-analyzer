"""MPushAgent Log Analyzer V4.4 — single-Agent, intake-first investigation."""
from __future__ import annotations
from pathlib import Path
import streamlit as st
from mpush_analyzer.lifecycle import list_cases
from mpush_analyzer.dashboard_data import read_result_bundle
from mpush_analyzer.support_ui import render_intake, render_support
from mpush_analyzer.support_store import case_title
from mpush_analyzer.workflow_theme import apply_theme

APP_ROOT = Path(__file__).resolve().parent
PAGES = ['1 자료 가져오기', '2 분석 결과', '3 문의·기록', '4 내보내기']
st.set_page_config(page_title='MPushAgent Log Analyzer', page_icon='🔎', layout='wide')
apply_theme()
st.title('MPushAgent Log Analyzer')
st.caption('로그 조사 · 단일 Agent · 로컬 전용 · V4.4 개발본')

pending = st.session_state.pop('support_pending_analysis', None)
if pending:
    chosen = next((p for p in list_cases(APP_ROOT/'workspace') if p.name == pending), None)
    if chosen:
        st.session_state['active_analysis_id'] = chosen.name
        st.session_state['dashboard_case'] = chosen
        st.session_state['report_case'] = chosen
        st.session_state['workflow_page'] = PAGES[1]
        st.session_state['workflow_advanced'] = False
    else:
        st.warning('선택한 분석이 더 이상 존재하지 않습니다.')
route = st.session_state.pop('workflow_pending_page', None)
if route in PAGES:
    st.session_state['workflow_page'] = route
message = st.session_state.pop('support_last_message', None)
if message:
    st.success(message)
page = st.radio('업무 단계', PAGES, horizontal=True, key='workflow_page', label_visibility='collapsed')

if page == PAGES[0]:
    render_intake(APP_ROOT)
    if list_cases(APP_ROOT/'workspace') and st.button('기존 분석 열기', key='workflow_existing'):
        st.session_state['workflow_pending_page'] = PAGES[1]
        st.rerun()
elif page == PAGES[1]:
    cases = list_cases(APP_ROOT/'workspace')
    if not cases:
        st.info('분석할 자료가 없습니다. 자료 가져오기에서 로그를 선택해 주세요.')
        if st.button('자료 가져오기로 이동'):
            st.session_state['workflow_pending_page'] = PAGES[0]
            st.rerun()
    else:
        if st.session_state.get('dashboard_case') not in cases:
            preferred=st.session_state.get('active_analysis_id')
            st.session_state['dashboard_case']=next((p for p in cases if p.name==preferred),cases[0])
        chosen = st.selectbox('분석 작업 선택', cases, format_func=case_title, key='dashboard_case')
        st.session_state['active_analysis_id']=chosen.name
        try:
            manifest,result,matches = read_result_bundle(chosen)
        except Exception:
            st.error('저장된 분석을 읽지 못했습니다. 원본을 보존한 상태로 내보내기에서 재분석을 확인하세요.')
        else:
            if st.session_state.pop('workflow_advanced_next', False):
                st.session_state['workflow_advanced'] = True
            if st.checkbox('고급 분석 도구 열기', key='workflow_advanced'):
                st.caption('전체 이벤트·DB·기존 상세 조사입니다. 핵심 화면에서 접은 기록도 보존돼 있습니다.')
                from dashboard_ui import render_dashboard
                render_dashboard(chosen,manifest,result,matches)
            else:
                from mpush_analyzer.diagnostics_ui import render_diagnostics
                render_diagnostics(chosen,manifest,result)
elif page == PAGES[2]:
    subsection = st.radio('기록 종류', ['문의·해결 기록','사례 라이브러리'], horizontal=True)
    if subsection == '문의·해결 기록':
        render_support(APP_ROOT)
    else:
        from mpush_analyzer.app_sections import render_library
        render_library(APP_ROOT)
else:
    from mpush_analyzer.app_sections import render_management
    render_management(APP_ROOT)

st.caption('원본 변경·자동 재발송·운영 명령·외부 로그 전송 없음')
