"""MPushAgent Log Analyzer - V4.3.1 입력 보정본 local inquiry investigation workspace."""
from __future__ import annotations

from pathlib import Path

import streamlit as st

from dashboard_ui import render_dashboard, render_exports
from mpush_analyzer.support_ui import render_support, render_intake, render_name_restore
from mpush_analyzer.support_store import case_title, ui_file_label
from mpush_analyzer.dashboard_data import read_result_bundle
from mpush_analyzer.lifecycle import list_cases, delete_case
from mpush_analyzer.runner import run_complete_analysis
from mpush_analyzer.case_contract import validate_case_json
from mpush_analyzer.case_library import import_case, list_case_summaries, approve_case, read_case_draft


APP_ROOT = Path(__file__).resolve().parent

st.set_page_config(page_title="MPushAgent Log Analyzer", page_icon="🔎", layout="wide")
st.title("MPushAgent Log Analyzer")
st.caption("V4.3.1 입력 보정본 · 고객 문의 → 장애 조사 → 조치·검증 → 해결 사례 · 로컬 전용")

pending = st.session_state.pop("support_pending_analysis", None)
if pending:
    chosen = next((p for p in list_cases(APP_ROOT / "workspace") if p.name == pending), None)
    if chosen:
        st.session_state["active_analysis_id"] = chosen.name
        st.session_state["dashboard_case"] = chosen
        st.session_state["report_case"] = chosen
message = st.session_state.pop("support_last_message", None)
if message:
    st.success(message)

tab_support, tab_dashboard, tab_upload, tab_case, tab_report = st.tabs([
    "문의·해결 기록", "분석 대시보드", "자료 가져오기", "사례 라이브러리", "내보내기·관리"
])

with tab_support:
    render_support(APP_ROOT)

with tab_dashboard:
    local_workspace = APP_ROOT / "workspace"
    available_cases = list_cases(local_workspace)
    if not available_cases:
        st.info("저장된 로그 분석이 없습니다. '자료 가져오기' 탭에서 로그 파일을 선택해 분석해 주세요.")
    else:
        preferred = st.session_state.get("active_analysis_id")
        index = next((i for i, p in enumerate(available_cases) if p.name == preferred), 0)
        current = st.selectbox(
            "분석 작업 선택", available_cases, index=index,
            format_func=case_title,
            key="dashboard_case"
        )
        if current is not None:
            st.session_state["active_analysis_id"] = current.name
            try:
                manifest, result, matches = read_result_bundle(current)
            except Exception:
                st.warning("분석 결과를 읽을 수 없습니다. '내보내기·관리' 탭에서 해당 작업을 다시 분석해 주세요.")
            else:
                st.text(case_title(current))
                render_dashboard(current, manifest, result, matches)

with tab_upload:
    render_intake(APP_ROOT)

with tab_case:
    st.subheader("해결 사례 JSON 가져오기")
    st.caption("별도 AI가 작성한 JSON은 검토 대기함(inbox)에만 저장합니다. 직접 승인한 사례만 자동 매칭됩니다.")
    uploads = st.file_uploader(
        "사례 JSON 여러 개 선택", type=["json"],
        accept_multiple_files=True, key="case_file"
    )
    if uploads:
        if len(uploads) > 20:
            st.warning("한 번에 최대 20건까지만 검증합니다.")
        for i, file in enumerate(uploads[:20], 1):
            data = file.getvalue()
            verdict = validate_case_json(data)
            with st.expander(f"{i}. 사례 형식 검증 — {file.name}", expanded=False):
                if verdict.valid:
                    st.success("JSON 형식·등록 규격 검사 통과 (사실관계 확인과는 별개)")
                    st.json(verdict.summary)
                    if st.button("초안 검토 대기함에 등록", key=f"case_import_{i}"):
                        try:
                            stored = import_case(data)
                        except ValueError as exc:
                            st.error(str(exc))
                        else:
                            st.success(f"{stored['case_id']} r{stored['revision']} 검토 대기 등록")
                else:
                    st.error("검증 실패")
                    for error in verdict.errors:
                        st.text(error)

    st.divider()
    st.subheader("검토 대기 사례 승인")
    pending = list_case_summaries(state="inbox")
    if not pending:
        st.caption("검토 대기 중인 사례가 없습니다.")
    else:
        options = [(item["case_id"], item["revision"]) for item in pending]
        chosen = st.selectbox("검토할 사례", options,
            format_func=lambda item: f"{item[0]} · r{item[1]}")
        doc = read_case_draft(chosen[0], chosen[1])
        if doc is not None:
            st.json(doc, expanded=False)
            st.warning("JSON 검증만으로 사고 원인이나 조치 효과가 확인되는 것은 아닙니다.")
            confirmed = st.checkbox(
                "내용·출처·개인정보 포함 여부를 직접 검토했습니다.",
                key="confirm_case_review"
            )
            confirmed_solution = st.checkbox(
                "근본 원인과 실제 조치·해결 결과까지 근거로 확인했습니다(해결 완료로 승인).",
                key="confirm_verified_resolution"
            )
            if st.button("선택한 사례 승인", key="approve_case_action"):
                try:
                    approved = approve_case(
                        chosen[0], chosen[1], confirm_reviewed=confirmed,
                        confirm_solution=confirmed_solution
                    )
                except ValueError as exc:
                    st.error(str(exc))
                else:
                    st.success(f"{approved['case_id']} 사례 승인 완료 · {approved['status']}")
                    st.rerun()

    st.subheader("승인된 사례")
    approved_list = list_case_summaries(state="approved")
    if approved_list:
        st.dataframe(approved_list, hide_index=True, width='stretch')
        st.caption("기존 분석에 반영하려면 '내보내기·관리' 탭에서 재분석해 주세요.")
    else:
        st.caption("아직 승인된 사례가 없습니다.")

with tab_report:
    st.subheader("분석 보고서 및 로컬 작업 관리")
    st.caption("로그 원본을 변경하지 않고 분석을 다시 실행하거나 비식별 보고서를 다운로드할 수 있습니다.")
    workspace = APP_ROOT / "workspace"
    cases = list_cases(workspace)
    if not cases:
        st.info("현재 저장된 분석 작업이 없습니다.")
    else:
        preferred = st.session_state.get("active_analysis_id")
        index = next((i for i, p in enumerate(cases) if p.name == preferred), 0)
        case_dir = st.selectbox("관리할 분석 작업", cases, index=index, format_func=case_title,
                                key="report_case")
        if case_dir is not None:
            if st.button("원본 검증 후 재분석·사례 매칭·보고서 갱신", type="primary",
                         key="rerun_saved_analysis"):
                try:
                    with st.spinner("원본 해시 검증 · 시간대별 이벤트 분석 · 보고서 생성 중..."):
                        result, matches, _ = run_complete_analysis(case_dir)
                except Exception:
                    st.error("재분석에 실패했습니다. 원본·설정·저장 파일 상태를 확인해 주세요.")
                else:
                    st.success(f"재분석 완료: 이벤트 {result['metrics']['events_total']:,}건, "
                               f"이상 징후 {len(result['findings'])}건")
            try:
                manifest, result, matches = read_result_bundle(case_dir)
            except Exception:
                st.warning("결과 파일이 없거나 검증에 실패했습니다. 위 버튼으로 다시 분석해 주세요.")
            else:
                render_name_restore(case_dir)
                render_exports(result, matches, manifest, case_dir=case_dir)
                with st.expander("분석에 사용한 로그 범위"):
                    st.dataframe([{
                        "파일": ui_file_label(case_dir, f["file_id"], manifest), "종류": f["kind"], "완전성": f["completeness"],
                        "기록 처음": f["first_time_hint"], "기록 마지막": f["last_time_hint"]
                    } for f in manifest["files"]], hide_index=True, width='stretch')

            st.divider()
            with st.expander("이 분석 작업의 로컬 데이터 영구 삭제"):
                st.warning("이 앱에 복사한 원본·이벤트·보고서·원본명 연결을 삭제합니다. 고객사 폴더 원본, 문의 해결 기록, 사례 라이브러리는 삭제하지 않습니다.")
                confirmation = st.text_input(
                    "삭제하려면 전체 분석 ID를 그대로 입력하세요.", value="",
                    key="delete_case_confirmation"
                )
                if st.button("이 분석 작업 영구 삭제", key="delete_case_submit"):
                    try:
                        delete_case(case_dir, confirmation=confirmation, workspace=workspace)
                    except ValueError:
                        st.error("삭제가 거부됐습니다. 분석 ID 또는 파일 상태를 확인해 주세요.")
                    else:
                        if st.session_state.get("active_analysis_id") == case_dir.name:
                            del st.session_state["active_analysis_id"]
                        st.success("해당 분석 작업의 로컬 데이터를 삭제했습니다.")
                        st.rerun()

st.divider()
st.caption("로컬 전용 · 원본 해시·개인정보 보호 · 기존 Agent/DB 접근 및 변경 없음 · V4.3.1 입력 보정본 장애 조사·문의 워크스페이스")
