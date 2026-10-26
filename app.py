"""MPushAgent Log Analyzer - Stage 4 local-only Streamlit app."""
from __future__ import annotations

from datetime import date
from pathlib import Path

import streamlit as st

from dashboard_ui import render_dashboard, render_exports
from mpush_analyzer.dashboard_data import read_result_bundle
from mpush_analyzer.lifecycle import list_cases, delete_case
from mpush_analyzer.runner import run_complete_analysis
from mpush_analyzer.case_contract import validate_case_json
from mpush_analyzer.case_library import import_case, list_case_summaries, approve_case, read_case_draft
from mpush_analyzer.config_ini import parse_agent_ini
from mpush_analyzer.intake import KINDS, Upload, decode_upload, inspect_uploads
from mpush_analyzer.storage import save_intake
from mpush_analyzer.finding_ui import render_finding_review

APP_ROOT = Path(__file__).resolve().parent

st.set_page_config(page_title="MPushAgent Log Analyzer", page_icon="🔎", layout="wide")
st.title("MPushAgent Log Analyzer")
st.caption("로컬 전용 · Agent 3.2/3.3 로그 진단 · 근거 중심 분석 · 검토된 해결 사례")

tab_dashboard, tab_upload, tab_case, tab_report = st.tabs(["분석 대시보드", "로그 업로드", "해결 사례", "보고서·관리"])

with tab_dashboard:
    local_workspace = APP_ROOT / "workspace"
    available_cases = list_cases(local_workspace)
    if not available_cases:
        st.info("저장된 로그 분석이 없습니다. '로그 업로드' 탭에서 로그 파일을 선택해 분석해 주세요.")
    else:
        preferred = st.session_state.get("active_analysis_id")
        index = next((i for i, p in enumerate(available_cases) if p.name == preferred), 0)
        current = st.selectbox(
            "분석 작업 선택", available_cases, index=index,
            format_func=lambda p: p.name,
            key="dashboard_case"
        )
        if current is not None:
            st.session_state["active_analysis_id"] = current.name
            try:
                manifest, result, matches = read_result_bundle(current)
            except Exception:
                st.warning("분석 결과를 읽을 수 없습니다. '보고서·관리' 탭에서 해당 작업을 다시 분석해 주세요.")
            else:
                render_dashboard(current, manifest, result, matches)

with tab_upload:
    st.subheader("파일 업로드")
    st.write("Agent 하나의 로그를 선택하세요. debug, info, job, dbwrap, err 및 agent.ini를 여러 개 동시에 업로드할 수 있습니다.")
    st.caption("서로 다른 서버 또는 A1/A2 로그는 별도 분석 작업으로 생성하세요. Agent 동일성은 자동 검증되지 않습니다.")
    st.info("원본 로그에는 개인·인증정보가 포함될 수 있습니다. 외부 서버로 전송하지 않고 이 Mac 안에서만 처리하며, 분석 작업 생성 시 접근 제한된 로컬 workspace/raw에 보관합니다.")
    user_files = st.file_uploader(
        "로그 또는 agent.ini 파일", type=["log", "txt", "ini"],
        accept_multiple_files=True, key="log_files",
        help="ZIP 압축은 지원하지 않습니다. 개별 로그 파일을 여러 개 선택하세요."
    )

    agent_version = st.selectbox("Agent 버전", ["auto", "3.2", "3.3"])
    reference_date: date | None = st.date_input(
        "로그 기준 날짜 (선택)", value=None,
        help="파일명에 날짜가 없을 때 2단계 분석에 참고하는 날짜입니다."
    )
    collected_at = st.text_input(
        "실제 로그 수집 시각 (선택)", value="",
        placeholder="2026-10-15 15:20",
        help="마지막 로그 발생 시각과 로그 압축·수집 시각은 서로 다릅니다."
    )

    prepared: list[Upload] = []
    if user_files:
        st.markdown("#### 파일별 설정")
        for index, f in enumerate(user_files, start=1):
            with st.expander(f"{index}. {f.name}", expanded=False):
                a, b = st.columns(2)
                with a:
                    completeness = st.selectbox(
                        "로그 완전성", ["unknown", "full", "partial"],
                        format_func=lambda x: {"unknown": "확인 불가", "full": "원본 전체", "partial": "일부 추출"}[x],
                        key=f"complete_{index}"
                    )
                with b:
                    kind = st.selectbox(
                        "파일 종류", ["auto", *KINDS],
                        key=f"kind_{index}",
                        help="자동 분류가 정확하지 않을 때 직접 지정합니다."
                    )
                prepared.append(
                    Upload(
                        name=f.name,
                        content=f.getvalue(),
                        completeness=completeness,
                        override_kind=None if kind == "auto" else kind,
                    )
                )
        try:
            inspected = inspect_uploads(prepared)
        except ValueError as exc:
            st.error(str(exc))
            inspected = []
        if inspected:
            st.markdown("#### 자동 파일 분류 결과")
            st.dataframe([{
                "번호": i + 1,
                "업로드 파일": x.label,
                "분류": x.kind,
                "근거": x.detection,
                "확신도": x.confidence,
                "크기(B)": x.size_bytes,
                "날짜 힌트": x.date_hint or "-",
                "처음 시각": x.first_time_hint or "-",
                "마지막 시각": x.last_time_hint or "-",
                "완전성": x.upload.completeness,
                "중복": f"{x.duplicate_of}번과 동일" if x.duplicate_of else "-",
            } for i, x in enumerate(inspected)], hide_index=True, use_container_width=True)
            for x in inspected:
                for warning in x.warnings:
                    st.warning(f"{x.label}: {warning}")
            configs = [x for x in inspected if x.kind == "agent_ini" and x.duplicate_of is None]
            if len(configs) == 1:
                st.markdown("#### agent.ini 안전 설정 요약")
                safe_summary = parse_agent_ini(decode_upload(configs[0].upload.content)[0])
                st.json(safe_summary, expanded=False)
                st.caption("비밀번호, 인증 키, 서버 주소, JDBC URL, 서비스 번호의 실제 값은 추출하거나 표시하지 않습니다.")
            elif len(configs) > 1:
                st.error("agent.ini가 두 개 이상입니다. Agent 인스턴스별로 별도 분석해 주세요.")

            if st.button("로컬 분석 작업 생성 및 이상 탐지", type="primary"):
                try:
                    case_dir, manifest = save_intake(
                        inspected,
                        APP_ROOT / "workspace",
                        agent_version=agent_version,
                        reference_date=reference_date,
                        collected_at=collected_at.strip() or None,
                    )
                except ValueError as exc:
                    st.error(str(exc))
                else:
                    st.success(f"로컬 분석 작업 생성: {manifest['analysis_id']}")
                    st.write(f"저장 위치: {case_dir}")
                    try:
                        with st.spinner("로그 이벤트 추출, 이상 탐지 및 유사 사례 매칭 중..."):
                            result, case_matches, _ = run_complete_analysis(case_dir)
                            st.session_state["active_analysis_id"] = case_dir.name
                    except Exception:
                        st.error("파싱 중 문제가 발생했습니다. 원본 로그는 보존되어 있습니다. 해당 분석 ID로 재시도할 수 있습니다.")
                    else:
                        metrics = result["metrics"]
                        st.success("로그 파싱 · 이상 징후 탐지 · 승인 사례 검색 완료")
                        st.caption("상세 시간대별 차트·근거 조회는 분석 대시보드에서, 보고서 다운로드는 보고서·관리에서 사용할 수 있습니다.")
                        col_a, col_b, col_c = st.columns(3)
                        col_a.metric("정규화 이벤트", metrics["events_total"])
                        col_b.metric("Job 종류", len(metrics["job_runs"]))
                        col_c.metric("DB 실행 기록", metrics["db_executions"]["runs"])
                        st.write("분석 범위:", result["analysis_status"])
                        render_finding_review(
                            case_dir, manifest, result, case_matches, namespace="new_upload"
                        )
    else:
        st.caption("업로드한 파일은 작업 생성 버튼을 누르기 전까지 별도 분석 작업으로 저장하지 않습니다.")

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
        st.dataframe(approved_list, hide_index=True, use_container_width=True)
        st.caption("기존 분석에 반영하려면 '기존 분석 다시 실행' 탭에서 재분석해 주세요.")
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
        case_dir = st.selectbox("관리할 분석 작업", cases, index=index, format_func=lambda p: p.name,
                                key="report_case")
        if case_dir is not None:
            st.session_state["active_analysis_id"] = case_dir.name
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
                render_exports(result, matches, manifest)
                with st.expander("분석에 사용한 로그 범위"):
                    st.dataframe([{
                        "파일": f["file_id"], "종류": f["kind"], "완전성": f["completeness"],
                        "기록 처음": f["first_time_hint"], "기록 마지막": f["last_time_hint"]
                    } for f in manifest["files"]], hide_index=True, use_container_width=True)

            st.divider()
            with st.expander("이 분석 작업의 로컬 데이터 영구 삭제"):
                st.warning("원본 로그, 이벤트, 보고서를 함께 삭제합니다. 별도 AI 사례 라이브러리는 삭제하지 않습니다.")
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
st.caption("로컬 전용 · 원본 해시·개인정보 보호 · 기존 Agent/DB 접근 및 변경 없음 · MVP 1.0")
