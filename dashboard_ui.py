"""Streamlit Stage-4 dashboard and evidence viewer with safe, bounded queries."""
from __future__ import annotations
from pathlib import Path
import re
import pandas as pd
import streamlit as st

from mpush_analyzer.dashboard_data import (
    EventFilters, find_correlated_events, read_result_bundle, summarize_events,
)
from mpush_analyzer.report import build_exports
from mpush_analyzer.source_view import excerpt
from mpush_analyzer.finding_ui import render_finding_review


def _finding_label(value: tuple[int, dict]) -> str:
    i, finding = value
    refs = finding.get("evidence_refs") or []
    position = refs[0].get("occurred_at") if refs else "시간 미확인"
    return f"{i+1}. {finding.get('title', '이상 징후')} · {position or '시간 미확인'}"


def render_metrics(result: dict, matches: dict) -> None:
    metrics = result["metrics"]
    jobs = metrics.get("job_runs") or {}
    job_runs = sum(x["runs"] for x in jobs.values())
    targets = sum(x["target_count_total"] for x in jobs.values())
    a, b, c, d, e = st.columns(5)
    a.metric("정규화 이벤트", f"{metrics['events_total']:,}")
    b.metric("Job 실행 기록", f"{job_runs:,}")
    c.metric("작업대상건수 합계", f"{targets:,}")
    d.metric("DB 실행 기록", f"{metrics['db_executions']['runs']:,}")
    e.metric("이상 징후", f"{len(result.get('findings', [])):,}")
    st.caption(
        "작업대상건수 합계는 Job별 처리 건수의 합이며 중복 여부가 확인된 최종 전송 건수가 아닙니다. "
        "CNS RESPONSE_CODE=S도 최종 수신자 전달 성공을 의미하지 않습니다."
    )


def _render_overview_tables(result: dict) -> None:
    stage3 = result["metrics"].get("stage3") or {}
    jobs = stage3.get("job_duration_statistics") or {}
    if jobs:
        rows = []
        for job, item in sorted(jobs.items()):
            rows.append({
                "Job": job,
                "완료 실행": item["samples"],
                "평균(초)": item["average"],
                "P50(초)": item["p50"],
                "P95(초)": item["p95"],
                "최대(초)": item["max_seconds"],
                "절대 기준 초과": item["slow_above_absolute"],
            })
        st.markdown("#### Job별 처리시간")
        st.dataframe(pd.DataFrame(rows), hide_index=True, use_container_width=True)
        if any(item["percentiles_skipped_due_to_limit"] for item in jobs.values()):
            st.warning("일부 Job은 표본 상한을 초과해 P50/P95를 계산하지 않았습니다.")
    db = stage3.get("db_duration_statistics") or {}
    if db:
        st.markdown("#### DB 실행시간")
        rows = [{
            "SQL 유형": name, "실행 횟수": item["samples"],
            "평균(ms)": item["average"], "P95(ms)": item["p95"],
            "최대(ms)": item["max_ms"], "지연 기준 초과": item["slow_above_absolute"],
        } for name, item in sorted(db.items())]
        st.dataframe(pd.DataFrame(rows), hide_index=True, use_container_width=True)
    responses = result["metrics"].get("cns_request_responses") or {}
    if responses:
        st.markdown("#### CNS 요청 응답")
        st.dataframe([{"응답 코드": code, "수신 횟수": count} for code, count in
                      sorted(responses.items())], hide_index=True)
    source = result["metrics"].get("source_summary") or []
    if source:
        with st.expander("파일별 파서 처리 범위와 분석 한계"):
            st.dataframe([{
                "파일": s["file_id"], "유형": s["kind"],
                "읽은 줄": s["lines_read"], "추출 이벤트": s["events_extracted"],
                "자정 경과 추론": s["midnight_rollovers"],
                "시각 순서 이상": s["out_of_order_timestamps"],
            } for s in source], hide_index=True, use_container_width=True)


def _preview(case_dir: Path, reference: dict, *, namespace: str) -> None:
    if not reference:
        st.caption("근거 파일 또는 로그 줄번호 정보가 없습니다.")
        return
    st.caption("원본 파일은 로컬에서 해시를 확인한 뒤 필요한 줄만 읽습니다. 개인정보·SQL 원문·메시지는 표시하지 않습니다.")
    context = st.slider("함께 볼 주변 줄 수", 0, 4, 1, key=f"context_{namespace}")
    try:
        preview = excerpt(case_dir, reference["file_id"], reference["line_start"],
                          reference["line_end"], context=context)
    except Exception:
        st.error("원본 근거를 열 수 없습니다. 로그 무결성 또는 조회 범위를 확인해 주세요.")
        return
    text = "\n".join(f"{x['line']:>7}  {x['text']}" for x in preview["lines"])
    st.code(text or "해당 줄의 원본 기록이 없습니다.", language=None)
    if preview["truncated"]:
        st.caption("표시 가능한 최대 줄 수 제한으로 일부만 보여줍니다.")
    st.caption(preview["notice"])


def _render_timeline(case_dir: Path, manifest: dict, result: dict) -> None:
    st.markdown("### 시간대별 처리 흐름")
    try:
        baseline = summarize_events(case_dir, manifest, page_size=10)
    except Exception:
        st.error("정규화 이벤트 조회에 실패했습니다. 원본 자료와 결과 파일을 확인해 주세요.")
        return
    if baseline["total"] == 0:
        st.info("추출된 이벤트가 없어 타임라인을 표시할 수 없습니다.")
        return
    col_a, col_b, col_c = st.columns(3)
    kind = col_a.selectbox("로그 종류", ["전체", "job", "dbwrap", "debug", "info", "err"])
    job_names = sorted((result["metrics"].get("stage3") or {}).get("job_duration_statistics", {}))
    job = col_b.selectbox("Job", ["전체"] + job_names)
    file_ids = [x["file_id"] for x in manifest["files"] if x["kind"] not in {"agent_ini", "unknown"}]
    file_id = col_c.selectbox("원본 파일", ["전체"] + file_ids)

    timeline = baseline["timeline"]
    start_minute, end_minute = None, None
    options = [x["기간"] for x in timeline]
    if len(options) >= 2:
        selection = st.select_slider(
            "시간대 범위", options=options, value=(options[0], options[-1]),
            help="정확한 연관성 분석을 위해 좁은 시간대를 선택할 수 있습니다.",
        )
        start_minute, end_minute = selection
        if baseline["time_bucket"] == "hour":
            end_minute = end_minute[:13] + ":59"
            st.caption("이 로그는 시간 단위로 차트를 표시합니다.")
        elif baseline["time_bucket"] == "day":
            start_minute = start_minute[:10] + "T00:00"
            end_minute = end_minute[:10] + "T23:59"
            st.caption("이 로그는 날짜 단위로 차트를 표시합니다.")
    elif len(options) == 1:
        start_minute, end_minute = options[0], options[0]
        if baseline["time_bucket"] == "hour":
            end_minute = end_minute[:13] + ":59"
        elif baseline["time_bucket"] == "day":
            start_minute = start_minute[:10] + "T00:00"
            end_minute = end_minute[:10] + "T23:59"
    if not options:
        st.caption("날짜 확인이 어려운 이벤트는 시간 필터 없이 조회됩니다.")
    flt = EventFilters(
        start_minute=start_minute, end_minute=end_minute,
        log_kind=None if kind == "전체" else kind,
        job_name=None if job == "전체" else job,
        source_file_id=None if file_id == "전체" else file_id,
    )

    page = st.number_input("이벤트 페이지", min_value=1, value=1, step=1, key=f"page_{case_dir.name}")
    filtered = summarize_events(case_dir, manifest, flt, page=page, page_size=100)
    st.caption(f"해당 조건: {filtered['total']:,}건 · {filtered['pages']:,}페이지 중 {min(page, filtered['pages']):,}페이지")
    if filtered["timeline"]:
        chart = pd.DataFrame(filtered["timeline"]).set_index("기간")
        chart = chart.rename(columns={"job_runs": "Job", "db_calls": "DB", "log_errors": "오류"})
        st.bar_chart(chart[["Job", "DB", "오류"]], height=240)
        st.line_chart(chart[["longest_job_seconds"]].rename(
            columns={"longest_job_seconds": "최대 Job 처리시간(초)"}), height=210)
    if not filtered["rows"]:
        st.caption("현재 필터 및 페이지에 해당하는 이벤트가 없습니다.")
        return
    st.dataframe(pd.DataFrame(filtered["rows"]), hide_index=True, use_container_width=True)
    selected_event = st.selectbox(
        "원본을 확인할 이벤트", filtered["rows"],
        format_func=lambda row: f"{row['시간']} · {row['유형']} · {row['근거 위치']}",
        key=f"event_select_{case_dir.name}")
    if selected_event:
        # The displayed source-reference format is generated from sanitized events.
        match = re.fullmatch(r"(file_\d{2}):(\d+)-(\d+)", selected_event["근거 위치"])
        if match:
            _preview(case_dir, {
                "file_id": match.group(1), "line_start": int(match.group(2)),
                "line_end": int(match.group(3))
            }, namespace="event_"+case_dir.name)


def render_dashboard(case_dir: Path, manifest: dict,
                     result: dict, matches: dict) -> None:
    st.subheader("로그 분석 대시보드")
    st.caption("파일·시간대·Job 필터 및 탐지 근거를 확인할 수 있습니다. 실제 원인은 추가 자료로 검증해야 합니다.")
    if result["analysis_status"] != "complete":
        st.warning("입력 일부가 잘렸거나 날짜·시간·파일 완전성에 한계가 있습니다. 통계는 제공된 자료만 기준으로 합니다.")
    render_metrics(result, matches)
    _render_overview_tables(result)
    render_finding_review(case_dir, manifest, result, matches, namespace='dashboard')
    _render_timeline(case_dir, manifest, result)
    st.markdown("### 관련 해결 사례")
    if matches["matched_cases"]:
        st.dataframe([{
            "사례 번호": x["case_id"], "검토 상태": x["review_state"],
            "자료 구분": x["result_type"], "매칭 순서 점수": x["match_rank_score"],
            "일치 신호": ", ".join(x["matched_required_signals"] + x["matched_supporting_signals"]),
        } for x in matches["matched_cases"]], hide_index=True, use_container_width=True)
        st.caption("점수는 신호 일치에 따른 목록 정렬 값이며 같은 원인일 확률이 아닙니다.")
    else:
        st.caption("현재 분석 신호와 일치하는 승인된 기존 사례가 없습니다.")


def render_exports(result: dict, matches: dict, manifest: dict) -> None:
    st.subheader("비식별 분석 보고서 다운로드")
    data = build_exports(result, matches, manifest)
    short_id = result["analysis_id"][-10:]
    formats = [
        ("report.md", "Markdown 보고서", "text/markdown"),
        ("report.html", "인쇄용 HTML", "text/html"),
        ("report.json", "JSON 보고서", "application/json"),
    ]
    cols = st.columns(3)
    for col, (name, title, mime) in zip(cols, formats):
        with col:
            st.download_button(
                title, data=data[name], file_name=f"mpush_{short_id}_{name}",
                mime=mime, use_container_width=True
            )
    st.caption("보고서에는 로그 원문, SQL·메시지 내용, 연락처, 자격 증명을 포함하지 않습니다.")
    st.markdown("#### 보고서 내용 미리보기")
    with st.expander("보안 처리된 Markdown 보고서 미리보기"):
        st.code(data["report.md"].decode("utf-8"), language="markdown")
