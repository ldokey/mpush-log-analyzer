"""Human-first Streamlit incident dashboard.

Core findings are tables and fact panels, never opaque collapsed JSON. Every
date and source label carries an explicit provenance and appropriate caveat.
"""
from __future__ import annotations

from pathlib import Path
import re
import pandas as pd
import streamlit as st

from mpush_analyzer.ai_brief_v2 import build_ai_exports
from mpush_analyzer.incident_overview import category, finding_time_sort_key, snapshot
from mpush_analyzer.dashboard_data import (
    EventFilters, find_correlated_events, read_result_bundle, summarize_events
)
from mpush_analyzer.finding_view_v2 import (
    details as finding_details,
    evidence_rows, file_label, file_labels, measure_rows, summary_row
)
from mpush_analyzer.report import build_exports
from mpush_analyzer.source_view import excerpt


def _table_selection(value) -> int:
    """Streamlit DataframeState single-row selection with a safe default."""
    try:
        rows = value.selection.rows
        return int(rows[0]) if rows else 0
    except (AttributeError, KeyError, IndexError, TypeError):
        return 0


def render_metrics(result: dict, matches: dict) -> None:
    metrics = result["metrics"]
    jobs = metrics.get("job_runs") or {}
    job_runs = sum(x["runs"] for x in jobs.values())
    targets = sum(x["target_count_total"] for x in jobs.values())
    a, b, c, d, e = st.columns(5)
    a.metric("정규화 이벤트", f"{metrics['events_total']:,}")
    b.metric("Job 실행 기록", f"{job_runs:,}")
    c.metric("Job 작업대상 합계", f"{targets:,}")
    d.metric("DB 실행 기록", f"{metrics['db_executions']['runs']:,}")
    e.metric("탐지 징후", f"{len(result.get('findings', [])):,}")
    st.caption(
        "Job 실행 횟수·작업대상건수·최종 발송 성공은 서로 다릅니다. "
        "CNS RESPONSE_CODE=S는 요청 수락만 뜻합니다."
    )


def _render_incident_snapshot(result: dict, manifest: dict) -> None:
    """Bring trustworthy incident context above the analyst's first scroll."""
    overview = snapshot(result, manifest)
    st.markdown("#### 로그 근거 한눈에 보기")
    a, b, c = st.columns(3)
    def show_clock(column, label: str, timestamp: str | None, *, collected: bool = False) -> None:
        if not timestamp:
            column.metric(label, "확인 불가")
            column.caption("별도의 날짜·시각 근거가 없습니다.")
            return
        if timestamp.startswith("날짜 미확인 · "):
            column.metric(label, timestamp.partition(" · ")[2])
            column.caption("날짜 미확인 · 로그의 시각만 표시")
            return
        # Separate date from time to prevent a long timestamp overflowing each KPI.
        stamp_date = timestamp[:10]
        clock = timestamp[11:23].lstrip("T") or "확인 불가"
        column.metric(label, clock)
        column.caption(stamp_date + (" · 사용자 입력" if collected else " · 원본 로그 근거"))

    show_clock(a, "첫 탐지 근거", overview["first_evidence"])
    show_clock(b, "마지막 탐지 근거", overview["last_evidence"])
    show_clock(c, "자료 수집 시각", overview["collected_at"], collected=True)
    counts = overview["categories"]
    if counts:
        st.caption("이상 유형별 탐지: " + " · ".join(
            f"{name} {count}건" for name, count in sorted(counts.items())
        ))
    if overview["incomplete_file_count"] or overview["unknown_date_event_count"]:
        st.warning(f"원본 완전성 미확인·일부 추출 파일 {overview['incomplete_file_count']}개 · "
                   f"날짜 미확인 이벤트 {overview['unknown_date_event_count']:,}개")
    st.caption(overview["note"])


def _render_overview_tables(result: dict, manifest: dict) -> None:
    stage3 = result["metrics"].get("stage3") or {}
    col_a, col_b = st.columns(2)
    with col_a:
        st.markdown("#### Job 처리시간")
        rows = [{
            "Job": name, "완료 실행": item["samples"],
            "평균(초)": item["average"], "P50(초)": item["p50"],
            "P95(초)": item["p95"], "최대(초)": item["max_seconds"],
            "기준 초과": item["slow_above_absolute"],
        } for name, item in sorted((stage3.get("job_duration_statistics") or {}).items())]
        if rows:
            st.dataframe(pd.DataFrame(rows), hide_index=True, width='stretch')
        else:
            st.caption("집계된 완료 Job이 없습니다.")
    with col_b:
        st.markdown("#### DB 실행시간")
        rows = [{
            "SQL 유형": name, "실행 횟수": item["samples"],
            "평균(ms)": item["average"], "P95(ms)": item["p95"],
            "최대(ms)": item["max_ms"], "기준 초과": item["slow_above_absolute"],
        } for name, item in sorted((stage3.get("db_duration_statistics") or {}).items())]
        if rows:
            st.dataframe(pd.DataFrame(rows), hide_index=True, width='stretch')
        else:
            st.caption("집계된 SQL 실행 기록이 없습니다.")
    if any(item.get("percentiles_skipped_due_to_limit") for item in
           (stage3.get("job_duration_statistics") or {}).values()):
        st.warning("표본 상한을 넘은 Job의 P50/P95는 계산하지 않았습니다.")

    st.markdown("#### 분석 자료와 근거 파일")
    sources = [{
        "표시할 파일명": file_label(e["file_id"], manifest),
        "종류": e["kind"],
        "원본 완전성": {"full": "전체로 제출", "partial": "일부 추출", "unknown": "확인 불가"}.get(
            e.get("completeness"), "확인 불가"),
        "날짜 근거": e.get("date_hint") or manifest.get("reference_date") or "미확인",
        "줄 수": e.get("line_count", 0),
    } for e in manifest["files"]]
    st.dataframe(pd.DataFrame(sources), hide_index=True, width='stretch')
    st.caption("파일명은 개인정보 보호를 위해 저장 시 부여한 안전한 별칭입니다. 원래 업로드 파일명과 다를 수 있습니다.")


def _preview(case_dir: Path, reference: dict, *, namespace: str) -> None:
    if not reference:
        st.caption("근거 위치 정보가 없습니다.")
        return
    context = st.slider("원본 근거 주변 줄", 0, 4, 1, key=f"context_{namespace}")
    try:
        preview = excerpt(case_dir, reference["file_id"], reference["line_start"],
                          reference["line_end"], context=context)
    except Exception:
        st.error("원본 근거를 표시할 수 없습니다. 파일 해시와 줄번호를 확인하세요.")
        return
    value = "\n".join(f"{x['line']:>7} | {x['text']}" for x in preview["lines"])
    st.code(value or "표시 가능한 내용이 없습니다.", language=None)
    st.caption(preview["notice"])
    if preview["truncated"]:
        st.caption("최대 미리보기 줄 수를 초과하여 일부만 표시했습니다.")


def _render_findings(case_dir: Path, manifest: dict, result: dict, matches: dict) -> None:
    st.markdown("### 이상 징후 · 근거 · 판단 한계")
    findings = result.get("findings") or []
    if not findings:
        st.info("현재 설정된 규칙에서 감지된 이상 징후가 없습니다. 정상 운영이 확인된 것은 아닙니다.")
        return
    st.caption(
        "행을 선택하면 아래에서 근거와 탐지 수치를 확인할 수 있습니다. "
        "표시된 시각은 실제 장애 시작시각이 아닌 로그에 기록된 대표 시각일 수 있습니다."
    )
    csort, cgroup = st.columns([2, 2])
    sort = csort.selectbox("표시 순서", ["근거 시각순", "주의 수준순"],
                           key=f"findings_sort_v3_{case_dir.name}")
    filter_options = ["전체"] + sorted({category(item) for item in findings})
    group = cgroup.selectbox("유형 필터", filter_options,
                            key=f"findings_category_v3_{case_dir.name}")
    visible = [item for item in findings if group == "전체" or category(item) == group]
    if not visible:
        st.info("선택한 유형에 해당하는 탐지 항목이 없습니다.")
        return
    if sort == "근거 시각순":
        visible.sort(key=finding_time_sort_key)
    else:
        visible.sort(key=lambda f: (0 if f.get("severity") == "warning" else 1,
                                    finding_time_sort_key(f)))
    rows = [summary_row(item, manifest) for item in visible]
    columns = ["대표/기준 시각", "이상 항목", "주요 수치", "근거 파일", "심각도", "판정"]
    st.caption(f"현재 {len(visible)}건 표시 · 목록 시각은 대표 로그 또는 대표 구간 기준이며 장애 시작시각이 아닙니다.")
    selected = st.dataframe(pd.DataFrame(rows)[columns], hide_index=True, width='stretch',
                            height=min(425, 54 + 36 * len(rows)),
                            on_select="rerun", selection_mode="single-row",
                            key=f"findings_v3_{case_dir.name}")
    index = max(0, min(_table_selection(selected), len(visible) - 1))
    item = visible[index]
    presentation = finding_details(item, manifest)

    st.divider()
    st.markdown(f"#### {presentation['finding_id']} · {presentation['title']}")
    c1, c2, c3 = st.columns(3)
    c1.metric("판정 유형", presentation["statement"])
    c2.metric("탐지 근거 평가", presentation["confidence"])
    c3.metric("심각도", presentation["severity"])
    st.caption("탐지 근거의 강도이지 장애 원인의 확실성을 뜻하지 않습니다.")

    time = presentation["time"]
    st.markdown("**탐지 기준 및 수치 비교**")
    st.write(presentation["why_flagged"])
    measures = presentation["measurements"]
    if measures:
        st.dataframe(pd.DataFrame(measures), hide_index=True, width='stretch')
    left, right = st.columns([3, 2])
    with left:
        st.markdown("**관측 사실**")
        st.write(presentation["summary"])
        if presentation["analysis_detail"]:
            st.write(presentation["analysis_detail"])
        st.markdown("**다음 확인 사항**")
        st.write(presentation["next_check"])
    with right:
        st.markdown("**시간 정보**")
        st.table(pd.DataFrame([
            {"구분": "시각의 의미", "값": time["기준"]},
            {"구분": "기준 시작", "값": time["시작"]},
            {"구분": "기준 종료", "값": time["끝"]},
        ]))
        st.caption(time["신뢰 안내"])

    st.markdown("**근거 로그 위치**")
    refs = presentation["evidence"]
    if refs:
        show_cols = ["근거시각", "근거 파일", "줄", "날짜 근거", "관측 구분"]
        evidence_table = st.dataframe(
            pd.DataFrame(refs)[show_cols], hide_index=True, width='stretch',
            on_select="rerun", selection_mode="single-row",
            key=f"evidence_v2_{case_dir.name}_{presentation['finding_id']}")
        chosen = refs[max(0, min(_table_selection(evidence_table), len(refs) - 1))]
        if chosen.get("로그상 시작") not in {None, "-"}:
            st.caption("로그상 Job 시작: " + chosen["로그상 시작"])
        if chosen.get("계산상 시작") not in {None, "-"}:
            st.caption("소요시간으로 계산한 시작: " + chosen["계산상 시작"]
                       + " · " + chosen.get("시작시각 주의", ""))
        st.markdown("##### 선택 근거의 마스킹된 원본")
        _preview(case_dir, {
            "file_id": chosen["원본 ID"], "line_start": chosen["시작행"],
            "line_end": chosen["끝행"]
        }, namespace=f"source_v2_{case_dir.name}_{presentation['finding_id']}")
    else:
        st.caption("보관된 근거 줄번호가 없습니다.")

    st.markdown("**같은 시각에 관측된 다른 로그**")
    # Correlate with the selected, validated evidence row, not always the
    # first raw ref. The latter can belong to a different occurrence/time.
    from mpush_analyzer.finding_view_v2 import _valid_evidence_refs
    valid_refs = _valid_evidence_refs(item)
    selected_ref = valid_refs[max(0, min(_table_selection(evidence_table), len(valid_refs) - 1))] if valid_refs else {}
    other = find_correlated_events(case_dir, manifest, selected_ref, window_seconds=120, limit=80)
    if other:
        converted = []
        for event in other:
            label = event["근거 위치"]
            m = re.match(r"(file_[0-9]{2}):", label)
            converted.append({
                "시간": event["시간"],
                "기준 시각차(초)": event.get("시각차(초)"),
                "로그": file_label(m.group(1), manifest) if m else "미확인",
                "종류": event["유형"],
                "처리 내용": event["주요값"],
                "줄번호": label.split(":")[-1],
            })
        st.dataframe(pd.DataFrame(converted), hide_index=True, width='stretch')
    else:
        st.caption("근처 이벤트가 없거나 날짜 정보가 부족해 관련 시간대를 확인할 수 없습니다.")
    st.caption("같은 시간대에 기록됐다는 이유만으로 원인·결과 관계가 입증되는 것은 아닙니다.")

    st.markdown("#### 이 징후를 AI에 전달하기")
    st.caption("원본 SQL·메시지·고객 식별값은 포함하지 않습니다. 외부 AI 전달 전 내용을 직접 검토해 주세요.")
    if st.button("선택한 징후의 AI 분석 자료 만들기", key=f"ai_single_v2_{case_dir.name}"):
        try:
            exports = build_ai_exports(
                case_dir, manifest, result, matches, only_finding_id=item["finding_id"]
            )
        except Exception:
            st.error("AI 분석 자료를 생성하지 못했습니다. 로그 파일 상태를 확인해 주세요.")
        else:
            st.session_state[f"ai_single_packet_{case_dir.name}"] = (
                item["finding_id"], exports["ai_brief.md"], exports["ai_brief.json"]
            )
    packet = st.session_state.get(f"ai_single_packet_{case_dir.name}")
    if packet and packet[0] == item["finding_id"]:
        st.caption("코드 블록의 복사 버튼을 이용하거나 Markdown 파일을 내려받아 AI에 전달할 수 있습니다.")
        with st.expander("AI 질문에 사용할 비식별 내용 미리보기", expanded=False):
            st.code(packet[1].decode("utf-8"), language="markdown")
        col1, col2 = st.columns(2)
        with col1:
            st.download_button("이 징후 Markdown 받기", packet[1],
                               file_name=f"{item['finding_id']}_ai_brief.md",
                               mime="text/markdown", key=f"single_md_{case_dir.name}")
        with col2:
            st.download_button("이 징후 JSON 받기", packet[2],
                               file_name=f"{item['finding_id']}_ai_brief.json",
                               mime="application/json", key=f"single_json_{case_dir.name}")

def _render_timeline(case_dir: Path, manifest: dict, result: dict) -> None:
    st.markdown("### 시간대별 작업 흐름")
    overview = summarize_events(case_dir, manifest, page_size=10)
    if overview["total"] == 0:
        st.info("표시할 이벤트가 없습니다.")
        return
    a,b,c = st.columns(3)
    kind = a.selectbox("로그 종류", ["전체", "job", "dbwrap", "debug", "info", "err"],
                       key=f"filter_kind_v2_{case_dir.name}")
    job_names = sorted((result["metrics"].get("stage3") or {}).get("job_duration_statistics", {}))
    job = b.selectbox("Job", ["전체"] + job_names, key=f"filter_job_v2_{case_dir.name}")
    files = [f["file_id"] for f in manifest["files"] if f["kind"] not in {"unknown", "agent_ini"}]
    fid = c.selectbox("파일", ["전체"] + files,
                      format_func=lambda x: x if x == "전체" else file_label(x, manifest),
                      key=f"filter_file_v2_{case_dir.name}")
    options = [v["기간"] for v in overview["timeline"]]
    start, end = None, None
    if len(options) >= 2:
        start, end = st.select_slider("관측 시간 범위", options=options,
                     value=(options[0], options[-1]), key=f"time_v2_{case_dir.name}")
    elif options:
        start, end = options[0], options[0]
    if overview["time_bucket"] == "hour" and end:
        end = end[:13] + ":59"
    if overview["time_bucket"] == "day" and start and end:
        start, end = start[:10] + "T00:00", end[:10] + "T23:59"
    flt = EventFilters(start_minute=start, end_minute=end,
                       log_kind=None if kind == "전체" else kind,
                       job_name=None if job == "전체" else job,
                       source_file_id=None if fid == "전체" else fid)
    page = st.number_input("이벤트 페이지", min_value=1, value=1, step=1,
                           key=f"events_page_v2_{case_dir.name}")
    overview = summarize_events(case_dir, manifest, flt, page=page, page_size=100)
    st.caption(f"{overview['total']:,}개 이벤트 · 전체 {overview['pages']}페이지 · "
               f"시간 집계 단위: {overview['time_bucket']}")
    if overview["timeline"]:
        frame = pd.DataFrame(overview["timeline"]).set_index("기간")
        st.bar_chart(frame[["job_runs", "db_calls", "log_errors"]].rename(
            columns={"job_runs":"Job 완료", "db_calls":"DB 실행", "log_errors":"오류 기록"}))
        st.line_chart(frame[["longest_job_seconds"]].rename(
            columns={"longest_job_seconds":"최대 Job 처리시간 (초)"}))
    if overview["rows"]:
        events = overview["rows"]
        mapped = []
        for event in events:
            pos = event["근거 위치"]
            m = re.fullmatch(r"(file_\d{2}):(\d+)-(\d+)", pos)
            mapped.append({
                "시간":event["시간"],
                "파일":file_label(m.group(1),manifest) if m else "미확인",
                "이벤트":event["유형"],
                "핵심 수치":event["주요값"],
                "근거 줄":m.group(2)+"–"+m.group(3) if m else "-",
            })
        selected=st.dataframe(pd.DataFrame(mapped), hide_index=True, width='stretch',
                               on_select="rerun",selection_mode="single-row",
                               key=f"event_v2_{case_dir.name}")
        chosen=events[max(0,min(_table_selection(selected),len(events)-1))]
        match=re.fullmatch(r"(file_\d{2}):(\d+)-(\d+)",chosen["근거 위치"])
        if match:
            st.markdown("**선택 이벤트 원본 근거**")
            _preview(case_dir, {"file_id":match.group(1),
                                "line_start":int(match.group(2)), "line_end":int(match.group(3))},
                     namespace=f"timeline_v2_{case_dir.name}")
    else:
        st.caption("필터에 해당하는 이벤트가 없습니다.")


def render_dashboard(case_dir: Path, manifest: dict,
                     result: dict, matches: dict) -> None:
    """Route to the six-screen workbench; legacy evidence/report helpers stay."""
    from mpush_analyzer.workbench_ui import render_workbench
    render_workbench(case_dir, manifest, result, matches)


def render_exports(result: dict, matches: dict, manifest: dict, case_dir: Path | None = None) -> None:
    st.subheader("비식별 보고서 다운로드")
    reports=build_exports(result, matches, manifest)
    labels = [
        ("report.md","Markdown 보고서","text/markdown"),
        ("report.html","인쇄용 HTML","text/html"),
        ("report.json","JSON 보고서","application/json"),
    ]
    columns=st.columns(3)
    for col,(filename,title,mime) in zip(columns,labels):
        with col:
            st.download_button(title,reports[filename],
                file_name=f"mpush_{result['analysis_id'][-10:]}_{filename}",
                mime=mime,width='stretch')
    st.caption("보고서에는 원본 SQL·개인정보·비밀번호를 포함하지 않습니다.")

    if case_dir is not None:
        st.divider()
        st.subheader("AI 전달용 전체 분석 자료")
        st.write(
            "최대 80개 이상 징후의 대표 시각·탐지 수치·근거 파일과 줄번호·관련 "
            "타 로그 이벤트를 하나의 자료로 구성합니다."
        )
        st.warning("외부 AI로 보내기 전에 개인정보·내부 업무 정보가 남아 있지 않은지 검토해 주세요.")
        if st.button("AI 전체 분석 자료 생성",key=f"ai_whole_build_v2_{case_dir.name}"):
            try:
                st.session_state[f"ai_all_packet_{case_dir.name}"] = build_ai_exports(
                    case_dir, manifest, result, matches
                )
            except Exception:
                st.error("AI 분석 자료 생성에 실패했습니다. 로그 무결성을 확인해 주세요.")
        ai = st.session_state.get(f"ai_all_packet_{case_dir.name}")
        if ai:
            st.code(ai["ai_brief.md"].decode("utf-8"),language="markdown")
            a,b=st.columns(2)
            with a:
                st.download_button("AI 분석용 Markdown",ai["ai_brief.md"],
                                   file_name="mpush_ai_investigation.md",
                                   mime="text/markdown",key=f"ai_full_md_{case_dir.name}")
            with b:
                st.download_button("AI 분석용 JSON",ai["ai_brief.json"],
                                   file_name="mpush_ai_investigation.json",
                                   mime="application/json",key=f"ai_full_json_{case_dir.name}")
    with st.expander("고객 제출 보고서 미리보기"):
        st.code(reports["report.md"].decode("utf-8"),language="markdown")
