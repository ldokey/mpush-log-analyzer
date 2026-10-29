"""Six-screen human investigator workbench; all record content is allowlisted.

The active section alone runs its heavy JSONL queries; unlike Streamlit tabs,
radio navigation does not render/query five hidden sections on every rerun.
"""
from __future__ import annotations

from datetime import datetime
import hashlib
from pathlib import Path
from typing import Any

import pandas as pd
import streamlit as st

from .dashboard_data import find_correlated_events, summarize_events
from .finding_view_v2 import file_label
from .workbench_data import (
    DISPLAY_FIELDS, EVENT_NAMES, PAGE_SIZES, SIGNAL_TYPES,
    EventQuery, file_quality_rows, query_events,
)

SCREENS = (
    "종합 현황", "전체 이벤트", "Job 분석", "DB 분석",
    "이상·오류 분석", "수집·분석 품질",
)

DEFAULT_COLUMNS = {
    "events": ("시각", "유형", "상태", "Job", "처리시간(초)", "DB시간(ms)",
               "주요 정보", "근거 파일", "줄번호"),
    "jobs": ("시각", "로그상 시작", "Job", "상태", "작업대상",
             "처리시간(초)", "로그 TPS", "SOCKET(초)", "DB(초)",
             "근거 파일", "줄번호"),
    "db": DISPLAY_FIELDS["db"],
    "signals": DISPLAY_FIELDS["signals"],
}


def _safe_iso_minute(value: str) -> str | None:
    if not isinstance(value, str) or len(value) < 16:
        return None
    try:
        dt = datetime.fromisoformat(value)
    except ValueError:
        return None
    return dt.strftime("%Y-%m-%dT%H:%M")


def _selection_index(state: Any) -> int | None:
    try:
        rows = state.selection.rows
        return int(rows[0]) if rows else None
    except (AttributeError, KeyError, TypeError, IndexError):
        return None


def _filter_hash(*values: Any) -> str:
    return hashlib.sha256(repr(values).encode("utf-8")).hexdigest()[:12]


def _jump_to(begin: str, end: str, from_key: str,
             to_key: str, nav_key: str) -> None:
    # Streamlit callback runs before rerender, so widget state can change.
    st.session_state[from_key] = begin
    st.session_state[to_key] = end
    st.session_state[nav_key] = "전체 이벤트"


def _timeline(case_dir: Path, manifest: dict[str, Any],
              *, nav_key: str, from_key: str, to_key: str) -> None:
    overview = summarize_events(case_dir, manifest, page_size=10)
    timeline = overview.get("timeline") or []
    if not timeline:
        st.caption("날짜가 확인된 정규화 이벤트가 없어 시간대 차트를 그리지 못합니다.")
        return
    frame = pd.DataFrame(timeline).set_index("기간")
    st.markdown("#### 시간대별 처리량·오류")
    st.bar_chart(frame[["job_runs", "db_calls", "log_errors"]].rename(columns={
        "job_runs": "Job 실행", "db_calls": "SQL 실행", "log_errors": "오류 기록",
    }))
    st.markdown("#### Job 최대 처리시간 (초)")
    st.line_chart(frame[["longest_job_seconds"]].rename(columns={
        "longest_job_seconds": "Job 최대(초)",
    }))
    st.markdown("#### SQL 최대 처리시간 (ms)")
    st.line_chart(frame[["longest_sql_ms"]].rename(columns={
        "longest_sql_ms": "SQL 최대(ms)",
    }))
    st.caption("Job과 SQL 처리시간의 단위·수집 의미가 달라 별도 차트로 표시합니다.")
    options = [x["기간"] for x in timeline]
    if len(options) < 2:
        return
    start, end = st.select_slider(
        "조회할 시간대 선택", options=options, value=(options[0], options[-1]),
        key=f"wb_time_window_{case_dir.name}",
    )
    unit = overview["time_bucket"]
    begin = start[:10] + "T00:00" if unit == "day" else start[:16]
    finish = (end[:10] + "T23:59" if unit == "day"
              else end[:13] + ":59" if unit == "hour" else end[:16])
    st.button("선택 시간대의 전체 이벤트 조회", key=f"wb_drill_{case_dir.name}",
              on_click=_jump_to, args=(begin, finish,
                                       from_key, to_key, nav_key))
    st.caption(f"시간 집계 단위: {unit} · 선택 구간을 전체 이벤트 필터로 연결합니다.")


def _overview(case_dir: Path, manifest: dict[str, Any],
              result: dict[str, Any], matches: dict[str, Any],
              *, nav_key: str, from_key: str, to_key: str) -> None:
    from dashboard_ui import render_metrics, _render_incident_snapshot
    render_metrics(result, matches)
    _render_incident_snapshot(result, manifest)
    metrics = result.get("metrics") or {}
    counts = metrics.get("event_counts") or {}
    if counts:
        st.markdown("#### 추출된 이벤트 종류별 건수")
        rows = [{"이벤트": EVENT_NAMES[k], "건수": count}
                for k, count in counts.items()
                if k in EVENT_NAMES and type(count) is int]
        if rows:
            st.dataframe(pd.DataFrame(rows).sort_values("건수", ascending=False),
                         hide_index=True, width="stretch")
    _timeline(case_dir, manifest, nav_key=nav_key,
              from_key=from_key, to_key=to_key)
    st.caption(
        "이 화면의 징후 개수는 실제 지연·오류 발생 횟수와 다릅니다. "
        "발생 시간별 기록은 '전체 이벤트', Job·DB 상세 이력은 전용 화면에서 확인하세요."
    )


def _query_controls(case_dir: Path, manifest: dict[str, Any],
                    result: dict[str, Any], *, view: str,
                    from_key: str, to_key: str) -> tuple[EventQuery, int, int]:
    prefix = f"wb_{case_dir.name}_{view}"
    metric_jobs = (result.get("metrics") or {}).get("job_runs") or {}
    jobs = sorted(x for x in metric_jobs
                  if isinstance(x, str) and x.isupper() and x.replace("_", "").isalnum()
                  and 3 <= len(x) <= 64)
    files = [f.get("file_id") for f in manifest.get("files") or []
             if f.get("kind") not in {"unknown", "agent_ini"}]
    choices = [f for f in files if isinstance(f, str) and f.startswith("file_")]
    types = ([t for t in EVENT_NAMES if t in SIGNAL_TYPES] if view == "signals"
             else ["job_run"] if view == "jobs"
             else ["sql_execution"] if view == "db" else list(EVENT_NAMES))

    a, b, c, d = st.columns(4)
    log_kind = a.selectbox("로그 종류", ["전체", "job", "dbwrap", "debug", "info", "err"],
                           key=f"{prefix}_kind")
    kind = b.selectbox("이벤트", ["전체"] + types, format_func=lambda x: (
        "전체" if x == "전체" else EVENT_NAMES[x]), key=f"{prefix}_type")
    job_name = c.selectbox("Job", ["전체"] + jobs, key=f"{prefix}_job")
    source = d.selectbox("파일", ["전체"] + choices,
                         format_func=lambda x: ("전체" if x == "전체"
                             else file_label(x, manifest)), key=f"{prefix}_file")
    a, b, c, d = st.columns(4)
    from_date = a.text_input("시작 시각", value="", key=from_key if view == "events"
                             else f"{prefix}_from", placeholder="2026-10-15T10:00",
                             help="YYYY-MM-DDTHH:MM 형식. 비워 두면 제한 없음.")
    to_date = b.text_input("종료 시각", value="", key=to_key if view == "events"
                           else f"{prefix}_to", placeholder="2026-10-15T12:00",
                           help="날짜가 확인되지 않은 이벤트는 시간 조건에서 제외됩니다.")
    status = c.selectbox("실행 상태",
                          ["전체", "complete", "incomplete", "observed", "failed"],
                          key=f"{prefix}_status")
    sorts = {"발생시각 오래된 순": "time_asc", "발생시각 최신 순": "time_desc"}
    if view in ("jobs", "db"):
        sorts["처리시간 긴 순"] = "duration_desc"
    sort_label = d.selectbox("정렬", list(sorts), index=1,
                             key=f"{prefix}_sort")

    min_duration = None
    if view in ("jobs", "db"):
        label = "최소 Job 처리시간(초)" if view == "jobs" else "최소 SQL 처리시간(ms)"
        value = st.number_input(label, min_value=0.0, max_value=1e9,
                                value=0.0, step=1.0 if view == "jobs" else 100.0,
                                key=f"{prefix}_min_duration")
        min_duration = value if value > 0 else None
    slow_only = False
    if view in ("jobs", "db"):
        slow_only = st.checkbox(
            "설정된 절대 기준 초과 실행만 표시 (상대 기준 최종 판정과 별개)",
            key=f"{prefix}_slow_only",
        )
    page_size = st.selectbox("페이지당 표시", PAGE_SIZES, index=1,
                             key=f"{prefix}_page_size")
    query = EventQuery(
        view=view,
        log_kind=None if log_kind == "전체" else log_kind,
        event_type=None if kind == "전체" else kind,
        job_name=None if job_name == "전체" else job_name,
        file_id=None if source == "전체" else source,
        status=None if status == "전체" else status,
        from_minute=from_date.strip() or None,
        to_minute=to_date.strip() or None,
        min_duration=min_duration,
        slow_only=slow_only,
        sort=sorts[sort_label],
    )
    signature = _filter_hash(query, page_size)
    page = st.number_input("페이지 번호", min_value=1, max_value=1000000,
                           value=1, step=1, key=f"{prefix}_page_{signature}")
    return query, page, page_size


def _detail(case_dir: Path, manifest: dict[str, Any], selected: dict[str, Any],
            *, key: str) -> None:
    from dashboard_ui import _preview
    st.markdown("#### 선택 이벤트 상세 · 구조화 항목")
    omitted = {"원본 ID", "시작행", "끝행", "이벤트 코드"}
    pairs = [{"속성": name, "값": str(value)}
             for name, value in selected.items()
             if name not in omitted and value is not None]
    st.dataframe(pd.DataFrame(pairs), hide_index=True, width="stretch")
    st.caption("날짜·시각·근거 파일 정보는 관측값 또는 정규화 결과이며, 장애 원인의 확정 근거는 아닙니다.")

    fid, start, end = (selected.get("원본 ID"), selected.get("시작행"),
                       selected.get("끝행"))
    if not (isinstance(fid, str) and type(start) is int and type(end) is int):
        st.info("확인 가능한 원본 근거 위치가 없습니다.")
        return
    if st.checkbox("마스킹된 원본 로그 근거 확인", key=f"{key}_show_source"):
        _preview(case_dir, {"file_id": fid, "line_start": start,
                            "line_end": end}, namespace=f"{key}_source")

    if st.checkbox("이 시각 주변의 다른 로그 함께 보기 (전후 120초)",
                   key=f"{key}_show_related"):
        recorded = selected.get("시각")
        center = _safe_iso_minute(recorded)
        if not center or not recorded or not isinstance(recorded, str) or "T" not in recorded:
            st.info("날짜가 확인된 로그 근거가 없어 주변 이벤트를 연결할 수 없습니다.")
        else:
            nearby = find_correlated_events(
                case_dir, manifest,
                {"occurred_at": recorded},
                window_seconds=120, limit=80,
            )
            mapped = [{
                "시각": record["시간"],
                "기준 시각차(초)": record.get("시각차(초)"),
                "이벤트": EVENT_NAMES.get(record["유형"], "미분류"),
                "정보": record["주요값"],
                "근거 위치": record["근거 위치"],
            } for record in nearby]
            if mapped:
                st.dataframe(pd.DataFrame(mapped), hide_index=True, width="stretch")
            else:
                st.caption("주변에 날짜가 확인된 구조화 이벤트가 없습니다.")
            st.caption("시간적으로 가까운 기록이라는 사실만으로 인과관계가 확정되지 않습니다.")


def _events_table(case_dir: Path, manifest: dict[str, Any],
                  result: dict[str, Any], *, view: str,
                  from_key: str, to_key: str) -> None:
    prefix = f"wb_{case_dir.name}_{view}"
    query, page, page_size = _query_controls(
        case_dir, manifest, result, view=view,
        from_key=from_key, to_key=to_key,
    )
    try:
        summary = query_events(case_dir, manifest, query, page=page, page_size=page_size)
    except ValueError as exc:
        st.warning(str(exc))
        return
    st.caption(f"실제 조건 일치: {summary['total']:,}건 · 전체 {summary['pages']:,}페이지 · "
               f"현재 {page:,}페이지 · 원본은 변경하지 않습니다.")
    if page > summary["pages"]:
        st.info("선택한 조건의 마지막 페이지를 초과했습니다. 페이지 번호를 줄여 주세요.")
        return
    rows = summary["rows"]
    if not rows:
        st.info("해당 조건에 맞는 이벤트가 없습니다. 유형·시간 조건을 조정하세요.")
        return
    columns = st.multiselect(
        "표에 표시할 열",
        options=DISPLAY_FIELDS[view],
        default=DEFAULT_COLUMNS[view],
        key=f"{prefix}_columns",
    )
    if not columns:
        st.warning("표시할 열을 하나 이상 선택하세요.")
        return
    frame = pd.DataFrame(rows)
    st.download_button(
        "현재 페이지 CSV 받기 (구조화·비식별 값만)",
        data=frame[list(columns)].to_csv(index=False).encode("utf-8-sig"),
        file_name=f"mpush_{view}_page_{page}.csv",
        mime="text/csv", key=f"{prefix}_csv",
    )
    table = st.dataframe(
        frame[list(columns)], hide_index=True, width="stretch",
        height=min(620, 55 + 35 * len(rows)),
        on_select="rerun", selection_mode="single-row",
        key=f"{prefix}_table_{_filter_hash(query, page, columns)}",
    )
    selected_index = _selection_index(table)
    if selected_index is None or not 0 <= selected_index < len(rows):
        st.caption("상세 속성·원본 근거를 보려면 표에서 한 행을 선택하세요.")
        return
    _detail(case_dir, manifest, rows[selected_index],
            key=f"{prefix}_detail_{_filter_hash(query, page, selected_index, rows[selected_index].get('줄번호'))}")


def _job_summary(result: dict[str, Any]) -> None:
    metrics = result.get("metrics") or {}
    jobs = metrics.get("job_runs") or {}
    stats = (metrics.get("stage3") or {}).get("job_duration_statistics") or {}
    rows = []
    for name, item in sorted(jobs.items()):
        if not isinstance(name, str) or not name.isupper() or not name.replace("_", "").isalnum():
            continue
        q = stats.get(name) or {}
        rows.append({
            "Job": name, "실행 기록": item.get("runs"), "완료": item.get("completed"),
            "미완료": item.get("incomplete"), "처리대상 합계": item.get("target_count_total"),
            "평균(초)": q.get("average"), "P50(초)": q.get("p50"),
            "P95(초)": q.get("p95"), "최대(초)": q.get("max_seconds"),
            "절대 기준 초과": q.get("slow_above_absolute"),
        })
    st.markdown("#### Job별 처리 통계")
    if rows:
        st.dataframe(pd.DataFrame(rows), hide_index=True, width="stretch")
    else:
        st.info("파싱된 Job 실행 기록이 없습니다.")
    st.caption("Job 실행 기록, 처리대상 건수 및 최종 수신 성공은 동일한 지표가 아닙니다.")
    if any(item.get("percentiles_skipped_due_to_limit") for item in stats.values()):
        st.warning("집계 표본 상한으로 일부 Job의 P50/P95를 계산하지 못했습니다.")


def _db_summary(result: dict[str, Any]) -> None:
    metrics = result.get("metrics") or {}
    sql = metrics.get("db_executions") or {}
    stats = (metrics.get("stage3") or {}).get("db_duration_statistics") or {}
    a, b, c = st.columns(3)
    a.metric("전체 SQL 실행 기록", f"{sql.get('runs', 0):,}")
    b.metric("미완료 SQL 기록", f"{sql.get('incomplete', 0):,}")
    max_time = sql.get("max_laptime_ms")
    c.metric("최대 SQL 시간(ms)", f"{max_time:,.1f}" if type(max_time) in (int, float) else "확인 불가")
    rows = [{
        "PSTMT 유형": name, "실행 기록": stat.get("samples"),
        "평균(ms)": stat.get("average"), "P50(ms)": stat.get("p50"),
        "P95(ms)": stat.get("p95"), "최대(ms)": stat.get("max_ms"),
        "절대 기준 초과": stat.get("slow_above_absolute"),
    } for name, stat in sorted(stats.items()) if isinstance(name, str) and name.isupper()]
    st.markdown("#### SQL 유형별 처리시간")
    if rows:
        st.dataframe(pd.DataFrame(rows), hide_index=True, width="stretch")
    else:
        st.caption("집계된 SQL 처리시간 정보가 없습니다.")
    if any(item.get("percentiles_skipped_due_to_limit") for item in stats.values()):
        st.warning("집계 표본 상한으로 일부 SQL의 P50/P95를 계산하지 못했습니다.")
    st.caption("SQL 실행 지연은 관측 사실이며 DB Lock·자원 고갈이 확인된 것은 아닙니다.")


def _signal_summary(case_dir: Path, result: dict[str, Any],
                    manifest: dict[str, Any]) -> None:
    stage3 = (result.get("metrics") or {}).get("stage3") or {}
    errors = stage3.get("explicit_errors_count") or {}
    if errors:
        st.markdown("#### 명시적으로 기록된 오류")
        from .incident_overview import CATEGORIES
        lines = [{"오류 유형": name, "발생 기록": count}
                 for name, count in errors.items() if name in CATEGORIES and type(count) is int]
        if lines:
            st.dataframe(pd.DataFrame(lines), hide_index=True, width="stretch")
    found = query_events(case_dir, manifest, EventQuery(view="signals"), page_size=25)
    exceptions = found.get("by_exception") or {}
    if exceptions:
        st.markdown("#### 예외 클래스별 실제 발생 건수")
        st.dataframe(pd.DataFrame([
            {"예외 클래스": name, "발생": count}
            for name, count in sorted(exceptions.items(), key=lambda x: -x[1])
        ]), hide_index=True, width="stretch")
    stats = stage3.get("healthcheck_statistics") or {}
    lines = []
    for fid, values in sorted(stats.items()):
        if not isinstance(values, dict):
            continue
        lines.append({
            "로그": file_label(fid, manifest),
            "관측 헬스체크": values.get("healthcheck_samples"),
            "날짜 확정 표본": values.get("anchored_samples"),
            "관측 통상 간격(초)": values.get("estimated_interval_seconds"),
            "긴 공백 횟수": values.get("long_gaps_detected"),
            "최대 기록 간격(초)": values.get("largest_observed_gap_seconds"),
        })
    if lines:
        st.markdown("#### 헬스체크 기록 간격")
        st.dataframe(pd.DataFrame(lines), hide_index=True, width="stretch")
    skips = stage3.get("running_state_skips") or {}
    if skips:
        st.markdown("#### RUNNING 상태 중복 실행 건너뛰기")
        st.dataframe(pd.DataFrame([{"Job": k, "횟수": v} for k, v in sorted(skips.items())
                                  if isinstance(k, str) and k.isupper() and type(v) is int]),
                     hide_index=True, width="stretch")
    st.caption("헬스체크 기록 공백은 Agent 정지나 통신 장애의 확정 증거가 아닙니다.")


def _quality(manifest: dict[str, Any], result: dict[str, Any]) -> None:
    metrics = result.get("metrics") or {}
    a, b, c, d = st.columns(4)
    a.metric("분석 상태", "완료" if result.get("analysis_status") == "complete" else "제한 있음")
    b.metric("날짜 미확인 이벤트", f"{metrics.get('undated_events', 0):,}")
    c.metric("미완료 이벤트", f"{metrics.get('incomplete_events', 0):,}")
    d.metric("제출 파일", f"{len(manifest.get('files') or []):,}")
    st.markdown("#### 제출된 전체 파일 목록")
    submitted = manifest.get("files") or []
    sources = [{
        "파일": file_label(f.get("file_id"), manifest),
        "종류": f.get("kind"),
        "완전성": {"full": "전체 제출", "partial": "일부 추출",
                 "unknown": "미확인"}.get(f.get("completeness"), "미확인"),
        "원본 줄 수": f.get("line_count"),
        "용량(MiB)": round(f.get("size_bytes", 0) / (1024 ** 2), 2),
    } for f in submitted]
    if sources:
        st.dataframe(pd.DataFrame(sources), hide_index=True, width="stretch")
    st.markdown("#### 파일별 수집·파싱 현황")
    records = file_quality_rows(result, manifest)
    if records:
        st.dataframe(pd.DataFrame(records), hide_index=True, width="stretch")
    else:
        st.info("파일별 파싱 품질 기록이 없습니다.")
    st.caption(
        "로그의 모든 줄이 이벤트인 것은 아니므로, '구조화 이벤트 / 읽은 줄'을 "
        "파싱 성공률로 해석해서는 안 됩니다."
    )
    st.markdown("#### 분석 결과를 해석할 때 확인할 점")
    partial = sum(f.get("completeness") != "full" for f in submitted
                  if f.get("kind") != "agent_ini")
    unknown = sum(f.get("kind") == "unknown" for f in submitted)
    flags = [
        ("원본 완전성 미확인·일부 추출 파일", partial),
        ("미지원·미분류 파일", unknown),
        ("날짜 미확인 이벤트", metrics.get("undated_events", 0)),
        ("미완료 정규화 이벤트", metrics.get("incomplete_events", 0)),
    ]
    st.dataframe(pd.DataFrame([{"검토 사항": n, "건수": x} for n, x in flags]),
                 hide_index=True, width="stretch")
    st.info(
        "현재 분석은 제출된 Agent 로그에 나타난 이벤트만 다룹니다. "
        "동일 Agent 인스턴스 여부, 로그 누락, 운영 DB·JVM·네트워크의 실제 상태는 "
        "이 화면만으로 확정할 수 없습니다."
    )
    st.caption("원본 파일명·SQL 본문·메시지 내용 및 인증정보는 결과 조회에 표시하지 않습니다.")


def render_workbench(case_dir: Path, manifest: dict[str, Any],
                     result: dict[str, Any], matches: dict[str, Any]) -> None:
    st.subheader("MPushAgent 로그 분석 워크벤치")
    st.caption("전체 실행 이력 → 이상 발생 시간대 → 관련 로그 → 원본 근거 순으로 조사합니다.")
    if result.get("analysis_status") != "complete":
        st.warning("분석 자료가 일부 추출됐거나 날짜 근거가 부족합니다. 결과 해석에 제한이 있습니다.")
    nav_key = f"workbench_nav_{case_dir.name}"
    from_key = f"wb_{case_dir.name}_range_from"
    to_key = f"wb_{case_dir.name}_range_to"
    screen = st.radio("분석 메뉴", SCREENS, horizontal=True, key=nav_key)
    st.divider()
    if screen == "종합 현황":
        _overview(case_dir, manifest, result, matches, nav_key=nav_key,
                  from_key=from_key, to_key=to_key)
    elif screen == "전체 이벤트":
        st.markdown("### 전체 정규화 이벤트 탐색")
        st.caption("탐지된 대표 항목만이 아니라 모든 구조화 이벤트를 조건별로 조회합니다.")
        _events_table(case_dir, manifest, result, view="events",
                      from_key=from_key, to_key=to_key)
    elif screen == "Job 분석":
        st.markdown("### Job 실행·처리시간 상세")
        st.caption("목록의 '시각'은 Job 완료 기록 기준입니다. 로그상 시작과 역산 시작은 별도 열로 확인하세요.")
        _job_summary(result)
        _events_table(case_dir, manifest, result, view="jobs",
                      from_key=from_key, to_key=to_key)
    elif screen == "DB 분석":
        st.markdown("### SQL 실행·지연 상세")
        _db_summary(result)
        _events_table(case_dir, manifest, result, view="db",
                      from_key=from_key, to_key=to_key)
    elif screen == "이상·오류 분석":
        from dashboard_ui import _render_findings
        st.markdown("### 이상 징후 · 발생 근거 · 추가 확인")
        _signal_summary(case_dir, result, manifest)
        _render_findings(case_dir, manifest, result, matches)
        st.divider()
        st.markdown("### 오류·헬스체크·통신 이벤트 전체 조회")
        st.caption("이 목록은 징후 대표 근거 상한과 무관한 개별 이벤트 조회입니다.")
        _events_table(case_dir, manifest, result, view="signals",
                      from_key=from_key, to_key=to_key)
    else:
        st.markdown("### 제출 자료 및 분석 신뢰성")
        _quality(manifest, result)
