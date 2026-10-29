"""Investigation workbench V4: all events, detailed fields and safe drilldown.

Synthetic fixtures only. Existing user workspaces and customer logs are unused.
"""
from __future__ import annotations

from datetime import datetime, timedelta
import json
from pathlib import Path

import pytest

from mpush_analyzer.dashboard_data import events_iter
from mpush_analyzer.pipeline import _get_manifest
from mpush_analyzer.runner import run_complete_analysis
from mpush_analyzer.workbench_data import (
    EventQuery, file_quality_rows, project_event, query_events,
)


@pytest.fixture
def analyzed_case(tmp_path: Path):
    from test_incident_evidence_v2 import create_case
    case = create_case(tmp_path)
    result, matches, _ = run_complete_analysis(
        case, knowledge_root=tmp_path / "test_knowledge"
    )
    return case, _get_manifest(case), result, matches


def test_full_event_explorer_preserves_counts_and_refs(analyzed_case):
    case, manifest, result, _ = analyzed_case
    actual = list(events_iter(case, manifest))
    page = query_events(case, manifest, EventQuery(), page_size=200)
    assert page["total"] == result["metrics"]["events_total"] == len(actual)
    assert page["is_truncated"] is False
    assert len(page["rows"]) == len(actual)
    assert all("근거 파일" in row and "줄번호" in row for row in page["rows"])
    assert all(row["원본 ID"] and row["시작행"] > 0 for row in page["rows"])
    assert "Job 실행" in page["by_type"]
    assert "SQL 실행" in page["by_type"]
    assert "헬스체크 결과" in page["by_type"]


def test_job_details_and_filter_preserve_step_breakdown(analyzed_case):
    case, manifest, result, _ = analyzed_case
    found = query_events(case, manifest, EventQuery(view="jobs"), page_size=25)
    assert found["total"] == sum(x["runs"] for x in result["metrics"]["job_runs"].values())
    names = {row["Job"] for row in found["rows"]}
    assert {"SEND_REAL_FILE_IMAGE", "HA_RECEIVE_RESULT"} <= names
    outgoing = next(x for x in found["rows"] if x["Job"] == "SEND_REAL_FILE_IMAGE")
    assert outgoing["작업대상"] == 2
    assert outgoing["SOCKET(초)"] == 1.01
    assert outgoing["처리시간(초)"] == 1.04
    assert outgoing["로그 TPS"] == 2
    assert outgoing["로그상 시작"].startswith("2026-10-15T09:59:59")
    by_job = query_events(
        case, manifest, EventQuery(view="jobs", job_name="HA_RECEIVE_RESULT"),
        page_size=25,
    )
    assert by_job["total"] == 1
    assert by_job["rows"][0]["HTTP OUT(초)"] == 7.95


def test_sql_details_durations_and_threshold_filter(analyzed_case):
    case, manifest, _, _ = analyzed_case
    found = query_events(case, manifest, EventQuery(view="db"), page_size=25)
    assert found["total"] == 1
    db = found["rows"][0]
    assert db["PSTMT 유형"] == "EQ"
    assert db["SQL 명령"] == "SELECT"
    assert db["처리시간(ms)"] == 7119
    assert db["결과"] == "select_completed"
    above = query_events(
        case, manifest, EventQuery(view="db", slow_only=True), page_size=25,
    )
    assert above["total"] == 1
    below = query_events(
        case, manifest, EventQuery(view="db", min_duration=7200), page_size=25,
    )
    assert below["total"] == 0


def test_slow_job_filter_uses_per_job_absolute_threshold(analyzed_case):
    case, manifest, _, _ = analyzed_case
    found = query_events(
        case, manifest, EventQuery(view="jobs", slow_only=True), page_size=25,
    )
    assert found["total"] == 0
    # This is an *absolute* threshold view, not the relative-median finding rule.


def test_cross_log_time_and_kind_filters(analyzed_case):
    case, manifest, _, _ = analyzed_case
    filtered = query_events(case, manifest, EventQuery(
        from_minute="2026-10-15T10:01",
        to_minute="2026-10-15T10:01",
        log_kind="dbwrap",
        event_type="sql_execution",
    ), page_size=25)
    assert filtered["total"] == 1
    assert filtered["rows"][0]["이벤트 코드"] == "sql_execution"
    other = query_events(case, manifest, EventQuery(
        from_minute="2026-10-15T11:00",
        to_minute="2026-10-15T12:00",
    ), page_size=25)
    assert other["total"] == 0


def test_cns_response_not_mislabelled_as_delivery(analyzed_case):
    case, manifest, _, _ = analyzed_case
    found = query_events(case, manifest, EventQuery(
        event_type="cns_response",
    ), page_size=25)
    assert found["total"] == 1
    assert "최종 수신 아님" in found["rows"][0]["주요 정보"]


def test_signals_include_every_error_not_just_representative(analyzed_case):
    case, manifest, _, _ = analyzed_case
    found = query_events(case, manifest, EventQuery(view="signals"), page_size=200)
    errors = [x for x in found["rows"] if x["이벤트 코드"] == "log_error"]
    assert errors
    assert sum(found["by_exception"].values()) == len(errors)
    assert any("SocketTimeoutException" in r["주요 정보"] for r in errors)
    assert any(x["이벤트 코드"] == "healthcheck_result" for x in found["rows"])


def test_projection_never_includes_arbitrary_payload_fields():
    manifest = {"files": [{"file_id": "file_01", "kind": "dbwrap",
                           "storage_name": "dbwrap_01.log"}]}
    event = {
        "file_id": "file_01", "line_start": 10, "line_end": 12,
        "log_kind": "dbwrap", "event_type": "sql_execution",
        "status": "complete", "clock": "10:00:00.001",
        "occurred_at": "2026-10-15T10:00:00+09:00",
        "details": {
            "statement_kind": "EQ", "sql_operation": "SELECT",
            "laptime_ms": 1000, "outcome": "select_completed",
            "sql": "SELECT PRIVATE_VALUE FROM PRIVATE_TABLE",
            "phone": "010-1234-5678", "message": "PRIVATE_KEY",
            "affected_rows": "010-1234-5678",
        },
        "exception": "PRIVATE_TOKEN",
    }
    rendered = project_event(event, manifest)
    text = json.dumps(rendered, ensure_ascii=False)
    for forbidden in ("PRIVATE_VALUE", "PRIVATE_TABLE", "PRIVATE_KEY",
                      "PRIVATE_TOKEN", "010-1234-5678", "SELECT PRIVATE"):
        assert forbidden not in text
    assert rendered["PSTMT 유형"] == "EQ"
    assert rendered["처리시간(ms)"] == 1000
    assert rendered["영향 행수"] is None
    assert rendered["시각"].startswith("2026-10-15T10:00")


def test_projection_rejects_malicious_timestamps_and_untrusted_types():
    manifest = {"files": [{"file_id": "file_01", "kind": "err",
                           "storage_name": "err_01.log"}]}
    malicious = {
        "file_id": "file_01", "line_start": 3, "line_end": 3,
        "event_type": [], "clock": "PRIVATE_CLOCK",
        "occurred_at": "PRIVATE_TIMESTAMP", "status": "PRIVATE_STATUS",
        "details": {"exception_class": "PRIVATE"},
    }
    result = project_event(malicious, manifest)
    assert result["시각"] == "시각 미확인"
    assert result["상태"] == "미확인"
    assert result["주요 정보"] == "구조화 세부값 없음"
    assert "PRIVATE" not in json.dumps(result)


def test_invalid_filters_fail_closed(analyzed_case):
    case, manifest, _, _ = analyzed_case
    cases = [
        EventQuery(view="invalid"),
        EventQuery(event_type="PRIVATE"),
        EventQuery(job_name="some private text"),
        EventQuery(file_id="../private"),
        EventQuery(from_minute="not a date"),
        EventQuery(from_minute="2026-10-15T25:00"),
        EventQuery(from_minute="2026-10-16T10:00", to_minute="2026-10-15T10:00"),
        EventQuery(view="events", slow_only=True),
        EventQuery(view="events", sort="duration_desc"),
        EventQuery(view="db", min_duration=-1),
    ]
    for query in cases:
        with pytest.raises(ValueError):
            query_events(case, manifest, query, page_size=25)
    with pytest.raises(ValueError, match="20,000"):
        query_events(case, manifest, EventQuery(view="jobs", sort="time_desc"),
                     page=1000, page_size=200)


def _many_events(tmp_path: Path) -> tuple[Path, dict]:
    root = tmp_path / "many"
    root.mkdir()
    manifest = {"files": [{
        "file_id": "file_01", "storage_name": "job_01.log", "kind": "job",
    }]}
    origin = datetime.fromisoformat("2026-10-15T10:00:00+09:00")
    with (root / "events.jsonl").open("w", encoding="utf-8") as handle:
        for i in range(213):
            item = {
                "file_id": "file_01", "line_start": i + 1, "line_end": i + 1,
                "event_id": f"file_01_{i+1:09d}", "event_type": "job_run",
                "log_kind": "job", "status": "complete",
                "clock": "10:00:00.000",
                "occurred_at": (origin + timedelta(minutes=i)).isoformat(),
                "details": {
                    "job_name": "SEND_REAL_FILE_IMAGE", "target_count": i,
                    "duration_seconds": i, "completed": True,
                    "steps_seconds": {},
                },
            }
            handle.write(json.dumps(item) + "\n")
    return root, manifest


def test_paging_ascending_latest_and_slowest(tmp_path: Path):
    root, manifest = _many_events(tmp_path)
    asc = query_events(root, manifest, EventQuery(view="jobs"), page=3, page_size=50)
    assert asc["total"] == 213
    assert asc["pages"] == 5
    assert asc["rows"][0]["시작행"] == 101
    assert asc["rows"][-1]["시작행"] == 150
    recent = query_events(root, manifest, EventQuery(view="jobs", sort="time_desc"),
                          page=2, page_size=25)
    assert recent["rows"][0]["시작행"] == 188
    assert recent["rows"][-1]["시작행"] == 164
    slowest = query_events(root, manifest, EventQuery(view="jobs", sort="duration_desc"),
                           page=1, page_size=25)
    assert slowest["rows"][0]["처리시간(초)"] == 212
    assert slowest["rows"][-1]["처리시간(초)"] == 188
    last = query_events(root, manifest, EventQuery(view="jobs"), page=5, page_size=50)
    assert len(last["rows"]) == 13
    assert last["is_truncated"] is False


def test_slow_filter_preserves_all_matching_occurrences(tmp_path: Path):
    root, manifest = _many_events(tmp_path)
    records = query_events(
        root, manifest, EventQuery(view="jobs", slow_only=True),
        page=1, page_size=200,
    )
    assert records["total"] == 208
    assert records["rows"][0]["처리시간(초)"] == 5
    second = query_events(
        root, manifest, EventQuery(view="jobs", slow_only=True),
        page=2, page_size=25,
    )
    assert second["total"] == 208
    assert second["rows"][0]["처리시간(초)"] == 30


def test_quality_table_is_safe_and_traceable(analyzed_case):
    _, manifest, result, _ = analyzed_case
    rows = file_quality_rows(result, manifest)
    assert any(x["종류"] == "dbwrap" and x["구조화 이벤트"] == 1 for x in rows)
    assert all(x["읽은 줄"] >= x["구조화 이벤트"] for x in rows)
    assert all("file_" in x["파일"] for x in rows)


def test_workbench_streamlit_screens_render_synthetic_case(analyzed_case, monkeypatch):
    from streamlit.testing.v1 import AppTest
    import mpush_analyzer.lifecycle as lifecycle
    case, _, _, _ = analyzed_case
    monkeypatch.setattr(lifecycle, "list_cases", lambda _: [case])
    app = AppTest.from_file(
        str(Path(__file__).resolve().parents[1] / "app.py"),
        default_timeout=60,
    ).run()
    assert not app.exception, [x.message for x in app.exception]
    navigation = next(r for r in app.radio if r.label == "분석 메뉴")
    for screen in ("전체 이벤트", "Job 분석", "DB 분석",
                   "이상·오류 분석", "수집·분석 품질"):
        app = next(r for r in app.radio if r.label == "분석 메뉴").set_value(screen).run()
        assert not app.exception, (screen, [x.message for x in app.exception])
        expected = {
            "전체 이벤트": "전체 정규화 이벤트 탐색",
            "Job 분석": "Job 실행·처리시간 상세",
            "DB 분석": "SQL 실행·지연 상세",
            "이상·오류 분석": "이상 징후 · 발생 근거",
            "수집·분석 품질": "제출 자료 및 분석 신뢰성",
        }[screen]
        assert any(expected in x.value for x in app.markdown)


def test_overview_time_window_drills_into_prefiltered_event_list(analyzed_case, monkeypatch):
    from streamlit.testing.v1 import AppTest
    import mpush_analyzer.lifecycle as lifecycle
    case, _, _, _ = analyzed_case
    monkeypatch.setattr(lifecycle, "list_cases", lambda _: [case])
    app = AppTest.from_file(
        str(Path(__file__).resolve().parents[1] / "app.py"),
        default_timeout=60,
    ).run()
    assert not app.exception
    jump = next(x for x in app.button if x.label == "선택 시간대의 전체 이벤트 조회")
    app = jump.click().run()
    assert not app.exception, [x.message for x in app.exception]
    navigation = next(x for x in app.radio if x.label == "분석 메뉴")
    assert navigation.value == "전체 이벤트"
    begin = next(x.value for x in app.text_input if x.label == "시작 시각")
    end = next(x.value for x in app.text_input if x.label == "종료 시각")
    assert begin.startswith("2026-10-15T")
    assert end.startswith("2026-10-15T")
    assert begin <= end
