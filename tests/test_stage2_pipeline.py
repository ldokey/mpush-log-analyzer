"""Stage-2 integration and security tests; all inputs are synthetic."""
from __future__ import annotations

from datetime import date
import json
from pathlib import Path
import hashlib

import pytest
from jsonschema import Draft202012Validator

from mpush_analyzer.case_contract import load_schema
from mpush_analyzer.intake import Upload, inspect_uploads
from mpush_analyzer.pipeline import analyze_case, _merged_chunks, _write_jsonlines
from mpush_analyzer.storage import save_intake


SYNTHETIC_JOB = """10:12:17[106]

##  SEND_REAL_FILE_IMAGE 작업
10:12:17[106] ##  작업대상건수 : 2
10:12:17[106] ##  시작시간 : 10시 11분 23.30초
10:12:17[106] ##  종료시간 : 10시 12분 17.106초
10:12:17[106] ##  SELECT 시간(초.0f) : 0.436초
10:12:17[106] ##  FILE 시간(초.0f) : 0.645초
10:12:17[106] ##  SOCKET 시간(초.0f) : 52.995초
10:12:17[106] ##  소요시간(초.0f) : 54.076초
10:12:17[106] ##  초당 작업 건수 : 0.037건
10:14:30[000]

##  HA_RECEIVE_RESULT 작업
10:14:30[000] ##  작업대상건수 : 1
10:14:30[000] ##  시작시간 : 10시 13분 4.523초
10:14:30[000] ##  종료시간 : 10시 14분 30.000초
10:14:30[000] ##  HTTP IN 시간(초.0f) : 23.939초
10:14:30[000] ##  DB 시간(초.0f) : 5.817초
10:14:30[000] ##  HTTP OUT 시간(초.0f) : 55.721초
10:14:30[000] ##  소요시간(초.0f) : 85.477초
10:14:30[000] Done
"""
SYNTHETIC_DB = """10:13:10[001]
NO_ID_-456=PSTMT.EQ Laptime : 7119
NO_ID_-456=    SELECT SECRET_CUSTOMER_TOKEN
NO_ID_-456=    FROM SECRET_CUSTOMER_SCHEMA.MESSAGES
NO_ID_-456=Result : select completed.
10:13:11[021]
NO_ID_789=PSTMT.EU Laptime : 123
NO_ID_789=UPDATE DEMO SET token='SECRET_TOKEN_NOT_FOR_OUTPUT'
NO_ID_789=Result : 0 row(s) updated.
10:13:12[000]
NO_ID_789=PSTMT.EB Laptime : 14 Result : batch job success.
"""
SYNTHETIC_DEBUG = """10:12:10[000] 헬스 체크 서비스 번호 : 9876543210
10:12:10[195] 헬스 체크 결과 : {"TARGET":"Nothing"}
10:12:32[010] ***************** 서버에서 받은 문자열 [{"RESPONSE_CODE":"S"}]
10:12:40[001] -- Can't execute task in RUNNING state :: SEND_REAL_FILE_IMAGE --
10:13:27[000] 헬스 체크 결과 : {"TARGET":"Nothing"}
10:14:15[190] my_sensitive_field=SECRET_CUSTOMER_TOKEN
"""
SYNTHETIC_INI = """[AGENT]
id=A1
type=real
[DBMS]
type=mysql
password=SECRET_INI_PASSWORD
url=jdbc:mysql://192.0.2.88:3306/db
"""


def make_case(tmp_path: Path, *, completeness: str = "full", no_date: bool = False) -> Path:
    prefix = "sample" if no_date else "20261015"
    files = [
        Upload(f"{prefix}job.log", SYNTHETIC_JOB.encode(), completeness=completeness),
        Upload(f"{prefix}dbwrap.log", SYNTHETIC_DB.encode(), completeness=completeness),
        Upload(f"{prefix}debug.log", SYNTHETIC_DEBUG.encode(), completeness=completeness),
        Upload("agent.ini", SYNTHETIC_INI.encode(), completeness=completeness),
    ]
    inspected = inspect_uploads(files)
    path, _ = save_intake(
        inspected, tmp_path / "workspace",
        agent_version="3.3",
        reference_date=None if no_date else date(2026, 10, 15),
        collected_at="2026-10-15T15:20:00+09:00",
    )
    return path


def test_analyze_case_stats_sorting_privacy_and_schema(tmp_path: Path):
    path = make_case(tmp_path)
    result = analyze_case(path)
    metrics = result["metrics"]
    assert metrics["job_runs"]["SEND_REAL_FILE_IMAGE"] == {
        "runs": 1, "completed": 1, "incomplete": 0,
        "target_count_total": 2, "max_duration_seconds": 54.076
    }
    assert metrics["job_runs"]["HA_RECEIVE_RESULT"]["max_duration_seconds"] == 85.477
    assert metrics["db_executions"]["runs"] == 3
    assert metrics["db_executions"]["by_statement"] == {"EQ": 1, "EU": 1, "EB": 1}
    assert metrics["db_executions"]["max_laptime_ms"] == 7119.0
    assert metrics["cns_request_responses"] == {"S": 1}
    assert metrics["event_counts"]["healthcheck_result"] == 2
    assert result["analysis_status"] == "complete"
    assert result["findings"] == []  # Stage-3 owns anomaly findings.
    lines = (path / "events.jsonl").read_text(encoding="utf-8").splitlines()
    events = [json.loads(line) for line in lines]
    timestamps = [x["occurred_at"] for x in events]
    assert timestamps == sorted(timestamps)
    assert any(x["event_type"] == "job_run" and x["line_start"] > 0 for x in events)
    cns = next(x for x in events if x["event_type"] == "cns_response")
    assert cns["details"]["final_delivery_confirmed"] is False
    assert cns["details"]["interpretation"] == "request_accepted"
    derived = (path / "events.jsonl").read_text() + (path / "analysis_result.json").read_text()
    for sensitive in ("SECRET_CUSTOMER_TOKEN", "SECRET_TOKEN_NOT_FOR_OUTPUT", "SECRET_INI_PASSWORD", "9876543210", "192.0.2.88", "NO_ID_789"):
        assert sensitive not in derived
    assert (path / "events.jsonl").stat().st_mode & 0o077 == 0
    assert (path / "analysis_result.json").stat().st_mode & 0o077 == 0
    Draft202012Validator(load_schema("analysis_result.schema.json")).validate(result)

    original_events = (path / "events.jsonl").read_bytes()
    original_summary = (path / "analysis_result.json").read_bytes()
    assert analyze_case(path) == result
    assert (path / "events.jsonl").read_bytes() == original_events
    assert (path / "analysis_result.json").read_bytes() == original_summary


def test_hash_tampering_fails_before_derived_output(tmp_path: Path):
    path = make_case(tmp_path)
    raw = path / "raw" / "job_01.log"
    raw.write_text(raw.read_text() + "tamper\n")
    with pytest.raises(ValueError):
        analyze_case(path)
    assert not (path / "events.jsonl").exists()
    assert not (path / "analysis_result.json").exists()


def test_symlink_raw_file_fails_closed(tmp_path: Path):
    path = make_case(tmp_path)
    raw = path / "raw" / "job_01.log"
    target = tmp_path / "elsewhere.log"
    target.write_bytes(raw.read_bytes())
    raw.unlink()
    raw.symlink_to(target)
    with pytest.raises(ValueError):
        analyze_case(path)


def test_partial_and_missing_date_show_limitations(tmp_path: Path):
    path = make_case(tmp_path, completeness="partial", no_date=True)
    result = analyze_case(path)
    assert result["analysis_status"] == "partial"
    assert result["metrics"]["undated_events"] > 0
    assert any("기준 날짜" in x for x in result["limitations"])
    assert any("일부 추출" in x for x in result["limitations"])


def test_incomplete_job_is_not_counted_as_completed(tmp_path: Path):
    truncated = "12:00:00[000] \n##  SEND_REAL_FILE_IMAGE 작업\n12:00:00[000] ##  작업대상건수 : 2\n".encode()
    path, _ = save_intake(
        inspect_uploads([Upload("20261015job.log", truncated,
            completeness="full")]), tmp_path / "workspace",
        reference_date=date(2026, 10, 15)
    )
    result = analyze_case(path)
    assert result["analysis_status"] == "partial"
    assert result["metrics"]["job_runs"]["SEND_REAL_FILE_IMAGE"]["incomplete"] == 1
    assert result["metrics"]["job_runs"]["SEND_REAL_FILE_IMAGE"]["completed"] == 0


def test_midnight_rollover_carries_date(tmp_path: Path):
    data = """23:59:59[950] 헬스 체크 결과 : {"TARGET":"Nothing"}
00:00:00[002] 헬스 체크 결과 : {"TARGET":"Nothing"}
""".encode()
    path, _ = save_intake(
        inspect_uploads([Upload("20261015debug.log", data, completeness="full")]),
        tmp_path / "workspace", reference_date=date(2026, 10, 15),
    )
    result = analyze_case(path)
    events = [json.loads(x) for x in (path / "events.jsonl").read_text().splitlines()]
    assert events[0]["occurred_at"].startswith("2026-10-15")
    assert events[1]["occurred_at"].startswith("2026-10-16")
    assert result["metrics"]["source_summary"][0]["midnight_rollovers"] == 1


def test_multi_pass_external_merge(tmp_path: Path):
    paths = []
    for index in range(31):
        path = tmp_path / f"chunk_{index}.jsonl"
        _write_jsonlines(path, [{
            "occurred_at": f"2026-10-15T10:00:{30-index:02d}.000+09:00",
            "file_id": "file_01", "line_start": index + 1, "clock": None,
        }])
        paths.append(path)
    merged = _merged_chunks(paths, tmp_path)
    events = [json.loads(line) for line in merged.read_text().splitlines()]
    assert len(events) == 31
    assert [x["occurred_at"] for x in events] == sorted(x["occurred_at"] for x in events)



def test_pending_summary_symlink_is_rejected(tmp_path: Path):
    path = make_case(tmp_path)
    outside = tmp_path / "outside.txt"
    outside.write_text("keep me", encoding="utf-8")
    (path / "analysis_result.json.pending").symlink_to(outside)
    with pytest.raises(ValueError):
        analyze_case(path)
    assert outside.read_text(encoding="utf-8") == "keep me"
    assert not (path / "analysis_result.json").exists()
