"""Evidence-first incident UI / AI handoff regression, synthetic data only."""
from __future__ import annotations
from copy import deepcopy
from datetime import date
import json
from pathlib import Path

import pytest

from mpush_analyzer.ai_brief_v2 import build_ai_exports, build_packet, to_markdown
from mpush_analyzer.finding_view_v2 import (
    details, evidence_rows, file_label, format_timestamp, summary_row, time_information
)
from mpush_analyzer.intake import Upload, inspect_uploads
from mpush_analyzer.permissions import private_fd
from mpush_analyzer.pipeline import _get_manifest
from mpush_analyzer.report import build_exports, report_data
from mpush_analyzer.runner import run_complete_analysis
from mpush_analyzer.storage import save_intake
from mpush_analyzer.time_utils import job_time_fields

SYNTHETIC_JOB = """10:00:00[340]
##  SEND_REAL_FILE_IMAGE 작업
10:00:00[340] ##  작업대상건수 : 2
10:00:00[340] ##  시작시간 : 9시 59분 59.300초
10:00:00[340] ##  종료시간 : 10시 0분 0.340초
10:00:00[340] ##  SOCKET 시간(초.0f) : 1.010초
10:00:00[340] ##  소요시간(초.0f) : 1.040초
10:00:00[340] ##  초당 작업 건수 : 2건
10:01:20[300]
##  HA_RECEIVE_RESULT 작업
10:01:20[300] ##  작업대상건수 : 1
10:01:20[300] ##  시작시간 : 10시 1분 12.300초
10:01:20[300] ##  종료시간 : 10시 1분 20.300초
10:01:20[300] ##  HTTP OUT 시간(초.0f) : 7.950초
10:01:20[300] ##  소요시간(초.0f) : 8.000초
"""
SYNTHETIC_DB = """10:01:16[004]
NO_ID_-99=PSTMT.EQ Laptime : 7119
NO_ID_-99=SELECT PRIVATE_CLIENT_KEY FROM SECRET_SCHEMA
NO_ID_-99=WHERE PHONE='010-1234-5678'
NO_ID_-99=Result : select completed.
"""
SYNTHETIC_DEBUG = """10:00:00[001] 헬스 체크 결과 : {"TARGET":"Nothing"}
10:00:10[001] 헬스 체크 결과 : {"TARGET":"Nothing"}
10:00:20[001] 헬스 체크 결과 : {"TARGET":"Nothing"}
10:00:30[001] 헬스 체크 결과 : {"TARGET":"Nothing"}
10:01:35[001] 헬스 체크 결과 : {"TARGET":"Nothing"}
10:01:40[001] 헬스 체크 결과 : {"TARGET":"Nothing"}
10:01:41[001] ***************** 서버에서 받은 문자열 [{"RESPONSE_CODE":"S"}]
10:01:42[001] SECRET_CLIENT_KEY=PRIVATE_VALUE
"""
SYNTHETIC_ERR = """10:01:22[033] java.net.SocketTimeoutException: SECRET_CLIENT_KEY
   at demo.module.run(Module.java:123)
"""
INI = """[AGENT]
id=A1
[DBMS]
type=mysql
password=TEST_PRIVATE_PASSWORD
"""


def create_case(tmp_path: Path, *, date_given: bool = True) -> Path:
    path,_ = save_intake(
        inspect_uploads([
            Upload("job.log", SYNTHETIC_JOB.encode("utf-8"), completeness="full"),
            Upload("dbwrap.log", SYNTHETIC_DB.encode("utf-8"), completeness="full"),
            Upload("debug.log", SYNTHETIC_DEBUG.encode("utf-8"), completeness="full"),
            Upload("err.log", SYNTHETIC_ERR.encode("utf-8"), completeness="full"),
            Upload("agent.ini", INI.encode("utf-8"), completeness="full"),
        ]),
        tmp_path / "workspace", agent_version="3.3",
        reference_date=date(2026, 10, 15) if date_given else None,
        collected_at="2026-10-15T15:20:00+09:00"
    )
    return path


def test_finding_alias_and_gap_time_labels(tmp_path: Path):
    case=create_case(tmp_path)
    result,matches,_=run_complete_analysis(case,knowledge_root=tmp_path/"library")
    manifest=_get_manifest(case)
    assert file_label("file_01", manifest)=="job_01.log (file_01)"
    assert file_label("file_02", manifest)=="dbwrap_01.log (file_02)"
    assert file_label("file_05", manifest)=="agent_ini_01.ini (file_05)"
    gap=next(f for f in result["findings"] if f.get("rule_id")=="HEALTHCHECK_TAIL")
    shown=details(gap,manifest)
    assert shown["time"]["시작"].startswith("2026-10-15 10:01:40.001")
    assert shown["time"]["끝"].startswith("2026-10-15 15:20:00")
    assert "장애 발생시각 아님" in shown["time"]["기준"]
    assert "debug_01.log" in summary_row(gap,manifest)["근거 파일"]
    assert "file_03" in summary_row(gap,manifest)["근거 파일"]
    for row in evidence_rows(gap,manifest):
        assert row["시작행"] > 0 and row["끝행"] >= row["시작행"]
        assert row["근거시각"].startswith("2026-10-15")
    report=report_data(result,matches,manifest)
    gap_report=next(x for x in report["findings"] if x["signal"]=="HEALTHCHECK_GAP" and "수집" in x["time"]["기준"])
    assert "마지막" in gap_report["time"]["기준"]
    assert "시각" in gap_report["explanation"]
    assert any("debug_01.log" in x for x in gap_report["evidence_locations"])


def test_time_without_date_and_inferred_job_start(tmp_path: Path):
    case=create_case(tmp_path,date_given=False)
    result,matches,_=run_complete_analysis(case,knowledge_root=tmp_path/"library")
    manifest=_get_manifest(case)
    assert result["analysis_status"]=="partial"
    first=next(iter((case/"events.jsonl").read_text().splitlines()))
    assert json.loads(first)["occurred_at"] is None
    for finding in result["findings"]:
        shown=details(finding,manifest)
        assert shown["time"]["시작"].startswith(("날짜 미확인","시각 확인 불가"))
    assert format_timestamp(None,clock="10:14:30.001")=="날짜 미확인 · 10:14:30.001"


def test_log_job_start_and_duration_consistency(tmp_path: Path):
    case=create_case(tmp_path)
    result,matches,_=run_complete_analysis(case,knowledge_root=tmp_path/"library")
    jobs=[json.loads(line) for line in (case/"events.jsonl").read_text().splitlines()
          if '"event_type":"job_run"' in line]
    assert len(jobs)==2
    send=next(job for job in jobs if job["details"]["job_name"]=="SEND_REAL_FILE_IMAGE")
    details_value=send["details"]
    assert details_value["start_clock"]=="09:59:59.300"
    assert details_value["start_clock_consistent"] is True
    assert details_value["calculated_start_at"].startswith("2026-10-15T09:59:59.300")
    assert send["time_date_source"]=="reference_date"
    fake=job_time_fields("2026-10-15T10:00:00.000+09:00",
        {"start_clock":"08:00:00.000","duration_seconds":1})
    assert fake["start_time_quality"]=="duration_clock_conflict"
    assert fake["start_clock_consistent"] is False


def test_ai_packets_include_source_context_without_personal_details(tmp_path: Path):
    case=create_case(tmp_path)
    result,matches,_=run_complete_analysis(case,knowledge_root=tmp_path/"library")
    manifest=_get_manifest(case)
    packet=build_packet(case,manifest,result,matches)
    assert len(packet["findings"])==len(result["findings"])
    assert packet["analysis_status"]==result["analysis_status"]
    assert packet["source_files"][0]["label"]=="job_01.log (file_01)"
    refs=[e for f in packet["findings"] for e in f["evidence"]]
    assert any(e.get("occurred_at") for e in refs)
    assert any(f["nearby_sanitized_events"] for f in packet["findings"])
    exports=build_ai_exports(case,manifest,result,matches)
    assert set(exports)=={"ai_brief.md","ai_brief.json"}
    content=exports["ai_brief.md"].decode("utf-8")
    assert "탐지 이유" in content
    assert "근거시각" in content
    assert "dbwrap_01.log" in content
    assert "10:01:16" in content
    assert "사실과 가능한 원인" in content
    for bad in ("PRIVATE_CLIENT_KEY", "010-1234-5678", "SECRET_SCHEMA", "TEST_PRIVATE_PASSWORD",
                "NO_ID_-99", "SECRET_CLIENT_KEY", "PRIVATE_VALUE"):
        assert bad not in content
        assert bad not in exports["ai_brief.json"].decode("utf-8")
    chosen_id=next(f["finding_id"] for f in result["findings"] if f["signal_code"]=="DB_SQL_DELAY")
    selected=build_ai_exports(case,manifest,result,matches,only_finding_id=chosen_id)
    assert len(json.loads(selected["ai_brief.json"])["findings"])==1
    with pytest.raises(ValueError):
        build_ai_exports(case,manifest,result,matches,only_finding_id="F-9999")


def test_reports_never_reproduce_tampered_descriptions_or_case_titles(tmp_path: Path):
    case=create_case(tmp_path)
    result,matches,_=run_complete_analysis(case,knowledge_root=tmp_path/"library")
    manifest=_get_manifest(case)
    forged=deepcopy(result)
    forged["findings"][0]["description"]="PRIVATE_SECRET <script>alert(1)</script>"
    altered=deepcopy(matches)
    altered["matched_cases"]=[{
        "case_id":"MPA-CASE-000010", "revision":2,"title":"PRIVATE_SECRET <script>alert(1)</script>",
        "result_type":"reference_only","matched_required_signals":["SQL_ERROR"],
        "matched_supporting_signals":[]
    }]
    report=build_exports(forged,altered,manifest)
    packet=build_ai_exports(case,manifest,forged,altered)
    for payload in [*report.values(),*packet.values()]:
        assert b"PRIVATE_SECRET" not in payload
        assert b"<script>" not in payload
    assert "2026-10-15" in report["report.md"].decode("utf-8")
    assert "dbwrap_01.log" in report["report.md"].decode("utf-8")


def test_windows_permission_fallback_when_fchmod_not_available(monkeypatch):
    import mpush_analyzer.permissions as permissions
    monkeypatch.delattr(permissions.os, "fchmod", raising=False)
    private_fd(42)  # No exception when Python is built without os.fchmod.


def test_streamlit_dashboard_synthetic_case(tmp_path: Path, monkeypatch):
    from streamlit.testing.v1 import AppTest
    import mpush_analyzer.lifecycle as lifecycle
    case=create_case(tmp_path)
    run_complete_analysis(case,knowledge_root=tmp_path/"library")
    monkeypatch.setattr(lifecycle,"list_cases", lambda workspace: [case])
    test=AppTest.from_file(str(Path(__file__).resolve().parents[1]/"app.py"),default_timeout=35).run()
    assert len(test.exception)==0, [str(x.message) for x in test.exception]
    labels=[x.value for x in test.subheader]
    assert any("장애 분석 대시보드" in x for x in labels)
    assert any("이상 징후" in element.value for element in test.markdown)



def test_ai_limitations_use_safe_templates_and_ignore_secret_prose(tmp_path: Path):
    case = create_case(tmp_path)
    result, matches, _ = run_complete_analysis(case, knowledge_root=tmp_path / "library")
    manifest = _get_manifest(case)
    forged = deepcopy(result)
    forged["limitations"] = [
        "민감한 고객사 이름 DO_NOT_OUTPUT_ME; SOME-PRIVATE-ACCOUNT-999",
        "기준 날짜 없음: 고객 내부 주소 10.7.8.9; confidential-user",
        "일부 추출: SECRET_UNKNOWN_PII_SCHEMA=abcdef987654",
    ]
    result_package = build_ai_exports(case, manifest, forged, matches)
    for data in result_package.values():
        for secret in ("DO_NOT_OUTPUT_ME", "PRIVATE-ACCOUNT-999", "10.7.8.9",
                       "confidential-user", "SECRET_UNKNOWN_PII_SCHEMA"):
            assert secret.encode("utf-8") not in data
    packet = json.loads(result_package["ai_brief.json"])
    assert any("기준 날짜" in line for line in packet["analysis_limitations"])
    assert any("일부 추출" in line for line in packet["analysis_limitations"])


def test_ai_export_requires_untampered_raw_source(tmp_path: Path):
    case = create_case(tmp_path)
    result, matches, _ = run_complete_analysis(case, knowledge_root=tmp_path / "library")
    manifest = _get_manifest(case)
    chosen = next(e for e in manifest["files"] if e["kind"] == "dbwrap")
    raw = case / "raw" / chosen["storage_name"]
    raw.write_bytes(raw.read_bytes() + b"\nSYNTHETIC_MODIFIED_AFTER_ANALYSIS")
    with pytest.raises(ValueError):
        build_ai_exports(case, manifest, result, matches)


def test_bounded_related_events_have_traceable_location(tmp_path: Path):
    case = create_case(tmp_path)
    result, matches, _ = run_complete_analysis(case, knowledge_root=tmp_path / "library")
    manifest = _get_manifest(case)
    selected_id = next(f["finding_id"] for f in result["findings"]
                       if f["signal_code"] == "DB_SQL_DELAY")
    document = build_packet(case, manifest, result, matches, only_finding_id=selected_id)
    nearby = document["findings"][0]["nearby_sanitized_events"]
    assert nearby
    assert len(nearby) <= 16
    for event in nearby:
        assert "file_" in event["evidence_lines"]
        assert any(name in event["log_file"] for name in
                   ("job_01.log", "dbwrap_01.log", "debug_01.log", "err_01.log"))
        assert "PRIVATE_CLIENT_KEY" not in str(event)



def test_duplicate_tail_timestamp_retains_context_for_all_findings(tmp_path: Path):
    case = create_case(tmp_path)
    result, matches, _ = run_complete_analysis(case, knowledge_root=tmp_path / "library")
    manifest = _get_manifest(case)
    packet = build_packet(case, manifest, result, matches)
    tail_ids = {
        f["finding_id"] for f in result["findings"]
        if f.get("rule_id") in {"HEALTHCHECK_TAIL", "MULTI_LOG_TAIL"}
    }
    assert len(tail_ids) >= 2
    for record in packet["findings"]:
        if record["finding_id"] in tail_ids:
            assert record["nearby_sanitized_events"], record["finding_id"]


def test_job_evidence_shows_recorded_and_derived_start_separately(tmp_path: Path):
    case = create_case(tmp_path)
    result, matches, _ = run_complete_analysis(case, knowledge_root=tmp_path / "library")
    manifest = _get_manifest(case)
    finding = next(f for f in result["findings"]
                   if f.get("signal_code") == "TRANSPORT_DELAY")
    records = evidence_rows(finding, manifest)
    assert records
    job_row = records[0]
    assert job_row["로그상 시작"].startswith("2026-10-15")
    assert job_row["계산상 시작"].startswith("2026-10-15")
    assert job_row["시작시각 주의"]
    exports = build_ai_exports(case, manifest, result, matches,
                               only_finding_id=finding["finding_id"])
    assert "로그상 시작" in exports["ai_brief.md"].decode()



def test_nearest_cross_file_records_are_not_dropped_by_dense_early_logs(tmp_path: Path):
    from datetime import datetime, timedelta
    from mpush_analyzer.dashboard_data import find_correlated_events
    root = tmp_path / "sample"
    root.mkdir()
    manifest = {"files": [
        {"file_id": "file_01", "kind": "debug", "storage_name": "debug_01.log"},
        {"file_id": "file_02", "kind": "err", "storage_name": "err_01.log"}
    ]}
    origin = datetime.fromisoformat("2026-10-15T10:00:00+09:00")
    with (root / "events.jsonl").open("w", encoding="utf-8") as handle:
        for index in range(240):
            stamp = (origin + timedelta(seconds=index)).isoformat(timespec="milliseconds")
            event = {
                "file_id": "file_01", "line_start": index + 1,
                "line_end": index + 1, "clock": "10:00:00.000",
                "occurred_at": stamp, "log_kind": "debug",
                "event_type": "healthcheck_result", "details": {"target_action": "no_action"}
            }
            handle.write(json.dumps(event) + "\n")
        outlier = {
            "file_id": "file_02", "line_start": 1000, "line_end": 1003,
            "clock": "10:03:30.000",
            "occurred_at": (origin + timedelta(seconds=210)).isoformat(timespec="milliseconds"),
            "log_kind": "err", "event_type": "log_error",
            "details": {"exception_class": "SocketTimeoutException"}
        }
        handle.write(json.dumps(outlier) + "\n")
    reference = {"occurred_at": (origin + timedelta(seconds=209)).isoformat(timespec="milliseconds")}
    nearby = find_correlated_events(root, manifest, reference,
                                    window_seconds=120, limit=7)
    assert len(nearby) == 7
    assert any(item["근거 위치"] == "file_02:1000-1003" for item in nearby)
    assert all(abs(item["시각차(초)"]) <= 7 for item in nearby)
    assert nearby[0]["시각차(초)"] == 0


def test_richer_ai_statistics_are_numerical_and_semantically_named(tmp_path: Path):
    case = create_case(tmp_path)
    result, matches, _ = run_complete_analysis(case, knowledge_root=tmp_path / "library")
    manifest = _get_manifest(case)
    packet = build_packet(case, manifest, result, matches)
    assert packet["statistics"]["events_extracted"] == result["metrics"]["events_total"]
    assert packet["statistics"]["events_without_confirmed_date"] == 0
    assert packet["statistics"]["incomplete_events"] == 0
    assert packet["statistics"]["job_run_counts"]["SEND_REAL_FILE_IMAGE"]["runs"] == 1
    assert packet["statistics"]["job_run_counts"]["HA_RECEIVE_RESULT"]["target_count_total"] == 1
    assert "Job HA_RECEIVE_RESULT 실행/완료/미완료/작업대상" in to_markdown(packet)
