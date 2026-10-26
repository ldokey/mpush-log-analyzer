"""Third-stage privacy-safe anomaly regression, all synthetic."""
from __future__ import annotations
from datetime import date
import json
from pathlib import Path

from mpush_analyzer.intake import Upload, inspect_uploads
from mpush_analyzer.storage import save_intake
from mpush_analyzer.stage3 import analyze_case_full

def make_stage3_case(tmp_path: Path, *, partial_debug=False, short_debug=False) -> Path:
    blocks = []
    for index in range(7):
        sec = index * 10
        t = f"10:00:{sec:02d}" if sec < 60 else "10:01:00"
        duration = "54.076" if index == 6 else "0.400"
        socket = "52.995" if index == 6 else "0.100"
        blocks.append(f"""{t}[500]
##  SEND_REAL_FILE_IMAGE 작업
{t}[500] ##  작업대상건수 : 1
{t}[500] ##  시작시간 : 10시 0분 0.0초
{t}[500] ##  종료시간 : 10시 0분 0.500초
{t}[500] ##  SOCKET 시간(초.0f) : {socket}초
{t}[500] ##  소요시간(초.0f) : {duration}초
{t}[500] ##  초당 작업 건수 : 2.50건
""")
    blocks.append("""10:02:00[477]
##  HA_RECEIVE_RESULT 작업
10:02:00[477] ##  작업대상건수 : 2
10:02:00[477] ##  종료시간 : 10시 2분 0.477초
10:02:00[477] ##  HTTP IN 시간(초.0f) : 23.939초
10:02:00[477] ##  HTTP OUT 시간(초.0f) : 55.721초
10:02:00[477] ##  소요시간(초.0f) : 85.477초
""")
    health_times = (
        ["10:00:00","10:00:10"] if short_debug else
        ["10:00:00","10:00:10","10:00:20","10:00:30","10:01:40","10:01:50"]
    )
    debug = "".join(f'{t}[001] 헬스 체크 결과 : {{"TARGET":"Nothing"}}\n' for t in health_times)
    debug += """10:02:10[200] -- Can't execute task in RUNNING state :: SEND_REAL_FILE_IMAGE --
10:02:20[200] -- Can't execute task in RUNNING state :: SEND_REAL_FILE_IMAGE --
10:02:30[200] -- Can't execute task in RUNNING state :: SEND_REAL_FILE_IMAGE --
10:02:40[200] ***************** 서버에서 받은 문자열 [{"RESPONSE_CODE":"S"}]
10:02:50[001] SECRET_CLIENT_KEY=NEVER_INCLUDE_IN_RESULTS
"""
    db = """10:00:00[003]
NO_ID_-7=PSTMT.EQ Laptime : 3
NO_ID_-7=SELECT SECRET_CREDENTIAL FROM SECRET_TABLE
NO_ID_-7=Result : select completed.
10:00:10[001]
NO_ID_-7=PSTMT.EQ Laptime : 5
NO_ID_-7=Result : select completed.
10:01:45[002]
NO_ID_-7=PSTMT.EQ Laptime : 7119
NO_ID_-7=Result : select completed.
10:01:50[002]
NO_ID_-7=PSTMT.EU Laptime : 50
NO_ID_-7=Result : 0 row(s) updated.
10:01:55[002]
NO_ID_-7=PSTMT.EU Laptime : 90
NO_ID_-7=Result : failed due to synthetic
"""
    err = """10:01:59[001] java.net.SocketTimeoutException: synthetic secret
  at synthetic.Test.run(Test.java:1)
10:02:01[002] java.sql.SQLException: secret
  at synthetic.Test.read(Test.java:2)
"""
    ini = """[AGENT]
id=A1
type=real
[DBMS]
type=mysql
password=TOP_SECRET_TEST_PASS
"""
    items = [
        Upload("20261015job.log", "\n".join(blocks).encode(), completeness="full"),
        Upload("20261015dbwrap.log", db.encode(), completeness="full"),
        Upload("20261015debug.log", debug.encode(), completeness="partial" if partial_debug else "full"),
        Upload("20261015err.log", err.encode(), completeness="full"),
        Upload("agent.ini", ini.encode(), completeness="full")
    ]
    case_dir, _ = save_intake(
        inspect_uploads(items),tmp_path/"workspace", agent_version="3.3",
        reference_date=date(2026,10,15), collected_at="2026-10-15T15:20:00+09:00"
    )
    return case_dir

def test_anomaly_signals_evidence_and_stats(tmp_path: Path):
    case_dir=make_stage3_case(tmp_path)
    result, matches=analyze_case_full(case_dir, knowledge_root=tmp_path/"knowledge")
    codes={f["signal_code"] for f in result["findings"]}
    assert {"SEND_JOB_DELAY","RESULT_JOB_DELAY","DB_SQL_DELAY","HEALTHCHECK_GAP",
            "PERIODIC_JOB_GAP","JOB_RUNNING_STATE","SQL_ERROR","TRANSPORT_ERROR"}.issubset(codes)
    metrics=result["metrics"]["stage3"]
    job=metrics["job_duration_statistics"]["SEND_REAL_FILE_IMAGE"]
    assert job["samples"]==7
    assert job["max_seconds"]==54.076
    assert job["p50"] == 0.4
    assert job["average"] > 0.4
    assert metrics["db_duration_statistics"]["EQ"]["max_ms"]==7119
    assert metrics["running_state_skips"]["SEND_REAL_FILE_IMAGE"]==3
    assert metrics["healthcheck_statistics"]["file_03"]["estimated_interval_seconds"]==10
    assert result["metrics"]["cns_request_responses"]["S"]==1
    assert result["findings"]
    assert all(f["statement_type"] in {"observed","indicator","hypothesis"} for f in result["findings"])
    assert all(f["evidence_file_ids"] and f["evidence_refs"] for f in result["findings"])
    assert all(f["evidence_refs"][0]["line_start"]>=1 for f in result["findings"])
    assert matches["matched_cases"]==[]
    merged=(case_dir/"analysis_result.json").read_text()+(case_dir/"case_matches.json").read_text()
    for secret in ["SECRET_CREDENTIAL", "SECRET_CLIENT_KEY", "TOP_SECRET_TEST_PASS",
                   "SECRET_TABLE","NO_ID_-7"]:
        assert secret not in merged
    assert (case_dir/"analysis_result.json").stat().st_mode & 0o077 == 0
    assert (case_dir/"case_matches.json").stat().st_mode & 0o077 == 0
    # Reproducible analysis with unchanged raw evidence and catalog.
    second, again=analyze_case_full(case_dir, knowledge_root=tmp_path/"knowledge")
    assert second==result and again==matches

def test_partial_debug_suppresses_tail_and_periodic(tmp_path: Path):
    case_dir=make_stage3_case(tmp_path,partial_debug=True)
    result,_=analyze_case_full(case_dir,knowledge_root=tmp_path/"knowledge")
    assert result["analysis_status"]=="partial"
    assert not any(f["rule_id"]=="HEALTHCHECK_TAIL" for f in result["findings"])
    assert not any(f["signal_code"]=="PERIODIC_JOB_GAP" for f in result["findings"])
    # An actual internal gap between known healthcheck events may still be reported.
    assert any(f["rule_id"]=="HEALTHCHECK_INTERVAL" for f in result["findings"])

def test_insufficient_heartbeat_samples_suppresses_gap(tmp_path: Path):
    case_dir=make_stage3_case(tmp_path,short_debug=True)
    result,_=analyze_case_full(case_dir,knowledge_root=tmp_path/"knowledge")
    assert not any(f["signal_code"] in {"HEALTHCHECK_GAP","PERIODIC_JOB_GAP"} for f in result["findings"])

def test_cns_success_is_acceptance_not_delivery(tmp_path:Path):
    case_dir=make_stage3_case(tmp_path)
    result,_=analyze_case_full(case_dir,knowledge_root=tmp_path/"knowledge")
    assert result["metrics"]["cns_request_responses"]=={"S":1}
    assert "최종 수신" in " ".join(result["limitations"])
    assert not any("최종 수신 성공" in f["description"] for f in result["findings"])


def test_full_pipeline_matches_reviewed_case_and_catalog_version(tmp_path: Path):
    from mpush_analyzer.case_library import import_case, approve_case
    root=tmp_path/"knowledge"
    fixture=Path(__file__).parent/"fixtures"/"case_draft.json"
    import_case(fixture.read_bytes(),root=root)
    approve_case("MPA-CASE-000001",1,confirm_reviewed=True,root=root)
    case_dir=make_stage3_case(tmp_path)
    result,matches=analyze_case_full(case_dir,knowledge_root=root)
    assert matches["catalog_version"]=="1.1"
    assert matches["analysis_id"]==case_dir.name
    assert matches["matched_cases"][0]["case_id"]=="MPA-CASE-000001"
    assert matches["matched_cases"][0]["result_type"]=="reference_only"
    assert "PERIODIC_JOB_GAP" in matches["matched_cases"][0]["matched_required_signals"]
    assert any(f["signal_code"]=="TRANSPORT_DELAY" for f in result["findings"])
    from jsonschema import Draft202012Validator
    from mpush_analyzer.case_contract import load_schema
    Draft202012Validator(load_schema("case_matches.schema.json")).validate(matches)


def test_runner_refuses_tampered_raw_before_case_matching(tmp_path: Path):
    import pytest
    case_dir=make_stage3_case(tmp_path)
    raw=case_dir/"raw"/"job_01.log"
    raw.write_bytes(raw.read_bytes()+b"synthetic added after upload")
    with pytest.raises(ValueError):
        analyze_case_full(case_dir,knowledge_root=tmp_path/"knowledge")
    assert not (case_dir/"case_matches.json").exists()


def test_runner_rejects_symlinked_result_target(tmp_path: Path):
    import pytest
    case_dir=make_stage3_case(tmp_path)
    external=tmp_path/"untouched.txt"
    external.write_text("unchanged",encoding="utf-8")
    (case_dir/"case_matches.json").symlink_to(external)
    with pytest.raises(ValueError):
        analyze_case_full(case_dir,knowledge_root=tmp_path/"knowledge")
    assert external.read_text(encoding="utf-8")=="unchanged"


def test_other_job_and_generic_exception_signals(tmp_path: Path):
    from mpush_analyzer.anomalies import detect_anomalies, load_rules
    from datetime import datetime
    import json
    events=[
        {
          "event_type":"job_run","file_id":"file_01","line_start":1,"line_end":9,
          "occurred_at":"2026-10-15T10:00:00.000+09:00","status":"complete",
          "details":{"job_name":"CUSTOM_JOB","target_count":1,"duration_seconds":50,
                     "completed":True,"steps_seconds":{}}
        },
        {
          "event_type":"log_error","file_id":"file_02","line_start":1,"line_end":3,
          "occurred_at":"2026-10-15T10:01:00.000+09:00","status":"observed",
          "details":{"exception_class":"IllegalStateException"}
        },
    ]
    events_file=tmp_path/"events.jsonl"
    events_file.write_text("".join(json.dumps(e)+"\n" for e in events))
    manifest={"files":[{"file_id":"file_01","kind":"job","completeness":"full"},
                       {"file_id":"file_02","kind":"err","completeness":"full"}],
              "collected_at":None}
    metrics,findings,limits=detect_anomalies(events_file,manifest)
    assert {"OTHER_JOB_DELAY","GENERAL_EXCEPTION"}.issubset({f["signal_code"] for f in findings})
    assert next(f for f in findings if f["signal_code"]=="GENERAL_EXCEPTION")["statement_type"]=="observed"
    assert next(f for f in findings if f["signal_code"]=="OTHER_JOB_DELAY")["statement_type"]=="indicator"
