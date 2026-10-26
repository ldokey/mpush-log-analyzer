"""Stage-4 end-to-end dashboard, evidence, export and deletion tests.

All fixtures are generated with synthetic values. No customer data is accessed.
"""
from __future__ import annotations
from datetime import date
from copy import deepcopy
import json
from pathlib import Path

import pytest

from mpush_analyzer.dashboard_data import (
    EventFilters, find_correlated_events, read_result_bundle,
    summarize_events, events_iter
)
from mpush_analyzer.intake import Upload, inspect_uploads
from mpush_analyzer.lifecycle import delete_case, list_cases
from mpush_analyzer.report import build_exports, to_html, report_data
from mpush_analyzer.runner import run_complete_analysis
from mpush_analyzer.source_view import masked_line, excerpt
from mpush_analyzer.storage import save_intake

JOB = """10:00:00[000]
##  SEND_REAL_FILE_IMAGE 작업
10:00:00[002] ##  작업대상건수  : 2
10:00:00[003] ##  종료시간 : 10시 0분 0.003초
10:00:00[004] ##  SOCKET 시간(초.0f) : 7.003초
10:00:00[005] ##  소요시간(초.0f) : 8.001초
10:00:25[000]
##  HA_RECEIVE_RESULT 작업
10:00:25[002] ##  작업대상건수  : 1
10:00:25[003] ##  종료시간 : 10시 0분 25.003초
10:00:25[004] ##  HTTP OUT 시간(초.0f) : 11.001초
10:00:25[005] ##  소요시간(초.0f) : 12.001초
"""
DEBUG = """10:00:00[100] 헬스 체크 서비스 번호 : 9876543210
10:00:00[200] 헬스 체크 결과 : {"TARGET":"Nothing"}
10:00:10[000] 헬스 체크 결과 : {"TARGET":"Nothing"}
10:00:20[000] 헬스 체크 결과 : {"TARGET":"Nothing"}
10:00:30[000] 헬스 체크 결과 : {"TARGET":"Nothing"}
10:00:40[000] 헬스 체크 결과 : {"TARGET":"Nothing"}
10:00:41[012] 서버에서 받은 문자열 [{"RESPONSE_CODE":"S"}]
10:00:42[099] clientPlainKey=PRIVATE_SECRET_123
10:00:42[100] Mobile number=010-1234-5678
"""
DB = """10:00:03[001]
NO_ID_-42=PSTMT.EQ Laptime : 7119
NO_ID_-42=SELECT CLIENT_PLAIN_KEY, PHONE FROM PRIVATE_SCHEMA
NO_ID_-42=WHERE PHONE='010-2222-3333'
NO_ID_-42=Result : select completed.
"""
INFO = """04:30:01[001] Agent Exited................
04:30:02[001] Starting....
04:30:02[728] Started
"""
ERROR = """10:00:35[101] java.net.SocketTimeoutException: PRIVATE_TOKEN
  at demo.server.send(Demo.java:7)
Caused by: java.io.IOException: 192.0.2.99
"""


def make_case(tmp_path: Path, *, debug_complete: str = "full") -> tuple[Path, Path]:
    samples = [
        Upload("20261015job.log", JOB.encode(), completeness="full"),
        Upload("20261015debug.log", DEBUG.encode(), completeness=debug_complete),
        Upload("20261015dbwrap.log", DB.encode(), completeness="full"),
        Upload("20261015info.log", INFO.encode(), completeness="full"),
        Upload("20261015err.log", ERROR.encode(), completeness="full"),
        Upload("agent.ini", b"[AGENT]\nid=A1\ntype=real\n[DBMS]\ntype=mysql\npassword=SECRET_PASS_DO_NOT_SHOW\n",
               completeness="full"),
    ]
    workspace = tmp_path / "workspace"
    case_dir, _ = save_intake(
        inspect_uploads(samples), workspace,
        agent_version="3.3", reference_date=date(2026,10,15),
        collected_at="2026-10-15T15:20:00+09:00",
    )
    return case_dir, workspace


def test_complete_runner_produces_schema_and_reports(tmp_path: Path):
    case_dir,_=make_case(tmp_path)
    result, matches, exports = run_complete_analysis(case_dir, knowledge_root=tmp_path/"knowledge")
    assert result["metrics"]["job_runs"]["SEND_REAL_FILE_IMAGE"]["target_count_total"] == 2
    assert result["metrics"]["cns_request_responses"]["S"] == 1
    assert len(result["findings"]) > 0
    assert set(exports)=={"report.md", "report.html", "report.json"}
    for name, content in exports.items():
        assert (case_dir / name).read_bytes()==content
        assert (case_dir / name).stat().st_mode & 0o077 == 0
        assert b"PRIVATE" not in content
        assert b"SECRET" not in content
        assert b"010-" not in content
        assert b"NO_ID" not in content
        assert b"192.0.2.99" not in content
    md=exports["report.md"].decode()
    assert "분석 자료" in md and "확인된 이상 징후" in md
    assert "CNS 발송 요청 수락" in md
    assert "최종 수신 성공이 아닙니다." in md
    html=exports["report.html"].decode()
    assert "Content-Security-Policy" in html and "<script" not in html.lower()
    report=json.loads(exports["report.json"])
    assert report["analysis_id"]==case_dir.name
    assert report["related_cases"]==[]
    assert not (case_dir/"events.jsonl").stat().st_mode & 0o077
    again,again_matches,again_exports=run_complete_analysis(case_dir,knowledge_root=tmp_path/"knowledge")
    assert again==result and again_matches==matches and again_exports==exports


def test_dashboard_filters_minute_and_evidence(tmp_path: Path):
    case_dir,_=make_case(tmp_path)
    run_complete_analysis(case_dir,knowledge_root=tmp_path/"knowledge")
    manifest,result,matches=read_result_bundle(case_dir)
    summary=summarize_events(case_dir,manifest,page=1,page_size=5)
    assert summary["total"]==result["metrics"]["events_total"]
    assert len(summary["rows"]) == 5
    assert summary["pages"] >= 2
    assert summary["first_minute"] <= summary["last_minute"]
    assert all("근거 위치" in row for row in summary["rows"])
    assert any(row["job_runs"] > 0 for row in summary["timeline"])
    filtered=summarize_events(case_dir,manifest,EventFilters(log_kind="dbwrap"))
    assert filtered["total"]==1
    assert filtered["rows"][0]["유형"]=="sql_execution"
    job_filter=summarize_events(case_dir,manifest,EventFilters(job_name="SEND_REAL_FILE_IMAGE"))
    assert job_filter["total"]==1
    result_window=summarize_events(case_dir,manifest,
        EventFilters(start_minute="2026-10-15T10:00",end_minute="2026-10-15T10:00"))
    assert result_window["total"] > 0
    missing=summarize_events(case_dir,manifest,
        EventFilters(start_minute="2026-10-15T12:00",end_minute="2026-10-15T13:00"))
    assert missing["total"] == 0
    first_finding=next(f for f in result["findings"] if f["evidence_refs"])
    refs=first_finding["evidence_refs"][0]
    nearby=find_correlated_events(case_dir,manifest,refs,window_seconds=120)
    assert nearby and all("근거 위치" in row for row in nearby)
    raw=excerpt(case_dir,refs["file_id"],refs["line_start"],refs["line_end"],context=2)
    assert raw["shown_lines"] > 0
    assert all("010-" not in row["text"] for row in raw["lines"])


def test_safe_evidence_redaction_covers_unknown_sql_message_and_ini(tmp_path: Path):
    samples=[
        "10:00:00[000] clientPlainKey=SECRET_KEY_123",
        "10:00:00[000] SELECT recipient_phone FROM secret_table WHERE num='010-1234-5678'",
        "10:00:00[000] mobile data=010-1234-5678",
        "10:00:00[000] ##  작업대상건수 : 010-1234-5678",
        "10:00:00[000] ##  SOCKET 시간(초.0f) : 01012345678초",
        "10:00:00[000] RESPONSE_CODE=\"S\" secret=1234",
        "10:00:00[000] java.net.SocketTimeoutException: SECRET_CLIENT_KEY",
        "10:00:00[000] NO_ID_89=PSTMT.EQ Laptime : 123",
    ]
    for line in samples:
        clean,masked=masked_line(line)
        for leak in ("SECRET_KEY_123","SECRET_CLIENT_KEY","01012345678","010-1234-5678","recipient_phone"):
            assert leak not in clean
    case_dir,_=make_case(tmp_path)
    result,_matches,_reports=run_complete_analysis(case_dir,knowledge_root=tmp_path/"knowledge")
    manifest,_,_=read_result_bundle(case_dir)
    db_entry=next(x for x in manifest["files"] if x["kind"]=="dbwrap")
    raw=excerpt(case_dir,db_entry["file_id"],2,5,context=1)
    output=json.dumps(raw)
    assert "PRIVATE_SCHEMA" not in output
    assert "PHONE" not in output
    assert "NO_ID_-42" not in output
    assert "010-2222" not in output
    with pytest.raises(ValueError):
        excerpt(case_dir, next(x["file_id"] for x in manifest["files"] if x["kind"]=="agent_ini"),1,2)
    with pytest.raises(ValueError):
        excerpt(case_dir,db_entry["file_id"],0,1)
    with pytest.raises(ValueError):
        excerpt(case_dir,db_entry["file_id"],1,10_000)


def test_report_omits_untrusted_titles_and_html_escapes(tmp_path: Path):
    case_dir,_=make_case(tmp_path)
    result,matches,exports=run_complete_analysis(case_dir,knowledge_root=tmp_path/"knowledge")
    polluted=deepcopy(matches)
    polluted["matched_cases"]=[{
      "case_id":"MPA-CASE-000012","revision":1,"title":"PRIVATE_SECRET<script>alert(1)</script>",
      "result_type":"reference_only","matched_required_signals":["SEND_JOB_DELAY"],
      "matched_supporting_signals":[]}]
    altered=deepcopy(result)
    altered["findings"][0]["description"]="PRIVATE_SECRET<script>alert(1)</script>"
    manifest,_,_=read_result_bundle(case_dir)
    view=build_exports(altered,polluted,manifest)
    assert "PRIVATE_SECRET" not in view["report.md"].decode()
    assert "<script" not in view["report.html"].decode().lower()
    assert "MPA-CASE-000012" in view["report.md"].decode()


def test_delete_only_selected_case_and_rejects_unexpected_files(tmp_path: Path):
    case_dir,workspace=make_case(tmp_path)
    sibling,_=make_case(tmp_path)
    run_complete_analysis(case_dir,knowledge_root=tmp_path/"knowledge")
    assert len(list_cases(workspace))==2
    with pytest.raises(ValueError):
        delete_case(case_dir,confirmation="no",workspace=workspace)
    (case_dir/"unknown_customer_note.txt").write_text("keep",encoding="utf-8")
    with pytest.raises(ValueError):
        delete_case(case_dir,confirmation=case_dir.name,workspace=workspace)
    (case_dir/"unknown_customer_note.txt").unlink()
    delete_case(case_dir,confirmation=case_dir.name,workspace=workspace)
    assert not case_dir.exists()
    assert sibling.is_dir() and (sibling/"manifest.json").exists()
    assert len(list_cases(workspace))==1


def test_symlinked_report_is_never_overwritten(tmp_path: Path):
    case_dir,_=make_case(tmp_path)
    external=tmp_path/"outside_secret.txt"
    external.write_text("external safety invariant",encoding="utf-8")
    (case_dir/"report.md").symlink_to(external)
    with pytest.raises(ValueError):
        run_complete_analysis(case_dir,knowledge_root=tmp_path/"knowledge")
    assert external.read_text(encoding="utf-8")=="external safety invariant"



def test_dashboard_adaptive_time_buckets_and_pagination(tmp_path: Path):
    """Long-running logs should not create an unbounded chart point per minute."""
    from datetime import datetime, timedelta
    fake_case = tmp_path / "events_only"
    fake_case.mkdir()
    origin = datetime(2026, 10, 15)
    manifest = {"files": [{"file_id": "file_01", "kind": "debug"}]}
    with (fake_case / "events.jsonl").open("w", encoding="utf-8") as handle:
        for i in range(3000):
            stamp = (origin + timedelta(minutes=i)).isoformat(timespec="milliseconds") + "+09:00"
            entry = {
                "file_id": "file_01", "line_start": i+1, "line_end": i+1,
                "event_id": f"file_01_{i+1:09d}", "log_kind": "debug",
                "event_type": "healthcheck_result", "clock": "10:00:00.001",
                "occurred_at": stamp, "time_quality": "anchored", "status": "observed",
                "details": {"target_action": "no_action"}
            }
            handle.write(json.dumps(entry, ensure_ascii=False)+"\n")
    result = summarize_events(fake_case, manifest, page=3, page_size=100)
    assert result["total"] == 3000
    assert result["pages"] == 30
    assert result["rows"][0]["근거 위치"] == "file_01:201-201"
    assert result["time_bucket"] == "hour"
    assert len(result["timeline"]) < 1800
    assert sum(x["events"] for x in result["timeline"]) == 3000


def test_source_excerpt_does_not_display_numeric_pii_in_metrics():
    from mpush_analyzer.source_view import masked_line
    for sensitive in ("01012345678", "010-1234-5678", "987654321012"):
        for metric in ("작업대상건수", "SELECT 시간(초.0f)", "소요시간(초.0f)"):
            log = f"10:12:17[100] ##  {metric} : {sensitive}초"
            display, _ = masked_line(log)
            assert sensitive not in display
