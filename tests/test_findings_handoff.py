"""Synthetic regression for readable evidence, time provenance, and safe AI handoff."""
from __future__ import annotations

from datetime import date
from pathlib import Path
import json

import pytest
from streamlit.testing.v1 import AppTest

from mpush_analyzer.ai_brief import build_brief, brief_json, brief_markdown
from mpush_analyzer.finding_view import finding_detail, finding_row
from mpush_analyzer.intake import Upload, inspect_uploads
from mpush_analyzer.runner import run_complete_analysis
from mpush_analyzer.storage import save_intake


JOB = """10:12:17[106]
##  SEND_REAL_FILE_IMAGE 작업
10:12:17[106] ##  작업대상건수 : 2
10:12:17[106] ##  시작시간 : 10시 11분 23.30초
10:12:17[106] ##  종료시간 : 10시 12분 17.106초
10:12:17[106] ##  SOCKET 시간(초.0f) : 52.995초
10:12:17[106] ##  소요시간(초.0f) : 54.076초
"""
DB = """10:13:10[001]
NO_ID_-456=PSTMT.EQ Laptime : 7119
NO_ID_-456=SELECT secret_customer_token FROM customers WHERE phone='010-9999-8888'
NO_ID_-456=Result : select completed.
"""
DEBUG = """10:00:00[001] 헬스 체크 결과 : {"TARGET":"Nothing"}
10:00:10[001] 헬스 체크 결과 : {"TARGET":"Nothing"}
10:00:20[001] 헬스 체크 결과 : {"TARGET":"Nothing"}
10:00:30[001] 헬스 체크 결과 : {"TARGET":"Nothing"}
10:12:10[001] 헬스 체크 결과 : {"TARGET":"Nothing"}
10:12:20[001] 헬스 체크 결과 : {"TARGET":"Nothing"}
10:12:21[001] token=PRIVATE_PLAINTEXT_DO_NOT_SHOW
"""


def fixture(tmp_path: Path, date_known=True):
    files = [
        Upload("sample-job.log",JOB.encode(),completeness="full",override_kind="job"),
        Upload("sample-dbwrap.log",DB.encode(),completeness="full",override_kind="dbwrap"),
        Upload("sample-debug.log",DEBUG.encode(),completeness="full",override_kind="debug"),
    ]
    case,_=save_intake(
        inspect_uploads(files),tmp_path/"workspace",
        agent_version="3.3",
        reference_date=date(2026,10,15) if date_known else None
    )
    result,matches,exports=run_complete_analysis(case,knowledge_root=tmp_path/"knowledge")
    manifest=json.loads((case/"manifest.json").read_text())
    return case,manifest,result,matches,exports


def test_job_start_end_and_evidence_time_preserved(tmp_path):
    case,manifest,result,matches,exports=fixture(tmp_path)
    from mpush_analyzer.dashboard_data import events_iter
    job=next(e for e in events_iter(case,manifest) if e["event_type"]=="job_run")
    assert job["details"]["start_clock"]=="10:11:23.300"
    assert job["details"]["end_clock"]=="10:12:17.106"
    assert job["details"]["start_at"]=="2026-10-15T10:11:23.300+09:00"
    assert job["occurred_at"]=="2026-10-15T10:12:17.106+09:00"
    f=next(f for f in result["findings"] if f["signal_code"]=="SEND_JOB_DELAY")
    assert f["representative_at"].startswith("2026-10-15T10:12:17")
    assert f["evidence_refs"][0]["clock"]=="10:12:17.106"
    assert f["evidence_refs"][0]["start_at"]==job["details"]["start_at"]


def test_readable_display_and_ai_bundle_remain_non_sensitive(tmp_path):
    case,manifest,result,matches,exports=fixture(tmp_path)
    findings=result["findings"]
    sql=next(f for f in findings if f["signal_code"]=="DB_SQL_DELAY")
    row=finding_row(sql,manifest)
    assert "2026-10-15 10:13:10.001" in row["발생시각"]
    assert row["근거 파일"]=="dbwrap_01.log"
    assert "7,119" in row["주요 수치"]
    detail=finding_detail(sql,manifest)
    assert detail["evidence"][0]["로그 파일"]=="dbwrap_01.log"
    assert detail["limitation"]
    assert detail["next_check"]
    whole=build_brief(result,matches,manifest)
    only=build_brief(result,matches,manifest,finding_id=sql["finding_id"])
    assert len(whole["findings"])>len(only["findings"])==1
    md=brief_markdown(whole)
    js=brief_json(whole)
    report=exports["report.md"].decode("utf-8")
    for content in (md,js,report):
        assert "PRIVATE_PLAINTEXT_DO_NOT_SHOW" not in content
        assert "secret_customer_token" not in content
        assert "010-9999-8888" not in content
        assert "2026-10-15" in content
        assert "dbwrap_01.log" in content
        assert "7,119" in content
    assert "근본 원인은 동일하지 않습니다" in md
    assert "원인 확정" not in detail["observed"]
    assert "file_02" in md
    with pytest.raises(ValueError):
        build_brief(result,matches,manifest,finding_id="F-9999")


def test_date_unknown_remains_unknown(tmp_path):
    case,manifest,result,matches,exports=fixture(tmp_path,date_known=False)
    sql=next(f for f in result["findings"] if f["signal_code"]=="DB_SQL_DELAY")
    row=finding_row(sql,manifest)
    assert "날짜 미확인" in row["발생시각"]
    assert not sql["evidence_refs"][0]["occurred_at"]
    md=brief_markdown(build_brief(result,matches,manifest))
    assert "날짜 미확인" in md


def test_ui_loads_readable_panel_with_local_synthetic_case(tmp_path):
    # Test the human-readable panel against a synthetic saved analysis.
    import os
    import shutil
    import streamlit as st
    from mpush_analyzer.finding_ui import render_finding_review
    case,manifest,result,matches,exports=fixture(tmp_path)
    script=tmp_path/"synthetic_ui.py"
    script.write_text("""import json
from pathlib import Path
from mpush_analyzer.finding_ui import render_finding_review
case=Path(__file__).parent/'workspace'/'"""+case.name+"""'
manifest=json.loads((case/'manifest.json').read_text())
result=json.loads((case/'analysis_result.json').read_text())
matches=json.loads((case/'case_matches.json').read_text())
render_finding_review(case,manifest,result,matches,namespace='synthetic')
""")
    app=AppTest.from_file(str(script),default_timeout=20).run()
    assert not app.exception, [str(e) for e in app.exception]
    # Core blocks must render without raw JSON expanders.
    assert len(app.get("dataframe"))>=2
    assert any("탐지된 로그 이상 징후" in x.value for x in app.get("subheader"))
