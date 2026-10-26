"""Stage-3 false-positive guards and bounded large-sample regression."""
from __future__ import annotations

from datetime import date, datetime, timedelta
import json
from pathlib import Path

from mpush_analyzer.intake import Upload, inspect_uploads
from mpush_analyzer.storage import save_intake
from mpush_analyzer.stage3 import analyze_case_full


def _case(tmp_path: Path, uploads, *, collected=None, reference=date(2026,10,15)):
    p,_=save_intake(
        inspect_uploads(uploads), tmp_path/"workspace",
        reference_date=reference, collected_at=collected
    )
    return p


def test_zero_updated_rows_are_not_sql_failure(tmp_path: Path):
    source="""10:00:00[003]
NO_ID_-8=PSTMT.EU Laptime : 2
NO_ID_-8=UPDATE SYNTHETIC SET SOME_FIELD=1
NO_ID_-8=Result : 0 row(s) updated.
"""
    p=_case(tmp_path,[Upload("20261015dbwrap.log",source.encode(),completeness="full")])
    result,_=analyze_case_full(p,knowledge_root=tmp_path/"knowledge")
    assert result["metrics"]["db_executions"]["by_outcome"]=={"rows_affected":1}
    assert not any(f["signal_code"]=="SQL_ERROR" for f in result["findings"])


def test_job_alone_cannot_establish_scheduler_hang(tmp_path: Path):
    source="""10:00:00[001]
##  SEND_REAL_FILE_IMAGE 작업
10:00:00[001] ##  작업대상건수 : 1
10:00:00[001] ##  종료시간 : 10시 0분 0.001초
10:00:00[001] ##  소요시간(초.0f) : 0.1초
"""
    p=_case(tmp_path,[Upload("20261015job.log",source.encode(),completeness="full")],
            collected="2026-10-15T15:20:00+09:00")
    result,_=analyze_case_full(p,knowledge_root=tmp_path/"knowledge")
    assert not any(f["signal_code"] in {"PERIODIC_JOB_GAP","HEALTHCHECK_GAP"} for f in result["findings"])


def test_35k_regular_heartbeat_stream_no_false_gap(tmp_path: Path):
    origin=datetime(2026,10,15,6,0,0)
    logs=[]
    for n in range(35000):
        t=(origin+timedelta(seconds=n)).strftime("%H:%M:%S")
        logs.append(f'{t}[001] 헬스 체크 결과 : {{"TARGET":"Nothing"}}\n')
    p=_case(tmp_path,[Upload("20261015debug.log","".join(logs).encode(),completeness="full")])
    result,_=analyze_case_full(p,knowledge_root=tmp_path/"knowledge")
    assert result["metrics"]["events_total"]==35000
    assert not any(f["signal_code"] in {"PERIODIC_JOB_GAP","HEALTHCHECK_GAP"} for f in result["findings"])
    assert result["metrics"]["stage3"]["healthcheck_statistics"]["file_01"]["estimated_interval_seconds"]==1
    assert len((p/"events.jsonl").read_text().splitlines())==35000



def test_cli_stage3_default_and_stage2_option(tmp_path: Path, monkeypatch, capsys):
    from mpush_analyzer import cli
    source="""10:00:00[001]
##  SEND_REAL_FILE_IMAGE 작업
10:00:00[001] ##  작업대상건수 : 1
10:00:00[001] ##  종료시간 : 10시 0분 0.001초
10:00:00[001] ##  소요시간(초.0f) : 11.0초
"""
    path=_case(tmp_path,[Upload("20261015job.log",source.encode(),completeness="full")])
    monkeypatch.setattr(cli,"__file__",str(tmp_path/"mpush_analyzer"/"cli.py"))
    assert cli.main([path.name]) == 0
    output=capsys.readouterr().out
    assert "FINDINGS=" in output and "MATCHED_CASES=" in output
    assert (path/"case_matches.json").is_file()
    assert cli.main([path.name,"--stage2-only"]) == 0
    output=capsys.readouterr().out
    assert "FINDINGS=" not in output
