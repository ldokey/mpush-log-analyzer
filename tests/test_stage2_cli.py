"""Stage-2 CLI, no-log handling and bounded chunk merge tests."""
from __future__ import annotations

from datetime import date, datetime, timedelta
from pathlib import Path
import json

from mpush_analyzer import cli
from mpush_analyzer.intake import Upload, inspect_uploads
from mpush_analyzer.pipeline import analyze_case
from mpush_analyzer.storage import save_intake


def test_cli_by_analysis_id_only(tmp_path: Path, capsys, monkeypatch):
    case_dir, _ = save_intake(
        inspect_uploads([Upload(
            "20261015debug.log",
            b'10:12:32[001] ***************** server text {"RESPONSE_CODE":"S"}\n',
            completeness="full",
        )]),
        tmp_path / "workspace",
        reference_date=date(2026, 10, 15),
    )
    monkeypatch.setattr(cli, "__file__", str(tmp_path / "mpush_analyzer" / "cli.py"))
    assert cli.main([case_dir.name]) == 0
    out = capsys.readouterr().out
    assert "EVENTS_EXTRACTED=0" in out  # not a known Korean debug response marker
    assert "OUTPUT=events.jsonl,analysis_result.json" in out


def test_case_with_only_ini_is_partial(tmp_path: Path):
    path, _ = save_intake(
        inspect_uploads([Upload(
            "agent.ini", b"[AGENT]\nid=A1\n[DBMS]\ntype=oracle\n", completeness="full"
        )]),
        tmp_path / "workspace",
    )
    result = analyze_case(path)
    assert result["analysis_status"] == "partial"
    assert result["metrics"]["events_total"] == 0
    assert any("분석 가능한 로그" in x for x in result["limitations"])


def test_large_synthetic_log_chunk_sorting(tmp_path: Path):
    origin = datetime(2026, 10, 15)
    count = 21005
    rows = []
    for index in range(count):
        t = (origin + timedelta(seconds=index)).strftime("%H:%M:%S")
        rows.append(f'{t}[001] 헬스 체크 결과 : {{"TARGET":"Nothing"}}\n')
    path, _ = save_intake(
        inspect_uploads([Upload("20261015debug.log", "".join(rows).encode(), completeness="full")]),
        tmp_path / "workspace",
    )
    result = analyze_case(path)
    assert result["metrics"]["event_counts"]["healthcheck_result"] == count
    events = [json.loads(line) for line in (path / "events.jsonl").read_text().splitlines()]
    assert len(events) == count
    assert [x["occurred_at"] for x in events] == sorted(x["occurred_at"] for x in events)
    assert result["metrics"]["source_summary"][0]["lines_read"] == count
