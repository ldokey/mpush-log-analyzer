"""Synthetic bulk regression resembling a day of Agent logs, never customer data."""
from __future__ import annotations

from datetime import date, datetime, timedelta
from pathlib import Path

from mpush_analyzer.intake import Upload, inspect_uploads
from mpush_analyzer.pipeline import analyze_case
from mpush_analyzer.storage import save_intake


def stamp(i: int, *, start: int = 8 * 3600) -> str:
    dt = datetime(2026, 10, 15) + timedelta(seconds=start + i)
    return dt.strftime("%H:%M:%S")


def test_bulk_967_job_396_db_patterns(tmp_path: Path):
    job_blocks: list[str] = []
    # 967 distinct jobs, 654 send + 313 result; no true client data.
    for i in range(967):
        kind = "SEND_REAL_FILE_IMAGE" if i < 654 else "HA_RECEIVE_RESULT"
        total = "54.076" if i == 653 else "85.477" if i == 966 else "0.312"
        t = stamp(i)
        h, m, s = t.split(":")
        metrics = [
            f"{t}[312]",
            f"##  {kind} 작업",
            f"{t}[312] ##  작업대상건수 : 1",
            f"{t}[312] ##  시작시간 : {int(h)}시 {int(m)}분 {int(s)}.0초",
            f"{t}[312] ##  종료시간 : {int(h)}시 {int(m)}분 {int(s)}.312초",
            f"{t}[312] ##  소요시간(초.0f) : {total}초",
        ]
        if kind == "SEND_REAL_FILE_IMAGE":
            metrics.append(f"{t}[312] ##  SOCKET 시간(초.0f) : 0.176초")
        else:
            metrics.append(f"{t}[312] ##  HTTP OUT 시간(초.0f) : 0.076초")
        job_blocks.append("\n".join(metrics) + "\n")
    sql_blocks: list[str] = []
    for i in range(396):
        t = stamp(i, start=10 * 3600)
        if i < 316:
            sql_blocks.append(f"{t}[003]\nNO_ID_-42=PSTMT.EQ Laptime : 1\nNO_ID_-42=SELECT 1\nNO_ID_-42=Result : select completed.\n")
        else:
            sql_blocks.append(f"{t}[003]\nNO_ID_-42=PSTMT.EB Laptime : 2 Result : batch job success.\n")
    path, _ = save_intake(
        inspect_uploads([
            Upload("20261015job.log", "\n".join(job_blocks).encode(), completeness="full"),
            Upload("20261015dbwrap.log", "\n".join(sql_blocks).encode(), completeness="full")
        ]), tmp_path / "workspace", reference_date=date(2026, 10, 15)
    )
    result = analyze_case(path)
    m = result["metrics"]
    assert m["job_runs"]["SEND_REAL_FILE_IMAGE"]["runs"] == 654
    assert m["job_runs"]["HA_RECEIVE_RESULT"]["runs"] == 313
    assert m["job_runs"]["SEND_REAL_FILE_IMAGE"]["max_duration_seconds"] == 54.076
    assert m["job_runs"]["HA_RECEIVE_RESULT"]["max_duration_seconds"] == 85.477
    assert m["db_executions"]["runs"] == 396
    assert m["db_executions"]["by_statement"] == {"EQ": 316, "EB": 80}
    assert m["job_runs"]["SEND_REAL_FILE_IMAGE"]["target_count_total"] == 654
    assert m["incomplete_events"] == 0
    assert m["events_total"] == 967 + 396
