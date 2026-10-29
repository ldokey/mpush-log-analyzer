#!/usr/bin/env python3
"""Offline synthetic-only performance check. No customer files and no production effects."""
from __future__ import annotations

import argparse
from datetime import date
import json
from pathlib import Path
import resource
import tempfile
from time import perf_counter

from mpush_analyzer.dashboard_data import read_result_bundle, summarize_events
from mpush_analyzer.workbench_data import EventQuery, query_events
from mpush_analyzer.intake import Upload, inspect_uploads
from mpush_analyzer.runner import run_complete_analysis
from mpush_analyzer.storage import save_intake


def synthetic_bytes(target_bytes: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < target_bytes:
        n = len(chunks) // 64
        t = n % 86400
        h, rest = divmod(t, 3600)
        m, s = divmod(rest, 60)
        row = f'{h:02}:{m:02}:{s:02}[001] 헬스 체크 결과 : {{"TARGET":"Nothing"}}\n'.encode()
        if len(chunks) + len(row) > target_bytes:
            break
        chunks.extend(row)
    return bytes(chunks)


def main() -> int:
    parser = argparse.ArgumentParser(description="Synthetic-only MPushAgent analysis benchmark")
    parser.add_argument("--megabytes", type=int, choices=[5, 10, 25, 50], default=10)
    args = parser.parse_args()
    source = synthetic_bytes(args.megabytes * 1024 * 1024)

    with tempfile.TemporaryDirectory(prefix="mpush-synthetic-benchmark-") as temp:
        start = perf_counter()
        inspected = inspect_uploads([
            Upload("20261015debug.log", source, completeness="full")
        ])
        case_dir, _ = save_intake(
            inspected, Path(temp) / "workspace", reference_date=date(2026, 10, 15)
        )
        intake_time = perf_counter() - start
        parse_start = perf_counter()
        result, matches, exports = run_complete_analysis(
            case_dir, knowledge_root=Path(temp) / "knowledge"
        )
        parse_time = perf_counter() - parse_start
        query_start = perf_counter()
        manifest, _, _ = read_result_bundle(case_dir)
        overview = summarize_events(case_dir, manifest, page=1, page_size=100)
        query_time = perf_counter() - query_start
        workbench_start = perf_counter()
        oldest = query_events(case_dir, manifest, EventQuery(), page=3, page_size=50)
        oldest_query_time = perf_counter() - workbench_start
        latest_start = perf_counter()
        latest = query_events(case_dir, manifest,
                              EventQuery(sort="time_desc"), page=1, page_size=50)
        latest_query_time = perf_counter() - latest_start
        count = result["metrics"]["events_total"]
        assert count == overview["total"] and count >= 10000
        assert oldest["total"] == latest["total"] == count
        assert len(oldest["rows"]) == len(latest["rows"]) == 50
        assert not matches["matched_cases"]
        assert len(overview["timeline"]) <= 1800
        assert all(exports[k] for k in ("report.json", "report.html", "report.md"))
        import platform
        usage = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        peak_mb = usage / (1024 * 1024) if platform.system() == "Darwin" else usage / 1024
        print(json.dumps({
            "source_kind": "synthetic_only",
            "source_megabytes": round(len(source) / 1024**2, 2),
            "events": count,
            "intake_seconds": round(intake_time, 3),
            "full_analysis_seconds": round(parse_time, 3),
            "dashboard_query_seconds": round(query_time, 3),
            "workbench_ascending_page_seconds": round(oldest_query_time, 3),
            "workbench_latest_page_seconds": round(latest_query_time, 3),
            "total_seconds": round(intake_time+parse_time+query_time+oldest_query_time+latest_query_time, 3),
            "timeline_buckets": len(overview["timeline"]),
            "peak_process_memory_mb": round(peak_mb, 1),
            "privacy": "no customer files used, temporary directory removed",
        }, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
