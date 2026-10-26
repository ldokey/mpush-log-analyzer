"""Local CLI for Stage-2 parsing and Stage-3 rule/case analysis."""
from __future__ import annotations

import argparse
import re
from pathlib import Path

from .pipeline import analyze_case
from .runner import run_complete_analysis


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="MPushAgent local log analysis (Stage 2/3)")
    parser.add_argument("analysis_id", help="analysis_<32 lowercase hex> from Stage-1 manifest")
    parser.add_argument("--stage2-only", action="store_true", help="이상 탐지 및 사례 매칭 없이 로그 파싱만 수행")
    args = parser.parse_args(argv)
    if not re.fullmatch(r"analysis_[0-9a-f]{32}", args.analysis_id):
        parser.error("유효한 분석 작업 ID가 아닙니다.")
    root = Path(__file__).resolve().parents[1] / "workspace"
    case_dir = root / args.analysis_id
    try:
        if args.stage2_only:
            result = analyze_case(case_dir)
            matches = None
        else:
            result, matches, _ = run_complete_analysis(case_dir)
    except (ValueError, OSError) as exc:
        # Never output exception values: they might carry customer raw input.
        print(f"FAILED: {type(exc).__name__}; original inputs were not modified.")
        return 1
    except Exception as exc:
        print(f"FAILED: {type(exc).__name__}; original inputs were not modified.")
        return 1
    metrics = result["metrics"]
    print(f"ANALYSIS_ID={result['analysis_id']}")
    print(f"ANALYSIS_STATUS={result['analysis_status']}")
    print(f"EVENTS_EXTRACTED={metrics['events_total']}")
    print(f"JOB_TYPES={len(metrics['job_runs'])}")
    print(f"DB_EXECUTIONS={metrics['db_executions']['runs']}")
    if matches is not None:
        print(f"FINDINGS={len(result['findings'])}")
        print(f"MATCHED_CASES={matches['displayed_count']}")
        print("OUTPUT=events.jsonl,analysis_result.json,case_matches.json")
        print("REPORTS=report.md,report.html,report.json")
    else:
        print("OUTPUT=events.jsonl,analysis_result.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
