"""Stage-4 end-to-end local workflow: Stage 3 analysis plus safe static exports."""
from __future__ import annotations
from pathlib import Path
from typing import Any
from .stage3 import analyze_case_full
from .report import generate_case_exports

def run_complete_analysis(
    case_dir: Path, *, knowledge_root: Path | None = None
) -> tuple[dict[str, Any], dict[str, Any], dict[str, bytes]]:
    result, matches = analyze_case_full(case_dir, knowledge_root=knowledge_root)
    reports = generate_case_exports(case_dir, result, matches)
    return result, matches, reports
