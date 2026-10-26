"""Stage-3 orchestration: verified-source parsing, anomaly rules, approved case matching."""
from __future__ import annotations

from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker

from .anomalies import detect_anomalies, load_rules
from .case_contract import load_schema
from .case_matcher import match_cases
from .pipeline import _atomic_json, _get_manifest, analyze_case


def analyze_case_full(case_dir: Path, *, knowledge_root: Path | None = None,
                      ) -> tuple[dict[str, Any], dict[str, Any]]:
    """Always rebuild from SHA-verified originals. Never trust a stale event artifact."""
    parsed = analyze_case(case_dir)
    manifest = _get_manifest(case_dir)
    rules = load_rules()
    supplemental, findings, limitations = detect_anomalies(
        case_dir / "events.jsonl", manifest, rules=rules
    )
    result = dict(parsed)
    result["metrics"] = dict(parsed["metrics"])
    result["metrics"]["stage3"] = supplemental
    result["findings"] = findings
    result["limitations"] = list(dict.fromkeys(parsed["limitations"] + limitations + [
        "이상 신호는 지연·오류·기록 공백을 식별하며 Agent 결함 또는 외부 환경 문제를 확정하지 않습니다."
    ]))
    matches = match_cases(
        findings, manifest, supplemental["job_duration_statistics"],
        **({"root": knowledge_root} if knowledge_root is not None else {}),
        limit=rules["matches"]["limit"]
    )
    matches["analysis_id"] = manifest["analysis_id"]

    Draft202012Validator(
        load_schema("analysis_result.schema.json"), format_checker=FormatChecker()
    ).validate(result)
    Draft202012Validator(
        load_schema("case_matches.schema.json"), format_checker=FormatChecker()
    ).validate(matches)
    _atomic_json(case_dir / "case_matches.json", matches)
    _atomic_json(case_dir / "analysis_result.json", result)
    return result, matches
