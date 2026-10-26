"""Validate AI-authored troubleshooting cases without trusting or exposing content."""
from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker
from .security import detect_sensitive_patterns

SCHEMAS = Path(__file__).resolve().parents[1] / "knowledge" / "schema"
MAX_CASE_JSON_BYTES = 512 * 1024


@dataclass(frozen=True)
class CaseValidation:
    valid: bool
    errors: tuple[str, ...]
    summary: dict[str, Any] | None


def _no_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    d: dict[str, Any] = {}
    for key, value in pairs:
        if key in d:
            raise ValueError("JSON에 중복된 키가 있습니다.")
        d[key] = value
    return d


def load_schema(filename: str) -> dict[str, Any]:
    if filename not in {
        "case.schema.json", "manifest.schema.json",
        "analysis_result.schema.json", "case_matches.schema.json", "signal_catalog.json"
    }:
        raise ValueError("허용되지 않은 스키마 이름입니다.")
    return json.loads((SCHEMAS / filename).read_text(encoding="utf-8"))


def _format_errors(doc: dict[str, Any]) -> list[str]:
    schema = load_schema("case.schema.json")
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    # Do not use error.message: it may repeat secret values from invalid input.
    failures = sorted(validator.iter_errors(doc), key=lambda e: tuple(str(x) for x in e.absolute_path))
    return [
        "스키마 불일치: /" + "/".join(str(x) for x in e.absolute_path) +
        " (" + e.validator + ")"
        for e in failures[:25]
    ]


def validate_case_json(source: bytes) -> CaseValidation:
    if len(source) > MAX_CASE_JSON_BYTES:
        return CaseValidation(False, ("사례 JSON 크기 제한(512KiB) 초과",), None)
    try:
        payload = json.loads(source.decode("utf-8-sig"), object_pairs_hook=_no_duplicate_keys)
    except (ValueError, UnicodeDecodeError):
        return CaseValidation(False, ("유효하지 않은 JSON 인코딩 또는 중복 키입니다.",), None)
    if not isinstance(payload, dict):
        return CaseValidation(False, ("사례 JSON은 객체여야 합니다.",), None)

    issues = _format_errors(payload)
    if detect := detect_sensitive_patterns(json.dumps(payload, ensure_ascii=False)):
        issues.append("민감정보 패턴 포함: " + ", ".join(detect))
    sig = payload.get("match_signals")
    if isinstance(sig, dict) and all(isinstance(sig.get(k), list) for k in ("required", "supporting", "excluding")):
        groups = [set(x for x in sig[k] if isinstance(x, str)) for k in ("required", "supporting", "excluding")]
        if groups[0] & groups[2] or groups[1] & groups[2]:
            issues.append("필수/보조 신호와 제외 신호가 중복됩니다.")
        if not groups[0] and not groups[1]:
            issues.append("매칭 신호가 최소 하나 필요합니다.")
        allowed = {x["code"] for x in load_schema("signal_catalog.json")["signals"]}
        unknown = set.union(*groups) - allowed
        if unknown:
            issues.append("정의되지 않은 신호 코드가 포함되어 있습니다.")
    if payload.get("status") == "resolved_verified":
        cause = payload.get("root_cause")
        resolution = payload.get("resolution")
        verification = payload.get("verification")
        review = payload.get("review")
        if not (isinstance(cause, dict) and cause.get("status") == "confirmed"):
            issues.append("원인 확정 사례에는 확인된 근본 원인이 필요합니다.")
        if not (isinstance(resolution, dict) and resolution.get("verified") is True and resolution.get("actions")):
            issues.append("원인 확정 사례에는 검증된 실제 조치가 필요합니다.")
        if not (isinstance(verification, dict) and verification.get("status") == "verified" and verification.get("evidence")):
            issues.append("원인 확정 사례에는 해결 검증 근거가 필요합니다.")
        if not (isinstance(review, dict) and review.get("state") == "approved" and review.get("approved_at")):
            issues.append("원인 확정 사례에는 검토 승인 기록이 필요합니다.")
        if not payload.get("references"):
            issues.append("원인 확정 사례에는 출처가 필요합니다.")
    review = payload.get("review")
    if isinstance(review, dict) and review.get("state") != "approved" and review.get("approved_at"):
        issues.append("미승인 사례에 승인 일자가 지정되어 있습니다.")
    if isinstance(review, dict) and review.get("state") == "approved" and not review.get("approved_at"):
        issues.append("승인 사례에는 승인 일자가 필요합니다.")

    if issues:
        return CaseValidation(False, tuple(issues), None)
    return CaseValidation(
        True, (),
        {
            "case_id": payload["case_id"],
            "revision": payload["revision"],
            "title": payload["title"],
            "status": payload["status"],
            "review_state": payload["review"]["state"],
            "signal_count": sum(len(payload["match_signals"][k]) for k in ("required", "supporting", "excluding")),
        },
    )
