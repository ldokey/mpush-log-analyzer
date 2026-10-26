"""Evidence-first matching of observed signal codes to human-approved case revisions.

A ranking score is NOT a probability of shared root cause.
"""
from __future__ import annotations

from collections import defaultdict
from typing import Any

from .case_library import read_approved_cases
from .case_contract import load_schema


def match_cases(
    findings: list[dict[str, Any]], manifest: dict[str, Any],
    job_stats: dict[str, Any], *, root=None, limit: int = 10,
) -> dict[str, Any]:
    if not 1 <= limit <= 30:
        raise ValueError("유사 사례 결과 개수 제한을 확인해 주세요.")
    docs, rejected = read_approved_cases(**({"root":root} if root is not None else {}))
    signals: set[str] = set()
    references: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for finding in findings:
        code = finding.get("signal_code")
        if not isinstance(code, str):
            continue
        signals.add(code)
        for ref in finding.get("evidence_refs", []):
            if ref not in references[code] and len(references[code]) < 5:
                references[code].append(ref)

    known_version = manifest.get("agent_version")
    if known_version == "auto":
        known_version = None
    cfg = manifest.get("config_summary") or {}
    dbms = (cfg.get("dbms") or {}).get("type")
    if dbms == "unknown":
        dbms = None
    known_jobs = set(job_stats)
    matches: list[dict[str, Any]] = []
    for doc in docs:
        requirements = doc["match_signals"]
        required = set(requirements["required"])
        supporting = set(requirements["supporting"])
        exclusions = set(requirements["excluding"])
        if not required.issubset(signals) or (exclusions & signals):
            continue
        supporting_hits = sorted(supporting & signals)
        if not required and not supporting_hits:
            continue
        environ = doc["environment"]
        unknown_checks = []
        if environ["agent_versions"]:
            if known_version and known_version not in environ["agent_versions"]:
                continue
            if not known_version:
                unknown_checks.append("Agent 버전")
        if environ["dbms"]:
            if dbms and dbms not in environ["dbms"]:
                continue
            if not dbms:
                unknown_checks.append("DBMS")
        if environ["jobs"]:
            if known_jobs and not (known_jobs & set(environ["jobs"])):
                continue
            if not known_jobs:
                unknown_checks.append("Job")
        # Local analyzer runs on macOS, which tells us nothing about the customer OS.
        if environ["os"]:
            unknown_checks.append("고객사 OS")
        required_hits = sorted(required)
        score = (
            45 + (20 if required else 0)
            + round(20 * len(supporting_hits) / max(1, len(supporting)))
            + (5 if known_version and environ["agent_versions"] else 0)
            + (5 if dbms and environ["dbms"] else 0)
            + (5 if known_jobs and environ["jobs"] else 0)
        )
        matched = sorted(set(required_hits + supporting_hits))
        evidence = []
        for code in matched:
            for ref in references[code]:
                if ref not in evidence and len(evidence) < 8:
                    evidence.append(ref)
        verified = doc["status"] == "resolved_verified"
        matches.append({
            "case_id": doc["case_id"], "revision": doc["revision"],
            "title": doc["title"], "status": doc["status"],
            "review_state": doc["review"]["state"],
            "match_rank_score": min(score, 100),
            "score_meaning": "relative_order_only_not_probability",
            "matched_required_signals": required_hits,
            "matched_supporting_signals": supporting_hits,
            "unchecked_environment": unknown_checks,
            "evidence_refs": evidence,
            "result_type": "verified_solution" if verified else "reference_only",
            "diagnostic_checks": doc["diagnostic_checks"][:12],
            "resolution_actions": doc["resolution"]["actions"][:12] if verified else [],
            "limitations": (
                ["유사한 신호가 동일한 근본 원인을 보장하지 않습니다."]
                + (["근본 원인이 검증되지 않아 참고 사례로만 제공합니다."] if not verified else [])
                + (["고객사 환경 일부가 확인되지 않았습니다."] if unknown_checks else [])
            ),
        })
    matches.sort(key=lambda m: (-m["match_rank_score"], m["result_type"] != "verified_solution",
                                m["case_id"], -m["revision"]))
    return {
        "schema_version": "1.0",
        "catalog_version": load_schema("signal_catalog.json")["schema_version"],
        "approved_case_count": len(docs),
        "invalid_approved_case_count": rejected,
        "match_count": len(matches),
        "matched_cases": matches[:limit],
        "displayed_count": min(len(matches), limit),
        "limitations": [
            "점수는 증상 일치 기반 표시 우선순위이며 원인이 같을 확률이 아닙니다.",
            "검토된 사례도 현재 장애의 원인이나 실제 복구 결과를 보장하지 않습니다.",
        ],
    }
