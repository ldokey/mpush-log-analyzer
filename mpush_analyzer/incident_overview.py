"""Concise, privacy-safe snapshot of what the submitted logs actually support.

Observed evidence timestamps are not incident start/end, and human-entered
collection times are not treated as server events.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any


CATEGORIES = {
    "SEND_JOB_DELAY": "발송",
    "RESULT_JOB_DELAY": "발송",
    "OTHER_JOB_DELAY": "발송",
    "JOB_RUNNING_STATE": "발송",
    "DB_SQL_DELAY": "DB",
    "SQL_ERROR": "DB",
    "TRANSPORT_DELAY": "통신",
    "TRANSPORT_ERROR": "통신",
    "HEALTHCHECK_GAP": "헬스체크",
    "PERIODIC_JOB_GAP": "헬스체크",
    "GENERAL_EXCEPTION": "오류",
    "AGENT_EXIT_SEEN": "기동·종료",
    "AGENT_START_SEEN": "기동·종료",
}


def category(finding: dict[str, Any]) -> str:
    return CATEGORIES.get(finding.get("signal_code"), "기타")


def finding_time_sort_key(finding: dict[str, Any]) -> tuple[int, str, str]:
    """Chronological sort by the recorded evidence, never by a guessed outage time."""
    refs = finding.get("evidence_refs") or []
    times = [ref["occurred_at"] for ref in refs
             if isinstance(ref.get("occurred_at"), str)]
    context = finding.get("time_context") or {}
    first = context.get("start_at")
    if isinstance(first, str):
        times.append(first)
    elif isinstance(finding.get("representative_at"), str):
        times.append(finding["representative_at"])
    if times:
        return 0, min(times), str(finding.get("finding_id", ""))
    clocks = [ref["clock"] for ref in refs
              if isinstance(ref.get("clock"), str)]
    return 1, min(clocks) if clocks else "", str(finding.get("finding_id", ""))


def snapshot(result: dict[str, Any], manifest: dict[str, Any]) -> dict[str, Any]:
    findings = result.get("findings") or []
    all_recorded = sorted({
        ref["occurred_at"] for finding in findings
        for ref in finding.get("evidence_refs", [])
        if isinstance(ref.get("occurred_at"), str)
    })
    undated_clocks = sorted({
        ref["clock"] for finding in findings
        for ref in finding.get("evidence_refs", [])
        if not ref.get("occurred_at") and isinstance(ref.get("clock"), str)
    })
    captures = manifest.get("collected_at")
    if not isinstance(captures, str):
        captures = None
    else:
        try:
            captures = datetime.fromisoformat(captures).strftime("%Y-%m-%d %H:%M:%S")
        except ValueError:
            captures = None
    incomplete = sum(
        source.get("completeness") != "full"
        for source in manifest.get("files", [])
        if source.get("kind") != "agent_ini"
    )
    categories = {}
    for f in findings:
        name = category(f)
        categories[name] = categories.get(name, 0) + 1
    return {
        "first_evidence": all_recorded[0] if all_recorded else (
            "날짜 미확인 · " + undated_clocks[0] if undated_clocks else None),
        "last_evidence": all_recorded[-1] if all_recorded else (
            "날짜 미확인 · " + undated_clocks[-1] if undated_clocks else None),
        "collected_at": captures,
        "findings_count": len(findings),
        "categories": categories,
        "incomplete_file_count": incomplete,
        "unknown_date_event_count": (result.get("metrics") or {}).get("undated_events", 0),
        "note": "표시된 최초·최종 시각은 보관된 탐지 근거의 표본 시각입니다. 장애 시작·종료를 뜻하지 않습니다.",
    }
