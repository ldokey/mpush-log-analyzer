"""AI handoff packets with evidence, time provenance and cross-log context.

Only allowlisted, sanitized numerical and categorical fields are exported.
No raw logs, SQL, identifiers, user-upload filenames or AI-authored case prose.
"""
from __future__ import annotations

from bisect import bisect_left, bisect_right
from datetime import datetime
import json
from pathlib import Path
import re
from typing import Any

from .dashboard_data import _display_event, events_iter
from .finding_view_v2 import details, file_label, format_timestamp

_CONTEXT_WINDOW = 120
_MAX_CONTEXT = 16
_MAX_ITEMS = 80
_EVENT_PRIORITY = {
    "log_error": 0, "job_running_skip": 1, "job_run": 2,
    "sql_execution": 3, "cns_response": 4, "agent_exit": 5,
    "agent_started": 6, "healthcheck_result": 7, "healthcheck_request": 8,
}


def _safe_lines(raw: Any) -> list[str]:
    """Project untrusted limitation strings onto fixed, disclosure-safe phrases.

    Rejecting known secret patterns is insufficient: client names and new secret
    formats may not match a regex. Never copy an arbitrary limitation verbatim.
    """
    categories = (
        ("일부 추출", "일부 추출된 원본이 포함되어 전체 기록을 대표하지 않습니다."),
        ("완전성", "제출 로그 중 원본 완전성이 확인되지 않은 자료가 있을 수 있습니다."),
        ("기준 날짜", "일부 이벤트는 기준 날짜가 없어서 시각만 분석했습니다."),
        ("수집 시각", "사용자가 입력한 로그 수집 시각만으로 프로세스 상태를 확정할 수 없습니다."),
        ("인코딩", "일부 입력에서 문자 디코딩 손실 가능성이 확인됐습니다."),
        ("자정 경과", "일부 날짜는 자정 경과를 로그 순서로부터 추론했습니다."),
        ("순서", "일부 로그는 시각이 단조 증가하지 않아 시간순 해석에 제약이 있습니다."),
        ("헬스체크", "헬스체크 표본 또는 완전성 부족으로 일부 공백 판단을 보류했습니다."),
        ("이벤트", "알려진 형식 외 로그 줄은 분석 결과에 포함되지 않았을 수 있습니다."),
    )
    selected = []
    if isinstance(raw, list):
        for msg in raw[:200]:
            if not isinstance(msg, str):
                continue
            for token, template in categories:
                if token in msg and template not in selected:
                    selected.append(template)
    selected.append(
        "기록 공백·Job 지연·통신 단계 소요시간은 장애의 근본 원인이나 수신 성공을 입증하지 않습니다."
    )
    return selected[:20]


def _context_events(case_dir: Path, manifest: dict[str, Any],
                    observed: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    """Return nearby sanitized events for up to twelve evidence timestamps.

    Each timestamp with matching records receives at least one context event,
    before other high-priority records fill the remaining output slots. This
    prevents one dense interval from hiding every later event in a finding.
    """
    from datetime import timedelta

    anchors_by_time: dict[datetime, list[str]] = {}
    all_ids: list[str] = []
    for record in observed:
        finding_id = record["finding_id"]
        all_ids.append(finding_id)
        for ref in record.get("evidence", [])[:12]:
            raw = ref.get("occurred_at")
            if not isinstance(raw, str):
                continue
            try:
                at = datetime.fromisoformat(raw)
            except ValueError:
                continue
            group = anchors_by_time.setdefault(at, [])
            if finding_id not in group:
                group.append(finding_id)
    if not anchors_by_time:
        return {}
    timestamps = sorted(anchors_by_time)
    per_anchor: dict[tuple[str, datetime], list[tuple[tuple[Any, ...], dict[str, Any]]]] = {}
    max_per_anchor = 4

    for event in events_iter(case_dir, manifest):
        raw_at = event.get("occurred_at")
        if not isinstance(raw_at, str):
            continue
        try:
            at = datetime.fromisoformat(raw_at)
            left = bisect_left(timestamps, at - timedelta(seconds=_CONTEXT_WINDOW))
            right = bisect_right(timestamps, at + timedelta(seconds=_CONTEXT_WINDOW))
        except (ValueError, TypeError):
            continue
        if left == right:
            continue
        shown = _display_event(event)
        entity = {
            "recorded_at": shown["시간"],
            "log_file": file_label(event["file_id"], manifest),
            "event_type": shown["유형"],
            "safe_summary": shown["주요값"][:220],
            "evidence_lines": shown["근거 위치"],
        }
        for anchor_at in timestamps[left:right]:
            seconds = abs((at - anchor_at).total_seconds())
            rank = (_EVENT_PRIORITY.get(event.get("event_type"), 50), seconds,
                    str(event.get("file_id")), int(event.get("line_start", 0)))
            for finding_id in anchors_by_time[anchor_at]:
                bucket = per_anchor.setdefault((finding_id, anchor_at), [])
                if any(x[1]["evidence_lines"] == entity["evidence_lines"] for x in bucket):
                    continue
                if len(bucket) >= max_per_anchor and rank >= bucket[-1][0]:
                    continue
                bucket.append((rank, entity))
                bucket.sort(key=lambda x: x[0])
                if len(bucket) > max_per_anchor:
                    bucket.pop()

    output: dict[str, list[dict[str, Any]]] = {}
    for finding_id in all_ids:
        selected: list[dict[str, Any]] = []
        taken: set[str] = set()
        rows = sorted((at, entries) for (fid, at), entries in per_anchor.items()
                      if fid == finding_id)
        # Include one event per evidenced timestamp, when possible (<=12 anchors).
        for _, entries in rows:
            if len(selected) >= _MAX_CONTEXT:
                break
            for _, entity in entries:
                ref = entity["evidence_lines"]
                if ref not in taken:
                    taken.add(ref)
                    selected.append(entity)
                    break
        # Fill remaining places using meaningful categories first, then distance.
        remaining = sorted((item for _, entries in rows for item in entries),
                           key=lambda item: item[0])
        for _, entity in remaining:
            if len(selected) >= _MAX_CONTEXT:
                break
            ref = entity["evidence_lines"]
            if ref not in taken:
                taken.add(ref)
                selected.append(entity)
        output[finding_id] = selected
    return output


def build_packet(case_dir: Path, manifest: dict[str, Any],
                 result: dict[str, Any], matches: dict[str, Any],
                 *, only_finding_id: str | None = None) -> dict[str, Any]:
    """Construct a trustworthy inspectable document from an existing analysis."""
    from .pipeline import _get_manifest
    checked = _get_manifest(case_dir)  # Recheck every original hash before export.
    if (checked["analysis_id"] != manifest.get("analysis_id") or
            result.get("analysis_id") != manifest.get("analysis_id") or
            matches.get("analysis_id") != manifest.get("analysis_id")):
        raise ValueError("AI 인계 대상 분석 ID가 일치하지 않습니다.")
    findings = [f for f in result.get("findings", [])
                if only_finding_id is None or f.get("finding_id") == only_finding_id][:_MAX_ITEMS]
    if only_finding_id and not findings:
        raise ValueError("선택한 이상 징후 ID를 찾을 수 없습니다.")
    records: list[dict[str, Any]] = []
    for finding in findings:
        item = details(finding, manifest)
        item["evidence"] = [{
            **row, "occurred_at": (
                ref.get("occurred_at") if isinstance(ref.get("occurred_at"), str) else None
            )
        } for row, ref in zip(item["evidence"], finding.get("evidence_refs") or [])]
        records.append(item)
    nearby = _context_events(case_dir, manifest, records)
    for item in records:
        item["nearby_sanitized_events"] = nearby.get(item["finding_id"], [])
        item["context_anchor_count"] = len({
            ref["occurred_at"] for ref in item.get("evidence", [])[:12]
            if isinstance(ref.get("occurred_at"), str)
        })

    source_list = []
    for entry in manifest.get("files", []):
        fid = entry.get("file_id")
        if not isinstance(fid, str):
            continue
        source_list.append({
            "label": file_label(fid, manifest),
            "type": entry.get("kind"),
            "completeness": entry.get("completeness"),
            "date_hint": entry.get("date_hint"),
            "first_clock_hint": entry.get("first_time_hint"),
            "last_clock_hint": entry.get("last_time_hint"),
            "lines_total": entry.get("line_count"),
        })
    metrics = result.get("metrics") or {}
    summaries = (metrics.get("stage3") or {})
    config = manifest.get("config_summary") or {}
    dbms = (config.get("dbms") or {}).get("type")
    if dbms not in {"mysql", "mariadb", "oracle", "postgresql", "mssql", "db2", "unknown"}:
        dbms = "unknown"
    known_version = manifest.get("agent_version")
    if known_version not in {"3.2", "3.3", "auto"}:
        known_version = "auto"
    safe_jobs = {}
    for name, values in summaries.get("job_duration_statistics", {}).items():
        if isinstance(name, str) and re.fullmatch(r"[A-Z][A-Z0-9_]{2,63}", name):
            safe_jobs[name] = {k: values.get(k) for k in (
                "samples", "average", "p50", "p95", "max_seconds", "slow_above_absolute")}
    safe_db = {}
    for name, values in summaries.get("db_duration_statistics", {}).items():
        if name in {"EQ", "EU", "EB", "UNKNOWN"}:
            safe_db[name] = {k: values.get(k) for k in (
                "samples", "average", "p95", "max_ms", "slow_above_absolute")}
    safe_runs = {}
    for name, values in (metrics.get("job_runs") or {}).items():
        if not isinstance(name, str) or not re.fullmatch(r"[A-Z][A-Z0-9_]{2,63}", name):
            continue
        safe_runs[name] = {
            key: values.get(key) if isinstance(values.get(key), int) and not isinstance(values.get(key), bool) else 0
            for key in ("runs", "completed", "incomplete", "target_count_total")
        }
    related_cases = [{
        "case_id": x["case_id"],
        "revision": x["revision"],
        "result_type": x["result_type"],
        "matched_signals": x["matched_required_signals"] + x["matched_supporting_signals"],
        "rank_is_probability": False,
    } for x in matches.get("matched_cases", [])[:10]
       if re.fullmatch(r"MPA-CASE-\d{6}", str(x.get("case_id", "")))]

    return {
        "schema_version": "1.0",
        "purpose": "AI_ASSISTED_INCIDENT_TRIAGE_NOT_ROOT_CAUSE_CONFIRMATION",
        "analysis_id": manifest["analysis_id"],
        "agent_version": known_version,
        "dbms": dbms,
        "timezone": "Asia/Seoul",
        "reference_date": manifest.get("reference_date"),
        "collected_at": manifest.get("collected_at"),
        "analysis_status": result.get("analysis_status"),
        "scope": "selected_finding" if only_finding_id else "all_findings",
        "source_files": source_list,
        "statistics": {
            "events_extracted": metrics.get("events_total"),
            "events_without_confirmed_date": metrics.get("undated_events"),
            "incomplete_events": metrics.get("incomplete_events"),
            "job_run_counts": safe_runs,
            "job_statistics": safe_jobs,
            "sql_statistics": safe_db,
            "cns_request_response_counts": {
                str(key): int(value) for key, value in (metrics.get("cns_request_responses") or {}).items()
                if isinstance(key, str) and re.fullmatch(r"[A-Z0-9_-]{1,20}", key)
                and isinstance(value, int) and not isinstance(value, bool)
            },
            "job_runs_not_equal_delivered_messages": True,
        },
        "findings": records,
        "related_approved_cases": related_cases,
        "analysis_limitations": _safe_lines(result.get("limitations", [])),
        "mandatory_review": (
            "AI 서비스에 전달하기 전에 개인정보·영업기밀이 남지 않았는지 담당자가 확인해야 합니다. "
            "기록 공백은 프로세스 종료의 증거가 아니며 CNS 요청 수락은 수신 성공이 아닙니다."
        ),
        "questions_for_ai": [
            "확인된 사실과 가능한 원인 가설을 구분하고, 어떤 증거가 부족한지 평가해 주세요.",
            "추가 조사 우선순위와 필요한 DB/네트워크/JVM 점검 사항을 제안해 주세요.",
            "근거가 없는 원인 확정이나 무조건적인 재기동 지시는 하지 말아 주세요.",
        ],
    }


def to_markdown(packet: dict[str, Any]) -> str:
    lines = [
        "# MPushAgent 로그 진단 — AI 분석 전달 자료",
        "",
        "> 개인정보·업무정보 사전 검토 필요. 원본 로그/SQL/전화번호는 포함하지 않음.",
        "",
        f"- 분석 ID: {packet['analysis_id']}",
        f"- 분석 범위: {packet['scope']} · {packet['analysis_status']}",
        f"- Agent: {packet['agent_version']} · DBMS: {packet['dbms']}",
        f"- 기준 날짜: {packet['reference_date'] or '미확인'}",
        f"- 수집 시각: {packet['collected_at'] or '미확인'}",
        "- 기준 시간대: Asia/Seoul (원본 서버의 시간대는 별도 검증 필요)",
        "",
        "## 1. 분석 자료",
        "",
        "| 자료 | 유형 | 완전성 | 날짜 힌트 | 최초 시각 | 최종 시각 |",
        "|---|---|---|---|---|---|",
    ]
    for f in packet["source_files"]:
        lines.append(
            f"| {f['label']} | {f['type']} | {f['completeness']} | "
            f"{f['date_hint'] or '미확인'} | {f['first_clock_hint'] or '-'} | {f['last_clock_hint'] or '-'} |"
        )
    lines.extend(["", "## 2. 공통 지표", ""])
    stats = packet["statistics"]
    lines.append(f"- 추출 이벤트: {stats['events_extracted']}개")
    lines.append(f"- 날짜 미확인 이벤트: {stats['events_without_confirmed_date']}개")
    lines.append(f"- 미완료/부분 기록 이벤트: {stats['incomplete_events']}개")
    lines.append(f"- CNS 요청 수락 코드는 실제 최종 배송 성공이 아닙니다: {stats['cns_request_response_counts']}")
    for job, values in stats["job_run_counts"].items():
        lines.append(f"- Job {job} 실행/완료/미완료/작업대상: "
                     f"{values['runs']}/{values['completed']}/{values['incomplete']}/{values['target_count_total']}")
    def fmt(value: Any) -> str:
        if value is None:
            return "미확인"
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            return "미확인"
        return f"{value:,g}"

    lines.extend([
        "", "### Job 처리시간 분포 (초)", "",
        "| Job | 완료 표본 | 평균 | P50 | P95 | 최대 | 절대 기준 초과 횟수 |",
        "|---|---:|---:|---:|---:|---:|---:|",
    ])
    for job, data in stats["job_statistics"].items():
        lines.append(
            f"| {job} | {fmt(data.get('samples'))} | {fmt(data.get('average'))} | "
            f"{fmt(data.get('p50'))} | {fmt(data.get('p95'))} | "
            f"{fmt(data.get('max_seconds'))} | {fmt(data.get('slow_above_absolute'))} |"
        )
    lines.extend([
        "", "### DB SQL 처리시간 분포 (ms)", "",
        "| 유형 | 실행 표본 | 평균 | P95 | 최대 | 절대 기준 초과 횟수 |",
        "|---|---:|---:|---:|---:|---:|",
    ])
    for kind, data in stats["sql_statistics"].items():
        lines.append(
            f"| {kind} | {fmt(data.get('samples'))} | {fmt(data.get('average'))} | "
            f"{fmt(data.get('p95'))} | {fmt(data.get('max_ms'))} | "
            f"{fmt(data.get('slow_above_absolute'))} |"
        )
    lines.extend(["", "## 3. 탐지된 이상 징후와 조사 근거", ""])
    if not packet["findings"]:
        lines.append("등록된 이상 징후가 없습니다. 정상 상태임을 보증하지 않습니다.")
    for number, item in enumerate(packet["findings"], 1):
        tm = item["time"]
        lines.extend([
            f"### {number}. {item['title']} ({item['signal_code']})",
            "",
            f"- 구분: {item['statement']} · 신뢰 정도: {item['confidence']}",
            f"- 시간 의미: {tm['기준']}",
            f"- 시작: {tm['시작']}",
            f"- 끝: {tm['끝']}",
            f"- 시간 해석 주의: {tm['신뢰 안내']}",
            f"- 확인된 사실: {item['summary']}",
            f"- 상세 설명: {item['analysis_detail'] or '-'}",
            f"- 탐지 이유: {item['why_flagged']}",
            f"- 확인할 사항: {item['next_check']}",
            "",
            "| 수치 | 값 |", "|---|---|",
        ])
        for value in item["measurements"]:
            lines.append(f"| {value['항목']} | {value['측정값']} |")
        lines.extend(["", "| 근거시각 | 파일 | 줄 | 날짜 근거 | 로그상 시작 | 계산상 시작 | 시작시각 주의 |",
                      "|---|---|---|---|---|---|---|"])
        for evidence in item["evidence"]:
            lines.append(
                f"| {evidence['근거시각']} | {evidence['근거 파일']} | {evidence['줄']} | "
                f"{evidence['날짜 근거']} | {evidence['로그상 시작']} | "
                f"{evidence['계산상 시작']} | {evidence['시작시각 주의']} |"
            )
        lines.extend(["", "같은 시간대의 비식별 이벤트 (근거 표본시각 최대 12곳에 각각 ±120초, 총 최대 16건; 인과관계 미확정):",
                      f"- 조사에 사용한 기준 시각: {item.get('context_anchor_count', 0)}개"])
        for event in item["nearby_sanitized_events"]:
            lines.append(
                f"- {event['recorded_at']} · {event['log_file']} · {event['event_type']}"
                f" · {event['safe_summary']} · {event['evidence_lines']}"
            )
        lines.append("")
    lines.extend(["## 4. 승인된 기존 참고 사례", ""])
    if packet["related_approved_cases"]:
        for case in packet["related_approved_cases"]:
            lines.append(
                f"- {case['case_id']} r{case['revision']} · {case['result_type']} "
                f"· 일치 신호: {', '.join(case['matched_signals'])}"
            )
    else:
        lines.append("유사한 승인 사례 없음.")
    lines.extend(["", "## 5. 분석 제한 및 AI에게 요청할 질문", ""])
    for value in packet["analysis_limitations"]:
        lines.append(f"- {value}")
    lines.extend(["", "**검토 안내:** " + packet["mandatory_review"], ""])
    for q in packet["questions_for_ai"]:
        lines.append("- " + q)
    return "\n".join(lines) + "\n"


def build_ai_exports(case_dir: Path, manifest: dict[str, Any],
                     result: dict[str, Any], matches: dict[str, Any],
                     *, only_finding_id: str | None = None) -> dict[str, bytes]:
    packet = build_packet(case_dir, manifest, result, matches, only_finding_id=only_finding_id)
    return {
        "ai_brief.md": to_markdown(packet).encode("utf-8"),
        "ai_brief.json": (json.dumps(packet, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8"),
    }
