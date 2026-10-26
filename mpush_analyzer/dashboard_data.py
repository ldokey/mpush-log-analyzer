"""Bounded, local-only dashboard queries over Stage-2 sanitized JSONL.

Preserve original event references while preventing raw customer payload exposure.
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta
import json
from pathlib import Path
import re
from typing import Any, Iterator

from .pipeline import _get_manifest
from .finding_view import source_map

MAX_PAGE_SIZE = 250
MAX_TIMELINE_POINTS = 1800
EVENT_KEYS = {"file_id", "line_start", "line_end", "event_type", "clock",
              "occurred_at", "time_quality", "status", "details", "log_kind", "event_id"}
SAFE_KIND = {"job_run", "sql_execution", "healthcheck_result", "healthcheck_request",
             "cns_response", "job_running_skip", "agent_start", "agent_started",
             "agent_starting", "agent_exit", "agent_config_loading",
             "scheduler_registration", "transport_event", "log_error"}


@dataclass(frozen=True)
class EventFilters:
    start_minute: str | None = None
    end_minute: str | None = None
    log_kind: str | None = None
    job_name: str | None = None
    source_file_id: str | None = None


def read_result_bundle(case_dir: Path) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    """Do not trust an arbitrary JSON file or symlink in the workspace."""
    from jsonschema import Draft202012Validator, FormatChecker
    from .case_contract import load_schema

    manifest = _get_manifest(case_dir)
    paths = [case_dir / "analysis_result.json", case_dir / "case_matches.json"]
    bundles = []
    for path, schema in zip(paths, ("analysis_result.schema.json", "case_matches.schema.json")):
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 10 * 1024 * 1024:
            raise ValueError("분석 결과 파일을 확인할 수 없습니다.")
        document = json.loads(path.read_text(encoding="utf-8"))
        Draft202012Validator(load_schema(schema), format_checker=FormatChecker()).validate(document)
        if document["analysis_id"] != manifest["analysis_id"]:
            raise ValueError("분석 ID가 일치하지 않습니다.")
        bundles.append(document)
    return manifest, bundles[0], bundles[1]


def events_iter(case_dir: Path, manifest: dict[str, Any]) -> Iterator[dict[str, Any]]:
    path = case_dir / "events.jsonl"
    if path.is_symlink() or not path.is_file():
        raise ValueError("이벤트 저장 파일이 없습니다.")
    ids = {item["file_id"] for item in manifest["files"]}
    with path.open("r", encoding="utf-8") as handle:
        for raw in handle:
            if len(raw) > 25000:
                raise ValueError("비정상적으로 큰 이벤트를 확인했습니다.")
            event = json.loads(raw)
            if not isinstance(event, dict) or event.get("file_id") not in ids:
                raise ValueError("이벤트 파일과 원본 자료가 일치하지 않습니다.")
            if not (isinstance(event.get("line_start"), int) and
                    isinstance(event.get("line_end"), int) and
                    1 <= event["line_start"] <= event["line_end"]):
                raise ValueError("잘못된 로그 줄번호가 감지되었습니다.")
            # Stage-2 already produces sanitized fields; do not expose arbitrary injected extras.
            yield {k: event.get(k) for k in EVENT_KEYS}


def _display_event(event: dict[str, Any], aliases: dict[str, dict[str, str]] | None = None) -> dict[str, Any]:
    details = event.get("details") or {}
    # Fixed allowlist of short, structural, non-personal display fields.
    field_names = ("job_name", "duration_seconds", "laptime_ms",
                   "statement_kind", "sql_operation", "outcome",
                   "target_count", "response_code", "exception_class", "completed")
    pieces = []
    for key in field_names:
        value = details.get(key)
        if value is None:
            continue
        if isinstance(value, bool) or isinstance(value, (int, float)):
            pieces.append(f"{key}: {value}")
        elif isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9_]{1,70}", value):
            pieces.append(f"{key}: {value}")
    return {
        "시간": event.get("occurred_at") or event.get("clock") or "미확인",
        "로그": (aliases or {}).get(event.get("file_id"), {}).get("display", event.get("log_kind") or "unknown"),
        "로그 유형": event.get("log_kind") or "unknown",
        "유형": event.get("event_type") or "unknown",
        "주요값": ", ".join(pieces[:5]),
        "근거 위치": f"{event['file_id']}:{event['line_start']}-{event['line_end']}",
        "event_id": event.get("event_id"),
    }


def matching(event: dict[str, Any], flt: EventFilters) -> bool:
    if flt.log_kind and event.get("log_kind") != flt.log_kind:
        return False
    if flt.source_file_id and event.get("file_id") != flt.source_file_id:
        return False
    if flt.job_name and (event.get("details") or {}).get("job_name") != flt.job_name:
        return False
    stamp = event.get("occurred_at")
    minute = stamp[:16] if isinstance(stamp, str) else None
    if flt.start_minute and (minute is None or minute < flt.start_minute):
        return False
    if flt.end_minute and (minute is None or minute > flt.end_minute):
        return False
    return True


def summarize_events(case_dir: Path, manifest: dict[str, Any],
                     flt: EventFilters = EventFilters(), *, page: int = 1,
                     page_size: int = 100) -> dict[str, Any]:
    if not 1 <= page_size <= MAX_PAGE_SIZE or page < 1 or page > 1000000:
        raise ValueError("유효하지 않은 이벤트 조회 범위입니다.")
    total = 0
    displayed: list[dict[str, Any]] = []
    by_type: dict[str, int] = defaultdict(int)
    by_job: dict[str, int] = defaultdict(int)
    timeline: dict[str, dict[str, int | float]] = {}
    bucket_granularity = "minute"
    aliases = source_map(manifest)
    offset = (page - 1) * page_size
    first_minute, last_minute = None, None
    for event in events_iter(case_dir, manifest):
        if not matching(event, flt):
            continue
        total += 1
        typ = event.get("event_type") or "unknown"
        by_type[typ] += 1
        if offset < total <= offset + page_size:
            displayed.append(_display_event(event, aliases))
        details = event.get("details") or {}
        if typ == "job_run":
            job = details.get("job_name")
            if isinstance(job, str) and re.fullmatch(r"[A-Z0-9_]{3,64}", job):
                by_job[job] += 1
        stamp = event.get("occurred_at")
        if not stamp or not isinstance(stamp, str):
            continue
        minute = stamp[:16]
        if first_minute is None or minute < first_minute:
            first_minute = minute
        if last_minute is None or minute > last_minute:
            last_minute = minute
        key = minute if bucket_granularity == "minute" else (
            minute[:13] + ":00" if bucket_granularity == "hour" else minute[:10]
        )
        if key not in timeline and len(timeline) >= MAX_TIMELINE_POINTS:
            bucket_granularity = "hour" if bucket_granularity == "minute" else "day"
            new_timeline: dict[str, dict[str, int | float]] = {}
            for existing, values in timeline.items():
                compressed = existing[:13] + ":00" if bucket_granularity == "hour" else existing[:10]
                agg = new_timeline.setdefault(compressed, {k: 0 for k in values})
                for field, val in values.items():
                    if field.startswith("longest_"):
                        agg[field] = max(agg[field], val)
                    else:
                        agg[field] += val
            timeline = new_timeline
            key = minute[:13] + ":00" if bucket_granularity == "hour" else minute[:10]
        if key not in timeline:
            timeline[key] = {
                "events": 0, "job_runs": 0, "db_calls": 0,
                "cns_responses": 0, "log_errors": 0,
                "longest_job_seconds": 0.0, "longest_sql_ms": 0.0,
            }
        b = timeline[key]
        b["events"] += 1
        if typ == "job_run":
            b["job_runs"] += 1
            value = details.get("duration_seconds")
            if isinstance(value, (int, float)):
                b["longest_job_seconds"] = max(b["longest_job_seconds"], value)
        elif typ == "sql_execution":
            b["db_calls"] += 1
            value = details.get("laptime_ms")
            if isinstance(value, (int, float)):
                b["longest_sql_ms"] = max(b["longest_sql_ms"], value)
        elif typ == "cns_response":
            b["cns_responses"] += 1
        elif typ == "log_error":
            b["log_errors"] += 1

    # Bucket size is tightened during streaming to bound memory use.
    timeline_rows = [{"기간": key, **row} for key, row in sorted(timeline.items())]
    return {
        "total": total, "page": page, "page_size": page_size,
        "pages": max(1, (total + page_size - 1) // page_size),
        "rows": displayed, "by_type": dict(sorted(by_type.items())),
        "by_job": dict(sorted(by_job.items())),
        "timeline": timeline_rows,
        "time_bucket": bucket_granularity,
        "first_minute": first_minute, "last_minute": last_minute,
    }


def find_correlated_events(case_dir: Path, manifest: dict[str, Any],
                           reference: dict[str, Any], *,
                           window_seconds: int = 120, limit: int = 150) -> list[dict[str, Any]]:
    """Return cross-file context, not causal relationships."""
    if not 10 <= window_seconds <= 3600 or not 1 <= limit <= 300:
        raise ValueError("연계 조회 범위를 확인해 주세요.")
    center = reference.get("occurred_at")
    if not isinstance(center, str):
        return []
    target = datetime.fromisoformat(center)
    aliases = source_map(manifest)
    # Bounded closest matches: a dense healthcheck interval must not displace
    # the exact incident or an exception because it appeared later in the log.
    priorities = {
        "log_error": 0, "job_running_skip": 1, "job_run": 2,
        "sql_execution": 3, "cns_response": 4, "healthcheck_result": 6,
    }
    ranked: list[tuple[tuple[Any, ...], dict[str, Any]]] = []
    for event in events_iter(case_dir, manifest):
        stamp = event.get("occurred_at")
        if not isinstance(stamp, str):
            continue
        moment = datetime.fromisoformat(stamp)
        offset = (moment - target).total_seconds()
        if abs(offset) > window_seconds:
            continue
        rank = (abs(offset), priorities.get(event.get("event_type"), 5),
                str(event.get("file_id")), int(event.get("line_start", 0)))
        if len(ranked) >= limit and rank >= ranked[-1][0]:
            continue
        preview = _display_event(event, aliases)
        preview["시각차(초)"] = round(offset, 3)
        ranked.append((rank, preview))
        ranked.sort(key=lambda item: item[0])
        if len(ranked) > limit:
            ranked.pop()
    return [event for _, event in ranked]
