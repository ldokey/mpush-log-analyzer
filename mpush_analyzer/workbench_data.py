"""Bounded, privacy-safe event exploration for the local MPushAgent workbench.

Every rendered value is projected from a small allowlist of typed parser fields.
Neither raw SQL text, exception messages nor unknown JSON keys can be surfaced.
The original JSONL is streamed; default paging does not hold the full log in RAM.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from datetime import datetime
import heapq
import math
import re
from typing import Any, Literal

from .dashboard_data import SAFE_KIND, events_iter
from .finding_view_v2 import file_label

PAGE_SIZES = (25, 50, 100, 200)
MAX_RANKED_ROWS = 20000
SAFE_JOB = re.compile(r"[A-Z][A-Z0-9_]{2,63}\Z")
SAFE_REF = re.compile(r"file_[0-9]{2}\Z")
SAFE_ERROR = re.compile(r"(?:[A-Za-z_][A-Za-z0-9_]{0,50}(?:Exception|Error)|unspecified)\Z")
SAFE_CODE = re.compile(r"[A-Z0-9_-]{1,12}\Z")
SAFE_CLOCK = re.compile(r"(?:[01]\d|2[0-3]):[0-5]\d:[0-5]\d\.\d{3}\Z")
SAFE_MINUTE = re.compile(r"\d{4}-\d{2}-\d{2}T[0-2]\d:[0-5]\d\Z")
STMT = re.compile(r"[A-Z]{1,4}\Z")
SQL_OPERATIONS = frozenset({"SELECT", "INSERT", "UPDATE", "DELETE", "MERGE", "WITH", "CALL", "UNKNOWN"})
STEP_FIELDS = (("select", "SELECT(초)"), ("file", "FILE(초)"),
               ("socket", "SOCKET(초)"), ("http_in", "HTTP IN(초)"),
               ("http_out", "HTTP OUT(초)"), ("db", "DB(초)"))
ACTION_CODES = frozenset({"no_action", "shutdown_requested", "unknown"})
TRANSPORT_STATES = frozenset({"socket_connected", "file_transfer_completed",
                              "awaiting_response", "file_transfer_result_seen"})
STATES = frozenset({"complete", "incomplete", "observed", "failed"})
EVENT_NAMES = {
    "job_run": "Job 실행", "sql_execution": "SQL 실행",
    "healthcheck_result": "헬스체크 결과", "healthcheck_request": "헬스체크 요청",
    "cns_response": "CNS 응답", "job_running_skip": "RUNNING 건너뜀",
    "agent_start": "Agent 시작", "agent_started": "Agent 기동 완료",
    "agent_starting": "Agent 기동 중", "agent_exit": "Agent 종료",
    "agent_config_loading": "설정 로드", "scheduler_registration": "스케줄 등록",
    "transport_event": "통신 상태", "log_error": "오류 기록",
}
DISPLAY_FIELDS = {
    "events": ("시각", "유형", "상태", "Job", "처리시간(초)", "DB시간(ms)",
               "주요 정보", "근거 파일", "줄번호"),
    "jobs": ("시각", "로그상 시작", "역산 시작", "시작시각 품질",
             "Job", "상태", "작업대상", "처리시간(초)", "로그 TPS",
             "SELECT(초)", "FILE(초)", "SOCKET(초)", "HTTP IN(초)",
             "HTTP OUT(초)", "DB(초)", "근거 파일", "줄번호"),
    "db": ("시각", "PSTMT 유형", "SQL 명령", "결과", "처리시간(ms)",
           "영향 행수", "상태", "근거 파일", "줄번호"),
    "signals": ("시각", "유형", "상태", "Job", "주요 정보", "근거 파일", "줄번호"),
}
SIGNAL_TYPES = frozenset({
    "log_error", "job_running_skip", "healthcheck_result",
    "healthcheck_request", "cns_response", "transport_event",
    "agent_exit", "agent_started", "agent_starting", "agent_config_loading",
})


@dataclass(frozen=True)
class EventQuery:
    """Optional filters; timestamps are ISO local minutes for this Agent."""
    view: Literal["events", "jobs", "db", "signals"] = "events"
    log_kind: str | None = None
    event_type: str | None = None
    job_name: str | None = None
    file_id: str | None = None
    status: str | None = None
    from_minute: str | None = None
    to_minute: str | None = None
    min_duration: float | None = None
    slow_only: bool = False
    sort: Literal["time_asc", "time_desc", "duration_desc"] = "time_asc"


def _enum(value: Any, allowed: set[str] | frozenset[str]) -> str | None:
    return value if isinstance(value, str) and value in allowed else None


def _code(value: Any, pattern: re.Pattern[str]) -> str | None:
    return value if isinstance(value, str) and pattern.fullmatch(value) else None


def _number(value: Any, maximum: float, *, decimal: int = 3) -> float | int | None:
    if type(value) not in (int, float) or not math.isfinite(value) or not 0 <= value <= maximum:
        return None
    return int(value) if type(value) is int else round(value, decimal)


def _safe_time(value: Any) -> str | None:
    if not isinstance(value, str) or len(value) > 48 or "T" not in value:
        return None
    try:
        return datetime.fromisoformat(value).isoformat(timespec="milliseconds")
    except ValueError:
        return None


def _event_clock(event: dict[str, Any]) -> str:
    observed = _safe_time(event.get("occurred_at"))
    if observed:
        return observed
    clock = _code(event.get("clock"), SAFE_CLOCK)
    return "날짜 미확인 · " + clock if clock else "시각 미확인"


def _safe_details(event: dict[str, Any]) -> dict[str, Any]:
    """All outputs are typed/allowlisted, even for a tampered derived JSONL."""
    d = event.get("details")
    d = d if isinstance(d, dict) else {}
    kind = event.get("event_type")
    if kind == "job_run":
        result: dict[str, Any] = {
            "Job": _code(d.get("job_name"), SAFE_JOB),
            "작업대상": _number(d.get("target_count"), 10_000_000, decimal=0),
            "처리시간(초)": _number(d.get("duration_seconds"), 1_000_000),
            "로그 TPS": _number(d.get("reported_tps"), 10_000_000),
            "로그상 시작": _safe_time(d.get("start_at")),
            "역산 시작": _safe_time(d.get("calculated_start_at")),
            "시작시각 품질": _enum(d.get("start_time_quality"), frozenset({
                "unavailable", "clock_only", "duration_calculated",
                "duration_clock_conflict",
            })),
        }
        steps = d.get("steps_seconds")
        steps = steps if isinstance(steps, dict) else {}
        for key, label in STEP_FIELDS:
            result[label] = _number(steps.get(key), 1_000_000)
        return result
    if kind == "sql_execution":
        return {
            "PSTMT 유형": _code(d.get("statement_kind"), STMT),
            "SQL 명령": _enum(d.get("sql_operation"), SQL_OPERATIONS),
            "처리시간(ms)": _number(d.get("laptime_ms"), 1_000_000_000),
            "결과": _enum(d.get("outcome"), frozenset({
                "select_completed", "batch_success", "rows_affected",
                "failed", "unknown",
            })),
            "영향 행수": _number(d.get("affected_rows"), 10_000_000, decimal=0),
        }
    if kind == "log_error":
        return {
            "예외 유형": _code(d.get("exception_class"), SAFE_ERROR),
            "스택 프레임 수": _number(d.get("stack_frame_count"), 10000, decimal=0),
        }
    if kind == "scheduler_registration":
        return {"Job": _code(d.get("job_name"), SAFE_JOB)}
    if kind == "job_running_skip":
        return {"Job": _code(d.get("job_name"), SAFE_JOB)}
    if kind == "cns_response":
        return {
            "응답 코드": _code(d.get("response_code"), SAFE_CODE),
            "응답 의미": "요청 수락(최종 수신 아님)" if d.get("response_code") == "S"
                       else "최종 수신 여부 미확인",
        }
    if kind == "healthcheck_result":
        return {"헬스체크 동작": _enum(d.get("target_action"), ACTION_CODES)}
    if kind == "transport_event":
        return {"통신 이벤트": _enum(d.get("state"), TRANSPORT_STATES)}
    return {}


def project_event(event: dict[str, Any], manifest: dict[str, Any]) -> dict[str, Any]:
    """Return a record fit for a table and its detail panel (never raw data)."""
    file_id = _code(event.get("file_id"), SAFE_REF)
    start, end = event.get("line_start"), event.get("line_end")
    valid_ref = (file_id is not None and type(start) is int and type(end) is int
                 and 1 <= start <= end)
    kind = event.get("event_type")
    kind = kind if isinstance(kind, str) and kind in SAFE_KIND and kind in EVENT_NAMES else None
    safe = _safe_details({**event, "event_type": kind})
    row = {
        "시각": _event_clock(event),
        "유형": EVENT_NAMES.get(kind, "미분류 이벤트"),
        "상태": _enum(event.get("status"), STATES) or "미확인",
        "Job": safe.get("Job"),
        "처리시간(초)": safe.get("처리시간(초)"),
        "DB시간(ms)": safe.get("처리시간(ms)"),
        "주요 정보": _short_summary(kind, safe),
        "근거 파일": file_label(file_id, manifest) if file_id else "미확인",
        "줄번호": f"{start:,}–{end:,}" if valid_ref else "미확인",
        "원본 ID": file_id if valid_ref else None,
        "시작행": start if valid_ref else None,
        "끝행": end if valid_ref else None,
        "이벤트 코드": kind or "unknown",
        "로그 종류": _enum(event.get("log_kind"), frozenset({
            "job", "dbwrap", "debug", "info", "err",
        })),
        "시각 출처": _enum(event.get("time_date_source"), frozenset({
            "filename_hint", "reference_date", "unknown",
        })) or "미확인",
    }
    row.update(safe)
    # A SQL row and a Job row have separate duration units.
    return row


def _short_summary(kind: str | None, details: dict[str, Any]) -> str:
    keys = {
        "job_run": ("작업대상", "처리시간(초)"),
        "sql_execution": ("PSTMT 유형", "SQL 명령", "결과"),
        "log_error": ("예외 유형",),
        "healthcheck_result": ("헬스체크 동작",),
        "cns_response": ("응답 코드", "응답 의미"),
        "transport_event": ("통신 이벤트",),
        "job_running_skip": ("Job",),
        "scheduler_registration": ("Job",),
    }.get(kind, ())
    return " · ".join(f"{key}: {details[key]}" for key in keys
                      if details.get(key) is not None)[:180] or "구조화 세부값 없음"


def _matches(event: dict[str, Any], query: EventQuery,
             slow_rules: dict[str, Any] | None = None) -> bool:
    kind = event.get("event_type")
    if not isinstance(kind, str):
        return False
    if query.view == "jobs" and kind != "job_run":
        return False
    if query.view == "db" and kind != "sql_execution":
        return False
    if query.view == "signals" and kind not in SIGNAL_TYPES:
        return False
    if query.log_kind and event.get("log_kind") != query.log_kind:
        return False
    if query.event_type and kind != query.event_type:
        return False
    if query.file_id and event.get("file_id") != query.file_id:
        return False
    if query.status and event.get("status") != query.status:
        return False
    d = event.get("details")
    d = d if isinstance(d, dict) else {}
    if query.job_name and d.get("job_name") != query.job_name:
        return False
    observed = _safe_time(event.get("occurred_at"))
    if query.from_minute and (not observed or observed[:16] < query.from_minute):
        return False
    if query.to_minute and (not observed or observed[:16] > query.to_minute):
        return False
    if query.min_duration is not None:
        duration = d.get("laptime_ms") if query.view == "db" else d.get("duration_seconds")
        amount = _number(duration, 1_000_000_000)
        if amount is None or amount < query.min_duration:
            return False
    if query.slow_only:
        if not slow_rules:
            return False
        if query.view == "db":
            threshold = slow_rules["sql"]["absolute_ms"]
            elapsed = _number(d.get("laptime_ms"), 1_000_000_000)
        else:
            name = _code(d.get("job_name"), SAFE_JOB)
            threshold = slow_rules["job"]["absolute_seconds_by_job"].get(
                name, slow_rules["job"]["absolute_default_seconds"])
            elapsed = _number(d.get("duration_seconds"), 1_000_000_000)
        if elapsed is None or elapsed < threshold:
            return False
    return True


def _validate(query: EventQuery, page: int, page_size: int) -> None:
    if query.view not in DISPLAY_FIELDS or query.sort not in {
        "time_asc", "time_desc", "duration_desc",
    }:
        raise ValueError("지원하지 않는 조회 종류 또는 정렬입니다.")
    if type(page) is not int or page < 1 or page > 1000000 or page_size not in PAGE_SIZES:
        raise ValueError("조회 페이지 크기 또는 번호가 올바르지 않습니다.")
    if (type(query.slow_only) is not bool or
            query.slow_only and query.view not in ("jobs", "db")):
        raise ValueError("절대 기준 초과 필터는 Job·SQL에만 지원됩니다.")
    if query.sort == "duration_desc" and query.view not in ("jobs", "db"):
        raise ValueError("처리시간 정렬은 Job·SQL 상세 화면에서만 지원됩니다.")
    if query.log_kind and query.log_kind not in {"job", "dbwrap", "debug", "info", "err"}:
        raise ValueError("허용되지 않는 로그 종류입니다.")
    if query.event_type and query.event_type not in EVENT_NAMES:
        raise ValueError("허용되지 않는 이벤트 종류입니다.")
    if query.file_id and not SAFE_REF.fullmatch(query.file_id):
        raise ValueError("파일 식별자가 유효하지 않습니다.")
    if query.job_name and not SAFE_JOB.fullmatch(query.job_name):
        raise ValueError("Job 이름이 유효하지 않습니다.")
    if query.status and query.status not in STATES:
        raise ValueError("상태 값이 유효하지 않습니다.")
    for value in (query.from_minute, query.to_minute):
        if value is not None:
            if not SAFE_MINUTE.fullmatch(value):
                raise ValueError("시각은 YYYY-MM-DDTHH:MM 형식으로 입력하세요.")
            try:
                datetime.fromisoformat(value)
            except ValueError as exc:
                raise ValueError("유효한 날짜·시각을 입력하세요.") from exc
    if query.from_minute and query.to_minute and query.from_minute > query.to_minute:
        raise ValueError("시작 시각은 종료 시각보다 늦을 수 없습니다.")
    if query.min_duration is not None and _number(query.min_duration, 1_000_000_000) is None:
        raise ValueError("최소 처리시간이 유효하지 않습니다.")
    if query.sort != "time_asc" and page * page_size > MAX_RANKED_ROWS:
        raise ValueError("정렬 조회는 앞쪽 20,000건까지 제공됩니다. 시간·유형 필터를 좁혀 주세요.")


def _rank(event: dict[str, Any], query: EventQuery) -> tuple[Any, ...]:
    d = event.get("details") or {}
    if not isinstance(d, dict):
        d = {}
    moment = _safe_time(event.get("occurred_at")) or ""
    file_id = event.get("file_id") or ""
    line = event.get("line_start") or 0
    if query.sort == "duration_desc":
        raw_duration = (d.get("laptime_ms") if query.view == "db"
                        else d.get("duration_seconds") if event.get("event_type") == "job_run"
                        else d.get("laptime_ms"))
        duration = _number(raw_duration, 1_000_000_000)
        return (float(duration) if duration is not None else -1.0, moment, file_id, line)
    return (bool(moment), moment, file_id, line)


def query_events(case_dir, manifest: dict[str, Any], query: EventQuery,
                 *, page: int = 1, page_size: int = 50) -> dict[str, Any]:
    """Return full matching count and a bounded page; no silent occurrence cap.

    Ascending scan: O(page_size) memory. Latest/slowest: bounded top-N
    (limit 20,000); all events are still scanned for accurate totals.
    """
    _validate(query, page, page_size)
    start, stop = (page - 1) * page_size, page * page_size
    rows: list[dict[str, Any]] = []
    best: list[tuple[tuple[Any, ...], int, dict[str, Any]]] = []
    count = 0
    distribution: Counter[str] = Counter()
    exceptions: Counter[str] = Counter()
    slow_rules = None
    if query.slow_only:
        from .anomalies import load_rules
        slow_rules = load_rules()
    for event in events_iter(case_dir, manifest):
        if not _matches(event, query, slow_rules):
            continue
        count += 1
        event_type = event.get("event_type") or "unknown"
        if event_type in EVENT_NAMES:
            distribution[EVENT_NAMES[event_type]] += 1
        if event_type == "log_error":
            d = event.get("details") or {}
            if isinstance(d, dict):
                exception = _code(d.get("exception_class"), SAFE_ERROR)
                if exception:
                    exceptions[exception] += 1
        if query.sort == "time_asc":
            if start < count <= stop:
                rows.append(project_event(event, manifest))
            continue
        key = _rank(event, query)
        # Counter disambiguates otherwise equal timestamps and source positions.
        # Only project top-ranked candidates after scanning. This avoids
        # formatting hundreds of thousands of rows on every Streamlit rerun.
        ranked = (key, count, event)
        if len(best) < stop:
            heapq.heappush(best, ranked)
        elif key > best[0][0]:
            heapq.heapreplace(best, ranked)
    if query.sort != "time_asc":
        ordered = sorted(best, reverse=True)
        rows = [project_event(item[2], manifest) for item in ordered[start:stop]]
    return {
        "total": count,
        "page": page,
        "pages": max(1, (count + page_size - 1) // page_size),
        "page_size": page_size,
        "rows": rows,
        "by_type": dict(sorted(distribution.items())),
        "by_exception": dict(sorted(exceptions.items())),
        "is_truncated": False,
    }


def file_quality_rows(result: dict[str, Any], manifest: dict[str, Any]) -> list[dict[str, Any]]:
    """File-level quality, without treating non-event log lines as parse errors."""
    sources = {f.get("file_id"): f for f in manifest.get("files", [])}
    output = []
    for stats in (result.get("metrics") or {}).get("source_summary") or []:
        fid = stats.get("file_id")
        if fid not in sources:
            continue
        entry = sources[fid]
        output.append({
            "파일": file_label(fid, manifest),
            "종류": entry.get("kind"),
            "원본 완전성": {"full": "전체 제출", "partial": "일부 추출",
                          "unknown": "미확인"}.get(entry.get("completeness"), "미확인"),
            "읽은 줄": _number(stats.get("lines_read"), 1_000_000_000, decimal=0),
            "구조화 이벤트": _number(stats.get("events_extracted"), 1_000_000_000, decimal=0),
            "인코딩 대체 줄": _number(stats.get("decode_replacement_lines"), 1_000_000_000, decimal=0),
            "역순 시각": _number(stats.get("out_of_order_timestamps"), 1_000_000_000, decimal=0),
            "자정 경과 추정": _number(stats.get("midnight_rollovers"), 1_000_000_000, decimal=0),
        })
    return output
