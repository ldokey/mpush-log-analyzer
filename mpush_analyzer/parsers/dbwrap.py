"""dbwrap SQL execution parser; NO_ID and SQL text are never persisted."""
from __future__ import annotations
import re
from typing import Iterable, Iterator
from .common import MAX_RECORD_LINES, RawEvent, finite_float, parse_clock

HEADER = re.compile(r"PSTMT\.(EQ|EU|EB|[A-Z]{1,4})\s+Laptime\s*:\s*(\d{1,10}(?:\.\d+)?)", re.I)
RESULT = re.compile(r"Result\s*:\s*([^\r\n]{0,180})", re.I)
SQL_OP = re.compile(r"^(?:NO_ID_-?\d+=)*\s*(SELECT|INSERT|UPDATE|DELETE|MERGE|WITH|CALL)\b", re.I)
ROWS = re.compile(r"\b(\d{1,10})\s+row\(s\)\s+(?:updated|inserted|deleted)\b", re.I)

def _result_kind(text: str | None) -> tuple[str, int | None]:
    if not text:
        return "unknown", None
    norm = text.lower()
    if "select completed" in norm:
        return "select_completed", None
    if "batch job success" in norm:
        return "batch_success", None
    if rows := ROWS.search(text):
        return "rows_affected", int(rows.group(1))
    if any(word in norm for word in ("failed", "exception", "error", "rollback")):
        return "failed", None
    return "unknown", None

def _event(block: list[tuple[int,str]], head: re.Match[str], stamp: str | None, forced_incomplete: bool = False) -> RawEvent:
    operation = "UNKNOWN"
    result: str | None = None
    for _, line in block:
        if result is None and (found := RESULT.search(line)):
            result = found.group(1)
        if operation == "UNKNOWN" and (found_op := SQL_OP.search(line)):
            operation = found_op.group(1).upper()
    outcome, affected = _result_kind(result)
    laptime = finite_float(head.group(2), max_value=1e10)
    complete = not forced_incomplete and outcome != "unknown" and laptime is not None
    return RawEvent(
        kind="sql_execution",
        start_line=block[0][0], end_line=block[-1][0], clock=stamp,
        status="complete" if complete else "incomplete",
        data={"statement_kind": head.group(1).upper(), "sql_operation": operation,
              "laptime_ms": laptime, "outcome": outcome,
              "affected_rows": affected, "completed": complete}
    )

def parse(lines: Iterable[tuple[int,str]]) -> Iterator[RawEvent]:
    pending_clock: str | None = None
    pending_line: int | None = None
    active: list[tuple[int,str]] = []
    active_header: re.Match[str] | None = None
    active_stamp: str | None = None
    for number, line in lines:
        clock = parse_clock(line)
        header = HEADER.search(line)
        if header:
            if active_header and active:
                yield _event(active, active_header, active_stamp)
            active_header = header
            active_stamp = pending_clock or clock
            active = [(pending_line, "")] if pending_line is not None else []
            active.append((number, line))
            pending_line, pending_clock = None, None
            continue
        if active_header is not None:
            if clock:
                yield _event(active, active_header, active_stamp)
                active, active_header, active_stamp = [], None, None
                pending_clock, pending_line = clock, number
                continue
            active.append((number, line))
            if len(active) >= MAX_RECORD_LINES:
                yield _event(active, active_header, active_stamp, forced_incomplete=True)
                active, active_header, active_stamp = [], None, None
            continue
        if clock:
            pending_clock, pending_line = clock, number
    if active_header and active:
        yield _event(active, active_header, active_stamp)
