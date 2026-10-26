"""Shared sanitized event representation and clock normalization."""
from __future__ import annotations
from dataclasses import dataclass
from datetime import date, datetime, time, timedelta
import re
from typing import Any

LOG_START = re.compile(r"^\s*(?P<h>[01]\d|2[0-3]):(?P<m>[0-5]\d):(?P<s>[0-5]\d)\[(?P<ms>\d{1,3})\]")
JOB_TOKEN = re.compile(r"^[A-Z][A-Z0-9_]{2,63}$")
MAX_RECORD_LINES = 2500

@dataclass(frozen=True)
class RawEvent:
    kind: str
    start_line: int
    end_line: int
    clock: str | None
    data: dict[str, Any]
    status: str = "observed"

def parse_clock(line: str) -> str | None:
    m = LOG_START.match(line)
    return f"{m['h']}:{m['m']}:{m['s']}.{m['ms'].ljust(3, '0')}" if m else None

def sanitized_job_token(raw: str | None) -> str | None:
    if raw and JOB_TOKEN.fullmatch(raw.upper()):
        return raw.upper()
    return None

def finite_float(text: str | None, max_value: float = 1e9) -> float | None:
    if not text or not re.fullmatch(r"\d{1,10}(?:\.\d{1,9})?", text.strip()):
        return None
    v = float(text.strip())
    return v if v <= max_value else None

class ClockResolver:
    """Only infer midnight for obvious 20:00-04:00 rollovers."""
    def __init__(self, anchor: date | None):
        self.current_date = anchor
        self.prev_ms: int | None = None
        self.rollovers = 0
        self.out_of_order = 0

    def normalize(self, clock: str | None) -> tuple[str | None, str]:
        if clock is None:
            return None, "missing"
        try:
            t = time.fromisoformat(clock)
        except ValueError:
            return None, "invalid"
        ms = (t.hour * 3600 + t.minute * 60 + t.second) * 1000 + t.microsecond // 1000
        if self.prev_ms is not None and ms < self.prev_ms:
            if self.prev_ms >= 20 * 3600 * 1000 and ms <= 4 * 3600 * 1000:
                self.rollovers += 1
                if self.current_date is not None:
                    self.current_date += timedelta(days=1)
            else:
                self.out_of_order += 1
        self.prev_ms = ms
        if self.current_date is None:
            return None, "clock_only"
        return datetime.combine(self.current_date, t).isoformat(timespec="milliseconds") + "+09:00", (
            "anchored" if self.rollovers == 0 else "midnight_inferred"
        )
