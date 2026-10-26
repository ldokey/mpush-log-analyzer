"""MPushAgent multiline Job execution summary parser, no raw payload retention."""
from __future__ import annotations
import re
from typing import Iterable, Iterator
from .common import MAX_RECORD_LINES, RawEvent, finite_float, parse_clock, sanitized_job_token

JOB_HEADER = re.compile(r"^\s*##\s+([A-Za-z0-9_]{3,64})\s+작업\s*$")
METRIC = re.compile(r"##\s*(.+?)\s*:\s*(.*?)\s*$")
TIMED_NUMBER = re.compile(r"(\d{1,10}(?:\.\d{1,9})?)\s*초")
TARGET_NUMBER = re.compile(r"(\d{1,10})")
TIMESTAMP_ONLY = re.compile(r"^\s*\d{2}:\d{2}:\d{2}\[\d{1,3}\]\s*$")
KOREAN_TIME = re.compile(r"(?P<h>\d{1,2})시\s*(?P<m>\d{1,2})분\s*(?P<s>\d{1,2})(?:\.(?P<ms>\d{1,3}))?초")
LIFECYCLE = {
    "Agent Exited": "agent_exit",
    "Config Loading": "agent_config_loading",
    "Starting....": "agent_starting",
    "Started": "agent_started",
}
STEP_NAMES = {"SELECT": "select", "FILE": "file", "SOCKET": "socket",
              "HTTP IN": "http_in", "HTTP OUT": "http_out", "DB": "db"}

def _clock_korean(text: str | None) -> str | None:
    if not text:
        return None
    m = KOREAN_TIME.search(text)
    if not m:
        return None
    h, mi, s = int(m["h"]), int(m["m"]), int(m["s"])
    if h > 23 or mi > 59 or s > 59:
        return None
    return f"{h:02}:{mi:02}:{s:02}.{(m['ms'] or '0').ljust(3, '0')}"

def _tps(text: str) -> float | None:
    match = re.match(r"\s*([0-9]+(?:\.[0-9]+)?)", text)
    return finite_float(match.group(1)) if match else None


def _summary(lines: list[tuple[int,str]], job_name: str, stamp: str | None, forced_incomplete: bool = False) -> RawEvent:
    pairs: dict[str, str] = {}
    steps: dict[str, float] = {}
    for _, text in lines:
        m = METRIC.search(text)
        if not m:
            continue
        key, value = m.group(1).strip(), m.group(2).strip()
        if key in {"작업대상건수", "시작시간", "종료시간", "초당 작업 건수"}:
            pairs[key] = value
        elif "소요시간" in key and "초당" not in key:
            pairs["total"] = value
        else:
            for source, dest in STEP_NAMES.items():
                if key.startswith(source + " 시간"):
                    if match := TIMED_NUMBER.search(value):
                        if (duration := finite_float(match.group(1))) is not None:
                            steps[dest] = duration
    match_count = TARGET_NUMBER.search(pairs.get("작업대상건수", ""))
    target_count = int(match_count.group(1)) if match_count else None
    if target_count is not None and target_count > 1_000_000_000:
        target_count = None
    duration_match = TIMED_NUMBER.search(pairs.get("total", ""))
    duration = finite_float(duration_match.group(1)) if duration_match else None
    start_clock = _clock_korean(pairs.get("시작시간"))
    end_clock = _clock_korean(pairs.get("종료시간"))
    if end_clock is None:
        for _, line in reversed(lines):
            if found := parse_clock(line):
                end_clock = found
                break
    end_clock = end_clock or stamp
    complete = not forced_incomplete and duration is not None and target_count is not None and end_clock is not None
    return RawEvent(
        kind="job_run", start_line=lines[0][0], end_line=lines[-1][0],
        clock=end_clock, status="complete" if complete else "incomplete",
        data={"job_name": job_name, "target_count": target_count, "duration_seconds": duration,
              "steps_seconds": steps, "start_clock": start_clock, "end_clock": end_clock,
              "reported_tps": _tps(pairs.get("초당 작업 건수", "")),
              "completed": complete}
    )

def parse(lines: Iterable[tuple[int,str]]) -> Iterator[RawEvent]:
    active: list[tuple[int,str]] = []
    job_name: str | None = None
    recent_stamp: str | None = None
    for number, line in lines:
        clock = parse_clock(line)
        match = JOB_HEADER.match(line)
        if match:
            if job_name and active:
                yield _summary(active, job_name, recent_stamp)
            job_name = sanitized_job_token(match.group(1))
            active = [(number, line)] if job_name is not None else []
            continue
        if job_name is not None:
            if clock and TIMESTAMP_ONLY.fullmatch(line):
                yield _summary(active, job_name, recent_stamp)
                job_name, active = None, []
                recent_stamp = clock
                continue
            if clock and any(marker in line for marker in LIFECYCLE):
                if active:
                    yield _summary(active, job_name, recent_stamp)
                job_name, active = None, []
            else:
                active.append((number, line))
                if len(active) >= MAX_RECORD_LINES:
                    yield _summary(active, job_name, recent_stamp, forced_incomplete=True)
                    job_name, active = None, []
                continue
        if clock:
            recent_stamp = clock
            for marker, kind in LIFECYCLE.items():
                if marker in line:
                    yield RawEvent(kind=kind, start_line=number, end_line=number, clock=clock, data={})
                    break
    if job_name is not None and active:
        yield _summary(active, job_name, recent_stamp)
