"""Parse info lifecycle, quartz registrations, and sanitized transport status."""
from __future__ import annotations
import re
from typing import Iterable, Iterator
from .common import RawEvent, parse_clock, sanitized_job_token
SCHEDULE = re.compile(r"\*?([A-Z][A-Z0-9_]{2,63})\s+은\s+(.{0,140}?)\s+으로 예약 되었습니다\.")
CRON = re.compile(r"^[\d*/?,\s-]{3,100}$")
EXCEPTION = re.compile(r"\b([A-Za-z_][\w.$]{0,90}(?:Exception|Error))\b")
LIFECYCLE = {
    "Agent Exited": "agent_exit",
    "Starting....": "agent_starting",
    "Config Loading": "agent_config_loading",
    "Started": "agent_started",
}
TRANSPORT = {
    "연결 되었습니다": "socket_connected",
    "서버로의 파일전송이 완료": "file_transfer_completed",
    "서버로 부터의 응답을 기다립니다": "awaiting_response",
    "파일전송 결과는 다음과 같습니다": "file_transfer_result_seen",
}

def parse(lines: Iterable[tuple[int,str]]) -> Iterator[RawEvent]:
    for number, text in lines:
        clock = parse_clock(text)
        if clock is None:
            continue
        lifecycle = next((name for marker, name in LIFECYCLE.items() if marker in text), None)
        if lifecycle:
            yield RawEvent(lifecycle, number, number, clock, {})
            continue
        if match := SCHEDULE.search(text):
            token = sanitized_job_token(match.group(1))
            if token is not None:
                cron = match.group(2).strip()
                yield RawEvent("scheduler_registration", number, number, clock, {
                    "job_name": token, "cron": cron if CRON.fullmatch(cron) else None
                })
            continue
        for marker, subtype in TRANSPORT.items():
            if marker in text:
                yield RawEvent("transport_event", number, number, clock, {"state": subtype})
                break
        else:
            match = EXCEPTION.search(text)
            if match or re.search(r"\bERROR\b", text, re.I):
                suffix = match.group(1).rsplit(".", 1)[-1] if match else "unspecified"
                clean = suffix if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{1,55}", suffix) else "unspecified"
                yield RawEvent("log_error", number, number, clock, {"exception_class": clean})
