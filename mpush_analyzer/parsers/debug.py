"""Recognize debug status/response events while discarding raw payload/keys."""
from __future__ import annotations
import re
from typing import Iterable, Iterator
from .common import RawEvent, parse_clock, sanitized_job_token

RESPONSE = re.compile(r"""['"]?RESPONSE_CODE['"]?\s*:\s*['"]?([A-Z0-9_-]{1,20})""", re.I)
TARGET = re.compile(r"""['"]?TARGET['"]?\s*:\s*['"]?([A-Za-z_]{1,30})""", re.I)
RUNNING = re.compile(r"RUNNING state\s*::\s*([A-Z0-9_]{3,64})", re.I)
EXCEPTION = re.compile(r"\b([A-Za-z_][\w.$]{0,90}(?:Exception|Error))\b")

def _exception_kind(text: str) -> str:
    found = EXCEPTION.search(text)
    if not found:
        return "unspecified"
    result = found.group(1).rsplit(".", 1)[-1]
    return result if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{1,55}", result) else "unspecified"

def parse(lines: Iterable[tuple[int,str]]) -> Iterator[RawEvent]:
    for number, text in lines:
        clock = parse_clock(text)
        if clock is None:
            continue
        if "헬스 체크 결과" in text:
            match = TARGET.search(text)
            normalized = match.group(1).lower() if match else ""
            state = "no_action" if normalized == "nothing" else (
                "shutdown_requested" if normalized == "shutdown" else "unknown"
            )
            yield RawEvent("healthcheck_result", number, number, clock, {"target_action": state})
        elif "헬스 체크 서비스 번호" in text:
            yield RawEvent("healthcheck_request", number, number, clock, {})
        elif "서버에서 받은 문자열" in text and (match := RESPONSE.search(text)):
            code = match.group(1).upper()
            yield RawEvent("cns_response", number, number, clock, {
                "response_code": code,
                "interpretation": "request_accepted" if code == "S" else "other_response",
                "final_delivery_confirmed": False,
            })
        elif "Can't execute task in RUNNING state" in text:
            match = RUNNING.search(text)
            yield RawEvent("job_running_skip", number, number, clock, {
                "job_name": sanitized_job_token(match.group(1)) if match else None
            })
        elif EXCEPTION.search(text) or re.search(r"\bERROR\b", text, re.I):
            yield RawEvent("log_error", number, number, clock, {
                "exception_class": _exception_kind(text)
            })
