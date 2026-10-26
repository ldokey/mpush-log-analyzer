"""Group err.log records and stack traces; never copy exception messages/frames."""
from __future__ import annotations
import re
from typing import Iterable, Iterator
from .common import MAX_RECORD_LINES, RawEvent, parse_clock
EXCEPTION = re.compile(r"\b([A-Za-z_][\w.$]{0,90}(?:Exception|Error))\b")
FRAME = re.compile(r"^\s*(?:at\s+[\w.$<>]+\(|\.\.\.\s+\d+\s+more|Caused by\s*:)")

def _event(block: list[tuple[int,str]], clock: str | None, forced_incomplete: bool = False) -> RawEvent:
    suffix = "unspecified"
    for _, line in block:
        match = EXCEPTION.search(line)
        if match:
            tail = match.group(1).rsplit(".", 1)[-1]
            if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{1,55}", tail):
                suffix = tail
                break
    frames = sum(1 for _, line in block if FRAME.search(line))
    return RawEvent(
        kind="log_error", start_line=block[0][0], end_line=block[-1][0],
        clock=clock, status="incomplete" if forced_incomplete else "observed",
        data={"exception_class": suffix, "stack_frame_count": frames}
    )

def parse(lines: Iterable[tuple[int,str]]) -> Iterator[RawEvent]:
    block: list[tuple[int,str]] = []
    stamp: str | None = None
    for number, line in lines:
        clock = parse_clock(line)
        if clock is not None and block:
            yield _event(block, stamp)
            block = []
        if not block and not line.strip():
            continue
        if clock is not None:
            stamp = clock
        block.append((number, line))
        if len(block) >= MAX_RECORD_LINES:
            yield _event(block, stamp, forced_incomplete=True)
            block = []
            stamp = None
    if block:
        yield _event(block, stamp)
