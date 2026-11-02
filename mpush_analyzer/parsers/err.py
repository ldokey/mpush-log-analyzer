"""One exception stack per event; preserve explicit cause/suppressed links only."""
from __future__ import annotations
from typing import Iterable, Iterator
from .common import MAX_RECORD_LINES, RawEvent, parse_clock
from ..exception_chain import chain_details, continuation, has_exception, CLASS


def _event(block: list[tuple[int,str]], clock: str | None, forced_incomplete: bool = False) -> RawEvent:
    return RawEvent('log_error', block[0][0], block[-1][0], clock,
                    chain_details(block, incomplete=forced_incomplete),
                    'incomplete' if forced_incomplete else 'observed')


def parse(lines: Iterable[tuple[int,str]]) -> Iterator[RawEvent]:
    block: list[tuple[int,str]] = []; stamp = None
    for number, line in lines:
        clock = parse_clock(line)
        # Explicit Caused by / Suppressed / frame lines with a repeated same
        # timestamp are part of the current stack, not extra error incidents.
        attached = bool(block and continuation(line) and (clock is None or clock == stamp))
        new_root = bool(block and CLASS.search(line) and not continuation(line)
                        and any(CLASS.search(text) for _,text in block))
        if block and ((clock is not None and not attached) or new_root):
            yield _event(block, stamp)
            block = []; stamp = None
        if not block and not line.strip(): continue
        if not block and clock is not None: stamp = clock
        block.append((number,line))
        if len(block) >= MAX_RECORD_LINES:
            yield _event(block, stamp, True)
            block = []; stamp = None
    if block: yield _event(block, stamp)
