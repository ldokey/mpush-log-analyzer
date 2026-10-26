"""Dispatch approved log kinds to a version-tolerant parser."""
from __future__ import annotations
from typing import Iterable, Iterator
from .common import RawEvent
from . import job, dbwrap, debug, info, err

PARSERS = {
    "job": job.parse,
    "dbwrap": dbwrap.parse,
    "debug": debug.parse,
    "info": info.parse,
    "err": err.parse,
}

def parse_by_kind(kind: str, lines: Iterable[tuple[int,str]]) -> Iterator[RawEvent]:
    handler = PARSERS.get(kind)
    if handler is None:
        return iter(())
    return handler(lines)
