"""Safe temporal context for parsed Job execution records.

The Job timestamp on the log summary refers to the completion time.
Duration-derived starts are estimates and must never be presented as raw facts.
"""
from __future__ import annotations
from datetime import datetime, time, timedelta
import re
from typing import Any


def job_time_fields(occurred_at: str | None, details: dict[str, Any]) -> dict[str, Any]:
    """Return additive, explicit time provenance without overwriting original fields."""
    start_clock = details.get("start_clock")
    duration = details.get("duration_seconds")
    outcome: dict[str, Any] = {
        "start_at": None,
        "calculated_start_at": None,
        "start_time_quality": "unavailable",
        "start_clock_consistent": None,
    }
    if not isinstance(occurred_at, str) or not isinstance(duration, (float, int)) or isinstance(duration, bool):
        if isinstance(start_clock, str):
            outcome["start_time_quality"] = "clock_only"
        return outcome
    if not 0 <= duration <= 86400 * 14:
        return outcome
    try:
        end_at = datetime.fromisoformat(occurred_at)
    except ValueError:
        return outcome
    inferred = end_at - timedelta(seconds=duration)
    outcome["calculated_start_at"] = inferred.isoformat(timespec="milliseconds")
    outcome["start_time_quality"] = "duration_calculated"
    if isinstance(start_clock, str) and re.fullmatch(r"\d{2}:\d{2}:\d{2}\.\d{3}", start_clock):
        try:
            indicated = time.fromisoformat(start_clock)
        except ValueError:
            return outcome
        actual = end_at.replace(hour=indicated.hour, minute=indicated.minute,
                                second=indicated.second, microsecond=indicated.microsecond)
        if actual > end_at + timedelta(seconds=1):
            actual -= timedelta(days=1)
        # Log start clocks may be rounded to whole seconds.
        difference = abs((inferred - actual).total_seconds())
        outcome["start_clock_consistent"] = difference <= 1.5
        if difference <= 1.5:
            outcome["start_at"] = actual.isoformat(timespec="milliseconds")
        if difference > 1.5:
            outcome["start_time_quality"] = "duration_clock_conflict"
    return outcome
