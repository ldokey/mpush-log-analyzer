"""Read-only Stage-2 pipeline: hash checks, sanitized event JSONL, summaries.

No SQL text, transport payload, identifiers, credentials or raw exception lines
are written to derived event files. Source files remain unchanged.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from datetime import date
import hashlib
import heapq
import json
import os
from pathlib import Path
import re
import tempfile
from typing import Any, Iterator

from jsonschema import Draft202012Validator, FormatChecker

from .case_contract import load_schema
from .parsers import parse_by_kind
from .parsers.common import ClockResolver

INPUT_NAME = re.compile(r"^[a-z0-9_]+\.(?:log|txt|ini)$")
CASE_NAME = re.compile(r"^analysis_[a-f0-9]{32}$")
CHUNK_SIZE = 10000
MERGE_FAN_IN = 24


def _safe_source(case_dir: Path, entry: dict[str, Any]) -> Path:
    name = entry["storage_name"]
    if not INPUT_NAME.fullmatch(name):
        raise ValueError("보안 검사 실패: 저장 파일명이 유효하지 않습니다.")
    raw_dir = case_dir / "raw"
    if raw_dir.is_symlink() or not raw_dir.is_dir():
        raise ValueError("보안 검사 실패: 원본 디렉터리가 유효하지 않습니다.")
    result = raw_dir / name
    if result.is_symlink() or not result.is_file():
        raise ValueError("보안 검사 실패: 원본 로그가 없거나 심볼릭 링크입니다.")
    if result.stat().st_size != entry["size_bytes"]:
        raise ValueError("원본 로그 크기가 수집 당시와 다릅니다.")
    digest = hashlib.sha256()
    with result.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    if digest.hexdigest() != entry["content_sha256"]:
        raise ValueError("원본 로그 해시가 수집 당시와 다릅니다.")
    return result


def _get_manifest(case_dir: Path) -> dict[str, Any]:
    if case_dir.is_symlink() or not case_dir.is_dir() or not CASE_NAME.fullmatch(case_dir.name):
        raise ValueError("유효하지 않은 분석 작업 디렉터리입니다.")
    source = case_dir / "manifest.json"
    if source.is_symlink() or not source.is_file():
        raise ValueError("분석 작업 메타데이터가 없습니다.")
    manifest = json.loads(source.read_text(encoding="utf-8"))
    Draft202012Validator(load_schema("manifest.schema.json"), format_checker=FormatChecker()).validate(manifest)
    if manifest["analysis_id"] != case_dir.name:
        raise ValueError("분석 ID와 저장 경로가 일치하지 않습니다.")
    for entry in manifest["files"]:
        _safe_source(case_dir, entry)  # preflight all inputs BEFORE output write
    return manifest


def _read_numbered(path: Path, encoding: str, stats: dict[str, int]) -> Iterator[tuple[int, str]]:
    # Invalid sequences are replaced and counted, never embedded in output.
    with path.open("r", encoding=encoding, errors="replace", newline=None) as stream:
        for number, line in enumerate(stream, 1):
            stats["lines_read"] += 1
            if "\ufffd" in line:
                stats["decode_replacement_lines"] += 1
            if len(line) > 16384:
                stats["oversized_lines"] += 1
                line = line[:16384]
            yield number, line.rstrip("\r\n")


def _sort_key(event: dict[str, Any]) -> tuple[Any, ...]:
    stamp = event["occurred_at"]
    return (0, stamp, event["file_id"], event["line_start"]) if stamp is not None else (
        1, event["clock"] or "", event["file_id"], event["line_start"]
    )


def _write_jsonlines(path: Path, events: list[dict[str, Any]]) -> None:
    with path.open("x", encoding="utf-8") as stream:
        os.fchmod(stream.fileno(), 0o600)
        for event in events:
            stream.write(json.dumps(event, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n")


def _read_jsonlines(path: Path) -> Iterator[dict[str, Any]]:
    with path.open("r", encoding="utf-8") as stream:
        for line in stream:
            yield json.loads(line)


def _merge_many(paths: list[Path], output: Path) -> None:
    iterators = [_read_jsonlines(p) for p in paths]
    with output.open("x", encoding="utf-8") as stream:
        os.fchmod(stream.fileno(), 0o600)
        for event in heapq.merge(*iterators, key=_sort_key):
            stream.write(json.dumps(event, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n")
    for generator in iterators:
        generator.close()


def _merged_chunks(source_chunks: list[Path], temp_dir: Path) -> Path:
    if not source_chunks:
        path = temp_dir / "empty.jsonl"
        _write_jsonlines(path, [])
        return path
    rounds = 0
    chunks = source_chunks
    while len(chunks) > 1:
        output_chunks: list[Path] = []
        for begin in range(0, len(chunks), MERGE_FAN_IN):
            group = chunks[begin : begin + MERGE_FAN_IN]
            out = temp_dir / f"merge_{rounds:02d}_{len(output_chunks):05d}.jsonl"
            _merge_many(group, out)
            output_chunks.append(out)
        for source in chunks:
            source.unlink()
        chunks = output_chunks
        rounds += 1
    return chunks[0]


def _atomic_json(path: Path, payload: dict[str, Any]) -> None:
    """Create a fresh private staging file and atomically replace only the target."""
    if path.is_symlink() or path.parent.is_symlink():
        raise ValueError("출력 경로는 심볼릭 링크를 허용하지 않습니다.")
    fd, staging_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".pending", dir=path.parent
    )
    staging = Path(staging_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            os.fchmod(stream.fileno(), 0o600)
            json.dump(payload, stream, ensure_ascii=False, sort_keys=True, indent=2)
            stream.write("\n")
        os.replace(staging, path)
    finally:
        if staging.exists():
            staging.unlink()


def _empty_metric() -> dict[str, Any]:
    return {
        "runs": 0, "completed": 0, "incomplete": 0,
        "target_count_total": 0, "max_duration_seconds": None
    }


def _update_metrics(metrics: dict[str, Any], event: dict[str, Any]) -> None:
    metrics["events_total"] += 1
    kind = event["event_type"]
    metrics["event_counts"][kind] += 1
    details = event["details"]
    if kind == "job_run":
        name = details["job_name"]
        x = metrics["job_runs"].setdefault(name, _empty_metric())
        x["runs"] += 1
        x["completed" if details["completed"] else "incomplete"] += 1
        if details["completed"]:
            x["target_count_total"] += details["target_count"]
            d = details["duration_seconds"]
            if x["max_duration_seconds"] is None or d > x["max_duration_seconds"]:
                x["max_duration_seconds"] = d
    elif kind == "sql_execution":
        x = metrics["db_executions"]
        x["runs"] += 1
        x["by_statement"][details["statement_kind"]] += 1
        x["by_outcome"][details["outcome"]] += 1
        if not details["completed"]:
            x["incomplete"] += 1
        ms = details["laptime_ms"]
        if ms is not None and (x["max_laptime_ms"] is None or ms > x["max_laptime_ms"]):
            x["max_laptime_ms"] = ms
    elif kind == "cns_response":
        metrics["cns_request_responses"][details["response_code"]] += 1
    if event["occurred_at"] is None:
        metrics["undated_events"] += 1
    if event["status"] == "incomplete":
        metrics["incomplete_events"] += 1


def analyze_case(case_dir: Path) -> dict[str, Any]:
    """Generate sorted events.jsonl + schema-valid analysis_result.json for existing case.

    All source SHA256 values are validated first; CLI or UI never alters originals.
    """
    manifest = _get_manifest(case_dir)
    metrics: dict[str, Any] = {
        "events_total": 0,
        "event_counts": Counter(),
        "job_runs": {},
        "db_executions": {
            "runs": 0, "incomplete": 0, "max_laptime_ms": None,
            "by_statement": Counter(), "by_outcome": Counter(),
        },
        "cns_request_responses": Counter(),
        "undated_events": 0,
        "incomplete_events": 0,
        "source_summary": [],
    }
    limitations: list[str] = [
        "2단계는 로그에서 관측된 이벤트만 추출하며, 장애 원인이나 최종 수신자 배송 성공을 판정하지 않습니다.",
        "동일 Agent의 로그인지 파일 간 인스턴스 동일성은 아직 자동 검증되지 않습니다.",
    ]
    incomplete_sources = False
    if not manifest.get("collected_at"):
        limitations.append("로그 수집 시각이 제공되지 않아 마지막 기록 이후 프로세스 상태를 판단할 수 없습니다.")
    else:
        limitations.append("로그 수집 시각은 메타데이터이며, 로그 공백을 프로세스 중단으로 단정할 수 없습니다.")

    result: dict[str, Any]
    with tempfile.TemporaryDirectory(prefix=".stage2_", dir=case_dir) as temp_name:
        temp_dir = Path(temp_name)
        os.chmod(temp_dir, 0o700)
        chunks: list[Path] = []
        batch: list[dict[str, Any]] = []

        def flush_batch() -> None:
            if batch:
                batch.sort(key=_sort_key)
                out = temp_dir / f"chunk_{len(chunks):06d}.jsonl"
                _write_jsonlines(out, batch)
                chunks.append(out)
                batch.clear()

        for source in manifest["files"]:
            file_stats = {"lines_read": 0, "decode_replacement_lines": 0, "oversized_lines": 0}
            if source["completeness"] != "full":
                incomplete_sources = True
            if source["completeness"] == "partial":
                limitations.append(f"{source['file_id']}: 일부 추출 로그여서 전체 기록을 대표하지 않습니다.")
            elif source["completeness"] == "unknown":
                limitations.append(f"{source['file_id']}: 로그 원본 완전성이 확인되지 않았습니다.")

            if source["kind"] in {"agent_ini", "unknown"}:
                if source["kind"] == "unknown":
                    incomplete_sources = True
                    limitations.append(f"{source['file_id']}: 지원되지 않는 로그 유형이라 이벤트를 추출하지 않았습니다.")
                continue

            anchor = None
            if source["date_hint"]:
                anchor = date.fromisoformat(source["date_hint"])
            elif manifest["reference_date"]:
                anchor = date.fromisoformat(manifest["reference_date"])
            clock_resolver = ClockResolver(anchor)
            parsed_events = 0
            origin = _safe_source(case_dir, source)
            codec = "utf-8" if source["encoding"] == "utf-8-replace" else source["encoding"]
            for raw in parse_by_kind(source["kind"], _read_numbered(origin, codec, file_stats)):
                parsed_events += 1
                occurred_at, quality = clock_resolver.normalize(raw.clock)
                entry = {
                    "schema_version": "1.0",
                    "event_id": f"{source['file_id']}_{raw.start_line:09d}",
                    "file_id": source["file_id"],
                    "log_kind": source["kind"],
                    "line_start": raw.start_line,
                    "line_end": raw.end_line,
                    "clock": raw.clock,
                    "occurred_at": occurred_at,
                    "time_quality": quality,
                    "event_type": raw.kind,
                    "status": raw.status,
                    "details": raw.data,
                }
                _update_metrics(metrics, entry)
                batch.append(entry)
                if len(batch) >= CHUNK_SIZE:
                    flush_batch()
            _safe_source(case_dir, source)  # detect changes during parsing
            if file_stats["lines_read"] != source["line_count"]:
                limitations.append(f"{source['file_id']}: 수집 시점과 현재의 로그 줄 수가 일치하지 않습니다.")
                incomplete_sources = True
            if file_stats["decode_replacement_lines"]:
                limitations.append(f"{source['file_id']}: 인코딩 변환 손실이 관측되어 일부 이벤트 누락 가능성이 있습니다.")
                incomplete_sources = True
            if file_stats["oversized_lines"]:
                limitations.append(f"{source['file_id']}: 매우 긴 줄이 축약되어 일부 이벤트 누락 가능성이 있습니다.")
                incomplete_sources = True
            if clock_resolver.out_of_order:
                limitations.append(f"{source['file_id']}: 비단조 로그 시각이 관측되어 시간순 정렬 해석에 주의해야 합니다.")
                incomplete_sources = True
            if clock_resolver.rollovers:
                limitations.append(f"{source['file_id']}: 자정 경과를 로그 시각에서 추론했습니다.")
            if anchor is None:
                limitations.append(f"{source['file_id']}: 기준 날짜가 없어서 시각만 기록했습니다.")
                incomplete_sources = True
            if parsed_events == 0 and file_stats["lines_read"] > 0:
                limitations.append(f"{source['file_id']}: 알려진 이벤트 패턴이 검출되지 않았습니다.")
                incomplete_sources = True
            metrics["source_summary"].append({
                "file_id": source["file_id"],
                "kind": source["kind"],
                "lines_read": file_stats["lines_read"],
                "events_extracted": parsed_events,
                "midnight_rollovers": clock_resolver.rollovers,
                "out_of_order_timestamps": clock_resolver.out_of_order,
                "decode_replacement_lines": file_stats["decode_replacement_lines"],
            })

        if not metrics["source_summary"]:
            limitations.append("분석 가능한 로그 파일이 제공되지 않아 이벤트를 추출하지 않았습니다.")
            incomplete_sources = True
        flush_batch()
        sorted_chunks = _merged_chunks(chunks, temp_dir)
        pending_events = case_dir / "events.jsonl.pending"
        if pending_events.is_symlink():
            raise ValueError("출력 경로가 심볼릭 링크입니다.")
        # TemporaryDirectory is private; replacing an existing safe file is atomic.
        sorted_chunks.replace(pending_events)
        os.chmod(pending_events, 0o600)

        result = {
            "schema_version": "1.0",
            "analysis_id": manifest["analysis_id"],
            "analysis_status": (
                "partial" if incomplete_sources or metrics["incomplete_events"] > 0 else "complete"
            ),
            "metrics": metrics,
            "findings": [],  # Stage-3 anomaly engine owns findings.
            "limitations": limitations,
        }
        Draft202012Validator(load_schema("analysis_result.schema.json"), format_checker=FormatChecker()).validate(result)
        pending_json = case_dir / "analysis_result.json.pending"
        if pending_json.is_symlink():
            raise ValueError("출력 임시 경로가 심볼릭 링크입니다.")
        with pending_json.open("w", encoding="utf-8") as stream:
            os.fchmod(stream.fileno(), 0o600)
            json.dump(result, stream, ensure_ascii=False, indent=2, sort_keys=True)
            stream.write("\n")
        pending_events.replace(case_dir / "events.jsonl")
        pending_json.replace(case_dir / "analysis_result.json")
    return result
