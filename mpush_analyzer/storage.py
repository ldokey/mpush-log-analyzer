"""Local-only private stage-1 intake storage. No original customer names in JSON."""
from __future__ import annotations
from .permissions import private_fd, private_path

from collections import defaultdict
from datetime import date, datetime
import json
import os
from pathlib import Path
from typing import Any
from uuid import uuid4
from zoneinfo import ZoneInfo

from jsonschema import Draft202012Validator, FormatChecker

from .case_contract import load_schema
from .config_ini import parse_agent_ini
from .intake import Inspected, decode_upload

TIMEZONE = ZoneInfo("Asia/Seoul")
AGENT_VERSIONS = {"auto", "3.2", "3.3"}


def _format_collected_at(raw: str | None) -> str | None:
    if not raw:
        return None
    try:
        dt = datetime.fromisoformat(raw)
    except ValueError:
        raise ValueError("로그 수집 시각을 ISO 날짜/시간으로 입력해 주세요.") from None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=TIMEZONE)
    return dt.astimezone(TIMEZONE).isoformat()


def save_intake(
    inspected: list[Inspected],
    workspace_root: Path,
    *,
    agent_version: str = "auto",
    reference_date: date | None = None,
    collected_at: str | None = None,
) -> tuple[Path, dict[str, Any]]:
    if not inspected:
        raise ValueError("분석할 입력 파일이 없습니다.")
    if agent_version not in AGENT_VERSIONS:
        raise ValueError("지원되지 않는 Agent 버전입니다.")
    if workspace_root.is_symlink():
        raise ValueError("심볼릭 링크 작업 폴더는 허용되지 않습니다.")

    accepted = [item for item in inspected if item.duplicate_of is None]
    ini_files = [item for item in accepted if item.kind == "agent_ini"]
    if len(ini_files) > 1:
        raise ValueError("하나의 분석 작업에는 agent.ini를 하나만 사용할 수 있습니다.")
    if ini_files and len(ini_files[0].upload.content) > 2 * 1024 * 1024:
        raise ValueError("agent.ini 파일은 최대 2MiB까지만 지원합니다.")
    cfg = None
    if ini_files:
        text, _ = decode_upload(ini_files[0].upload.content)
        cfg = parse_agent_ini(text)

    counts: dict[str, int] = defaultdict(int)
    files: list[dict[str, Any]] = []
    planned: list[tuple[str, bytes]] = []
    warnings: list[str] = []
    for item in inspected:
        for reason in item.warnings:
            if len(warnings) < 60 and reason not in warnings:
                warnings.append(reason)
        if item.duplicate_of is not None:
            continue
        counts[item.kind] += 1
        suffix = ".ini" if item.kind == "agent_ini" else (
            ".txt" if item.label.lower().endswith(".txt") else ".log"
        )
        storage_name = f"{item.kind}_{counts[item.kind]:02d}{suffix}"
        planned.append((storage_name, item.upload.content))
        files.append({
            "file_id": f"file_{len(files) + 1:02d}",
            "storage_name": storage_name,
            "kind": item.kind,
            "content_sha256": item.sha256,
            "size_bytes": item.size_bytes,
            "completeness": item.upload.completeness,
            "date_hint": item.date_hint,
            "first_time_hint": item.first_time_hint,
            "last_time_hint": item.last_time_hint,
            "line_count": item.line_count,
            "encoding": item.encoding,
            "confidence": item.confidence,
            "status": "unclassified" if item.kind == "unknown" else "accepted",
        })
    if not files:
        raise ValueError("중복이 아닌 유효한 입력 파일이 없습니다.")
    if cfg:
        warnings.extend(cfg.get("warnings", []))
    # Stage 1 cannot prove that all individual logs came from the same Agent.
    warnings.append("1단계에서는 서로 다른 Agent 로그의 혼합 여부를 확정할 수 없습니다. 동일 인스턴스 자료인지 확인이 필요합니다.")
    manifest: dict[str, Any] = {
        "schema_version": "1.0",
        "analysis_id": f"analysis_{uuid4().hex}",
        "created_at": datetime.now(tz=TIMEZONE).isoformat(),
        "timezone": "Asia/Seoul",
        "phase": "intake",
        "agent_version": agent_version,
        "reference_date": reference_date.isoformat() if reference_date else None,
        "collected_at": _format_collected_at(collected_at),
        "files": files,
        "config_summary": cfg,
        "warnings": warnings[:60],
    }
    Draft202012Validator(
        load_schema("manifest.schema.json"), format_checker=FormatChecker()
    ).validate(manifest)

    # User-provided paths are never used for filenames, and workspace is not linked.
    workspace_root.mkdir(mode=0o700, parents=True, exist_ok=True)
    private_path(workspace_root, directory=True)
    case_dir = workspace_root / manifest["analysis_id"]
    case_dir.mkdir(mode=0o700)
    raw_dir = case_dir / "raw"
    raw_dir.mkdir(mode=0o700)
    try:
        for storage_name, data in planned:
            dest = raw_dir / storage_name
            with dest.open("xb") as stream:
                private_fd(stream.fileno())
                stream.write(data)
        with (case_dir / "manifest.json").open("x", encoding="utf-8") as stream:
            private_fd(stream.fileno())
            json.dump(manifest, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
    except Exception:
        # Only remove paths this function created, never existing project files.
        for child in raw_dir.iterdir():
            if child.is_file():
                child.unlink()
        raw_dir.rmdir()
        for child in case_dir.iterdir():
            if child.is_file():
                child.unlink()
        case_dir.rmdir()
        raise
    return case_dir, manifest
