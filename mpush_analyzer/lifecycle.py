"""Explicit, scoped deletion of a single local analysis case.

No automatic retention deletion. Caller must supply the full matching case ID.
"""
from __future__ import annotations
from pathlib import Path
import re

from .pipeline import _get_manifest

CASE_PATTERN = re.compile(r"^analysis_[0-9a-f]{32}$")
OUTPUTS = {
    "manifest.json", "events.jsonl", "analysis_result.json",
    "case_matches.json", "report.md", "report.html", "report.json"
}


def list_cases(workspace: Path) -> list[Path]:
    if workspace.is_symlink() or not workspace.is_dir():
        return []
    return sorted((p for p in workspace.iterdir()
                   if p.is_dir() and not p.is_symlink()
                   and CASE_PATTERN.fullmatch(p.name)
                   and (p / "manifest.json").is_file()
                   and not (p / "manifest.json").is_symlink()),
                  key=lambda p: p.stat().st_mtime, reverse=True)


def delete_case(case_dir: Path, *, confirmation: str, workspace: Path) -> None:
    """Delete only a validated child case with known files, after explicit consent."""
    if not CASE_PATTERN.fullmatch(confirmation) or confirmation != case_dir.name:
        raise ValueError("분석 ID와 삭제 확인 문구가 일치하지 않습니다.")
    if workspace.is_symlink() or case_dir.is_symlink():
        raise ValueError("심볼릭 링크 디렉터리는 삭제할 수 없습니다.")
    if not workspace.is_dir() or case_dir.parent.resolve() != workspace.resolve():
        raise ValueError("분석 작업 경로가 올바르지 않습니다.")
    manifest = _get_manifest(case_dir)
    raw_dir = case_dir / "raw"
    accepted = {e["storage_name"] for e in manifest["files"]}
    actual_raw = {p.name for p in raw_dir.iterdir()}
    if accepted != actual_raw:
        raise ValueError("예상하지 못한 원본 파일이 포함되어 있어 삭제를 중단했습니다.")
    all_entries = {p.name for p in case_dir.iterdir()}
    unexpected = all_entries - OUTPUTS - {"raw"}
    if unexpected:
        raise ValueError("알 수 없는 파일이 포함되어 있어 안전한 삭제를 수행할 수 없습니다.")
    for p in case_dir.iterdir():
        if p.is_symlink() or (p.is_file() and p.name not in OUTPUTS):
            raise ValueError("허용되지 않은 파일/심볼릭 링크가 있습니다.")
    # All paths are descendants of a single verified workspace case.
    for entry in manifest["files"]:
        target = raw_dir / entry["storage_name"]
        if target.is_symlink() or not target.is_file():
            raise ValueError("원본 로그 상태가 변경되어 삭제할 수 없습니다.")
    for entry in manifest["files"]:
        (raw_dir / entry["storage_name"]).unlink()
    raw_dir.rmdir()
    for name in sorted(OUTPUTS):
        target = case_dir / name
        if target.exists():
            target.unlink()
    case_dir.rmdir()
