"""Private local knowledge-case lifecycle.

AI-authored files always enter inbox as drafts. Only an explicit human approval
action moves a reviewed revision to approved. JSON Schema validation != truth.
"""
from __future__ import annotations
from .permissions import private_fd, private_path

from datetime import datetime
import json
import os
from pathlib import Path
import re
from typing import Any
from zoneinfo import ZoneInfo

from .case_contract import validate_case_json, MAX_CASE_JSON_BYTES

ROOT = Path(__file__).resolve().parents[1] / "knowledge"
VALID_FILE = re.compile(r"^(MPA-CASE-\d{6})_r(\d{4,})\.json$")
VALID_CASE = re.compile(r"^MPA-CASE-\d{6}$")


def _ensure_private_dirs(root: Path) -> tuple[Path, Path]:
    if root.is_symlink():
        raise ValueError("지식 저장소가 심볼릭 링크입니다.")
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    inbox, approved = root / "inbox", root / "approved"
    for folder in (inbox, approved):
        if folder.is_symlink():
            raise ValueError("사례 저장 폴더에 심볼릭 링크를 사용할 수 없습니다.")
        folder.mkdir(mode=0o700, exist_ok=True)
    return inbox, approved


def _filename(case_id: str, revision: int) -> str:
    if not VALID_CASE.fullmatch(case_id) or isinstance(revision, bool) or not 1 <= revision <= 999999:
        raise ValueError("사례 ID 또는 revision이 유효하지 않습니다.")
    return f"{case_id}_r{revision:04d}.json"


def _load_verified(path: Path) -> dict[str, Any] | None:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_CASE_JSON_BYTES:
        return None
    data = path.read_bytes()
    if not validate_case_json(data).valid:
        return None
    payload = json.loads(data.decode("utf-8-sig"))
    if _filename(payload["case_id"], payload["revision"]) != path.name:
        return None
    return payload


def _existing_revisions(root: Path, case_id: str) -> set[int]:
    revisions: set[int] = set()
    for folder in (root / "inbox", root / "approved"):
        if not folder.is_dir() or folder.is_symlink():
            raise ValueError("사례 저장 디렉터리가 안전하지 않습니다.")
        for path in folder.iterdir():
            m = VALID_FILE.fullmatch(path.name)
            if m and m.group(1) == case_id:
                revisions.add(int(m.group(2)))
    return revisions


def import_case(data: bytes, *, root: Path = ROOT) -> dict[str, Any]:
    """Store a validated AI draft; NEVER trust embedded approved flags."""
    verdict = validate_case_json(data)
    if not verdict.valid:
        raise ValueError("사례 JSON 계약·민감정보 검사 실패 (상세 내용은 로컬 검증 화면 확인)")
    payload = json.loads(data.decode("utf-8-sig"))
    if payload["review"]["state"] != "draft" or payload["review"]["approved_at"] is not None:
        raise ValueError("AI 사례는 draft 상태로만 등록할 수 있습니다.")
    if payload["status"] == "resolved_verified":
        raise ValueError("원인·해결 검증 완료 상태는 AI 초안에서 지정할 수 없습니다.")
    inbox, _ = _ensure_private_dirs(root)
    case_id, revision = payload["case_id"], payload["revision"]
    name = _filename(case_id, revision)
    used = _existing_revisions(root, case_id)
    if revision in used:
        raise ValueError("동일 사례 ID·수정 버전이 이미 존재합니다.")
    if used and revision <= max(used):
        raise ValueError("사례 수정 버전은 기존 최대 버전보다 커야 합니다.")
    dest = inbox / name
    # Prefer canonical serialization; no sender-controlled filename or path.
    with dest.open("x", encoding="utf-8") as handle:
        private_fd(handle.fileno())
        json.dump(payload, handle, ensure_ascii=False, indent=2, sort_keys=True)
        handle.write("\n")
    return dict(verdict.summary, storage_state="inbox")


def list_case_summaries(*, root: Path = ROOT, state: str = "inbox") -> list[dict[str, Any]]:
    if state not in {"inbox", "approved"}:
        raise ValueError("지원되지 않는 사례 상태입니다.")
    folder = root / state
    if folder.is_symlink():
        raise ValueError("사례 저장 폴더가 안전하지 않습니다.")
    if not folder.is_dir():
        return []
    entries: list[dict[str, Any]] = []
    for path in sorted(folder.iterdir(), key=lambda p: p.name):
        if not VALID_FILE.fullmatch(path.name):
            continue
        doc = _load_verified(path)
        if doc is None:
            continue
        expected = "draft" if state == "inbox" else "approved"
        if doc["review"]["state"] != expected:
            continue
        entries.append({
            "case_id": doc["case_id"], "revision": doc["revision"],
            "title": doc["title"], "status": doc["status"],
            "review_state": expected,
            "references_count": len(doc["references"]),
            "signals": doc["match_signals"]["required"] + doc["match_signals"]["supporting"],
        })
    return entries


def approve_case(case_id: str, revision: int, *, confirm_reviewed: bool = False,
                 confirm_solution: bool = False, root: Path = ROOT) -> dict[str, Any]:
    """Approval of editorial evidence requires a direct human review confirmation.

    This does not upgrade an unverified case to resolved_verified.
    """
    if confirm_reviewed is not True:
        raise ValueError("사례 내용 및 출처를 직접 검토한 후 승인할 수 있습니다.")
    inbox, approved = _ensure_private_dirs(root)
    filename = _filename(case_id, revision)
    src = inbox / filename
    doc = _load_verified(src)
    if doc is None or doc["review"]["state"] != "draft":
        raise ValueError("승인 가능한 유효한 초안이 없습니다.")
    if confirm_solution:
        cause = doc.get("root_cause")
        resolution = doc.get("resolution") or {}
        verification = doc.get("verification") or {}
        if not (isinstance(cause, dict) and cause.get("status") == "confirmed"
                and cause.get("evidence") and resolution.get("verified") is True
                and resolution.get("actions") and verification.get("status") == "verified"
                and verification.get("evidence") and doc.get("references")):
            raise ValueError("검증된 원인·조치·해결 근거 및 출처가 모두 필요합니다.")
        doc["status"] = "resolved_verified"
    doc["review"] = {
        "state": "approved", "approved_at": datetime.now(ZoneInfo("Asia/Seoul")).isoformat()
    }
    serialized = json.dumps(doc, ensure_ascii=False, sort_keys=True, indent=2).encode("utf-8")
    if not validate_case_json(serialized).valid:
        raise ValueError("승인 후 스키마·민감정보 검증 실패")
    dest = approved / filename
    # If any version exists in approved, only a newer revision may be approved.
    older = _existing_revisions(root, case_id)
    if any(i > revision for i in older):
        raise ValueError("더 높은 수정 버전이 이미 등록되어 있습니다.")
    with dest.open("xb") as handle:
        private_fd(handle.fileno())
        handle.write(serialized + b"\n")
    src.unlink()
    return {"case_id":case_id,"revision":revision,"review_state":"approved",
            "status":doc["status"]}


def read_approved_cases(*, root: Path = ROOT) -> tuple[list[dict[str, Any]], int]:
    """Returns newest valid APPROVED revision per ID. Invalid files are ignored."""
    folder = root / "approved"
    if folder.is_symlink():
        raise ValueError("승인 사례 폴더가 심볼릭 링크입니다.")
    if not folder.is_dir():
        return [], 0
    latest: dict[str, dict[str, Any]] = {}
    rejected = 0
    for path in sorted(folder.iterdir(), key=lambda p: p.name):
        if not VALID_FILE.fullmatch(path.name):
            rejected += 1
            continue
        doc = _load_verified(path)
        if doc is None or doc["review"]["state"] != "approved":
            rejected += 1
            continue
        old = latest.get(doc["case_id"])
        if old is None or doc["revision"] > old["revision"]:
            latest[doc["case_id"]] = doc
    return [latest[k] for k in sorted(latest)], rejected

def read_case_draft(case_id: str, revision: int, *, root: Path = ROOT) -> dict[str, Any] | None:
    """Read only an explicitly named validated draft for a human review screen."""
    _filename(case_id, revision)
    inbox = root / "inbox"
    if inbox.is_symlink() or not inbox.is_dir():
        return None
    item = _load_verified(inbox / _filename(case_id, revision))
    return item if item and item["review"]["state"] == "draft" else None
