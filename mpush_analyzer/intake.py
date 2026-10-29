"""Stage-1 source inventory, content classification and safe input limits."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from hashlib import sha256
from pathlib import Path
import re
from typing import Literal

from .security import display_filename

Kind = Literal["debug", "job", "dbwrap", "info", "err", "agent_ini", "unknown"]
Completeness = Literal["full", "partial", "unknown"]
# Upload caps are in MiB. Streamlit's per-file limit is set separately in
# .streamlit/config.toml; this check also protects direct/CLI callers.
MAX_SINGLE_FILE = 350 * 1024 * 1024
MAX_TOTAL_FILES_BYTES = 600 * 1024 * 1024
MAX_FILE_COUNT = 30
VALID_SUFFIXES = {".log", ".txt", ".ini"}
KINDS = ("debug", "job", "dbwrap", "info", "err", "agent_ini", "unknown")
TIMESTAMP_RE = re.compile(
    r"(?<!\d)(?P<time>(?:[01]\d|2[0-3]):[0-5]\d:[0-5]\d)(?:\[(?P<millis>\d{1,3})\])?"
)


@dataclass(frozen=True)
class Upload:
    name: str
    content: bytes
    completeness: Completeness = "unknown"
    override_kind: Kind | None = None


@dataclass(frozen=True)
class Inspected:
    upload: Upload
    label: str
    kind: Kind
    confidence: str
    detection: str
    encoding: str
    sha256: str
    size_bytes: int
    line_count: int
    date_hint: str | None
    first_time_hint: str | None
    last_time_hint: str | None
    duplicate_of: int | None
    warnings: tuple[str, ...]


def decode_upload(data: bytes) -> tuple[str, str]:
    if data.startswith(b"\xef\xbb\xbf"):
        return data.decode("utf-8-sig"), "utf-8-sig"
    try:
        return data.decode("utf-8"), "utf-8"
    except UnicodeDecodeError:
        try:
            return data.decode("cp949"), "cp949"
        except UnicodeDecodeError:
            return data.decode("utf-8", errors="replace"), "utf-8-replace"


def _filename_kind(label: str) -> Kind | None:
    basename = display_filename(label).lower()
    if basename == "agent.ini":
        return "agent_ini"
    stem = Path(basename).stem
    stem = re.sub(r"^\d{8}[-_.]*", "", stem)
    for name in ("dbwrap", "debug", "info", "job", "err", "error"):
        if (stem.startswith(name) and (len(stem) == len(name) or not stem[len(name)].isalpha())) or (
            re.search(r"(?:[-_.])" + name + r"(?=$|[-_.0-9])", stem) is not None
        ):
            return "err" if name == "error" else name  # type: ignore[return-value]
    return None


def _content_kind(text: str) -> Kind | None:
    # Do not print source snippets: debug and SQL logs can contain credentials.
    upper = text[:120_000].upper()
    if re.search(r"(?m)^\s*\[AGENT\]\s*$", upper) and re.search(r"(?m)^\s*\[DBMS\]\s*$", upper):
        return "agent_ini"
    if ("NO_ID" in upper and ("LAPTIME" in upper or "SQL" in upper)):
        return "dbwrap"
    if ("##  SEND_REAL_FILE_IMAGE" in upper or "##  HA_RECEIVE_RESULT" in upper or
            ("작업대상건수" in text and "소요시간" in text)):
        return "job"
    if "서버에서 받은 문자열" in text or "헬스 체크" in text or "RESPONSE_CODE" in upper:
        return "debug"
    if "AGENT EXITED" in upper or "CONFIG LOADING" in upper or "STARTING...." in upper:
        return "info"
    if "CAUSED BY:" in upper or "EXCEPTION IN THREAD" in upper:
        return "err"
    return None


def _date_hint(label: str) -> str | None:
    for match in re.finditer(r"(?<!\d)(20\d{6})(?!\d)", label):
        try:
            return datetime.strptime(match.group(1), "%Y%m%d").date().isoformat()
        except ValueError:
            continue
    return None


def _timestamp_hints(data: bytes) -> tuple[str | None, str | None]:
    # Use small windows for Stage-1 sampling; Stage-2 parses complete files.
    first, _ = decode_upload(data[: min(len(data), 131072)])
    last, _ = decode_upload(data[max(0, len(data) - 131072):])
    matches_start = list(TIMESTAMP_RE.finditer(first))
    matches_end = list(TIMESTAMP_RE.finditer(last))

    def format_hit(m: re.Match[str]) -> str:
        result = m.group("time")
        if m.group("millis") is not None:
            result += "." + m.group("millis").zfill(3)
        return result

    return (
        format_hit(matches_start[0]) if matches_start else None,
        format_hit(matches_end[-1]) if matches_end else None
    )


def validate_upload_limits(sizes: list[int]) -> None:
    """Validate sizes BEFORE the UI copies full UploadedFile content into RAM."""
    if not sizes or len(sizes) > MAX_FILE_COUNT:
        raise ValueError(f"파일 개수는 1~{MAX_FILE_COUNT}개여야 합니다.")
    if any(type(size) is not int or size < 0 for size in sizes):
        raise ValueError("업로드 파일 크기를 확인할 수 없습니다.")
    if any(size > MAX_SINGLE_FILE for size in sizes):
        raise ValueError(f"개별 파일이 {MAX_SINGLE_FILE // (1024 * 1024)}MiB 제한을 초과했습니다.")
    if sum(sizes) > MAX_TOTAL_FILES_BYTES:
        raise ValueError(f"총 업로드 용량이 {MAX_TOTAL_FILES_BYTES // (1024 * 1024)}MiB 제한을 초과했습니다.")


def inspect_uploads(uploads: list[Upload]) -> list[Inspected]:
    validate_upload_limits([len(item.content) for item in uploads])
    found: dict[str, int] = {}
    result: list[Inspected] = []
    for index, upload in enumerate(uploads, 1):
        label = display_filename(upload.name)
        if Path(label).suffix.lower() not in VALID_SUFFIXES:
            raise ValueError("지원하지 않는 확장자가 있습니다. .log, .txt, .ini만 가능합니다.")
        if upload.completeness not in ("full", "partial", "unknown"):
            raise ValueError("잘못된 로그 완전성 값입니다.")
        if upload.override_kind is not None and upload.override_kind not in KINDS:
            raise ValueError("잘못된 수동 로그 유형입니다.")
        if b"\x00" in (upload.content[:4096] + upload.content[-4096:]):
            raise ValueError("텍스트 파일이 아닌 입력이 감지되었습니다.")

        digest = sha256(upload.content).hexdigest()
        duplicate_of = found.get(digest)
        found.setdefault(digest, index)
        sample_text, encoding = decode_upload(upload.content[:131072])
        filename_kind = _filename_kind(label)
        content_kind = _content_kind(sample_text)
        warnings: list[str] = []
        if upload.override_kind is not None:
            kind: Kind = upload.override_kind
            confidence, detection = "high", "manual"
        elif filename_kind:
            kind = filename_kind
            confidence, detection = "high", "filename"
            if content_kind and content_kind != filename_kind:
                confidence = "low"
                warnings.append("파일명과 내용의 로그 분류가 서로 다릅니다. 직접 확인이 필요합니다.")
        elif content_kind:
            kind = content_kind
            confidence, detection = "medium", "content"
        else:
            kind = "unknown"
            confidence, detection = "low", "unclassified"
            warnings.append("파일 유형을 판별할 수 없습니다.")
        if not upload.content:
            warnings.append("파일이 비어 있습니다.")
        if duplicate_of:
            warnings.append(f"{duplicate_of}번째 업로드 파일과 내용이 중복됩니다.")
        first, last = _timestamp_hints(upload.content)
        result.append(Inspected(
            upload=upload, label=label, kind=kind,
            confidence=confidence, detection=detection, encoding=encoding,
            sha256=digest, size_bytes=len(upload.content),
            line_count=upload.content.count(b"\n") + (
                1 if upload.content and not upload.content.endswith(b"\n") else 0
            ), date_hint=_date_hint(label), first_time_hint=first,
            last_time_hint=last, duplicate_of=duplicate_of,
            warnings=tuple(warnings)
        ))
    return result
