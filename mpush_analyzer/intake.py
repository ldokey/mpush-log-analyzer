"""Stage-1 source inventory, content classification and safe input limits."""
from __future__ import annotations

import codecs
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
    origin: str | None = None  # local-only source/archive-relative label


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


def detect_text_encoding(chunks_factory) -> str:
    """Validate complete text incrementally, not a potentially split sample."""
    for codec in ('utf-8-sig', 'cp949'):
        decoder = codecs.getincrementaldecoder(codec)(errors='strict')
        try:
            bom = False
            for i, block in enumerate(chunks_factory()):
                if i == 0:
                    bom = block.startswith(b'\xef\xbb\xbf')
                decoder.decode(block, final=False)
            decoder.decode(b'', final=True)
            return ('utf-8-sig' if bom else 'utf-8') if codec == 'utf-8-sig' else codec
        except UnicodeDecodeError:
            continue
    return 'utf-8-replace'


def content_encoding(data: bytes) -> str:
    return detect_text_encoding(lambda: (data[i:i+131072] for i in range(0,len(data),131072)))


def decode_prefix(data: bytes, encoding: str) -> str:
    codec = 'utf-8' if encoding == 'utf-8-replace' else encoding
    return codecs.getincrementaldecoder(codec)(errors='replace').decode(data, final=False)


def _filename_kind(label: str) -> Kind | None:
    basename = display_filename(label).lower()
    if basename == "agent.ini":
        return "agent_ini"
    stem = Path(basename).stem
    stem = re.sub(r"^\d{8}(?:[0-2]\d(?:[0-5]\d)?)?[-_.]*", "", stem)
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
    # Daily/hourly/minute rotation only; never truncate a longer numeric ID.
    pattern = r"(?<!\d)(20\d{2})[-_]?(\d{2})[-_]?(\d{2})(?:[-_]?([0-2]\d)(?:[-_]?([0-5]\d))?)?(?!\d)"
    for match in re.finditer(pattern, label):
        try:
            y, m, d, hour, minute = match.groups()
            value = datetime(int(y),int(m),int(d),int(hour or 0),int(minute or 0))
            return value.date().isoformat()
        except ValueError:
            continue
    return None


def _timestamp_hints(data: bytes, encoding: str | None = None) -> tuple[str | None, str | None]:
    # Use small windows for Stage-1 sampling; Stage-2 parses complete files.
    codec = encoding or content_encoding(data)
    first = decode_prefix(data[:131072], codec)
    tail = data[max(0, len(data)-131072):]
    if len(data)>131072 and b'\n' in tail:
        tail = tail.split(b'\n',1)[1]
    last = decode_prefix(tail, codec)
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


def supported_log_name(name: str) -> bool:
    basename = display_filename(name).lower()
    return (Path(basename).suffix in VALID_SUFFIXES or
            re.search(r"\.log(?:[._-]\d{1,4}|[._-]20\d{2}[-_]?\d{2}[-_]?\d{2})$", basename) is not None)


def inspect_uploads(uploads: list[Upload]) -> list[Inspected]:
    validate_upload_limits([len(item.content) for item in uploads])
    found: dict[tuple[str, str | None], int] = {}
    result: list[Inspected] = []
    for index, upload in enumerate(uploads, 1):
        label = display_filename(upload.name)
        if not supported_log_name(label):
            raise ValueError("지원하지 않는 확장자가 있습니다. .log, 회전 .log.1, .txt, .ini 형식을 사용하세요.")
        if upload.completeness not in ("full", "partial", "unknown"):
            raise ValueError("잘못된 로그 완전성 값입니다.")
        if upload.override_kind is not None and upload.override_kind not in KINDS:
            raise ValueError("잘못된 수동 로그 유형입니다.")
        if b"\x00" in (upload.content[:4096] + upload.content[-4096:]):
            raise ValueError("텍스트 파일이 아닌 입력이 감지되었습니다.")

        digest = sha256(upload.content).hexdigest()
        encoding = content_encoding(upload.content)
        sample_text = decode_prefix(upload.content[:131072], encoding)
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
        # Equal bytes on different dated files are not the same observation
        # stream. Within the same date retain the legacy first-copy policy.
        duplicate_key = (digest, _date_hint(label))
        duplicate_of = found.get(duplicate_key)
        found.setdefault(duplicate_key, index)
        if not upload.content:
            warnings.append("파일이 비어 있습니다.")
        if duplicate_of:
            warnings.append(f"{duplicate_of}번째 업로드 파일과 내용이 중복됩니다.")
        first, last = _timestamp_hints(upload.content, encoding)
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
