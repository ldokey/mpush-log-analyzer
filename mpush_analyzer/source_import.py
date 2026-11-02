"""Read-only bounded import from a selected directory or uploaded archives.

No extract/extractall, no source writes, no shell utilities. Archive labels are
provenance only. Every byte stream is capped independently of claimed sizes.
"""
from __future__ import annotations
from contextlib import contextmanager
from dataclasses import dataclass
import gzip
import hashlib
from io import BytesIO
import os
from pathlib import Path, PurePosixPath
import re
import stat
import tarfile
import unicodedata
import zipfile
import zlib

from .intake import Upload, MAX_FILE_COUNT, MAX_SINGLE_FILE, MAX_TOTAL_FILES_BYTES, supported_log_name
from .support_store import folder_hint, reject_links, source_label

MAX_ENTRIES = 2000
MAX_SCAN_ENTRIES = 5000
MAX_DEPTH = 12
MAX_RATIO = 1000
ARCHIVES = ('.zip', '.tar', '.tar.gz', '.tgz', '.gz')


@dataclass(frozen=True)
class Source:
    label: str
    path: Path | None = None
    content: bytes | None = None
    root: Path | None = None
    snapshot: tuple[int, int, int, int] | None = None

    @property
    def size(self) -> int:
        return self.snapshot[0] if self.snapshot else len(self.content or b'')


@dataclass(frozen=True)
class Candidate:
    source: Source
    name: str
    mode: str
    member: str = ''
    size: int | None = None

    @property
    def label(self) -> str:
        return source_label(self.source.label + ('!/' + self.member if self.member else ''))

    @property
    def group(self) -> str:
        path = self.member if self.member else self.source.label
        parent = str(PurePosixPath(path.replace('\\', '/')).parent)
        return (self.source.label + '!/' if self.member else '') + parent

    @property
    def key(self) -> str:
        raw = f'{self.source.label}\0{self.member}\0{self.mode}\0{self.source.snapshot}'
        return hashlib.sha256(raw.encode()).hexdigest()[:24]


def fingerprint_stat(st: os.stat_result) -> tuple[int, int, int, int]:
    return st.st_size, st.st_mtime_ns, st.st_ino, st.st_dev


def disk_source(path: Path, root: Path) -> Source:
    reject_links(path); reject_links(root)
    try:
        rel = path.resolve(strict=True).relative_to(root.resolve(strict=True))
    except (ValueError, OSError) as exc:
        raise ValueError('선택한 파일이 등록 폴더 밖에 있거나 접근할 수 없습니다.') from exc
    st = path.stat()
    if not stat.S_ISREG(st.st_mode) or st.st_size > MAX_SINGLE_FILE:
        raise ValueError('일반 파일이 아니거나 파일당 350MiB 한도를 초과했습니다.')
    return Source(rel.as_posix(), path=path, root=root, snapshot=fingerprint_stat(st))


@contextmanager
def open_source(source: Source):
    if source.path is None:
        if source.content is None or len(source.content) > MAX_SINGLE_FILE:
            raise ValueError('업로드 입력이 없거나 파일당 한도를 초과했습니다.')
        with BytesIO(source.content) as stream:
            yield stream
        return
    current = disk_source(source.path, source.root or source.path.parent)
    if current.snapshot != source.snapshot:
        raise ValueError('파일이 목록 조회 후 변경됐습니다. 복사가 끝난 뒤 다시 스캔하세요.')
    flags = os.O_RDONLY | getattr(os, 'O_BINARY', 0) | getattr(os, 'O_NOFOLLOW', 0)
    fd = os.open(source.path, flags)
    with os.fdopen(fd, 'rb') as stream:
        if fingerprint_stat(os.fstat(stream.fileno())) != source.snapshot:
            raise ValueError('파일 열기 중 원본 상태가 변경됐습니다.')
        yield stream
        if fingerprint_stat(os.fstat(stream.fileno())) != source.snapshot:
            raise ValueError('읽는 중 파일이 변경됐습니다. 복사 완료 후 다시 시도하세요.')


def archive_kind(name: str) -> str | None:
    name = name.lower()
    if name.endswith('.zip'): return 'zip'
    if name.endswith(('.tar.gz', '.tgz', '.tar')): return 'tar'
    if name.endswith('.gz'): return 'gz'
    return None


def safe_member(name: str) -> str:
    if not isinstance(name, str) or not name or len(name) > 1024:
        raise ValueError('압축 내부 파일 경로가 잘못됐습니다.')
    value = name.replace('\\', '/')
    if (value.startswith('/') or ':' in value or any(unicodedata.category(c) in {'Cc', 'Cf'} for c in value)
        or '..' in value.split('/') or len(value.split('/')) > MAX_DEPTH):
        raise ValueError('압축 경로 탈출·절대경로·제어문자 또는 깊이 제한 위반을 차단했습니다.')
    parts = [p for p in value.split('/') if p not in {'', '.'}]
    if not parts or any(p.rstrip(' .').upper().split('.')[0] in
                        {'CON','PRN','AUX','NUL',*(f'COM{i}' for i in range(1,10)),*(f'LPT{i}' for i in range(1,10))} for p in parts):
        raise ValueError('압축 내부에 허용되지 않는 파일명이 있습니다.')
    return '/'.join(parts)


def _bounded_read(stream, maximum: int) -> bytes:
    pieces = []; total = 0
    while True:
        block = stream.read(min(1024 * 1024, maximum - total + 1))
        if not block: break
        total += len(block)
        if total > maximum:
            raise ValueError('압축 해제 실제 크기가 한도를 초과했습니다.')
        pieces.append(block)
    return b''.join(pieces)


class _ReadBudget:
    """Bound decompressed TAR metadata too (including PAX headers/padding)."""
    def __init__(self, stream, budget: int):
        self.stream, self.remaining = stream, budget
    def read(self, size: int = -1) -> bytes:
        amount = min(size if size >= 0 else self.remaining + 1, self.remaining + 1)
        data = self.stream.read(amount)
        self.remaining -= len(data)
        if self.remaining < 0:
            raise ValueError('TAR 해제 데이터·메타데이터의 전체 한도를 초과했습니다.')
        return data


@contextmanager
def _open_tar(raw, source: Source):
    signature = raw.read(2); raw.seek(0)
    compressed = signature == b'\x1f\x8b'
    stream = gzip.GzipFile(fileobj=raw) if compressed else raw
    budget = MAX_TOTAL_FILES_BYTES + 2 * 1024**2
    if compressed:
        budget = min(budget, max(1024**2, source.size * MAX_RATIO) + 2 * 1024**2)
    try:
        with tarfile.open(fileobj=_ReadBudget(stream,budget),mode='r|') as archive:
            yield archive
    finally:
        if compressed: stream.close()


def inspect_source(source: Source) -> tuple[list[Candidate], list[str]]:
    candidates: list[Candidate] = []; notices: list[str] = []
    mode = archive_kind(source.label)
    if mode is None:
        if supported_log_name(source.label):
            return [Candidate(source, PurePosixPath(source.label).name, 'file', size=source.size)], []
        return [], [source_label(source.label) + ': 지원하지 않는 파일 형식 — 제외']
    total = 0; seen: set[str] = set()

    def accept(name: str, size: int, *, compressed: int | None = None) -> str:
        nonlocal total
        clean = safe_member(name)
        folded = unicodedata.normalize('NFC', clean).casefold()
        if folded in seen:
            raise ValueError('압축 내부의 중복 파일명(대소문자 포함)을 차단했습니다.')
        seen.add(folded)
        if len(seen) > MAX_ENTRIES or not 0 <= size <= MAX_SINGLE_FILE:
            raise ValueError('압축 항목 수 또는 파일 크기 한도를 초과했습니다.')
        total += size
        if total > MAX_TOTAL_FILES_BYTES:
            raise ValueError('압축 해제 합계 600MiB 제한을 초과했습니다.')
        if compressed is not None and size > 1024**2 and size / max(1, compressed) > MAX_RATIO:
            raise ValueError('비정상 압축률(압축 폭탄 가능성)을 차단했습니다.')
        return clean

    try:
        with open_source(source) as raw:
            if mode == 'zip':
                with zipfile.ZipFile(raw) as bundle:
                    infos = bundle.infolist()
                    if len(infos) > MAX_ENTRIES:
                        raise ValueError('압축 항목 수 2,000개 제한을 초과했습니다.')
                    for item in infos:
                        if item.is_dir() and item.filename in {'.','./'}: continue
                        clean = safe_member(item.filename)
                        typ = stat.S_IFMT(item.external_attr >> 16)
                        if item.flag_bits & 1:
                            raise ValueError('암호화 ZIP은 지원하지 않습니다. 별도 해제 후 로그를 선택하세요.')
                        if typ not in {0, stat.S_IFREG, stat.S_IFDIR}:
                            raise ValueError('압축 내부 링크·특수파일을 차단했습니다.')
                        if item.is_dir(): continue
                        clean = accept(item.filename, item.file_size, compressed=item.compress_size)
                        if supported_log_name(clean):
                            candidates.append(Candidate(source, PurePosixPath(clean).name, 'zip', item.filename, item.file_size))
                        else:
                            reason = '중첩 압축 미지원' if archive_kind(clean) else '분석 대상 아님'
                            notices.append(source.label + '!/' + clean + ': ' + reason)
            elif mode == 'tar':
                with _open_tar(raw, source) as bundle:
                    for count, item in enumerate(bundle, 1):
                        if count > MAX_ENTRIES:
                            raise ValueError('압축 항목 수 2,000개 제한을 초과했습니다.')
                        if item.isdir() and item.name in {'.','./'}: continue
                        clean = safe_member(item.name)
                        if item.isdir(): continue
                        if not item.isfile() or item.issparse():
                            raise ValueError('TAR 링크·장치·희소파일을 차단했습니다.')
                        clean = accept(item.name, item.size)
                        if supported_log_name(clean):
                            candidates.append(Candidate(source, PurePosixPath(clean).name, 'tar', item.name, item.size))
                        else:
                            notices.append(source.label + '!/' + clean + ': 중첩 압축 또는 분석 대상 아님')
                    if total > 1024**2 and total / max(1, source.size) > MAX_RATIO:
                        raise ValueError('비정상 TAR 압축률을 차단했습니다.')
            else:
                name = PurePosixPath(source.label).name[:-3]
                if supported_log_name(name):
                    candidates.append(Candidate(source, name, 'gz', name, None))
                else:
                    notices.append(source.label + ': GZ 내부 파일명이 로그 형식이 아니므로 제외')
    except (zipfile.BadZipFile, tarfile.TarError, EOFError, NotImplementedError, RuntimeError, OSError, zlib.error) as exc:
        raise ValueError('압축 파일이 손상됐거나 지원하지 않는 형식입니다. 원본은 변경하지 않았습니다.') from exc
    return candidates, notices


def read_candidate(candidate: Candidate, *, remaining: int = MAX_TOTAL_FILES_BYTES) -> Upload:
    limit = min(MAX_SINGLE_FILE, remaining)
    if limit < 0 or candidate.size is not None and candidate.size > limit:
        raise ValueError('선택한 자료의 실제 해제 용량 한도를 초과했습니다.')
    source = candidate.source
    if not supported_log_name(candidate.name):
        raise ValueError('선택한 내부 파일은 지원하는 로그 형식이 아닙니다.')
    if candidate.mode != 'file': safe_member(candidate.member)
    if candidate.mode != (archive_kind(source.label) or 'file'):
        raise ValueError('원본과 선택 항목의 압축 형식이 일치하지 않습니다.')
    try:
        with open_source(source) as raw:
            if candidate.mode == 'file':
                data = _bounded_read(raw, limit)
            elif candidate.mode == 'zip':
                with zipfile.ZipFile(raw) as archive:
                    info = archive.getinfo(candidate.member)
                    if (info.flag_bits & 1 or stat.S_IFMT(info.external_attr >> 16) not in {0,stat.S_IFREG}
                        or (info.file_size > 1024**2 and info.file_size / max(1,info.compress_size) > MAX_RATIO)):
                        raise ValueError('선택한 ZIP 항목의 안전 검증에 실패했습니다.')
                    if info.file_size != candidate.size:
                        raise ValueError('압축 내부 파일 크기가 스캔 후 변경됐습니다.')
                    with archive.open(info) as handle: data = _bounded_read(handle, limit)
            elif candidate.mode == 'tar':
                with _open_tar(raw, source) as archive:
                    data = None
                    for member in archive:
                        if member.name == candidate.member:
                            if not member.isfile() or member.size != candidate.size:
                                raise ValueError('선택한 TAR 멤버가 변경됐습니다.')
                            handle = archive.extractfile(member)
                            if handle is None: raise ValueError('TAR 내부 파일을 읽을 수 없습니다.')
                            with handle: data = _bounded_read(handle, limit)
                            break
                    if data is None: raise ValueError('선택한 압축 멤버가 없습니다.')
            elif candidate.mode == 'gz':
                with gzip.GzipFile(fileobj=raw) as handle: data = _bounded_read(handle, limit)
                if len(data) > 1024**2 and len(data) / max(source.size, 1) > MAX_RATIO:
                    raise ValueError('GZ 비정상 압축률을 차단했습니다.')
            else:
                raise ValueError('미지원 가져오기 형식입니다.')
    except (zipfile.BadZipFile, tarfile.TarError, EOFError, OSError, RuntimeError, NotImplementedError, zlib.error) as exc:
        raise ValueError('원본/압축 파일을 읽지 못했습니다. 변경·손상 여부를 확인하세요.') from exc
    if candidate.size is not None and len(data) != candidate.size:
        raise ValueError('읽은 내용과 파일 목록의 크기가 다릅니다.')
    return Upload(candidate.name, data, origin=candidate.label)


def load_candidates(selected: list[Candidate]) -> list[Upload]:
    if not 1 <= len(selected) <= MAX_FILE_COUNT:
        raise ValueError('같은 Agent의 파일을 1~30개 선택하세요.')
    if sum(c.size or 0 for c in selected) > MAX_TOTAL_FILES_BYTES:
        raise ValueError('선택 자료의 해제 합계가 600MiB를 넘습니다.')
    result = []; total = 0
    for candidate in selected:
        item = read_candidate(candidate, remaining=MAX_TOTAL_FILES_BYTES - total)
        total += len(item.content); result.append(item)
    return result


def issue_folders(root: Path) -> list[dict]:
    reject_links(root)
    if not root.is_absolute() or not root.is_dir():
        raise ValueError('앱이 실행되는 PC에서 접근 가능한 고객사 문의 루트 절대경로를 입력하세요.')
    folders = []
    for count, path in enumerate(root.iterdir(), 1):
        if count > MAX_SCAN_ENTRIES: raise ValueError('루트 항목 5,000개 제한을 초과했습니다.')
        if path.is_symlink() or (hasattr(path, 'is_junction') and path.is_junction()): continue
        hint = folder_hint(path.name)
        if hint and path.is_dir(): folders.append({'folder': path.name, **hint})
    return sorted(folders, key=lambda row: (-int(row['number']), row['folder']))


def scan_folder(root: Path, relative: str) -> tuple[list[Candidate], list[str]]:
    safe = safe_member(relative)
    folder = root / safe
    reject_links(folder); reject_links(root)
    if not root.is_absolute() or not folder.is_dir() or not folder.resolve().is_relative_to(root.resolve()):
        raise ValueError('등록 루트 내의 문의 폴더만 조회할 수 있습니다.')
    candidates = []; notices = []; count = 0
    def onerror(error): raise ValueError('하위 폴더 접근 권한을 확인하세요.') from error
    for current, dirs, files in os.walk(folder, followlinks=False, onerror=onerror):
        location = Path(current)
        if len(location.relative_to(folder).parts) > MAX_DEPTH:
            raise ValueError('폴더 탐색 깊이 제한을 초과했습니다.')
        for name in list(dirs):
            p = location / name
            if p.is_symlink() or (hasattr(p, 'is_junction') and p.is_junction()):
                dirs.remove(name); notices.append(str(p.relative_to(root)) + ': 링크 디렉터리 제외')
        count += len(dirs) + len(files)
        if count > MAX_SCAN_ENTRIES: raise ValueError('폴더 탐색 항목 5,000개 제한을 초과했습니다.')
        for name in sorted(files):
            path = location / name
            if path.is_symlink():
                notices.append(str(path.relative_to(root)) + ': 링크 파일 제외'); continue
            if not (supported_log_name(name) or archive_kind(name)):
                notices.append(str(path.relative_to(root)) + ': 분석 대상 아님'); continue
            source = disk_source(path, root)
            found, skipped = inspect_source(source)
            candidates += found; notices += skipped
            if len(candidates) > MAX_ENTRIES:
                raise ValueError('분석 후보 2,000개 제한을 초과했습니다. 하위 폴더별로 분리하세요.')
    return candidates, notices
