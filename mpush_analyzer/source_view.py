"""Strictly allowlisted evidence excerpts from hash-verified local raw logs.

No option returns unmasked arbitrary user messages, SQL, credentials or URLs.
"""
from __future__ import annotations

from itertools import islice
from pathlib import Path
import re
from typing import Any

from .pipeline import _get_manifest, _safe_source

CLOCK = re.compile(r"^\s*((?:[01]\d|2[0-3]):[0-5]\d:[0-5]\d\[\d{1,3}\])")
JOB_HEADER = re.compile(r"##\s+([A-Z][A-Z0-9_]{2,63})\s+작업\s*$")
METRIC = re.compile(
    r"##\s*(작업대상건수|시작시간|종료시간|SELECT 시간(?:\([^)]{0,20}\))?|"
    r"FILE 시간(?:\([^)]{0,20}\))?|SOCKET 시간(?:\([^)]{0,20}\))?|"
    r"DB 시간(?:\([^)]{0,20}\))?|HTTP IN 시간(?:\([^)]{0,20}\))?|"
    r"HTTP OUT 시간(?:\([^)]{0,20}\))?|소요시간(?:\([^)]{0,20}\))?|"
    r"초당 작업 건수)\s*:\s*(.{0,180})",
)
VALUE_NUM = re.compile(r"\d{1,10}(?:\.\d{1,9})?")
PSTMT = re.compile(r"\bPSTMT\.(EQ|EU|EB|[A-Z]{1,4})\s+Laptime\s*:\s*(\d{1,10}(?:\.\d+)?)", re.I)
SQL_RESULT = re.compile(r"Result\s*:\s*(?:select completed|batch job success|(\d{1,10})\s+row\(s\)\s+updated|failed)", re.I)
CODE = re.compile(r"""RESPONSE_CODE['"]?\s*[:=]\s*['"]?([A-Z0-9_-]{1,16})""", re.I)
TARGET = re.compile(r"""TARGET['"]?\s*[:=]\s*['"]?([a-zA-Z_]{1,30})""", re.I)
EXCEPTION = re.compile(r"\b([A-Za-z_][\w.$]{0,90}(?:Exception|Error))\b")
MAX_CONTEXT = 4
MAX_SHOW_LINES = 30
MAX_LINE_LENGTH = 16000


def masked_line(line: str) -> tuple[str, bool]:
    """Extract structural fragments only. Unknown text is never displayed."""
    prefix_match = CLOCK.match(line)
    prefix = prefix_match.group(1) + " " if prefix_match else ""
    if m := JOB_HEADER.search(line):
        return prefix + m.group(1) + " 작업", False
    if m := METRIC.search(line):
        metric = m.group(1).split("(", 1)[0]
        value = m.group(2).strip()
        if metric in {"시작시간", "종료시간"}:
            found = re.fullmatch(
                r"(\d{1,2})시\s*(\d{1,2})분\s*(\d{1,2})(?:\.(\d{1,3}))?초",
                value
            )
            if found and all(int(x) < maximum for x, maximum in zip(found.groups()[:3], (24, 60, 60))):
                h, minute, second, ms = found.groups()
                display = f"{int(h):02}:{int(minute):02}:{int(second):02}"
                return prefix + metric + " : " + display + (
                    "." + ms.ljust(3, "0") if ms else ""
                ), False
            return prefix + metric + " : [값 비표시]", True
        if metric == "작업대상건수":
            safe = re.fullmatch(r"(\d{1,7})\s*(?:건)?", value)
        elif metric == "초당 작업 건수":
            safe = re.fullmatch(r"(\d{1,6}(?:\.\d{1,6})?)\s*건", value)
        else:
            safe = re.fullmatch(r"(\d{1,7}(?:\.\d{1,9})?)\s*초", value)
        if safe:
            return prefix + metric + " : " + safe.group(1), False
        return prefix + metric + " : [값 비표시]", True
    if m := PSTMT.search(line):
        return prefix + f"PSTMT.{m.group(1).upper()} Laptime: {m.group(2)}ms", False
    if m := SQL_RESULT.search(line):
        if m.group(1):
            return prefix + "DB 업데이트 건수: " + m.group(1), False
        text = line.lower()
        if "select completed" in text:
            return prefix + "DB 조회 실행 완료", False
        if "batch job success" in text:
            return prefix + "DB 배치 실행 완료", False
        return prefix + "DB 실행 실패 기록", False
    if "헬스 체크 서비스 번호" in line:
        return prefix + "헬스체크 요청 (서비스 식별값 비표시)", True
    if "헬스 체크 결과" in line:
        if m := TARGET.search(line):
            v = m.group(1)
            if v.lower() in {"nothing", "shutdown"}:
                return prefix + "헬스체크 응답: " + v.lower(), False
        return prefix + "헬스체크 응답 (본문 비표시)", True
    if "서버에서 받은 문자열" in line or "RESPONSE_CODE" in line:
        if m := CODE.search(line):
            return prefix + "CNS RESPONSE_CODE: " + m.group(1).upper(), False
    if "Can't execute task in RUNNING state" in line:
        return prefix + "Job RUNNING 상태로 실행 건너뛰기", False
    if m := EXCEPTION.search(line):
        name = m.group(1).rsplit(".", 1)[-1]
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{1,55}", name):
            return prefix + "예외 유형: " + name, True
    for word in ("Agent Exited", "Config Loading", "Starting....", "Started"):
        if word in line:
            return prefix + word, False
    return prefix + "[민감정보 보호: 로그 본문 비표시]", True


def excerpt(
    case_dir: Path, file_id: str, first_line: int, last_line: int,
    *, context: int = 1,
) -> dict[str, Any]:
    if not 0 <= context <= MAX_CONTEXT:
        raise ValueError("주변 로그 표시 범위를 확인해 주세요.")
    if not isinstance(first_line, int) or not isinstance(last_line, int):
        raise ValueError("원본 줄번호는 정수여야 합니다.")
    if first_line < 1 or last_line < first_line or last_line - first_line > 5000:
        raise ValueError("원본 로그 줄번호가 잘못되었습니다.")
    manifest = _get_manifest(case_dir)  # SHA-256 checks for all source inputs
    selected = next((item for item in manifest["files"] if item["file_id"] == file_id), None)
    if selected is None or selected["kind"] in {"agent_ini", "unknown"}:
        raise ValueError("이 파일의 원본 로그 조회는 제공되지 않습니다.")
    path = _safe_source(case_dir, selected)
    lo = max(1, first_line - context)
    hi = min(last_line + context, lo + MAX_SHOW_LINES - 1)
    lines = []
    masked_count = 0
    encoding = selected["encoding"]
    codec = "utf-8" if encoding == "utf-8-replace" else encoding
    with path.open("r", encoding=codec, errors="replace") as source:
        for n, raw in enumerate(islice(source, lo - 1, hi), start=lo):
            text, masked = masked_line(raw[:MAX_LINE_LENGTH].rstrip("\r\n"))
            masked_count += bool(masked)
            lines.append({
                "line": n,
                "text": text,
                "masked": masked,
                "within_evidence": first_line <= n <= last_line,
            })
    return {
        "file_id": file_id, "kind": selected["kind"],
        "requested_lines": [first_line, last_line],
        "shown_lines": len(lines),
        "masked_lines": masked_count,
        "truncated": hi < last_line + context,
        "lines": lines,
        "notice": "구조적 항목만 표시합니다. SQL 본문·개인정보·메시지 내용은 노출하지 않습니다.",
    }
