"""Human-readable, privacy-bounded finding projection for local UI and AI briefs.

All free-form source strings are deliberately ignored. The JSON contract can
remain machine-oriented while the presentation remains concise and legible.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any
import re

SAFE_FILE = re.compile(r"^(?:debug|job|dbwrap|info|err|agent_ini|unknown)_[0-9]{2}\.(?:log|txt|ini)$")
SAFE_JOB = re.compile(r"^[A-Z][A-Z0-9_]{2,63}$")
SAFE_ID = re.compile(r"^file_[0-9]{2}$")
SAFE_TIME = re.compile(r"^20[0-9]{2}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,6})?[+-]\d\d:\d\d$")
SAFE_CLOCK = re.compile(r"^\d\d:\d\d:\d\d\.\d{3}$")
SAFE_CODES = {
    "SEND_JOB_DELAY": "발송 Job 지연",
    "RESULT_JOB_DELAY": "결과 수신 Job 지연",
    "OTHER_JOB_DELAY": "기타 Job 지연",
    "TRANSPORT_DELAY": "통신 단계 처리시간 증가",
    "DB_SQL_DELAY": "DB SQL 처리 지연",
    "SQL_ERROR": "SQL 오류 기록",
    "TRANSPORT_ERROR": "통신 오류 기록",
    "GENERAL_EXCEPTION": "기타 예외 기록",
    "JOB_RUNNING_STATE": "RUNNING 상태 반복",
    "HEALTHCHECK_GAP": "헬스체크 기록 공백",
    "PERIODIC_JOB_GAP": "헬스체크·Job 기록 공백",
    "AGENT_EXIT_SEEN": "Agent 종료 기록",
    "AGENT_START_SEEN": "Agent 시작 기록",
}
MEASUREMENTS = {
    "max_seconds": ("최대 처리시간", "초"),
    "max_stage_seconds": ("최대 단계시간", "초"),
    "max_laptime_ms": ("최대 DB 실행시간", "ms"),
    "threshold_seconds": ("탐지 임계값", "초"),
    "threshold_ms": ("탐지 임계값", "ms"),
    "max_gap_seconds": ("최대 관측 공백", "초"),
    "tail_gap_seconds": ("수집시각까지 공백", "초"),
    "healthcheck_tail_seconds": ("헬스체크 공백", "초"),
    "job_tail_seconds": ("Job 기록 공백", "초"),
    "estimated_interval_seconds": ("관측된 통상 주기", "초"),
    "above_absolute_count": ("절대 기준 초과 실행", "건"),
    "above_threshold_count": ("기준 초과", "건"),
    "gap_count": ("관측 공백 구간", "건"),
    "observed_count": ("관측 수", "건"),
    "count": ("오류 기록 수", "건"),
    "window_seconds": ("반복 관측 시간창", "초"),
}
RULE_LIMITS = {
    "JOB_DURATION": "Job 처리시간 증가를 관측했으며 선행 원인이나 실제 전달 성공은 판단할 수 없습니다.",
    "TRANSPORT_STEP": "SOCKET/HTTP 단계 시간에 후속 처리가 포함될 수 있어 네트워크 장애로 단정하지 않습니다.",
    "SQL_DURATION": "DB 실행 지연은 확인됐지만 Lock·SQL 튜닝 필요성·서버 자원 부족은 확정되지 않았습니다.",
    "EXPLICIT_ERROR": "오류 유형의 존재만 확인됐으며 재시도 성공 여부와 영향 범위는 별도 검증이 필요합니다.",
    "REPEATED_JOB_SKIP": "RUNNING 반복은 확인됐지만 Job 스레드가 교착 상태인지는 확인되지 않았습니다.",
    "HEALTHCHECK_INTERVAL": "두 헬스체크 기록 사이 공백은 확인됐지만 프로세스 종료가 입증된 것은 아닙니다.",
    "HEALTHCHECK_TAIL": "사용자가 입력한 수집 시각을 기준으로 한 기록 공백입니다. 수집 전 로그 회전·누락 가능성이 있습니다.",
    "MULTI_LOG_TAIL": "헬스체크와 Job의 기록 공백이 겹치지만 작업대상이 없었던 경우를 배제할 수 없습니다.",
    "LIFECYCLE": "시작·종료 문자열을 관측했을 뿐 정상/비정상 종료 여부는 확인할 수 없습니다.",
}
NEXT_CHECKS = {
    "SEND_JOB_DELAY": "동일 시각의 DB 실행시간, SOCKET 단계 시간 및 작업대상건수를 비교",
    "RESULT_JOB_DELAY": "HTTP IN/OUT, DB 갱신시간, 결과 이관 지연 여부를 시간순으로 확인",
    "OTHER_JOB_DELAY": "해당 Job 설정, 작업대상건수, 동시 실행 로그를 확인",
    "TRANSPORT_DELAY": "TCP 상태·응답 지연·해당 단계 포함 로직을 확인",
    "DB_SQL_DELAY": "DB 세션 대기, Lock, 실행계획 및 장시간 SQL을 별도로 확인",
    "SQL_ERROR": "DBMS 오류 코드, 재시도 여부 및 트랜잭션 결과 확인",
    "TRANSPORT_ERROR": "대상 연결 상태, 연결·읽기 시간초과 및 재시도 여부 확인",
    "GENERAL_EXCEPTION": "예외 유형과 발생 전후 Job 및 Agent 상태 확인",
    "JOB_RUNNING_STATE": "반복 실행 시각, 선행 Job 종료 기록, JVM Thread Dump 확인",
    "HEALTHCHECK_GAP": "수집 시각·로그 완전성·프로세스 생존·스케줄러 상태 검증",
    "PERIODIC_JOB_GAP": "프로세스 상태, 작업대상 존재 여부, Job 스케줄·Thread Dump 확인",
    "AGENT_EXIT_SEEN": "종료 직전 오류와 실제 OS 프로세스 재시작 여부 확인",
    "AGENT_START_SEEN": "정상 기동과 Job 스케줄 등록 여부 확인",
}


def safe_time(value: Any) -> str | None:
    if not isinstance(value, str) or not SAFE_TIME.fullmatch(value):
        return None
    try:
        return datetime.fromisoformat(value).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    except ValueError:
        return None


def source_map(manifest: dict[str, Any]) -> dict[str, dict[str, str]]:
    result = {}
    for item in manifest.get("files", []):
        fid = item.get("file_id")
        name = item.get("storage_name")
        kind = item.get("kind")
        if isinstance(fid, str) and SAFE_ID.fullmatch(fid):
            result[fid] = {
                "display": name if isinstance(name, str) and SAFE_FILE.fullmatch(name) else (kind if kind in {"job", "debug", "dbwrap", "err", "info"} else "미분류") + " 로그",
                "kind": kind if kind in {"job", "debug", "dbwrap", "err", "info", "agent_ini", "unknown"} else "unknown",
            }
    return result


def evidence_rows(finding: dict[str, Any], manifest: dict[str, Any]) -> list[dict[str, Any]]:
    names = source_map(manifest)
    rows = []
    for ref in finding.get("evidence_refs", [])[:15]:
        fid = ref.get("file_id")
        if fid not in names:
            continue
        start, end = ref.get("line_start"), ref.get("line_end")
        if not (isinstance(start, int) and isinstance(end, int) and 1 <= start <= end):
            continue
        when = safe_time(ref.get("occurred_at"))
        raw_clock = ref.get("clock")
        label = when or ("날짜 미확인 · " + raw_clock if isinstance(raw_clock, str) and SAFE_CLOCK.fullmatch(raw_clock) else "발생시각 미확인")
        rows.append({
            "시각": label, "로그 파일": names[fid]["display"],
            "종류": names[fid]["kind"], "근거": f"{fid}:{start}-{end}",
            "file_id": fid, "line_start": start, "line_end": end,
            "occurred_at": ref.get("occurred_at") if when else None,
            "start_at": safe_time(ref.get("start_at")),
        })
    return rows


def metrics_rows(finding: dict[str, Any]) -> list[dict[str, str]]:
    data = finding.get("measure") or {}
    rows = []
    for field, (label, unit) in MEASUREMENTS.items():
        value = data.get(field)
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            rows.append({"항목": label, "값": f"{value:,.3f}".rstrip("0").rstrip(".") + f" {unit}"})
    job = data.get("job_name")
    if isinstance(job, str) and SAFE_JOB.fullmatch(job):
        rows.insert(0, {"항목": "대상 Job", "값": job})
    stmt = data.get("statement_kind")
    if stmt in {"EQ", "EU", "EB"}:
        rows.insert(0, {"항목": "SQL 유형", "값": stmt})
    collected = safe_time(data.get("collected_at"))
    if collected:
        rows.append({"항목": "사용자 입력 수집시각", "값": collected})
    return rows


def finding_row(finding: dict[str, Any], manifest: dict[str, Any]) -> dict[str, str]:
    evidences = evidence_rows(finding, manifest)
    first = evidences[0] if evidences else None
    code = finding.get("signal_code")
    return {
        "번호": finding.get("finding_id") if re.fullmatch(r"F-\d{4}", str(finding.get("finding_id"))) else "-",
        "발생시각": first["시각"] if first else "발생시각 미확인",
        "탐지 항목": SAFE_CODES.get(code, "알 수 없는 신호"),
        "주요 수치": " · ".join(x["값"] for x in metrics_rows(finding) if x["항목"] in
                           {"최대 처리시간", "최대 단계시간", "최대 DB 실행시간", "최대 관측 공백", "수집시각까지 공백"}) or "—",
        "판정": "관측 기록" if finding.get("statement_type") == "observed" else "이상 징후",
        "근거 파일": ", ".join(dict.fromkeys(e["로그 파일"] for e in evidences)) or "확인 불가",
        "근거": first["근거"] if first else "—",
    }


def finding_detail(finding: dict[str, Any], manifest: dict[str, Any]) -> dict[str, Any]:
    code = finding.get("signal_code")
    ev = evidence_rows(finding, manifest)
    times = [row["시각"] for row in ev if not row["시각"].startswith(("날짜", "발생시각"))]
    return {
        "title": SAFE_CODES.get(code, "미분류 신호"),
        "signal": code if code in SAFE_CODES else "UNKNOWN",
        "rule": finding.get("rule_id") if finding.get("rule_id") in RULE_LIMITS else "UNKNOWN",
        "statement": "직접 관측된 기록" if finding.get("statement_type") == "observed" else "규칙에 따른 이상 징후",
        "confidence": {"high": "높음", "medium": "보통", "low": "낮음"}.get(finding.get("confidence"), "확인 불가"),
        "representative_at": safe_time(finding.get("representative_at")) or (times[0] if times else "발생시각 미확인"),
        "evidence_range": (min(times), max(times)) if times else None,
        "range_note": "표본으로 저장한 근거의 시간 범위이며 전체 발생 구간을 뜻하지 않습니다.",
        "measurements": metrics_rows(finding),
        "evidence": ev,
        "limitation": RULE_LIMITS.get(finding.get("rule_id"), "원인은 확정되지 않았습니다."),
        "next_check": NEXT_CHECKS.get(code, "추가 로그와 관련 서비스 상태를 확인"),
        "observed": SAFE_CODES.get(code, "알 수 없는 신호") + " 기록 또는 임계값 초과가 확인되었습니다.",
        "sampling_note": f"대표 근거 {len(ev)}건 표시. 모든 개별 발생의 목록이 아닐 수 있습니다.",
    }
