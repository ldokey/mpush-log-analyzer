"""Human-facing projection of evidence-based MPushAgent findings.

Raw data objects are kept for machine processing, while this layer provides
safe labels, occurrence-time context and clear investigation explanations.
"""
from __future__ import annotations
from datetime import datetime
import re
from typing import Any

from .security import detect_sensitive_patterns

SAFE_FILENAME = re.compile(r"^(?:debug|job|dbwrap|info|err|agent_ini|unknown)_[0-9]{2}\.(?:log|txt|ini)$")
SAFE_JOB = re.compile(r"^[A-Z][A-Z0-9_]{2,63}$")
SAFE_REF = re.compile(r"^file_[0-9]{2}$")

SIGNALS = {
    "SEND_JOB_DELAY": ("발송 Job 처리 지연", "발송 Job의 완료 처리시간이 탐지 기준 이상입니다.", "Job 처리량, SOCKET·FILE·SELECT 각 단계 및 같은 시각 DB 처리시간 확인"),
    "RESULT_JOB_DELAY": ("결과 수신 Job 처리 지연", "결과 수신 Job의 처리시간이 탐지 기준 이상입니다.", "HTTP IN·DB·HTTP OUT 단계, 결과 이관 처리 및 DB 상태 확인"),
    "OTHER_JOB_DELAY": ("기타 Job 처리 지연", "등록된 Job의 실행 처리시간이 기준을 초과했습니다.", "해당 Job의 실행 주기와 단계별 지연 확인"),
    "TRANSPORT_DELAY": ("통신 관련 단계 처리 지연", "SOCKET 또는 HTTP 작업 구간의 기록된 처리시간이 길어졌습니다.", "네트워크 연결·서버 응답·동일 구간의 후속 내부 처리 분리 확인"),
    "DB_SQL_DELAY": ("SQL 처리 지연", "DBWrap에 SQL 실행 지연 시간이 기록됐습니다.", "해당 시각 DB 세션, 대기, Lock 가능성 및 실행계획 확인"),
    "SQL_ERROR": ("SQL 오류 기록", "SQL 실패 또는 SQL 계열 예외가 명시적으로 관측됐습니다.", "DB 오류 코드, 실패 SQL 종류, 재시도 여부를 원본에서 별도 확인"),
    "TRANSPORT_ERROR": ("통신 오류 기록", "Socket/HTTP 관련 예외가 기록됐습니다.", "연결 실패·타임아웃·실제 통신 구간 및 전후 이벤트 확인"),
    "GENERAL_EXCEPTION": ("기타 예외 기록", "분류되지 않은 명시적 예외가 기록됐습니다.", "예외 종류와 최초 발생 위치, 전후 Job 상태 확인"),
    "JOB_RUNNING_STATE": ("Job 중복 실행 건너뜀", "Job이 RUNNING 상태여서 예정된 재실행을 건너뛴 로그가 반복됩니다.", "이전 Job 완료 여부, Quartz 실행 상태, JVM Thread Dump 확인"),
    "HEALTHCHECK_GAP": ("헬스체크 기록 공백", "관측된 헬스체크 주기보다 긴 기록 공백이 확인됐습니다.", "실제 수집 시각, 로그 완전성, 스케줄러·프로세스 상태 확인"),
    "PERIODIC_JOB_GAP": ("Job·헬스체크 기록 공백", "헬스체크와 Job 로그의 마지막 기록 이후 공백이 함께 관측됩니다.", "미처리 발송 데이터 유무와 실제 프로세스 상태를 별도 확인"),
    "AGENT_EXIT_SEEN": ("Agent 종료 로그", "Agent 종료를 나타내는 문구가 기록됐습니다.", "운영자 정상 종료 여부와 실제 프로세스 수명주기 확인"),
    "AGENT_START_SEEN": ("Agent 시작 로그", "Agent 시작을 나타내는 문구가 기록됐습니다.", "동일 인스턴스 시작인지, 기동 완료·연결 성공 여부 확인"),
}
LEVELS = {"warning": "주의", "info": "정보"}
STATEMENTS = {"observed": "직접 관측", "indicator": "이상 징후", "hypothesis": "가설"}
CONFIDENCE = {"high": "근거 충분", "medium": "일부 근거", "low": "제한적"}
TIME_DATE_SOURCES = {
    "filename_hint": "파일명에서 추정한 날짜",
    "reference_date": "사용자가 지정한 기준 날짜",
    "unknown": "날짜 미확인",
}
UNITS = {
    "max_seconds": ("최대 처리시간", "초"),
    "threshold_seconds": ("절대 탐지 기준", "초"),
    "effective_threshold_seconds": ("실제 판정 기준", "초"),
    "baseline_median_seconds": ("동일 작업량 중앙값", "초"),
    "baseline_sample_count": ("동일 작업량 비교 표본수", "건"),
    "max_stage_seconds": ("최대 단계시간", "초"),
    "max_laptime_ms": ("최대 SQL 실행시간", "ms"),
    "threshold_ms": ("SQL 임계값", "ms"),
    "max_gap_seconds": ("최대 기록 공백", "초"),
    "baseline_seconds": ("관측된 통상 주기", "초"),
    "estimated_interval_seconds": ("추정 헬스체크 주기", "초"),
    "tail_gap_seconds": ("수집 시각까지 기록 공백", "초"),
    "healthcheck_tail_seconds": ("헬스체크 마지막 기록부터", "초"),
    "job_tail_seconds": ("Job 마지막 기록부터", "초"),
    "observed_count": ("관측된 실행/건수", "건"),
    "count": ("관측된 오류 건수", "건"),
    "above_absolute_count": ("절대 기준 초과 횟수", "회"),
    "above_threshold_count": ("탐지 기준 초과 횟수", "회"),
    "gap_count": ("기록 공백 검출 수", "건"),
    "window_seconds": ("반복 탐지 구간", "초"),
}
EXPLANATIONS = {
    "SQL_DURATION": "임계값 이상의 SQL 실행 구간을 탐지했습니다. DB Lock 발생이 확인된 것은 아닙니다.",
    "JOB_DURATION": "완료된 Job 처리시간을 기준으로 측정했습니다. 느린 실행이 최종 발송 실패를 의미하지는 않습니다.",
    "TRANSPORT_STEP": "SOCKET/HTTP로 표시된 내부 처리 구간의 시간입니다. 실제 네트워크 왕복시간만을 의미하지 않을 수 있습니다.",
    "HEALTHCHECK_INTERVAL": "로그 내 두 헬스체크 기록 사이 시간 차이를 비교했습니다. 로그 누락·회전 가능성도 있습니다.",
    "HEALTHCHECK_TAIL": "마지막으로 관측된 로그 시각과 사용자가 입력한 수집 시각의 차이입니다. 장애 발생시각이 아닙니다.",
    "MULTI_LOG_TAIL": "헬스체크와 Job 로그가 모두 수집 시각보다 이전에 끝났습니다. 작업이 없어서 Job 로그가 없을 가능성도 있습니다.",
    "REPEATED_JOB_SKIP": "반복 실행 건너뛰기를 감지했습니다. Quartz 중복 실행 방지 규칙에 따른 정상 동작일 가능성도 있습니다.",
    "EXPLICIT_ERROR": "원본에 명시적인 오류가 있습니다. 오류 유형만 식별했으며 근본 원인은 미확정입니다.",
    "LIFECYCLE": "기동/종료 문자열 관측 사실이며, 장애를 뜻하는 것은 아닙니다.",
}


def file_labels(manifest: dict[str, Any]) -> dict[str, str]:
    """Keep internal file ID as a stable traceability suffix, never a raw filename."""
    labels = {}
    for entry in manifest.get("files", []):
        fid = entry.get("file_id")
        if not isinstance(fid, str) or not SAFE_REF.fullmatch(fid):
            continue
        filename = entry.get("storage_name")
        if not isinstance(filename, str) or not SAFE_FILENAME.fullmatch(filename):
            filename = str(entry.get("kind", "log")).upper() + " 로그"
        labels[fid] = f"{filename} ({fid})"
    return labels


def file_label(file_id: str, manifest: dict[str, Any]) -> str:
    return file_labels(manifest).get(file_id, "자료 미확인")


def format_timestamp(value: str | None, *, clock: str | None = None,
                     quality: str | None = None, date_source: str | None = None) -> str:
    if isinstance(value, str):
        try:
            normalized = datetime.fromisoformat(value)
            formatted = normalized.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
            suffix = " (자정 경과 추정)" if quality == "midnight_inferred" else ""
            return formatted + suffix
        except ValueError:
            pass
    if isinstance(clock, str) and re.fullmatch(r"\d{2}:\d{2}:\d{2}\.\d{3}", clock):
        return f"날짜 미확인 · {clock}"
    return "시각 확인 불가"


def measure_rows(finding: dict[str, Any]) -> list[dict[str, str]]:
    measure = finding.get("measure") or {}
    rows = []
    for key, (label, unit) in UNITS.items():
        value = measure.get(key)
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            display = f"{value:,g}" if isinstance(value, int) else f"{value:,.3f}".rstrip("0").rstrip(".")
            rows.append({"항목": label, "측정값": display + " " + unit})
    for key in ("job_name", "statement_kind"):
        value = measure.get(key)
        if isinstance(value, str) and re.fullmatch(r"[A-Z0-9_]{2,64}", value):
            rows.insert(0, {"항목": "Job" if key == "job_name" else "SQL 유형", "측정값": value})
    return rows


def _ref_time(ref: dict[str, Any]) -> str:
    return format_timestamp(ref.get("occurred_at"), clock=ref.get("clock"),
                            quality=ref.get("time_quality"), date_source=ref.get("time_date_source"))


def evidence_rows(finding: dict[str, Any], manifest: dict[str, Any]) -> list[dict[str, Any]]:
    result = []
    for ref in finding.get("evidence_refs", [])[:15]:
        fid = ref.get("file_id")
        if not isinstance(fid, str) or not SAFE_REF.fullmatch(fid):
            continue
        start, end = ref.get("line_start"), ref.get("line_end")
        if not (isinstance(start, int) and isinstance(end, int) and start > 0 and end >= start):
            continue
        result.append({
            "근거시각": _ref_time(ref),
            "근거 파일": file_label(fid, manifest),
            "줄": f"{start:,}–{end:,}",
            "원본 ID": fid,
            "시작행": start, "끝행": end,
            "날짜 근거": TIME_DATE_SOURCES.get(ref.get("time_date_source"), "기존 분석 값"),
            "관측 구분": "완료 기록" if ref.get("event_type") == "job_run" else "로그 기록",
            "로그상 시작": format_timestamp(ref.get("start_at")) if ref.get("start_at") else "-",
            "계산상 시작": format_timestamp(ref.get("calculated_start_at")) if ref.get("calculated_start_at") else "-",
            "시작시각 주의": (
                "실행시간 기준 역산, 시작 로그와 불일치"
                if ref.get("start_time_quality") == "duration_clock_conflict"
                else "완료시각−소요시간의 계산값"
                if ref.get("calculated_start_at") else "-"
            ),
        })
    return result


def time_information(finding: dict[str, Any]) -> dict[str, str]:
    context = finding.get("time_context") or {}
    refs = finding.get("evidence_refs") or []
    kind = context.get("kind")
    if kind in {"last_observation_to_collection", "parallel_tail_observations"}:
        return {
            "기준": "마지막 관측 기록 → 사용자 입력 수집시각 (장애 발생시각 아님)",
            "시작": format_timestamp(context.get("start_at")),
            "끝": format_timestamp(context.get("end_at")),
            "신뢰 안내": "끝 시각은 장비 로그가 아니라 사용자가 입력한 수집 시각입니다.",
        }
    # A Job finding is anchored to a completed run, NOT necessarily the time
    # when a customer-visible failure began. A confirmed clock start is distinct
    # from the duration-derived estimate and must never replace raw evidence.
    if finding.get("rule_id") in {"JOB_DURATION", "TRANSPORT_STEP"}:
        representative = next((r for r in refs if r.get("event_type") == "job_run"
                               and isinstance(r.get("occurred_at"), str)), None)
        if representative:
            completed = format_timestamp(representative["occurred_at"])
            if representative.get("start_at") and representative.get("start_time_quality") != "duration_clock_conflict":
                return {
                    "기준": "대표 Job 1회 실행 구간 (기록된 시작 → 완료)",
                    "시작": format_timestamp(representative["start_at"]),
                    "끝": completed,
                    "신뢰 안내": "Job 한 번의 처리 구간입니다. 전체 장애 발생시각이나 지속시간은 확인되지 않았습니다.",
                }
            if representative.get("calculated_start_at"):
                return {
                    "기준": "대표 Job 1회 처리 구간 (시작은 소요시간으로 역산)",
                    "시작": format_timestamp(representative["calculated_start_at"]),
                    "끝": completed,
                    "신뢰 안내": "시작시각은 계산값이며 원본 시작 기록과 다를 수 있습니다. 전체 장애 구간은 아닙니다.",
                }
            return {
                "기준": "대표 Job 완료 기록시각 (시작 정보 부족)",
                "시작": "확인 불가", "끝": completed,
                "신뢰 안내": "Job 실행 시작과 장애 발생시각은 확인되지 않았습니다.",
            }
    context = finding.get("time_context") or {}
    if kind == "observed_interval" and isinstance(context.get("start_at"), str) and isinstance(context.get("end_at"), str):
        return {
            "기준": "관측된 대표 헬스체크 간격 (장애 지속시간 아님)",
            "시작": format_timestamp(context["start_at"]),
            "끝": format_timestamp(context["end_at"]),
            "신뢰 안내": "두 로그 기록 사이의 공백입니다. 헬스체크 미기록이 프로세스 종료를 입증하지는 않습니다.",
        }
    stamped = sorted(r.get("occurred_at") for r in refs if isinstance(r.get("occurred_at"), str))
    if stamped:
        first = stamped[0]
        last = stamped[-1]
        label = "대표 근거 기록시각" if len(stamped) == 1 else "제한된 근거 표본의 시간 범위"
        return {
            "기준": label,
            "시작": format_timestamp(first),
            "끝": format_timestamp(last),
            "신뢰 안내": "전체 발생 구간은 아니며 실제로 보관된 대표 근거만 표시합니다.",
        }
    first_ref = refs[0] if refs else {}
    return {
        "기준": "날짜 미확인 로그 기록시각",
        "시작": _ref_time(first_ref),
        "끝": "확인 불가",
        "신뢰 안내": "로그 기준 날짜가 없으므로 발생 날짜를 임의로 계산하지 않았습니다.",
    }


def _measurement(finding: dict[str, Any], key: str) -> float | None:
    value = (finding.get("measure") or {}).get(key)
    if isinstance(value, (int, float)) and not isinstance(value, bool) and 0 <= value <= 1e12:
        return float(value)
    return None


def quantified_reason(finding: dict[str, Any], fallback: str) -> str:
    """Quantitative, safe explanation from numeric data only, never raw log prose."""
    rule = finding.get("rule_id")
    groups = {
        "JOB_DURATION": ("max_seconds", "threshold_seconds", "초", "Job 처리시간"),
        "TRANSPORT_STEP": ("max_stage_seconds", "threshold_seconds", "초", "SOCKET/HTTP 단계시간"),
        "SQL_DURATION": ("max_laptime_ms", "threshold_ms", "ms", "SQL 실행시간"),
    }
    if rule in groups:
        observed_key, threshold_key, unit, subject = groups[rule]
        observed = _measurement(finding, observed_key)
        threshold = (_measurement(finding, "effective_threshold_seconds")
                     if rule == "JOB_DURATION" else None)
        if threshold is None:
            threshold = _measurement(finding, threshold_key)
        if observed is not None and threshold is not None and threshold > 0:
            ratio = observed / threshold
            comparator = "실제 판정 기준" if rule == "JOB_DURATION" else "설정된 탐지 기준"
            return (f"기록된 최대 {subject} {observed:,.3f}{unit}가 {comparator} "
                    f"{threshold:,.3f}{unit}의 약 {ratio:,.1f}배입니다. " + fallback)
    if rule == "HEALTHCHECK_INTERVAL":
        gap = _measurement(finding, "max_gap_seconds")
        baseline = _measurement(finding, "baseline_seconds")
        if gap is not None and baseline is not None and baseline > 0:
            return (f"두 헬스체크 로그 간 최대 {gap:,.1f}초 공백이 관측됐으며, "
                    f"관측 표본의 통상 간격은 약 {baseline:,.1f}초입니다. " + fallback)
    if rule == "HEALTHCHECK_TAIL":
        gap = _measurement(finding, "tail_gap_seconds")
        if gap is not None:
            return (f"마지막 헬스체크 기록부터 사용자가 입력한 수집 시각까지 {gap:,.0f}초입니다. "
                    "이 차이는 장애가 지속된 시간과 다릅니다. " + fallback)
    if rule == "MULTI_LOG_TAIL":
        health = _measurement(finding, "healthcheck_tail_seconds")
        job = _measurement(finding, "job_tail_seconds")
        if health is not None and job is not None:
            return (f"수집 시각 기준 헬스체크 최종 기록은 {health:,.0f}초 전, "
                    f"Job 최종 기록은 {job:,.0f}초 전입니다. " + fallback)
    if rule == "EXPLICIT_ERROR":
        count = _measurement(finding, "count")
        if count is not None:
            return f"명시적인 오류 기록 {count:,.0f}건이 식별됐습니다. " + fallback
    return fallback


def details(finding: dict[str, Any], manifest: dict[str, Any]) -> dict[str, Any]:
    signal = finding.get("signal_code")
    title, observation, next_check = SIGNALS.get(
        signal, ("분류되지 않은 기록", "로그 이상 신호가 기록됐습니다.", "원본 및 관련 로그를 검토하세요.")
    )
    measurements = measure_rows(finding)
    timings = time_information(finding)
    # Never echo an arbitrary description stored in an analysis JSON file.
    # Even a pattern-based privacy filter cannot prove text is disclosure-safe.
    safe_description = "; ".join(
        f"{row['항목']}: {row['측정값']}" for row in measurements[:8]
    )
    return {
        "finding_id": finding.get("finding_id", ""),
        "title": title,
        "signal_code": signal,
        "severity": LEVELS.get(finding.get("severity"), "정보"),
        "statement": STATEMENTS.get(finding.get("statement_type"), "구분 미상"),
        "confidence": CONFIDENCE.get(finding.get("confidence"), "확인 필요"),
        "time": timings,
        "summary": observation,
        "why_flagged": quantified_reason(
            finding, EXPLANATIONS.get(finding.get("rule_id"), "관측된 기록의 탐지 기준을 검토하세요.")
        ),
        "analysis_detail": safe_description[:1200],
        "measurements": measurements,
        "evidence": evidence_rows(finding, manifest),
        "next_check": next_check,
        "limitations": "로그에서 관측된 사실과 분석 신호일 뿐, 장애 원인·프로세스 종료·수신 성공을 확정하지 않습니다.",
    }


def summary_row(finding: dict[str, Any], manifest: dict[str, Any]) -> dict[str, str]:
    full = details(finding, manifest)
    timing = full["time"]
    evidence = full["evidence"]
    value = ", ".join(x["측정값"] for x in full["measurements"]
                      if x["항목"] in {"최대 처리시간", "최대 SQL 실행시간", "수집 시각까지 기록 공백",
                                       "최대 기록 공백", "관측된 오류 건수", "최대 단계시간"})[:2]
    distinct_files = list(dict.fromkeys(e["근거 파일"] for e in evidence))
    short_files = (distinct_files[0] + f" 외 {len(distinct_files) - 1}개"
                   if len(distinct_files) > 1 else distinct_files[0] if distinct_files else "미확인")
    return {
        "ID": str(full["finding_id"]),
        "판정": str(full["statement"]),
        "심각도": str(full["severity"]),
        "대표/기준 시각": timing["시작"],
        "시간 의미": timing["기준"],
        "이상 항목": str(full["title"]),
        "주요 수치": value or "기록 관측",
        "근거 파일": short_files,
        "근거 수": str(len(evidence)),
    }
