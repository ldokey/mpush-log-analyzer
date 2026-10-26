"""Deterministic, privacy-minimized Korean reports, using only allowlisted values."""
from __future__ import annotations
from .fs_compat import private_file_mode
from html import escape as html_escape
import json
import os
from pathlib import Path
import re
import tempfile
from typing import Any
from .pipeline import _get_manifest
from .finding_view import finding_detail

SIGNAL_LABELS = {
    "SEND_JOB_DELAY": "발송 Job 처리시간 증가",
    "RESULT_JOB_DELAY": "발송결과 Job 처리시간 증가",
    "OTHER_JOB_DELAY": "기타 Job 처리시간 증가",
    "TRANSPORT_DELAY": "SOCKET/HTTP 단계 처리시간 증가",
    "DB_SQL_DELAY": "SQL 실행시간 증가",
    "SQL_ERROR": "명시적 SQL 오류 기록",
    "TRANSPORT_ERROR": "명시적 통신 오류 기록",
    "GENERAL_EXCEPTION": "명시적인 기타 예외 기록",
    "JOB_RUNNING_STATE": "반복적인 RUNNING 상태 기록",
    "HEALTHCHECK_GAP": "헬스체크 기록 간격 증가",
    "PERIODIC_JOB_GAP": "주기 작업 기록 공백",
    "AGENT_EXIT_SEEN": "Agent 종료 기록",
    "AGENT_START_SEEN": "Agent 시작 기록",
}
JOB_NAMES = re.compile(r"^[A-Z][A-Z0-9_]{2,63}$")
CASE_ID = re.compile(r"^MPA-CASE-\d{6}$")


def _safe_number(value: Any) -> str:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return "미확인"
    return f"{value:,.3f}".rstrip("0").rstrip(".") if isinstance(value, float) else f"{value:,}"


def _position(ref: dict[str, Any]) -> str:
    fid, start, end = ref.get("file_id"), ref.get("line_start"), ref.get("line_end")
    if not (isinstance(fid, str) and re.fullmatch(r"file_\d{2}", fid)
            and isinstance(start, int) and isinstance(end, int)
            and 1 <= start <= end):
        return "근거 위치 미확인"
    return f"{fid} {start}-{end}행"


def _safe_version(raw: Any) -> str:
    return raw if raw in {"3.2", "3.3", "auto"} else "미확인"


def _safe_analysis_id(raw: Any) -> str:
    if isinstance(raw, str) and re.fullmatch(r"analysis_[a-f0-9]{32}", raw):
        return raw
    raise ValueError("분석 ID가 유효하지 않습니다.")


def _scope_value(item: dict[str, Any]) -> dict[str, Any]:
    kind = item.get("kind")
    return {
        "file_id": item.get("file_id") if re.fullmatch(r"file_\d{2}", str(item.get("file_id"))) else "unknown",
        "kind": kind if kind in {"debug", "job", "dbwrap", "info", "err", "agent_ini", "unknown"} else "unknown",
        "completeness": item.get("completeness") if item.get("completeness") in {"full", "partial", "unknown"} else "unknown",
        "date": item.get("date_hint") if re.fullmatch(r"20\d{2}-\d{2}-\d{2}", str(item.get("date_hint"))) else None,
        "first": item.get("first_time_hint") if re.fullmatch(r"\d{2}:\d{2}:\d{2}(?:\.\d{3})?", str(item.get("first_time_hint"))) else None,
        "last": item.get("last_time_hint") if re.fullmatch(r"\d{2}:\d{2}:\d{2}(?:\.\d{3})?", str(item.get("last_time_hint"))) else None,
    }


def _checks(findings: list[dict[str, Any]]) -> list[str]:
    found = {f["signal"] for f in findings}
    checks = []
    if found & {"HEALTHCHECK_GAP", "PERIODIC_JOB_GAP", "JOB_RUNNING_STATE"}:
        checks.append("현상 재발 시 Agent 재기동 전 프로세스 상태와 JVM Thread Dump를 확보해 주세요.")
    if found & {"DB_SQL_DELAY", "SQL_ERROR"}:
        checks.append("해당 시각 DB 장시간 실행 쿼리, 세션 대기 및 Lock 여부를 확인해 주세요.")
    if found & {"TRANSPORT_DELAY", "TRANSPORT_ERROR"}:
        checks.append("해당 시각 SOCKET/HTTP 통신 세션 및 응답 지연 여부를 확인해 주세요.")
    if found & {"SEND_JOB_DELAY", "RESULT_JOB_DELAY", "OTHER_JOB_DELAY"}:
        checks.append("지연 Job과 같은 시간대의 DB·통신·헬스체크 기록을 함께 확인해 주세요.")
    if not checks:
        checks.append("정확한 장애 시각과 메시지 처리 상태를 확인하고 해당 시간대의 추가 로그를 확보해 주세요.")
    return checks


def report_data(result: dict[str, Any], matches: dict[str, Any],
                manifest: dict[str, Any]) -> dict[str, Any]:
    analysis_id = _safe_analysis_id(result.get("analysis_id"))
    if manifest.get("analysis_id") != analysis_id or matches.get("analysis_id") != analysis_id:
        raise ValueError("분석 결과 파일의 식별자가 일치하지 않습니다.")
    metrics = result.get("metrics", {})
    jobs = []
    for key, row in sorted(metrics.get("job_runs", {}).items()):
        if not JOB_NAMES.fullmatch(key):
            continue
        jobs.append({
            "job": key, "executions": row.get("runs") if isinstance(row.get("runs"), int) else 0,
            "completed_executions": row.get("completed") if isinstance(row.get("completed"), int) else 0,
            "target_count": row.get("target_count_total") if isinstance(row.get("target_count_total"), int) else 0,
            "max_duration_seconds": row.get("max_duration_seconds") if isinstance(row.get("max_duration_seconds"), (int, float)) else None,
        })
    db = metrics.get("db_executions", {})
    findings = []
    for f in result.get("findings", [])[:80]:
        code = f.get("signal_code")
        if code not in SIGNAL_LABELS:
            continue
        refs = [_position(r) for r in f.get("evidence_refs", [])[:5]]
        statement = f.get("statement_type") if f.get("statement_type") in {"observed", "indicator", "hypothesis"} else "indicator"
        measure = f.get("measure") or {}
        numeric_measure = {
            k: v for k, v in sorted(measure.items())
            if k in {"max_seconds", "max_laptime_ms", "max_stage_seconds", "max_gap_seconds",
                     "tail_gap_seconds", "above_absolute_count", "above_threshold_count",
                     "threshold_seconds", "threshold_ms", "gap_count", "observed_count", "count"}
            and isinstance(v, (int, float)) and not isinstance(v, bool)
        }
        detail = finding_detail(f, manifest)
        findings.append({
            "signal": code,
            "title": SIGNAL_LABELS[code],
            "statement_type": statement,
            "severity": f.get("severity") if f.get("severity") in {"warning", "info"} else "info",
            "measure": numeric_measure,
            "evidence_locations": refs,
            "representative_at": detail["representative_at"],
            "evidence_time_range": detail["evidence_range"],
            "evidence": [{
                "when":e["시각"],"file":e["로그 파일"],"position":e["근거"],
                "job_start_at":e["start_at"]
            } for e in detail["evidence"]],
            "interpretation_limit": detail["limitation"],
            "next_check": detail["next_check"],
            "sampling_note": detail["sampling_note"],
        })
    related = []
    for case in matches.get("matched_cases", [])[:10]:
        cid = case.get("case_id")
        if not isinstance(cid, str) or not CASE_ID.fullmatch(cid):
            continue
        related.append({
            "case_id": cid,
            "revision": case.get("revision") if isinstance(case.get("revision"), int) else 1,
            "status": case.get("result_type") if case.get("result_type") in {"reference_only", "verified_solution"} else "reference_only",
            "matching_signals": [
                sig for sig in (
                    case.get("matched_required_signals", []) + case.get("matched_supporting_signals", [])
                ) if sig in SIGNAL_LABELS
            ],
        })
    scope = [_scope_value(x) for x in manifest.get("files", [])]
    collected = manifest.get("collected_at")
    capture_time = (collected if isinstance(collected, str) and
                    re.fullmatch(r"\d{4}-\d{2}-\d{2}T[\d:.]+[+-]\d{2}:\d{2}", collected) else None)
    return {
        "schema_version": "1.0",
        "analysis_id": analysis_id,
        "agent_version": _safe_version(manifest.get("agent_version")),
        "capture_time": capture_time,
        "analysis_status": result.get("analysis_status") if result.get("analysis_status") in {"complete", "partial", "pending"} else "partial",
        "source_files": scope,
        "statistics": {
            "events_extracted": metrics.get("events_total") if isinstance(metrics.get("events_total"), int) else 0,
            "jobs": jobs,
            "sql_executions": db.get("runs") if isinstance(db.get("runs"), int) else 0,
            "cns_request_accepted": metrics.get("cns_request_responses", {}).get("S", 0),
            "max_sql_laptime_ms": db.get("max_laptime_ms") if isinstance(db.get("max_laptime_ms"), (int, float)) else None,
        },
        "findings": findings,
        "related_cases": related,
        "recommended_checks": _checks(findings),
        "limitations": [
            "CNS RESPONSE_CODE=S는 발송 요청 수락 기록이며 최종 수신 성공이 아닙니다.",
            "오류 기록 부재만으로 정상 가동을 확정할 수 없습니다.",
            "Job 기록이 없거나 끊겼다는 사실만으로 프로세스 종료를 확정할 수 없습니다.",
            "DB·SOCKET·HTTP 처리시간 증가만으로 외부 환경 장애나 Agent 결함을 확정할 수 없습니다.",
            "분석 범위와 로그 완전성에 따라 판단 가능한 사실이 제한됩니다.",
        ],
    }


def to_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# MPushAgent 로그 분석 보고서", "",
        f"- 분석 ID: {report['analysis_id']}",
        f"- Agent 버전: {report['agent_version']}",
        f"- 분석 범위: {report['analysis_status']}",
        f"- 로그 수집 시각: {report['capture_time'] or '미입력'}", "",
        "## 1. 분석 자료", "",
        "| 파일 ID | 유형 | 원본 완전성 | 기록 시작 | 기록 종료 |",
        "|---|---|---|---|---|",
    ]
    for row in report["source_files"]:
        lines.append(f"| {row['file_id']} | {row['kind']} | {row['completeness']} | {row['first'] or '-'} | {row['last'] or '-'} |")
    stats = report["statistics"]
    lines.extend([
        "", "## 2. 처리 현황", "",
        f"- 추출 이벤트: {_safe_number(stats['events_extracted'])}건",
        f"- DB 실행 기록: {_safe_number(stats['sql_executions'])}건",
        f"- CNS 발송 요청 수락(RESPONSE_CODE=S): {_safe_number(stats['cns_request_accepted'])}건",
        "- RESPONSE_CODE=S는 CNS 측 요청 수락이며 수신자 전달 성공을 의미하지 않습니다.", "",
        "| Job | 완료 실행 | 처리대상 수 | 최대 처리시간(초) |",
        "|---|---:|---:|---:|"
    ])
    for job in stats["jobs"]:
        lines.append(f"| {job['job']} | {_safe_number(job['completed_executions'])} | {_safe_number(job['target_count'])} | {_safe_number(job['max_duration_seconds'])} |")
    lines.extend(["", "## 3. 확인된 이상 징후", ""])
    if not report["findings"]:
        lines.append("설정된 탐지 규칙에 해당하는 이상 징후가 없습니다. 로그의 정상 동작을 보증하는 의미는 아닙니다.")
    for i, f in enumerate(report["findings"], 1):
        nums = ", ".join(f"{k}={_safe_number(v)}" for k, v in f["measure"].items())
        refs = "; ".join(f["evidence_locations"]) or "근거 위치 미확인"
        lines.extend([
            f"{i}. **{f['title']}** ({f['signal']}, {f['statement_type']})",
            f"   - 대표 발생시각: {f['representative_at']}",
            f"   - 관측 수치: {nums or '별도 수치 없음'}",
            f"   - 근거: {refs}",
        ])
        for ev in f["evidence"]:
            lines.append(f"   - {ev['when']} / {ev['file']} / {ev['position']}")
        lines.extend([
            f"   - 해석 한계: {f['interpretation_limit']}",
            f"   - 추가 확인: {f['next_check']}",
            f"   - 표본 제한: {f['sampling_note']}",
        ])
    lines.extend(["", "## 4. 관련 기존 사례", ""])
    if report["related_cases"]:
        for case in report["related_cases"]:
            status = "검증된 기존 해결 사례" if case["status"] == "verified_solution" else "참고용 사례(원인 미확정)"
            lines.append(f"- {case['case_id']} r{case['revision']}: {status}; 일치 신호: {', '.join(case['matching_signals'])}")
    else:
        lines.append("매칭되는 승인 사례가 없습니다.")
    lines.extend(["", "## 5. 추가 확인사항", ""])
    for item in report["recommended_checks"]:
        lines.append("- " + item)
    lines.extend(["", "## 6. 분석 한계", ""])
    for limitation in report["limitations"]:
        lines.append("- " + limitation)
    lines.append("")
    return "\n".join(lines)


def to_html(report: dict[str, Any]) -> str:
    """Semantic, printable static HTML with escaped source-derived values."""
    def h(value: Any) -> str:
        return html_escape(str(value), quote=True)

    def table(headers: list[str], rows: list[list[Any]]) -> str:
        head = "".join("<th>" + h(col) + "</th>" for col in headers)
        body = "".join(
            "<tr>" + "".join("<td>" + h(cell if cell is not None else "-") + "</td>" for cell in row) + "</tr>"
            for row in rows
        )
        return "<div class='tablewrap'><table><thead><tr>" + head + "</tr></thead><tbody>" + body + "</tbody></table></div>"

    scopes = [[f["file_id"], f["kind"], f["completeness"],
               f["first"] or "-", f["last"] or "-"] for f in report["source_files"]]
    stats = report["statistics"]
    jobs = [[x["job"], _safe_number(x["completed_executions"]),
             _safe_number(x["target_count"]), _safe_number(x["max_duration_seconds"])]
            for x in stats["jobs"]]
    findings = []
    for f in report["findings"]:
        nums = ", ".join(f"{k}: {_safe_number(v)}" for k, v in f["measure"].items())
        refs = ", ".join(f["evidence_locations"]) or "근거 위치 미확인"
        findings.append(
            "<article class='finding'><h3>" + h(f["title"]) +
            " <span class='code'>" + h(f["signal"]) + "</span></h3>"
            "<p class='muted'>판정: " + h(f["statement_type"]) +
            " · 관측 수치: " + h(nums or "별도 수치 없음") +
            "</p><p>대표 발생시각: " + h(f["representative_at"]) +
            "</p><p>원본 근거: " + h(refs) +
            "</p><p>판단 한계: " + h(f["interpretation_limit"]) +
            "</p><p>추가 확인: " + h(f["next_check"]) + "</p></article>"
        )
    cases = [
        "<li>" + h(x["case_id"]) + " r" + h(x["revision"]) +
        " — " + ("해결 검증 사례" if x["status"] == "verified_solution" else "참고용 사례") +
        " · 일치 신호: " + h(", ".join(x["matching_signals"])) + "</li>"
        for x in report["related_cases"]
    ]
    checks = "".join("<li>" + h(x) + "</li>" for x in report["recommended_checks"])
    limits = "".join("<li>" + h(x) + "</li>" for x in report["limitations"])
    return (
        "<!doctype html><html lang='ko'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        "<meta http-equiv='Content-Security-Policy' content=\"default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'\">"
        "<title>MPushAgent 로그 분석 보고서</title>"
        "<style>"
        "*{box-sizing:border-box}body{margin:0;padding:44px 18px;background:#f3f6fa;color:#263446;"
        "font-family:-apple-system,BlinkMacSystemFont,'Apple SD Gothic Neo','Malgun Gothic',sans-serif}"
        "main{max-width:960px;margin:auto;background:white;border:1px solid #dbe3eb;"
        "border-radius:16px;padding:42px 48px;box-shadow:0 12px 30px rgba(25,45,70,.05)}"
        "header{border-bottom:2px solid #122a44;padding-bottom:24px;margin-bottom:32px}"
        "h1{font-size:26px;color:#122a44;margin:0 0 12px;letter-spacing:-.4px}"
        "h2{font-size:17px;margin:30px 0 13px;border-bottom:1px solid #e2e8ef;padding-bottom:10px}"
        "h3{font-size:14px;margin:0 0 9px}p,li,td,th{font-size:13px;line-height:1.75}"
        ".eyebrow{font-size:12px;font-weight:700;color:#506f93;letter-spacing:1.2px;margin-bottom:8px}"
        ".meta{font-size:13px;color:#526579;margin:7px 0}.muted{color:#627184}"
        ".metrics{display:flex;gap:12px;flex-wrap:wrap;margin:15px 0}"
        ".metric{background:#f7f9fc;border:1px solid #e6ecf2;border-radius:10px;padding:14px;flex:1;min-width:155px}"
        ".metric strong{display:block;font-size:21px;color:#132d49;margin-top:6px}"
        ".tablewrap{width:100%;overflow-x:auto}table{width:100%;border-collapse:collapse}"
        "th{text-align:left;color:#4b5b6f;background:#f7f9fc;font-weight:700}"
        "th,td{border-bottom:1px solid #e7ecf2;padding:9px 10px}"
        ".finding{padding:14px 16px;margin:10px 0;background:#fafbfc;border:1px solid #dfe6ed;"
        "border-left:3px solid #496b91;border-radius:5px}"
        ".finding p{margin:4px 0}.code{font-size:10px;font-weight:600;color:#476b8e}"
        "ul{padding-left:20px;margin:8px 0}li{margin-bottom:7px}"
        ".foot{margin-top:28px;border-top:1px solid #e7ecf2;padding-top:14px;font-size:12px;color:#758394}"
        "@media print{body{background:white;padding:0}main{border:none;box-shadow:none;padding:0}"
        ".finding{break-inside:avoid}h2{break-after:avoid}}"
        "</style></head><body><main>"
        "<header><div class='eyebrow'>MPUSHAGENT · LOG ANALYZER</div>"
        "<h1>로그 분석 보고서</h1>"
        "<p class='meta'>분석 ID: " + h(report["analysis_id"]) + "</p>"
        "<p class='meta'>Agent 버전: " + h(report["agent_version"]) +
        " · 분석 상태: " + h(report["analysis_status"]) +
        " · 수집 시각: " + h(report["capture_time"] or "미입력") + "</p></header>"
        "<section><h2>01. 분석 자료</h2>" +
        table(["파일 ID","종류","원본 완전성","기록 시작","기록 종료"], scopes) +
        "</section><section><h2>02. 처리 현황</h2>"
        "<div class='metrics'><div class='metric'>추출 이벤트<strong>" +
        h(_safe_number(stats["events_extracted"])) +
        "</strong></div><div class='metric'>DB 실행 기록<strong>" +
        h(_safe_number(stats["sql_executions"])) +
        "</strong></div><div class='metric'>CNS 요청 수락<strong>" +
        h(_safe_number(stats["cns_request_accepted"])) +
        "</strong></div></div><p class='muted'>CNS 요청 수락은 최종 수신 성공을 의미하지 않습니다.</p>" +
        table(["Job","완료 실행","작업대상건수","최대 처리시간(초)"], jobs) +
        "</section><section><h2>03. 확인된 이상 징후</h2>" +
        ("".join(findings) or "<p>현재 규칙에서 발견된 이상 징후가 없습니다. 정상 가동 보증은 아닙니다.</p>") +
        "</section><section><h2>04. 관련 기존 사례</h2><ul>" +
        ("".join(cases) or "<li>매칭되는 승인 사례가 없습니다.</li>") +
        "</ul></section><section><h2>05. 추가 확인사항</h2><ul>" + checks +
        "</ul></section><section><h2>06. 분석 한계</h2><ul>" + limits +
        "</ul></section><div class='foot'>본 보고서는 로컬 로그의 확인된 사실과 이상 징후를 정리한 자료입니다."
        " 원인 확정이나 수신자 전달 성공을 보증하지 않습니다.</div></main></body></html>"
    )


def build_exports(result: dict[str, Any], matches: dict[str, Any],
                  manifest: dict[str, Any]) -> dict[str, bytes]:
    report = report_data(result, matches, manifest)
    return {
        "report.md": to_markdown(report).encode("utf-8"),
        "report.html": to_html(report).encode("utf-8"),
        "report.json": (json.dumps(report, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8"),
    }


def save_exports(case_dir: Path, exports: dict[str, bytes]) -> None:
    if case_dir.is_symlink() or not case_dir.is_dir():
        raise ValueError("잘못된 분석 작업 경로입니다.")
    for name, payload in exports.items():
        if name not in {"report.md", "report.html", "report.json"} or len(payload) > 3 * 1024 * 1024:
            raise ValueError("허용되지 않은 보고서 출력 형식 또는 크기입니다.")
        path = case_dir / name
        if path.is_symlink():
            raise ValueError("심볼릭 링크 출력 경로는 허용되지 않습니다.")
        fd, temp_name = tempfile.mkstemp(prefix=f".{name}.",suffix=".pending",dir=case_dir)
        tmp = Path(temp_name)
        try:
            with os.fdopen(fd,"wb") as writer:
                private_file_mode(writer.fileno(),0o600)
                writer.write(payload)
            os.replace(tmp,path)
        finally:
            if tmp.exists():
                tmp.unlink()


def generate_case_exports(case_dir: Path, result: dict[str, Any],
                          matches: dict[str, Any]) -> dict[str, bytes]:
    manifest = _get_manifest(case_dir)
    exports = build_exports(result, matches, manifest)
    save_exports(case_dir, exports)
    return exports
