"""AI handoff notes containing only allowlisted, non-sensitive diagnostic facts.

No external API call. Users inspect a local preview and explicitly copy/download.
Never include raw logs, SQL, message contents, secret values, or unreviewed case prose.
"""
from __future__ import annotations

from typing import Any
import json
import re
from .finding_view import finding_detail, source_map, safe_time

SCHEMA_VERSION = "1.0"
SAFE_CASE = re.compile(r"^MPA-CASE-\d{6}$")


def build_brief(result: dict[str, Any], matches: dict[str, Any],
                manifest: dict[str, Any], *, finding_id: str | None = None) -> dict[str, Any]:
    if result.get("analysis_id") != manifest.get("analysis_id"):
        raise ValueError("분석 ID 불일치")
    findings = result.get("findings", [])
    if finding_id is not None:
        findings = [x for x in findings if x.get("finding_id") == finding_id]
        if not findings:
            raise ValueError("선택한 탐지 항목을 찾지 못했습니다.")
    sources = source_map(manifest)
    chosen = []
    for item in findings[:80]:
        v = finding_detail(item, manifest)
        chosen.append({
            "finding_id": item["finding_id"],
            "signal": v["signal"], "title": v["title"],
            "representative_at": v["representative_at"],
            "sample_range": v["evidence_range"],
            "sample_range_note": v["range_note"],
            "statement": v["statement"], "confidence": v["confidence"],
            "metrics": v["measurements"],
            "evidence": [
                {"when":e["시각"],"file":e["로그 파일"],"file_id":e["file_id"],
                 "line_start":e["line_start"],"line_end":e["line_end"],
                 "job_start_at":e["start_at"]} for e in v["evidence"]
            ],
            "limitation": v["limitation"],"next_check":v["next_check"],
            "sampling_note": v["sampling_note"]
        })
    known_cases = []
    for m in matches.get("matched_cases", [])[:10]:
        cid = m.get("case_id")
        if isinstance(cid, str) and SAFE_CASE.fullmatch(cid):
            known_cases.append({"case_id":cid,
                "review_status": "검증된 기존 해결 사례" if m.get("result_type")=="verified_solution"
                                 else "참고용 미확정 사례"})
    cfg = manifest.get("config_summary") or {}
    dbtype = (cfg.get("dbms") or {}).get("type") if isinstance(cfg.get("dbms"),dict) else None
    if dbtype not in {"mysql","mariadb","oracle","mssql","postgresql","tibero","db2"}:
        dbtype = "확인 불가"
    version = manifest.get("agent_version")
    if version not in {"3.2","3.3"}:
        version = "확인 불가"
    files = []
    for item in manifest.get("files", []):
        fid=item.get("file_id")
        if fid not in sources:
            continue
        files.append({
            "file_id": fid, "display": sources[fid]["display"],
            "kind": sources[fid]["kind"],
            "completeness": item.get("completeness") if item.get("completeness") in {"full","partial","unknown"} else "unknown",
            "date_hint": item.get("date_hint") if isinstance(item.get("date_hint"),str) and re.fullmatch(r"\d{4}-\d{2}-\d{2}",item["date_hint"]) else None,
        })
    raw_collected = manifest.get("collected_at")
    return {
        "schema_version": SCHEMA_VERSION,
        "purpose": "로그 진단을 돕기 위한 비식별 근거 자료",
        "analysis_status": result.get("analysis_status") if result.get("analysis_status") in {"complete","partial","pending"} else "partial",
        "analysis_id": result["analysis_id"],
        "agent_version": version, "dbms": dbtype,
        "collected_at": safe_time(raw_collected),
        "files": files, "findings": chosen,
        "approved_case_refs": known_cases,
        "uncertainty": [
            "이상 신호와 장애의 근본 원인은 동일하지 않습니다.",
            "처리시간 증가는 DB Lock, 통신 장애 또는 Agent 결함을 단독으로 입증하지 않습니다.",
            "CNS RESPONSE_CODE=S는 요청 수락이지 수신자 최종 전달 성공이 아닙니다.",
            "파일 간 동일 Agent 여부, 로그 완전성, 수집시각을 독립적으로 검증해야 합니다.",
            "AI가 추론한 가설은 관측 사실과 분리해 표시해야 합니다.",
            "원본 SQL, 고객 메시지, 수신자 번호 및 인증정보는 이 자료에 포함되지 않습니다.",
        ],
        "questions_for_ai": [
            "직접 관측된 사실과 확인이 필요한 가설을 나누어 분석해 주세요.",
            "가능한 원인을 확정하지 말고 우선순위와 확인 방법을 제시해 주세요.",
            "추가 확보할 로그/DB 세션/Thread Dump와 확인할 시각을 구체적으로 제시해 주세요.",
        ],
    }


def brief_markdown(bundle: dict[str, Any]) -> str:
    lines = [
        "# MPushAgent 장애 조사 — AI 전달용 비식별 근거",
        "",
        f"분석 작업: {bundle['analysis_id']}",
        f"분석 완전성: {bundle['analysis_status']}",
        f"Agent 버전: {bundle['agent_version']} / DBMS: {bundle['dbms']}",
        f"로그 수집 시각: {bundle['collected_at'] or '미입력/미확인'}",
        "",
        "## 분석 파일",
    ]
    for item in bundle["files"]:
        lines.append(
            f"- {item['display']} ({item['file_id']}): 종류={item['kind']}, "
            f"원본 완전성={item['completeness']}, 날짜 힌트={item['date_hint'] or '없음'}"
        )
    lines.append("")
    lines.append("## 이상 신호와 근거")
    if not bundle["findings"]:
        lines.append("탐지된 항목 없음. 정상 동작이 입증된 것은 아닙니다.")
    for f in bundle["findings"]:
        lines += [
            "",f"### {f['finding_id']} · {f['title']} [{f['signal']}]",
            f"- 대표 근거 시각: {f['representative_at']}",
            f"- 판정: {f['statement']}, 신뢰도: {f['confidence']}",
        ]
        if f["sample_range"]:
            lines.append(f"- 저장한 근거 시간 범위: {f['sample_range'][0]} ~ {f['sample_range'][1]}")
            lines.append(f"  ({f['sample_range_note']})")
        for metric in f["metrics"]:
            lines.append(f"- {metric['항목']}: {metric['값']}")
        lines.append("- 출처 (로그 본문은 제외):")
        for e in f["evidence"]:
            row = f"  - {e['when']} · {e['file']} ({e['file_id']}:{e['line_start']}-{e['line_end']})"
            if e["job_start_at"]:
                row += f" · Job 시작 {e['job_start_at']}"
            lines.append(row)
        lines += [
            f"- 해석 한계: {f['limitation']}",
            f"- 추가 확인: {f['next_check']}",
            f"- 표본 제한: {f['sampling_note']}",
        ]
    if bundle["approved_case_refs"]:
        lines += ["","## 관련 승인 사례 (근본 원인 동일 여부 미확인)"]
        for m in bundle["approved_case_refs"]:
            lines.append(f"- {m['case_id']}: {m['review_status']}")
    lines += ["","## 판단 전제 및 한계"] + ["- "+s for s in bundle["uncertainty"]]
    lines += ["","## AI에게 요청할 질문"] + ["- "+s for s in bundle["questions_for_ai"]]
    return "\n".join(lines) + "\n"


def brief_json(bundle: dict[str, Any]) -> str:
    return json.dumps(bundle, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
