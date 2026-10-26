"""Readable investigation tables and an evidence-first detail panel.

Machine JSON remains stored for automation; user-facing UI is Korean prose,
tabular metrics, file aliases, and a copy-ready sanitized AI brief.
"""
from __future__ import annotations
from pathlib import Path
import pandas as pd
import streamlit as st
from .finding_view import finding_row, finding_detail
from .ai_brief import build_brief, brief_markdown, brief_json
from .source_view import excerpt


def _show_evidence(case_dir: Path, detail: dict, *, key: str) -> None:
    rows = detail["evidence"]
    if not rows:
        st.info("로그 근거 위치 또는 신뢰할 수 있는 발생시각을 확보하지 못했습니다.")
        return
    st.markdown("#### 근거 로그 목록")
    frame = pd.DataFrame([{
        "발생시각": row["시각"], "로그": row["로그 파일"],
        "원본 위치": row["근거"], "Job 시작": row["start_at"] or "—",
    } for row in rows])
    choice = st.dataframe(
        frame, hide_index=True, use_container_width=True, height=min(325, 82 + 35 * len(rows)),
        key=f"{key}_evidence", on_select="rerun", selection_mode="single-row",
    )
    selected = choice.selection.rows
    index = selected[0] if selected else 0
    row = rows[index]
    st.caption(f"원본 로그: {row['로그 파일']} · {row['근거']} — 내용은 제한된 항목만 마스킹 표시합니다.")
    try:
        safe_excerpt = excerpt(case_dir, row["file_id"], row["line_start"], row["line_end"], context=1)
    except Exception:
        st.warning("원본 무결성 또는 줄번호 확인에 실패했습니다. 표시된 근거 정보만 사용하세요.")
    else:
        safe_text = "\n".join(f"{r['line']:>6}  {r['text']}" for r in safe_excerpt["lines"])
        st.code(safe_text or "표시할 로그가 없습니다.", language=None)


def render_finding_review(
    case_dir: Path, manifest: dict, result: dict, matches: dict, *,
    namespace: str,
) -> None:
    findings = result.get("findings", [])
    st.subheader("탐지된 로그 이상 징후")
    st.caption("시각은 원본 로그에서 확인된 값 또는 입력한 기준 날짜를 사용합니다. 일부 신호는 전체 발생이 아닌 대표 근거 표본만 제공합니다.")
    if not findings:
        st.info("현재 규칙으로 탐지된 이상 징후가 없습니다. 정상 가동의 증거는 아닙니다.")
        return

    visible = [finding_row(x, manifest) for x in findings]
    table = pd.DataFrame(visible)
    selected = st.dataframe(
        table, hide_index=True, use_container_width=True, on_select="rerun",
        selection_mode="single-row", key=f"{namespace}_findings",
        height=min(470, 100 + len(visible) * 36)
    )
    idx = selected.selection.rows[0] if selected.selection.rows else 0
    chosen = findings[idx]
    detail = finding_detail(chosen, manifest)

    st.markdown("### 선택한 항목의 분석 상세")
    st.markdown(f"**{detail['title']}**  ·  {detail['statement']}")
    a, b, c = st.columns(3)
    a.metric("대표 근거 시각", detail["representative_at"])
    b.metric("근거 신뢰도", detail["confidence"])
    c.metric("저장된 근거", f"{len(detail['evidence'])}건")
    st.markdown("#### 기록된 측정값과 탐지 기준")
    if detail["measurements"]:
        st.dataframe(
            pd.DataFrame(detail["measurements"]),
            hide_index=True, use_container_width=True, height=min(380, 76 + 35*len(detail["measurements"]))
        )
    else:
        st.caption("해당 유형에는 별도 수치 또는 임계값이 없습니다.")
    if detail["evidence_range"]:
        st.caption(
            f"저장된 근거 시간 범위: {detail['evidence_range'][0]} ~ {detail['evidence_range'][1]}. "
            + detail["range_note"]
        )
    st.markdown("#### 판단 내용")
    st.write("**관측 내용:** " + detail["observed"])
    st.write("**판단 한계:** " + detail["limitation"])
    st.write("**추가 확인:** " + detail["next_check"])
    st.caption(detail["sampling_note"])
    _show_evidence(case_dir, detail, key=f"{namespace}_{chosen['finding_id']}")

    st.markdown("### AI에 전달할 분석 자료")
    st.caption("원본 SQL·전화번호·고객 메시지·인증 키를 제외한 사실·측정값·근거 위치·판단 한계만 포함합니다.")
    scope = st.radio(
        "자료 범위", ["선택한 이상 징후", "전체 탐지 결과"],
        horizontal=True, key=f"{namespace}_brief_scope"
    )
    target = chosen["finding_id"] if scope == "선택한 이상 징후" else None
    try:
        bundle = build_brief(result, matches, manifest, finding_id=target)
    except ValueError:
        st.warning("AI 분석 자료 생성 조건이 일치하지 않습니다.")
        return
    message = brief_markdown(bundle)
    # st.code includes a native copy action; source never leaves the browser
    # unless the user explicitly copies or downloads this sanitized text.
    st.code(message, language="markdown", wrap_lines=True)
    left, right = st.columns(2)
    with left:
        st.download_button(
            "AI 분석용 Markdown 다운로드", message.encode("utf-8"),
            file_name="mpush_ai_brief.md", mime="text/markdown",
            key=f"{namespace}_md_download", use_container_width=True,
        )
    with right:
        st.download_button(
            "AI 분석용 JSON 다운로드", brief_json(bundle).encode("utf-8"),
            file_name="mpush_ai_brief.json", mime="application/json",
            key=f"{namespace}_json_download", use_container_width=True,
        )
