"""Evidence UX v3: chronological findings, clock provenance and AI context.

All inputs are generated synthetic logs. No customer originals are used.
"""
from __future__ import annotations

from datetime import datetime, date, timedelta
import json
from pathlib import Path

import pytest

from mpush_analyzer.ai_brief_v2 import _context_events, build_ai_exports
from mpush_analyzer.finding_view_v2 import details, summary_row
from mpush_analyzer.incident_overview import category, finding_time_sort_key, snapshot
from mpush_analyzer.pipeline import _get_manifest
from mpush_analyzer.runner import run_complete_analysis


def _synthetic_case(tmp_path: Path):
    from test_incident_evidence_v2 import create_case
    case = create_case(tmp_path)
    result, matches, _ = run_complete_analysis(case, knowledge_root=tmp_path / "knowledge")
    return case, _get_manifest(case), result, matches


def test_known_job_start_and_end_are_in_anomaly_panel(tmp_path: Path):
    case, manifest, result, _ = _synthetic_case(tmp_path)
    finding = next(f for f in result["findings"]
                   if f.get("rule_id") == "TRANSPORT_STEP")
    shown = details(finding, manifest)
    assert shown["time"]["시작"].startswith("2026-10-15 10:01:12.300")
    assert shown["time"]["끝"].startswith("2026-10-15 10:01:20.300")
    assert "Job 1회" in shown["time"]["기준"]
    assert "전체 장애" in shown["time"]["신뢰 안내"]
    assert "약 1.6배" in shown["why_flagged"]
    assert "기준" in shown["why_flagged"]
    assert summary_row(finding, manifest)["시간 의미"] == shown["time"]["기준"]


def test_heartbeat_interval_uses_exact_observed_pair_not_full_outage(tmp_path: Path):
    case, manifest, result, _ = _synthetic_case(tmp_path)
    gap = next(f for f in result["findings"]
               if f.get("rule_id") == "HEALTHCHECK_INTERVAL")
    assert gap["time_context"]["kind"] == "observed_interval"
    shown = details(gap, manifest)
    assert shown["time"]["시작"].startswith("2026-10-15 10:00:30.001")
    assert shown["time"]["끝"].startswith("2026-10-15 10:01:35.001")
    assert "장애 지속시간 아님" in shown["time"]["기준"]
    assert "통상 간격" in shown["why_flagged"]
    assert "10.0초" in shown["why_flagged"]


def test_summary_dates_separate_collection_time_and_unknown_dates(tmp_path: Path):
    case, manifest, result, matches = _synthetic_case(tmp_path)
    report = snapshot(result, manifest)
    assert report["first_evidence"] and report["last_evidence"]
    assert report["first_evidence"] < report["last_evidence"]
    assert report["collected_at"] == "2026-10-15 15:20:00"
    assert report["categories"]["DB"] >= 1
    assert report["findings_count"] == len(result["findings"])
    assert "장애 시작·종료" in report["note"]
    undated = {
        "findings": [{
            "finding_id": "F-0001", "signal_code": "SQL_ERROR",
            "evidence_refs": [{"clock": "10:14:30.001", "occurred_at": None}]
        }],
        "metrics": {"undated_events": 1},
    }
    result_no_date = snapshot(undated, {"files": [], "collected_at": None})
    assert result_no_date["first_evidence"] == "날짜 미확인 · 10:14:30.001"
    assert finding_time_sort_key(undated["findings"][0])[0] == 1
    assert category(undated["findings"][0]) == "DB"


def test_ai_context_includes_second_and_first_evidence_window(tmp_path: Path):
    """Old nearest-first algorithm omitted the second distant occurrence."""
    event_file = tmp_path / "events.jsonl"
    manifest = {"files": [{"file_id": "file_01", "kind": "err",
                           "storage_name": "err_01.log"}]}
    def stamp(sec):
        return (datetime.fromisoformat("2026-10-15T10:00:00+09:00")
                + timedelta(seconds=sec)).isoformat(timespec="milliseconds")
    events = [
        {"file_id": "file_01", "line_start": 1, "line_end": 2,
         "event_type": "log_error", "log_kind": "err",
         "occurred_at": stamp(5),
         "details": {"exception_class": "SocketTimeoutException"}},
        {"file_id": "file_01", "line_start": 3, "line_end": 4,
         "event_type": "log_error", "log_kind": "err",
         "occurred_at": stamp(725),
         "details": {"exception_class": "SQLException"}},
    ]
    event_file.write_text("\n".join(json.dumps(x) for x in events) + "\n")
    records = [{
        "finding_id": "F-0001",
        "evidence": [
            {"occurred_at": stamp(0)},
            {"occurred_at": stamp(720)},
        ],
    }]
    grouped = _context_events(tmp_path, manifest, records)
    joined = " ".join(x["recorded_at"] for x in grouped["F-0001"])
    assert stamp(5) in joined
    assert stamp(725) in joined
    assert len(grouped["F-0001"]) == 2


def test_full_ai_brief_is_chronological_and_privacy_safe(tmp_path: Path):
    case, manifest, result, matches = _synthetic_case(tmp_path)
    packets = build_ai_exports(case, manifest, result, matches)
    markdown = packets["ai_brief.md"].decode("utf-8")
    obj = json.loads(packets["ai_brief.json"])
    assert "시간대의 비식별 이벤트" in markdown
    assert "시작시각" in markdown
    assert "context_anchor_count" in str(obj["findings"][0])
    assert any(r.get("nearby_sanitized_events") for r in obj["findings"])
    assert "010-1234-5678" not in markdown
    assert "PRIVATE_CLIENT_KEY" not in markdown
    assert "TEST_PRIVATE_PASSWORD" not in markdown
    assert markdown.count("근거시각") >= 1


def test_streamlit_v3_is_readable_without_raw_findings_json(tmp_path: Path, monkeypatch):
    from streamlit.testing.v1 import AppTest
    import mpush_analyzer.lifecycle as lifecycle
    case, manifest, result, _ = _synthetic_case(tmp_path)
    monkeypatch.setattr(lifecycle, "list_cases", lambda _: [case])
    test = AppTest.from_file(str(Path(__file__).resolve().parents[1] / "app.py"),
                             default_timeout=40).run()
    assert not test.exception, [x.message for x in test.exception]
    headings_first = [x.value for x in test.markdown]
    assert any("로그 근거 한눈에 보기" in h for h in headings_first)
    nav = next(x for x in test.radio if x.label == "분석 메뉴")
    assert all(name in nav.options for name in (
        "종합 현황", "전체 이벤트", "Job 분석", "DB 분석",
        "이상·오류 분석", "수집·분석 품질",
    ))
    # The V3 evidence section now lives in the dedicated investigation screen.
    test = nav.set_value("이상·오류 분석").run()
    assert not test.exception, [x.message for x in test.exception]
    headings = [x.value for x in test.markdown]
    assert any("탐지 기준 및 수치 비교" in h for h in headings)
    assert not any("탐지 근거 및 판단 한계" in h for h in headings)


def test_job_effective_threshold_reports_true_comparison(tmp_path: Path):
    """Relative baseline is part of the actual rule, not just the absolute floor."""
    from mpush_analyzer.anomalies import detect_anomalies
    from mpush_analyzer.finding_view_v2 import details
    durations = [5.0, 5.1, 5.2, 5.3, 5.4, 200.0]
    items = []
    for i, duration in enumerate(durations):
        items.append({
            "file_id": "file_01", "line_start": i + 1, "line_end": i + 1,
            "event_type": "job_run", "status": "complete",
            "occurred_at": f"2026-10-15T10:00:{i:02}.000+09:00",
            "details": {"job_name": "SEND_REAL_FILE_IMAGE",
                        "target_count": 1, "duration_seconds": duration,
                        "completed": True, "steps_seconds": {}},
        })
    (tmp_path / "events.jsonl").write_text(
        "\n".join(json.dumps(x) for x in items) + "\n", encoding="utf-8"
    )
    manifest = {"files": [{"file_id": "file_01", "kind": "job",
                           "storage_name": "job_01.log", "completeness": "full"}],
                "collected_at": None}
    _, findings, _ = detect_anomalies(tmp_path / "events.jsonl", manifest)
    target = next(f for f in findings if f["rule_id"] == "JOB_DURATION")
    numbers = target["measure"]
    assert numbers["threshold_seconds"] == 5
    assert numbers["baseline_median_seconds"] is not None
    assert numbers["effective_threshold_seconds"] > numbers["threshold_seconds"]
    view = details(target, manifest)
    assert "실제 판정 기준" in view["why_flagged"]
    assert f"{numbers['effective_threshold_seconds']:.3f}" in view["why_flagged"]
    assert any(x["항목"] == "동일 작업량 중앙값" for x in view["measurements"])


def test_ai_context_guarantees_sparse_second_window_with_dense_first(tmp_path: Path):
    """A later low-priority event must not be hidden by many earlier exceptions."""
    manifest = {"files": [{"file_id": "file_01", "kind": "err",
                           "storage_name": "err_01.log"},
                          {"file_id": "file_02", "kind": "debug",
                           "storage_name": "debug_01.log"}]}
    base = datetime.fromisoformat("2026-10-15T10:00:00+09:00")
    def at(n):
        return (base + timedelta(seconds=n)).isoformat(timespec="milliseconds")
    events = []
    for index in range(45):
        events.append({
            "file_id": "file_01", "line_start": index + 1, "line_end": index + 1,
            "event_type": "log_error", "log_kind": "err",
            "occurred_at": at(index), "details": {"exception_class": "SQLException"},
        })
    events.append({
        "file_id": "file_02", "line_start": 100, "line_end": 100,
        "event_type": "healthcheck_result", "log_kind": "debug",
        "occurred_at": at(725), "details": {"target_action": "no_action"},
    })
    (tmp_path / "events.jsonl").write_text(
        "\n".join(json.dumps(item) for item in events) + "\n", encoding="utf-8")
    groups = _context_events(tmp_path, manifest, [{
        "finding_id": "F-0001",
        "evidence": [{"occurred_at": at(0)}, {"occurred_at": at(720)}],
    }])
    selected = groups["F-0001"]
    assert len(selected) <= 16
    assert any(x["evidence_lines"] == "file_02:100-100" for x in selected)
    assert any(x["log_file"].startswith("err_01.log") for x in selected)


def test_ai_evidence_ref_alignment_and_timestamp_scrubbing(tmp_path: Path):
    """A rejected source ref must not transfer its timestamp to another row."""
    from copy import deepcopy
    from mpush_analyzer.ai_brief_v2 import build_packet

    case, manifest, result, matches = _synthetic_case(tmp_path)
    modified = deepcopy(result)
    finding = next(f for f in modified["findings"]
                   if f["signal_code"] == "DB_SQL_DELAY")
    good = finding["evidence_refs"][0].copy()
    expected_time = datetime.fromisoformat(good["occurred_at"]).isoformat()
    bad_source = {**good, "file_id": "PRIVATE_FAKE_FILE",
                  "occurred_at": "PRIVATE_WRONG_ANCHOR"}
    bad_line = {**good, "line_start": 0,
                "occurred_at": "PRIVATE_ZERO_LINE"}
    bad_timestamp = {**good, "occurred_at": "PRIVATE_INVALID_TIMESTAMP"}
    finding["evidence_refs"] = [bad_source, bad_line, bad_timestamp, good]

    packet = build_packet(case, manifest, modified, matches,
                          only_finding_id=finding["finding_id"])
    evidence = packet["findings"][0]["evidence"]
    assert len(evidence) == 2
    assert evidence[0]["occurred_at"] is None
    assert evidence[1]["occurred_at"] == expected_time
    assert evidence[1]["원본 ID"] == good["file_id"]
    assert evidence[1]["시작행"] == good["line_start"]
    assert packet["findings"][0]["context_anchor_count"] == 1
    exports = build_ai_exports(case, manifest, modified, matches,
                               only_finding_id=finding["finding_id"])
    assert all(b"PRIVATE_" not in raw for raw in exports.values())
