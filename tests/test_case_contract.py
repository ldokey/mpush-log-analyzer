from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path

import pytest

from mpush_analyzer.case_contract import load_schema, validate_case_json

FIXTURE = Path(__file__).parent / "fixtures" / "case_draft.json"


def _valid() -> dict:
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def _check(payload: dict):
    return validate_case_json(json.dumps(payload, ensure_ascii=False).encode("utf-8"))


def test_draft_schema_is_valid():
    r = validate_case_json(FIXTURE.read_bytes())
    assert r.valid, r.errors
    assert r.summary["status"] == "investigating"
    assert r.summary["review_state"] == "draft"


def test_schemas_are_valid_draft202012():
    from jsonschema import Draft202012Validator
    for name in ("case.schema.json", "manifest.schema.json", "analysis_result.schema.json"):
        Draft202012Validator.check_schema(load_schema(name))
    assert len(load_schema("signal_catalog.json")["signals"]) >= 8


def test_resolved_requires_verified_root_cause_and_review():
    o = _valid()
    o["status"] = "resolved_verified"
    r = _check(o)
    assert not r.valid
    assert any("원인" in err for err in r.errors)
    o["root_cause"] = {"status": "confirmed", "description": "합성 테스트에서 재현된 원인", "evidence": ["synthetic evidence"]}
    o["resolution"] = {"actions": ["합성 환경 재시작"], "verified": True}
    o["verification"] = {"status": "verified", "evidence": ["synthetic verification"]}
    o["review"] = {"state": "approved", "approved_at": "2026-10-26T12:00:00+09:00"}
    r = _check(o)
    assert r.valid, r.errors


def test_unknown_and_contradictory_signals_rejected():
    o = _valid()
    o["match_signals"]["required"] = ["NON_EXISTENT_SIGNAL"]
    assert not _check(o).valid
    o["match_signals"]["required"] = ["PERIODIC_JOB_GAP"]
    o["match_signals"]["excluding"] = ["PERIODIC_JOB_GAP"]
    assert not _check(o).valid


@pytest.mark.parametrize("injection", [
    "password: secret",
    "010-2222-3333",
    "someone@example.com",
    "192.0.2.9",
    "jdbc:mysql://server/db"
])
def test_blocks_common_sensitive_patterns(injection):
    o = _valid()
    o["symptoms"].append("Sample " + injection)
    r = _check(o)
    assert not r.valid
    assert any("민감정보 패턴" in err for err in r.errors)
    assert injection not in str(r.errors)


def test_rejects_duplicate_keys_without_echoing():
    raw = b'{"case_id":"MPA-CASE-000001","case_id":"MPA-CASE-000002"}'
    r = validate_case_json(raw)
    assert not r.valid
    assert "000002" not in str(r.errors)


def test_rejects_invalid_case_json_and_large_json():
    assert not validate_case_json(b"{}").valid
    assert not validate_case_json(b"[]").valid
    assert not validate_case_json(b'{' + b'a' * 600000 + b'}').valid
    assert not validate_case_json(b"\xff").valid


def test_refuses_approved_without_approval_timestamp():
    o = _valid()
    o["review"]["state"] = "approved"
    assert not _check(o).valid
