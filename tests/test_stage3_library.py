"""Local knowledge-store security and deterministic evidence-based matching."""
from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path

import pytest

from mpush_analyzer.case_library import (
    approve_case, import_case, list_case_summaries, read_approved_cases
)
from mpush_analyzer.case_matcher import match_cases


FIXTURE = Path(__file__).resolve().parent / "fixtures" / "case_draft.json"


def draft(case_id="MPA-CASE-000001", revision=1):
    doc=json.loads(FIXTURE.read_text(encoding="utf-8"))
    doc["case_id"]=case_id
    doc["revision"]=revision
    return doc


def encode(doc):
    return json.dumps(doc,ensure_ascii=False).encode("utf-8")


def evidence(signal, number):
    ref={"file_id":"file_01","line_start":number,"line_end":number,
         "occurred_at":"2026-10-15T10:00:00.000+09:00"}
    return {"signal_code":signal,"evidence_refs":[ref]}


def manifest(dbms="mysql", version="3.3"):
    return {"agent_version":version,"config_summary":{"dbms":{"type":dbms}}}


def test_ai_draft_only_human_approval_and_match(tmp_path):
    root=tmp_path/"knowledge"
    submission=encode(draft())
    stored=import_case(submission,root=root)
    assert stored["storage_state"]=="inbox"
    assert list_case_summaries(root=root,state="inbox")[0]["review_state"]=="draft"
    with pytest.raises(ValueError):
        import_case(submission,root=root)
    with pytest.raises(ValueError):
        approve_case("MPA-CASE-000001",1,root=root)
    assert not read_approved_cases(root=root)[0]
    approved=approve_case("MPA-CASE-000001",1,root=root,confirm_reviewed=True)
    assert approved["status"]=="investigating"
    assert not list_case_summaries(root=root,state="inbox")
    assert len(list_case_summaries(root=root,state="approved"))==1
    assert ((root/"approved"/"MPA-CASE-000001_r0001.json").stat().st_mode & 0o077)==0
    events=[
        evidence("PERIODIC_JOB_GAP",3),
        evidence("SEND_JOB_DELAY",10),
        evidence("HEALTHCHECK_GAP",20),
    ]
    matches=match_cases(events,manifest(),{"SEND_REAL_FILE_IMAGE":{"runs":5}},root=root)
    assert matches["approved_case_count"]==1
    assert matches["match_count"]==1
    result=matches["matched_cases"][0]
    assert result["result_type"]=="reference_only"
    assert result["resolution_actions"]==[]
    assert "고객사 OS" in result["unchecked_environment"]
    assert result["matched_required_signals"]==["PERIODIC_JOB_GAP"]
    assert result["matched_supporting_signals"]==["HEALTHCHECK_GAP","SEND_JOB_DELAY"]
    assert result["evidence_refs"]
    assert result["score_meaning"]=="relative_order_only_not_probability"
    assert match_cases(events,manifest(dbms="oracle"),{"SEND_REAL_FILE_IMAGE":{}},root=root)["match_count"]==0
    assert match_cases(events,manifest(version="3.1"),{"SEND_REAL_FILE_IMAGE":{}},root=root)["match_count"]==0


def test_missing_required_exclusion_and_revision(tmp_path):
    root=tmp_path/"knowledge"
    first=draft()
    first["match_signals"]["excluding"]=["SQL_ERROR"]
    import_case(encode(first),root=root)
    approve_case(first["case_id"],1,confirm_reviewed=True,root=root)
    events=[evidence("PERIODIC_JOB_GAP",1),evidence("SQL_ERROR",9)]
    assert match_cases(events,manifest(),{"SEND_REAL_FILE_IMAGE":{}},root=root)["match_count"]==0
    assert match_cases([evidence("SEND_JOB_DELAY",1)],manifest(),{},root=root)["match_count"]==0
    new=draft(revision=2)
    import_case(encode(new),root=root)
    approve_case(new["case_id"],2,confirm_reviewed=True,root=root)
    docs, rejected=read_approved_cases(root=root)
    assert rejected==0 and len(docs)==1 and docs[0]["revision"]==2
    found=match_cases([evidence("PERIODIC_JOB_GAP",1)],manifest(),{},root=root)
    assert found["matched_cases"][0]["revision"]==2
    older=draft(revision=1)
    with pytest.raises(ValueError):
        import_case(encode(older),root=root)


def test_verified_solution_requires_positive_confirmation_and_evidence(tmp_path):
    root=tmp_path/"knowledge"
    sample=draft("MPA-CASE-000002")
    sample["status"]="mitigated"
    import_case(encode(sample),root=root)
    with pytest.raises(ValueError):
        approve_case(sample["case_id"],1,root=root,confirm_reviewed=True,confirm_solution=True)
    assert list_case_summaries(root=root,state="inbox")
    full=draft("MPA-CASE-000003")
    full["status"]="mitigated"
    full["root_cause"]={"status":"confirmed","description":"합성 테스트에 의해 확인된 통신 설정 오류","evidence":["독립 테스트 로그 확인"]}
    full["resolution"]={"actions":["허용된 테스트 환경에서 설정 복구"],"verified":True}
    full["verification"]={"status":"verified","evidence":["합성 재현에서 재발하지 않음"]}
    import_case(encode(full),root=root)
    result=approve_case(full["case_id"],1,root=root,confirm_reviewed=True,confirm_solution=True)
    assert result["status"]=="resolved_verified"
    matches=match_cases([evidence("PERIODIC_JOB_GAP",1)],manifest(),{"SEND_REAL_FILE_IMAGE":{}},root=root)
    assert matches["matched_cases"][0]["result_type"]=="verified_solution"
    assert matches["matched_cases"][0]["resolution_actions"]


def test_rejects_forged_approvals_invalid_and_symlinks(tmp_path):
    root=tmp_path/"knowledge"
    doc=draft()
    doc["review"]={"state":"approved","approved_at":"2026-10-26T10:00:00+09:00"}
    with pytest.raises(ValueError):
        import_case(encode(doc),root=root)
    doc=draft()
    doc["title"]="비밀 서버 192.0.2.11 보고서"
    with pytest.raises(ValueError):
        import_case(encode(doc),root=root)
    sample=draft()
    import_case(encode(sample),root=root)
    approved=approve_case(sample["case_id"],1,root=root,confirm_reviewed=True)
    path=root/"approved"/"MPA-CASE-000001_r0001.json"
    data=json.loads(path.read_text())
    data["symptoms"].append("011-333-4444")
    path.write_text(json.dumps(data))
    docs,rejected=read_approved_cases(root=root)
    assert docs==[] and rejected==1
    path.unlink()
    path.symlink_to(root/"inbox"/"nonexistent.json")
    docs,rejected=read_approved_cases(root=root)
    assert docs==[] and rejected==1
    bogus=tmp_path/"outside"
    bogus.mkdir()
    (tmp_path/"linked").symlink_to(bogus,target_is_directory=True)
    with pytest.raises(ValueError):
        import_case(encode(draft("MPA-CASE-000004")),root=tmp_path/"linked")


def test_unknown_os_not_inferred_from_developer_mac(tmp_path):
    root=tmp_path/"knowledge"
    doc=draft()
    doc["environment"]["os"]=["linux"]
    import_case(encode(doc),root=root)
    approve_case(doc["case_id"],1,root=root,confirm_reviewed=True)
    m=match_cases([evidence("PERIODIC_JOB_GAP",1)],manifest(),{"SEND_REAL_FILE_IMAGE":{}},root=root)
    assert m["match_count"]==1
    assert "고객사 OS" in m["matched_cases"][0]["unchecked_environment"]
