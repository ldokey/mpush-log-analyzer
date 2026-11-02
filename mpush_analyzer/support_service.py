"""Orchestrate private inquiry records, imports and explicit knowledge drafts."""
from __future__ import annotations
from datetime import date
import hashlib
import json
from pathlib import Path
import secrets

from .intake import Upload, inspect_uploads
from .lifecycle import list_cases
from .pipeline import _get_manifest
from .storage import save_intake
from .runner import run_complete_analysis
from .support_store import (ANALYSIS_ID, file_lock, get_issue, issue_path, link_analysis,
                            plain, read_context, redmine_ref, save_issue, set_context,
                            stamp, write_json)


def analysis_fingerprint(inspected: list, *, agent: str, version: str,
                         reference_date: date | None, collected_at: str | None) -> str:
    files = sorted((x.sha256, x.kind, x.date_hint or '', x.upload.completeness)
                   for x in inspected if x.duplicate_of is None)
    doc = {'files': files, 'agent': agent, 'version': version,
           'reference_date': reference_date.isoformat() if reference_date else None,
           'collected_at': collected_at or None}
    return hashlib.sha256(json.dumps(doc, sort_keys=True).encode()).hexdigest()


def import_analysis(uploads: list[Upload], workspace: Path, *, same_agent: bool,
                    agent: str, reference: str = '', base_url: str = '',
                    customer: str = '', title: str = '', problem: str = '',
                    agent_version: str = 'auto', reference_date: date | None = None,
                    collected_at: str | None = None, knowledge_root: Path | None = None) -> tuple[Path, bool]:
    if same_agent is not True or not plain(agent, 120):
        raise ValueError('Agent 구분과 동일 Agent 자료 확인이 필요합니다.')
    if agent_version not in {'auto','3.2','3.3'}:
        raise ValueError('지원하지 않는 Agent 버전입니다.')
    if reference_date is not None and type(reference_date) is not date:
        raise ValueError('로그 기준 날짜가 잘못됐습니다.')
    inspected = inspect_uploads(uploads)
    if not any(x.kind not in {'agent_ini', 'unknown'} for x in inspected):
        raise ValueError('분석 가능한 로그가 없습니다. 파일 종류를 확인하세요.')
    # Validate all intake conditions before creating an inquiry.
    config = [x for x in inspected if x.kind == 'agent_ini' and x.duplicate_of is None]
    if len(config) > 1 or any(x.size_bytes > 2 * 1024**2 for x in config):
        raise ValueError('Agent 설정이 여러 개이거나 크기 제한을 초과합니다. Agent별로 분리하세요.')
    from .storage import _format_collected_at
    normalized_collection = _format_collected_at(collected_at)
    key = ''
    if reference.strip():
        ref = redmine_ref(reference, base_url)
        key = ref['key']
        issue = get_issue(workspace, key)
        if issue is None:
            save_issue(workspace, ref, {'customer': customer, 'title': title,
                                      'problem': problem, 'status': '접수'}, expected_revision=0)
    digest = analysis_fingerprint(inspected, agent=agent, version=agent_version,
                                  reference_date=reference_date, collected_at=normalized_collection)
    lock_id = 'import-' + (key or 'unlinked')
    with file_lock(workspace / 'support', lock_id):
        for saved in list_cases(workspace):
            ctx = read_context(saved)
            if ctx.get('fingerprint') == digest and ctx.get('issue_key', '') == key:
                manifest = _get_manifest(saved)
                set_context(saved, manifest, inspected, issue_key=key, agent=agent, fingerprint=digest)
                if key: link_analysis(workspace, key, saved.name, agent)
                # Failed/incomplete pipeline runs are never passed off as successful reuse.
                from .dashboard_data import read_result_bundle
                try:
                    read_result_bundle(saved)
                except (ValueError, OSError, KeyError):
                    kwargs = {'knowledge_root': knowledge_root} if knowledge_root else {}
                    run_complete_analysis(saved, **kwargs)
                return saved, True
        case, manifest = save_intake(inspected, workspace, agent_version=agent_version,
                                    reference_date=reference_date, collected_at=normalized_collection)
        set_context(case, manifest, inspected, issue_key=key, agent=agent, fingerprint=digest)
        if key: link_analysis(workspace, key, case.name, agent)
        kwargs = {'knowledge_root': knowledge_root} if knowledge_root else {}
        run_complete_analysis(case, **kwargs)
        return case, False


def restore_names(case: Path, uploads: list[Upload]) -> int:
    manifest = _get_manifest(case)
    inspected = inspect_uploads(uploads)
    original = {f['content_sha256'] for f in manifest['files']}
    matches = original & {f.sha256 for f in inspected}
    if not matches:
        raise ValueError('SHA-256이 일치하는 원본이 없습니다. 이름만으로 연결하지 않습니다.')
    ctx = set_context(case, manifest, inspected)
    count = sum(f['content_sha256'] in matches and f['file_id'] in ctx['sources'] for f in manifest['files'])
    if not count:
        raise ValueError('동일 내용의 여러 날짜 파일이 있어 이름을 확정하지 못했습니다. 날짜가 포함된 원본명을 제공하세요.')
    return count


def attach_existing(case: Path, ref: dict, *, agent: str) -> None:
    """Explicit migration of an existing analysis to an existing inquiry."""
    manifest = _get_manifest(case)
    if get_issue(case.parent, ref['key']) is None:
        raise ValueError('문의 기록을 먼저 저장하세요.')
    set_context(case, manifest, [], issue_key=ref['key'], agent=plain(agent, 120))
    link_analysis(case.parent, ref['key'], case.name, agent)


def _lines(value: str) -> list[str]:
    lines = list(dict.fromkeys(x.strip() for x in plain(value).splitlines() if x.strip()))
    if len(lines) > 60 or any(len(x) > 200 for x in lines):
        raise ValueError('사례 항목은 한 줄 200자, 최대 60줄로 작성하세요.')
    return lines


def create_knowledge_draft(workspace: Path, key: str, *, knowledge_root: Path,
                           title: str, symptoms: str, cause: str, actions: str,
                           verification: str, checks: str, signals: list[str],
                           reviewed_private: bool, confirmed_cause: bool = False,
                           verified_solution: bool = False) -> dict:
    """User-curated content only; private issue prose is not copied implicitly."""
    from .case_contract import validate_case_json
    from .case_library import import_case
    if reviewed_private is not True:
        raise ValueError('개인정보·고객 식별정보를 제거하고 검토했는지 확인하세요.')
    issue = get_issue(workspace, key)
    if issue is None: raise ValueError('문의가 없습니다.')
    symptoms_list = _lines(symptoms); action_list = _lines(actions); verify_list = _lines(verification)
    cause_text = plain(cause, 1500)
    if confirmed_cause and not verify_list:
        raise ValueError('확인된 원인에는 검증 근거가 필요합니다.')
    if verified_solution and not (action_list and verify_list and confirmed_cause and cause_text):
        raise ValueError('해결 검증 표시에는 확인된 원인·조치·검증 근거가 필요합니다.')
    payload = {
        'schema_version': '1.0', 'case_id': 'MPA-CASE-000001', 'revision': 1,
        'title': plain(title, 180), 'status': 'investigating',
        'environment': {'agent_versions': [], 'os': [], 'dbms': [], 'jobs': []},
        'symptoms': symptoms_list,
        'match_signals': {'required': list(dict.fromkeys(signals)), 'supporting': [], 'excluding': []},
        'root_cause': {'status': 'confirmed' if confirmed_cause else 'suspected',
                       'description': cause_text, 'evidence': verify_list if confirmed_cause else []} if cause_text else None,
        'resolution': {'actions': action_list, 'verified': verified_solution},
        'verification': {'status': 'verified' if verified_solution else 'not_verified', 'evidence': verify_list},
        'diagnostic_checks': _lines(checks),
        'references': [{'type': 'redmine', 'id': '#' + issue['number']},
                       {'type': 'internal_case', 'id': key}],
        'review': {'state': 'draft', 'approved_at': None},
    }
    data = json.dumps(payload, ensure_ascii=False).encode()
    verdict = validate_case_json(data)
    if not verdict.valid:
        raise ValueError('사례 형식·민감정보 검사: ' + '; '.join(verdict.errors))
    # A repeated submission of the same curated data returns the existing draft.
    digest = hashlib.sha256(data).hexdigest()
    path = issue_path(workspace, key)
    with file_lock(path.parent, key):
        issue = get_issue(workspace, key)
        for link in issue.get('knowledge_links', []):
            if link.get('digest') == digest:
                return link
        with file_lock(knowledge_root, 'draft-allocation'):
            for _ in range(100):
                case_id = f'MPA-CASE-{secrets.randbelow(999999) + 1:06d}'
                if not any(list((knowledge_root / f).glob(case_id + '_r*.json')) for f in ('inbox','approved')):
                    break
            else: raise ValueError('사례 ID를 할당하지 못했습니다.')
            payload['case_id'] = case_id
            import_case(json.dumps(payload, ensure_ascii=False).encode(), root=knowledge_root)
        link = {'case_id': case_id, 'revision': 1, 'digest': digest, 'at': stamp()}
        issue.setdefault('knowledge_links', []).append(link)
        issue['revision'] += 1; issue['updated_at'] = stamp()
        issue['history'] = (issue.get('history',[]) + [{'revision':issue['revision'],
            'at':issue['updated_at'],'changed':['knowledge_links']}])[-200:]
        write_json(path, issue)
        return link
