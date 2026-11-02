"""Local-only issue records and provenance sidecars; never used by AI exports.

Source paths/names and support prose are private operational data. Stable file
IDs, anonymized manifests and approved case contracts remain unchanged.
"""
from __future__ import annotations
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile
import unicodedata
from urllib.parse import urlsplit, urlunsplit
from typing import Any

from .permissions import private_fd, private_path

ISSUE_KEY = re.compile(r'issue_[a-f0-9]{24}\Z')
ANALYSIS_ID = re.compile(r'analysis_[a-f0-9]{32}\Z')
SOURCE_ID = re.compile(r'file_[0-9]{2}\Z')
MAX_JSON = 2 * 1024 * 1024
CONTEXT_FILE = 'local_context.private.json'
STATES = ('접수', '분석 중', '추가자료 대기', '조치 적용', '해결 확인', '보류')
TEXT_FIELDS = ('customer', 'title', 'problem', 'observations', 'cause', 'actions', 'verification', 'next_steps')


def stamp() -> str:
    return datetime.now(timezone.utc).isoformat()


def plain(value: Any, limit: int = 12000) -> str:
    if not isinstance(value, str) or len(value) > limit:
        raise ValueError('입력 문자열 형식 또는 길이를 확인하세요.')
    return ''.join(c for c in value if c in '\n\t' or unicodedata.category(c) not in {'Cc', 'Cf'}).strip()


def reject_links(path: Path) -> None:
    """Reject symlink/junction ancestors, including on Windows."""
    for p in (path, *path.parents):
        if p.is_symlink() or (hasattr(p, 'is_junction') and p.is_junction()):
            raise ValueError('링크·junction 경로는 허용하지 않습니다.')


def private_dir(path: Path) -> None:
    reject_links(path)
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    private_path(path, directory=True)


def read_json(path: Path, default: Any = None) -> Any:
    reject_links(path)
    if not path.exists():
        return default
    if not path.is_file() or path.stat().st_size > MAX_JSON:
        raise ValueError('로컬 관리 파일 크기 또는 형식이 잘못됐습니다.')
    try:
        return json.loads(path.read_text(encoding='utf-8'))
    except (ValueError, UnicodeError) as exc:
        raise ValueError('로컬 관리 파일을 읽을 수 없습니다. 원본을 보존하고 확인하세요.') from exc


def write_json(path: Path, payload: Any) -> None:
    reject_links(path)
    data = (json.dumps(payload, ensure_ascii=False, indent=2) + '\n').encode('utf-8')
    if len(data) > MAX_JSON:
        raise ValueError('로컬 관리 파일 제한 2MiB를 초과했습니다.')
    private_dir(path.parent)
    fd, name = tempfile.mkstemp(prefix='.' + path.name + '.', dir=path.parent)
    temp = Path(name)
    try:
        with os.fdopen(fd, 'wb') as stream:
            private_fd(stream.fileno()); stream.write(data); stream.flush(); os.fsync(stream.fileno())
        reject_links(path)
        os.replace(temp, path)
    finally:
        temp.unlink(missing_ok=True)


@contextmanager
def file_lock(folder: Path, name: str):
    if not isinstance(name, str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,100}', name):
        raise ValueError('잠금 식별자가 잘못됐습니다.')
    private_dir(folder)
    lock = folder / (name + '.lock')
    reject_links(lock)
    try:
        fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError as exc:
        raise ValueError('다른 저장 작업이 진행 중입니다. 잠시 후 새로고침하세요. 중단된 잠금은 수동 확인이 필요합니다.') from exc
    try:
        os.close(fd)
        yield
    finally:
        lock.unlink(missing_ok=True)


def redmine_ref(raw: str, base_url: str = '') -> dict[str, str]:
    """Parse only. Never contact the server or accept credentials in a URL."""
    text = plain(raw, 1200)
    base = plain(base_url, 1000).rstrip('/')
    number = re.fullmatch(r'#?([1-9][0-9]{0,9})', text)
    if number:
        num = number.group(1)
        url = base + '/issues/' + num if base else ''
    else:
        url = text
        num = ''
    if url:
        try:
            parsed = urlsplit(url)
            _ = parsed.port
        except ValueError as exc:
            raise ValueError('Redmine URL 형식이 잘못됐습니다.') from exc
        if (parsed.scheme not in {'http', 'https'} or not parsed.hostname or
            parsed.username or parsed.password or parsed.query or parsed.fragment or
            any(c.isspace() for c in url) or '\\' in url or '%' in url):
            raise ValueError('인증정보·쿼리·fragment 없는 http(s) Redmine 이슈 링크를 입력하세요.')
        match = re.fullmatch(r'(.*)/issues/([1-9][0-9]{0,9})/?', parsed.path)
        if not match or any(p in {'.', '..'} for p in parsed.path.split('/')):
            raise ValueError('Redmine 번호 또는 /issues/번호 형식의 링크가 필요합니다.')
        prefix, num = match.groups()
        base = urlunsplit((parsed.scheme, parsed.netloc.lower(), prefix.rstrip('/'), '', ''))
        url = base + '/issues/' + num
    if not num:
        raise ValueError('Redmine 번호 또는 링크를 입력하세요.')
    identity = (base or 'local-unconfigured') + '\0' + num
    return {'number': num, 'url': url, 'base_url': base,
            'key': 'issue_' + hashlib.sha256(identity.encode()).hexdigest()[:24]}


def folder_hint(name: str) -> dict[str, str]:
    label = plain(name, 500)
    match = re.fullmatch(r'#?([1-9][0-9]{0,9})[ _-]+(.+)', label)
    return {'number': match.group(1), 'customer': match.group(2).strip()} if match else {}


def issue_path(workspace: Path, key: str) -> Path:
    if not isinstance(key, str) or not ISSUE_KEY.fullmatch(key):
        raise ValueError('문의 식별자가 올바르지 않습니다.')
    return workspace / 'support' / (key + '.json')


def get_issue(workspace: Path, key: str) -> dict | None:
    doc = read_json(issue_path(workspace, key))
    if doc is not None:
        if (not isinstance(doc, dict) or doc.get('key') != key or
            type(doc.get('revision')) is not int or doc.get('revision', 0) < 1 or
            doc.get('status') not in STATES or not isinstance(doc.get('analyses'), list)):
            raise ValueError('문의 기록 정합성이 잘못됐습니다.')
        reference = redmine_ref(doc.get('url') or doc.get('number', ''), doc.get('base_url', ''))
        if reference['key'] != key:
            raise ValueError('문의 번호와 서버 식별자가 일치하지 않습니다.')
        for f in TEXT_FIELDS:
            plain(doc.get(f, ''), 240 if f in ('title','customer') else 12000)
        if len(doc['analyses']) > 500:
            raise ValueError('문의 분석 연결 수 제한을 초과했습니다.')
        ids = set()
        for entry in doc['analyses']:
            if (not isinstance(entry, dict) or not isinstance(entry.get('analysis_id'), str)
                or not ANALYSIS_ID.fullmatch(entry['analysis_id']) or entry['analysis_id'] in ids):
                raise ValueError('문의의 연결된 분석 ID가 올바르지 않습니다.')
            ids.add(entry['analysis_id']); plain(entry.get('agent',''),120); plain(entry.get('at',''),60)
        links = doc.get('knowledge_links', [])
        history = doc.get('history', [])
        if not isinstance(links,list) or len(links)>500 or not isinstance(history,list) or len(history)>200:
            raise ValueError('문의 연결/변경 이력 형식이 올바르지 않습니다.')
        for item in links:
            if (not isinstance(item,dict) or not isinstance(item.get('case_id'),str)
                or not re.fullmatch(r'MPA-CASE-[0-9]{6}',item['case_id'])
                or type(item.get('revision')) is not int or item['revision'] < 1):
                raise ValueError('해결 사례 연결 ID가 올바르지 않습니다.')
    return doc


def save_issue(workspace: Path, reference: dict, fields: dict, *, expected_revision: int) -> dict:
    ref = redmine_ref(reference.get('url') or reference.get('number', ''), reference.get('base_url', ''))
    key = ref['key']; path = issue_path(workspace, key)
    with file_lock(path.parent, key):
        old = get_issue(workspace, key)
        current = old['revision'] if old else 0
        if type(expected_revision) is not int or expected_revision != current:
            raise ValueError('다른 화면에서 문의 기록이 변경됐습니다. 새로고침 후 다시 저장하세요.')
        values = {f: plain(fields.get(f, old.get(f, '') if old else ''),
                           240 if f in ('title', 'customer') else 12000) for f in TEXT_FIELDS}
        status = fields.get('status', old.get('status', '접수') if old else '접수')
        if status not in STATES:
            raise ValueError('지원하지 않는 문의 상태입니다.')
        if status == '해결 확인' and not (values['actions'] and values['verification']):
            raise ValueError('해결 확인에는 실제 조치와 검증 결과가 필요합니다.')
        now = stamp()
        changes = [f for f in (*TEXT_FIELDS, 'status') if (old or {}).get(f) != ({**values, 'status': status})[f]]
        history = list((old or {}).get('history', []))
        history.append({'revision': current + 1, 'at': now, 'changed': changes})
        doc = {**ref, **values, 'status': status, 'revision': current + 1,
               'created_at': old['created_at'] if old else now, 'updated_at': now,
               'analyses': (old or {}).get('analyses', []),
               'knowledge_links': (old or {}).get('knowledge_links', []), 'history': history[-200:]}
        write_json(path, doc)
        return doc


def link_analysis(workspace: Path, key: str, analysis_id: str, agent: str) -> dict:
    if not ANALYSIS_ID.fullmatch(analysis_id):
        raise ValueError('분석 ID가 올바르지 않습니다.')
    path = issue_path(workspace, key)
    with file_lock(path.parent, key):
        doc = get_issue(workspace, key)
        if doc is None:
            raise ValueError('문의 기록을 먼저 저장하세요.')
        if not any(a['analysis_id'] == analysis_id for a in doc['analyses']):
            if len(doc['analyses']) >= 500:
                raise ValueError('문의당 분석 연결 500개 제한을 초과했습니다.')
            doc['analyses'].append({'analysis_id': analysis_id, 'agent': plain(agent, 120), 'at': stamp()})
            doc['revision'] += 1; doc['updated_at'] = stamp()
            doc['history'] = (doc.get('history',[]) + [{'revision':doc['revision'],
                'at':doc['updated_at'],'changed':['analyses']}])[-200:]
            write_json(path, doc)
        return doc


def list_issues(workspace: Path) -> list[dict]:
    folder = workspace / 'support'
    reject_links(folder)
    if not folder.exists():
        return []
    results = []
    for path in sorted(folder.glob('issue_*.json')):
        if not ISSUE_KEY.fullmatch(path.stem):
            continue
        doc = get_issue(workspace, path.stem)
        if doc: results.append(doc)
        if len(results) > 5000:
            raise ValueError('문의 목록 5,000건 제한을 초과했습니다.')
    return sorted(results, key=lambda d: d['updated_at'], reverse=True)


def source_label(name: str) -> str:
    clean = plain(name, 2000).replace('\\', '/')
    # Labels only; never use this value as a filesystem destination.
    if clean.startswith('/') or re.match(r'^[A-Za-z]:', clean) or '..' in clean.split('/'):
        clean = clean.rsplit('/', 1)[-1]
    return clean[-700:] or '이름 미확인'


def set_context(case_dir: Path, manifest: dict, inspected: list, *, issue_key: str = '',
                agent: str = '', fingerprint: str = '') -> dict:
    with file_lock(case_dir, 'local-context'):
        return _set_context_locked(case_dir,manifest,inspected,issue_key=issue_key,
                                   agent=agent,fingerprint=fingerprint)


def _set_context_locked(case_dir: Path, manifest: dict, inspected: list, *, issue_key: str = '',
                agent: str = '', fingerprint: str = '') -> dict:
    if not ANALYSIS_ID.fullmatch(case_dir.name) or manifest['analysis_id'] != case_dir.name:
        raise ValueError('분석 작업 식별자가 일치하지 않습니다.')
    old = read_context(case_dir)
    if issue_key and not ISSUE_KEY.fullmatch(issue_key):
        raise ValueError('문의 키가 잘못됐습니다.')
    if old.get('issue_key') and issue_key and old['issue_key'] != issue_key:
        raise ValueError('다른 문의에 연결된 분석의 연결은 자동으로 바꾸지 않습니다.')
    by_hash: dict[str, list[str]] = {}
    exact: dict[tuple, list[str]] = {}
    for item in inspected:
        label = source_label(item.upload.origin or item.upload.name)
        by_hash.setdefault(item.sha256, []).append(label)
        exact.setdefault((item.sha256,item.kind,item.date_hint),[]).append(label)
    mapping = dict(old.get('sources', {}))
    for item in manifest['files']:
        sha = item['content_sha256']
        names = exact.get((sha,item['kind'],item.get('date_hint')))
        if not names and sum(f['content_sha256'] == sha for f in manifest['files']) == 1:
            names = by_hash.get(sha)
        if names:
            mapping[item['file_id']] = {'label': names[0], 'alternatives': list(dict.fromkeys(names)),
                                        'sha256': sha}
    doc = {'version': 1, 'analysis_id': case_dir.name, 'issue_key': issue_key or old.get('issue_key', ''),
           'agent': plain(agent, 120) or old.get('agent', ''), 'sources': mapping,
           'fingerprint': fingerprint or old.get('fingerprint', ''), 'updated_at': stamp()}
    write_json(case_dir / CONTEXT_FILE, doc)
    return doc


def read_context(case_dir: Path) -> dict:
    doc = read_json(case_dir / CONTEXT_FILE, {})
    if not isinstance(doc, dict) or (doc and (doc.get('analysis_id') != case_dir.name or not isinstance(doc.get('sources'), dict))):
        raise ValueError('로컬 원본명 기록의 분석 ID가 일치하지 않습니다.')
    if doc:
        issue_key=doc.get('issue_key','')
        if not isinstance(issue_key,str) or (issue_key and not ISSUE_KEY.fullmatch(issue_key)):
            raise ValueError('로컬 연결 문의 ID가 잘못됐습니다.')
        plain(doc.get('agent',''),120)
        fingerprint=doc.get('fingerprint','')
        if not isinstance(fingerprint,str) or (fingerprint and not re.fullmatch(r'[a-f0-9]{64}',fingerprint)):
            raise ValueError('분석 자료 지문 형식이 잘못됐습니다.')
        if len(doc['sources']) > 30:
            raise ValueError('원본명 연결 파일 수 제한을 초과했습니다.')
        for key, item in doc['sources'].items():
            if (not isinstance(key,str) or not SOURCE_ID.fullmatch(key) or not isinstance(item,dict)
                or not isinstance(item.get('sha256'),str) or not re.fullmatch(r'[a-f0-9]{64}',item['sha256'])):
                raise ValueError('원본명 연결의 파일 ID 또는 해시가 잘못됐습니다.')
            source_label(item.get('label'))
    return doc


def ui_file_label(case_dir: Path, file_id: str, manifest: dict) -> str:
    from .finding_view_v2 import file_label
    fallback = file_label(file_id, manifest)
    try:
        doc = read_context(case_dir)
        source = doc.get('sources', {}).get(file_id)
        original = next((x for x in manifest['files'] if x['file_id'] == file_id), None)
        if (isinstance(source, dict) and original and source.get('sha256') == original['content_sha256']):
            return source_label(source['label']) + f' [{file_id}]'
    except (ValueError, KeyError, OSError):
        pass
    return fallback + ' · 원본명 미보관'


def ui_rows(case_dir: Path, manifest: dict, rows: list[dict]) -> list[dict]:
    """New copies for UI ONLY. Callers keep original rows for safe downloads."""
    labels = {f['file_id']: ui_file_label(case_dir, f['file_id'], manifest) for f in manifest['files']}
    result = []
    for row in rows:
        updated = dict(row)
        for column in ('근거 파일', '파일', '로그', '표시할 파일명', '근거 위치'):
            value = row.get(column)
            if not isinstance(value, str): continue
            fid = row.get('원본 ID')
            match = re.search(r'file_[0-9]{2}', value)
            fid = fid or (match.group() if match else '')
            if fid in labels:
                suffix = re.search(r' 외 [0-9]+개', value)
                updated[column] = labels[fid] + (':' + value.split(':')[-1] if column == '근거 위치' else '') + (suffix.group() if suffix else '')
        result.append(updated)
    return result


def case_title(case_dir: Path) -> str:
    try:
        ctx = read_context(case_dir)
        issue = get_issue(case_dir.parent, ctx['issue_key']) if ctx.get('issue_key') else None
        if issue:
            return f"#{issue['number']} · {issue['customer']} · {ctx.get('agent') or 'Agent'} · {case_dir.name[-8:]}"
    except (ValueError, OSError):
        pass
    return case_dir.name


def internal_note(doc: dict) -> str:
    rows = [f"Redmine #{doc['number']} — {doc['title']}", f"고객사: {doc['customer']}", f"상태: {doc['status']}"]
    for field, label in [('problem','문의/증상'),('observations','관측된 사실'),('cause','원인 후보/확인'),
                         ('actions','실제 조치'),('verification','검증 결과'),('next_steps','추가 확인')]:
        rows += ['', label, doc.get(field) or '(미기록)']
    return '\n'.join(rows)
