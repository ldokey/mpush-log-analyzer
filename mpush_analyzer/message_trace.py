"""On-demand message evidence tracing. Never persist raw identifiers or SQL.

Only co-located explicit SERVICE_SEQNO and MESSAGE_SEQNO fields are linked.
Unknown bind positions, missing IDs, batch lists and temporal proximity are NOT
identity evidence. Stages are observed markers, never a fabricated success path.
"""
from __future__ import annotations
from collections import Counter
from datetime import date
import hashlib
import hmac
import re
import secrets
from pathlib import Path

from .pipeline import _get_manifest, _safe_source, _read_numbered
from .parsers.common import ClockResolver, parse_clock
from .investigation import Window, instant, iso, number

PAIR = re.compile(r'''(?<![A-Za-z0-9_])['"]?(MESSAGE_SEQNO|SERVICE_SEQNO|JOB_TYPE|SEND_FLAG|RESPONSE_CODE)['"]?\s*[:=]\s*(?:['"]([A-Za-z0-9_-]{1,64})['"]|([A-Za-z0-9_-]{1,64})(?=$|[\s,;)}\]]))''',re.I)
VALID_ID = re.compile(r'[A-Za-z0-9_-]{1,64}\Z')
MAX_TRACE_ROWS = 20000
MAX_TRACE_GROUPS = 5000
MAX_RECORD_LINES = 200
MAX_RECORD_CHARS = 64*1024
STAGES = (
 ('request','발송 요청'), ('claim','선점'), ('file','파일 생성'),
 ('encryption','암호화'), ('tcp','전송'), ('accepted','요청 수락'),
 ('result','결과 수신'), ('db_transfer','DB 이관'),
)
MARKERS = {
 'request':('발송 요청','발송요청','send request'),
 'claim':('선점', 'claim message'),
 'file':('파일 생성','파일생성','file created','file creation'),
 'encryption':('암호화','encrypt'),
 'tcp':('파일전송','파일 전송','tcp send'),
 'result':('결과 수신','결과수신','result received'),
 'db_transfer':('로그 테이블 이관','결과 이관','결과이관'),
}


def fields(text: str) -> tuple[dict[str,str], bool]:
    found={};ambiguous=False
    for m in PAIR.finditer(text):
        key=m.group(1).upper();value=m.group(2) or m.group(3)
        if key in found and found[key]!=value:ambiguous=True
        found[key]=value
    # A quoted payload body is not a structured outer key-value record.
    if re.search(r'''\b(?:MESSAGE_BODY|MESSAGE_TEXT|CONTENT|BODY|TEXT)\b\s*['"]?\s*[:=]''',text,re.I):
        ambiguous=True
    return found,ambiguous


def stage_codes(text: str, values: dict[str,str]) -> list[str]:
    lower=text.lower();out=[]
    for code,markers in MARKERS.items():
        if any(marker in lower for marker in markers):out.append(code)
    if values.get('RESPONSE_CODE')=='S':out.append('accepted')
    if not out:out=['identifier_observed']
    return out


def _alias(salt: bytes, kind: str, value: str) -> str:
    return kind+'_'+hmac.new(salt,(kind+'\0'+value).encode(),hashlib.sha256).hexdigest()[:24]


def raw_records(path: Path, codec: str):
    """One timestamped record; a timestamp-free SQL continuation may attach.

    Record limits are fail-closed for identity, not silently truncated matches.
    """
    stats={'lines_read':0,'decode_replacement_lines':0,'oversized_lines':0}
    block=[];stamp=None;chars=0;truncated=False;oversized_before=0
    for n,line in _read_numbered(path,codec,stats):
        current=parse_clock(line)
        if current is not None and block:
            yield block,stamp,truncated
            block=[];chars=0;truncated=False
        if current is not None:stamp=current
        if stats['oversized_lines']>oversized_before:truncated=True
        oversized_before=stats['oversized_lines']
        if not block and current is None and stamp is None:continue
        chars+=len(line)
        if len(block)<MAX_RECORD_LINES and chars<=MAX_RECORD_CHARS:
            block.append((n,line))
        else:truncated=True
    if block:yield block,stamp,truncated


def trace_messages(case: Path, window: Window, *, salt: bytes | None=None,
                   message: str='', service: str='', limit: int=MAX_TRACE_ROWS) -> dict:
    if not 1<=limit<=MAX_TRACE_ROWS:raise ValueError('메시지 조회 상한을 확인하세요.')
    if message and not VALID_ID.fullmatch(message):raise ValueError('메시지 식별값 형식이 올바르지 않습니다.')
    if service and not VALID_ID.fullmatch(service):raise ValueError('서비스 식별값 형식이 올바르지 않습니다.')
    manifest=_get_manifest(case);bounds=window.bounds()
    salt=salt or secrets.token_bytes(32)
    if not isinstance(salt,bytes) or len(salt)!=32:raise ValueError('추적 키 형식을 확인하세요.')
    groups={};events=[];counts=Counter();candidates=0;omitted=0;stats=Counter();unsupported_sql=0
    for f in manifest['files']:
        if f['kind'] not in {'job','info','debug','dbwrap','err'}:continue
        origin=_safe_source(case,f);codec='utf-8' if f['encoding']=='utf-8-replace' else f['encoding']
        anchor=date.fromisoformat(f['date_hint'] or manifest['reference_date']) if (f['date_hint'] or manifest['reference_date']) else None
        resolver=ClockResolver(anchor)
        for block,clock,truncated in raw_records(origin,codec):
            occurred,quality=resolver.normalize(clock)
            t=instant(occurred)
            if t is None:stats['undated_records']+=1;continue
            if not bounds[0]<=t<bounds[1]:continue
            stats['scanned_records']+=1
            text='\n'.join(line for _,line in block)
            if 'MESSAGE_SEQNO' not in text.upper():continue
            candidates+=1
            if truncated:stats['oversized_records_skipped']+=1;continue
            values,ambiguous=fields(text)
            # Never associate separate SQL execution IDs in a single record.
            sql_ids=set(re.findall(r'\bNO_ID_(-?\d+)=',text))
            if ambiguous or len(sql_ids)>1:stats['ambiguous_records']+=1;continue
            msg=values.get('MESSAGE_SEQNO');svc=values.get('SERVICE_SEQNO')
            if not msg or not svc:
                stats['missing_identity_records']+=1
                if '?' in text:unsupported_sql+=1
                continue
            if message and msg!=message or service and svc!=service:continue
            key=_alias(salt,'message',svc+'\0'+msg);svc_alias=_alias(salt,'service',svc)
            if key not in groups and len(groups)>=MAX_TRACE_GROUPS:
                omitted+=1;continue
            g=groups.setdefault(key,{'message':key,'service':svc_alias,'records':0,'first':iso(t),'last':iso(t),'stages':set(),
                                    'job_types':set(),'send_flags':set(),'stage_times':{},'evidence':[]})
            # SQL predicates/literals are not acknowledgements or transitions.
            sql_context=bool(f['kind']=='dbwrap' or re.search(r'\b(?:SELECT|UPDATE|INSERT|DELETE|MERGE|WHERE|PSTMT)\b',text,re.I))
            stages=['identifier_observed'] if sql_context else stage_codes(text,values)
            jt=values.get('JOB_TYPE');jt=jt if jt in {'R00','B00'} else 'unknown'
            flag=values.get('SEND_FLAG');flag=flag if flag and re.fullmatch(r'[A-Z0-9]{1,4}',flag) else None
            response=values.get('RESPONSE_CODE');response=response if response and re.fullmatch(r'[A-Z0-9_-]{1,12}',response) else None
            failed=bool(re.search(r'\b(?:failed|failure|error)\b|[A-Za-z]+Exception\b|실패|오류|수락되지|not accepted',text,re.I))
            # A stage label says its marker was seen; failure markers suppress
            # acceptance even when a conflicting S appears in the same record.
            if failed and 'accepted' in stages:stages.remove('accepted');stages.append('acceptance_conflict')
            g['records']+=1;g['first']=min(g['first'],iso(t));g['last']=max(g['last'],iso(t))
            g['stages'].update(stages);g['job_types'].add(jt)
            if flag:g['send_flags'].add(flag)
            for stage in stages:
                g['stage_times'].setdefault(stage,[])
                if len(g['stage_times'][stage])<100:g['stage_times'][stage].append(iso(t))
            ref={'file_id':f['file_id'],'line_start':block[0][0],'line_end':block[-1][0],'occurred_at':iso(t)}
            if len(g['evidence'])<30:g['evidence'].append(ref)
            counts[jt]+=1
            if len(events)<limit:
                events.append({'message':key,'service':svc_alias,'job_type':jt,'send_flag':flag,'response_code':response,
                               'stages':stages,'failure_marker':failed,'final_delivery_confirmed':False,
                               'observation_basis':'SQL 식별값·조건(실행 결과 미확인)' if sql_context else '로그에 기록된 식별값·단계 표지','ref':ref})
            else:omitted+=1
        _safe_source(case,f)
    result=[]
    for g in groups.values():
        g['missing_stages']=[code for code,_ in STAGES if code not in g['stages']]
        g['stages']=sorted(g['stages']);g['job_types']=sorted(g['job_types']);g['send_flags']=sorted(g['send_flags'])
        g['evidence_omitted']=g['records']-len(g['evidence']);g['final_delivery_confirmed']=False
        # Timings are between observed markers, not a service guarantee. Retries
        # are left as repeated records; no arbitrary request/result pairing.
        requests=g['stage_times'].get('request',[]);results=g['stage_times'].get('result',[])
        g['request_to_result_seconds']=((instant(results[0])-instant(requests[0])).total_seconds()
               if len(requests)==len(results)==1 and instant(results[0])>=instant(requests[0]) else None)
        result.append(g)
    return {'groups':sorted(result,key=lambda g:(g['first'],g['message'])),
            'events':sorted(events,key=lambda e:(e['ref']['occurred_at'],e['ref']['file_id'],e['ref']['line_start'])),
            'candidate_records':candidates,'observations_by_job_type':dict(counts),'coverage':dict(stats),
            'unsupported_bind_records':unsupported_sql,'omitted_records':omitted,
            'note':'동일 레코드에 명시된 서비스+메시지 키만 연결합니다. 표시는 가명이며 원본 ID·본문·SQL은 보관하지 않습니다. '
                   '미관측 단계는 실패가 아닌 자료 미확인입니다. SQL 조건값을 수락·상태 전이로 해석하지 않습니다. '
                   'R00/B00 기록 수는 완료·고유 메시지·DB 적체 건수가 아닙니다.'}
