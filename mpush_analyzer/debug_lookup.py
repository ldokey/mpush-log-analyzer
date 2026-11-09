"""Exact-ID debug lookup across native key/value, JSON and LMultiData tables.

Discovery is not delivery inference. Missing service is shown separately, never
filled from the user's filter, another line, configuration or a nearby record.
"""
from __future__ import annotations
from collections import Counter
from datetime import date
from pathlib import Path
import json
import re
import secrets

from .pipeline import _get_manifest, _safe_source, _read_numbered
from .parsers.common import ClockResolver, parse_clock, LOG_START
from .message_trace import _alias, VALID_ID
from .message_outcomes import _received, _operation_states, _leg, SAFE_RESULT_CODE, PENDING
from .investigation import instant, iso, Window

KEYS={k.replace('_','').lower():k for k in ('MESSAGE_SEQNO','AGENT_MESSAGE_SEQNO','SERVICE_SEQNO','RESPONSE_CODE','SEND_RESULT_CODE1','SEND_RESULT_CODE2','BACKUP_PROCESS_CODE')}
KEY_RE=r'(?:AGENT_?MESSAGE_?SEQNO|MESSAGE_?SEQNO|SERVICE_?SEQNO|RESPONSE_?CODE|SEND_?RESULT_?CODE[12]|BACKUP_?PROCESS_?CODE)'
PAIR=re.compile(r'(?<![A-Za-z0-9_])(?:[\'"])?('+KEY_RE+r')(?:[\'"])?\s*(?:value\s*)?(?:::|:|=)\s*[\'"]?([A-Za-z0-9_-]{1,64})(?=[\s,;)}\]>\'\"]|$)',re.I)
BODY=re.compile(r'\b(?:SEND_MESSAGE|SENDMESSAGE|BACKUP_MESSAGE|BACKUPMESSAGE|MESSAGE_BODY|MESSAGE_TEXT|CONTENT|BODY|TEXT|SUBJECT|SQL_TEXT|QUERY_TEXT)\b\s*[\'"]?\s*[:=]',re.I)
SQL=re.compile(r'\b(?:SELECT|UPDATE|INSERT|DELETE|MERGE|WHERE|PSTMT)\b',re.I)
MAX_ROWS=5000
MAX_RECORD_CHARS=65536
MAX_JSON_NODES=2000


def canonical(key):
    return KEYS.get(re.sub(r'[_\s-]','',key).lower()) if isinstance(key,str) else None


def pairs(text):
    out={};ambiguous=False
    for m in PAIR.finditer(text):
        k=canonical(m.group(1));v=m.group(2)
        if k in out and out[k]!=v:ambiguous=True
        out[k]=v
    return out,ambiguous


def json_records(text):
    """Parse complete JSON subtrees, retaining only known scalar outer fields."""
    prefix=LOG_START.match(text)
    text=text[prefix.end():] if prefix else text
    def unique_object(items):
        out={};seen=set()
        for key,value in items:
            name=canonical(key)
            if name and name in seen:
                out['__ambiguous_identity__']=True
            if name:seen.add(name)
            out[key]=value
        return out
    decoder=json.JSONDecoder(object_pairs_hook=unique_object);first=min([i for i in (text.find('{'),text.find('[')) if i>=0],default=-1)
    if first<0:return [],False,''
    candidates=[m.start() for m in re.finditer(r'[\[{]',text)][:20]
    root=None
    for at in candidates:
        try:
            root,_=decoder.raw_decode(text[at:]);break
        except (ValueError,RecursionError):continue
    if root is None:return [],False,''
    queue=[root];out=[];visited=0
    while queue and visited<MAX_JSON_NODES:
        obj=queue.pop();visited+=1
        if isinstance(obj,dict):
            if obj.get('__ambiguous_identity__') is True:continue
            values={}
            for k,v in obj.items():
                c=canonical(k)
                if c and type(v) in (str,int) and VALID_ID.fullmatch(str(v)):
                    values[c]=str(v)
            if any(k in values for k in ('MESSAGE_SEQNO','AGENT_MESSAGE_SEQNO')):out.append(values)
            # Never recurse into a message/body/SQL field, even when it is an object.
            for k,v in obj.items():
                if re.sub(r'[_-]','',str(k)).lower() in {'message','sendmessage','backupmessage','messagebody','messagetext','content','body','text','subject','sql','sqltext','querytext'}:continue
                if isinstance(v,(dict,list)) and len(queue)<MAX_JSON_NODES:queue.append(v)
        elif isinstance(obj,list):queue.extend(reversed(obj[:MAX_JSON_NODES-visited]))
    return out,True,text[:at]


def records(path: Path, codec: str):
    """Stream tables one row at a time; long batches do not hit record-line caps."""
    stats={'lines_read':0,'decode_replacement_lines':0,'oversized_lines':0}
    block=[];stamp=None;chars=0;truncated=False;headers=None;context='';header_line=None
    def ordinary():
        if not block:return []
        text='\n'.join(t for _,t in block)
        base={'clock':stamp,'start':block[0][0],'end':block[-1][0]}
        if truncated:return [{**base,'excluded':'oversized'}]
        js,parsed,prefix=json_records(text)
        if parsed:
            if SQL.search(prefix):return [{**base,'excluded':'sql'}]
            return [{**base,'values':v,'context':prefix,'format':'json'} for v in js] or [{**base,'excluded':'json_without_identity'}]
        if SQL.search(text):return [{**base,'excluded':'sql'}]
        if BODY.search(text):return [{**base,'excluded':'payload'}]
        v,ambiguous=pairs(text)
        if ambiguous:return [{**base,'excluded':'ambiguous'}]
        return [{**base,'values':v,'context':text,'format':'key_value'}] if v else []
    last_oversized=0
    for n,line in _read_numbered(path,codec,stats):
        current=parse_clock(line)
        if current is not None:
            yield from ordinary();block=[];chars=0;truncated=False;headers=None;context='';header_line=None;stamp=current
        oversize=stats['oversized_lines']>last_oversized;last_oversized=stats['oversized_lines']
        # Known table header names only; preserve column positions but discard unknown values.
        structural=line.strip()
        cells=[c.strip() for c in structural[1:-1].split('|')] if structural.startswith('|') and structural.endswith('|') else None
        known=[canonical(c) for c in cells] if cells else []
        if cells and any(k in {'MESSAGE_SEQNO','AGENT_MESSAGE_SEQNO'} for k in known) and any(c.lower()=='{index}' for c in cells):
            context='\n'.join(t for _,t in block)
            if SQL.search(context) or BODY.search(context) or truncated:
                headers=None;block=[];continue
            headers=known;header_line=n;block=[];chars=0
            continue
        if headers is not None:
            if cells:
                if oversize or len(cells)!=len(headers):
                    yield {'clock':stamp,'start':n,'end':n,'excluded':'malformed_table'};continue
                values={};ambiguous=False
                for key,value in zip(headers,cells):
                    if key and value:
                        if not VALID_ID.fullmatch(value):ambiguous=True;continue
                        if key in values and values[key]!=value:ambiguous=True
                        values[key]=value
                if ambiguous:yield {'clock':stamp,'start':n,'end':n,'excluded':'ambiguous'};continue
                cv,_=pairs(context)
                # Only explicit request acceptance is shared by this table's enclosing log.
                if 'RESPONSE_CODE' not in values and cv.get('RESPONSE_CODE') in {'S','E','F'}:values['RESPONSE_CODE']=cv['RESPONSE_CODE']
                yield {'clock':stamp,'start':n,'end':n,'header_line':header_line,'values':values,'context':context,'format':'table'}
                continue
            if not line.strip() or re.fullmatch(r'[\s+\-=]+',line):continue
            if '[Total Row Size' in line:headers=None;context='';continue
            headers=None;context=''
        if stamp is None:continue
        chars+=len(line)
        if oversize:truncated=True
        if len(block)<200 and chars<=MAX_RECORD_CHARS:block.append((n,line))
        else:truncated=True
    yield from ordinary()


def search_debug(case: Path, window: Window | None, *, message: str, service: str='',
                 identifier_field: str='MESSAGE_SEQNO', include_secondary: bool=False,
                 include_undated: bool=True, anchor_date: date | None=None,
                 date_confirmed: bool=False, redetect_encoding: bool=False,
                 salt: bytes | None=None, limit: int=MAX_ROWS) -> dict:
    if not isinstance(message,str) or not VALID_ID.fullmatch(message):raise ValueError('정확한 메시지 번호를 입력하세요.')
    if not isinstance(service,str) or service and not VALID_ID.fullmatch(service):raise ValueError('서비스 번호 형식을 확인하세요.')
    if identifier_field not in {'MESSAGE_SEQNO','AGENT_MESSAGE_SEQNO'}:raise ValueError('메시지 번호 종류를 확인하세요.')
    if type(limit) is not int or not 1<=limit<=MAX_ROWS:raise ValueError('검색 표시 상한을 확인하세요.')
    for b in (include_secondary,include_undated,redetect_encoding):
        if type(b) is not bool:raise ValueError('검색 옵션 형식이 올바르지 않습니다.')
    salt=secrets.token_bytes(32) if salt is None else salt
    if not isinstance(salt,bytes) or len(salt)!=32:raise ValueError('가명화 키가 올바르지 않습니다.')
    manifest=_get_manifest(case)
    if anchor_date is not None:
        if type(anchor_date) is not date or date_confirmed is not True or manifest.get('reference_date'):raise ValueError('날짜 보정의 실제 기준일 확인이 필요합니다.')
        manifest['reference_date']=anchor_date.isoformat()
    bounds=window.bounds() if window else None
    kinds={'debug','info','err'} if include_secondary else {'debug'}
    rows=[];counts=Counter();sources=[];matched=0;outcomes={};table_formats=Counter()
    for f in manifest['files']:
        if f['kind'] not in kinds:continue
        sources.append(f['file_id']);path=_safe_source(case,f)
        codec=f['encoding']
        if redetect_encoding:
            from .diagnostics_input import _file_encoding
            codec=_file_encoding(path)
        codec='utf-8' if codec=='utf-8-replace' else codec
        hint=f.get('date_hint') or manifest.get('reference_date');resolver=ClockResolver(date.fromisoformat(hint) if hint else None)
        for r in records(path,codec):
            counts['records']+=1
            occurred,_=resolver.normalize(r['clock']);point=instant(occurred)
            if r.get('excluded'):
                counts['excluded_'+r['excluded']]+=1;continue
            values=r['values']
            if values.get(identifier_field)!=message:continue
            counts['message_matches']+=1
            if point is None:
                counts['undated_matches']+=1
                if not include_undated:continue
            elif bounds and not bounds[0]<=point<bounds[1]:counts['outside_window']+=1;continue
            svc=values.get('SERVICE_SEQNO')
            if svc and service and svc!=service:counts['service_mismatch']+=1;continue
            scope='confirmed' if svc else 'unconfirmed'
            counts['service_'+scope]+=1;matched+=1
            table_formats[r['format']]+=1
            # Build a safe structural record; no raw body, SQL, fileName, DB schema or ID.
            safe_context=r['context'];received=_received(safe_context)
            sql=bool(SQL.search(safe_context))
            codes={}
            for key in ('SEND_RESULT_CODE1','SEND_RESULT_CODE2'):
                code=values.get(key,'').upper()
                if received and not sql and code not in PENDING and SAFE_RESULT_CODE.fullmatch(code):codes[key]=code
            primary=_leg({codes['SEND_RESULT_CODE1']} if 'SEND_RESULT_CODE1' in codes else set(),False)
            fallback=_leg({codes['SEND_RESULT_CODE2']} if 'SEND_RESULT_CODE2' in codes else set(),False)
            accepted=values.get('RESPONSE_CODE')=='S' and not re.search(r'not accepted|수락\s*(?:실패|거절)|요청\s*실패',safe_context,re.I)
            status='result_success' if primary['state']=='success' or fallback['state']=='success' else 'result_failure_observed' if primary['state']=='failure' or fallback['state']=='failure' else 'request_accepted' if accepted else 'identifier_found'
            if not svc:status='service_unconfirmed'
            group_key=_alias(salt,'message',identifier_field+'\0'+(svc or '<unconfirmed>')+'\0'+message)
            if group_key not in outcomes and len(outcomes)>=MAX_ROWS:
                counts['outcome_groups_omitted']+=1
                continue
            g=outcomes.setdefault(group_key,{'primary':set(),'fallback':set(),'confirmed':bool(svc),'records':0})
            g['records']+=1
            if svc:
                for leg,field in [('primary','SEND_RESULT_CODE1'),('fallback','SEND_RESULT_CODE2')]:
                    if field in codes:
                        if len(g[leg])<12:g[leg].add(codes[field])
                        elif codes[field] not in g[leg]:counts['outcome_codes_omitted']+=1
            if len(rows)<limit:
                rows.append({'message':group_key,'service':_alias(salt,'service',svc) if svc else None,
                    'service_scope':scope,'identifier_field':identifier_field,'format':r['format'],
                    'status':status,'primary':primary,'fallback':fallback,'request_accepted':accepted,
                    'result_received':received,'final_result_eligible':bool(svc and received and codes),
                    'clock':r['clock'],'undated':point is None,
                    'stages':_operation_states(safe_context,values,sql),
                    'ref':{'file_id':f['file_id'],'line_start':r['start'],'line_end':r['end'],'occurred_at':iso(point)},
                    'header_line':r.get('header_line')})
        _safe_source(case,f)
    conflicts=sum(len(g['primary'])>1 or len(g['fallback'])>1 for g in outcomes.values())
    return {'rows':rows,'total_matches':matched,'omitted':max(0,matched-len(rows)),
        'coverage':dict(counts),'sources':sources,'formats':dict(table_formats),'conflicting_messages':conflicts,
        'identifier_field':identifier_field,'source_mode':'debug + info/err' if include_secondary else 'debug',
        'note':'메시지 번호가 발견된 기록을 표시합니다. 서비스 미기록은 사용자 입력으로 채우지 않으며, 수락 S·단계 표지는 최종 발송 성공이 아닙니다.',
        'empty_reason':None if matched else '선택한 로그/구간에서 해당 메시지 번호를 찾지 못했습니다. debug 존재 여부, 실제 번호 종류, 날짜/구간과 별도 서비스 불일치 건수를 확인하세요.'}
