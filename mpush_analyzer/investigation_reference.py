"""Optional XML summaries and operator observations; never prerequisites.

No source XML values/credentials are retained except allowlisted cron/debug
facts. This is advisory configuration evidence, not proven runtime state.
"""
from __future__ import annotations
import hashlib
from pathlib import Path
import re
from xml.parsers import expat

from .investigation import instant, iso, job_name, daily_time, periodic_interval
from .support_store import read_json, write_json, file_lock, plain, stamp
from .pipeline import _get_manifest

REFERENCE_FILE='investigation.private.json'
MAX_XML=512*1024
MAX_NODES=5000
MAX_DEPTH=24
BOOL={'true':True,'false':False,'yes':True,'no':False,'on':True,'off':False,'1':True,'0':False}
ALIASES={'DailyBatchJob':'DAILY_BATCH_JOB','ReceiveResultAgentJob':'RECEIVE_RESULT_AGENT_JOB',
         'HACheckJob':'HA_CHECK_JOB','SendBatchFileJob':'SEND_BATCH_FILE_JOB'}


def parse_xml_reference(data: bytes) -> dict:
    if not isinstance(data,bytes) or not 0<len(data)<=MAX_XML:
        raise ValueError('선택 XML은 비어 있지 않은 512KiB 이하 파일이어야 합니다.')
    try:text=data.decode('utf-8-sig')
    except UnicodeError as exc:raise ValueError('XML 참고 파서는 UTF-8만 지원합니다. 없어도 로그 분석은 가능합니다.') from exc
    if '\x00' in text or re.search(r'<!\s*(?:DOCTYPE|ENTITY)',text,re.I):
        raise ValueError('DOCTYPE/ENTITY 또는 잘못된 XML 문자를 차단했습니다.')
    parser=expat.ParserCreate(namespace_separator='}')
    stack=[];nodes=0;schedules=[];debug=[];ha_comments=0
    def fail(*args):raise ValueError('외부 엔터티·DTD·파라미터 엔터티는 허용하지 않습니다.')
    def tag(value):return value.rsplit('}',1)[-1].lower().replace('_','-')
    def add_schedule(name,cron,line):
        name=ALIASES.get(name,name)
        if job_name(name) and isinstance(cron,str) and re.fullmatch(r'[0-9*/?, -]{3,100}',cron) and len(cron.split()) in (6,7):
            item={'job':name,'cron':cron,'line':line,'daily':daily_time(cron),'interval':periodic_interval(cron)}
            if item not in schedules:schedules.append(item)
    def start(name,attrs):
        nonlocal nodes
        nodes+=1
        if nodes>MAX_NODES or len(stack)>=MAX_DEPTH or len(attrs)>30:raise ValueError('XML 항목 수·중첩 깊이·속성 제한을 초과했습니다.')
        attributes={tag(k):v for k,v in attrs.items()}
        if any(len(v)>2000 for v in attributes.values()):raise ValueError('XML 속성 길이 제한을 초과했습니다.')
        entry={'tag':tag(name),'attrs':attributes,'text':'','children':{},'line':parser.CurrentLineNumber}
        stack.append(entry)
        candidate=attributes.get('job-name') or attributes.get('job') or attributes.get('name')
        cron=attributes.get('cron-expression') or attributes.get('cron')
        if candidate and cron:add_schedule(candidate,cron,entry['line'])
        if attributes.get('name','').lower() in {'debug','debug.enabled'} or entry['tag'] in {'debug','debug-enabled'}:
            value=attributes.get('value') or attributes.get('enabled')
            if value is not None and value.lower() in BOOL:debug.append({'enabled':BOOL[value.lower()],'line':entry['line']})
    def chars(value):
        if stack:
            stack[-1]['text']+=value
            if len(stack[-1]['text'])>4096:raise ValueError('XML 텍스트 길이 제한을 초과했습니다.')
    def end(name):
        item=stack.pop();children=item['children'];value=item['text'].strip()
        candidate=children.get('job-name') or children.get('name') or item['attrs'].get('name')
        cron=children.get('cron-expression') or children.get('cron')
        if candidate and cron:add_schedule(candidate,cron,item['line'])
        if item['tag'] in {'debug','debug-enabled'} and value.lower() in BOOL:
            debug.append({'enabled':BOOL[value.lower()],'line':item['line']})
        if stack and item['tag'] in {'name','job-name','cron-expression','cron'}:
            stack[-1]['children'][item['tag']]=value
    def comment(value):
        nonlocal ha_comments
        if re.search(r'\b(?:AGENT_HA_CHECK|HACheckJob)\b',value):ha_comments+=1
    def declaration(version,encoding,standalone):
        if encoding and encoding.lower().replace('_','-') not in {'utf-8','utf8'}:fail()
    parser.StartElementHandler=start;parser.EndElementHandler=end;parser.CharacterDataHandler=chars
    parser.CommentHandler=comment;parser.StartDoctypeDeclHandler=fail;parser.EntityDeclHandler=fail
    parser.ExternalEntityRefHandler=fail;parser.XmlDeclHandler=declaration
    parser.SetParamEntityParsing(expat.XML_PARAM_ENTITY_PARSING_NEVER)
    try:parser.Parse(text,True)
    except expat.ExpatError as exc:raise ValueError('XML 참고자료 형식이 올바르지 않습니다. 핵심 로그 분석과는 별개입니다.') from exc
    return {'sha256':hashlib.sha256(data).hexdigest(),'schedules':schedules[:100],
            'schedules_omitted':max(0,len(schedules)-100),'debug_flags':debug[:100],
            'ha_mentions_in_comments':ha_comments,
            'note':'제공된 XML의 참고 정보입니다. 실제 배포·활성화·주석 외 설정 여부는 별도 확인이 필요합니다.'}


def read_observations(case: Path) -> dict:
    doc=read_json(case/REFERENCE_FILE,{})
    if not isinstance(doc,dict) or (doc and (doc.get('analysis_id')!=case.name or type(doc.get('revision')) is not int or doc['revision']<1)):
        raise ValueError('운영 관측 기록을 검증하지 못했습니다.')
    if doc:
        if (doc.get('pid_status') not in {'unknown','alive','not_running'} or
            doc.get('reference_version') not in {'unknown','3.2','3.3','2.8-reference'} or
            type(doc.get('restart_confirmed')) is not bool):
            raise ValueError('운영 관측 상태 값이 올바르지 않습니다.')
        if doc['pid_status']!='unknown' and instant(doc.get('pid_checked_at')) is None:
            raise ValueError('PID 확인 시각이 올바르지 않습니다.')
        if doc['restart_confirmed'] and instant(doc.get('restarted_at')) is None:
            raise ValueError('재시작 시각이 올바르지 않습니다.')
        plain(doc.get('operator_note',''),3000)
    return doc


def save_observations(case: Path, fields: dict, *, expected_revision: int) -> dict:
    _get_manifest(case)
    with file_lock(case,'investigation-reference'):
        old=read_observations(case)
        if type(expected_revision) is not int or old.get('revision',0)!=expected_revision:
            raise ValueError('운영 관측 기록이 변경됐습니다. 새로고침 후 저장하세요.')
        pid=fields.get('pid_status','unknown')
        if pid not in {'unknown','alive','not_running'}:raise ValueError('PID 상태 형식이 잘못됐습니다.')
        checked=instant(fields.get('pid_checked_at')) if fields.get('pid_checked_at') else None
        if pid!='unknown' and checked is None:raise ValueError('PID 상태를 확인한 시각을 입력하세요.')
        restarted=fields.get('restart_confirmed',False)
        if type(restarted) is not bool:raise ValueError('재시작 확인 형식이 잘못됐습니다.')
        restarted_at=instant(fields.get('restarted_at')) if fields.get('restarted_at') else None
        if restarted and restarted_at is None:raise ValueError('재시작을 확인한 시각을 입력하세요.')
        version=fields.get('reference_version','unknown')
        if version not in {'unknown','3.2','3.3','2.8-reference'}:raise ValueError('참고 버전 형식을 확인하세요.')
        doc={'analysis_id':case.name,'revision':expected_revision+1,'updated_at':stamp(),
             'pid_status':pid,'pid_checked_at':iso(checked),'restart_confirmed':restarted,
             'restarted_at':iso(restarted_at),'reference_version':version,
             'operator_note':plain(fields.get('operator_note',''),3000)}
        write_json(case/REFERENCE_FILE,doc)
        return doc


def crosscheck_config(manifest: dict, cadence: dict, xml_reference: dict | None = None) -> list[dict]:
    """Compare provided settings and observed registrations, not runtime truth."""
    rows=[];config=manifest.get('config_summary') or {}
    debug=(config.get('agent') or {}).get('debug_enabled')
    has_debug=any(f['kind']=='debug' for f in manifest['files'])
    rows.append({'항목':'debug 설정/자료','설정':str(debug) if debug is not None else '미제공',
                 '관측':'debug 파일 제공' if has_debug else 'debug 파일 미제공',
                 '해석':'현재 배포 설정인지 확인 필요. 파일 부재를 장애로 단정하지 않음'})
    ha=(config.get('ha') or {}).get('enabled')
    rows.append({'항목':'HA 사용 설정','설정':str(ha) if ha is not None else '미제공',
                 '관측':'단일 Agent 자료','해석':'이 설정만으로 Active/Standby 역할·전환·합산 처리량을 판단하지 않음'})
    if xml_reference:
        observed={}
        for item in cadence.get('schedules',[]):observed.setdefault(item['job'],set()).add(item['cron'])
        for item in xml_reference.get('schedules',[]):
            seen=observed.get(item['job'],set())
            verdict=('동일 표현식 관측' if seen=={item['cron']} else
                     '복수/다른 표현식 관측 — 배포 시점 확인' if seen else '대응 예약 로그 미관측 — 미설정으로 단정 금지')
            rows.append({'항목':item['job'],'설정':item['cron'],
                         '관측':' / '.join(sorted(seen)) or '미관측','해석':verdict})
    return rows
