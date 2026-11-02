"""Evidence-first investigation over sanitized event streams (bounded memory).

Windows are half-open [start,end), all calculations use Asia/Seoul instants.
No observed count is a delivery count. Missing evidence is never a zero result.
"""
from __future__ import annotations
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta
import math
from pathlib import Path
import re
from statistics import median
from zoneinfo import ZoneInfo

from .dashboard_data import events_iter
from .exception_chain import chain_label, safe_chain, REASONS
from .finding_view_v2 import file_label
from .workbench_data import project_event

KST = ZoneInfo('Asia/Seoul')
MAX_SAMPLES = 50_000
MAX_TOTAL_SAMPLES = 250_000
MAX_CONTINUITY_RECORDS = 100_000
MAX_GROUPS = 300
MAX_EVIDENCE = 100
JOB_RE = re.compile(r'[A-Z][A-Z0-9_]{2,63}\Z')
KINDS = {'err','job','info','debug','dbwrap'}
SELECT_NOTE = 'SELECT 단계에는 조회뿐 아니라 선점 DB 처리가 포함될 수 있습니다. DB Lock 확정 근거가 아닙니다.'
LIMIT_NOTE = '시간적으로 가까운 기록·긴 처리시간·기록 공백은 원인 확정이나 프로세스 종료의 증거가 아닙니다.'


def instant(value) -> datetime | None:
    if not isinstance(value,str) or len(value)>48: return None
    if not re.fullmatch(r'\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(?::\d{2}(?:\.\d{1,6})?)?(?:Z|[+-]\d{2}:\d{2})?',value): return None
    try:
        dt=datetime.fromisoformat(value)
        return (dt.replace(tzinfo=KST) if dt.tzinfo is None else dt).astimezone(KST)
    except ValueError: return None


def iso(value: datetime | None) -> str | None:
    return value.isoformat(timespec='milliseconds') if value else None


def number(value, limit=1e10):
    return value if type(value) in (int,float) and math.isfinite(value) and 0<=value<=limit else None


def job_name(value) -> str | None:
    return value if isinstance(value,str) and JOB_RE.fullmatch(value) else None


@dataclass(frozen=True)
class Window:
    start: str
    end: str
    def bounds(self):
        start,end=instant(self.start),instant(self.end)
        if start is None or end is None or not 0 < (end-start).total_seconds() <= 31*86400:
            raise ValueError('시작/종료를 유효한 날짜·시각으로 입력하세요. 조회 범위는 0초 초과 31일 이하입니다.')
        return start,end
    @property
    def seconds(self):
        start,end=self.bounds();return (end-start).total_seconds()


def in_window(event, bounds):
    point=instant(event.get('occurred_at'))
    return point is not None and bounds[0] <= point < bounds[1]


def reference(event):
    return {'file_id':event['file_id'],'line_start':event['line_start'],
            'line_end':event['line_end'],'occurred_at':iso(instant(event.get('occurred_at')))}


def population(case: Path, manifest: dict) -> dict:
    """Small aggregate, no raw values; first/last observed != outage interval."""
    first=last=None; dated=undated=0; kinds=Counter()
    for e in events_iter(case,manifest):
        t=instant(e.get('occurred_at'))
        kinds[e.get('log_kind') if e.get('log_kind') in KINDS else 'unknown']+=1
        if t:
            dated+=1;first=min(first,t) if first else t;last=max(last,t) if last else t
        else:undated+=1
    return {'first':iso(first),'last':iso(last),'dated':dated,'undated':undated,'by_kind':dict(kinds)}


def quality(manifest: dict) -> dict:
    logs=[f for f in manifest['files'] if f['kind'] in KINDS]
    return {
        'version':manifest.get('agent_version','auto'),
        'version_note':('버전은 사용자 지정 값이며 현장 빌드·커스터마이징까지 검증한 것은 아닙니다.'
                        if manifest.get('agent_version') in {'3.2','3.3'} else '버전 미상: 3.x 공통 구조만 해석하며 버전별 상태 의미를 확정하지 않습니다.'),
        'missing_kinds':sorted(KINDS-{f['kind'] for f in logs}),
        'nonfull_files':[f['file_id'] for f in logs if f['completeness']!='full'],
        'undated_files':[f['file_id'] for f in logs if not (f.get('date_hint') or manifest.get('reference_date'))],
        'collected_at':manifest.get('collected_at'),
        'notes':[LIMIT_NOTE, SELECT_NOTE, 'XML·Agent 2.8 자료는 선택 참고입니다. 없어도 분석을 수행합니다.'],
    }


def timeline(case: Path, manifest: dict, window: Window, *, page=1, page_size=100,
             kinds: tuple[str,...]=()) -> dict:
    bounds=window.bounds()
    if type(page) is not int or page<1 or page>1000000 or page_size not in (25,50,100,200):
        raise ValueError('타임라인 페이지 범위를 확인하세요.')
    if not set(kinds)<=KINDS:raise ValueError('지원하지 않는 로그 유형입니다.')
    total=undated=0; rows=[]; bins={}; widths=max(1,math.ceil(window.seconds/600))
    for e in events_iter(case,manifest):
        if kinds and e.get('log_kind') not in kinds:continue
        t=instant(e.get('occurred_at'))
        if t is None:undated+=1;continue
        if not bounds[0]<=t<bounds[1]:continue
        total+=1
        if (page-1)*page_size<total<=page*page_size:
            row=project_event(e,manifest)
            row['로그 유형']=e['log_kind'] if e['log_kind'] in KINDS else 'unknown'
            rows.append(row)
        b=int((t-bounds[0]).total_seconds()//widths)
        counts=bins.setdefault(b,{k:0 for k in sorted(KINDS)})
        if e['log_kind'] in counts:counts[e['log_kind']]+=1
    return {'total':total,'pages':max(1,math.ceil(total/page_size)),'page':page,'rows':rows,
            'undated_excluded':undated,'bucket_seconds':widths,
            'bins':[{'시각':iso(bounds[0]+timedelta(seconds=k*widths)),**v} for k,v in sorted(bins.items())]}


def exception_groups(case: Path, manifest: dict, window: Window) -> dict:
    bounds=window.bounds(); groups={}; skipped=0; total=0;legacy=0
    for e in events_iter(case,manifest):
        if e.get('event_type')!='log_error' or not in_window(e,bounds):continue
        total+=1; d=e.get('details') or {}
        legacy+=not isinstance(d.get('exception_chain'),list)
        label=chain_label(d,e['line_start'],e['line_end'])
        # Keep different source copies separate; repetition != independent incidents.
        key=(e['file_id'],label)
        if key not in groups and len(groups)>=MAX_GROUPS:skipped+=1;continue
        g=groups.setdefault(key,{'chain':label,'file_id':e['file_id'],'count':0,'first':None,'last':None,
                               'jobs':set(),'reasons':set(),'evidence':[],'truncated_records':0})
        g['count']+=1;t=instant(e['occurred_at'])
        if g['first'] is None or t<instant(g['first']):g['first']=iso(t)
        if g['last'] is None or t>instant(g['last']):g['last']=iso(t)
        g['truncated_records']+=bool(d.get('chain_truncated'))
        for name in d.get('job_names',[]) if isinstance(d.get('job_names',[]),list) else []:
            if job_name(name):g['jobs'].add(name)
        for code in d.get('reason_codes',[]) if isinstance(d.get('reason_codes',[]),list) else []:
            if code in REASONS:g['reasons'].add(code)
        if len(g['evidence'])<MAX_EVIDENCE:g['evidence'].append(reference(e))
    values=[]
    for g in groups.values():
        g['jobs']=sorted(g['jobs']);g['reasons']=sorted(g['reasons'])
        g['evidence_omitted']=g['count']-len(g['evidence']);values.append(g)
    return {'groups':sorted(values,key=lambda x:(-x['count'],x['first'] or '')),
            'records':total,'unaggregated_records':skipped,'legacy_records':legacy,
            'note':'반복은 로그 기록 수입니다. 여러 파일의 동일 오류 복사를 별도 사건 수로 합산하지 않습니다.'}


class Distribution:
    def __init__(self, budget=None):
        self.count=0;self.total=0.0;self.maximum=None;self.values=[];self.omitted=0
        self.budget=budget
    def add(self,value):
        value=number(value)
        if value is None:return
        self.count+=1;self.total+=value;self.maximum=max(self.maximum,value) if self.maximum is not None else value
        if len(self.values)<MAX_SAMPLES and (self.budget is None or self.budget[0]>0):
            self.values.append(value)
            if self.budget is not None:self.budget[0]-=1
        else:self.omitted+=1
    def summary(self):
        values=sorted(self.values) if not self.omitted else []
        def quantile(p):
            if not values:return None
            rank=(len(values)-1)*p;lo=int(rank);hi=min(len(values)-1,lo+1)
            return round(values[lo]+(values[hi]-values[lo])*(rank-lo),6)
        return {'samples':self.count,'total':round(self.total,6),'mean':round(self.total/self.count,6) if self.count else None,
                'p50':quantile(.5),'p95':quantile(.95),'max':self.maximum,
                'percentiles_unavailable':bool(self.omitted)}


def window_stats(case: Path, manifest: dict, window: Window) -> dict:
    bounds=window.bounds(); groups={}; errors=0; events=0; first=last=None;unknown=0;budget=[MAX_TOTAL_SAMPLES]
    for e in events_iter(case,manifest):
        if not instant(e.get('occurred_at')):unknown+=1;continue
        if not in_window(e,bounds):continue
        events+=1;t=instant(e['occurred_at']);first=min(first,t) if first else t;last=max(last,t) if last else t
        d=e.get('details') or {};typ=e.get('event_type')
        if typ=='log_error':errors+=1
        if typ not in {'job_run','sql_execution'}:continue
        name=job_name(d.get('job_name')) if typ=='job_run' else d.get('statement_kind')
        if not name or not isinstance(name,str) or not re.fullmatch(r'[A-Z][A-Z0-9_]{0,63}',name):continue
        key=(typ,name)
        if key not in groups and len(groups)>=MAX_GROUPS:
            raise ValueError('분석 그룹 300개 제한을 초과했습니다. 기간을 좁혀 주세요.')
        g=groups.setdefault(key,{'kind':typ,'name':name,'count':0,'complete':0,'targets':0,'target_samples':0,
                                'duration':Distribution(budget),'steps':{k:Distribution(budget) for k in ('select','file','socket','http_in','http_out','db')}})
        g['count']+=1;g['complete']+=e.get('status')=='complete'
        g['duration'].add(d.get('duration_seconds') if typ=='job_run' else d.get('laptime_ms'))
        target=number(d.get('target_count'),1e9)
        if e.get('status')=='complete' and target is not None:
            g['targets']+=target;g['target_samples']+=1
        for k,v in g['steps'].items():v.add((d.get('steps_seconds') or {}).get(k))
    results=[]
    for g in groups.values():
        g['duration']=g['duration'].summary()
        g['steps']={k:v.summary() for k,v in g['steps'].items() if v.count}
        g['targets_per_window_second']=round(g['targets']/window.seconds,6) if g['target_samples'] else None
        if not g['target_samples']:g['targets']=None
        results.append(g)
    return {'groups':sorted(results,key=lambda g:(g['kind'],g['name'])),'error_records':errors,
            'events':events,'unknown_time_excluded':unknown,'first':iso(first),'last':iso(last),
            'window_seconds':window.seconds,'coverage':quality(manifest),
            'note':'구간 내 완료기록의 작업대상 합계/구간초는 관측 지표이며 성공 TPS·지속 처리능력·적체 건수가 아닙니다.'}


def compare_windows(case: Path, manifest: dict, window: Window, baseline_case: Path,
                    baseline_manifest: dict, baseline_window: Window, *, same_agent_confirmed: bool) -> dict:
    if same_agent_confirmed is not True:raise ValueError('동일 Agent와 비교 가능한 수집 조건인지 확인해야 합니다.')
    if abs(window.seconds-baseline_window.seconds)>.001:
        raise ValueError('정상/장애 비교는 동일 길이 구간을 선택하세요.')
    before=window_stats(baseline_case,baseline_manifest,baseline_window)
    after=window_stats(case,manifest,window)
    b={(g['kind'],g['name']):g for g in before['groups']};a={(g['kind'],g['name']):g for g in after['groups']}
    rows=[]
    for key in sorted(set(a)|set(b)):
        x=b.get(key);y=a.get(key);bx=x['duration'] if x else {};ay=y['duration'] if y else {}
        ratio=ay.get('p95')/bx['p95'] if bx.get('p95') and ay.get('p95') is not None else None
        rows.append({'종류':key[0],'Job/SQL':key[1],'단위':'초' if key[0]=='job_run' else 'ms',
             '기준 기록':x['count'] if x else None,'조사 기록':y['count'] if y else None,
             '기준 대상':x['targets'] if x else None,'조사 대상':y['targets'] if y else None,
             '기준 평균':bx.get('mean'),'조사 평균':ay.get('mean'),
             '기준 P50':bx.get('p50'),'조사 P50':ay.get('p50'),
             '기준 P95':bx.get('p95'),'조사 P95':ay.get('p95'),
             '기준 최대':bx.get('max'),'조사 최대':ay.get('max'),'P95 배율':round(ratio,3) if ratio is not None else None,
             '비교 상태':'양쪽 기록 있음' if x and y else '한쪽 관측 없음(0건으로 단정 금지)'})
    warnings=[]
    if manifest.get('agent_version')!=baseline_manifest.get('agent_version'):warnings.append('선언된 Agent 버전이 다릅니다.')
    if not before['events'] or not after['events']:warnings.append('한 구간에 관측 이벤트가 없습니다. 정상·장애 여부를 비교할 수 없습니다.')
    if before['coverage']['nonfull_files'] or after['coverage']['nonfull_files']:warnings.append('부분/완전성 미확인 파일이 있어 직접 처리량 비교에 제한이 있습니다.')
    return {'baseline':before,'investigation':after,'rows':rows,'warnings':warnings,
            'note':'정상 구간은 담당자가 지정한 비교 기준입니다. 프로그램이 정상 상태를 보증하지 않습니다.'}


def job_spans(case: Path, manifest: dict, window: Window, *, limit=500) -> dict:
    if type(limit) is not int or not 1<=limit<=500:raise ValueError('Job 구간 조회 상한을 확인하세요.')
    bounds=window.bounds();rows=[];total=0
    for e in events_iter(case,manifest):
        if e.get('event_type')!='job_run':continue
        d=e.get('details') or {};end=instant(e.get('occurred_at'));elapsed=number(d.get('duration_seconds'),1e6)
        if end is None or elapsed is None:continue
        recorded=instant(d.get('start_at'));start=recorded or end-timedelta(seconds=elapsed)
        if start>end:continue
        if not (start<bounds[1] and end>bounds[0]):continue
        total+=1
        if len(rows)>=limit:continue
        steps={k:number((d.get('steps_seconds') or {}).get(k),1e6) for k in ('select','file','socket','http_in','http_out','db')}
        rows.append({'job':job_name(d.get('job_name')) or 'UNKNOWN','start':iso(start),'end':iso(end),
                     'start_basis':'로그상 시작' if recorded else '소요시간 역산(추정)',
                     'seconds':elapsed,'steps':steps,'ref':reference(e)})
    overlaps=[];overlap_count=0
    for i,left in enumerate(rows):
        for right in rows[i+1:]:
            if left['job']==right['job']:continue
            begin=max(instant(left['start']),instant(right['start']));end=min(instant(left['end']),instant(right['end']))
            if begin<end:overlap_count+=1
            if begin<end and len(overlaps)<100:
                overlaps.append({'left':left['job'],'right':right['job'],'start':iso(begin),'end':iso(end),
                                 'left_ref':left['ref'],'right_ref':right['ref']})
    return {'spans':rows,'total':total,'omitted':total-len(rows),'overlaps':overlaps,'overlap_omitted':overlap_count-len(overlaps),
            'note':SELECT_NOTE+' 구간 중첩은 시간적 동시성만 나타냅니다.'}


def daily_time(cron) -> str | None:
    if not isinstance(cron,str):return None
    parts=cron.split()
    if len(parts) not in (6,7) or (len(parts)==7 and parts[6]!='*'):return None
    if not (parts[3]=='*' and parts[4]=='*' and parts[5]=='?'):return None
    try: sec,minute,hour=map(int,parts[:3])
    except ValueError:return None
    return f'{hour:02}:{minute:02}:{sec:02}' if 0<=sec<60 and 0<=minute<60 and 0<=hour<24 else None


def continuity(case: Path, manifest: dict, window: Window) -> dict:
    bounds=window.bounds();streams={};tails={};schedules=[];lifecycle=[];skips=Counter();omitted=0;retained=0;extra=Counter()
    for e in events_iter(case,manifest):
        t=instant(e.get('occurred_at'))
        if t is None:continue
        fid=e['file_id'];d=e.get('details') or {};typ=e['event_type']
        if fid not in tails or t>instant(tails[fid]['occurred_at']):tails[fid]=reference(e)
        if typ=='scheduler_registration':
            cron=d.get('cron');job=job_name(d.get('job_name'))
            if job and isinstance(cron,str) and re.fullmatch(r'[0-9*/?, -]{3,100}',cron) and len(schedules)<100:
                schedules.append({'job':job,'cron':cron,'daily':daily_time(cron),
                                  'interval':periodic_interval(cron),'ref':reference(e)})
            else:extra['schedule_unlisted']+=1
        if typ in {'agent_exit','agent_started','agent_starting'}:
            if len(lifecycle)<200:lifecycle.append({'event':typ,'ref':reference(e)})
            else:extra['lifecycle_unlisted']+=1
        if not bounds[0]<=t<bounds[1]:continue
        if typ=='job_running_skip':
            skips[job_name(d.get('job_name')) or 'UNKNOWN']+=1
        stream=('HEALTHCHECK' if typ=='healthcheck_result' else job_name(d.get('job_name')) if typ=='job_run' else None)
        if not stream:continue
        key=(fid,stream)
        if key not in streams and len(streams)>=MAX_GROUPS:omitted+=1;continue
        values=streams.setdefault(key,[])
        if len(values)>=MAX_SAMPLES or retained>=MAX_CONTINUITY_RECORDS:omitted+=1;continue
        values.append((t,reference(e)));retained+=1
    gaps=[];summaries=[]
    for (fid,name),values in streams.items():
        # Do not bridge distinct input files or infer missing executions from rates.
        values.sort(key=lambda v:v[0]);deltas=[(b[0]-a[0]).total_seconds() for a,b in zip(values,values[1:]) if b[0]>a[0]]
        typical=median(deltas) if len(deltas)>=4 else None
        stable=(sum(.5*typical<=v<=1.5*typical for v in deltas)/len(deltas)>=.6) if typical else False
        configured = {x['interval'] for x in schedules if x['job']==name and x.get('interval')
                      and instant(x['ref']['occurred_at'])<=bounds[0]}
        # Conflicting/changed schedules cannot be silently collapsed.
        interval = next(iter(configured)) if len(configured)==1 and not any(
            x['job']==name and bounds[0]<instant(x['ref']['occurred_at'])<bounds[1] for x in schedules) else None
        basis = interval or (typical if stable else None)
        threshold=max(basis*3,basis+5) if basis else None
        summaries.append({'file_id':fid,'stream':name,'records':len(values),'observed_median_interval':typical,
                          'reference_basis':'로그에 등록된 주기(실제 배포 설정 확인 필요)' if interval else '관측된 완료/응답 기록 간격(예약 주기 아님)',
                          'configured_interval':interval,'threshold_seconds':threshold})
        if threshold:
            for a,b in zip(values,values[1:]):
                gap=(b[0]-a[0]).total_seconds()
                if gap>threshold and len(gaps)<500:
                    gaps.append({'file_id':fid,'stream':name,'from':iso(a[0]),'to':iso(b[0]),'seconds':gap,
                                 'threshold':threshold,'before_ref':a[1],'after_ref':b[1]})
    collection=instant(manifest.get('collected_at'));tail_rows=[]
    for fid,ref in sorted(tails.items()):
        t=instant(ref['occurred_at']);delta=(collection-t).total_seconds() if collection else None
        tail_rows.append({'file_id':fid,'last_observed':iso(t),'collected_at':iso(collection),'seconds_to_collection':delta,
                          'collection_conflict':bool(delta is not None and delta<0),'ref':ref})
    return {'streams':summaries,'gaps':gaps,'tails':tail_rows,'schedules':schedules,'lifecycle':lifecycle,
            'running_skips':dict(skips),'unprocessed_records':omitted,'unlisted':dict(extra),
            'note':'마지막 기록·수집시각·Agent Exited·예약 시각은 서로 다릅니다. 관측 공백으로 종료/스케줄러 정지를 확정하지 않습니다.'}


def periodic_interval(cron) -> int | None:
    """Only uniform all-day Quartz step schedules, never general cron guessing."""
    if not isinstance(cron,str):return None
    parts=cron.split()
    if len(parts) not in (6,7) or (len(parts)==7 and parts[6]!='*') or parts[3:6]!=['*','*','?']:return None
    for i,cycle,mult in ((0,60,1),(1,60,60),(2,24,3600)):
        m=re.fullmatch(r'(?:0|\*)/(\d{1,2})',parts[i])
        if m and all(parts[j]=='0' for j in range(i)) and all(parts[j]=='*' for j in range(i+1,3)):
            step=int(m.group(1))
            if 0<step<cycle and cycle%step==0:return step*mult
    return None
