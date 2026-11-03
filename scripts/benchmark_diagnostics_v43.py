"""Bounded V4.3 benchmark using synthetic data only (never reads workspace/).

Run: .venv/bin/python -m scripts.benchmark_diagnostics_v43 --mib 10 --messages 10000
"""
from __future__ import annotations
import argparse
from datetime import date
import json
from pathlib import Path
try:
    import resource
except ImportError:
    resource = None
import sys
import tempfile
import time

from mpush_analyzer.intake import Upload, inspect_uploads
from mpush_analyzer.storage import save_intake
from mpush_analyzer.runner import run_complete_analysis
from mpush_analyzer.pipeline import _safe_source
from mpush_analyzer.diagnostics import diagnose_jobs
from mpush_analyzer.message_outcomes import trace_outcomes
from mpush_analyzer.investigation import Window


def main() -> None:
    cli=argparse.ArgumentParser(description=__doc__)
    cli.add_argument('--mib',type=int,default=10,choices=range(1,101),metavar='1..100')
    cli.add_argument('--messages',type=int,default=10000,choices=range(1,20001),metavar='1..20000')
    cli.add_argument('--output',type=Path)
    a=cli.parse_args();wanted=a.mib*1024*1024
    source=bytearray();n=0
    while len(source)<wanted:
        # Monotonic milliseconds fit in the 20-minute fixture window.
        seconds,millis=divmod(n,1000);minute,second=divmod(seconds,60)
        t=f'10:{minute:02d}:{second:02d}[{millis:03d}]'
        duration=30 if n%500==0 else 2
        source.extend((f'{t}\n## SEND_REAL_FILE_IMAGE 작업\n{t} ## 작업대상건수 : 100\n'
            f'{t} ## SELECT 시간(초.0f) : {duration*.8}초\n{t} ## SOCKET 시간(초.0f) : {duration*.2}초\n'
            f'{t} ## 소요시간(초.0f) : {duration}초\n').encode())
        n+=1
    messages=''.join(f'10:10:00[000] MESSAGE_SEQNO=SYNTHETIC_{i} SERVICE_SEQNO=SYNTH_SERVICE result received SEND_RESULT_CODE1={"E101" if i%4==0 else "OK"} BACKUP_PROCESS_CODE=003\n' for i in range(a.messages)).encode()
    w=Window('2026-11-02T10:00:00','2026-11-02T10:20:00')
    with tempfile.TemporaryDirectory(prefix='mpush-v43-synthetic-benchmark-') as tmp:
        root=Path(tmp);begin=time.perf_counter()
        c,m=save_intake(inspect_uploads([Upload('20261102job.log',bytes(source)),Upload('20261102debug.log',messages)]),root/'workspace',reference_date=date(2026,11,2),collected_at='2026-11-02T10:21:00',agent_version='3.3')
        run_complete_analysis(c,knowledge_root=root/'knowledge');analysis=time.perf_counter()-begin
        begin=time.perf_counter();d=diagnose_jobs(c,m,w);diagnosis=time.perf_counter()-begin
        begin=time.perf_counter();t=trace_outcomes(c,w,salt=b'x'*32);message_time=time.perf_counter()-begin
        assert sum(j['current']['records'] for j in d['jobs'])==n
        assert t['summary']['unique_messages']==min(a.messages,5000)
        assert all(_safe_source(c,f).is_file() for f in m['files'])
        rss=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss/(1024*1024 if sys.platform=='darwin' else 1024) if resource else None
        result={'synthetic_only':True,'platform':sys.platform,'python':sys.version.split()[0],
            'source_mib':round((len(source)+len(messages))/1024**2,3),'job_records':n,'message_records':a.messages,
            'pipeline_seconds':round(analysis,3),'job_diagnostics_seconds':round(diagnosis,3),
            'message_outcomes_seconds':round(message_time,3),'peak_process_mib':round(rss,1) if rss is not None else None,
            'message_summary':t['summary'],'message_cap_explicit':t['population_limited'],
            'sequence_records_omitted':sum(j['sequence_records_omitted'] for j in d['jobs']),
            'source_hash_preserved':True,'windows_native_verified':False}
    if a.output:a.output.write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps(result,ensure_ascii=False,indent=2))

if __name__=='__main__':main()
