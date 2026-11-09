"""Strict structural exception-chain parsing; no raw exception prose is returned."""
from __future__ import annotations
import re
from typing import Iterable
from .error_semantics import observed_semantics, REASON_PATTERNS, structural_error_text

MAX_CHAIN_NODES = 24
CLASS = re.compile(r'\b((?:[A-Za-z_][A-Za-z0-9_$]*\.)*[A-Za-z_][A-Za-z0-9_$]{0,54}(?:Exception|Error))\b')
SAFE_CLASS = re.compile(r'[A-Za-z_][A-Za-z0-9_]{0,54}(?:Exception|Error)\Z')
RELATION = re.compile(r'^\s*(Caused by|Suppressed)\s*:', re.I)
FRAME = re.compile(r'^\s*(?:at\s+[\w.$<>]+\(|\.\.\.\s+\d+\s+more)')
JOB = re.compile(r'\b(?:JOB_NAME|JOB)\s*[:=]\s*([A-Z][A-Z0-9_]{2,63})(?![A-Za-z0-9_])')
REASONS = {
    'connect_timeout': re.compile(r'\bconnect(?:ion)? timed out\b', re.I),
    'read_timeout': re.compile(r'\bread timed out\b', re.I),
    'connection_refused': re.compile(r'\bconnection refused\b', re.I),
    'communications_failure': re.compile(r'\bcommunications link failure\b', re.I),
    'pool_timeout': re.compile(r'\b(?:connection is not available|timeout waiting for (?:idle object|connection))\b', re.I),
}


def body(text: str) -> str:
    match = re.match(r'^\s*\d{2}:\d{2}:\d{2}\[\d{1,3}\]\s*', text)
    return text[match.end():] if match else text


def continuation(text: str) -> bool:
    value = body(text)
    return bool(RELATION.match(value) or FRAME.match(value))


def has_exception(text: str) -> bool:
    text=structural_error_text(text)
    if any(pattern.search(text) for pattern in REASON_PATTERNS.values()):
        return True
    if not any(token in text for token in ('Exception','Error','ERROR')):
        return False
    return bool(CLASS.search(text) or re.search(r'\bERROR\b', text))


def chain_details(lines: Iterable[tuple[int, str]], *, incomplete: bool = False) -> dict:
    lines = list(lines)
    semantics = observed_semantics(lines)
    nodes = []; reasons = set(semantics["reason_codes"]); jobs = set(); frames = 0; omitted = 0
    for number, text in lines:
        value = body(structural_error_text(text))
        if FRAME.match(value):
            frames += 1
        if m := JOB.search(value):
            jobs.add(m.group(1))
        match = CLASS.search(value)
        relation = RELATION.match(value)
        if not match:
            continue
        name = match.group(1).rsplit('.', 1)[-1]
        if not SAFE_CLASS.fullmatch(name):
            continue
        # Only the first unqualified class is the root. Unqualified other
        # classes are not invented causal links.
        rel = ('cause' if relation and relation.group(1).lower() == 'caused by'
               else 'suppressed' if relation else 'root' if not nodes else 'unlinked')
        if len(nodes) < MAX_CHAIN_NODES:
            nodes.append({'class': name, 'relation': rel, 'line': number})
        else:
            omitted += 1
        for code, pattern in REASONS.items():
            if pattern.search(value): reasons.add(code)
    return {
        **semantics,
        'exception_class': nodes[0]['class'] if nodes else 'unspecified',
        'stack_frame_count': frames,
        'exception_chain': nodes,
        'chain_truncated': bool(omitted or incomplete),
        'chain_omitted_nodes': omitted,
        'reason_codes': sorted(reasons),
        'job_names': sorted(jobs)[:16],
    }


def safe_chain(details: dict, first_line: int = 1, last_line: int = 2**31) -> list[dict]:
    if not isinstance(details, dict): return []
    values = details.get('exception_chain', [])
    if not isinstance(values, list): return []
    result = []
    for n in values[:MAX_CHAIN_NODES]:
        if (isinstance(n, dict) and isinstance(n.get('class'), str) and SAFE_CLASS.fullmatch(n['class'])
            and n.get('relation') in {'root','cause','suppressed','unlinked'} and type(n.get('line')) is int
            and first_line <= n['line'] <= last_line):
            result.append({k: n[k] for k in ('class','relation','line')})
    return result


def chain_label(details: dict, first_line: int = 1, last_line: int = 2**31) -> str:
    nodes = safe_chain(details, first_line, last_line)
    if not nodes:
        name = details.get('exception_class') if isinstance(details,dict) else None
        return name if isinstance(name,str) and SAFE_CLASS.fullmatch(name) else '유형 미확인'
    pieces = []
    has_branches = any(n['relation']=='suppressed' for n in nodes)
    for node in nodes:
        prefix = {'root':'','cause':' → ','suppressed':' / suppressed: ','unlinked':' / 별도 언급: '}[node['relation']]
        if not pieces and node['relation']=='cause':prefix='상위 예외 미관측 → '
        elif has_branches and node['relation']=='cause':prefix=' / Caused by 관측: '
        pieces.append(prefix + node['class'])
    return ''.join(pieces)


def attach_preamble(block, text):
    """Only an adjacent explicit failure header may introduce its wrapper stack."""
    from .parsers.common import parse_clock
    from datetime import time
    text=structural_error_text(text)
    if not block or len(block)>3 or not CLASS.search(text) or continuation(text):return False
    if any(CLASS.search(value) for _,value in block):return False
    if not any(re.search(r'Connection execute error|http connection|\bERROR\b',value,re.I) for _,value in block):return False
    a,b=parse_clock(block[-1][1]),parse_clock(text)
    if a is None or b is None:return False
    def seconds(v):
        t=time.fromisoformat(v);return t.hour*3600+t.minute*60+t.second+t.microsecond/1e6
    return 0<=seconds(b)-seconds(a)<=1


def parse_mixed(lines, normal_parser):
    """Wrap info/debug line parsers; stack continuation never creates a new error."""
    from .parsers.common import RawEvent, MAX_RECORD_LINES, parse_clock
    block = []; clock = None
    def emit(partial=False):
        return RawEvent('log_error',block[0][0],block[-1][0],clock,
                        chain_details(block,incomplete=partial), 'incomplete' if partial else 'observed')
    for number,text in lines:
        current = parse_clock(text)
        preamble = attach_preamble(block, text)
        attached = preamble or bool(block and (continuation(text) or (current is None and CLASS.search(text)
                        and not any(CLASS.search(value) for _,value in block)))
                        and (current is None or current == clock))
        if block and not attached:
            yield emit(); block=[];clock=None
        if attached:
            if preamble:clock=current
            block.append((number,text))
            if len(block) >= MAX_RECORD_LINES:
                yield emit(True);block=[];clock=None
        elif has_exception(text) and current is not None:
            block=[(number,text)];clock=current
        else:
            yield from normal_parser([(number,text)])
    if block: yield emit()
