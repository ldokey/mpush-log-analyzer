"""Human-readable, evidence-limited error semantics. No raw message or host leaks."""
from __future__ import annotations
import re

REASON_PATTERNS = {
    'connect_timeout': re.compile(r'\bconnect(?:ion)? timed out\b', re.I),
    'read_timeout': re.compile(r'\bread timed out\b|\bresponse timeout\b', re.I),
    'connection_refused': re.compile(r'\bconnection refused\b', re.I),
    'connection_reset': re.compile(r'\bconnection reset\b|\bbroken pipe\b', re.I),
    'communications_failure': re.compile(r'\bcommunications link failure\b', re.I),
    'pool_timeout': re.compile(r'\b(?:connection is not available|timeout waiting for (?:idle object|connection)|timeout waiting for connection from pool)\b', re.I),
    'dns_failure': re.compile(r'\bUnknownHostException\b|\b(?:name or service not known|temporary failure in name resolution)\b', re.I),
    'tls_failure': re.compile(r'\b(?:SSLHandshakeException|SSLPeerUnverifiedException|PKIX path building failed|certificate verify failed)\b', re.I),
    'db_deadlock': re.compile(r'\bdeadlock (?:found|detected|victim)\b|\bORA-00060\b', re.I),
    'db_timeout': re.compile(r'\bSQLTimeoutException\b|\bquery timed out\b|\block wait timeout exceeded\b', re.I),
    'db_auth': re.compile(r'\bORA-01017\b|\baccess denied for user\b|\bpassword authentication failed\b', re.I),
    'db_syntax': re.compile(r'\bSQLSyntaxErrorException\b|\bORA-009(?:00|04|33|42)\b|\bSQL syntax\b', re.I),
    'memory_exhausted': re.compile(r'\bOutOfMemoryError\b|\bJava heap space\b|\bGC overhead limit exceeded\b'),
    'disk_full': re.compile(r'\bno space left on device\b', re.I),
    'permission_denied': re.compile(r'\bpermission denied\b|\bAccessDeniedException\b', re.I),
}
OPERATIONS = {
    'healthcheck': (r'httpClientToTSMSHealthCheck|ServerConfCheck(?:Job|Biz)|헬스\s*체크', '설정 확인·헬스체크'),
    'result_receive': (r'ReceiveResultAgentJob|ReceiveBiz\.|결과\s*수신', '발송 결과 수신'),
    'file_send': (r'SendRealFileImageJob|SocketClientWithFileSend|파일\s*전송', '발송 파일 전송'),
    'database': (r'\b(?:PSTMT|jdbc|SQLException|SQLTimeoutException)\b', 'DB 작업'),
}
LABELS = {
    'connect_timeout': ('서버 연결 시간 초과','서버에 연결하는 단계에서 제한시간을 초과했습니다.','방화벽 차단·네트워크 경로·대상 서버 미응답 중 어느 원인인지는 아직 확정할 수 없습니다.','동일 시각의 연결 대상/포트, 아웃바운드 정책, 방화벽 드롭·라우팅 및 서버 수신 상태를 확인하세요.'),
    'read_timeout': ('연결 후 응답 대기 시간 초과','연결 뒤 데이터를 읽는 대기 시간이 초과됐습니다.','연결 실패와 다릅니다. 서버 처리 지연이나 응답 경로 문제를 추가 확인해야 합니다.','같은 요청의 서버 처리 로그, 응답시간과 읽기 타임아웃 설정을 대조하세요.'),
    'connection_refused': ('대상 서버가 연결을 거부','연결 시도가 거부됐다는 기록입니다.','서비스 미기동·리스닝 주소·보안 장비 응답 등은 이 로그만으로 구분되지 않습니다.','대상 서버의 해당 포트 리스닝 상태와 접근 정책을 확인하세요.'),
    'connection_reset': ('통신 중 연결 끊김','연결 초기화 또는 broken pipe가 기록됐습니다.','누가 연결을 끊었는지, 유휴 종료인지 장애인지는 추가 근거가 필요합니다.','서버와 중간 장비의 연결 종료 로그 및 유휴 제한을 확인하세요.'),
    'pool_timeout': ('DB/HTTP 연결 풀 대기 시간 초과','사용 가능한 연결을 풀에서 얻지 못한 기록입니다.','외부 서버에 접속하지 못한 connect timeout과 같지 않습니다.','풀 사용량, 점유 시간, 미반납 연결과 동시 요청 수를 확인하세요.'),
    'dns_failure': ('서버 이름 조회 실패','호스트 이름을 주소로 해석하지 못한 기록입니다.','잘못된 주소·DNS 설정·일시적 해석 실패 여부를 확인해야 합니다.','로그에 기록된 호스트와 해당 서버의 DNS 설정/조회 결과를 확인하세요.'),
    'tls_failure': ('TLS 인증서·보안 연결 실패','TLS handshake 또는 인증서 검증 실패가 기록됐습니다.','인증서 만료·체인·신뢰 저장소·프로토콜 중 구체 원인은 추가 확인이 필요합니다.','인증서 체인/유효기간, JVM truststore와 협상 프로토콜을 확인하세요.'),
    'communications_failure': ('DB 통신 실패','DB 드라이버가 통신 실패를 보고했습니다.','DB Lock 또는 네트워크 원인으로 단정하지 않습니다.','하위 Caused by, DB 접속 로그, 연결 유지시간과 서버 상태를 확인하세요.'),
    'db_deadlock': ('DB 교착상태 기록','DB가 deadlock을 보고한 기록입니다.','개별 트랜잭션의 책임과 재시도 결과는 아직 모릅니다.','같은 시각의 DB deadlock 그래프와 트랜잭션/잠금 순서를 확인하세요.'),
    'db_timeout': ('DB 실행·잠금 대기 시간 초과','SQL 실행 또는 잠금 대기 제한시간 초과가 기록됐습니다.','쿼리 지연만으로 잠금 원인을 확정하지 않습니다.','실행계획, 대기 이벤트, 잠금 세션 및 쿼리 타임아웃을 확인하세요.'),
    'db_auth': ('DB 인증 실패','DB가 계정/인증 오류를 보고했습니다.','자격정보 원문은 표시하거나 외부로 내보내지 않습니다.','담당자가 계정 잠김, 비밀번호 변경, 인증 방식과 권한을 확인하세요.'),
    'db_syntax': ('DB SQL·객체 오류','SQL 문법 또는 참조 객체 관련 오류가 기록됐습니다.','SQL 본문 없이 세부 원인을 확정하지 않습니다.','DB 오류 번호, 객체 존재와 실행 계정 권한을 확인하세요.'),
    'memory_exhausted': ('JVM 메모리 부족','JVM 메모리 부족 오류가 기록됐습니다.','원인 객체나 메모리 누수 여부는 스택 한 장만으로 확정할 수 없습니다.','같은 시각의 heap/GC 로그와 JVM 메모리 사용량을 확인하세요.'),
    'disk_full': ('저장 공간 부족','저장 공간 부족 메시지가 기록됐습니다.','특정 볼륨의 현재 상태는 별도 확인이 필요합니다.','담당자가 로그/임시/발송 파일 경로의 용량과 inode를 확인하세요.'),
    'permission_denied': ('파일·자원 접근 권한 거부','접근 권한이 거부됐다는 기록입니다.','실행 계정/파일 권한/보안 제품 여부는 구분되지 않습니다.','실행 계정과 대상 경로의 읽기·쓰기 권한을 확인하세요.'),
}
PRIORITY = ('pool_timeout','connect_timeout','read_timeout','connection_refused','dns_failure','tls_failure','connection_reset','db_deadlock','db_auth','db_syntax','memory_exhausted','disk_full','permission_denied','db_timeout','communications_failure')


def structural_error_text(text):
    """Exclude message/SQL body fields from lexical failure classification."""
    payload=re.search(r"(?:^|[,{\s])[\"']?(?:SEND_?MESSAGE|BACKUP_?MESSAGE|MESSAGE_?BODY|MESSAGE_?TEXT|BODY|CONTENT|TEXT|SUBJECT|SQL_?TEXT|QUERY_?TEXT)[\"']?\s*[:=]",text,re.I)
    return text[:payload.start()] if payload else text


def observed_semantics(lines):
    reasons, operations, evidence, ports = set(), set(), [], set()
    for line, text in lines:
        text=structural_error_text(text)
        for code, pattern in REASON_PATTERNS.items():
            if pattern.search(text):
                reasons.add(code)
                if len(evidence)<32: evidence.append({'code':code,'line':line})
        for code,(pattern,_) in OPERATIONS.items():
            if re.search(pattern,text,re.I):operations.add(code)
        # A numeric port only, never a hostname/IP or arbitrary exception message.
        for hit in re.finditer(r'\bConnect to\s+(?:\[[A-Fa-f0-9:]+\]|[A-Za-z0-9_.-]{1,253}):([0-9]{1,5})(?=\s|\[|$)',text,re.I):
            port=int(hit.group(1))
            if 0<port<=65535:ports.add(port)
    return {'reason_codes':sorted(reasons),'operation_codes':sorted(operations),
            'reason_evidence':evidence,'target_ports':sorted(ports)[:8]}


def describe_error(details):
    from .exception_chain import safe_chain, chain_label
    d=details if isinstance(details,dict) else {}
    reasons={x for x in d.get('reason_codes',[]) if isinstance(x,str) and x in LABELS} if isinstance(d.get('reason_codes',[]),list) else set()
    codes=d.get('operation_codes',[]);codes=codes if isinstance(codes,list) else []
    operations=[OPERATIONS[c][1] for c in OPERATIONS if c in codes]
    # Class-only errors preserve uncertainty; SocketTimeoutException is ambiguous.
    chain=safe_chain(d)
    classes={x['class'] for x in chain}
    if not reasons:
        for cls,code in [('ConnectionPoolTimeoutException','pool_timeout'),('UnknownHostException','dns_failure'),('SSLHandshakeException','tls_failure'),('SQLSyntaxErrorException','db_syntax'),('OutOfMemoryError','memory_exhausted')]:
            if cls in classes:reasons.add(code)
    reason=next((c for c in PRIORITY if c in reasons),None)
    if reason:
        title,fact,limit,check=LABELS[reason]
    else:
        title='오류 상세 원인 미확인'
        fact='예외/오류 기록은 있으나 실패 단계를 특정할 메시지 근거가 부족합니다.'
        limit='상위 래퍼 예외명만으로 실제 원인을 단정하지 않습니다.'
        check='해당 오류 앞뒤 원문과 최하위 Caused by, 동일 시각의 관련 로그를 확인하세요.'
    if reason=='connect_timeout' and 'healthcheck' in codes:title='헬스체크 중 서버 연결 시간 초과'
    ports=[p for p in d.get('target_ports',[]) if type(p) is int and 0<p<=65535] if isinstance(d.get('target_ports',[]),list) else []
    if ports and reason=='connect_timeout':fact=f"서버 {', '.join(map(str,ports))}번 포트에 연결하는 단계에서 제한시간을 초과했습니다."
    deepest=next((x['class'] for x in reversed(chain) if x['relation'] in {'root','cause'}),None)
    return {'code':reason or 'unclassified','title':title,'fact':fact,'limit':limit,'check':check,
        'operation':' · '.join(operations) or '작업 미확인','chain':chain_label(d),'deepest_exception':deepest,
        'ports':ports,'reason_codes':sorted(reasons),'classification':'observed' if reason else 'insufficient'}
