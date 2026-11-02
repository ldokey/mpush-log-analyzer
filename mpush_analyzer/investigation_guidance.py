"""Evidence-separated support guidance. No commands or network calls executed."""
from __future__ import annotations
from .investigation import SELECT_NOTE, LIMIT_NOTE


def guidance(stats: dict, chains: dict, continuity: dict, spans: dict, manifest: dict) -> dict:
    facts=[];possibilities=[];requests=[];limitations=[LIMIT_NOTE,SELECT_NOTE]
    evidence=[]
    if stats['events']:
        facts.append(f"선택 구간에서 정규화 이벤트 {stats['events']:,}건, 오류 기록 {stats['error_records']:,}건이 관측됐습니다.")
    else:
        facts.append('선택 구간에 날짜가 확인된 정규화 이벤트가 없습니다. 정상 상태로 판단할 수 없습니다.')
    for g in stats['groups']:
        d=g['duration']
        if d['max'] is not None and len(facts)<12:
            unit='초' if g['kind']=='job_run' else 'ms'
            facts.append(f"{g['name']}: 기록 {g['count']}건, 최대 처리시간 {d['max']}{unit}.")
    reasons={reason for g in chains['groups'] for reason in g['reasons']}
    if reasons & {'connect_timeout','connection_refused','communications_failure','pool_timeout'}:
        possibilities.append('DB 연결 확보 또는 통신 경로 문제의 가능성을 조사할 필요가 있습니다. DB 서버/네트워크 중 원인을 확정하지 않습니다.')
        requests.extend(['같은 시각 DB 연결·세션 대기 및 연결 풀 상태','프로세스 생존 확인 시각과 TCP 연결 상태'])
    if spans['overlaps']:
        facts.append(f"표시 대상 Job 구간에서 서로 다른 Job의 시간 중첩 {len(spans['overlaps'])}쌍을 확인했습니다.")
        possibilities.append('DB 조회·선점·결과 이관 단계의 자원 경합 가능성은 추가 DB 근거로 검증해야 합니다.')
        requests.append('실제 Blocking Session/SQL 및 잠금 대기 자료(미보유 시 Lock 미확정)')
        evidence.extend(spans['overlaps'][0][k] for k in ('left_ref','right_ref'))
    if continuity['gaps']:
        facts.append(f"관측 간격/등록 주기를 기준으로 긴 기록 공백 {len(continuity['gaps'])}개가 표시됐습니다.")
        possibilities.append('작업량 변화·로그 누락·스케줄 지연을 구분해야 하며, 기록 공백만으로 Agent 종료를 판단하지 않습니다.')
        requests.extend(['공백 전후 완전한 로그와 실제 수집시각','같은 시간 정상일 로그 및 재시작 전 Thread Dump(확보된 경우)'])
        evidence.extend(continuity['gaps'][0][k] for k in ('before_ref','after_ref'))
    if continuity['running_skips']:
        facts.append('RUNNING 상태로 다음 실행을 건너뛴 기록이 있습니다.')
        requests.append('선행 Job 종료 기록과 해당 시점 스레드 상태')
    for group in chains['groups'][:3]:
        facts.append(f"{group['chain']}: 해당 파일 내 반복 기록 {group['count']}회.")
        evidence.extend(group['evidence'][:1])
    if not possibilities:
        possibilities.append('현재 선택 구간의 자료만으로 특정 원인을 좁히지 않았습니다.')
    missing=stats['coverage']['missing_kinds']
    if missing:requests.append('누락된 로그 유형의 제공 필요성 확인: '+', '.join(missing))
    if stats['coverage']['nonfull_files']:limitations.append('일부 파일이 부분 추출 또는 원본 완전성 미확인입니다.')
    if not manifest.get('collected_at'):requests.append('로그 기록 마지막 시각과 별개의 실제 수집시각')
    if stats['unknown_time_excluded']:limitations.append(f"날짜/시각 미확인 이벤트 {stats['unknown_time_excluded']}건은 기간 계산에서 제외했습니다.")
    limitations.extend(['S 응답은 요청 수락이며 최종 수신 성공이 아닙니다.',
                        'Job 작업대상·단기 TPS로 DB 적체나 전체 발송 완료시각을 추정하지 않습니다.',
                        'XML/2.8 참고자료가 없다는 이유로 핵심 분석을 차단하지 않습니다.'])
    return {'facts':facts,'possible_causes':possibilities,'additional_evidence':list(dict.fromkeys(requests)),
            'limitations':limitations,'evidence':evidence[:20],
            'read_only_examples':[
              {'목적':'프로세스 확인(실행한 시각 별도 기록)','예시':"ps -ef | grep '[M]PushAgent'"},
              {'목적':'Java TCP 연결 관측','예시':'ss -tnp | grep java'},
              {'목적':'DB 잔존 건수 예시(실제 스키마·권한·부하 확인 필요)','예시':'SELECT COUNT(*) FROM TSMS_AGENT_MESSAGE;'},
              {'목적':'서비스별 자료 분포 예시(완료/적체 정의와 별개)','예시':'SELECT SERVICE_SEQNO, COUNT(*) FROM TSMS_AGENT_MESSAGE GROUP BY SERVICE_SEQNO;'},
            ]}


def reply_draft(packet: dict) -> str:
    lines=['안녕하세요. 전달해 주신 로그의 선택 구간을 기준으로 확인한 내용을 안내드립니다.',
           '', '[확인된 관측 사실]']
    lines.extend('- '+x for x in packet['facts'])
    lines.extend(['','[가능성 검토 — 원인 확정 아님]'])
    lines.extend('- '+x for x in packet['possible_causes'])
    lines.extend(['','[추가 확인이 필요한 자료]'])
    lines.extend('- '+x for x in packet['additional_evidence'] or ['문의 증상과 로그 수집 범위를 추가 확인하겠습니다.'])
    lines.extend(['','[해석 한계]'])
    lines.extend('- '+x for x in packet['limitations'])
    lines.extend(['','추가 자료와 실제 조치 후 검증 결과를 확인한 뒤 원인 및 해결 여부를 정리하겠습니다.',
                  '※ 자동 생성 초안입니다. 담당자가 내용·근거·공유 범위를 검토한 뒤 사용해 주세요.'])
    return '\n'.join(lines)
