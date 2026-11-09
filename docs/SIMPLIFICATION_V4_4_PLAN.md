# V4.4 — 단일 Agent 중심 조사 흐름 정리

## 승인 범위
자료 가져오기 우선, 하나의 분석 흐름/디자인, 오류 의미 우선 표시, debug 메시지 검색 보강, 정상 반복 조회 기본 접기. 다중 Agent/HA/설정 연계/버전 호환성 확장은 하지 않는다. 기존 원본·문의·사례·이전 분석을 삭제/자동 갱신하지 않는다. 공개 push/release는 별도 승인.

## 조사에서 확인한 형식
첨부 화면은 LSysException → ConnectTimeoutException → SocketTimeoutException 및 connect timed out, httpClientToTSMSHealthCheck/ServerConfCheckJob을 포함한다. 래퍼 예외명보다 실패 단계·작업·추가 확인 항목을 우선 표시해야 한다. 연결 시간초과만으로 방화벽 차단을 확정하지 않는다.
제공된 Agent 패키지 소스/기존 debug 로그에는 messageSeqno/serviceSeqno camelCase 및 LMultiData의 열 헤더/행 값 구조가 있다. 같은 줄의 MESSAGE_SEQNO=키값만 요구하던 방식은 실제 표를 놓친다. RESPONSE_CODE=S는 표가 있어도 요청 수락일 뿐 최종 성공은 아니다.
DB의 select completed는 반환행 0건의 근거가 아니다. 정상 빠른 SELECT는 기본 접기하되 오류/지연/불완전/쓰기 SQL은 보존하고 전체 근거 조회를 제공한다.

## 구현 계약
1. 상단 4단계: 자료 가져오기 → 분석 결과 → 문의·기록 → 내보내기. 선택된 단계만 렌더/조회. 최초 진입은 자료 가져오기, 분석 완료 후 결과로 이동.
2. 결과 기본 4개: 핵심 요약 / 오류 원인 / 메시지 검색 / Job·성능. 기존 전체 이벤트/DB/세부 조사/사례는 고급 경로로 보존. 분석 둘 선택·HA 입력은 기본 및 신규 조사 경로에서 제거. 파일명의 HA_RECEIVE_RESULT는 원래 Job 이름이므로 임의로 삭제/제외하지 않는다.
3. 오류는 구조적 reason code, operation code, port, 예외 원인 체인, 근거 줄번호만 비식별 출력. endpoint/원문은 해시 검증한 로컬 근거에서 필요할 때만 조회. connect/read/pool timeout, refused, DNS, TLS, SQL/권한/메모리/디스크 구분. 일반 오류 문구도 예외 class 없이 reason 탐지. 직후 래퍼 stack과 연결하는 것은 같은 파일의 인접 1초 이내 명시 오류 프리앰블만 허용.
4. 메시지 검색은 debug 기본, info/err 보조 선택. dbwrap은 검색 대상/필수 입력에서 제외. MESSAGE_SEQNO 필수, SERVICE_SEQNO 선택. camelCase/대문자 키값, JSON 외부 필드, LMultiData 표 행을 지원한다. 본문 문자열 안의 가짜 식별값·SQL·여러 ID가 모호한 레코드는 최종 결과 판단에서 제외한다. 서비스 없는 메시지 일치도 '서비스 미확인'으로 보여주되 확정 그룹과 합치지 않는다. AGENT_MESSAGE_SEQNO와 MESSAGE_SEQNO를 혼동하지 않는다. 표 수락과 명시적 최종 결과를 구분한다. 출력은 세션 가명과 구조적 필드만 포함.
5. 기본 요약은 오류 묶음, 느린/실패한 Job·DB, RUNNING/ABNORMAL, 자료 제한. 빠른 정상 SELECT/대상0의 빠른 완료 Job/정상 헬스체크는 삭제 없이 접고 건수를 공개한다. 반환행 미기록을 '빈 쿼리'로 단정하지 않는다. 전체 조회 토글 제공.
6. Google Stitch 실제 DESKTOP 생성 원본을 확보해 공통 시각 토큰/카드/헤더를 재사용한다. 원본 예시 숫자는 제품에 삽입하지 않는다. Streamlit 네이티브 입력과 iframe 모두 같은 토큰을 사용한다. 모바일 제외, 외부 CDN/API 없음.
7. 기존 분석에 새 오류 의미를 채우려면 명시적 원본 재해석(세션용) 또는 기존 재분석을 사용한다. DB·Agent·Redmine 명령 실행 없음.

## 검증
기존 366개 테스트 의미 유지, UI 경로 변경 테스트만 새 진입 절차로 보정. 첨부 형태 합성 스택, lower-case 오류 전용 줄, connect/read/pool 구분, 본문/비밀 비노출, camelCase/표/JSON/서비스 미기록/중복/시간 누락/대량 표, 빠른 SELECT/느린 SELECT/실패/쓰기 분리, intake→results 실제 브라우저 흐름, 1280/1440/1920px 검증. 현재 사용자 Windows의 정확한 로그집합을 재현했다고 주장하지 않는다.
