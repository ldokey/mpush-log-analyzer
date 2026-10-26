# MPushAgent Log Analyzer — MVP 1.0 (4/4)

독립 실행형 MPushAgent 3.2/3.3 로컬 로그 분석기입니다.
기존 Agent, 고객사 DB, CNS 서버에 접속하거나 이를 수정하지 않습니다.
**4단계 구현 완료:** 개별 로그 업로드 → 로그 파싱 → 이상 신호 탐지
→ 승인된 해결 사례 비교 → 대시보드·원본 근거 조회 → 비식별 보고서.

## 이상 징후 화면·AI 전달 개선 (2026-10-26)

기존 v1.1 개선 내용은 docs/FINDING_UX_V1_1.md를 참고하고, V2 추가 제약·검증은 docs/INCIDENT_EVIDENCE_UX_V2.md에 정리했습니다.

- '이상 징후 · 근거 · 판단 한계' 목록은 **JSON 대신 클릭 가능한 표**를 기본으로 사용합니다.
- 표에는 대표 관측시각, 탐지 신호, 주요 수치, 안전한 파일명과 근거 줄이 표시됩니다.
- 로그 파일은 `job_01.log (file_01)`처럼 내부 저장명으로 표기하며 원본 고객 파일명은 공개하지 않습니다.
- 행을 선택하면 관측 사실·탐지 기준·비교값·시간의 의미·추가 확인사항이 한 화면에서 제공됩니다.
- 근거 표에서 한 행을 선택하면 해시가 검증된 원본의 **마스킹된 구간만** 표시합니다.
- Job에는 종료시각과 로그에 기록된 시작시각을 구분하며, 실행시간으로 계산한 시작시각은 추정값으로 표기합니다.
- 헬스체크 마지막 기록과 수집 시각의 차이는 **장애 발생시각이 아닙니다.**
- 'AI에 전달할 선택 징후 자료 생성' 및 '보고서·관리 > AI 전달용 전체 분석 자료'에서 Markdown/JSON을 받을 수 있습니다.
- AI 자료에는 안전한 범위의 Job/SQL 통계, 탐지 기준, 근거 파일·줄번호, 같은 시간대의 비식별 이벤트를 포함합니다.
- JSON은 저장·전달 형식이고 화면의 기본 표현은 표·문장·차트입니다.
- 외부 AI 서비스로 자동 전송하지 않습니다. 전송 전에 담당자가 반드시 민감정보를 점검해야 합니다.

Windows 3.13:

    scripts\run_windows.bat

- Windows에서는 `tzdata`를 requirements.txt 조건부 종속성으로 설치합니다.
- Windows NTFS 권한은 현재 사용자/폴더 ACL에 따라 달라집니다. **공용 네트워크 공유 폴더에 고객사 원본을 넣지 마세요.**
- Windows용 파일 저장 경로 호환성은 수정했지만 실제 고객 환경에서의 전체 현장 회귀 검증은 별도입니다.

## 실행

    git clone https://github.com/ldokey/mpush-log-analyzer.git
    cd mpush-log-analyzer
    python3.13 -m venv .venv
    .venv/bin/python -m pip install -r requirements-dev.txt
    bash scripts/run_local.sh

Mac 로컬 브라우저에서 http://127.0.0.1:8501 접속. 종료는 Ctrl+C.
다른 PC/스마트폰에서는 이 주소가 그대로 열리지 않습니다.
인터넷 공개나 0.0.0.0 바인딩을 하지 마세요.

## 화면 구성

| 화면 | 기능 |
|---|---|
| 분석 대시보드 | Job·DB·CNS 처리 통계, 시간대 차트, 이벤트 필터, 이상 근거 및 같은 시간대 기록 |
| 로그 업로드 | debug/job/dbwrap/info/err/agent.ini의 여러 텍스트 파일을 선택하고 분석 |
| 해결 사례 | 별도 AI의 JSON 가져오기, 검토 대기, 담당자 승인, 승인 사례 검색 |
| 보고서·관리 | Markdown/HTML/JSON 다운로드, 재분석, 정확한 ID 확인 후 로컬 작업 삭제 |

- ZIP 압축은 지원하지 않습니다. .log/.txt/.ini만 선택할 수 있습니다.
- 파일별 전체/일부/확인 불가를 구분하고 실제 수집 시각을 입력해야 합니다.
- 파일당 50MiB, 최대 30개, 총 200MiB. 작업별 Agent 인스턴스 하나만 분석합니다.
- CNS RESPONSE_CODE=S는 발송 요청 수락이며 최종 수신자 배송 성공이 아닙니다.
- 지연·헬스체크 공백은 원인을 확정하지 않으며 SQL Lock이나 프로세스 종료를 단정하지 않습니다.

## 로컬 데이터 저장

    workspace/analysis_<UUID>/
      raw/                  # 원본 로컬 자료, Git 제외
      manifest.json         # 파일 정보, 완전성, 수집 시각
      events.jsonl          # 구조화·비식별 이벤트, 원본 줄번호 연결
      analysis_result.json  # 처리량과 이상 징후
      case_matches.json     # 검토 승인 사례 매칭
      report.md
      report.html
      report.json

별도 AI 해결 사례 데이터 계약:

- knowledge/schema/case.schema.json
- knowledge/schema/signal_catalog.json
- docs/CASE_AUTHOR_GUIDE.md

고객사의 원본 로그·설정·비밀번호·키·개인정보를 Git 또는 외부 AI로 전송하지 않습니다.
구조적 로그 근거만 마스킹 조회할 수 있으며 원본 전체 표시 기능은 제공하지 않습니다.
사례 자동 승인이나 자동 복구 조치는 제공하지 않습니다.

## CLI

    .venv/bin/python -m mpush_analyzer.cli analysis_<32자리 소문자 16진수 ID>
    .venv/bin/python -m mpush_analyzer.cli analysis_<ID> --stage2-only

기본 CLI는 전체 분석과 세 종류의 보고서를 갱신합니다.
--stage2-only는 기존 2단계 파서만 실행합니다.

## 테스트 및 성능

    .venv/bin/python -m pytest -q
    .venv/bin/python -m scripts.benchmark_synthetic --megabytes 10
    .venv/bin/python -m scripts.benchmark_synthetic --megabytes 50

합성 데이터만 사용합니다. 성능 수치는 CPU/디스크/로그 구성에 따라 달라집니다.
MVP 1.0 시험 장비(macOS arm64, Python 3.13)에서:
- 10MB / 180,789 이벤트: 전체 분석·조회 3.47초, peak process 165MB
- 50MB / 903,944 이벤트: 전체 분석·조회 21.97초, peak process 246MB

실제 고객사 로그의 완전한 회귀 테스트는 개인정보 취급 승인을 거친 뒤 로컬에서 수행해야 합니다.

## 문서

- docs/USER_GUIDE.md — 사용·보안·삭제·CLI·분석 한계
- docs/CASE_AUTHOR_GUIDE.md — 별도 AI가 따라야 할 해결 사례 JSON 규칙
- STAGE1_HANDOFF.md / STAGE2_HANDOFF.md / STAGE3_HANDOFF.md — 이전 단계 구현 기록
- STAGE4_HANDOFF.md — 최종 검증 및 후속 개선 사항
