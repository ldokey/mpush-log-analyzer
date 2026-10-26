# MPushAgent Log Analyzer — 분석 상세·AI 연계 개선 (v1.1)

기존 JSONL/analysis_result.json 계약을 유지하면서 탐지 결과를 읽기 쉽게 개선합니다.

## 탐지 목록과 근거 조회
- 발생시각, 탐지 항목, 대표 수치, 판정, 비식별 로그 파일 별칭과 줄번호를 표로 표시합니다.
- 행을 선택하면 측정값/임계값, 판단 한계, 다음 확인사항, 마스킹된 로그 근거를 같은 화면에서 확인합니다.
- 원본 고객사 파일명은 수집 당시 저장하지 않으므로 job_01.log / file_01 등 안전한 저장 별칭을 사용합니다.
- 날짜가 확인되면 YYYY-MM-DD HH:MM:SS.mmm을 표시하고, 알 수 없으면 '날짜 미확인'으로 표시합니다.
- Job 시작시각과 종료시각을 분리해 저장합니다. 날짜 근거가 없으면 시작시각의 날짜는 추정하지 않습니다.
- 이상 징후의 대표/표본 근거 시간 범위는 실제 전체 장애 지속시간을 보장하지 않습니다.
- 헬스체크의 마지막 기록과 수집시각 사이 공백은 프로세스 종료의 증거가 아닙니다.

## AI 전달
- 선택한 이상 징후 또는 전체 탐지 결과의 Markdown을 복사하거나 Markdown/JSON으로 다운로드합니다.
- AI 자료에는 확인된 환경, 로그 완전성, 대표시각, 근거 별칭·줄번호, 측정값과 임계값, 해석 한계, 추가 확인사항을 포함합니다.
- 원본 SQL/전화번호/키/고객 메시지 및 비검토 사례 설명문은 복제하지 않습니다.
- 외부 AI API 호출을 추가하지 않았습니다. 패턴 마스킹은 완벽한 익명화가 아니므로 외부 공유 전 사람 검토가 필요합니다.

## 기존 보고서
report.md / report.html / report.json은 이제 근거 시각, 파일 별칭, 측정값, 판단 한계와 다음 확인사항을 포함합니다.

## Windows
POSIX의 os.fchmod를 파일 권한 호환 래퍼로 대체했습니다. Windows NTFS/사내 NAS에서는 폴더와 계정 ACL을 운영자가 직접 확인해야 하며, 코드 수정만으로 비공개 권한이 보증되지 않습니다. Windows 실제 GUI/ACL 검증은 별도로 필요합니다.

## PowerShell에서 실행
    py -3.13 -m venv .venv
    .\.venv\Scripts\python.exe -m pip install -r requirements.txt tzdata
    .\.venv\Scripts\python.exe -m streamlit run app.py --server.address 127.0.0.1 --server.port 8501

실제 고객사 원본 로그 없이 합성 데이터로 회귀 테스트를 수행합니다.
