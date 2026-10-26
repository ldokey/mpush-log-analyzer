#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
cd "$ROOT"
PORT="${MPUSH_ANALYZER_PORT:-8501}"
if [[ ! "$PORT" =~ ^[0-9]{1,5}$ ]] || (( PORT < 1 || PORT > 65535 )); then
  echo "잘못된 로컬 포트 번호입니다." >&2
  exit 2
fi
if [[ ! -x .venv/bin/python ]]; then
  echo "Python 가상환경이 없습니다. README 설치 방법을 확인하세요." >&2
  exit 2
fi
echo "MPushAgent Analyzer: http://127.0.0.1:$PORT"
echo "종료: Ctrl+C"
exec .venv/bin/python -m streamlit run app.py \
  --server.address 127.0.0.1 \
  --server.port "$PORT" \
  --browser.gatherUsageStats false
