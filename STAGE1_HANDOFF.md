# STAGE1 HANDOFF — MPushAgent Log Analyzer

Project: MPUSH-LOG-ANALYZER-01
Stage: 1/4
Project root: /path/to/mpush-log-analyzer
Stack: Python 3.13, Streamlit, jsonschema, pytest
Execution: local-only, read-only Agent reference; no Agent or PropertyAI mutations

## Delivered

- New isolated Git repository + .venv
- Streamlit upload UI: multiple .log/.txt/.ini, file-level completeness, manual classification, input metadata
- File detection using filenames + bounded content snippets; SHA-256 duplicate detection, dates/clock hints and CP949/UTF8 decoding
- Agent 3.2/3.3 .ini allowlist-only extraction (AGENT, SERVICE, DBMS, HA, JOB_SELECT, TEST, REAL)
- Private local storage of originals in workspace/analysis_<uuid>/raw, sanitized manifest.json
- Case JSON contract, signal catalog and a validator with approval/verification constraints
- Synthetic fixtures, automated tests, README and separate AI case authoring guide

## Acceptance and observed checks

- pytest: 31 tests passed (re-run after any patch)
- Local Streamlit HTTP smoke: GET / and /_stcore/health both HTTP 200 on 127.0.0.1:18501 (temporary test)
- Listener remained limited to 127.0.0.1, service stopped after smoke test
- Agent 3.2/3.3 real reference agent.ini: seven supported sections recognized, eight JOB_SELECT keys per config; values not printed
- .gitignore excludes workspace/, .venv/, knowledge/inbox/, knowledge/approved/, *.log and *.ini
- File upload UI/validation and case JSON validator were also covered by unit/Streamlit AppTest; synthetic only

## Contracts frozen for next stage

- knowledge/schema/manifest.schema.json (1.0): one intake and sanitized metadata record
- knowledge/schema/case.schema.json (1.0): case evidence, resolution status, review controls
- knowledge/schema/signal_catalog.json (1.0): stable signal codes
- knowledge/schema/analysis_result.schema.json (1.0): future output contract
- workspace/analysis_<uuid>/raw/<safe_generated_name>
- workspace/analysis_<uuid>/manifest.json

Schema changes must be explicit and versioned. Never infer that missing log lines imply Agent shutdown.

## Known limitations (deliberate Stage-1 boundaries)

- No parsing of complete Job/DB/debug events, error classification, metric engine, or customer report yet
- No case storage approval or similarity matching; validator only
- No ZIP upload, no direct server or DB access
- Agent instance identity is NOT verified across files: one instance per intake is a user workflow rule
- Date/time hints are heuristic, sampled from start/end of each file, not full-file event timestamps
- Sensitive-data pattern scanning is best-effort only; human privacy review remains necessary
- Current file size limit: 50MiB/file and 200MiB total, 30 files per intake
- No real customer logs committed; production-format regression data should be synthetic

## Stage-2 tasks and acceptance

1. Implement dedicated parsers for debug, info, job, dbwrap, err.
2. Reconstruct multiline events / stack traces; preserve source file_id and original line range.
3. Handle dates, midnight rollover, missing/truncated inputs, logging time ambiguities.
4. Create events.jsonl and analysis_result.json from manifest+raw files; no external DB.
5. Validate raw/manifest hashes on read; avoid copying secret raw text into derived outputs.
6. Assert known synthetic counts and delays, no false "delivery success" interpretation.
7. Keep UI and core engine separate; Stage-2 can operate from CLI on an existing case directory.
8. Use separate Stage-2 Git commit, STAGE2_HANDOFF.md and reproducible pytest results.

## Execution / verification

    cd /path/to/mpush-log-analyzer
    .venv/bin/python -m pytest -q
    .venv/bin/python -m streamlit run app.py --server.address 127.0.0.1 --server.port 8501

No public network exposure, no production deployment, no automatic restart of Agent.
