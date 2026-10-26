# STAGE2 HANDOFF — MPushAgent Log Analyzer

Project: MPUSH-LOG-ANALYZER-01
Stage: 2 / 4
Root: /path/to/mpush-log-analyzer
Baseline: Stage-1 commit 656d65c745fef0ea4e5f502a84cf0854202118b2
Stack: Python 3.13, Streamlit, jsonschema, pytest
Safety: local-only file processing, no existing Agent/DB/remote network mutations

## Delivered

1. Specialized parsers:
   - mpush_analyzer/parsers/job.py: multiline job summary, target_count, completed/incomplete, duration/steps/TPS, lifecycle
   - parsers/dbwrap.py: PSTMT.EQ, EU, EB execution records, Laptime milliseconds, result class/row count; no SQL text or NO_ID persistence
   - parsers/debug.py: request acceptance (RESPONSE_CODE=S), healthcheck, RUNNING skip and sanitized exceptions
   - parsers/info.py: scheduler registration, Agent lifecycle, transport state
   - parsers/err.py: multiline Stack Trace grouping, exception class + frame count only
   - parsers/common.py: timestamp parsing and midnight inference
2. Hash-verified local event pipeline: mpush_analyzer/pipeline.py
   - Preflight SHA-256/size of each original before writing output; re-check after parsing.
   - File ID + original line range for every event.
   - Clock normalized with explicit date hint/reference_date; unknown dates never invented.
   - Chunked external merge produces chronological events.jsonl without loading all raw text.
   - Summaries in analysis_result.json; schema validated and written atomically.
   - Input file contents never copied to derived events; only allowlisted enums and numeric values.
   - No persistent SQL text, actual phone, service identifiers, JDBC, secret values, or raw exception messages.
3. CLI: python -m mpush_analyzer.cli analysis_<32_lowercase_hex>
4. Streamlit: '로컬 분석 작업 생성 및 파싱' uploads then parses immediately; mini-summary.
5. Synthetic tests: 5 parser units, pipeline, hash/tamper safety, time order, multi-chunk, 967-job/396-db regression, CLI and prior Stage-1 tests.
6. README Stage-2 execution instructions.

## Key data contract

Input:
  workspace/analysis_<uuid>/raw/*
  workspace/analysis_<uuid>/manifest.json

Outputs:
  workspace/analysis_<uuid>/events.jsonl
  workspace/analysis_<uuid>/analysis_result.json

Each sanitized event:
  schema_version
  event_id, file_id, log_kind
  line_start, line_end
  clock, occurred_at, time_quality
  event_type, status, details

Summary:
  schema_version, analysis_id, analysis_status
  metrics.event_counts
  metrics.job_runs (runs, completed, incomplete, target_count_total, max_duration_seconds)
  metrics.db_executions (runs, incomplete, max_laptime_ms, by_statement, by_outcome)
  metrics.cns_request_responses (REQUEST acceptance != final delivery)
  metrics.source_summary, undated_events, incomplete_events
  findings=[] until Stage-3
  limitations[]

No external database or zip input. No customer data staged in Git.

## Accuracy notes

- A Job run count is NOT a message count. Sum target_count separately.
- RESPONSE_CODE=S is an acknowledgement of send request by CNS, NOT final customer delivery.
- dbwrap NO_ID (including negative IDs) is NOT a stable message identifier; never use it to join jobs.
- PSTMT.EB can include Result on the same physical line as Laptime.
- The current 'completed' status means the log summary contains required completion evidence; it does not prove any recipient delivery.
- Lack of error logs is not proof of healthy processing.
- Missing log timestamp after capture is not process exit. Completeness and capture time are stored separately.
- Time zone defaults to Asia/Seoul by contract; server clock source/time zone must be independently checked.
- 'partial' status can result from a cropped source, unknown completeness, unanchored dates, incomplete event, or unsupported log kind.
- Every unrecognized line is not necessarily an error. Stage-2 intentionally outputs only supported events.

## Acceptance

- Existing Stage-1 tests remain green.
- New synthetic tests validate 654 SEND_REAL_FILE_IMAGE, 313 HA_RECEIVE_RESULT and 396 DB executions with expected max durations.
- SHA mismatch refuses analysis before derived output modification.
- Two-pass+ chunk merge produces globally time-ordered JSONL for 20,000+ events.
- Stage-2 results do not include secrets, phone numbers, SQL body, NO_ID or original file names.
- Web UI smoke GET / + /_stcore/health HTTP 200 at 127.0.0.1 only, server stopped afterwards.
- Git staged files must be source/tests/docs only, no customer raw log files or .ini.

## Remaining for Stage 3

- Rule-based anomaly detector fills findings[] with observed vs indicator vs hypothesis.
- Job histograms: avg/p50/p95, duration against absolute and baseline criteria.
- SQL delay, DB wait candidate, network/HTTP latency and RUNNING recurrence.
- Healthcheck gaps: compare periodic scheduling while respecting completeness and collected_at.
- Approved knowledge-case JSON ingestion with schema validation, versioning and review controls.
- Signal-based matching with required/supporting/excluding rules.
- Source evidence line references for every finding; never infer root cause as certain.
- Stage-3 unit tests, handoff and a separate local Git commit.

## Remaining for Stage 4

- Full dashboard, filters, cross-file log-timeline evidence drill-down, report downloads.
- Large real-format synthetic stress/performance and privacy/security checks.
- Distribution/usage documentation; local-only listener default.

## Reproduction

    cd /path/to/mpush-log-analyzer
    .venv/bin/python -m pytest -q
    .venv/bin/python -m streamlit run app.py --server.address 127.0.0.1 --server.port 8501
    .venv/bin/python -m mpush_analyzer.cli analysis_<32_lowercase_hex>

Credentials and customer raw inputs must NEVER be sent to external AI or checked into Git.
For full real incident regression in the future, supply the source only to the isolated
local workspace after confirming explicit handling approval. Use synthetic inputs for Git tests.
