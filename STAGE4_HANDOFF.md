# STAGE4 HANDOFF — MPushAgent Log Analyzer MVP 1.0

Project code: MPUSH-LOG-ANALYZER-01
Stage: 4/4 (final MVP)
Remote Mac root: /path/to/mpush-log-analyzer
Stage-3 baseline commit: 5ee231def4aa1bc909d78da0da19a150bfe676cf
Platform: macOS arm64, Python 3.13.14, Streamlit 1.66.1, pandas 3.1.0
Safety: standalone local-only program; existing MPushAgent 3.2/3.3 and other projects untouched.

## Delivered in Stage 4

1. Dashboard (dashboard_ui.py, mpush_analyzer/dashboard_data.py)
   - Four tabs: 분석 대시보드 / 로그 업로드 / 해결 사례 / 보고서·관리.
   - Job counts versus job target counts are distinguished.
   - Job and DB max/average/P50/P95 from prior stages shown in summary tables.
   - Time charts for Job executions, DB calls, errors and longest Job duration.
   - Time range, Job, source-file and log-type filtering; paged sanitized event tables.
   - Minute -> hour -> day aggregation to avoid excessive timeline series for long logs.
   - Select an anomaly and inspect cross-file events within a bounded ±2 minute window.
   - Select source reference to see verified file ID, physical line range, safe excerpt.
   - Same-clock events are not assumed to prove a causal chain.

2. Raw evidence viewer (mpush_analyzer/source_view.py)
   - Verifies recorded hashes and resolves only manifest-allowlisted local files.
   - Shows structural log attributes: Job type, measured steps, Pstmt Laptime,
     recognized response code, lifecycle and exception CLASS only.
   - Never shows raw SQL, message text, phone numbers, credentials or arbitrary
     log bodies. Non-allowlisted text is masked.
   - Hard limits for context lines and oversized evidence requests.
   - Supports log provenance file ID + line number without copying source text
     into JSON reports.

3. Reports (mpush_analyzer/report.py)
   - Deterministic Markdown, print-friendly escaped semantic HTML, JSON.
   - Inputs are allowlisted metrics, signal titles, event references and approved
     case IDs; never copy original case descriptions or customer SQL.
   - Static HTML with CSP, no external fonts/scripts/assets.
   - Auto-generated during a full analysis and downloadable from the web UI.
   - Files: report.md, report.html, report.json in ignored per-analysis workspace.
   - Root causes and recipient delivery are never asserted from an indicator.

4. Operations and lifecycle
   - mpush_analyzer/runner.py: Stage-3 parser/analyzer then three reports.
   - CLI full mode also generates the reports; --stage2-only is still supported.
   - mpush_analyzer/lifecycle.py: validated local case listing and explicit
     full-ID confirmation before deleting exactly one expected analysis folder.
   - No automatic retention or deletion, no network listener beyond 127.0.0.1.
   - scripts/run_local.sh: dedicated localhost launcher; configurable local port.
   - docs/USER_GUIDE.md: upload, filters, redaction, reports, case approval, retention,
     CLI usage, safe deletion, limitations.
   - README updated to MVP 1.0; direct pandas dependency declared.

5. Memory/performance and regression
   - Dashboard reads sanitized JSONL incrementally with page limits.
   - Health and RUNNING-state internal samples now have explicit memory caps;
     skipped samples are surfaced as a stated analysis limitation, never hidden.
   - Configurable thresholds and caps in config/analysis_rules.json.
   - tests/test_stage4_report_dashboard.py: end-to-end safe report generation,
     cross-file event filtering, precise source excerpt, redaction, symlink
     refusal, explicit scope-only delete, dynamic timeline aggregation.
   - scripts/benchmark_synthetic.py: synthetic logs only; temporary files removed.
   - Existing Stage 1/2/3 tests continue to pass.

## Verified results (synthetic data ONLY)

- pytest: 73 passed (all stages combined)
- Python compileall: PASS
- pip check: No broken requirements
- bash -n scripts/run_local.sh: PASS
- Streamlit AppTest with synthetic saved case: PASS, four tabs verified
- Streamlit localhost test: index and _stcore/health HTTP 200
- Listener bound to 127.0.0.1 only (no public server)
- Stage-4 source security: raw details/secret patterns omitted from exported report;
  source excerpt only allowlisted fields; corrupted raw/symlinks refused.
- Markdown/HTML/JSON reproducibility with identical synthetic source inputs.
- Git ignore excludes workspace, original .log/.ini, case inbox/approved files and venv.

Synthetic benchmark on this Mac:
- 10 MiB / 180,789 events: intake .019s, full analysis 2.884s,
  dashboard query .562s; TOTAL 3.465s; peak process memory 165.3 MiB.
- 50 MiB / 903,944 events: intake .063s, full analysis 18.971s,
  dashboard query 2.934s; TOTAL 21.967s; peak memory 245.8 MiB.
- Real logs, alternate data distributions, network delays and DB locks may vary.
- One Streamlit/third-party pandas compatibility deprecation warning appeared in
  AppTest, but it did not affect test result.

## Data compatibility

Stage 1 contracts and Stage 2 normalized event JSONL are preserved.
Stage 3 findings/approved-case matching and v1.1 signal catalog are preserved.
Stage 4 uses the same analysis manifest and results with additive reports.
There is no new DB, external AI API, network tunnel or public Git push.

## Usage

    cd /path/to/mpush-log-analyzer
    bash scripts/run_local.sh

localhost URL: http://127.0.0.1:8501
Stop with Ctrl+C.

CLI full reanalysis:
    .venv/bin/python -m mpush_analyzer.cli analysis_<32_lowercase_hex>

Synthetic benchmark:
    .venv/bin/python -m scripts.benchmark_synthetic --megabytes 10

AI case author guidance:
    docs/CASE_AUTHOR_GUIDE.md
    knowledge/schema/case.schema.json
    knowledge/schema/signal_catalog.json

## Operational boundaries and remaining checks

- This is a locally validated MVP, not a deployed multiuser SaaS product.
- Browser-native screenshot/visual UX review has not been completed;
  Streamlit AppTest and local HTTP startup were verified.
- Some older uploaded real logs have expired and were not used for this build.
- Before customer-live use, obtain authorized local copies of redacted
  representative 3.2/3.3 customer logs to validate parser pattern coverage.
- Source information in existing AI case JSON must be checked by a human;
  regex-based privacy validation does not guarantee complete anonymization.
- The tool cannot prove final message delivery, a root cause, process termination,
  lock contention or JVM thread deadlock from log patterns alone.
- Thread Dump/DB session integration, customer-specific plugin rules,
  multi-Agent analysis, remote authenticated access and AI semantic search
  are optional later enhancements, not part of this MVP.

## Final state handoff

Commit SHA and Git clean status are recorded in final execution results.
All customer files remain only in ignored local workspace; no production source
or existing Agent was modified.
