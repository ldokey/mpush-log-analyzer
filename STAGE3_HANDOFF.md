# STAGE3 HANDOFF — MPushAgent Log Analyzer

Project: MPUSH-LOG-ANALYZER-01
Stage: 3 / 4
Project root: /path/to/mpush-log-analyzer
Stage-2 baseline: e6eeaf5a8df40199d216ac0605950ea0f659055a
Stack: Python 3.13, Streamlit, JSON/JSONL, jsonschema, pytest
Isolation: Existing MPushAgent sources and PropertyAI projects are untouched.
Data rule: synthetic fixtures only in Git; customer raw logs live under ignored local workspace.

## Stage-3 delivered

1. Conservative anomaly rules in mpush_analyzer/anomalies.py
   - Detect SEND_JOB_DELAY, RESULT_JOB_DELAY, OTHER_JOB_DELAY.
   - Use per-Job absolute seconds and target-count-bucket baseline when available.
   - Capture transport-step runtime separately as TRANSPORT_DELAY:
     measured SOCKET / HTTP step duration is NOT proof of network failure.
   - Detect DB_SQL_DELAY on recorded Laptime milliseconds;
     SQL '0 row(s) updated' is NOT an error.
   - Detect explicit SQL_ERROR, TRANSPORT_ERROR, GENERAL_EXCEPTION by safe exception types.
   - Detect repeated JOB_RUNNING_STATE skips within an explicit time window.
   - Detect HEALTHCHECK_GAP only when enough observed interval evidence exists;
     last-record-to-collection gaps require complete debug file(s) and collection time.
   - Flag PERIODIC_JOB_GAP only when independent heartbeat plus job logs
     have stale records with verified completeness; job logs alone never establish hang.
   - Preserve AGENT_EXIT_SEEN and AGENT_START_SEEN as observed lifecycle facts.
   - Do NOT infer Agent termination, actual DB Lock or confirmed socket outage.
2. Statistics and evidence
   - Per Job exact average/p50/p95 under configured sample cap; bounded-memory
     percentiles intentionally suppressed rather than misleading when cap exceeded.
   - Job max/target counts and SQL by statement category statistics.
   - Evidence refs store file_id and physical line range, with no raw SQL/text.
   - findings[] carries statement_type, confidence, severity, rule_id and caveat.
3. Knowledge lifecycle in mpush_analyzer/case_library.py
   - A separate AI's case JSON enters knowledge/inbox/ (ignored by Git) as draft only.
   - Case JSON schema + signal catalog + privacy pattern validation enforced.
   - Explicit direct human review approval required for knowledge/approved/.
   - Verified solution promotion requires confirmed root cause, source references,
     real resolution actions and explicit verification evidence + second confirmation.
   - Case IDs immutable; revision increases; highest valid approved revision wins.
   - No import of preapproved AI draft and no automatic case execution/fix.
4. Case matching in mpush_analyzer/case_matcher.py
   - Required/supporting/excluding signals and known Agent version/DBMS/Job condition.
   - Customer OS is UNKNOWN unless independently established; never infer it
     from the local Mac on which analyzer happens to run.
   - Matched reasons and source line evidence are returned for review.
   - Similarity is only a display rank, not a probability of identical root cause.
   - Unverified but approved cases marked reference_only, not verified_solution.
5. Integrated workflow
   - mpush_analyzer/stage3.py: rehash and reparse Stage-2 source on every run.
   - analysis_result.json gains metrics.stage3 + findings.
   - case_matches.json stores approved case search results in case folder.
   - CLI: python -m mpush_analyzer.cli analysis_<uuid> (Stage-3 default)
          python -m mpush_analyzer.cli analysis_<uuid> --stage2-only
   - Streamlit: upload -> parse -> detect -> match;
     case drafts upload/verify -> local inbox -> human approval -> matching;
     saved case reanalysis after catalog changes.
6. Contracts and docs
   - config/analysis_rules.json configurable local thresholds and caps.
   - knowledge/schema/case_matches.schema.json output data contract v1.0.
   - knowledge/schema/signal_catalog.json minor additive version 1.1:
     + OTHER_JOB_DELAY, TRANSPORT_DELAY, GENERAL_EXCEPTION.
   - Existing case.schema.json v1.0 and manifest schema remain unchanged.
   - README.md and docs/CASE_AUTHOR_GUIDE.md updated.

## Workflow

    cd /path/to/mpush-log-analyzer
    .venv/bin/python -m pytest -q
    .venv/bin/python -m streamlit run app.py --server.address 127.0.0.1 --server.port 8501

Use the "로그 업로드 및 분석" tab for new logs.
Use the "해결 사례 관리" tab for AI JSON drafts and explicit review/approval.
Use the "기존 분석 다시 실행" tab to rematch older case IDs.

## Safety invariants

- Existing Agent and production data sources unchanged.
- No direct external network AI calls, database connections or Agent restarts.
- Upload filenames never become stored paths. Synthetic fixtures only in Git.
- Raw messages, SQL bodies, client keys, JDBC URLs and phone numbers never
  become structured analysis event content.
- All cases require schema/privacy validation; AI JSON cannot assert approval.
- Original sources are hash-checked and never mutated by Stage-3.
- Stage-3 outputs are local JSON in ignored workspace/analysis_<uuid>.
- Knowledge inbox / approved directories are excluded by .gitignore and private.
- Incident root cause must never be stated as certain on symptom matching alone.
- Captured no-logs period is not automatically diagnosed as a process stop.
- Runtime app binds localhost only and does not publish a web endpoint.

## Evidence / tests

- Prior Stage-1/2 tests retained.
- Stage-3 synthetic tests cover incident-like 54.076s and 85.477s Job delays,
  SQL 7119ms, transport-step delays, heartbeat intervals/tail gap,
  RUNNING repeats, explicit SQL/socket/general exceptions and row-count zero.
- Partial debug logs suppress collection tail / periodic job gap conclusions.
- Only-job logs cannot independently trigger global scheduler hang.
- 35,000 regular heartbeat synthetic events produce no false gap alerts.
- Approved vs unreviewed, revision ordering, conflicting/excluded signals,
  DBMS/version mismatch, unknown OS and verified solution claims tested.
- SHA tampering, symlink outputs, private file modes, and deterministic reruns tested.
- Streamlit AppTest and local HTTP health/index smoke checked.
- Exact total test count and Git commit are in the execution report / local git log.

## Stage-4 remaining

- Polished dashboard and time-range/Job/Agent filtering; correlated event views.
- Clickable original line ranges with clear permissions and masking controls.
- Exportable sanitized customer-facing report and business-style wording.
- Larger synthetic performance tests, logging of parser unsupported variations,
  and operational instructions for safe deletion / retention.
- Optional enhancements: plugin-style Agent version adapters; broader signal
  classifications, explicit DB session / Thread Dump import (future scope).
- Review case library and rules with actual redacted customer incidents only
  after authorized local handling and privacy review.
- Stage-4 commit, independent regression, final handoff and deployment package.

Never send raw customer logs or configuration secrets to external AI for development.
