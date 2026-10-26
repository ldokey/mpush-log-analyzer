# Evidence UX V3 — incomplete-work review and targeted improvements

## Baseline inspected before editing

- Remote project: `/path/to/mpush-log-analyzer`
- Base branch: `main`, commit `a690274`; clean worktree at inspection.
- Previous work `a451df4` already provided readable finding evidence and AI exports.
- V2 integration `a690274` was already committed and present on `main`.
- Baseline: 93 tests PASS (synthetic data). No uncommitted work was overwritten.
- Implementation used isolated branch `feature/evidence-ux-review-v3`.

## What V3 changes

1. **Opening overview that distinguishes evidence from outage time**
   - Observed earliest/latest *finding evidence* and user-supplied collection time are separate KPIs.
   - Clock-only inputs are displayed with "date unknown" rather than discarded.
   - Incomplete source files and undated events are highlighted.
   - Counts by finding class support a faster incident orientation.

2. **Readable, focused anomaly list**
   - Chronological evidence order by default, with severity order as an option.
   - Categories to filter send, DB, network, health check, errors and lifecycle.
   - Primary visible columns: time, anomaly, numerical measure, recognizable file alias, severity and finding type.
   - Internal IDs and detailed evidence remain accessible, but are not dominant columns.
   - Click a table row to view its case details without expanding raw JSON.
   - Tabs separate anomaly investigation, timeline and job/DB statistics.

3. **Time provenance**
   - For qualifying Job evidence, display original recorded start to completed end.
   - If start is absent or inconsistent, show duration-calculated start explicitly as an *estimate*.
   - For healthcheck interval gaps, display the actual pair of log timestamps delimiting the representative gap.
   - Distinguish last observed timestamp → log collection timestamp from incident start/end.
   - Sampled evidence range is never described as an exhaustive outage period.

4. **Rule explanation and baseline**
   - SQL duration and HTTP/SOCKET-step excess: actual value versus configured threshold.
   - Job duration: actual value versus *effective* threshold, including comparable-target-count median where available.
   - Health check interval: observed largest gap versus sampled normal interval.
   - Health tail / simultaneous tail: explain log-to-collection time in numbers, not assumed downtime.
   - Avoid repeating the same measurement table several times on screen.

5. **More complete AI handoff**
   - Nearby sanitized events now cover up to 12 evidence timestamps per finding, not just the first one.
   - One event per matching evidence window is selected before high-priority extras, avoiding dense-window starvation.
   - Per-finding results remain limited to 16 selected related events within ±120 seconds.
   - Job and SQL statistics are represented as Markdown tables rather than Python dictionary strings.
   - Explicitly state sample basis, date uncertainty and that proximity is not proof of cause.
   - Original SQL bodies, message text, credentials, private file paths and raw exception messages are never included.

## Deferred / boundaries

- Current event and findings schemas remain backwards-compatible; old records without V3 fields still render.
- Customer original names remain intentionally excluded. Generated names (e.g., `dbwrap_01.log (file_02)`) are preferred.
- Distinct jobs or clocks don't guarantee causal associations; lag/timeout diagnosis still needs external data and possibly JVM Thread Dump.
- No new external AI service, remote server connection or automated Agent restart.
- No customer production log imported; tests use synthetic fixtures only.
- The latest GitHub public release must be updated with a sanitized snapshot; local development history or OS user paths must not be pushed.
- Native Windows UI/ACL validation is pending on the user's machine. Local Mac tests cannot establish Windows security behavior.
- Visual pixel-level browser review is not guaranteed when private browser tooling is unavailable; Streamlit interaction tests and localhost smoke are required.

## Verification

Run:
    .venv/bin/python -m pytest -q
    .venv/bin/python -m compileall -q mpush_analyzer dashboard_ui.py app.py
    .venv/bin/python -m scripts.benchmark_synthetic --megabytes 10

Regression includes prior 93 tests plus tests/test_evidence_ux_v3.py covering:
- recorded versus inferred Job start
- observed heartbeat gap timestamps
- effective Job threshold versus absolute minimum
- meaningful undated clock display
- multi-evidence AI context
- privacy-safe AI Markdown/JSON
- Streamlit table/tabs and readable front page

## User workflow

Dashboard -> "이상 징후·근거" tab -> select time-ordered anomaly row -> see actual
measure/threshold and short explanation -> inspect safe evidence file/line ->
review same-time events -> export finding Markdown/JSON to ask an AI.

Use the "보고서·관리" tab to create the whole-case AI handoff and normal customer report.
AI sharing remains a deliberate user action and requires a final privacy review.

## Completed verification

- 101 automated tests passed (including prior 93), synthetic input only.
- Python compileall and pip check passed.
- 10 MiB synthetic logs: 180,788 events, 3.766 seconds for intake + full analysis + dashboard query; process peak 173.2 MiB.
- Streamlit localhost health returned HTTP 200; private browser screenshot service was unavailable (429). No pixel-perfect visual verification claimed.
- Temporary synthetic dashboard case removed and localhost test server shut down.
- Existing production agent source and customer's data were not modified.
