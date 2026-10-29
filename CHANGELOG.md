# Changelog

## v4.0.0 — 2026-10-29

Includes V3 and V3.1 capabilities and adds V4 investigation workbench.

### V4
- Six analysis screens: overview, all normalized events, Job, DB, incident/error investigation and source quality.
- Full structured event browsing independently of summarized Finding and evidence caps.
- Time / source / job / type / status filters, paging, safe detail drilldown and page CSV.
- Job stage durations, TPS and target count; SQL statement category, outcome and execution latency.
- Cross-file time context and selected evidence alignment.

### V3.1 included
- Correct provenance alignment of evidence file, line number and timestamp for AI summaries.
- Increased input limits to 350MiB/file and 600MiB overall, up to 30 files.
- Windows 10/11 double-click launcher, install/troubleshooting guide and static tests.

### Verification & limitations
- 122 synthetic tests passed on macOS with Python 3.13.
- Local-only Streamlit HTTP smoke: 200.
- Windows native execution, enterprise security policy and customer log compatibility require independent verification.
- No sensitive original log, internal development handoff or local credentials are distributed.
