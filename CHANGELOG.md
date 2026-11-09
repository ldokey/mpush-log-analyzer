# Changelog

## v4.4 development — 2026-11-09 (feature branch only; not released)

- Reorganized the desktop workflow into import → focused findings → inquiry/notes → export, with lazy screen loading and common Stitch-derived design styles.
- Replaced exception-class-first summaries with evidence-backed connection, network, database and resource failure explanations, retaining uncertainty and masked source references.
- Added native debug message search across key/value, JSON and LMultiData table records; missing-service matches stay unconfirmed, SQL and body text cannot stand in for final delivery evidence.
- Collapsed routine fast SELECT/zero-target Job noise by default while preserving slow, failed, incomplete, write operations, full raw records and advanced investigation.
- Removed multi-Agent/HA selection UI; kept existing log job names and read-only legacy analysis available.
- Synthetic verification: 440 pytest cases and 50 desktop browser checks (1280/1440/1920px) on macOS. No native Windows or customer-specific acceptance claimed.
- No public main/release change, no customer log upload, no automatic operations.

## v4.3.1 development — 2026-11-04 (not released)

- Fixed timestamp-prefixed Job headers, clock-only log date absence, hourly/minute date detection, UTF-8/CP949 chunk boundaries and ABNORMAL skip observations.
- Added inspectable input coverage and manual hash-verified, temporary reparse for existing analysis snapshots without modifying workspace or customer notes.
- Improved original-only message scan boundaries and explicit empty-result explanations; reset stale Job/message filters when analysis scope changes.
- Existing 313 + 53 new synthetic tests: 366 passed; 37 recovery/browser checks on macOS. Native Windows/customer logs unverified.
- No main/release update, no migration of saved cases, and no automatic operations.

## v4.3 development — 2026-11-03 (not released)

- Added three Stitch-derived desktop workbench tabs for Job stalls, message outcomes, and observed throughput/backlog.
- Explicitly separated server request acceptance from original/fallback message outcomes; no assumed success from SQL predicates or missing stages.
- Compared Job gaps/RUNNING repeats/duration spikes against observed baselines, with evidence links and explicit uncertainty.
- Added session-only manual backlog observations and offline, de-identified JSON export.
- Synthetic regression: 313 tests (229 existing + 84 new); 39 real-browser integration/robustness checks on macOS.
- No main/release update; no Windows native or real customer-log acceptance claimed.

## v4.2.0 — 2026-11-02

Integrated **V4.1 + V4.2** release; includes existing V4.0.0 and V3.1 functionality.

### V4.2 — Investigation
- Time-aligned investigation across info/err/job/debug/dbwrap and Job execution spans with source evidence.
- Root/Caused by/Suppressed exception-stack chains and repeated-record counts/timing.
- Equal-length baseline/incident comparison: job/SQL counts, mean, P50/P95, maximum and step timings.
- Job/scheduler/healthcheck recording gaps compared with observed/configured cadence; RUNNING skip, last event versus collected time, optional PID/restart facts.
- On-demand, explicit SERVICE_SEQNO + MESSAGE_SEQNO trace with ephemeral hashed identities; no unsupported final-delivery assertion.
- Optional read-only XML references, safe agent.ini crosschecks, evidence requests and reviewer-approved reply draft.
- XML and Agent 2.8 are optional context, not prerequisites or confirmed full compatibility.
- Automated multi-Agent/HA total throughput inference is not implemented.

### V4.1 — Customer Support Workspace
- Redmine issue-number or URL mapped to local inquiry, Agent-specific analyses, symptoms, actions and verification.
- Selected folder and ZIP/TAR/TGZ/GZ intake with path traversal/link/size/bomb safeguards.
- Original source path/name visible locally with anonymous aliases maintained in standard exports.
- Date-aware duplicate handling and SHA-256-verified old source-name recovery.
- Review-gated local issue notes and reusable knowledge drafts.

### Verification and limits
- 229 automated tests pass on macOS/Python 3.13 using synthetic fixtures; release ZIP also independently tested.
- Real Windows/NAS/customer-log runtime remains unverified.
- No Redmine write API, operating DB writes, or external AI log upload included.
- Python/Streamlit ZIP; not independent EXE. New folder creates a new virtual environment.

## v4.0.0 — 2026-10-29

- Six-screen event/exploration workbench plus previous V3.1 evidence-alignment, input limits and Windows launcher.
