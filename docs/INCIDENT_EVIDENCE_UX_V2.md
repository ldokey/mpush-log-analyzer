# INCIDENT-EVIDENCE-UX-V2 — 2026-10-26

Project: MPushAgent Log Analyzer
Goal: evidence-first investigator UI and privacy-safe AI handoff
Base: a451df45182d2539f4403e4715b718ee75a03813
Branch: feature/evidence-ux-integrated
Worktree: mpush-log-analyzer

## New investigator dashboard

- JSON expanders are replaced by a selectable table and immediately readable detail panel.
- Every finding shows observed or basis time, Korean title, numeric deviation,
  safe source filename plus file_XX ID, and original physical line range.
- Detailed facts include what was observed, why the rule triggered, measured
  values, time-quality limitations, and the next verification action.
- Job starts from a recorded clock are distinguished from duration-calculated
  starts. Conflicts are explicitly marked.
- Healthcheck last-record-to-collection time is NEVER called outage start/end.
- Evidence-linked nearby events are ranked by time distance so a dense interval
  does not hide the triggering incident. Same-time findings all retain context.
- Old cases without newly added timestamp provenance are still readable.

## Reports and AI handoff

- Normal Markdown/HTML/JSON reports now include timestamps, safe log aliases,
  interpretation, measured values, and evidence references.
- Separate full-case or single-finding AI Markdown/JSON is generated locally
  on a deliberate click; no external AI network call.
- AI packets include agent version, DB type, source completeness, relative
  time and the stated reference-date source, Job counts vs message target
  counts, unknown-date/incomplete event counts, and nearby sanitized events.
- Each finding includes at most 16 nearby events, within +/-120 seconds;
  a shared timestamp can anchor multiple different findings.
- AI files never include raw SQL, exception message, credentials,
  recipient phone numbers or arbitrary original log lines.
- All AI exports revalidate SHA-256 of original inputs before generation.
- Unsafe free-text descriptions and limitations are not passed through
  unchanged; safe static templates and numeric/categorical values are used.
- Users must still review locally generated text for privacy before sharing.

## Windows compatibility

- Filesystem permission helper keeps 0600/0700 on macOS/Linux while avoiding
  unsupported fchmod on Windows.
- Windows permission enforcement relies on inherited NTFS ACLs.
- Windows-only tzdata dependency added to requirements and pyproject.
- scripts/run_windows.bat uses Python 3.13 and binds Streamlit to localhost.
- Prefer a private local Windows NTFS volume over a network-mapped share.
- Native Windows customer-machine end-to-end verification is still required.

## Compatibility and validation

- Stage1-4 contracts and v1.1 AI/finding modules are retained.
- New modules have a _v2 suffix to avoid replacing existing v1.1 APIs.
- All tests use synthetic input; actual enterprise client logs were not used.
- Test coverage includes: source alias, start/end clock provenance, date
  uncertainty, limit windows, duplicate timestamps, priority ranking, safe
  AI outputs, tampering refusal, Windows fallback, and Streamlit screen checks.
- Before GitHub PUBLIC push, prepare a standalone sanitized public release
  snapshot and exclude all local user paths and private historical commits.

## Run

Mac:
    cd mpush-log-analyzer
    bash scripts/run_local.sh

Windows (PowerShell within project root):
    .\scripts\run_windows.bat

Reanalyze an older saved analysis through the "보고서·관리" tab for enhanced
time metadata. Raw data remains in the local ignored workspace.

## Important limitations

Log gaps do not prove process death. Job delay does not prove message failure.
SOCKET/HTTP timing buckets do not prove actual network faults. CNS response S
is request acceptance, not recipient delivery. Analysis sampling may exclude
actual earliest/latest occurrences and must never be called full outage time.

## Acceptance evidence

- Full pytest regression: 93 tests PASS (synthetic inputs only).
- Streamlit local index and health probes: HTTP 200 / 200 at 127.0.0.1:18533.
- Test listener stopped on completion.
- Python compilation: PASS; pip dependency check: PASS.
- 10 MiB synthetic log: 180,788 normalized events;
  3.161s full analysis + 0.591s dashboard query;
  total (including intake) 3.772s, peak process memory 173.1 MiB.
- These are synthetic benchmarks on a Mac and do not establish native Windows throughput.
- Remaining native validation: Python 3.13 Windows file uploads and NTFS ACL review
  on the actual user machine, with non-sensitive test logs before customer data.
