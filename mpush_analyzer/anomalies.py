"""Conservative, evidence-linked Stage-3 anomaly rules over sanitized Stage-2 events.

No runtime network calls, no parsing of raw SQL or message bodies, no root-cause claims.
"""
from __future__ import annotations

from collections import Counter, defaultdict, deque
from datetime import datetime
import json
from math import ceil
from pathlib import Path
from statistics import mean, median
from typing import Any, Iterator

CONFIG = Path(__file__).resolve().parents[1] / "config" / "analysis_rules.json"
BASIC_TIME_KIND = {"anchored", "midnight_inferred"}
TRANSPORT_EXCEPTIONS = {
    "SocketTimeoutException", "ConnectException", "SocketException",
    "NoRouteToHostException", "UnknownHostException", "SSLException",
    "HttpTimeoutException", "ConnectionClosedException",
}
SQL_EXCEPTIONS = {"SQLException", "SQLTimeoutException", "SQLTransientConnectionException",
                  "SQLNonTransientConnectionException", "SQLSyntaxErrorException"}


def load_rules() -> dict[str, Any]:
    data = json.loads(CONFIG.read_text(encoding="utf-8"))
    if data.get("schema_version") != "1.0":
        raise ValueError("지원되지 않는 분석 규칙 버전입니다.")
    expected = {
        ("job", "absolute_default_seconds"): (0.01, 100000),
        ("job", "baseline_min_samples"): (3, 100000),
        ("job", "median_multiplier"): (1.01, 100),
        ("job", "max_percentile_samples"): (100, 1000000),
        ("job", "max_evidence_per_job"): (1, 10),
        ("sql", "absolute_ms"): (1, 1e9),
        ("sql", "max_evidence"): (1, 10),
        ("sql", "max_percentile_samples"): (100, 1000000),
        ("transport", "step_seconds"): (0.01, 1e9),
        ("healthcheck", "min_intervals"): (2, 100),
        ("healthcheck", "min_gap_seconds"): (1, 3600),
        ("healthcheck", "multiplier"): (1.1, 100),
        ("healthcheck", "max_estimated_interval_seconds"): (1, 3600),
        ("healthcheck", "max_stored_events_per_kind"): (100, 200000),
        ("healthcheck", "tail_min_gap_seconds"): (1, 86400),
        ("running", "min_occurrences"): (2, 100),
        ("running", "max_stored_events"): (100, 200000),
        ("running", "window_seconds"): (1, 86400),
        ("findings", "max_total"): (1, 500),
        ("findings", "max_evidence_refs"): (1, 15),
        ("matches", "limit"): (1, 30),
    }
    for (section, key), (low, high) in expected.items():
        number = data[section][key]
        if isinstance(number, bool) or not isinstance(number, (int, float)) or not low <= number <= high:
            raise ValueError("분석 규칙 범위 오류")
    for job, threshold in data["job"]["absolute_seconds_by_job"].items():
        if not job.isupper() or isinstance(threshold, bool) or not 0 < threshold <= 1e6:
            raise ValueError("Job 임계값 오류")
    return data


def _dt(e: dict[str, Any]) -> datetime | None:
    try:
        return datetime.fromisoformat(e["occurred_at"]) if e.get("occurred_at") else None
    except (TypeError, ValueError):
        return None


def _ref(e: dict[str, Any]) -> dict[str, Any]:
    details = e.get("details") or {}
    return {"file_id": e["file_id"], "line_start": e["line_start"],
            "line_end": e["line_end"], "occurred_at": e.get("occurred_at"),
            "clock": e.get("clock"), "log_kind": e.get("log_kind"),
            "start_at": details.get("start_at") if e.get("event_type") == "job_run" else None}


def _job_bucket(target: Any) -> str:
    if not isinstance(target, int) or isinstance(target, bool):
        return "unknown"
    if target == 0:
        return "zero"
    if target == 1:
        return "one"
    return "2-9" if target < 10 else "10+"


def _stats(values: list[float], total_count: int, total_sum: float) -> dict[str, Any]:
    sampled = total_count != len(values)
    return {
        "samples": total_count,
        "average": round(total_sum / total_count, 6) if total_count else None,
        "p50": round(median(values), 6) if values and not sampled else None,
        "p95": round(sorted(values)[ceil(.95 * len(values)) - 1], 6) if values and not sampled else None,
        "percentiles_skipped_due_to_limit": sampled,
    }


def _top_append(entries: list[tuple[float, dict[str, Any]]],
                amount: float, event: dict[str, Any], limit: int) -> None:
    entries.append((amount, event))
    entries.sort(key=lambda item: (-item[0], item[1].get("file_id", ""), item[1]["line_start"]))
    if len(entries) > limit:
        del entries[limit:]


def _finding(signal: str, rule_id: str, title: str, text: str,
             events: list[dict[str, Any]], *, severity: str = "warning",
             statement: str = "indicator", confidence: str = "medium",
             measure: dict[str, Any] | None = None) -> dict[str, Any]:
    unique = list({(e["file_id"], e["line_start"]): e for e in events}.values())
    times = sorted(e["occurred_at"] for e in unique if e.get("occurred_at"))
    # These refer only to sampled evidence, not every occurrence in the entire source.
    primary = unique[0] if unique else None
    return {
        "representative_at": primary.get("occurred_at") if primary else None,
        "evidence_first_at": times[0] if times else None,
        "evidence_last_at": times[-1] if times else None,
        "time_basis": "sampled_evidence",
        "finding_id": "", "signal_code": signal, "rule_id": rule_id,
        "statement_type": statement, "severity": severity, "confidence": confidence,
        "title": title, "description": text,
        "evidence_file_ids": sorted({e["file_id"] for e in unique}),
        "evidence_refs": [_ref(e) for e in unique],
        "measure": measure or {},
    }


def _iter_events(path: Path) -> Iterator[dict[str, Any]]:
    if path.is_symlink() or not path.is_file():
        raise ValueError("분석 이벤트 파일이 유효하지 않습니다.")
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            if len(line) > 25000:
                raise ValueError("비정상적으로 큰 정규화 이벤트입니다.")
            yield json.loads(line)


def detect_anomalies(
    events_path: Path, manifest: dict[str, Any], rules: dict[str, Any] | None = None,
) -> tuple[dict[str, Any], list[dict[str, Any]], list[str]]:
    """Return supplemental metrics, findings and scope limitations.

    Healthcheck gap is an indicator of missing records, not process termination.
    """
    rules = rules or load_rules()
    job_groups: dict[str, dict[str, Any]] = {}
    sql_groups: dict[str, dict[str, Any]] = {}
    health: dict[str, dict[str, deque]] = defaultdict(dict)
    health_skipped: Counter[str] = Counter()
    running: dict[tuple[str, str], deque] = {}
    running_count: Counter[tuple[str, str]] = Counter()
    running_skipped: Counter[str] = Counter()
    explicit: dict[str, list[dict[str, Any]]] = defaultdict(list)
    explicit_count: Counter[str] = Counter()
    lifecycle: dict[str, list[dict[str, Any]]] = defaultdict(list)
    last_job: dict[str, dict[str, Any]] = {}
    scopes = {x["file_id"]: x for x in manifest["files"]}
    limitations: list[str] = []
    top_limit = rules["job"]["max_evidence_per_job"]
    for event in _iter_events(events_path):
        kind = event.get("event_type")
        details = event.get("details") or {}
        file_id = event.get("file_id")
        if file_id not in scopes:
            raise ValueError("파일 ID와 manifest가 일치하지 않습니다.")
        if kind == "job_run":
            job = details.get("job_name")
            if not job or not isinstance(job, str):
                continue
            if _dt(event) and (job not in last_job or _dt(event) > _dt(last_job[job])):
                last_job[job] = event
            if event.get("status") != "complete" or not details.get("completed"):
                continue
            duration = details.get("duration_seconds")
            if not isinstance(duration, (int, float)) or not 0 <= duration <= 1e9:
                continue
            group = job_groups.setdefault(job, {"count": 0, "sum": 0.0,
                "max": 0.0, "values": [], "by_bucket": defaultdict(list), "slow": [],
                "slow_count": 0, "max_steps": defaultdict(float), "transport_count": 0,
                "transport_slow": []})
            group["count"] += 1
            group["sum"] += duration
            group["max"] = max(group["max"], duration)
            if len(group["values"]) < rules["job"]["max_percentile_samples"]:
                group["values"].append(duration)
                bucket = _job_bucket(details.get("target_count"))
                group["by_bucket"][bucket].append(duration)
            for step, seconds in details.get("steps_seconds", {}).items():
                if step in {"socket", "http_in", "http_out", "db", "select", "file"} and isinstance(seconds, (int,float)):
                    group["max_steps"][step] = max(group["max_steps"][step], seconds)
            transport_steps = [v for k, v in details.get("steps_seconds", {}).items()
                               if k in {"socket", "http_in", "http_out"} and isinstance(v, (int, float))]
            if transport_steps and max(transport_steps) >= rules["transport"]["step_seconds"]:
                group["transport_count"] += 1
                _top_append(group["transport_slow"], max(transport_steps), event, top_limit)
            threshold = rules["job"]["absolute_seconds_by_job"].get(
                job, rules["job"]["absolute_default_seconds"]
            )
            if duration >= threshold:
                group["slow_count"] += 1
                _top_append(group["slow"], float(duration), event, top_limit)
        elif kind == "sql_execution":
            stmt = details.get("statement_kind", "UNKNOWN")
            group = sql_groups.setdefault(stmt, {"count": 0, "sum": 0.0, "max": 0.0, "values": [],
                                                  "slow": [], "slow_count": 0})
            ms = details.get("laptime_ms")
            if isinstance(ms, (int, float)) and 0 <= ms <= 1e10:
                group["count"] += 1
                group["sum"] += ms
                group["max"] = max(group["max"], ms)
                if len(group["values"]) < rules["sql"]["max_percentile_samples"]:
                    group["values"].append(ms)
                if ms >= rules["sql"]["absolute_ms"]:
                    group["slow_count"] += 1
                    _top_append(group["slow"], float(ms), event, rules["sql"]["max_evidence"])
            if details.get("outcome") == "failed":
                explicit_count["SQL_ERROR"] += 1
                if len(explicit["SQL_ERROR"]) < rules["findings"]["max_evidence_refs"]:
                    explicit["SQL_ERROR"].append(event)
        elif kind in ("healthcheck_result", "healthcheck_request"):
            maximum = rules["healthcheck"]["max_stored_events_per_kind"]
            bucket = health[file_id].setdefault(kind, deque(maxlen=maximum))
            if len(bucket) >= maximum:
                health_skipped[file_id] += 1
            bucket.append(event)
        elif kind == "job_running_skip":
            job = details.get("job_name")
            if job:
                key = (file_id, job)
                bucket = running.setdefault(key, deque(maxlen=rules["running"]["max_stored_events"]))
                running_count[key] += 1
                if len(bucket) >= rules["running"]["max_stored_events"]:
                    running_skipped[file_id] += 1
                bucket.append(event)
        elif kind == "log_error":
            exc = details.get("exception_class")
            if exc in SQL_EXCEPTIONS:
                signal = "SQL_ERROR"
            elif exc in TRANSPORT_EXCEPTIONS:
                signal = "TRANSPORT_ERROR"
            else:
                signal = "GENERAL_EXCEPTION"  # explicit error record, cause unclassified
            explicit_count[signal] += 1
            if len(explicit[signal]) < rules["findings"]["max_evidence_refs"]:
                explicit[signal].append(event)
        elif kind in ("agent_exit", "agent_started"):
            if len(lifecycle[kind]) < rules["findings"]["max_evidence_refs"]:
                lifecycle[kind].append(event)

    findings: list[dict[str, Any]] = []
    job_stats: dict[str, Any] = {}
    for job, group in sorted(job_groups.items()):
        s = _stats(group["values"], group["count"], group["sum"])
        s.update({"max_seconds": round(group["max"], 6), "slow_above_absolute": group["slow_count"],
                  "max_steps_seconds": dict(sorted(group["max_steps"].items()))})
        job_stats[job] = s
        raw_threshold = rules["job"]["absolute_seconds_by_job"].get(job, rules["job"]["absolute_default_seconds"])
        qualified: list[dict[str, Any]] = []
        for seconds, e in group["slow"]:
            bucket = _job_bucket(e["details"].get("target_count"))
            same_bucket = group["by_bucket"].get(bucket, [])
            if len(same_bucket) >= rules["job"]["baseline_min_samples"]:
                cutoff = max(raw_threshold, median(same_bucket) * rules["job"]["median_multiplier"])
            else:
                cutoff = raw_threshold
            if seconds >= cutoff:
                qualified.append(e)
        if qualified:
            source = sorted(qualified, key=lambda e: -e["details"]["duration_seconds"])[0]
            signal = ("SEND_JOB_DELAY" if job.startswith("SEND_") else
                "RESULT_JOB_DELAY" if job == "HA_RECEIVE_RESULT" else "OTHER_JOB_DELAY")
            duration = source["details"]["duration_seconds"]
            steps = source["details"].get("steps_seconds") or {}
            prominent = sorted(
                [(name, value) for name, value in steps.items()
                 if name in {"socket", "http_in", "http_out", "db", "select", "file"} and isinstance(value, (int,float))],
                key=lambda x: -x[1]
            )[:2]
            stage = ", ".join(f"{k.upper()} {v:.3f}초" for k, v in prominent)
            note = f"; 단계별 기록: {stage}" if stage else ""
            findings.append(_finding(signal, "JOB_DURATION", f"{job} 처리 지연",
                f"완료 Job에서 최대 {duration:.3f}초가 기록되었습니다{note}. 해당 단계의 세부 원인은 로그만으로 확정되지 않습니다.",
                qualified, confidence="high" if group["count"] >= rules["job"]["baseline_min_samples"] else "medium",
                measure={"job_name": job, "max_seconds": duration, "observed_count": group["count"],
                         "above_absolute_count": group["slow_count"], "threshold_seconds":raw_threshold}))

        if group["transport_slow"]:
            longest = group["transport_slow"][0][0]
            findings.append(_finding("TRANSPORT_DELAY", "TRANSPORT_STEP",
                f"{job} 통신 단계 처리시간 증가",
                f"SOCKET/HTTP 단계에 최대 {longest:.3f}초가 기록되었습니다. 해당 단계에 DB 상태 변경 등 "
                "후속 처리가 포함될 수 있으므로 실제 네트워크 지연이나 통신 장애로 단정하지 않습니다.",
                [x[1] for x in group["transport_slow"]],
                measure={"job_name": job, "max_stage_seconds": longest,
                         "above_threshold_count": group["transport_count"],
                         "threshold_seconds": rules["transport"]["step_seconds"]}))

    sql_stats: dict[str, Any] = {}
    for stmt, group in sorted(sql_groups.items()):
        s = _stats(group["values"], group["count"], group["sum"])
        s.update({"max_ms": round(group["max"], 6), "slow_above_absolute": group["slow_count"]})
        sql_stats[stmt] = s
        if group["slow"]:
            highest = group["slow"][0][0]
            findings.append(_finding("DB_SQL_DELAY", "SQL_DURATION",
                f"DB {stmt} 처리시간 증가",
                f"{stmt} 실행 구간에서 최대 {highest:.0f}ms가 기록되었습니다. SQL 처리 지연이 관측되었지만 Lock이나 DB 자원 문제는 확인되지 않았습니다.",
                [x[1] for x in group["slow"]],
                measure={"statement_kind": stmt, "max_laptime_ms": highest,
                         "above_threshold_count": group["slow_count"],
                         "threshold_ms": rules["sql"]["absolute_ms"]}))
    for signal, events in sorted(explicit.items()):
        findings.append(_finding(signal, "EXPLICIT_ERROR", "명시적인 오류 기록",
            f"로그에서 {signal} 유형의 오류 기록 {explicit_count[signal]}건이 확인되었습니다. 오류 메시지의 상세 내용은 원본 줄에서 확인해야 합니다.",
            events, statement="observed", severity="warning", confidence="high",
            measure={"count": explicit_count[signal]}))
    for k, sig, title in (
        ("agent_exit", "AGENT_EXIT_SEEN", "Agent 종료 로그 관측"),
        ("agent_started", "AGENT_START_SEEN", "Agent 시작 로그 관측"),
    ):
        if lifecycle[k]:
            findings.append(_finding(sig, "LIFECYCLE", title,
                f"{title} 기록이 존재합니다. 종료 원인이나 장애 여부는 해당 기록만으로 확정할 수 없습니다.",
                lifecycle[k], statement="observed", severity="info", confidence="high"))

    running_stats: dict[str, int] = {}
    for (file_id, job), events in sorted(running.items()):
        running_stats[job] = running_stats.get(job, 0) + running_count[(file_id, job)]
        # Distinct sorted dated observations are required for a temporal recurrence alert.
        dates = [(t, e) for e in events if (t := _dt(e)) is not None]
        dates.sort(key=lambda item: item[0])
        span = deque()
        qualifying: list[dict[str, Any]] | None = None
        for t, e in dates:
            span.append((t, e))
            while span and (t - span[0][0]).total_seconds() > rules["running"]["window_seconds"]:
                span.popleft()
            if len(span) >= rules["running"]["min_occurrences"]:
                qualifying = [x[1] for x in span]
                break
        if qualifying:
            findings.append(_finding("JOB_RUNNING_STATE", "REPEATED_JOB_SKIP",
                f"{job} 중복 실행 건너뛰기 반복",
                f"동일 Job이 {rules['running']['window_seconds']}초 이내 "
                f"{len(qualifying)}회 이상 RUNNING 상태로 실행을 건너뛴 기록이 있습니다. "
                "선행 Job 정체가 지속됐는지 별도 확인이 필요합니다.",
                qualifying[:rules["findings"]["max_evidence_refs"]],
                measure={"job_name": job, "observed_count": running_count[(file_id, job)],
                         "window_seconds": rules["running"]["window_seconds"]}))

    for file_id, dropped in sorted(running_skipped.items()):
        limitations.append(f"{file_id}: RUNNING 상태 반복 기록 {dropped}건은 표본 상한 때문에 직접 비교되지 않았습니다.")
    for file_id, dropped in sorted(health_skipped.items()):
        limitations.append(f"{file_id}: 헬스체크 과거 기록 {dropped}건은 표본 상한 때문에 간격 비교에서 제외됐습니다.")
    health_stats: dict[str, Any] = {}
    health_tail_candidates: list[tuple[datetime, dict[str, Any], float]] = []
    for file_id, categories in sorted(health.items()):
        selected = categories.get("healthcheck_result", [])
        if len(selected) < rules["healthcheck"]["min_intervals"] + 1:
            selected = categories.get("healthcheck_request", [])
        dated = sorted(((t,e) for e in selected if (t := _dt(e))), key=lambda it: it[0])
        intervals = []
        for prev, current in zip(dated, dated[1:]):
            seconds = (current[0] - prev[0]).total_seconds()
            if seconds > 0:
                intervals.append(seconds)
        valid = sorted([x for x in intervals if x <= rules["healthcheck"]["max_estimated_interval_seconds"]])
        baseline = (median(valid[:max(1, ceil(len(valid)/2))])
                    if len(valid) >= rules["healthcheck"]["min_intervals"] else None)
        gaps = []
        if baseline is not None:
            threshold = max(rules["healthcheck"]["min_gap_seconds"],
                            baseline * rules["healthcheck"]["multiplier"])
            for first, second in zip(dated, dated[1:]):
                gap = (second[0] - first[0]).total_seconds()
                if gap >= threshold:
                    gaps.append((gap, first[1], second[1]))
        health_stats[file_id] = {
            "healthcheck_samples": len(selected), "anchored_samples": len(dated),
            "estimated_interval_seconds": baseline,
            "long_gaps_detected": len(gaps),
            "largest_observed_gap_seconds": max(intervals, default=None),
        }
        if gaps:
            worst = sorted(gaps, key=lambda x:-x[0])[:rules["findings"]["max_evidence_refs"] // 2 or 1]
            ev = []
            for _, before, after in worst:
                ev.extend([before, after])
            findings.append(_finding("HEALTHCHECK_GAP", "HEALTHCHECK_INTERVAL",
                "헬스체크 기록 간격 증가",
                f"동일 로그에서 평소 약 {baseline:g}초 간격과 비교하여 "
                f"최대 {max(x[0] for x in gaps):g}초의 기록 공백이 관측됩니다. "
                "프로세스 종료나 스케줄러 정체의 원인은 이 기록만으로 판단할 수 없습니다.",
                ev, confidence="high" if len(dated) >= 6 else "medium",
                measure={"baseline_seconds": baseline,
                         "max_gap_seconds": max(x[0] for x in gaps),
                         "gap_count": len(gaps)}))
        if dated and baseline is not None:
            health_tail_candidates.append((dated[-1][0], dated[-1][1], baseline))

    tail_gap_signal = None
    debug_sources = [entry for entry in manifest["files"] if entry["kind"] == "debug"]
    log_sources = [entry for entry in manifest["files"] if entry["kind"] == "job"]
    complete_debug = bool(debug_sources) and all(e["completeness"] == "full" for e in debug_sources)
    if not complete_debug:
        limitations.append("debug 로그 일부 추출 또는 완전성 미확인으로 마지막 헬스체크 이후 공백을 판정하지 않았습니다.")
    if manifest.get("collected_at") and complete_debug and health_tail_candidates:
        try:
            collected = datetime.fromisoformat(manifest["collected_at"])
        except (TypeError, ValueError):
            collected = None
        if collected is not None and collected.tzinfo is not None:
            last_dt, last_e, baseline = max(health_tail_candidates, key=lambda x: x[0])
            delta = (collected - last_dt).total_seconds()
            cutoff = max(rules["healthcheck"]["tail_min_gap_seconds"],
                         baseline * rules["healthcheck"]["multiplier"])
            if cutoff <= delta <= 14 * 86400:
                tail_gap_signal = (delta, last_e, collected)
                findings.append(_finding("HEALTHCHECK_GAP", "HEALTHCHECK_TAIL",
                    "마지막 헬스체크 이후 기록 공백",
                    f"마지막 헬스체크 기록 이후 사용자가 입력한 로그 수집 시각까지 "
                    f"{delta:.0f}초의 공백이 있습니다. 정상 종료·정지 여부는 로그에서 확인되지 않습니다.",
                    [last_e], confidence="medium", measure={
                        "tail_gap_seconds": delta, "estimated_interval_seconds": baseline,
                        "time_basis": "user_supplied_collection_time",
                        "collected_at": manifest["collected_at"]}))
                if log_sources and all(s["completeness"] == "full" for s in log_sources):
                    latest_job = max(last_job.values(), key=lambda e: _dt(e)) if last_job else None
                    if latest_job and _dt(latest_job) is not None:
                        job_delta = (collected - _dt(latest_job)).total_seconds()
                        if job_delta >= cutoff and job_delta <= 14 * 86400:
                            findings.append(_finding("PERIODIC_JOB_GAP", "MULTI_LOG_TAIL",
                                "헬스체크 및 Job 기록 공백",
                                "헬스체크와 Job 로그 모두 수집 시각 전부터 기록이 없습니다. "
                                "단, Job 로그는 처리대상 유무에 따라 생성되지 않을 수 있으므로 "
                                "Agent의 실행 중단으로 단정하지 않습니다.",
                                [last_e, latest_job], confidence="low",
                                measure={"healthcheck_tail_seconds": delta,
                                         "job_tail_seconds": job_delta,
                                         "time_basis": "user_supplied_collection_time",
                        "collected_at": manifest["collected_at"]}))
    if not health_tail_candidates and debug_sources:
        limitations.append("헬스체크 반복 주기 표본이 부족하거나 날짜가 없어 수집 시각과 비교하지 않았습니다.")

    supplemental_metrics = {
        "anomaly_engine_version": "1.0",
        "job_duration_statistics": job_stats,
        "db_duration_statistics": sql_stats,
        "running_state_skips": dict(sorted(running_stats.items())),
        "healthcheck_statistics": health_stats,
        "explicit_errors_count": dict(sorted(explicit_count.items())),
        "rules_version": rules["schema_version"],
    }
    # Sorting and cap are deterministic. Explicit errors are ranked above slow calls.
    severity_rank = {"warning": 0, "info": 1}
    findings.sort(key=lambda f: (
        severity_rank.get(f["severity"], 2), f["signal_code"],
        f["evidence_refs"][0]["file_id"] if f["evidence_refs"] else "",
        f["evidence_refs"][0]["line_start"] if f["evidence_refs"] else 0,
        f["rule_id"]
    ))
    findings = findings[:rules["findings"]["max_total"]]
    for i, f in enumerate(findings, start=1):
        f["finding_id"] = f"F-{i:04d}"
        f["evidence_refs"] = f["evidence_refs"][:rules["findings"]["max_evidence_refs"]]
    return supplemental_metrics, findings, limitations
