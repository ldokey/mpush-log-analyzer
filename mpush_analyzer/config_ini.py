"""Allowlist-only MPushAgent agent.ini parser.

Values never returned for credentials, hosts, JDBC URLs, services or arbitrary keys.
"""
from __future__ import annotations

import re
from typing import Any

from .security import validated_key_name

KNOWN_SECTIONS = {"AGENT", "SERVICE", "DBMS", "HA", "JOB_SELECT", "TEST", "REAL"}
RUN_TYPES = {"real", "test"}
DBMS_TYPES = {"mysql", "mariadb", "oracle", "db2", "mssql", "sqlserver", "postgresql"}
SAFE_DB_TIMINGS = {"connectiontimeout", "maxlifetime", "idletimeout"}
SAFE_HA_NUMERICS = {"timeout_sec"}


def parse_agent_ini(text: str) -> dict[str, Any]:
    sections: dict[str, dict[str, str]] = {}
    section: str | None = None
    malformed = 0
    duplicates = 0
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1].strip().upper()
            if not re.fullmatch(r"[A-Z][A-Z0-9_]{0,63}", section):
                section = None
                malformed += 1
            else:
                sections.setdefault(section, {})
            continue
        if "=" not in line or section is None:
            malformed += 1
            continue
        key, value = line.split("=", 1)
        key = key.strip().lower()
        if not re.fullmatch(r"[a-z][a-z0-9_]{0,63}", key):
            malformed += 1
            continue
        if key in sections[section]:
            duplicates += 1
        sections[section][key] = value.strip()

    agent = sections.get("AGENT", {})
    dbms = sections.get("DBMS", {})
    ha = sections.get("HA", {})
    run_type = agent.get("type", "").lower()
    dbms_type = dbms.get("type", "").lower()
    if run_type not in RUN_TYPES:
        run_type = "unknown"
    if dbms_type not in DBMS_TYPES:
        dbms_type = "unknown"

    def safe_nonnegative_int(value: str | None) -> int | None:
        if value is None or not re.fullmatch(r"\d{1,9}", value):
            return None
        return int(value)

    def safe_bool(value: str | None) -> bool | None:
        if value is None:
            return None
        normalized = value.strip().lower()
        if normalized in {"y", "yes", "true", "1", "on"}:
            return True
        if normalized in {"n", "no", "false", "0", "off"}:
            return False
        return None

    summary: dict[str, Any] = {
        "sections_present": sorted(set(sections) & KNOWN_SECTIONS),
        "agent": {
            "id_present": bool(agent.get("id")),
            "run_type": run_type,
        },
        "service": {"service_present": bool(sections.get("SERVICE", {}).get("service"))},
        "dbms": {"type": dbms_type, **{
            k: safe_nonnegative_int(dbms.get(k)) for k in sorted(SAFE_DB_TIMINGS)
        }},
        "ha": {
            **{k: safe_nonnegative_int(ha.get(k)) for k in sorted(SAFE_HA_NUMERICS)},
            "enabled": safe_bool(ha.get("use", ha.get("enabled"))),
        },
        "job_select": {
            "keys_present": sorted(
                cleaned for k in sections.get("JOB_SELECT", {})
                if (cleaned := validated_key_name(k)) is not None
            )
        },
        "target_endpoints": {
            s.lower(): {
                "tcp_host_configured": bool(sections.get(s, {}).get("tcp_server")),
                "tcp_port_configured": bool(sections.get(s, {}).get("tcp_port")),
                "http_port_configured": bool(sections.get(s, {}).get("port")),
            }
            for s in ("TEST", "REAL")
        },
        "warnings": [],
    }
    if "AGENT" not in sections or "DBMS" not in sections:
        summary["warnings"].append("필수 AGENT 또는 DBMS 섹션이 없습니다.")
    if malformed:
        summary["warnings"].append(f"해석할 수 없는 설정 행 {malformed}개")
    if duplicates:
        summary["warnings"].append(f"중복 설정 키 {duplicates}개")
    return summary
