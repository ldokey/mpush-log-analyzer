"""No raw customer data in project metadata, reports, or accepted case JSON."""
from __future__ import annotations

import re

# Patterns are intentionally conservative; validation cannot replace human review.
PRIVATE_PATTERNS = {
    "secret_field": re.compile(
        r"(?i)(?:\bpassword\b|\bpasswd\b|\bsecret\b|\bapi[_-]?key\b|"
        r"\bclientplainkey\b|\bclientenckey\b|\baccess[_-]?token\b|\bauthorization\b)"
        r"\s*[\"']?\s*[:=]\s*"
    ),
    "mobile_number": re.compile(r"(?<!\d)01[016789][\s-]?\d{3,4}[\s-]?\d{4}(?!\d)"),
    "email": re.compile(r"(?i)\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b"),
    "ipv4": re.compile(r"(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?!\d)"),
    "jdbc_url": re.compile(r"(?i)\bjdbc:[a-z]+:"),
    "bearer_token": re.compile(r"(?i)\bbearer\s+[a-z0-9._~+/-]{10,}"),
}


def detect_sensitive_patterns(text: str) -> list[str]:
    """Return pattern names only. Never return matched input."""
    return [name for name, pattern in PRIVATE_PATTERNS.items() if pattern.search(text)]


def display_filename(name: str) -> str:
    """File name is used for ephemeral local UI only, never for output paths."""
    return name.replace("\\", "/").rsplit("/", 1)[-1][:180]


def validated_key_name(key: str) -> str | None:
    clean = key.strip().upper()
    if re.fullmatch(r"[A-Z][A-Z0-9_]{0,63}", clean):
        return clean
    return None
