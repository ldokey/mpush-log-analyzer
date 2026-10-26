from __future__ import annotations

from datetime import date
import json
import os
from pathlib import Path

import pytest

from mpush_analyzer.intake import Upload, inspect_uploads
from mpush_analyzer.storage import save_intake

SYNTHETIC_CONFIG = b"""[AGENT]
id=A1
type=test
[SERVICE]
service=9876543210
[DBMS]
type=mysql
url=jdbc:mysql://192.0.2.1:3306/db
password=TOP_SECRET_TEST_VALUE
"""


def test_manifest_is_private_and_contains_no_credentials(tmp_path: Path):
    a = inspect_uploads([
        Upload("20261015debug.log", b"10:13:27[000] RESPONSE_CODE=S\n", completeness="full"),
        Upload("agent.ini", SYNTHETIC_CONFIG)
    ])
    dirname, manifest = save_intake(
        a, tmp_path / "workspace", agent_version="3.2",
        reference_date=date(2026, 10, 15), collected_at="2026-10-15T15:20:00"
    )
    saved = json.loads((dirname / "manifest.json").read_text(encoding="utf-8"))
    assert saved == manifest
    assert saved["timezone"] == "Asia/Seoul"
    assert saved["collected_at"].endswith("+09:00")
    assert saved["files"][0]["storage_name"] == "debug_01.log"
    assert saved["files"][1]["storage_name"] == "agent_ini_01.ini"
    assert (dirname / "raw" / "agent_ini_01.ini").read_bytes() == SYNTHETIC_CONFIG
    serialized = json.dumps(manifest)
    for secret in ("TOP_SECRET_TEST_VALUE", "9876543210", "192.0.2.1", "jdbc:mysql"):
        assert secret not in serialized
    assert "20261015debug.log" not in serialized
    assert (dirname.stat().st_mode & 0o077) == 0
    assert ((dirname / "manifest.json").stat().st_mode & 0o077) == 0
    assert ((dirname / "raw" / "agent_ini_01.ini").stat().st_mode & 0o077) == 0


def test_save_deduplicates_same_content(tmp_path: Path):
    results = inspect_uploads([
        Upload("20261015job.log", b"JOB LOG\n"),
        Upload("20261015job_2.log", b"JOB LOG\n")
    ])
    d, manifest = save_intake(results, tmp_path / "workspace")
    assert len(manifest["files"]) == 1
    assert len(list((d / "raw").iterdir())) == 1
    assert any("중복" in x for x in manifest["warnings"])


def test_multiple_agent_ini_fail_closed(tmp_path: Path):
    results = inspect_uploads([
        Upload("agent.ini", SYNTHETIC_CONFIG),
        Upload("another.ini", SYNTHETIC_CONFIG + b"\n# unique\n", override_kind="agent_ini"),
    ])
    with pytest.raises(ValueError):
        save_intake(results, tmp_path / "workspace")
    assert not (tmp_path / "workspace").exists()


def test_symlink_workspace_refused(tmp_path: Path):
    real = tmp_path / "real"
    real.mkdir()
    (tmp_path / "alias").symlink_to(real, target_is_directory=True)
    with pytest.raises(ValueError):
        save_intake(inspect_uploads([Upload("job.log", b"test")]), tmp_path / "alias")


def test_unknown_file_stored_with_safe_name(tmp_path: Path):
    a = inspect_uploads([Upload("../../sensitive-label.txt", b"unclassified note\n")])
    d, manifest = save_intake(a, tmp_path / "workspace")
    assert manifest["files"][0]["storage_name"] == "unknown_01.txt"
    assert not (d / "raw" / "sensitive-label.txt").exists()
