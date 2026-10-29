from __future__ import annotations

import pytest

from mpush_analyzer.intake import (
    Upload, inspect_uploads, decode_upload, MAX_SINGLE_FILE,
    MAX_TOTAL_FILES_BYTES, MAX_FILE_COUNT, validate_upload_limits,
)


def test_classifies_all_six_types_and_time_hints():
    examples = [
        Upload("20261015debug.log", b"10:12:17[106] RESPONSE_CODE=S\n"),
        Upload("20261015job.log", "10:12:17[106] ##  SEND_REAL_FILE_IMAGE\n".encode()),
        Upload("20261015dbwrap.log", b"10:12:18[106] NO_ID=1 Laptime=400 SQL\n"),
        Upload("20261015info.log", b"04:30:01[723] Agent Exited................\n"),
        Upload("20261015err.log", b"10:13:00[010] Caused by: RuntimeException\n"),
        Upload("agent.ini", b"[AGENT]\nid=A1\n[DBMS]\ntype=mysql\n"),
    ]
    results = inspect_uploads(examples)
    assert [x.kind for x in results] == ["debug", "job", "dbwrap", "info", "err", "agent_ini"]
    assert results[0].date_hint == "2026-10-15"
    assert results[0].first_time_hint == "10:12:17.106"
    assert results[0].last_time_hint == "10:12:17.106"
    assert results[0].line_count == 1
    assert all(x.confidence == "high" for x in results)


def test_txt_content_detection_and_ambiguity():
    samples = [
        Upload("customer_fragment.txt", b"10:12:17[106] RESPONSE_CODE=S\n"),
        Upload("20261015job.log", b"10:12:17[106] RESPONSE_CODE=S\n"),
        Upload("unknown.txt", b"a plain text note\n"),
    ]
    results = inspect_uploads(samples)
    assert results[0].kind == "debug" and results[0].confidence == "medium"
    assert results[1].kind == "job" and results[1].confidence == "low"
    assert results[2].kind == "unknown" and results[2].warnings


def test_override_duplicate_and_partial():
    data = b"10:12:17[106] RESPONSE_CODE=S\n"
    results = inspect_uploads([
        Upload("one.txt", data, completeness="partial", override_kind="job"),
        Upload("same.txt", data),
    ])
    assert results[0].kind == "job"
    assert results[0].upload.completeness == "partial"
    assert results[1].duplicate_of == 1


def test_filename_never_trusted_as_path():
    x = inspect_uploads([Upload("../../20261015debug.log", b"test\n")])[0]
    assert x.label == "20261015debug.log"
    assert x.kind == "debug"


def test_cp949_and_broken_encoding():
    data = "헬스 체크 결과".encode("cp949")
    decoded, enc = decode_upload(data)
    assert "헬스" in decoded and enc == "cp949"
    bad_text, enc = decode_upload(b"\x81\xff")
    assert isinstance(bad_text, str)
    assert enc == "utf-8-replace"


@pytest.mark.parametrize("item", [
    Upload("file.zip", b"a"),
    Upload("file.log", b"\x00bad"),
])
def test_rejects_bad_inputs(item):
    with pytest.raises(ValueError):
        inspect_uploads([item])


def test_empty_and_invalid_configuration_metadata():
    with pytest.raises(ValueError):
        inspect_uploads([])
    with pytest.raises(ValueError):
        inspect_uploads([Upload("job.log", b"hello", completeness="wrong")])
    with pytest.raises(ValueError):
        inspect_uploads([Upload("job.log", b"hello", override_kind="tar")])


def test_dedup_does_not_confuse_different_content():
    arr = [
        Upload("20261015job.log", b"job 1\n"),
        Upload("20261016job.log", b"job 2\n"),
    ]
    a, b = inspect_uploads(arr)
    assert a.duplicate_of is None and b.duplicate_of is None
    assert a.sha256 != b.sha256


def test_large_dbwrap_capacity_boundaries_without_allocating_hundreds_of_megabytes():
    mib = 1024 * 1024
    assert MAX_SINGLE_FILE == 350 * mib
    assert MAX_TOTAL_FILES_BYTES == 600 * mib
    assert MAX_FILE_COUNT == 30
    # A 300MiB dbwrap.log plus 250MiB of companion logs must be accepted.
    validate_upload_limits([300 * mib, 250 * mib])
    validate_upload_limits([MAX_SINGLE_FILE])
    validate_upload_limits([MAX_TOTAL_FILES_BYTES // 2] * 2)

    with pytest.raises(ValueError, match="350MiB"):
        validate_upload_limits([MAX_SINGLE_FILE + 1])
    with pytest.raises(ValueError, match="600MiB"):
        validate_upload_limits([MAX_SINGLE_FILE, MAX_SINGLE_FILE])
    with pytest.raises(ValueError, match="30"):
        validate_upload_limits([1] * 31)
    with pytest.raises(ValueError, match="크기"):
        validate_upload_limits([-1])
    with pytest.raises(ValueError, match="개수"):
        validate_upload_limits([])


def test_intake_enforces_file_limit_before_inspection_or_hashing():
    class FakeHugeContent:
        """Size-only stub; any attempt to access file bytes is a test failure."""
        def __len__(self):
            return MAX_SINGLE_FILE + 1

        def __getitem__(self, _index):
            raise AssertionError("oversized files must be rejected before reading")

    with pytest.raises(ValueError, match="350MiB"):
        inspect_uploads([Upload("dbwrap.log", FakeHugeContent())])



def test_streamlit_file_size_setting_matches_backend():
    """Keep Streamlit's HTTP per-file cap synchronized with intake's byte cap."""
    from pathlib import Path
    import tomllib

    config = Path(__file__).resolve().parents[1] / ".streamlit/config.toml"
    parsed = tomllib.loads(config.read_text(encoding="utf-8"))
    assert parsed["server"]["maxUploadSize"] * 1024 * 1024 == MAX_SINGLE_FILE
