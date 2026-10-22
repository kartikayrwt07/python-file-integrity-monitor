"""
Unit tests for baseline creation, validation, and persistence (fim.baseline).
"""

import json
from pathlib import Path
from unittest.mock import patch
import pytest

from fim.baseline import (
    create_baseline,
    load_baseline,
    save_baseline,
    validate_baseline_dict,
    BASELINE_SCHEMA_VERSION,
)
from fim.exceptions import (
    BaselineCorruptedError,
    BaselineExistsError,
    BaselineNotFoundError,
    ScanIncompleteError,
)
from fim.models import FileRecord, ScanResult

SAMPLE_HASH = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def create_sample_scan_result(target_path: Path, is_complete: bool = True) -> ScanResult:
    """Helper to produce a mock ScanResult."""
    records = {
        "app.py": FileRecord("app.py", SAMPLE_HASH, 120, "2026-10-22T12:00:00Z"),
        "config.json": FileRecord("config.json", SAMPLE_HASH, 45, "2026-10-22T12:05:00Z"),
    }
    errors = [] if is_complete else [{"path": "locked.dat", "error_type": "PermissionError", "message": "Denied"}]
    return ScanResult(
        target_path=str(target_path),
        records=records,
        errors=errors,
        is_complete=is_complete,
    )


def test_create_baseline_from_clean_scan(tmp_path: Path):
    """Creating a baseline from a clean scan populates all fields accurately."""
    scan = create_sample_scan_result(tmp_path, is_complete=True)
    baseline = create_baseline(scan, monitored_root_name="lab_root")

    assert baseline.schema_version == BASELINE_SCHEMA_VERSION
    assert baseline.monitored_root_name == "lab_root"
    assert baseline.total_files == 2
    assert "app.py" in baseline.files
    assert baseline.files["app.py"].sha256 == SAMPLE_HASH


def test_create_baseline_incomplete_scan_rejected(tmp_path: Path):
    """Attempting to initialize a baseline from an incomplete scan must raise ScanIncompleteError."""
    scan = create_sample_scan_result(tmp_path, is_complete=False)
    with pytest.raises(ScanIncompleteError) as exc_info:
        create_baseline(scan)

    assert "access/read error" in str(exc_info.value).lower()


def test_save_and_load_baseline_roundtrip(tmp_path: Path):
    """Saving and loading a baseline preserves exact schema and file entries."""
    scan = create_sample_scan_result(tmp_path, is_complete=True)
    baseline = create_baseline(scan)

    dest_file = tmp_path / "data" / "baseline.json"
    saved_path = save_baseline(baseline, dest_file)
    assert saved_path == dest_file
    assert dest_file.exists()

    loaded = load_baseline(dest_file)
    assert loaded.schema_version == baseline.schema_version
    assert loaded.monitored_root_name == baseline.monitored_root_name
    assert loaded.total_files == 2
    assert loaded.files["app.py"] == baseline.files["app.py"]


def test_save_baseline_overwrite_rejected_without_force(tmp_path: Path):
    """Saving over an existing baseline without force=True must raise BaselineExistsError."""
    scan = create_sample_scan_result(tmp_path, is_complete=True)
    baseline = create_baseline(scan)
    dest_file = tmp_path / "baseline.json"

    save_baseline(baseline, dest_file)
    assert dest_file.exists()

    with pytest.raises(BaselineExistsError) as exc_info:
        save_baseline(baseline, dest_file, force=False)
    assert "already exists" in str(exc_info.value).lower()


def test_save_baseline_overwrite_succeeds_with_force(tmp_path: Path):
    """Saving over an existing baseline with force=True successfully replaces the file."""
    scan = create_sample_scan_result(tmp_path, is_complete=True)
    baseline = create_baseline(scan, monitored_root_name="initial")
    dest_file = tmp_path / "baseline.json"

    save_baseline(baseline, dest_file)

    # Re-save with updated root name and force=True
    baseline_updated = create_baseline(scan, monitored_root_name="replaced")
    save_baseline(baseline_updated, dest_file, force=True)

    loaded = load_baseline(dest_file)
    assert loaded.monitored_root_name == "replaced"


def test_atomic_write_cleans_up_temp_file_on_error(tmp_path: Path):
    """If serialization fails mid-write, temp file is deleted and no corrupt file is left."""
    scan = create_sample_scan_result(tmp_path, is_complete=True)
    baseline = create_baseline(scan)
    dest_file = tmp_path / "baseline.json"

    # Simulate an error during json.dump
    with patch("json.dump", side_effect=OSError("Disk full simulation")):
        with pytest.raises(OSError):
            save_baseline(baseline, dest_file)

    assert not dest_file.exists()
    # Ensure no leftover *.tmp files exist in destination folder
    tmp_files = list(tmp_path.glob("*.tmp"))
    assert len(tmp_files) == 0


def test_load_baseline_missing_file_raises_not_found(tmp_path: Path):
    """Attempting to load a nonexistent baseline file must raise BaselineNotFoundError."""
    missing = tmp_path / "missing_baseline.json"
    with pytest.raises(BaselineNotFoundError):
        load_baseline(missing)


def test_load_baseline_directory_path_raises_corrupted(tmp_path: Path):
    """Passing a directory instead of a file must raise BaselineCorruptedError."""
    with pytest.raises(BaselineCorruptedError):
        load_baseline(tmp_path)


def test_load_baseline_malformed_json_raises_corrupted(tmp_path: Path):
    """Corrupted/truncated JSON must raise BaselineCorruptedError."""
    corrupt_file = tmp_path / "bad.json"
    corrupt_file.write_text("{\nincomplete json ...", encoding="utf-8")

    with pytest.raises(BaselineCorruptedError) as exc_info:
        load_baseline(corrupt_file)
    assert "malformed json" in str(exc_info.value).lower()


def test_validate_baseline_missing_keys():
    """Missing required top-level keys must raise BaselineCorruptedError."""
    bad_data = {"schema_version": "1.0.0", "files": {}}
    with pytest.raises(BaselineCorruptedError) as exc_info:
        validate_baseline_dict(bad_data)
    assert "missing required top-level keys" in str(exc_info.value).lower()


def test_validate_baseline_unsupported_version():
    """Unsupported schema version must raise BaselineCorruptedError."""
    bad_data = {
        "schema_version": "99.0.0",
        "created_at_utc": "2026-10-22T00:00:00Z",
        "monitored_root_name": "test",
        "hash_algorithm": "sha256",
        "total_files": 0,
        "files": {},
    }
    with pytest.raises(BaselineCorruptedError) as exc_info:
        validate_baseline_dict(bad_data)
    assert "unsupported baseline schema version" in str(exc_info.value).lower()


def test_validate_baseline_invalid_sha256_digest():
    """Non-64 character or non-hex string in sha256 must raise BaselineCorruptedError."""
    bad_data = {
        "schema_version": "1.0.0",
        "created_at_utc": "2026-10-22T00:00:00Z",
        "monitored_root_name": "test",
        "hash_algorithm": "sha256",
        "total_files": 1,
        "files": {
            "app.py": {
                "sha256": "not_a_valid_64_char_hex_digest",
                "size_bytes": 100,
                "modified_time_utc": "2026-10-22T00:00:00Z",
            }
        },
    }
    with pytest.raises(BaselineCorruptedError) as exc_info:
        validate_baseline_dict(bad_data)
    assert "invalid sha-256 digest" in str(exc_info.value).lower()
