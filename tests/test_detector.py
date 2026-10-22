"""
Unit tests for change detection and classification (fim.detector).
"""

from pathlib import Path
import pytest

from fim.detector import detect_changes
from fim.models import Baseline, ChangeEntry, FileRecord, FileStatus, ScanResult

HASH_A = "aaaa1111222233334444555566667777888899990000aaaabbbbccccddddeeee"
HASH_B = "bbbb1111222233334444555566667777888899990000aaaabbbbccccddddeeee"
HASH_C = "cccc1111222233334444555566667777888899990000aaaabbbbccccddddeeee"


def make_baseline(files_dict: dict) -> Baseline:
    """Helper to build a Baseline model with FileRecords."""
    records = {
        path: FileRecord(path, h, 100, "2026-10-22T00:00:00Z")
        for path, h in files_dict.items()
    }
    return Baseline(
        schema_version="1.0.0",
        created_at_utc="2026-10-22T00:00:00Z",
        monitored_root_name="test_root",
        total_files=len(records),
        files=records,
    )


def make_scan_result(records_dict: dict, errors: list = None, is_complete: bool = True) -> ScanResult:
    """Helper to build a ScanResult model with FileRecords."""
    records = {
        path: FileRecord(path, h, 100, "2026-10-22T01:00:00Z")
        for path, h in records_dict.items()
    }
    return ScanResult(
        target_path="/test/monitored",
        records=records,
        errors=errors or [],
        is_complete=is_complete,
    )


def test_detect_all_unchanged():
    """Identical files in baseline and scan must be classified as UNCHANGED."""
    baseline = make_baseline({"app.py": HASH_A, "config.json": HASH_B})
    scan = make_scan_result({"app.py": HASH_A, "config.json": HASH_B})

    report = detect_changes(baseline, scan)

    assert report.is_complete is True
    assert report.summary["unchanged"] == 2
    assert report.summary["modified"] == 0
    assert report.summary["added"] == 0
    assert report.summary["deleted"] == 0
    assert report.summary["errors"] == 0

    assert len(report.changes) == 2
    assert all(c.status == FileStatus.UNCHANGED for c in report.changes)


def test_detect_modified_file():
    """Hash discrepancy on the same path must be classified as MODIFIED."""
    baseline = make_baseline({"app.py": HASH_A})
    scan = make_scan_result({"app.py": HASH_B})

    report = detect_changes(baseline, scan)

    assert report.summary["modified"] == 1
    assert report.summary["unchanged"] == 0
    change = report.changes[0]
    assert change.path == "app.py"
    assert change.status == FileStatus.MODIFIED
    assert change.baseline_sha256 == HASH_A
    assert change.current_sha256 == HASH_B


def test_detect_added_file():
    """File present in scan but absent in baseline must be classified as ADDED."""
    baseline = make_baseline({"app.py": HASH_A})
    scan = make_scan_result({"app.py": HASH_A, "backdoor.php": HASH_C})

    report = detect_changes(baseline, scan)

    assert report.summary["added"] == 1
    added_entry = [c for c in report.changes if c.path == "backdoor.php"][0]
    assert added_entry.status == FileStatus.ADDED
    assert added_entry.baseline_sha256 is None
    assert added_entry.current_sha256 == HASH_C


def test_detect_deleted_file():
    """File present in baseline but missing from clean scan must be classified as DELETED."""
    baseline = make_baseline({"app.py": HASH_A, "legacy.py": HASH_B})
    scan = make_scan_result({"app.py": HASH_A})

    report = detect_changes(baseline, scan)

    assert report.summary["deleted"] == 1
    del_entry = [c for c in report.changes if c.path == "legacy.py"][0]
    assert del_entry.status == FileStatus.DELETED
    assert del_entry.baseline_sha256 == HASH_B
    assert del_entry.current_sha256 is None


def test_unreadable_file_never_classified_as_deleted():
    """Crucial security test: an unreadable file must be classified as ERROR, NEVER DELETED."""
    baseline = make_baseline({"app.py": HASH_A, "secret.key": HASH_B})
    # secret.key could not be read during scan
    scan = make_scan_result(
        {"app.py": HASH_A},
        errors=[{"path": "secret.key", "error_type": "PermissionError", "message": "Access denied"}],
        is_complete=False,
    )

    report = detect_changes(baseline, scan)

    assert report.is_complete is False
    assert report.summary["deleted"] == 0  # MUST NOT BE REPORTED AS DELETED
    assert report.summary["errors"] == 1

    error_entries = [c for c in report.changes if c.path == "secret.key"]
    assert len(error_entries) == 1
    assert error_entries[0].status == FileStatus.ERROR
    assert "access denied" in error_entries[0].details.lower()


def test_parent_directory_error_protects_child_files():
    """If a directory failed during scan, its children must be marked ERROR, NOT DELETED."""
    baseline = make_baseline({
        "app.py": HASH_A,
        "protected_dir/file1.txt": HASH_B,
        "protected_dir/sub/file2.txt": HASH_C,
    })
    # protected_dir was unreadable
    scan = make_scan_result(
        {"app.py": HASH_A},
        errors=[{"path": "protected_dir", "error_type": "PermissionError", "message": "Directory locked"}],
        is_complete=False,
    )

    report = detect_changes(baseline, scan)

    assert report.summary["deleted"] == 0
    protected_entries = [c for c in report.changes if c.path.startswith("protected_dir/")]
    assert len(protected_entries) == 2
    for entry in protected_entries:
        assert entry.status == FileStatus.ERROR
        assert "parent directory" in entry.details.lower()


def test_deterministic_alphabetical_sorting():
    """All ChangeEntry items must be ordered alphabetically by path."""
    baseline = make_baseline({"z_file.txt": HASH_A, "a_file.txt": HASH_B, "m_file.txt": HASH_C})
    scan = make_scan_result({"z_file.txt": HASH_A, "a_file.txt": HASH_B, "m_file.txt": HASH_C})

    report = detect_changes(baseline, scan)
    paths = [c.path for c in report.changes]
    assert paths == ["a_file.txt", "m_file.txt", "z_file.txt"]
