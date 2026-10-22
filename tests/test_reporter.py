"""
Unit tests for reporting engine (fim.reporter).
"""

import json
import os
from pathlib import Path
import pytest

from fim.exceptions import FIMError
from fim.models import ChangeEntry, FileStatus, ScanReport
from fim.reporter import export_json_report, load_json_report, render_terminal_summary

HASH_A = "11111111222233334444555566667777888899990000aaaabbbbccccddddeeee"
HASH_B = "22221111222233334444555566667777888899990000aaaabbbbccccddddeeee"


def sample_report(is_complete: bool = True, has_changes: bool = False) -> ScanReport:
    """Helper to create a synthetic ScanReport."""
    if has_changes:
        changes = [
            ChangeEntry("app.py", FileStatus.MODIFIED, HASH_A, HASH_B, "Hash mismatch."),
            ChangeEntry("new.txt", FileStatus.ADDED, None, HASH_B, "New file."),
            ChangeEntry("old.txt", FileStatus.DELETED, HASH_A, None, "Missing."),
            ChangeEntry("clean.cfg", FileStatus.UNCHANGED, HASH_A, HASH_A, None),
        ]
        summary = {"total_monitored": 4, "unchanged": 1, "modified": 1, "added": 1, "deleted": 1, "errors": 0}
        errors = []
    elif not is_complete:
        changes = [
            ChangeEntry("app.py", FileStatus.UNCHANGED, HASH_A, HASH_A, None),
            ChangeEntry("locked.dat", FileStatus.ERROR, HASH_A, None, "Permission denied"),
        ]
        summary = {"total_monitored": 2, "unchanged": 1, "modified": 0, "added": 0, "deleted": 0, "errors": 1}
        errors = [{"path": "locked.dat", "error_type": "PermissionError", "message": "Permission denied"}]
    else:
        changes = [
            ChangeEntry("app.py", FileStatus.UNCHANGED, HASH_A, HASH_A, None),
            ChangeEntry("data.csv", FileStatus.UNCHANGED, HASH_B, HASH_B, None),
        ]
        summary = {"total_monitored": 2, "unchanged": 2, "modified": 0, "added": 0, "deleted": 0, "errors": 0}
        errors = []

    return ScanReport(
        schema_version="1.0.0",
        scan_timestamp_utc="2026-10-22T12:00:00Z",
        target_directory="/opt/app",
        baseline_file="/opt/data/baseline.json",
        is_complete=is_complete,
        summary=summary,
        changes=changes,
        errors=errors,
    )


def test_export_and_load_json_report(tmp_path: Path):
    """Saving and loading a ScanReport preserves all summary stats and changes."""
    report = sample_report(has_changes=True)
    report_file = tmp_path / "reports" / "scan.json"

    saved_path = export_json_report(report, report_file)
    assert saved_path == report_file
    assert report_file.exists()

    loaded = load_json_report(report_file)
    assert loaded.schema_version == report.schema_version
    assert loaded.target_directory == report.target_directory
    assert loaded.summary == report.summary
    assert len(loaded.changes) == len(report.changes)
    assert loaded.changes[0].status == FileStatus.MODIFIED


def test_load_json_report_missing_file_raises(tmp_path: Path):
    """Loading a nonexistent report file raises FIMError."""
    missing = tmp_path / "missing.json"
    with pytest.raises(FIMError) as exc_info:
        load_json_report(missing)
    assert "not found" in str(exc_info.value).lower()


def test_load_json_report_malformed_json(tmp_path: Path):
    """Malformed report JSON raises FIMError."""
    bad_file = tmp_path / "bad.json"
    bad_file.write_text("{\"incomplete...", encoding="utf-8")
    with pytest.raises(FIMError) as exc_info:
        load_json_report(bad_file)
    assert "malformed json" in str(exc_info.value).lower()


def test_render_terminal_summary_clean():
    """Clean scan report renders positive integrity verdict."""
    report = sample_report(is_complete=True, has_changes=False)
    output = render_terminal_summary(report, use_color=False)

    assert "FILE INTEGRITY MONITOR - SCAN REPORT" in output
    assert "Total Monitored : 2" in output
    assert "All monitored files match the baseline with zero discrepancies." in output
    assert "VERDICT: INTEGRITY VERIFIED" in output


def test_render_terminal_summary_discrepancies():
    """Scan with changes highlights modified, added, and deleted files with alert verdict."""
    report = sample_report(is_complete=True, has_changes=True)
    output = render_terminal_summary(report, use_color=False)

    assert "[MODIFIED]  app.py" in output
    assert "[ADDED]     new.txt" in output
    assert "[DELETED]   old.txt" in output
    assert "VERDICT: INTEGRITY COMPROMISED - DISCREPANCIES DETECTED" in output


def test_render_terminal_summary_incomplete_warning():
    """Incomplete scan displays warning banner and error details."""
    report = sample_report(is_complete=False, has_changes=False)
    output = render_terminal_summary(report, use_color=False)

    assert "Scan Status     : INCOMPLETE (ERRORS DETECTED)" in output
    assert "WARNING: Scan was incomplete" in output
    assert "[PermissionError] locked.dat: Permission denied" in output
    assert "VERDICT: OPERATIONAL ERROR / INCOMPLETE SCAN" in output


def test_render_terminal_summary_no_color_env(monkeypatch):
    """When NO_COLOR environment variable is present, ANSI codes must be stripped."""
    monkeypatch.setenv("NO_COLOR", "1")
    report = sample_report(has_changes=True)
    output = render_terminal_summary(report, use_color=True)

    assert "\033[" not in output
