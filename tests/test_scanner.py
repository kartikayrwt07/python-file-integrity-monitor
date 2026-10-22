"""
Unit tests for recursive directory scanner (fim.scanner).
"""

from pathlib import Path
from unittest.mock import patch
import pytest

from fim.exceptions import FIMError, HashingError
from fim.hashing import hash_bytes
from fim.scanner import scan_directory


def test_scan_empty_directory(tmp_path: Path):
    """An empty directory should return an empty records dict and complete status."""
    result = scan_directory(tmp_path)
    assert result.records == {}
    assert result.errors == []
    assert result.is_complete is True


def test_scan_single_file(tmp_path: Path):
    """Scanning a single file records relative path, size, and matching SHA-256."""
    payload = b"Sample configuration content."
    test_file = tmp_path / "config.ini"
    test_file.write_bytes(payload)

    result = scan_directory(tmp_path)
    assert "config.ini" in result.records
    assert result.records["config.ini"].size_bytes == len(payload)
    assert result.records["config.ini"].sha256 == hash_bytes(payload)
    assert result.is_complete is True
    assert result.errors == []


def test_scan_nested_directories_posix_paths(tmp_path: Path):
    """Files in nested subdirectories must use POSIX forward-slash relative paths."""
    nested_dir = tmp_path / "level1" / "level2" / "level3"
    nested_dir.mkdir(parents=True)
    deep_file = nested_dir / "target.log"
    deep_file.write_text("Audit line 1\n", encoding="utf-8")

    result = scan_directory(tmp_path)
    assert "level1/level2/level3/target.log" in result.records
    record = result.records["level1/level2/level3/target.log"]
    assert record.path == "level1/level2/level3/target.log"
    assert "\\" not in record.path


def test_scan_nonexistent_directory(tmp_path: Path):
    """Target directory that does not exist must raise FIMError."""
    missing = tmp_path / "nonexistent_dir"
    with pytest.raises(FIMError) as exc_info:
        scan_directory(missing)
    assert "does not exist" in str(exc_info.value).lower()


def test_scan_target_is_file_raises_error(tmp_path: Path):
    """Target that is a file rather than a directory must raise FIMError."""
    plain_file = tmp_path / "not_a_dir.txt"
    plain_file.write_text("Hello", encoding="utf-8")

    with pytest.raises(FIMError) as exc_info:
        scan_directory(plain_file)
    assert "not a directory" in str(exc_info.value).lower()


def test_scan_excludes_specified_paths(tmp_path: Path):
    """Self-monitoring exclusion: baseline and report paths within target must be skipped."""
    file_a = tmp_path / "legit.txt"
    file_a.write_text("Legit file", encoding="utf-8")

    baseline_file = tmp_path / "baseline.json"
    baseline_file.write_text("{}", encoding="utf-8")

    reports_dir = tmp_path / "reports"
    reports_dir.mkdir()
    report_file = reports_dir / "scan.json"
    report_file.write_text("{}", encoding="utf-8")

    result = scan_directory(
        tmp_path,
        exclude_paths=[baseline_file, reports_dir]
    )

    assert "legit.txt" in result.records
    assert "baseline.json" not in result.records
    assert "reports/scan.json" not in result.records
    assert result.is_complete is True


def test_scan_skips_symlinks_by_default(tmp_path: Path):
    """Symbolic links should be skipped by default to avoid loops or escape."""
    target_file = tmp_path / "real.txt"
    target_file.write_text("real content", encoding="utf-8")

    symlink_file = tmp_path / "link_to_real.txt"
    try:
        symlink_file.symlink_to(target_file)
    except (OSError, NotImplementedError):
        pytest.skip("Symlink creation not permitted or supported on this system.")

    result = scan_directory(tmp_path, follow_symlinks=False)
    assert "real.txt" in result.records
    assert "link_to_real.txt" not in result.records


def test_scan_captures_unreadable_file_without_crashing(tmp_path: Path):
    """Unreadable files must be recorded as errors and mark the scan incomplete."""
    good_file = tmp_path / "good.txt"
    good_file.write_text("Accessible data", encoding="utf-8")

    bad_file = tmp_path / "locked.txt"
    bad_file.write_text("Locked data", encoding="utf-8")

    # Simulate HashingError (e.g. Permission denied / locked file)
    orig_hash_file = __import__("fim.scanner", fromlist=["hash_file"]).hash_file

    def mock_hash(filepath, chunk_size=None):
        if Path(filepath).name == "locked.txt":
            raise HashingError(str(filepath), "Simulated permission denied")
        return orig_hash_file(filepath, chunk_size=chunk_size) if chunk_size else orig_hash_file(filepath)

    with patch("fim.scanner.hash_file", side_effect=mock_hash):
        result = scan_directory(tmp_path)

    # Good file must be recorded
    assert "good.txt" in result.records
    # Bad file must NOT be in records, but recorded in errors
    assert "locked.txt" not in result.records
    assert len(result.errors) == 1
    assert result.errors[0]["path"] == "locked.txt"
    assert "simulated permission denied" in result.errors[0]["message"].lower()
    assert result.is_complete is False


def test_scan_repeated_consistency(tmp_path: Path):
    """Repeated scans of an unchanged directory must yield identical records."""
    (tmp_path / "a.txt").write_text("file A", encoding="utf-8")
    (tmp_path / "b.txt").write_text("file B", encoding="utf-8")

    result1 = scan_directory(tmp_path)
    result2 = scan_directory(tmp_path)

    assert result1.records.keys() == result2.records.keys()
    for k in result1.records:
        assert result1.records[k].sha256 == result2.records[k].sha256
        assert result1.records[k].size_bytes == result2.records[k].size_bytes
