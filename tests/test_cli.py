"""
Unit tests for command-line interface and exit code contracts (fim.cli).
"""

from pathlib import Path
import pytest

from fim.cli import (
    main,
    EXIT_SUCCESS,
    EXIT_INTEGRITY_VIOLATION,
    EXIT_OPERATIONAL_ERROR,
    EXIT_BASELINE_ERROR,
    EXIT_USAGE_ERROR,
)


def test_cli_no_arguments_returns_usage_error(capsys):
    """Invoking CLI with empty arguments should return exit code 4 (usage error)."""
    code = main([])
    assert code == EXIT_USAGE_ERROR


def test_cli_invalid_command_returns_usage_error():
    """Invoking an invalid subcommand returns exit code 4."""
    with pytest.raises(SystemExit) as exc_info:
        main(["unknown_verb"])
    assert exc_info.value.code == EXIT_USAGE_ERROR


def test_cli_init_success(tmp_path: Path, capsys):
    """Running 'init' on a valid directory creates baseline and exits with 0."""
    target_dir = tmp_path / "monitored"
    target_dir.mkdir()
    (target_dir / "file1.txt").write_text("Hello", encoding="utf-8")

    baseline_file = tmp_path / "data" / "baseline.json"

    code = main(["init", "--target", str(target_dir), "--baseline", str(baseline_file)])
    assert code == EXIT_SUCCESS
    assert baseline_file.exists()

    captured = capsys.readouterr()
    assert "[+] Baseline successfully initialized" in captured.out


def test_cli_init_overwrite_protection(tmp_path: Path, capsys):
    """Running 'init' over an existing baseline without --force returns exit code 3."""
    target_dir = tmp_path / "monitored"
    target_dir.mkdir()
    (target_dir / "file1.txt").write_text("Hello", encoding="utf-8")
    baseline_file = tmp_path / "baseline.json"

    # First init succeeds
    code1 = main(["init", "--target", str(target_dir), "--baseline", str(baseline_file)])
    assert code1 == EXIT_SUCCESS

    # Second init without --force fails with EXIT_BASELINE_ERROR (3)
    code2 = main(["init", "--target", str(target_dir), "--baseline", str(baseline_file)])
    assert code2 == EXIT_BASELINE_ERROR

    captured = capsys.readouterr()
    assert "already exists" in captured.err.lower()

    # Third init with --force succeeds with 0
    code3 = main(["init", "--target", str(target_dir), "--baseline", str(baseline_file), "--force"])
    assert code3 == EXIT_SUCCESS


def test_cli_init_nonexistent_target_returns_operational_error(tmp_path: Path, capsys):
    """Target directory that does not exist returns exit code 2."""
    missing_target = tmp_path / "not_found"
    baseline_file = tmp_path / "baseline.json"

    code = main(["init", "--target", str(missing_target), "--baseline", str(baseline_file)])
    assert code == EXIT_OPERATIONAL_ERROR


def test_cli_scan_clean_match_returns_zero(tmp_path: Path, capsys):
    """Scanning an unmodified directory against its baseline returns exit code 0."""
    target_dir = tmp_path / "monitored"
    target_dir.mkdir()
    (target_dir / "file.txt").write_text("Integrity data", encoding="utf-8")
    baseline_file = tmp_path / "baseline.json"

    # Init baseline
    assert main(["init", "--target", str(target_dir), "--baseline", str(baseline_file)]) == EXIT_SUCCESS

    # Scan unchanged
    code = main(["scan", "--target", str(target_dir), "--baseline", str(baseline_file), "--no-color"])
    assert code == EXIT_SUCCESS

    captured = capsys.readouterr()
    assert "VERDICT: INTEGRITY VERIFIED" in captured.out


def test_cli_scan_discrepancy_returns_one(tmp_path: Path, capsys):
    """Scanning a directory with modified or added files returns exit code 1."""
    target_dir = tmp_path / "monitored"
    target_dir.mkdir()
    file_path = target_dir / "file.txt"
    file_path.write_text("Original", encoding="utf-8")
    baseline_file = tmp_path / "baseline.json"

    # Init baseline
    assert main(["init", "--target", str(target_dir), "--baseline", str(baseline_file)]) == EXIT_SUCCESS

    # Modify file
    file_path.write_text("Tampered!", encoding="utf-8")

    code = main(["scan", "--target", str(target_dir), "--baseline", str(baseline_file), "--no-color"])
    assert code == EXIT_INTEGRITY_VIOLATION

    captured = capsys.readouterr()
    assert "[MODIFIED]" in captured.out
    assert "VERDICT: INTEGRITY COMPROMISED" in captured.out


def test_cli_scan_missing_baseline_returns_three(tmp_path: Path, capsys):
    """Scanning with a nonexistent baseline returns exit code 3."""
    target_dir = tmp_path / "monitored"
    target_dir.mkdir()
    missing_baseline = tmp_path / "missing.json"

    code = main(["scan", "--target", str(target_dir), "--baseline", str(missing_baseline)])
    assert code == EXIT_BASELINE_ERROR


def test_cli_scan_exports_report_file(tmp_path: Path):
    """Passing --report exports the JSON report artifact to disk."""
    target_dir = tmp_path / "monitored"
    target_dir.mkdir()
    (target_dir / "test.txt").write_text("data", encoding="utf-8")
    baseline_file = tmp_path / "baseline.json"
    report_file = tmp_path / "reports" / "scan_out.json"

    main(["init", "--target", str(target_dir), "--baseline", str(baseline_file)])
    code = main([
        "scan",
        "--target", str(target_dir),
        "--baseline", str(baseline_file),
        "--report", str(report_file),
        "--no-color",
    ])
    assert code == EXIT_SUCCESS
    assert report_file.exists()


def test_cli_verify_valid_baseline(tmp_path: Path, capsys):
    """Verifying a valid baseline prints details and returns exit code 0."""
    target_dir = tmp_path / "monitored"
    target_dir.mkdir()
    (target_dir / "f.txt").write_text("test", encoding="utf-8")
    baseline_file = tmp_path / "baseline.json"

    main(["init", "--target", str(target_dir), "--baseline", str(baseline_file)])
    code = main(["verify", "--baseline", str(baseline_file)])
    assert code == EXIT_SUCCESS

    captured = capsys.readouterr()
    assert "Baseline is valid and intact" in captured.out


def test_cli_verify_corrupt_baseline(tmp_path: Path, capsys):
    """Verifying a malformed baseline returns exit code 3."""
    bad_file = tmp_path / "bad.json"
    bad_file.write_text("{bad json", encoding="utf-8")

    code = main(["verify", "--baseline", str(bad_file)])
    assert code == EXIT_BASELINE_ERROR


def test_cli_report_subcommand(tmp_path: Path, capsys):
    """The 'report' subcommand displays an existing scan report and exits with 0."""
    target_dir = tmp_path / "monitored"
    target_dir.mkdir()
    (target_dir / "f.txt").write_text("test", encoding="utf-8")
    baseline_file = tmp_path / "baseline.json"
    report_file = tmp_path / "report.json"

    main(["init", "--target", str(target_dir), "--baseline", str(baseline_file)])
    main(["scan", "--target", str(target_dir), "--baseline", str(baseline_file), "--report", str(report_file)])

    code = main(["report", "--input", str(report_file), "--no-color"])
    assert code == EXIT_SUCCESS

    captured = capsys.readouterr()
    assert "FILE INTEGRITY MONITOR - SCAN REPORT" in captured.out
