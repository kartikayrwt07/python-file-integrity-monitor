"""
End-to-end integration tests simulating real-world attacker and operator scenarios.
"""

from pathlib import Path
import pytest

from fim.cli import (
    main,
    EXIT_SUCCESS,
    EXIT_INTEGRITY_VIOLATION,
)
from fim.reporter import load_json_report


def test_full_security_lifecycle_scenario(tmp_path: Path):
    """Simulates an entire real-world security lifecycle:
    1. System admin initializes baseline.
    2. Admin verifies baseline integrity.
    3. Routine audit: scan reports clean (exit code 0).
    4. Attacker modifies a script and uploads a web shell.
    5. Audit scan detects MODIFIED and ADDED files (exit code 1).
    6. Admin remediates by removing web shell and deleting compromised file.
    7. Audit scan detects DELETED file (exit code 1).
    8. Report artifact verified.
    """
    target = tmp_path / "production_app"
    target.mkdir()

    # Initial legitimate state
    main_py = target / "main.py"
    main_py.write_text("print('Secure Application v1.0')\n", encoding="utf-8")

    config_ini = target / "config.ini"
    config_ini.write_text("[database]\nhost=localhost\n", encoding="utf-8")

    baseline_json = tmp_path / "data" / "production_baseline.json"
    report_json = tmp_path / "reports" / "audit_report.json"

    # Step 1: Initialize baseline
    rc_init = main(["init", "--target", str(target), "--baseline", str(baseline_json)])
    assert rc_init == EXIT_SUCCESS
    assert baseline_json.exists()

    # Step 2: Verify baseline
    rc_verify = main(["verify", "--baseline", str(baseline_json)])
    assert rc_verify == EXIT_SUCCESS

    # Step 3: Routine audit on clean environment
    rc_clean_scan = main([
        "scan",
        "--target", str(target),
        "--baseline", str(baseline_json),
        "--report", str(report_json),
        "--no-color",
    ])
    assert rc_clean_scan == EXIT_SUCCESS

    clean_report = load_json_report(report_json)
    assert clean_report.summary["unchanged"] == 2
    assert clean_report.summary["modified"] == 0
    assert clean_report.summary["added"] == 0
    assert clean_report.summary["deleted"] == 0

    # Step 4: Attack simulation (Tampering main.py + injecting backdoor.py)
    main_py.write_text("print('Backdoored Application!')\n", encoding="utf-8")
    backdoor_py = target / "backdoor.py"
    backdoor_py.write_text("# Simulated unauthorized script insertion\n", encoding="utf-8")

    # Step 5: Audit detects breach
    rc_compromised_scan = main([
        "scan",
        "--target", str(target),
        "--baseline", str(baseline_json),
        "--report", str(report_json),
        "--no-color",
    ])
    assert rc_compromised_scan == EXIT_INTEGRITY_VIOLATION

    compromised_report = load_json_report(report_json)
    assert compromised_report.summary["modified"] == 1
    assert compromised_report.summary["added"] == 1
    assert compromised_report.summary["deleted"] == 0
    assert compromised_report.summary["unchanged"] == 1  # config.ini unchanged

    # Step 6: Incident cleanup (Removing backdoor and old config)
    backdoor_py.unlink()
    config_ini.unlink()

    # Step 7: Post-incident scan detects deletion
    rc_deleted_scan = main([
        "scan",
        "--target", str(target),
        "--baseline", str(baseline_json),
        "--report", str(report_json),
        "--no-color",
    ])
    assert rc_deleted_scan == EXIT_INTEGRITY_VIOLATION

    deleted_report = load_json_report(report_json)
    assert deleted_report.summary["deleted"] == 1
    assert deleted_report.summary["added"] == 0

    # Step 8: View exported report via CLI report command
    rc_report_view = main(["report", "--input", str(report_json), "--no-color"])
    assert rc_report_view == EXIT_SUCCESS
