"""
Reporting engine for File Integrity Monitor.

Renders human-readable terminal summaries and exports structured JSON reports
using atomic file persistence.
"""

import json
import os
from pathlib import Path
import tempfile
from typing import Optional, Union

from fim.exceptions import FIMError
from fim.models import ChangeEntry, FileStatus, ScanReport

# ANSI color escape codes for terminal formatting
COLOR_RESET = "\033[0m"
COLOR_RED = "\033[91m"
COLOR_GREEN = "\033[92m"
COLOR_YELLOW = "\033[93m"
COLOR_BLUE = "\033[94m"
COLOR_MAGENTA = "\033[95m"
COLOR_CYAN = "\033[96m"
COLOR_BOLD = "\033[1m"
COLOR_DIM = "\033[2m"


def _colorize(text: str, color_code: str, enabled: bool) -> str:
    """Helper to apply ANSI color codes if enabled."""
    if not enabled:
        return text
    return f"{color_code}{text}{COLOR_RESET}"


def export_json_report(
    report: ScanReport,
    destination_path: Union[str, Path],
) -> Path:
    """Save a ScanReport object to a JSON file using atomic file persistence.

    Args:
        report: The ScanReport object to serialize.
        destination_path: Path where the report should be saved.

    Returns:
        The resolved Path of the written report file.
    """
    dest = Path(destination_path).resolve()
    dest.parent.mkdir(parents=True, exist_ok=True)

    temp_file = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            dir=dest.parent,
            encoding="utf-8",
            delete=False,
            prefix="report_",
            suffix=".tmp",
        ) as tmp:
            temp_file = Path(tmp.name)
            json.dump(report.to_dict(), tmp, indent=2, sort_keys=True)
            tmp.flush()
            os.fsync(tmp.fileno())

        os.replace(temp_file, dest)
        return dest
    except Exception:
        if temp_file and temp_file.exists():
            try:
                temp_file.unlink()
            except OSError:
                pass
        raise


def load_json_report(source_path: Union[str, Path]) -> ScanReport:
    """Load and parse an existing ScanReport JSON file from disk.

    Args:
        source_path: Path to the JSON report file.

    Returns:
        A reconstructed ScanReport object.

    Raises:
        FIMError: If file is missing or contains invalid report data.
    """
    path = Path(source_path).resolve()

    if not path.exists():
        raise FIMError(f"Report file not found at '{path}'.")

    if path.is_dir():
        raise FIMError(f"Target report path '{path}' is a directory, not a file.")

    try:
        with path.open("r", encoding="utf-8") as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        raise FIMError(f"Report file '{path}' contains malformed JSON: {e}") from e
    except (OSError, UnicodeDecodeError) as e:
        raise FIMError(f"Could not read report file '{path}': {e}") from e

    try:
        changes = [
            ChangeEntry(
                path=c["path"],
                status=FileStatus(c["status"]),
                baseline_sha256=c.get("baseline_sha256"),
                current_sha256=c.get("current_sha256"),
                details=c.get("details"),
            )
            for c in data.get("changes", [])
        ]

        return ScanReport(
            schema_version=data["schema_version"],
            scan_timestamp_utc=data["scan_timestamp_utc"],
            target_directory=data["target_directory"],
            baseline_file=data["baseline_file"],
            is_complete=bool(data["is_complete"]),
            summary=dict(data["summary"]),
            changes=changes,
            errors=list(data.get("errors", [])),
        )
    except (KeyError, ValueError, TypeError) as e:
        raise FIMError(f"Report file '{path}' contains invalid schema structure: {e}") from e


def render_terminal_summary(
    report: ScanReport,
    show_unchanged: bool = False,
    use_color: bool = True,
) -> str:
    """Format a ScanReport into an informative terminal dashboard.

    Args:
        report: The ScanReport instance to format.
        show_unchanged: If True, include UNCHANGED files in the details list.
        use_color: If True, use ANSI color sequences for terminal highlighting.

    Returns:
        Formatted multi-line string ready for terminal display.
    """
    # Detect if NO_COLOR environment variable is set
    if "NO_COLOR" in os.environ:
        use_color = False

    lines = []
    divider = "=" * 72
    sub_divider = "-" * 72

    lines.append(divider)
    lines.append(
        _colorize(" FILE INTEGRITY MONITOR - SCAN REPORT", COLOR_BOLD, use_color)
    )
    lines.append(divider)
    lines.append(f" Timestamp (UTC) : {report.scan_timestamp_utc}")
    lines.append(f" Target Directory: {report.target_directory}")
    lines.append(f" Baseline File   : {report.baseline_file}")

    status_str = "COMPLETE" if report.is_complete else "INCOMPLETE (ERRORS DETECTED)"
    status_color = COLOR_GREEN if report.is_complete else COLOR_RED
    lines.append(f" Scan Status     : {_colorize(status_str, status_color, use_color)}")
    lines.append(sub_divider)

    # Summary Statistics Block
    lines.append(_colorize(" SUMMARY OF FINDINGS", COLOR_BOLD, use_color))
    sum_data = report.summary
    lines.append(
        f"  Total Monitored : {sum_data.get('total_monitored', 0):<4}  "
        f"|  Unchanged : {_colorize(str(sum_data.get('unchanged', 0)), COLOR_CYAN, use_color)}"
    )
    lines.append(
        f"  Modified        : {_colorize(str(sum_data.get('modified', 0)), COLOR_YELLOW if sum_data.get('modified', 0) else COLOR_DIM, use_color):<15}  "
        f"|  Added     : {_colorize(str(sum_data.get('added', 0)), COLOR_GREEN if sum_data.get('added', 0) else COLOR_DIM, use_color)}"
    )
    lines.append(
        f"  Deleted         : {_colorize(str(sum_data.get('deleted', 0)), COLOR_RED if sum_data.get('deleted', 0) else COLOR_DIM, use_color):<15}  "
        f"|  Errors    : {_colorize(str(sum_data.get('errors', 0)), COLOR_MAGENTA if sum_data.get('errors', 0) else COLOR_DIM, use_color)}"
    )
    lines.append(sub_divider)

    # Incomplete Scan Warning Banner
    if not report.is_complete:
        lines.append(
            _colorize(
                " [!] WARNING: Scan was incomplete due to file/directory access errors.",
                COLOR_YELLOW,
                use_color,
            )
        )
        lines.append("     Some missing files may not be verified or marked as DELETED.")
        lines.append(sub_divider)

    # File Changes Breakdown
    filtered_changes = [
        c for c in report.changes
        if show_unchanged or c.status != FileStatus.UNCHANGED
    ]

    if filtered_changes:
        lines.append(_colorize(" DETAILED FILE DISCREPANCIES", COLOR_BOLD, use_color))
        for change in filtered_changes:
            status = change.status
            if status == FileStatus.MODIFIED:
                badge = _colorize("[MODIFIED] ", COLOR_YELLOW, use_color)
                diff = f"(Baseline: {change.baseline_sha256[:10]}... -> Current: {change.current_sha256[:10]}...)"
                lines.append(f"  {badge} {change.path} {diff}")
            elif status == FileStatus.ADDED:
                badge = _colorize("[ADDED]    ", COLOR_GREEN, use_color)
                h = f"(SHA-256: {change.current_sha256[:10]}...)" if change.current_sha256 else ""
                lines.append(f"  {badge} {change.path} {h}")
            elif status == FileStatus.DELETED:
                badge = _colorize("[DELETED]  ", COLOR_RED, use_color)
                h = f"(Prev SHA-256: {change.baseline_sha256[:10]}...)" if change.baseline_sha256 else ""
                lines.append(f"  {badge} {change.path} {h}")
            elif status == FileStatus.ERROR:
                badge = _colorize("[ERROR]    ", COLOR_MAGENTA, use_color)
                lines.append(f"  {badge} {change.path} ({change.details or 'Access failed'})")
            elif status == FileStatus.UNCHANGED and show_unchanged:
                badge = _colorize("[UNCHANGED]", COLOR_DIM, use_color)
                lines.append(f"  {badge} {change.path}")
        lines.append(sub_divider)
    else:
        if sum_data.get("unchanged", 0) > 0 and sum_data.get("errors", 0) == 0:
            lines.append("  All monitored files match the baseline with zero discrepancies.")
            lines.append(sub_divider)

    # Errors List
    if report.errors:
        lines.append(_colorize(" SCAN ERRORS & ACCESS FAILURES", COLOR_BOLD, use_color))
        for err in report.errors:
            lines.append(f"  - [{err.get('error_type', 'Error')}] {err.get('path', 'unknown')}: {err.get('message', '')}")
        lines.append(sub_divider)

    # Final Security Verdict Banner
    has_discrepancies = (
        sum_data.get("modified", 0) > 0
        or sum_data.get("added", 0) > 0
        or sum_data.get("deleted", 0) > 0
    )

    if not report.is_complete or sum_data.get("errors", 0) > 0:
        verdict = _colorize("[!] VERDICT: OPERATIONAL ERROR / INCOMPLETE SCAN", COLOR_YELLOW, use_color)
    elif has_discrepancies:
        verdict = _colorize("[!] VERDICT: INTEGRITY COMPROMISED - DISCREPANCIES DETECTED", COLOR_RED, use_color)
    else:
        verdict = _colorize("[+] VERDICT: INTEGRITY VERIFIED - ALL FILES MATCH BASELINE", COLOR_GREEN, use_color)

    lines.append(f" {verdict}")
    lines.append(divider)

    return "\n".join(lines)
