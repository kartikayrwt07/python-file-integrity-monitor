"""
Change detection and classification engine for File Integrity Monitor.

Compares a fresh directory ScanResult against a trusted Baseline snapshot using
deterministic set-difference operations. Classifies each file into one of 5 states:
ADDED, DELETED, MODIFIED, UNCHANGED, or ERROR, while guaranteeing that scan access
failures are never misrepresented as deletions.
"""

from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Set

from fim.models import Baseline, ChangeEntry, FileStatus, ScanReport, ScanResult


def detect_changes(
    baseline: Baseline,
    scan_result: ScanResult,
    baseline_filepath: Optional[str] = None,
) -> ScanReport:
    """Compare a current scan against a trusted baseline and generate a ScanReport.

    Args:
        baseline: The trusted reference Baseline snapshot.
        scan_result: The fresh ScanResult from scanning the target directory.
        baseline_filepath: Optional path to the baseline file for report metadata.

    Returns:
        A complete ScanReport detailing state changes and summary statistics.
    """
    baseline_paths: Set[str] = set(baseline.files.keys())
    current_paths: Set[str] = set(scan_result.records.keys())

    # Map error paths for quick lookup
    error_by_path: Dict[str, str] = {
        err["path"]: err.get("message", "Unknown error")
        for err in scan_result.errors
    }

    changes: List[ChangeEntry] = []
    summary_counts: Dict[str, int] = {
        "total_monitored": 0,
        "unchanged": 0,
        "modified": 0,
        "added": 0,
        "deleted": 0,
        "errors": len(scan_result.errors),
    }

    # 1. Evaluate files present in both Baseline and Current Scan (Intersection)
    common_paths = baseline_paths & current_paths
    for path in common_paths:
        base_record = baseline.files[path]
        curr_record = scan_result.records[path]

        if base_record.sha256.lower() == curr_record.sha256.lower():
            changes.append(
                ChangeEntry(
                    path=path,
                    status=FileStatus.UNCHANGED,
                    baseline_sha256=base_record.sha256,
                    current_sha256=curr_record.sha256,
                    details=None,
                )
            )
            summary_counts["unchanged"] += 1
        else:
            changes.append(
                ChangeEntry(
                    path=path,
                    status=FileStatus.MODIFIED,
                    baseline_sha256=base_record.sha256,
                    current_sha256=curr_record.sha256,
                    details="Content SHA-256 hash mismatch.",
                )
            )
            summary_counts["modified"] += 1

    # 2. Evaluate files present in Current Scan but absent from Baseline (Added)
    added_paths = current_paths - baseline_paths
    for path in added_paths:
        curr_record = scan_result.records[path]
        changes.append(
            ChangeEntry(
                path=path,
                status=FileStatus.ADDED,
                baseline_sha256=None,
                current_sha256=curr_record.sha256,
                details="New file not present in baseline.",
            )
        )
        summary_counts["added"] += 1

    # 3. Evaluate files present in Baseline but absent from Current Scan (Deleted vs Error)
    missing_paths = baseline_paths - current_paths
    for path in missing_paths:
        base_record = baseline.files[path]

        # Defensive Guard: Check if the file (or a parent directory) failed during scan
        is_error = False
        error_msg = None

        if path in error_by_path:
            is_error = True
            error_msg = error_by_path[path]
        else:
            # Check if any recorded directory error is a prefix of this file's path
            for err_path, msg in error_by_path.items():
                if path.startswith(err_path.rstrip("/") + "/"):
                    is_error = True
                    error_msg = f"Parent directory '{err_path}' unreadable: {msg}"
                    break

        if is_error:
            changes.append(
                ChangeEntry(
                    path=path,
                    status=FileStatus.ERROR,
                    baseline_sha256=base_record.sha256,
                    current_sha256=None,
                    details=f"Inaccessible during scan: {error_msg}",
                )
            )
        else:
            changes.append(
                ChangeEntry(
                    path=path,
                    status=FileStatus.DELETED,
                    baseline_sha256=base_record.sha256,
                    current_sha256=None,
                    details="File missing from filesystem.",
                )
            )
            summary_counts["deleted"] += 1

    # 4. Also register any new/untracked files that hit errors during scan
    for err in scan_result.errors:
        err_path = err["path"]
        if err_path not in baseline_paths:
            changes.append(
                ChangeEntry(
                    path=err_path,
                    status=FileStatus.ERROR,
                    baseline_sha256=None,
                    current_sha256=None,
                    details=f"Scan error: {err.get('message', 'Unreadable file')}",
                )
            )

    # Sort changes alphabetically by path for consistent, deterministic reporting
    changes.sort(key=lambda c: c.path)

    # Total monitored represents distinct files evaluated (baseline plus newly added)
    summary_counts["total_monitored"] = len(baseline_paths | current_paths)

    return ScanReport(
        schema_version="1.0.0",
        scan_timestamp_utc=datetime.now(timezone.utc).isoformat(),
        target_directory=scan_result.target_path,
        baseline_file=baseline_filepath or "in-memory-baseline",
        is_complete=scan_result.is_complete,
        summary=summary_counts,
        changes=changes,
        errors=list(scan_result.errors),
    )
