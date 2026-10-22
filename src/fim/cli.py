"""
Command-line interface (CLI) for File Integrity Monitor.

Handles command-line parsing, diagnostic logging, subcommand routing, and
enforces the exit-code contract.
"""

import argparse
import logging
import os
from pathlib import Path
import sys
from typing import List, Optional

from fim.baseline import create_baseline, load_baseline, save_baseline
from fim.detector import detect_changes
from fim.exceptions import (
    BaselineCorruptedError,
    BaselineExistsError,
    BaselineNotFoundError,
    FIMError,
    ScanIncompleteError,
)
from fim.reporter import export_json_report, load_json_report, render_terminal_summary
from fim.scanner import scan_directory

# Exit code contract constants
EXIT_SUCCESS = 0               # Clean match / Successful init / Valid baseline
EXIT_INTEGRITY_VIOLATION = 1   # Discrepancies detected (MODIFIED, ADDED, or DELETED)
EXIT_OPERATIONAL_ERROR = 2     # Scan access error, unreadable files, target not found
EXIT_BASELINE_ERROR = 3        # Baseline missing, corrupt, or overwrite rejected
EXIT_USAGE_ERROR = 4           # Invalid CLI arguments or missing flags


class FIMArgumentParser(argparse.ArgumentParser):
    """Custom ArgumentParser that exits with code 4 on usage errors."""
    def error(self, message: str) -> None:
        sys.stderr.write(f"Error: {message}\n\n")
        self.print_help(sys.stderr)
        sys.exit(EXIT_USAGE_ERROR)


def build_parser() -> FIMArgumentParser:
    """Build and configure the top-level argument parser and subcommands."""
    parser = FIMArgumentParser(
        prog="fim",
        description="File Integrity Monitor (FIM) - Defensive cybersecurity tool for detecting filesystem changes.",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable detailed diagnostic logging output.",
    )

    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    # 1. init command
    init_parser = subparsers.add_parser(
        "init",
        help="Scan a target directory and initialize a new baseline JSON snapshot.",
    )
    init_parser.add_argument(
        "--target", "-t",
        required=True,
        help="Path to the directory to monitor.",
    )
    init_parser.add_argument(
        "--baseline", "-b",
        required=True,
        help="Path where baseline JSON will be created.",
    )
    init_parser.add_argument(
        "--force", "-f",
        action="store_true",
        help="Overwrite existing baseline file if it already exists.",
    )

    # 2. scan command
    scan_parser = subparsers.add_parser(
        "scan",
        help="Compare target directory against a baseline to detect modifications, additions, or deletions.",
    )
    scan_parser.add_argument(
        "--target", "-t",
        required=True,
        help="Path to the directory to monitor.",
    )
    scan_parser.add_argument(
        "--baseline", "-b",
        required=True,
        help="Path to the reference baseline JSON file.",
    )
    scan_parser.add_argument(
        "--report", "-r",
        help="Optional path to export machine-readable JSON report.",
    )
    scan_parser.add_argument(
        "--show-unchanged",
        action="store_true",
        help="Include UNCHANGED files in detailed terminal output.",
    )
    scan_parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI color codes in terminal output.",
    )

    # 3. verify command
    verify_parser = subparsers.add_parser(
        "verify",
        help="Validate baseline file syntax, schema version, and hash digest formats.",
    )
    verify_parser.add_argument(
        "--baseline", "-b",
        required=True,
        help="Path to the baseline JSON file to verify.",
    )

    # 4. report command
    report_parser = subparsers.add_parser(
        "report",
        help="Display an existing JSON scan report in human-readable terminal format.",
    )
    report_parser.add_argument(
        "--input", "-i",
        required=True,
        help="Path to the JSON scan report file to inspect.",
    )
    report_parser.add_argument(
        "--show-unchanged",
        action="store_true",
        help="Include UNCHANGED files in terminal output.",
    )
    report_parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI color codes in terminal output.",
    )

    return parser


def handle_init(args: argparse.Namespace) -> int:
    """Handle 'init' subcommand."""
    target_path = Path(args.target).resolve()
    baseline_path = Path(args.baseline).resolve()

    # Pre-check baseline existence before running full scan if not forced
    if baseline_path.exists() and not args.force:
        sys.stderr.write(
            f"Error: Baseline already exists at '{baseline_path}'. Use --force to overwrite.\n"
        )
        return EXIT_BASELINE_ERROR

    try:
        # Prevent self-monitoring by excluding baseline path if inside target
        scan_result = scan_directory(target_path, exclude_paths=[baseline_path])
    except FIMError as e:
        sys.stderr.write(f"Operational Error: {e}\n")
        return EXIT_OPERATIONAL_ERROR

    if not scan_result.is_complete:
        sys.stderr.write(
            f"Error: Cannot initialize baseline. Target scan encountered {len(scan_result.errors)} access/read error(s).\n"
        )
        for err in scan_result.errors:
            sys.stderr.write(f" - [{err.get('error_type')}] {err.get('path')}: {err.get('message')}\n")
        return EXIT_OPERATIONAL_ERROR

    try:
        baseline = create_baseline(scan_result)
        save_baseline(baseline, baseline_path, force=args.force)
        print(f"[+] Baseline successfully initialized at: {baseline_path}")
        print(f"    Monitored Root : {scan_result.target_path}")
        print(f"    Total Tracked  : {baseline.total_files} files")
        return EXIT_SUCCESS
    except BaselineExistsError as e:
        sys.stderr.write(f"Error: {e}\n")
        return EXIT_BASELINE_ERROR
    except FIMError as e:
        sys.stderr.write(f"Error initializing baseline: {e}\n")
        return EXIT_BASELINE_ERROR


def handle_scan(args: argparse.Namespace) -> int:
    """Handle 'scan' subcommand."""
    target_path = Path(args.target).resolve()
    baseline_path = Path(args.baseline).resolve()
    report_path = Path(args.report).resolve() if args.report else None

    # Load baseline
    try:
        baseline = load_baseline(baseline_path)
    except (BaselineNotFoundError, BaselineCorruptedError) as e:
        sys.stderr.write(f"Baseline Error: {e}\n")
        return EXIT_BASELINE_ERROR

    # Exclude baseline and report files if they reside within target tree
    excludes = [baseline_path]
    if report_path:
        excludes.append(report_path)

    # Scan target directory
    try:
        scan_result = scan_directory(target_path, exclude_paths=excludes)
    except FIMError as e:
        sys.stderr.write(f"Operational Error: {e}\n")
        return EXIT_OPERATIONAL_ERROR

    # Perform differential comparison
    report = detect_changes(baseline, scan_result, baseline_filepath=str(baseline_path))

    # Render terminal output
    use_color = not args.no_color
    print(render_terminal_summary(report, show_unchanged=args.show_unchanged, use_color=use_color))

    # Export report if requested
    if report_path:
        try:
            export_json_report(report, report_path)
            print(f"\n[+] Detailed report exported to: {report_path}")
        except Exception as e:
            sys.stderr.write(f"Warning: Failed to export report file: {e}\n")

    # Evaluate exit code contract
    if not report.is_complete or report.summary.get("errors", 0) > 0:
        return EXIT_OPERATIONAL_ERROR

    has_discrepancies = (
        report.summary.get("modified", 0) > 0
        or report.summary.get("added", 0) > 0
        or report.summary.get("deleted", 0) > 0
    )
    if has_discrepancies:
        return EXIT_INTEGRITY_VIOLATION

    return EXIT_SUCCESS


def handle_verify(args: argparse.Namespace) -> int:
    """Handle 'verify' subcommand."""
    baseline_path = Path(args.baseline).resolve()
    try:
        baseline = load_baseline(baseline_path)
        print(f"[+] Baseline is valid and intact: {baseline_path}")
        print(f"    Schema Version : {baseline.schema_version}")
        print(f"    Created (UTC)  : {baseline.created_at_utc}")
        print(f"    Root Name      : {baseline.monitored_root_name}")
        print(f"    Hash Algorithm : {baseline.hash_algorithm}")
        print(f"    Total Files    : {baseline.total_files}")
        return EXIT_SUCCESS
    except (BaselineNotFoundError, BaselineCorruptedError) as e:
        sys.stderr.write(f"Baseline Verification Failed: {e}\n")
        return EXIT_BASELINE_ERROR


def handle_report(args: argparse.Namespace) -> int:
    """Handle 'report' subcommand."""
    report_path = Path(args.input).resolve()
    try:
        report = load_json_report(report_path)
        use_color = not args.no_color
        print(render_terminal_summary(report, show_unchanged=args.show_unchanged, use_color=use_color))
        return EXIT_SUCCESS
    except FIMError as e:
        sys.stderr.write(f"Report Error: {e}\n")
        return EXIT_OPERATIONAL_ERROR


def main(argv: Optional[List[str]] = None) -> int:
    """Main CLI execution entrypoint."""
    parser = build_parser()

    # If no arguments provided, show help and exit with usage error
    if argv is None and len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        return EXIT_USAGE_ERROR

    args = parser.parse_args(argv)

    if not args.command:
        parser.print_help(sys.stderr)
        return EXIT_USAGE_ERROR

    # Configure root logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    if args.command == "init":
        return handle_init(args)
    elif args.command == "scan":
        return handle_scan(args)
    elif args.command == "verify":
        return handle_verify(args)
    elif args.command == "report":
        return handle_report(args)

    return EXIT_USAGE_ERROR
