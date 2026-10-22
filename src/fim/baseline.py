"""
Baseline management module for File Integrity Monitor.

Handles baseline instantiation, schema validation, JSON serialization,
atomic file writes, and overwrite protection.
"""

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import tempfile
from typing import Any, Dict, Optional, Set, Union

from fim.exceptions import (
    BaselineCorruptedError,
    BaselineExistsError,
    BaselineNotFoundError,
    ScanIncompleteError,
)
from fim.models import Baseline, FileRecord, ScanResult

# Supported schema versions for forward/backward compatibility
BASELINE_SCHEMA_VERSION = "1.0.0"
SUPPORTED_SCHEMA_VERSIONS: Set[str] = {BASELINE_SCHEMA_VERSION}

# Regex to validate standard 64-character lowercase or uppercase hex string
SHA256_HEX_REGEX = re.compile(r"^[a-fA-F0-9]{64}$")


def create_baseline(
    scan_result: ScanResult,
    monitored_root_name: Optional[str] = None,
) -> Baseline:
    """Create an in-memory Baseline instance from a ScanResult.

    Args:
        scan_result: The completed scan result of the target directory.
        monitored_root_name: Optional human-readable name of the root. Defaults to directory name.

    Returns:
        A validated Baseline object.

    Raises:
        ScanIncompleteError: If the scan had errors (preventing incomplete baselines).
    """
    if not scan_result.is_complete or scan_result.errors:
        raise ScanIncompleteError(
            f"Cannot initialize baseline: scan of '{scan_result.target_path}' encountered "
            f"{len(scan_result.errors)} access/read error(s). Baselines must be initialized "
            "from clean, complete scans to prevent tracking incomplete state."
        )

    root_name = monitored_root_name or Path(scan_result.target_path).name
    created_at = datetime.now(timezone.utc).isoformat()

    return Baseline(
        schema_version=BASELINE_SCHEMA_VERSION,
        created_at_utc=created_at,
        monitored_root_name=root_name,
        hash_algorithm="sha256",
        total_files=len(scan_result.records),
        files=dict(scan_result.records),
    )


def validate_baseline_dict(data: Any) -> Baseline:
    """Validate a dictionary against the FIM baseline schema and return a Baseline object.

    Args:
        data: Parsed JSON data.

    Returns:
        Validated Baseline object.

    Raises:
        BaselineCorruptedError: If any required fields are missing, malformed, or of invalid type.
    """
    if not isinstance(data, dict):
        raise BaselineCorruptedError("Baseline content must be a JSON object.")

    required_top_keys = {
        "schema_version",
        "created_at_utc",
        "monitored_root_name",
        "hash_algorithm",
        "total_files",
        "files",
    }
    missing_keys = required_top_keys - set(data.keys())
    if missing_keys:
        raise BaselineCorruptedError(
            f"Baseline missing required top-level keys: {sorted(missing_keys)}"
        )

    schema_version = str(data["schema_version"])
    if schema_version not in SUPPORTED_SCHEMA_VERSIONS:
        raise BaselineCorruptedError(
            f"Unsupported baseline schema version '{schema_version}'. "
            f"Supported versions: {sorted(SUPPORTED_SCHEMA_VERSIONS)}"
        )

    if data["hash_algorithm"] != "sha256":
        raise BaselineCorruptedError(
            f"Unsupported hash algorithm '{data['hash_algorithm']}'. Only 'sha256' is supported."
        )

    if not isinstance(data["files"], dict):
        raise BaselineCorruptedError("Field 'files' in baseline must be a dictionary.")

    parsed_files: Dict[str, FileRecord] = {}
    for path_key, file_info in data["files"].items():
        if not isinstance(path_key, str) or not path_key:
            raise BaselineCorruptedError("File path key in baseline must be a non-empty string.")

        if not isinstance(file_info, dict):
            raise BaselineCorruptedError(f"Entry for '{path_key}' must be a dictionary.")

        required_file_keys = {"sha256", "size_bytes", "modified_time_utc"}
        missing_file_keys = required_file_keys - set(file_info.keys())
        if missing_file_keys:
            raise BaselineCorruptedError(
                f"File entry '{path_key}' missing keys: {sorted(missing_file_keys)}"
            )

        sha256_val = str(file_info["sha256"])
        if not SHA256_HEX_REGEX.match(sha256_val):
            raise BaselineCorruptedError(
                f"File entry '{path_key}' has invalid SHA-256 digest: '{sha256_val}'"
            )

        try:
            size_bytes = int(file_info["size_bytes"])
            if size_bytes < 0:
                raise ValueError("size cannot be negative")
        except (ValueError, TypeError):
            raise BaselineCorruptedError(
                f"File entry '{path_key}' has invalid size_bytes: {file_info['size_bytes']}"
            )

        parsed_files[path_key] = FileRecord(
            path=path_key,
            sha256=sha256_val.lower(),
            size_bytes=size_bytes,
            modified_time_utc=str(file_info["modified_time_utc"]),
        )

    return Baseline(
        schema_version=schema_version,
        created_at_utc=str(data["created_at_utc"]),
        monitored_root_name=str(data["monitored_root_name"]),
        hash_algorithm="sha256",
        total_files=len(parsed_files),
        files=parsed_files,
    )


def save_baseline(
    baseline: Baseline,
    destination_path: Union[str, Path],
    force: bool = False,
) -> Path:
    """Save a Baseline object to a JSON file using atomic file writes.

    Args:
        baseline: The Baseline object to serialize.
        destination_path: Filesystem path where baseline JSON should be saved.
        force: If True, allow overwriting an existing baseline file.

    Returns:
        The resolved Path of the saved baseline file.

    Raises:
        BaselineExistsError: If destination exists and force is False.
    """
    dest = Path(destination_path).resolve()

    if dest.exists() and not force:
        raise BaselineExistsError(
            f"Baseline file already exists at '{dest}'. Use --force to confirm overwrite."
        )

    dest.parent.mkdir(parents=True, exist_ok=True)

    # Atomic write pattern: write to a unique temporary file in the same directory,
    # then use os.replace for an atomic rename. This prevents corrupted partial baselines
    # if power is lost or the process is terminated mid-write.
    temp_file = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            dir=dest.parent,
            encoding="utf-8",
            delete=False,
            prefix="baseline_",
            suffix=".tmp",
        ) as tmp:
            temp_file = Path(tmp.name)
            json.dump(baseline.to_dict(), tmp, indent=2, sort_keys=True)
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


def load_baseline(source_path: Union[str, Path]) -> Baseline:
    """Load and validate a Baseline JSON file from disk.

    Args:
        source_path: Path to the baseline JSON file.

    Returns:
        A validated Baseline object.

    Raises:
        BaselineNotFoundError: If the baseline file does not exist.
        BaselineCorruptedError: If file is a directory, malformed JSON, or schema-invalid.
    """
    path = Path(source_path).resolve()

    if not path.exists():
        raise BaselineNotFoundError(f"Baseline file does not exist at '{path}'.")

    if path.is_dir():
        raise BaselineCorruptedError(f"Specified baseline path '{path}' is a directory.")

    try:
        with path.open("r", encoding="utf-8") as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        raise BaselineCorruptedError(f"Baseline file '{path}' contains malformed JSON: {e}") from e
    except (OSError, UnicodeDecodeError) as e:
        raise BaselineCorruptedError(f"Could not read baseline file '{path}': {e}") from e

    return validate_baseline_dict(data)
