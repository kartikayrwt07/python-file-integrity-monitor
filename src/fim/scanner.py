"""
Recursive directory scanner for File Integrity Monitor.

Discovers files within a target directory, calculates metadata and SHA-256 hashes,
skips symlinks by default, guards against self-monitoring loops, and captures
filesystem errors gracefully.
"""

from datetime import datetime, timezone
import os
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set, Union

from fim.exceptions import FIMError, HashingError
from fim.hashing import hash_file, DEFAULT_CHUNK_SIZE
from fim.models import FileRecord, ScanResult


def scan_directory(
    target_path: Union[str, Path],
    exclude_paths: Optional[Iterable[Union[str, Path]]] = None,
    follow_symlinks: bool = False,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
) -> ScanResult:
    """Recursively scan a directory, calculating metadata and SHA-256 hashes.

    Args:
        target_path: Path to the root directory to monitor.
        exclude_paths: Optional paths (such as baseline or report files) to exclude.
        follow_symlinks: If True, traverse symbolic links (default False).
        chunk_size: Buffer size in bytes for streaming SHA-256 computation.

    Returns:
        ScanResult object containing discovered file records, errors, and completeness status.

    Raises:
        FIMError: If the target directory does not exist or is not a directory.
    """
    target = Path(target_path).resolve()

    if not target.exists():
        raise FIMError(f"Target directory '{target}' does not exist.")

    if not target.is_dir():
        raise FIMError(f"Target path '{target}' is not a directory.")

    # Normalize exclude paths to absolute resolved paths for robust matching
    resolved_excludes: Set[Path] = set()
    if exclude_paths:
        for p in exclude_paths:
            try:
                resolved_excludes.add(Path(p).resolve())
            except (OSError, RuntimeError):
                continue

    records: Dict[str, FileRecord] = {}
    errors: List[Dict[str, str]] = []

    def on_walk_error(err: OSError) -> None:
        """Capture directory access or permission errors during os.walk."""
        path_str = str(err.filename) if err.filename else str(target)
        try:
            rel_path = Path(path_str).resolve().relative_to(target).as_posix()
        except (ValueError, OSError):
            rel_path = path_str

        errors.append({
            "path": rel_path,
            "error_type": type(err).__name__,
            "message": str(err),
        })

    for root, dirs, files in os.walk(target, followlinks=follow_symlinks, onerror=on_walk_error):
        root_path = Path(root)

        # Filter and prune subdirectories in-place
        valid_dirs: List[str] = []
        for d in dirs:
            dir_path = root_path / d
            # Skip symlinks if follow_symlinks is False
            if not follow_symlinks and dir_path.is_symlink():
                continue
            # Skip if explicitly excluded
            if dir_path.resolve() in resolved_excludes:
                continue
            valid_dirs.append(d)
        dirs[:] = valid_dirs

        # Process discovered files in deterministic sorted order
        for fname in sorted(files):
            file_path = root_path / fname

            # Skip symlinks if not following symlinks
            if not follow_symlinks and file_path.is_symlink():
                continue

            # Skip explicitly excluded files (e.g. baseline or reports inside target)
            try:
                if file_path.resolve() in resolved_excludes:
                    continue
            except (OSError, RuntimeError):
                pass

            # Calculate POSIX relative path for portability
            try:
                rel_path = file_path.relative_to(target).as_posix()
            except ValueError:
                rel_path = file_path.name

            try:
                st = file_path.stat()
                size_bytes = st.st_size
                mtime_utc = datetime.fromtimestamp(st.st_mtime, tz=timezone.utc).isoformat()
                file_hash = hash_file(file_path, chunk_size=chunk_size)

                records[rel_path] = FileRecord(
                    path=rel_path,
                    sha256=file_hash,
                    size_bytes=size_bytes,
                    modified_time_utc=mtime_utc,
                )
            except (HashingError, PermissionError, FileNotFoundError, OSError) as e:
                errors.append({
                    "path": rel_path,
                    "error_type": type(e).__name__,
                    "message": str(e),
                })

    is_complete = (len(errors) == 0)
    return ScanResult(
        target_path=str(target),
        records=records,
        errors=errors,
        is_complete=is_complete,
    )
