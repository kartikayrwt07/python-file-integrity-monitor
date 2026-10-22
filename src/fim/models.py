"""
Domain data models and enumerations for File Integrity Monitor.
"""

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Dict, List, Optional, Any


class FileStatus(str, Enum):
    """Integrity status classifications for monitored files."""
    ADDED = "ADDED"
    DELETED = "DELETED"
    MODIFIED = "MODIFIED"
    UNCHANGED = "UNCHANGED"
    ERROR = "ERROR"


@dataclass(frozen=True)
class FileRecord:
    """Represents the baseline state of an individual file."""
    path: str
    sha256: str
    size_bytes: int
    modified_time_utc: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "sha256": self.sha256,
            "size_bytes": self.size_bytes,
            "modified_time_utc": self.modified_time_utc,
        }

    @classmethod
    def from_dict(cls, path: str, data: Dict[str, Any]) -> "FileRecord":
        return cls(
            path=path,
            sha256=str(data["sha256"]),
            size_bytes=int(data["size_bytes"]),
            modified_time_utc=str(data["modified_time_utc"]),
        )


@dataclass(frozen=True)
class Baseline:
    """Represents a complete baseline snapshot."""
    schema_version: str
    created_at_utc: str
    monitored_root_name: str
    total_files: int
    files: Dict[str, FileRecord]
    hash_algorithm: str = "sha256"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "created_at_utc": self.created_at_utc,
            "monitored_root_name": self.monitored_root_name,
            "hash_algorithm": self.hash_algorithm,
            "total_files": self.total_files,
            "files": {path: record.to_dict() for path, record in self.files.items()},
        }


@dataclass(frozen=True)
class ChangeEntry:
    """Represents a detected change or verified state of a file during comparison."""
    path: str
    status: FileStatus
    baseline_sha256: Optional[str] = None
    current_sha256: Optional[str] = None
    details: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "path": self.path,
            "status": self.status.value,
            "baseline_sha256": self.baseline_sha256,
            "current_sha256": self.current_sha256,
            "details": self.details,
        }


@dataclass
class ScanResult:
    """Represents the raw outcome of scanning a target directory before comparison."""
    target_path: str
    records: Dict[str, FileRecord]
    errors: List[Dict[str, str]] = field(default_factory=list)
    is_complete: bool = True


@dataclass
class ScanReport:
    """Represents a complete comparison report between a baseline and current filesystem."""
    schema_version: str
    scan_timestamp_utc: str
    target_directory: str
    baseline_file: str
    is_complete: bool
    summary: Dict[str, int]
    changes: List[ChangeEntry] = field(default_factory=list)
    errors: List[Dict[str, str]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "scan_timestamp_utc": self.scan_timestamp_utc,
            "target_directory": self.target_directory,
            "baseline_file": self.baseline_file,
            "is_complete": self.is_complete,
            "summary": self.summary,
            "changes": [c.to_dict() for c in self.changes],
            "errors": self.errors,
        }

