"""
Custom exceptions for the File Integrity Monitor.
"""


class FIMError(Exception):
    """Base exception for all File Integrity Monitor errors."""
    pass


class HashingError(FIMError):
    """Raised when an unrecoverable error occurs while calculating file hash."""
    def __init__(self, path: str, reason: str):
        self.path = path
        self.reason = reason
        super().__init__(f"Failed to hash '{path}': {reason}")


class BaselineError(FIMError):
    """Base exception for baseline operations."""
    pass


class BaselineNotFoundError(BaselineError):
    """Raised when a requested baseline file does not exist."""
    pass


class BaselineCorruptedError(BaselineError):
    """Raised when a baseline JSON file is malformed or invalid against schema."""
    pass


class BaselineExistsError(BaselineError):
    """Raised when attempting to overwrite an existing baseline without explicit consent."""
    pass


class ScanIncompleteError(FIMError):
    """Raised when a scan cannot be completed reliably due to access or operational errors."""
    pass
