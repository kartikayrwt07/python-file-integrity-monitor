"""
Cryptographic hashing module for File Integrity Monitor.

Computes SHA-256 hashes of files using streaming chunks to ensure low memory
utilization regardless of file size.
"""

import hashlib
from pathlib import Path
from typing import Union

from fim.exceptions import HashingError

# 64 KB chunk size balances I/O syscall overhead and buffer memory usage
DEFAULT_CHUNK_SIZE: int = 64 * 1024


def hash_file(filepath: Union[str, Path], chunk_size: int = DEFAULT_CHUNK_SIZE) -> str:
    """Calculate the SHA-256 cryptographic hex digest of a file in streaming chunks.

    Args:
        filepath: Path to the target file.
        chunk_size: Number of bytes to read per iteration (default 64 KB).

    Returns:
        Hexadecimal string representation of SHA-256 digest.

    Raises:
        HashingError: If the file cannot be accessed, read, or does not exist.
    """
    path = Path(filepath)

    if not path.exists():
        raise HashingError(str(path), "File does not exist.")

    if path.is_dir():
        raise HashingError(str(path), "Target is a directory, not a file.")

    hasher = hashlib.sha256()

    try:
        with path.open("rb") as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                hasher.update(chunk)
    except PermissionError as e:
        raise HashingError(str(path), f"Permission denied: {e}") from e
    except (OSError, IOError) as e:
        raise HashingError(str(path), f"I/O read failure: {e}") from e

    return hasher.hexdigest()


def hash_bytes(data: bytes) -> str:
    """Calculate the SHA-256 cryptographic hex digest of raw in-memory bytes.

    Useful for testing, checksum verification, and small payloads.
    """
    return hashlib.sha256(data).hexdigest()
