"""
Unit tests for cryptographic hashing module (fim.hashing).
"""

import hashlib
from pathlib import Path
import pytest

from fim.hashing import hash_file, hash_bytes, DEFAULT_CHUNK_SIZE
from fim.exceptions import HashingError

# NIST standard test vector: SHA-256 of empty input
EMPTY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def test_hash_empty_file(tmp_path: Path):
    """An empty file (0 bytes) must match the canonical empty SHA-256 digest."""
    empty_file = tmp_path / "empty.txt"
    empty_file.write_bytes(b"")

    digest = hash_file(empty_file)
    assert digest == EMPTY_SHA256


def test_hash_known_content(tmp_path: Path):
    """Hashing a file must match hashlib.sha256 of the exact bytes."""
    payload = b"Defensive cybersecurity engineering with Python.\n"
    expected = hashlib.sha256(payload).hexdigest()

    test_file = tmp_path / "sample.txt"
    test_file.write_bytes(payload)

    digest = hash_file(test_file)
    assert digest == expected


def test_hash_chunk_size_invariance(tmp_path: Path):
    """Hash result must be invariant to chunk size used during streaming."""
    # 256 KB of repeating data to span multiple small and large chunks
    payload = b"A" * (256 * 1024)
    expected = hashlib.sha256(payload).hexdigest()

    test_file = tmp_path / "chunk_test.bin"
    test_file.write_bytes(payload)

    # Test tiny (1 byte), odd (1019 bytes), and standard (64 KB) chunk sizes
    assert hash_file(test_file, chunk_size=1) == expected
    assert hash_file(test_file, chunk_size=1019) == expected
    assert hash_file(test_file, chunk_size=DEFAULT_CHUNK_SIZE) == expected


def test_hash_large_synthetic_file(tmp_path: Path):
    """A 1 MB file should hash correctly and verify streaming stability."""
    test_file = tmp_path / "large_file.dat"
    # 1024 chunks of 1024 bytes
    with test_file.open("wb") as f:
        for i in range(1024):
            f.write(f"block_{i:04d}\n".encode("utf-8") * 64)

    expected = hashlib.sha256(test_file.read_bytes()).hexdigest()
    assert hash_file(test_file) == expected


def test_hash_nonexistent_file(tmp_path: Path):
    """Attempting to hash a missing file must raise HashingError."""
    missing = tmp_path / "does_not_exist.txt"
    with pytest.raises(HashingError) as exc_info:
        hash_file(missing)

    assert "does not exist" in str(exc_info.value).lower()
    assert exc_info.value.path == str(missing)


def test_hash_directory_fails(tmp_path: Path):
    """Passing a directory path instead of a file must raise HashingError."""
    subdir = tmp_path / "subfolder"
    subdir.mkdir()

    with pytest.raises(HashingError) as exc_info:
        hash_file(subdir)

    assert "directory" in str(exc_info.value).lower()


def test_hash_bytes_matches_file(tmp_path: Path):
    """hash_bytes and hash_file should produce identical results for the same content."""
    payload = b"Integrity baseline verification test payload."
    test_file = tmp_path / "test.txt"
    test_file.write_bytes(payload)

    assert hash_bytes(payload) == hash_file(test_file)
