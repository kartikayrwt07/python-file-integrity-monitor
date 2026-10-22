#!/usr/bin/env python3
"""
File Integrity Monitor (FIM) Entrypoint

A modular defensive security tool for detecting unexpected filesystem changes
using cryptographic SHA-256 baseline hashing.
"""

from pathlib import Path
import sys

# Configure package path so that if fim.py is resolved as the 'fim' module,
# Python treats it as a package extending into src/fim
ROOT_DIR = Path(__file__).resolve().parent
SRC_FIM = ROOT_DIR / "src" / "fim"
SRC_DIR = ROOT_DIR / "src"

__path__ = [str(SRC_FIM)]

if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from fim.cli import main

if __name__ == "__main__":
    sys.exit(main())
