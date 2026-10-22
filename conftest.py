"""
Root pytest configuration for File Integrity Monitor.
Ensures src/ package is prioritized ahead of root entrypoint fim.py.
"""

from pathlib import Path
import sys

ROOT_DIR = Path(__file__).resolve().parent
SRC_DIR = str(ROOT_DIR / "src")

# Purge root and empty path strings from front of sys.path
while "" in sys.path:
    sys.path.remove("")
while str(ROOT_DIR) in sys.path:
    sys.path.remove(str(ROOT_DIR))
if SRC_DIR in sys.path:
    sys.path.remove(SRC_DIR)

sys.path.insert(0, SRC_DIR)
sys.path.append(str(ROOT_DIR))
