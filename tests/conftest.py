"""
Pytest configuration and environment fixtures for File Integrity Monitor.
"""

from pathlib import Path
import sys

# Ensure src/ package directory takes precedence over root fim.py script during imports
ROOT_DIR = Path(__file__).resolve().parent.parent
SRC_DIR = str(ROOT_DIR / "src")

# Remove root and empty paths from front of sys.path
while "" in sys.path:
    sys.path.remove("")
while str(ROOT_DIR) in sys.path:
    sys.path.remove(str(ROOT_DIR))
if SRC_DIR in sys.path:
    sys.path.remove(SRC_DIR)

# Insert src at the very front and append root to the back
sys.path.insert(0, SRC_DIR)
sys.path.append(str(ROOT_DIR))
