# Python File Integrity Monitor (FIM)

[![Python Version](https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.13%20%7C%203.14-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-55%20passed-brightgreen.svg)](#automated-testing)
[![Dependencies](https://img.shields.io/badge/dependencies-standard%20library%20only-brightgreen.svg)](#design-philosophy)
[![Security Standard](https://img.shields.io/badge/compliance-PCI--DSS%2011.5%20%7C%20NIST%20SI--7-orange.svg)](#defensive-security-context)

A modular, production-grade **Host-Based File Integrity Monitor (FIM)** developed in Python. Designed for security analysts, incident responders, and system administrators to detect unauthorized modifications, backdoor injections, stealth file deletions, and baseline drift across critical filesystems.

---

## Table of Contents
- [Defensive Security Context](#defensive-security-context)
- [Design Philosophy](#design-philosophy)
- [System Architecture](#system-architecture)
- [Core Capabilities](#core-capabilities)
- [The Threat Model & Baseline Integrity](#the-threat-model--baseline-integrity)
- [Exit Code Contract for Automation](#exit-code-contract-for-automation)
- [Installation & Quickstart](#installation--quickstart)
- [CLI Reference](#cli-reference)
- [JSON Report Schema](#json-report-schema)
- [Automated Testing](#automated-testing)
- [Roadmap](#roadmap)
- [License](#license)

---

## Defensive Security Context

Host-based intrusion detection systems (HIDS) rely on File Integrity Monitoring to catch adversaries who have breached perimeter defenses. Once inside a network, attackers frequently:
1. **Modify system configurations** (e.g., adding unauthorized SSH keys, weakening firewall rules, altering authentication providers).
2. **Inject backdoors & web shells** (e.g., hidden scripts in webroots or binary wrappers).
3. **Cover tracks** (e.g., altering or truncating log files, unlinking audit trails).
4. **Manipulate timestamps (*timestomping*)** to make altered binaries appear legitimate based on modification date.

By using **SHA-256 cryptographic hashing** rather than relying on filesystem timestamps, this tool detects content changes deterministically regardless of timestamp manipulation.

### Regulatory Compliance Mappings
- **PCI-DSS v4.0 Requirement 11.5**: Deploy a file integrity monitoring mechanism to alert personnel to unauthorized modification of critical system files, configuration files, or content files.
- **NIST SP 800-53 Rev. 5 (SI-7)**: Software, Firmware, and Information Integrity verification.
- **CIS Critical Security Controls (Control 8.4)**: Deploy file integrity monitoring tools to verify critical system files and binaries.

---

## Design Philosophy

- **Zero Third-Party Production Dependencies**: Built entirely upon Python's standard library (`hashlib`, `pathlib`, `json`, `argparse`, `tempfile`). No third-party packages are required to run the tool.
- **Constant Memory Footprint (Chunked Streaming)**: Streams file contents in 64 KB binary buffers (`f.read(65536)`). It easily hashes 50 GB database dumps or virtual disk images without `MemoryError` or causing system denial-of-service.
- **Atomic Operations**: Baselines and reports are written to disk using temporary staging files followed by atomic renames (`os.replace`), preventing corrupted state files during power failure or process interruption.
- **Cross-Platform Path Portability**: Normalizes all file paths to POSIX-compliant relative strings (`path.as_posix()`). Baselines generated on Windows can be audited on Linux or macOS without false discrepancy alerts.

---

## System Architecture

```text
python-file-integrity-monitor/
├── fim.py                      # CLI executable shim and package wrapper
├── src/
│   └── fim/
│       ├── __init__.py         # Package metadata and version info
│       ├── models.py           # Strongly-typed Dataclasses (Baseline, ScanReport, FileRecord)
│       ├── hashing.py          # Memory-efficient streaming SHA-256 engine
│       ├── scanner.py          # Recursive traversal, path filtering, and error capture
│       ├── baseline.py         # Baseline schema validation and atomic persistence
│       ├── detector.py         # Set-difference diffing and state classification
│       ├── reporter.py         # Terminal dashboard rendering and JSON exports
│       ├── exceptions.py       # Domain-specific custom exceptions (FIMError hierarchy)
│       └── cli.py              # Subcommand parser, logging, and exit code routing
├── tests/
│   ├── conftest.py             # Pytest environment fixtures
│   ├── test_hashing.py         # Hashing invariance, NIST empty vector, large file tests
│   ├── test_scanner.py         # Traversal, symlink avoidance, and unreadable file tests
│   ├── test_baseline.py        # Schema validation, atomic write, and corruption tests
│   ├── test_detector.py        # 5-state transitions and partial scan defense tests
│   ├── test_reporter.py        # Terminal rendering, NO_COLOR, and report exports
│   ├── test_cli.py             # CLI parser and exit code contract validation
│   └── test_integration.py     # End-to-end full incident lifecycle simulation
├── data/                       # Default storage for baseline JSON files
├── reports/                    # Default storage for generated scan reports
├── examples/                   # Synthetic production lab for demonstration
│   └── demo_lab/
├── pytest.ini                  # Pytest configuration
├── requirements.txt            # Dev/testing dependencies (pytest)
├── LICENSE                     # MIT License
└── README.md                   # System documentation
```

---

## Core Capabilities

### 1. 5-State Change Classification
Every discovered filesystem object is classified into one of five states:
- `ADDED`: File exists on disk, but was not present in the baseline.
- `DELETED`: File existed in the baseline, but is no longer present on disk.
- `MODIFIED`: File exists in both, but its SHA-256 hash has changed.
- `UNCHANGED`: File exists in both with identical SHA-256 hash.
- `ERROR`: File could not be reliably inspected (permission denied, locked file, I/O error).

### 2. Partial Scan Protection
A common bug in basic FIM tools is misinterpreting an unreadable file as deleted. If a file exists on disk but permission is restricted, this tool:
- Captures the exact exception and records the path in `errors`.
- Flags the scan as `is_complete = False`.
- Classifies the file as `ERROR` (with reason attached).
- **Guarantees that unreadable files are never falsely reported as `DELETED`**.

### 3. Self-Monitoring Prevention
If an operator saves the baseline or scan report inside the monitored directory (e.g. `--target ./webroot --baseline ./webroot/baseline.json`), the tool automatically excludes those files from hashing, preventing endless false-positive loops.

---

## The Threat Model & Baseline Integrity

### The "Trusted Baseline" Paradox
A File Integrity Monitor is a **detection control**, not a preventative control. It operates on the fundamental assumption that the initial baseline reflects an uncompromised, trusted state.

> **Defensive Principle**: If an adversary compromises a system *before* `fim.py init` is executed, the adversary's backdoors and modified binaries will be recorded into the baseline as the "trusted" standard.

### Recommended Operational Practices
1. **Initialize at Deployment**: Generate baselines immediately following clean operating system installation, image deployment, or verified CI/CD build artifact delivery.
2. **Enforce Read-Only Storage**: Store baseline JSON files on write-protected media, dedicated audit partitions, or remote immutable object storage (e.g., AWS S3 Object Lock, write-once storage).
3. **Overwrite Safeguard**: The `init` command strictly rejects overwriting an existing baseline unless the `--force` flag is explicitly provided.

---

## Exit Code Contract for Automation

In security operations and automated CI/CD pipelines, exit codes allow monitoring daemons to react deterministically:

| Exit Code | Constant | Meaning | Typical Action |
| :---: | :--- | :--- | :--- |
| **`0`** | `EXIT_SUCCESS` | Clean match / Baseline intact / Valid init | Proceed with deployment or next check. |
| **`1`** | `EXIT_INTEGRITY_VIOLATION` | Discrepancies detected (`MODIFIED`, `ADDED`, `DELETED`) | Trigger SOC alert / Isolate host / Investigate. |
| **`2`** | `EXIT_OPERATIONAL_ERROR` | File access failure / Incomplete scan / Missing target | Check permissions, process locks, or disk health. |
| **`3`** | `EXIT_BASELINE_ERROR` | Missing baseline / Corrupt JSON / Overwrite rejected | Verify baseline path or check schema version. |
| **`4`** | `EXIT_USAGE_ERROR` | Invalid CLI arguments or missing flags | Check command syntax using `--help`. |

---

## Installation & Quickstart

### Prerequisites
- Python 3.11 or newer installed.
- No external runtime dependencies required.

### Clone the Repository
```bash
git clone https://github.com/your-username/python-file-integrity-monitor.git
cd python-file-integrity-monitor
```

### Try the Demo Lab
We include a synthetic server environment in `examples/demo_lab/`:

```bash
# 1. Initialize baseline
python fim.py init --target ./examples/demo_lab --baseline ./data/demo_baseline.json

# 2. Verify baseline integrity
python fim.py verify --baseline ./data/demo_baseline.json

# 3. Perform routine scan (Clean match -> exit code 0)
python fim.py scan --target ./examples/demo_lab --baseline ./data/demo_baseline.json
```

---

## CLI Reference

### 1. `init` — Initialize Baseline
Scan a target directory and persist a baseline snapshot in JSON format:
```bash
python fim.py init --target /path/to/monitor --baseline /path/to/baseline.json [--force]
```
- `--target, -t`: Directory to monitor recursively.
- `--baseline, -b`: Output path for baseline JSON file.
- `--force, -f`: Allow replacing an existing baseline file.

### 2. `scan` — Perform Integrity Audit
Compare the live filesystem state against a trusted baseline:
```bash
python fim.py scan --target /path/to/monitor --baseline /path/to/baseline.json [--report /path/to/report.json] [--show-unchanged] [--no-color]
```
- `--target, -t`: Directory to scan.
- `--baseline, -b`: Path to reference baseline JSON.
- `--report, -r`: Optional path to export structured JSON report.
- `--show-unchanged`: Display all unchanged files in terminal breakdown.
- `--no-color`: Disable ANSI color escape codes (also automatic if `NO_COLOR=1` env is set).

### 3. `verify` — Baseline Health Check
Inspect and validate a baseline's internal schema and cryptographic hash formats without running a directory scan:
```bash
python fim.py verify --baseline /path/to/baseline.json
```

### 4. `report` — Inspect Exported Report
Display a previously generated JSON scan report in human-readable terminal format:
```bash
python fim.py report --input /path/to/report.json
```

---

## JSON Report Schema

Generated reports follow a strict, versioned JSON schema:

```json
{
  "schema_version": "1.0.0",
  "scan_timestamp_utc": "2026-10-22T14:41:20Z",
  "target_directory": "C:/app/webroot",
  "baseline_file": "C:/app/data/baseline.json",
  "is_complete": true,
  "summary": {
    "total_monitored": 4,
    "unchanged": 1,
    "modified": 1,
    "added": 1,
    "deleted": 1,
    "errors": 0
  },
  "changes": [
    {
      "path": "api/auth.py",
      "status": "MODIFIED",
      "baseline_sha256": "8f434346648f6b96df89dda901c5176b10a6d83961dd3c1ac88b59b2dc327aa4",
      "current_sha256": "3b128f73b88d8b67198bb6248c8b4182f768b4ef2141505c2194689252c80338",
      "details": "Content SHA-256 hash mismatch."
    },
    {
      "path": "api/backdoor.py",
      "status": "ADDED",
      "baseline_sha256": null,
      "current_sha256": "7d6c5a01bc189d81d2837f48bc23851b2e48227b4010372658826d9c9b101344",
      "details": "New file not present in baseline."
    },
    {
      "path": "static/css/main.css",
      "status": "DELETED",
      "baseline_sha256": "c47a11bb5832a829f03b5585b6118d0f1190bc74a6f7b11d4e7d446a89c44561",
      "current_sha256": null,
      "details": "File missing from filesystem."
    }
  ],
  "errors": []
}
```

---

## Automated Testing

The project includes unit, functional, and integration tests covering hashing edge cases, NIST vectors, unreadable file simulations, atomic crash safety, and end-to-end incident lifecycles.

Install pytest:
```bash
pip install -r requirements.txt
```

Run test suite:
```bash
python -m pytest
```

### Verified Test Results
```text
============================= test session starts =============================
platform win32 -- Python 3.14.8, pytest-9.1.1, pluggy-1.6.0
rootdir: C:\Users\karti\OneDrive\Desktop\File Integrity Monitor
configfile: pytest.ini
testpaths: tests
plugins: anyio-4.15.1
collected 55 items

tests\test_baseline.py ............                                      [ 21%]
tests\test_cli.py ............                                           [ 43%]
tests\test_detector.py .......                                           [ 56%]
tests\test_hashing.py .......                                            [ 69%]
tests\test_integration.py .                                              [ 70%]
tests\test_reporter.py .......                                           [ 83%]
tests\test_scanner.py .........                                          [100%]

============================= 55 passed in 1.03s ==============================
```

---

## Roadmap

- [ ] **Baseline Cryptographic Signatures**: Add HMAC-SHA256 or asymmetric GPG/Ed25519 digital signatures to detect offline tampering with baseline JSON files.
- [ ] **SIEM / Syslog Integration**: Forward alerts over RFC 5424 Syslog, Windows Event Log (ETW), or webhook endpoints (Slack, Discord, Microsoft Teams).
- [ ] **Real-Time Monitoring**: Optional asynchronous daemon mode using OS-native kernel file event notifications (`inotify` on Linux, `ReadDirectoryChangesW` on Windows).
- [ ] **Configurable Ignore Patterns**: Support `.fimignore` / glob rules for expected dynamic files (session caches, rotating logs).

---

## License

Distributed under the **MIT License**. See [`LICENSE`](LICENSE) for more information.
