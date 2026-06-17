from __future__ import annotations

import os
import re

from cloud.core import Finding, Severity, Status

CONTROL_IDS = {"SECRETS-001"}

_PATTERNS = [
    ("AWS Access Key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("Private Key", re.compile(r"BEGIN[A-Z ]*PRIVATE KEY")),
    ("Password assignment", re.compile(
        r"(?:password|passwd|secret)\s*[=:]\s*\S+", re.IGNORECASE
    )),
]

_IGNORE_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv"}
_IGNORE_EXTS = {
    ".pyc", ".pyo", ".so", ".dylib", ".dll", ".exe",
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".woff", ".ttf",
    ".zip", ".tar", ".gz", ".jar",
}


def _is_binary(path: str) -> bool:
    try:
        with open(path, "rb") as f:
            chunk = f.read(512)
        return b"\x00" in chunk
    except OSError:
        return True


def scan_path(path: str, args) -> list[Finding]:
    findings: list[Finding] = []
    for root, dirs, files in os.walk(path):
        dirs[:] = [d for d in dirs if d not in _IGNORE_DIRS]
        for fname in files:
            ext = os.path.splitext(fname)[1].lower()
            if ext in _IGNORE_EXTS:
                continue
            fpath = os.path.join(root, fname)
            if _is_binary(fpath):
                continue
            try:
                with open(fpath, encoding="utf-8", errors="ignore") as f:
                    for lineno, line in enumerate(f, 1):
                        for name, pattern in _PATTERNS:
                            if pattern.search(line):
                                findings.append(Finding(
                                    control_id="SECRETS-001",
                                    title="Hardcoded secret detected",
                                    status=Status.FAIL,
                                    severity=Severity.HIGH,
                                    resource=f"{fpath}:{lineno}",
                                    evidence=(
                                        f"pattern={name} (redacted)"
                                    ),
                                    remediation=(
                                        "Remove hardcoded secret; "
                                        "use environment variables "
                                        "or a secrets manager."
                                    ),
                                ))
                                break
            except OSError:
                continue
    return findings


def run_audit(args) -> list[Finding]:
    path = getattr(args, "path", None) or os.getcwd()
    return scan_path(path, args)
