"""Source-tree secrets scanner with enhanced pattern detection.

Scans files for hardcoded secrets, API keys, tokens, and credentials.
Supports configurable allowlists and custom patterns.
"""
from __future__ import annotations

import os
import re
from typing import Any

from cloud.core import Finding, Severity, Status
from cloud.input_validator import validate_path
from cloud.logging_config import get_logger

logger = get_logger("secrets_scanner")

CONTROL_IDS = {"SECRETS-001"}

# Enhanced secret detection patterns
_PATTERNS: list[tuple[str, re.Pattern[str], Severity]] = [
    # AWS credentials
    ("AWS Access Key", re.compile(r"AKIA[0-9A-Z]{16}"), Severity.CRITICAL),
    ("AWS Secret Key", re.compile(
        r"(?:aws_secret_access_key|aws_secret)\s*[=:]\s*[A-Za-z0-9/+=]{40}"
    ), Severity.CRITICAL),
    # Private keys
    ("Private Key", re.compile(r"-----BEGIN[A-Z ]*PRIVATE KEY-----"), Severity.CRITICAL),
    # Generic passwords/secrets
    ("Password assignment", re.compile(
        r"(?:password|passwd|pwd)\s*[=:]\s*['\"][^'\"]{4,}['\"]", re.IGNORECASE
    ), Severity.HIGH),
    ("Secret assignment", re.compile(
        r"(?:secret|api_?key|auth_?token)\s*[=:]\s*['\"][^'\"]{8,}['\"]", re.IGNORECASE
    ), Severity.HIGH),
    # Platform tokens
    ("GitHub Token", re.compile(r"gh[pousr]_[A-Za-z0-9_]{36,255}"), Severity.CRITICAL),
    ("GitLab Token", re.compile(r"glpat-[A-Za-z0-9\-_]{20,}"), Severity.CRITICAL),
    ("Slack Token", re.compile(r"xox[baprs]-[0-9]{10,13}-[A-Za-z0-9\-]{20,}"), Severity.HIGH),
    # JWT tokens (long base64 with dots)
    ("JWT Token", re.compile(
        r"eyJ[A-Za-z0-9_-]{20,}\.eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_\-]{20,}"
    ), Severity.HIGH),
    # Database connection strings
    ("Database URL", re.compile(
        r"(?:mysql|postgres|postgresql|mongodb|redis)://[^\s'\"]{10,}", re.IGNORECASE
    ), Severity.HIGH),
    # Azure/GCP
    ("Azure Connection String", re.compile(
        r"DefaultEndpointsProtocol=https;AccountName=[^;]+"
        r";AccountKey=[A-Za-z0-9+/=]{40,}",
        re.IGNORECASE,
    ), Severity.CRITICAL),
    ("GCP Service Account Key", re.compile(
        r'"type"\s*:\s*"service_account"', re.IGNORECASE
    ), Severity.CRITICAL),
    # Generic high-entropy secrets
    ("Bearer Token", re.compile(
        r"(?:Bearer|Authorization[=:])\s+[A-Za-z0-9\-._~+/]{20,}=*", re.IGNORECASE
    ), Severity.MEDIUM),
]

_IGNORE_DIRS = frozenset({
    ".git", "node_modules", "__pycache__", ".venv", "venv",
    ".tox", ".mypy_cache", ".pytest_cache", ".ruff_cache",
    "dist", "build", ".eggs", "vendor",
})

_IGNORE_EXTS = frozenset({
    ".pyc", ".pyo", ".so", ".dylib", ".dll", ".exe",
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg",
    ".woff", ".woff2", ".ttf", ".eot",
    ".zip", ".tar", ".gz", ".bz2", ".xz", ".jar", ".war",
    ".pdf", ".doc", ".docx", ".xlsx",
    ".lock", ".sum",
})

# Files that commonly contain test/example secrets (allowlist)
_ALLOWLIST_FILES = frozenset({
    "test_secrets_scanner.py",
    "secrets_scanner.py",
    ".pre-commit-hooks.yaml",
})

# Allowlist patterns - lines matching these are not flagged
_ALLOWLIST_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"#.*(?:example|test|fake|dummy|placeholder)", re.IGNORECASE),
    re.compile(r"\b(?:EXAMPLE|FAKE|DUMMY|PLACEHOLDER|CHANGEME|TODO)\b"),
    re.compile(r"re\.compile\("),  # Regex pattern definitions
]

# Maximum file size to scan (1 MiB)
_MAX_FILE_SIZE = 1024 * 1024


def _is_binary(path: str) -> bool:
    """Detect binary files by checking for null bytes."""
    try:
        with open(path, "rb") as f:
            chunk = f.read(512)
        return b"\x00" in chunk
    except OSError:
        return True


def _is_allowlisted(line: str, fname: str) -> bool:
    """Check if a line or file is in the allowlist."""
    if fname in _ALLOWLIST_FILES:
        return True
    return any(pattern.search(line) for pattern in _ALLOWLIST_PATTERNS)


def scan_path(path: str, args: Any) -> list[Finding]:
    """Scan a filesystem path for hardcoded secrets.

    Args:
        path: Root directory to scan.
        args: CLI arguments namespace.

    Returns:
        List of findings for detected secrets.
    """
    findings: list[Finding] = []
    scanned_files = 0
    skipped_files = 0

    logger.info("Starting secrets scan of: %s", path)

    for root, dirs, files in os.walk(path):
        # Prune ignored directories (in-place modification)
        dirs[:] = [d for d in dirs if d not in _IGNORE_DIRS]
        for fname in files:
            ext = os.path.splitext(fname)[1].lower()
            if ext in _IGNORE_EXTS:
                skipped_files += 1
                continue

            fpath = os.path.join(root, fname)

            # Skip files over size limit
            try:
                if os.path.getsize(fpath) > _MAX_FILE_SIZE:
                    skipped_files += 1
                    continue
            except OSError:
                continue

            if _is_binary(fpath):
                skipped_files += 1
                continue

            try:
                with open(fpath, encoding="utf-8", errors="ignore") as f:
                    scanned_files += 1
                    for lineno, line in enumerate(f, 1):
                        # Skip allowlisted lines
                        if _is_allowlisted(line, fname):
                            continue

                        for name, pattern, severity in _PATTERNS:
                            if pattern.search(line):
                                findings.append(Finding(
                                    control_id="SECRETS-001",
                                    title="Hardcoded secret detected",
                                    status=Status.FAIL,
                                    severity=severity,
                                    resource=f"{fpath}:{lineno}",
                                    evidence=f"pattern={name} (redacted)",
                                    remediation=(
                                        "Remove hardcoded secret; "
                                        "use environment variables "
                                        "or a secrets manager."
                                    ),
                                ))
                                break  # One finding per line
            except OSError:
                continue

    logger.info(
        "Secrets scan complete: scanned=%d, skipped=%d, findings=%d",
        scanned_files,
        skipped_files,
        len(findings),
    )
    return findings


def run_audit(args: Any) -> list[Finding]:
    """Run the secrets scanner audit.

    Args:
        args: CLI arguments namespace with optional 'path' attribute.

    Returns:
        List of findings.
    """
    path = getattr(args, "path", None) or os.getcwd()
    path_str = str(path)

    # Validate path
    try:
        validated = validate_path(path_str, must_exist=True, allow_symlinks=True)
        path_str = str(validated)
    except Exception as exc:
        return [Finding(
            control_id="SECRETS-001",
            title="Secrets scan path validation failed",
            status=Status.ERROR,
            severity=Severity.HIGH,
            resource=f"secrets:{path_str}",
            evidence=str(exc),
            remediation="Provide a valid, accessible directory path.",
        )]

    return scan_path(path_str, args)
