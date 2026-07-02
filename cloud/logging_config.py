"""Structured logging configuration for PagerWesi.

Provides a centralized, configurable logging system with support for
JSON-structured output suitable for SIEM integration, log rotation,
and secure handling of sensitive data.
"""
from __future__ import annotations

import json
import logging
import os
import re
import sys
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from typing import Any

# Sensitive patterns that should be redacted in log output
_SENSITIVE_PATTERNS = [
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"(?:password|secret|token|key)\s*[=:]\s*\S+", re.IGNORECASE),
    re.compile(r"Bearer\s+[A-Za-z0-9\-._~+/]+=*", re.IGNORECASE),
]

_LOG_FORMAT = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
_DATE_FORMAT = "%Y-%m-%dT%H:%M:%S%z"


def _redact(message: str) -> str:
    """Redact sensitive values from log messages."""
    for pattern in _SENSITIVE_PATTERNS:
        message = pattern.sub("[REDACTED]", message)
    return message


class SecureFormatter(logging.Formatter):
    """Formatter that redacts sensitive data from log records."""

    def format(self, record: logging.LogRecord) -> str:
        # Only redact the final formatted message, not individual args
        result = super().format(record)
        return _redact(result)


class JSONFormatter(logging.Formatter):
    """Emit log records as JSON lines for SIEM ingestion."""

    def format(self, record: logging.LogRecord) -> str:
        log_entry: dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": _redact(record.getMessage()),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }
        if record.exc_info and record.exc_info[1]:
            log_entry["exception"] = {
                "type": type(record.exc_info[1]).__name__,
                "message": str(record.exc_info[1]),
            }
        return json.dumps(log_entry, default=str)


def configure_logging(
    level: str = "INFO",
    json_output: bool = False,
    log_file: str | None = None,
    max_bytes: int = 10 * 1024 * 1024,
    backup_count: int = 5,
) -> logging.Logger:
    """Configure the root PagerWesi logger.

    Args:
        level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL).
        json_output: Use JSON structured output format.
        log_file: Optional path to a log file with rotation.
        max_bytes: Maximum log file size before rotation (default 10MB).
        backup_count: Number of rotated log files to keep.

    Returns:
        The configured root logger for pagerwesi.
    """
    logger = logging.getLogger("pagerwesi")
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    logger.handlers.clear()

    if json_output:
        formatter: logging.Formatter = JSONFormatter()
    else:
        formatter = SecureFormatter(_LOG_FORMAT, datefmt=_DATE_FORMAT)

    # Console handler
    console_handler = logging.StreamHandler(sys.stderr)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    # File handler with rotation
    if log_file:
        file_handler = RotatingFileHandler(
            log_file,
            maxBytes=max_bytes,
            backupCount=backup_count,
            encoding="utf-8",
        )
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

    return logger


def get_logger(name: str) -> logging.Logger:
    """Get a child logger under the pagerwesi namespace."""
    return logging.getLogger(f"pagerwesi.{name}")


# Auto-configure from environment variables on import
_default_level = os.environ.get("PAGERWESI_LOG_LEVEL", "INFO")
_default_json = os.environ.get("PAGERWESI_LOG_JSON", "").lower() in ("1", "true", "yes")
_default_file = os.environ.get("PAGERWESI_LOG_FILE")

configure_logging(
    level=_default_level,
    json_output=_default_json,
    log_file=_default_file,
)
