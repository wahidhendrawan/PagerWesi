"""Tests for the logging configuration module."""
from __future__ import annotations

import json
import logging

from cloud.logging_config import (
    JSONFormatter,
    SecureFormatter,
    _redact,
    configure_logging,
    get_logger,
)


class TestRedact:
    def test_redacts_aws_keys(self):
        """Should redact AWS access keys."""
        msg = "Key found: AKIAIOSFODNN7EXAMPLE in config"
        result = _redact(msg)
        assert "AKIAIOSFODNN7EXAMPLE" not in result
        assert "[REDACTED]" in result

    def test_redacts_bearer_tokens(self):
        """Should redact Bearer tokens."""
        msg = "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
        result = _redact(msg)
        assert "eyJhbG" not in result
        assert "[REDACTED]" in result

    def test_redacts_password_assignments(self):
        """Should redact password assignments."""
        msg = "password = mysecretvalue123"
        result = _redact(msg)
        assert "mysecretvalue123" not in result

    def test_preserves_normal_text(self):
        """Should not modify text without secrets."""
        msg = "Audit complete: 5 findings found"
        assert _redact(msg) == msg


class TestSecureFormatter:
    def test_redacts_in_messages(self):
        """Should redact secrets in formatted log messages."""
        formatter = SecureFormatter("%(message)s")
        record = logging.LogRecord(
            "test", logging.INFO, "", 0,
            "Key: %s", ("AKIAIOSFODNN7EXAMPLE",), None
        )
        output = formatter.format(record)
        assert "AKIAIOSFODNN7EXAMPLE" not in output
        assert "[REDACTED]" in output


class TestJSONFormatter:
    def test_outputs_json(self):
        """Should output valid JSON."""
        formatter = JSONFormatter()
        record = logging.LogRecord(
            "test", logging.INFO, "module.py", 42,
            "Test message", None, None
        )
        output = formatter.format(record)
        parsed = json.loads(output)
        assert parsed["level"] == "INFO"
        assert parsed["message"] == "Test message"
        assert "timestamp" in parsed

    def test_includes_exception_info(self):
        """Should include exception details when present."""
        formatter = JSONFormatter()
        try:
            raise ValueError("test error")
        except ValueError:
            import sys
            record = logging.LogRecord(
                "test", logging.ERROR, "module.py", 42,
                "Failed", None, sys.exc_info()
            )
        output = formatter.format(record)
        parsed = json.loads(output)
        assert parsed["exception"]["type"] == "ValueError"
        assert parsed["exception"]["message"] == "test error"

    def test_redacts_secrets_in_json(self):
        """Should redact secrets even in JSON format."""
        formatter = JSONFormatter()
        record = logging.LogRecord(
            "test", logging.INFO, "", 0,
            "Found key AKIAIOSFODNN7EXAMPLE", None, None
        )
        output = formatter.format(record)
        assert "AKIAIOSFODNN7EXAMPLE" not in output


class TestConfigureLogging:
    def test_creates_logger(self):
        """Should create a configured logger."""
        logger = configure_logging(level="DEBUG")
        assert logger.name == "pagerwesi"
        assert logger.level == logging.DEBUG

    def test_json_output_mode(self):
        """Should use JSON formatter when requested."""
        logger = configure_logging(json_output=True)
        assert any(
            isinstance(h.formatter, JSONFormatter)
            for h in logger.handlers
        )

    def test_file_handler(self, tmp_path):
        """Should create file handler when path specified."""
        log_file = str(tmp_path / "test.log")
        logger = configure_logging(log_file=log_file)
        # Should have both console and file handlers
        assert len(logger.handlers) == 2


class TestGetLogger:
    def test_returns_child_logger(self):
        """Should return a child of the pagerwesi logger."""
        logger = get_logger("test_module")
        assert logger.name == "pagerwesi.test_module"
