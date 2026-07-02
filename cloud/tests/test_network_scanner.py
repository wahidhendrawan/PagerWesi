"""Tests for the network scanner module."""
from __future__ import annotations

import ssl
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from cloud.core import Status
from cloud.network_scanner import (
    _check_cert_validity,
    _check_tls_version,
    run_audit,
    scan_endpoints,
)


@pytest.fixture
def scan_args():
    return SimpleNamespace(control=[], mode="audit", endpoints=None, workers=4)


class TestRunAudit:
    def test_no_endpoints_returns_error(self, scan_args):
        """Should return error when no endpoints specified."""
        findings = run_audit(scan_args)
        assert len(findings) == 1
        assert findings[0].status == Status.ERROR
        assert "No endpoints" in findings[0].title

    def test_empty_endpoints_string(self, scan_args):
        """Should return error for empty endpoints string."""
        scan_args.endpoints = ""
        findings = run_audit(scan_args)
        assert len(findings) == 1
        assert findings[0].status == Status.ERROR

    def test_invalid_endpoint_format(self, scan_args):
        """Should return error for invalid endpoint format."""
        scan_args.endpoints = "not-a-valid-endpoint"
        findings = run_audit(scan_args)
        assert len(findings) == 1
        assert findings[0].status == Status.ERROR
        assert "validation" in findings[0].title.lower()

    def test_invalid_port_number(self, scan_args):
        """Should return error for invalid port."""
        scan_args.endpoints = "example.com:99999"
        findings = run_audit(scan_args)
        assert len(findings) == 1
        assert findings[0].status == Status.ERROR

    def test_valid_endpoints_parsed(self, scan_args):
        """Should parse multiple valid endpoints."""
        scan_args.endpoints = "example.com:443,api.example.com:8443"
        with patch("cloud.network_scanner.scan_endpoints") as mock_scan:
            mock_scan.return_value = []
            run_audit(scan_args)
            mock_scan.assert_called_once()
            endpoints = mock_scan.call_args.args[0]
            assert len(endpoints) == 2
            assert endpoints[0] == ("example.com", 443)
            assert endpoints[1] == ("api.example.com", 8443)


class TestTLSVersionCheck:
    @patch("cloud.network_scanner._SCAN_RATE_LIMITER")
    @patch("socket.create_connection")
    def test_tls_13_passes(self, mock_conn, mock_limiter):
        """TLS 1.3 should pass."""
        mock_limiter.acquire.return_value = True
        mock_sock = MagicMock()
        mock_conn.return_value.__enter__ = MagicMock(return_value=mock_sock)
        mock_conn.return_value.__exit__ = MagicMock(return_value=False)

        mock_ssl_sock = MagicMock()
        mock_ssl_sock.version.return_value = "TLSv1.3"

        with patch("ssl.SSLContext") as mock_ctx:
            ctx_instance = MagicMock()
            mock_ctx.return_value = ctx_instance
            ctx_instance.wrap_socket.return_value.__enter__ = MagicMock(return_value=mock_ssl_sock)
            ctx_instance.wrap_socket.return_value.__exit__ = MagicMock(return_value=False)

            finding = _check_tls_version("example.com", 443)
            assert finding.status == Status.PASS

    @patch("cloud.network_scanner._SCAN_RATE_LIMITER")
    @patch("socket.create_connection")
    def test_connection_timeout(self, mock_conn, mock_limiter):
        """Connection timeout should return ERROR."""
        mock_limiter.acquire.return_value = True
        mock_conn.side_effect = TimeoutError("timed out")

        finding = _check_tls_version("unreachable.example.com", 443)
        assert finding.status == Status.ERROR
        assert "timed out" in finding.evidence.lower()


class TestCertValidityCheck:
    @patch("cloud.network_scanner._SCAN_RATE_LIMITER")
    @patch("socket.create_connection")
    @patch("ssl.create_default_context")
    def test_valid_cert_passes(self, mock_ctx, mock_conn, mock_limiter):
        """Valid certificate should pass."""
        mock_limiter.acquire.return_value = True
        mock_sock = MagicMock()
        mock_conn.return_value.__enter__ = MagicMock(return_value=mock_sock)
        mock_conn.return_value.__exit__ = MagicMock(return_value=False)

        mock_ssl_sock = MagicMock()
        mock_ssl_sock.getpeercert.return_value = {
            "subject": ((("commonName", "example.com"),),),
            "notAfter": "Dec 31 23:59:59 2030 GMT",
        }
        ctx_instance = mock_ctx.return_value
        ctx_instance.wrap_socket.return_value.__enter__ = MagicMock(return_value=mock_ssl_sock)
        ctx_instance.wrap_socket.return_value.__exit__ = MagicMock(return_value=False)

        finding = _check_cert_validity("example.com", 443)
        assert finding.status == Status.PASS

    @patch("cloud.network_scanner._SCAN_RATE_LIMITER")
    @patch("socket.create_connection")
    @patch("ssl.create_default_context")
    def test_invalid_cert_fails(self, mock_ctx, mock_conn, mock_limiter):
        """Invalid certificate should fail."""
        mock_limiter.acquire.return_value = True
        mock_sock = MagicMock()
        mock_conn.return_value.__enter__ = MagicMock(return_value=mock_sock)
        mock_conn.return_value.__exit__ = MagicMock(return_value=False)

        ctx_instance = mock_ctx.return_value
        ssl_error = ssl.SSLCertVerificationError("certificate has expired")
        ssl_error.verify_message = "certificate has expired"
        ctx_instance.wrap_socket.return_value.__enter__ = MagicMock(
            side_effect=ssl_error
        )
        ctx_instance.wrap_socket.return_value.__exit__ = MagicMock(return_value=False)

        finding = _check_cert_validity("expired.example.com", 443)
        assert finding.status == Status.FAIL


class TestScanEndpoints:
    @patch("cloud.network_scanner._check_tls_version")
    @patch("cloud.network_scanner._check_cert_validity")
    def test_scans_all_endpoints(self, mock_cert, mock_tls, scan_args):
        """Should run both checks for each endpoint."""
        from cloud.core import Finding, Severity

        mock_tls.return_value = Finding(
            "NET-TLS-001", "TLS check", Status.PASS,
            Severity.HIGH, "test:443", "ok"
        )
        mock_cert.return_value = Finding(
            "NET-TLS-002", "Cert check", Status.PASS,
            Severity.HIGH, "test:443", "ok"
        )

        endpoints = [("example.com", 443), ("api.example.com", 8443)]
        findings = scan_endpoints(endpoints, scan_args)
        assert len(findings) == 4  # 2 checks × 2 endpoints
