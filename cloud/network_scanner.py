from __future__ import annotations

import socket
import ssl

from cloud.core import Finding, Severity, Status

CONTROL_IDS = {"NET-TLS-001", "NET-TLS-002", "NET-PORT-001"}


def _finding(control_id, title, status, severity, resource, evidence, remediation=""):
    return Finding(
        control_id, title, status, severity, resource, evidence, remediation
    )


def _check_tls_version(host: str, port: int) -> Finding:
    """NET-TLS-001: TLS 1.2 or higher."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                version = ssock.version()
                ok = version and "TLSv1.2" <= version  # type: ignore[operator]
                return _finding(
                    "NET-TLS-001", "TLS 1.2 or higher",
                    Status.PASS if ok else Status.FAIL,
                    Severity.HIGH, f"{host}:{port}",
                    f"tls_version={version}",
                    "Upgrade server to TLS 1.2+.",
                )
    except Exception as exc:
        return _finding(
            "NET-TLS-001", "TLS 1.2 or higher",
            Status.ERROR, Severity.HIGH, f"{host}:{port}",
            f"{type(exc).__name__}: {exc}",
        )


def _check_cert_validity(host: str, port: int) -> Finding:
    """NET-TLS-002: Valid certificate."""
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert() or {}
                return _finding(
                    "NET-TLS-002", "Valid TLS certificate",
                    Status.PASS, Severity.HIGH, f"{host}:{port}",
                    f"subject={cert.get('subject', 'unknown')}",
                )
    except ssl.SSLCertVerificationError as exc:
        return _finding(
            "NET-TLS-002", "Valid TLS certificate",
            Status.FAIL, Severity.HIGH, f"{host}:{port}",
            f"cert_error={exc}",
            "Fix or renew the TLS certificate.",
        )
    except Exception as exc:
        return _finding(
            "NET-TLS-002", "Valid TLS certificate",
            Status.ERROR, Severity.HIGH, f"{host}:{port}",
            f"{type(exc).__name__}: {exc}",
        )


def _check_open_ports(
    host: str, ports: list[int], expected: set[int]
) -> list[Finding]:
    """NET-PORT-001: Unexpected open ports."""
    findings: list[Finding] = []
    for port in ports:
        if port in expected:
            continue
        try:
            with socket.create_connection(
                (host, port), timeout=5
            ):
                findings.append(_finding(
                    "NET-PORT-001", "Unexpected open port",
                    Status.FAIL, Severity.MEDIUM, f"{host}:{port}",
                    f"port={port} is open and not expected",
                    "Close or firewall unexpected ports.",
                ))
        except (TimeoutError, OSError):
            pass
    if not findings:
        findings.append(_finding(
            "NET-PORT-001", "No unexpected open ports",
            Status.PASS, Severity.MEDIUM, host,
            "all_ports_expected=true",
        ))
    return findings


def scan_endpoints(endpoints: list[str], args) -> list[Finding]:
    findings: list[Finding] = []
    for endpoint in endpoints:
        parts = endpoint.rsplit(":", 1)
        host = parts[0]
        port = int(parts[1]) if len(parts) > 1 else 443
        findings.append(_check_tls_version(host, port))
        findings.append(_check_cert_validity(host, port))
    return findings


def run_audit(args) -> list[Finding]:
    endpoints = getattr(args, "endpoints", None)
    if isinstance(endpoints, str):
        endpoints = [e.strip() for e in endpoints.split(",") if e.strip()]
    if not endpoints:
        return [_finding(
            "NET-TLS-001", "No endpoints specified",
            Status.ERROR, Severity.HIGH, "network:config",
            "Provide --endpoints host:port[,host:port,...]",
            "Specify endpoints to scan.",
        )]
    return scan_endpoints(endpoints, args)
