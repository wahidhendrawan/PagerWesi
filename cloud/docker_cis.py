from __future__ import annotations

import json
import subprocess

from cloud.core import Finding, Severity, Status

CONTROL_IDS = {
    "DOCKER-DAEMON-001",
    "DOCKER-DAEMON-002",
    "DOCKER-NET-001",
    "DOCKER-IMG-001",
}


def _selected(args, control_id: str) -> bool:
    return not args.control or control_id in args.control


def _finding(control_id, title, status, severity, resource, evidence, remediation=""):
    return Finding(
        control_id, title, status, severity, resource, evidence, remediation
    )


def _run_cmd(cmd: list[str]) -> tuple[str, bool]:
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=30
        )
        return result.stdout, result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return "", False


def _check_tls_enabled() -> Finding:
    """DOCKER-DAEMON-001: Docker daemon TLS enabled."""
    output, ok = _run_cmd(["docker", "info", "--format", "{{json .}}"])
    if not ok:
        return _finding(
            "DOCKER-DAEMON-001", "Docker daemon TLS enabled",
            Status.ERROR, Severity.HIGH, "docker:daemon",
            "docker info unavailable",
            "Ensure Docker is running and accessible.",
        )
    try:
        info = json.loads(output)
    except json.JSONDecodeError:
        info = {}
    security = info.get("SecurityOptions", [])
    tls = any("tls" in str(s).lower() for s in security)
    return _finding(
        "DOCKER-DAEMON-001", "Docker daemon TLS enabled",
        Status.PASS if tls else Status.FAIL, Severity.HIGH,
        "docker:daemon",
        f"tls_enabled={tls}",
        "Enable TLS on the Docker daemon with --tlsverify.",
    )


def _check_userns_remap() -> Finding:
    """DOCKER-DAEMON-002: User namespace remapping enabled."""
    output, ok = _run_cmd(["docker", "info", "--format", "{{json .}}"])
    if not ok:
        return _finding(
            "DOCKER-DAEMON-002", "User namespace remapping",
            Status.ERROR, Severity.HIGH, "docker:daemon",
            "docker info unavailable",
        )
    try:
        info = json.loads(output)
    except json.JSONDecodeError:
        info = {}
    security = info.get("SecurityOptions", [])
    userns = any("userns" in str(s).lower() for s in security)
    return _finding(
        "DOCKER-DAEMON-002", "User namespace remapping",
        Status.PASS if userns else Status.FAIL, Severity.MEDIUM,
        "docker:daemon",
        f"userns_remap={userns}",
        "Enable user namespace remapping in daemon.json.",
    )


def _check_host_network() -> Finding:
    """DOCKER-NET-001: No containers using --net=host."""
    output, ok = _run_cmd(
        ["docker", "ps", "--format", "{{json .}}"]
    )
    if not ok:
        return _finding(
            "DOCKER-NET-001", "No containers using host network",
            Status.ERROR, Severity.HIGH, "docker:containers",
            "docker ps unavailable",
        )
    violations = []
    for line in output.strip().splitlines():
        try:
            container = json.loads(line)
        except json.JSONDecodeError:
            continue
        networks = container.get("Networks", "")
        name = container.get("Names", "unknown")
        if "host" in networks.lower():
            violations.append(name)
    return _finding(
        "DOCKER-NET-001", "No containers using host network",
        Status.FAIL if violations else Status.PASS, Severity.HIGH,
        "docker:containers",
        f"host_network={','.join(violations) or 'none'}",
        "Avoid --net=host; use bridge or custom networks.",
    )


def _check_latest_tag() -> Finding:
    """DOCKER-IMG-001: No running containers with :latest tag."""
    output, ok = _run_cmd(
        ["docker", "ps", "--format", "{{json .}}"]
    )
    if not ok:
        return _finding(
            "DOCKER-IMG-001", "No latest tag in running containers",
            Status.ERROR, Severity.MEDIUM, "docker:containers",
            "docker ps unavailable",
        )
    violations = []
    for line in output.strip().splitlines():
        try:
            container = json.loads(line)
        except json.JSONDecodeError:
            continue
        image = container.get("Image", "")
        name = container.get("Names", "unknown")
        if image.endswith(":latest") or ":" not in image:
            violations.append(f"{name}({image})")
    return _finding(
        "DOCKER-IMG-001", "No latest tag in running containers",
        Status.FAIL if violations else Status.PASS, Severity.MEDIUM,
        "docker:containers",
        f"latest_tag={','.join(violations) or 'none'}",
        "Pin container images to specific version tags.",
    )


def _annotate_plan(findings: list[Finding]) -> list[Finding]:
    annotated = []
    for f in findings:
        if f.status == Status.FAIL:
            annotated.append(Finding(
                f.control_id, f.title, f.status, f.severity,
                f.resource, f.evidence, f.remediation, f.benchmark,
                planned=True,
                before={"compliant": False, "evidence": f.evidence},
                after={"compliant": True, "recommendation": f.remediation},
            ))
        else:
            annotated.append(f)
    return annotated


def run_audit(args) -> list[Finding]:
    _, docker_ok = _run_cmd(["docker", "version"])
    if not docker_ok:
        return [_finding(
            "DOCKER-DAEMON-001", "Docker availability",
            Status.ERROR, Severity.HIGH, "docker:daemon",
            "Docker is not available or not running.",
            "Install and start Docker.",
        )]

    checks = {
        "DOCKER-DAEMON-001": _check_tls_enabled,
        "DOCKER-DAEMON-002": _check_userns_remap,
        "DOCKER-NET-001": _check_host_network,
        "DOCKER-IMG-001": _check_latest_tag,
    }

    findings: list[Finding] = []
    for control_id, check_fn in checks.items():
        if _selected(args, control_id):
            try:
                findings.append(check_fn())
            except Exception as exc:
                findings.append(_finding(
                    control_id, f"{control_id} check failed",
                    Status.ERROR, Severity.HIGH, "docker:daemon",
                    f"{type(exc).__name__}: {exc}",
                ))

    if getattr(args, "mode", "audit") == "plan":
        findings = _annotate_plan(findings)
    return findings
