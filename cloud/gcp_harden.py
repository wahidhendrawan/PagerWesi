from __future__ import annotations

from cloud.core import Finding, Severity, Status

CONTROL_IDS = {"GCP-IAM-001", "GCP-SEC-001"}


def run_audit(args) -> list[Finding]:
    try:
        import google.auth
        from google.cloud import resourcemanager_v3
    except ImportError as exc:
        raise RuntimeError("Install the GCP dependencies with: pip install -e '.[gcp]'") from exc

    try:
        credentials, project = google.auth.default()
        client = resourcemanager_v3.ProjectsClient(credentials=credentials)
        projects = list(client.search_projects())
    except Exception as exc:
        return [
            Finding(
                "GCP-IAM-001",
                "GCP credentials can enumerate projects",
                Status.ERROR,
                Severity.HIGH,
                "gcp:organization",
                type(exc).__name__,
                "Configure Application Default Credentials with resource viewer access.",
            )
        ]
    if not projects:
        return [
            Finding(
                "GCP-IAM-001",
                "At least one project is visible",
                Status.FAIL,
                Severity.MEDIUM,
                "gcp:organization",
                f"default_project={project!r}",
                "Confirm organization/project selection and IAM permissions.",
            )
        ]
    findings = []
    for item in projects:
        resource = getattr(item, "name", "gcp:project:unknown")
        findings.append(
            Finding(
                "GCP-IAM-001",
                "Project is available for security assessment",
                Status.PASS,
                Severity.INFO,
                resource,
                f"state={getattr(item, 'state', 'unknown')}",
            )
        )
        findings.append(
            Finding(
                "GCP-SEC-001",
                "Security Command Center settings require assessment",
                Status.MANUAL,
                Severity.HIGH,
                resource,
                "The base GCP adapter currently inventories projects only.",
                "Enable Security Command Center and assess findings, services, and exports.",
            )
        )
    return [item for item in findings if not args.control or item.control_id in args.control]
