from __future__ import annotations

from cloud.core import Finding, Severity, Status

CONTROL_IDS = {
    "GCP-IAM-001",
    "GCP-STORAGE-001",
    "GCP-STORAGE-002",
    "GCP-NET-001",
    "GCP-LOG-001",
    "GCP-SEC-001",
}
PUBLIC_MEMBERS = {"allUsers", "allAuthenticatedUsers"}
ADMIN_PORTS = {"22", "3389"}


def _finding(control, title, status, severity, resource, evidence, remediation=""):
    return Finding(control, title, status, severity, resource, evidence, remediation)


def _selected(args, control):
    return not args.control or control in args.control


def _project_findings(credentials, project_id, resource, args):
    from google.cloud import compute_v1, logging_v2, storage

    findings = []
    if _selected(args, "GCP-STORAGE-001") or _selected(args, "GCP-STORAGE-002"):
        try:
            buckets = storage.Client(credentials=credentials, project=project_id).list_buckets()
            for bucket in buckets:
                bucket_resource = f"//storage.googleapis.com/{bucket.name}"
                if _selected(args, "GCP-STORAGE-001"):
                    policy = bucket.get_iam_policy(requested_policy_version=3)
                    public = sorted(
                        {member for binding in policy.bindings for member in binding["members"]}
                        & PUBLIC_MEMBERS
                    )
                    findings.append(
                        _finding(
                            "GCP-STORAGE-001",
                            "Cloud Storage bucket IAM is not public",
                            Status.FAIL if public else Status.PASS,
                            Severity.CRITICAL,
                            bucket_resource,
                            f"public_members={','.join(public) or 'none'}",
                            "Remove allUsers and allAuthenticatedUsers bucket IAM bindings.",
                        )
                    )
                if _selected(args, "GCP-STORAGE-002"):
                    uniform = bucket.iam_configuration.uniform_bucket_level_access_enabled
                    findings.append(
                        _finding(
                            "GCP-STORAGE-002",
                            "Uniform bucket-level access is enabled",
                            Status.PASS if uniform else Status.FAIL,
                            Severity.MEDIUM,
                            bucket_resource,
                            f"uniform_access={uniform}",
                            "Enable uniform bucket-level access.",
                        )
                    )
        except Exception as exc:
            findings.append(
                _finding(
                    "GCP-STORAGE-001",
                    "Cloud Storage security is assessable",
                    Status.ERROR,
                    Severity.HIGH,
                    resource,
                    type(exc).__name__,
                    "Grant Storage Viewer access.",
                )
            )

    if _selected(args, "GCP-NET-001"):
        try:
            exposed = []
            for firewall in compute_v1.FirewallsClient(credentials=credentials).list(
                project=project_id
            ):
                sources = set(getattr(firewall, "source_ranges", []) or [])
                for allowed in getattr(firewall, "allowed", []) or []:
                    ports = set(getattr(allowed, "ports", []) or [])
                    if "0.0.0.0/0" in sources and (not ports or ports & ADMIN_PORTS):
                        exposed.append(firewall.name)
            findings.append(
                _finding(
                    "GCP-NET-001",
                    "Administrative ports are not open to the internet",
                    Status.FAIL if exposed else Status.PASS,
                    Severity.CRITICAL,
                    resource,
                    f"exposed_firewalls={','.join(exposed) or 'none'}",
                    "Restrict SSH and RDP firewall rules to approved management networks.",
                )
            )
        except Exception as exc:
            findings.append(
                _finding(
                    "GCP-NET-001",
                    "VPC firewall rules are assessable",
                    Status.ERROR,
                    Severity.HIGH,
                    resource,
                    type(exc).__name__,
                    "Grant Compute Network Viewer access.",
                )
            )

    if _selected(args, "GCP-LOG-001"):
        try:
            sinks = list(
                logging_v2.Client(credentials=credentials, project=project_id).list_sinks()
            )
            findings.append(
                _finding(
                    "GCP-LOG-001",
                    "Centralized logging sink is configured",
                    Status.PASS if sinks else Status.FAIL,
                    Severity.HIGH,
                    resource,
                    f"logging_sinks={len(sinks)}",
                    "Export audit logs to a protected central project or SIEM.",
                )
            )
        except Exception as exc:
            findings.append(
                _finding(
                    "GCP-LOG-001",
                    "Logging sinks are assessable",
                    Status.ERROR,
                    Severity.HIGH,
                    resource,
                    type(exc).__name__,
                    "Grant Logging Viewer access.",
                )
            )

    if _selected(args, "GCP-SEC-001"):
        findings.append(
            _finding(
                "GCP-SEC-001",
                "Security Command Center organization posture requires assessment",
                Status.MANUAL,
                Severity.HIGH,
                resource,
                "SCC activation and premium services are organization-scoped.",
                "Verify Security Command Center activation, services, findings, and exports "
                "at organization scope.",
            )
        )
    return findings


def run_audit(args) -> list[Finding]:
    try:
        import google.auth
        from google.cloud import resourcemanager_v3
    except ImportError as exc:
        raise RuntimeError("Install the GCP dependencies with: pip install -e '.[gcp]'") from exc
    try:
        credentials, default_project = google.auth.default()
        projects = list(
            resourcemanager_v3.ProjectsClient(credentials=credentials).search_projects()
        )
    except Exception as exc:
        return [
            _finding(
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
            _finding(
                "GCP-IAM-001",
                "At least one project is visible",
                Status.FAIL,
                Severity.MEDIUM,
                "gcp:organization",
                f"default_project={default_project!r}",
                "Confirm organization/project selection and IAM permissions.",
            )
        ]
    findings = []
    for project in projects:
        resource = getattr(project, "name", "gcp:project:unknown")
        project_id = getattr(project, "project_id", None) or resource.rsplit("/", 1)[-1]
        if _selected(args, "GCP-IAM-001"):
            findings.append(
                _finding(
                    "GCP-IAM-001",
                    "Project is available for security assessment",
                    Status.PASS,
                    Severity.INFO,
                    resource,
                    f"state={getattr(project, 'state', 'unknown')}",
                )
            )
        findings.extend(_project_findings(credentials, project_id, resource, args))
    return findings
