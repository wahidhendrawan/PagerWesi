from __future__ import annotations

from cloud.core import Finding, Severity, Status
from cloud.policy import admin_ports, excluded

CONTROL_IDS = {
    "GCP-IAM-001",
    "GCP-IAM-002",
    "GCP-STORAGE-001",
    "GCP-STORAGE-002",
    "GCP-KMS-001",
    "GCP-NET-001",
    "GCP-LOG-001",
    "GCP-LOG-002",
    "GCP-SEC-001",
}
PUBLIC_MEMBERS = {"allUsers", "allAuthenticatedUsers"}
ADMIN_PORTS = {"22", "3389"}
PUBLIC_SOURCES = {"0.0.0.0/0", "::/0"}


def _finding(control, title, status, severity, resource, evidence, remediation=""):
    return Finding(control, title, status, severity, resource, evidence, remediation)


def _selected(args, control):
    return not args.control or control in args.control


def _includes_admin_port(values, sensitive_ports: set[str]) -> bool:
    if not values:
        return True
    for value in values:
        token = str(value).strip()
        if token in sensitive_ports:
            return True
        if "-" in token:
            start, end = token.split("-", 1)
            if start.isdigit() and end.isdigit():
                if any(int(start) <= int(port) <= int(end) for port in sensitive_ports):
                    return True
    return False


def _enum_name(value) -> str:
    return str(getattr(value, "name", value)).rsplit(".", 1)[-1]


def _has_required_audit_logs(audit_configs) -> bool:
    required = {"ADMIN_READ", "DATA_READ", "DATA_WRITE"}
    for config in audit_configs or []:
        service = getattr(config, "service", "")
        if service not in {"allServices", "all_services"}:
            continue
        enabled = {
            _enum_name(getattr(log_config, "log_type", ""))
            for log_config in getattr(config, "audit_log_configs", [])
        }
        if required <= enabled:
            return True
    return False


def _iam_client(credentials):
    from google.cloud import iam_admin_v1

    return iam_admin_v1.IAMClient(credentials=credentials)


def _kms_client(credentials):
    from google.cloud import kms_v1

    return kms_v1.KeyManagementServiceClient(credentials=credentials)


def _project_findings(credentials, project_id, resource, args):
    from google.cloud import compute_v1, logging_v2, resourcemanager_v3, storage

    findings = []
    if _selected(args, "GCP-STORAGE-001") or _selected(args, "GCP-STORAGE-002"):
        try:
            buckets = storage.Client(credentials=credentials, project=project_id).list_buckets()
            for bucket in buckets:
                bucket_resource = f"//storage.googleapis.com/{bucket.name}"
                if excluded(args, bucket_resource):
                    for control in ("GCP-STORAGE-001", "GCP-STORAGE-002"):
                        if _selected(args, control):
                            findings.append(
                                _finding(
                                    control,
                                    "Resource is excluded by policy",
                                    Status.SKIP,
                                    Severity.INFO,
                                    bucket_resource,
                                    "Matched exclude_resources policy.",
                                )
                            )
                    continue
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
            for control in ("GCP-STORAGE-001", "GCP-STORAGE-002"):
                if _selected(args, control):
                    findings.append(
                        _finding(
                            control,
                            "Cloud Storage security is assessable",
                            Status.ERROR,
                            Severity.HIGH,
                            resource,
                            type(exc).__name__,
                            "Grant Storage Viewer access.",
                        )
                    )

    if _selected(args, "GCP-IAM-002"):
        try:
            client = _iam_client(credentials)
            accounts = list(
                client.list_service_accounts(request={"name": f"projects/{project_id}"})
            )
            key_owners = []
            for account in accounts:
                keys = list(
                    client.list_service_account_keys(
                        request={"name": account.name, "key_types": ["USER_MANAGED"]}
                    )
                )
                if keys:
                    key_owners.append(getattr(account, "email", account.name))
            findings.append(
                _finding(
                    "GCP-IAM-002",
                    "Service accounts do not use user-managed keys",
                    Status.PASS if not key_owners else Status.FAIL,
                    Severity.HIGH,
                    resource,
                    f"service_accounts={len(accounts)}, "
                    f"user_managed_key_owners={','.join(key_owners) or 'none'}",
                    "Delete user-managed service account keys and prefer Workload Identity "
                    "Federation.",
                )
            )
        except Exception as exc:
            findings.append(
                _finding(
                    "GCP-IAM-002",
                    "Service account keys are assessable",
                    Status.ERROR,
                    Severity.HIGH,
                    resource,
                    type(exc).__name__,
                    "Grant Service Account Viewer access.",
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
                    protocol = str(getattr(allowed, "I_p_protocol", "tcp")).lower()
                    ports = getattr(allowed, "ports", []) or []
                    if (
                        sources & PUBLIC_SOURCES
                        and protocol in {"all", "tcp", "6"}
                        and _includes_admin_port(ports, admin_ports(args, "gcp", ADMIN_PORTS))
                    ):
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

    if _selected(args, "GCP-KMS-001"):
        try:
            client = _kms_client(credentials)
            project_name = f"projects/{project_id}"
            if not hasattr(client, "list_locations"):
                findings.append(
                    _finding(
                        "GCP-KMS-001",
                        "Cloud KMS symmetric keys rotate",
                        Status.MANUAL,
                        Severity.MEDIUM,
                        resource,
                        "list_locations operation is unavailable in this SDK version",
                        "Verify rotation_period and next_rotation_time on Cloud KMS keys.",
                    )
                )
            else:
                keys_checked = 0
                rotation_missing = []
                for location in client.list_locations(request={"name": project_name}):
                    location_name = getattr(location, "name", "")
                    for ring in client.list_key_rings(request={"parent": location_name}):
                        for key in client.list_crypto_keys(request={"parent": ring.name}):
                            keys_checked += 1
                            has_rotation = bool(
                                getattr(key, "rotation_period", None)
                                and getattr(key, "next_rotation_time", None)
                            )
                            if not has_rotation:
                                rotation_missing.append(key.name)
                findings.append(
                    _finding(
                        "GCP-KMS-001",
                        "Cloud KMS symmetric keys rotate",
                        Status.PASS if not rotation_missing else Status.FAIL,
                        Severity.MEDIUM,
                        resource,
                        f"keys={keys_checked}, "
                        f"rotation_missing={','.join(rotation_missing) or 'none'}",
                        "Set rotation_period and next_rotation_time for Cloud KMS keys.",
                    )
                )
        except Exception as exc:
            findings.append(
                _finding(
                    "GCP-KMS-001",
                    "Cloud KMS rotation settings are assessable",
                    Status.ERROR,
                    Severity.MEDIUM,
                    resource,
                    type(exc).__name__,
                    "Grant Cloud KMS Viewer access.",
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

    if _selected(args, "GCP-LOG-002"):
        try:
            policy = resourcemanager_v3.ProjectsClient(credentials=credentials).get_iam_policy(
                request={"resource": f"projects/{project_id}"}
            )
            enabled = _has_required_audit_logs(getattr(policy, "audit_configs", []))
            findings.append(
                _finding(
                    "GCP-LOG-002",
                    "Project audit logging captures admin and data access",
                    Status.PASS if enabled else Status.FAIL,
                    Severity.HIGH,
                    resource,
                    f"all_services_audit_logging={enabled}",
                    "Configure allServices audit logs for ADMIN_READ, DATA_READ, and DATA_WRITE.",
                )
            )
        except Exception as exc:
            findings.append(
                _finding(
                    "GCP-LOG-002",
                    "Project audit logging settings are assessable",
                    Status.ERROR,
                    Severity.HIGH,
                    resource,
                    type(exc).__name__,
                    "Grant Resource Manager IAM policy viewer access.",
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

    if getattr(args, "mode", "audit") == "plan":
        findings = _annotate_plan(findings)
    return findings


def _annotate_plan(findings: list[Finding]) -> list[Finding]:
    """Annotate FAIL findings with plan metadata for non-mutating plan mode."""
    annotated = []
    for f in findings:
        if f.status == Status.FAIL:
            annotated.append(
                Finding(
                    f.control_id,
                    f.title,
                    f.status,
                    f.severity,
                    f.resource,
                    f.evidence,
                    f.remediation,
                    f.benchmark,
                    planned=True,
                    before={"compliant": False, "evidence": f.evidence},
                    after={"compliant": True, "recommendation": f.remediation},
                )
            )
        else:
            annotated.append(f)
    return annotated
