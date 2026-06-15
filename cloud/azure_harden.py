from __future__ import annotations

from cloud.core import Finding, Severity, Status

CONTROL_IDS = {
    "AZURE-IAM-001",
    "AZURE-STORAGE-001",
    "AZURE-STORAGE-002",
    "AZURE-NET-001",
    "AZURE-SEC-001",
    "AZURE-LOG-001",
}
ADMIN_PORTS = {"22", "3389", "5985", "5986"}


def _finding(control, title, status, severity, resource, evidence, remediation=""):
    return Finding(control, title, status, severity, resource, evidence, remediation)


def _selected(args, control):
    return not args.control or control in args.control


def _subscription_findings(credential, subscription, args):
    from azure.mgmt.monitor import MonitorManagementClient
    from azure.mgmt.network import NetworkManagementClient
    from azure.mgmt.security import SecurityCenter
    from azure.mgmt.storage import StorageManagementClient

    subscription_id = subscription.subscription_id
    root = f"/subscriptions/{subscription_id}"
    findings = []

    if _selected(args, "AZURE-STORAGE-001") or _selected(args, "AZURE-STORAGE-002"):
        try:
            accounts = StorageManagementClient(credential, subscription_id).storage_accounts.list()
            for account in accounts:
                resource = account.id
                if _selected(args, "AZURE-STORAGE-001"):
                    tls = str(getattr(account, "minimum_tls_version", "unknown"))
                    https = getattr(account, "enable_https_traffic_only", False)
                    compliant = https and tls.lower() in {"tls1_2", "tls1_3"}
                    findings.append(
                        _finding(
                            "AZURE-STORAGE-001",
                            "Storage enforces HTTPS and modern TLS",
                            Status.PASS if compliant else Status.FAIL,
                            Severity.HIGH,
                            resource,
                            f"https_only={https}, minimum_tls={tls}",
                            "Enable HTTPS-only traffic and require TLS 1.2 or newer.",
                        )
                    )
                if _selected(args, "AZURE-STORAGE-002"):
                    default_action = str(
                        getattr(
                            getattr(account, "network_rule_set", None), "default_action", "Allow"
                        )
                    )
                    findings.append(
                        _finding(
                            "AZURE-STORAGE-002",
                            "Storage network access defaults to deny",
                            Status.PASS if default_action.lower() == "deny" else Status.FAIL,
                            Severity.HIGH,
                            resource,
                            f"default_action={default_action}",
                            "Set the storage network rule default action to Deny.",
                        )
                    )
        except Exception as exc:
            findings.append(
                _finding(
                    "AZURE-STORAGE-001",
                    "Storage security settings are assessable",
                    Status.ERROR,
                    Severity.HIGH,
                    root,
                    type(exc).__name__,
                    "Grant storage account reader access.",
                )
            )

    if _selected(args, "AZURE-NET-001"):
        try:
            exposed = []
            groups = NetworkManagementClient(
                credential, subscription_id
            ).network_security_groups.list_all()
            for group in groups:
                for rule in getattr(group, "security_rules", []) or []:
                    source = str(getattr(rule, "source_address_prefix", ""))
                    port = str(getattr(rule, "destination_port_range", ""))
                    if (
                        str(getattr(rule, "access", "")).lower() == "allow"
                        and str(getattr(rule, "direction", "")).lower() == "inbound"
                        and source in {"*", "0.0.0.0/0", "Internet"}
                        and (port in ADMIN_PORTS or port == "*")
                    ):
                        exposed.append(f"{group.name}/{rule.name}")
            findings.append(
                _finding(
                    "AZURE-NET-001",
                    "Administrative ports are not open to the internet",
                    Status.FAIL if exposed else Status.PASS,
                    Severity.CRITICAL,
                    root,
                    f"exposed_rules={','.join(exposed) or 'none'}",
                    "Restrict administrative ports to approved management networks.",
                )
            )
        except Exception as exc:
            findings.append(
                _finding(
                    "AZURE-NET-001",
                    "Network security groups are assessable",
                    Status.ERROR,
                    Severity.HIGH,
                    root,
                    type(exc).__name__,
                    "Grant Network Reader access.",
                )
            )

    if _selected(args, "AZURE-SEC-001"):
        try:
            plans = list(SecurityCenter(credential, subscription_id).pricings.list())
            free = [plan.name for plan in plans if str(plan.pricing_tier).lower() == "free"]
            findings.append(
                _finding(
                    "AZURE-SEC-001",
                    "Microsoft Defender plans are enabled",
                    Status.FAIL if free else Status.PASS,
                    Severity.HIGH,
                    root,
                    f"free_plans={','.join(free) or 'none'}",
                    "Enable appropriate Microsoft Defender for Cloud plans.",
                )
            )
        except Exception as exc:
            findings.append(
                _finding(
                    "AZURE-SEC-001",
                    "Defender for Cloud plans are assessable",
                    Status.ERROR,
                    Severity.HIGH,
                    root,
                    type(exc).__name__,
                    "Grant Security Reader access.",
                )
            )

    if _selected(args, "AZURE-LOG-001"):
        try:
            profiles = list(
                MonitorManagementClient(credential, subscription_id).log_profiles.list()
            )
            findings.append(
                _finding(
                    "AZURE-LOG-001",
                    "Subscription activity log export is configured",
                    Status.PASS if profiles else Status.FAIL,
                    Severity.HIGH,
                    root,
                    f"log_profiles={len(profiles)}",
                    "Export subscription activity logs to an approved Log Analytics workspace "
                    "or SIEM.",
                )
            )
        except Exception as exc:
            findings.append(
                _finding(
                    "AZURE-LOG-001",
                    "Subscription activity log export is assessable",
                    Status.ERROR,
                    Severity.HIGH,
                    root,
                    type(exc).__name__,
                    "Grant Monitoring Reader access.",
                )
            )
    return findings


def run_audit(args) -> list[Finding]:
    try:
        from azure.identity import DefaultAzureCredential
        from azure.mgmt.subscription import SubscriptionClient
    except ImportError as exc:
        raise RuntimeError(
            "Install the Azure dependencies with: pip install -e '.[azure]'"
        ) from exc

    try:
        credential = DefaultAzureCredential()
        subscriptions = list(SubscriptionClient(credential).subscriptions.list())
    except Exception as exc:
        return [
            _finding(
                "AZURE-IAM-001",
                "Azure credentials can enumerate subscriptions",
                Status.ERROR,
                Severity.HIGH,
                "azure:tenant",
                type(exc).__name__,
                "Authenticate with Azure CLI, workload identity, or managed identity.",
            )
        ]
    if not subscriptions:
        return [
            _finding(
                "AZURE-IAM-001",
                "At least one subscription is visible",
                Status.FAIL,
                Severity.MEDIUM,
                "azure:tenant",
                "No subscriptions returned",
                "Confirm tenant selection and subscription permissions.",
            )
        ]
    findings = []
    for subscription in subscriptions:
        if _selected(args, "AZURE-IAM-001"):
            findings.append(
                _finding(
                    "AZURE-IAM-001",
                    "Subscription is available for security assessment",
                    Status.PASS,
                    Severity.INFO,
                    f"/subscriptions/{subscription.subscription_id}",
                    f"state={getattr(subscription, 'state', 'unknown')}",
                )
            )
        findings.extend(_subscription_findings(credential, subscription, args))
    return findings
