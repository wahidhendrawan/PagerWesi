from __future__ import annotations

from cloud.core import Finding, Severity, Status

CONTROL_IDS = {"AZURE-IAM-001", "AZURE-SEC-001"}


def run_audit(args) -> list[Finding]:
    try:
        from azure.identity import DefaultAzureCredential
        from azure.mgmt.resource import SubscriptionClient
    except ImportError as exc:
        raise RuntimeError(
            "Install the Azure dependencies with: pip install -e '.[azure]'"
        ) from exc

    findings = []
    try:
        subscriptions = list(SubscriptionClient(DefaultAzureCredential()).subscriptions.list())
    except Exception as exc:
        return [
            Finding(
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
            Finding(
                "AZURE-IAM-001",
                "At least one subscription is visible",
                Status.FAIL,
                Severity.MEDIUM,
                "azure:tenant",
                "No subscriptions returned",
                "Confirm tenant selection and subscription permissions.",
            )
        ]
    for subscription in subscriptions:
        findings.append(
            Finding(
                "AZURE-IAM-001",
                "Subscription is available for security assessment",
                Status.PASS,
                Severity.INFO,
                f"/subscriptions/{subscription.subscription_id}",
                f"state={getattr(subscription, 'state', 'unknown')}",
            )
        )
        findings.append(
            Finding(
                "AZURE-SEC-001",
                "Microsoft Defender for Cloud settings require assessment",
                Status.MANUAL,
                Severity.HIGH,
                f"/subscriptions/{subscription.subscription_id}",
                "The base Azure adapter currently inventories subscriptions only.",
                "Install the security management extension and verify Defender plans "
                "and secure score.",
            )
        )
    return [item for item in findings if not args.control or item.control_id in args.control]
