from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from cloud.core import Status


def options(controls=None):
    return SimpleNamespace(control=controls or [], mode="audit")


def test_azure_inventory_and_manual_finding():
    subscription = SimpleNamespace(subscription_id="sub-1", state="Enabled")
    subscriptions = MagicMock()
    subscriptions.subscriptions.list.return_value = [subscription]
    with (
        patch("azure.identity.DefaultAzureCredential"),
        patch("azure.mgmt.resource.SubscriptionClient", return_value=subscriptions),
    ):
        from cloud.azure_harden import run_audit

        findings = run_audit(options())
    assert [item.status for item in findings] == [Status.PASS, Status.MANUAL]


def test_azure_control_filter():
    subscription = SimpleNamespace(subscription_id="sub-1", state="Enabled")
    subscriptions = MagicMock()
    subscriptions.subscriptions.list.return_value = [subscription]
    with (
        patch("azure.identity.DefaultAzureCredential"),
        patch("azure.mgmt.resource.SubscriptionClient", return_value=subscriptions),
    ):
        from cloud.azure_harden import run_audit

        findings = run_audit(options(["AZURE-IAM-001"]))
    assert [item.control_id for item in findings] == ["AZURE-IAM-001"]


def test_gcp_inventory_and_manual_finding():
    project = SimpleNamespace(name="projects/123", state="ACTIVE")
    client = MagicMock()
    client.search_projects.return_value = [project]
    with (
        patch("google.auth.default", return_value=(MagicMock(), "project-1")),
        patch("google.cloud.resourcemanager_v3.ProjectsClient", return_value=client),
    ):
        from cloud.gcp_harden import run_audit

        findings = run_audit(options())
    assert [item.status for item in findings] == [Status.PASS, Status.MANUAL]


def test_provider_authentication_errors_are_structured():
    with patch("azure.identity.DefaultAzureCredential", side_effect=RuntimeError("denied")):
        from cloud.azure_harden import run_audit

        findings = run_audit(options())
    assert findings[0].status == Status.ERROR
