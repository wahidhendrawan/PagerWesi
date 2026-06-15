from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from cloud.core import Status


def options(controls=None):
    return SimpleNamespace(control=controls or [], mode="audit")


def test_azure_full_subscription_baseline():
    from cloud.azure_harden import _subscription_findings

    account = SimpleNamespace(
        id="/subscriptions/sub-1/storage/account",
        enable_https_traffic_only=True,
        minimum_tls_version="TLS1_2",
        network_rule_set=SimpleNamespace(default_action="Deny"),
    )
    storage_client = MagicMock()
    storage_client.storage_accounts.list.return_value = [account]
    network_client = MagicMock()
    network_client.network_security_groups.list_all.return_value = []
    security_client = MagicMock()
    security_client.pricings.list.return_value = [
        SimpleNamespace(name="VirtualMachines", pricing_tier="Standard")
    ]
    monitor_client = MagicMock()
    monitor_client.log_profiles.list.return_value = [SimpleNamespace(name="central")]
    subscription = SimpleNamespace(subscription_id="sub-1")

    with (
        patch("azure.mgmt.storage.StorageManagementClient", return_value=storage_client),
        patch("azure.mgmt.network.NetworkManagementClient", return_value=network_client),
        patch("azure.mgmt.security.SecurityCenter", return_value=security_client),
        patch("azure.mgmt.monitor.MonitorManagementClient", return_value=monitor_client),
    ):
        findings = _subscription_findings(MagicMock(), subscription, options())

    assert len(findings) == 5
    assert all(item.status == Status.PASS for item in findings)


def test_azure_exposed_admin_rule_and_free_defender_fail():
    from cloud.azure_harden import _subscription_findings

    storage_client = MagicMock()
    storage_client.storage_accounts.list.return_value = []
    rule = SimpleNamespace(
        name="rdp-public",
        access="Allow",
        direction="Inbound",
        source_address_prefix="0.0.0.0/0",
        destination_port_range="3389",
    )
    group = SimpleNamespace(name="nsg", security_rules=[rule])
    network_client = MagicMock()
    network_client.network_security_groups.list_all.return_value = [group]
    security_client = MagicMock()
    security_client.pricings.list.return_value = [
        SimpleNamespace(name="VirtualMachines", pricing_tier="Free")
    ]
    monitor_client = MagicMock()
    monitor_client.log_profiles.list.return_value = []

    with (
        patch("azure.mgmt.storage.StorageManagementClient", return_value=storage_client),
        patch("azure.mgmt.network.NetworkManagementClient", return_value=network_client),
        patch("azure.mgmt.security.SecurityCenter", return_value=security_client),
        patch("azure.mgmt.monitor.MonitorManagementClient", return_value=monitor_client),
    ):
        findings = _subscription_findings(
            MagicMock(), SimpleNamespace(subscription_id="sub-1"), options()
        )
    assert {item.control_id for item in findings if item.status == Status.FAIL} == {
        "AZURE-NET-001",
        "AZURE-SEC-001",
        "AZURE-LOG-001",
    }


def test_azure_inventory_and_authentication_error():
    subscription = SimpleNamespace(subscription_id="sub-1", state="Enabled")
    subscriptions = MagicMock()
    subscriptions.subscriptions.list.return_value = [subscription]
    with (
        patch("azure.identity.DefaultAzureCredential"),
        patch("azure.mgmt.resource.SubscriptionClient", return_value=subscriptions),
        patch("cloud.azure_harden._subscription_findings", return_value=[]),
    ):
        from cloud.azure_harden import run_audit

        findings = run_audit(options(["AZURE-IAM-001"]))
    assert findings[0].status == Status.PASS

    with patch("azure.identity.DefaultAzureCredential", side_effect=RuntimeError("denied")):
        assert run_audit(options())[0].status == Status.ERROR


def test_gcp_full_project_baseline():
    from cloud.gcp_harden import _project_findings

    bucket = MagicMock()
    bucket.name = "private-bucket"
    bucket.get_iam_policy.return_value = SimpleNamespace(
        bindings=[{"members": {"serviceAccount:a@example.com"}}]
    )
    bucket.iam_configuration.uniform_bucket_level_access_enabled = True
    storage_client = MagicMock()
    storage_client.list_buckets.return_value = [bucket]
    compute_client = MagicMock()
    compute_client.list.return_value = []
    logging_client = MagicMock()
    logging_client.list_sinks.return_value = [SimpleNamespace(name="central")]
    with (
        patch("google.cloud.storage.Client", return_value=storage_client),
        patch("google.cloud.compute_v1.FirewallsClient", return_value=compute_client),
        patch("google.cloud.logging_v2.Client", return_value=logging_client),
    ):
        findings = _project_findings(MagicMock(), "project-1", "projects/1", options())
    assert [item.status for item in findings] == [
        Status.PASS,
        Status.PASS,
        Status.PASS,
        Status.PASS,
        Status.MANUAL,
    ]


def test_gcp_public_bucket_and_firewall_fail():
    from cloud.gcp_harden import _project_findings

    bucket = MagicMock()
    bucket.name = "public-bucket"
    bucket.get_iam_policy.return_value = SimpleNamespace(bindings=[{"members": {"allUsers"}}])
    bucket.iam_configuration.uniform_bucket_level_access_enabled = False
    storage_client = MagicMock()
    storage_client.list_buckets.return_value = [bucket]
    firewall = SimpleNamespace(
        name="ssh-public",
        source_ranges=["0.0.0.0/0"],
        allowed=[SimpleNamespace(ports=["22"])],
    )
    compute_client = MagicMock()
    compute_client.list.return_value = [firewall]
    logging_client = MagicMock()
    logging_client.list_sinks.return_value = []
    with (
        patch("google.cloud.storage.Client", return_value=storage_client),
        patch("google.cloud.compute_v1.FirewallsClient", return_value=compute_client),
        patch("google.cloud.logging_v2.Client", return_value=logging_client),
    ):
        findings = _project_findings(MagicMock(), "project-1", "projects/1", options())
    assert {item.control_id for item in findings if item.status == Status.FAIL} == {
        "GCP-STORAGE-001",
        "GCP-STORAGE-002",
        "GCP-NET-001",
        "GCP-LOG-001",
    }


def test_gcp_inventory_and_authentication_error():
    project = SimpleNamespace(name="projects/123", project_id="project-1", state="ACTIVE")
    client = MagicMock()
    client.search_projects.return_value = [project]
    with (
        patch("google.auth.default", return_value=(MagicMock(), "project-1")),
        patch("google.cloud.resourcemanager_v3.ProjectsClient", return_value=client),
        patch("cloud.gcp_harden._project_findings", return_value=[]),
    ):
        from cloud.gcp_harden import run_audit

        findings = run_audit(options(["GCP-IAM-001"]))
    assert findings[0].status == Status.PASS

    with patch("google.auth.default", side_effect=RuntimeError("denied")):
        assert run_audit(options())[0].status == Status.ERROR
