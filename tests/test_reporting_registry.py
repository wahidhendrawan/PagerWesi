import importlib
import json
from unittest.mock import patch

from cloud.compliance import export_evidence
from cloud.control_registry import CONTROL_METADATA
from cloud.core import Finding, Severity, Status
from cloud.dashboard_gen import generate_dashboard
from cloud.providers import PROVIDERS
from cloud.webhooks import _filter_actionable, _summary, notify


def test_provider_control_ids_are_registered():
    missing: dict[str, list[str]] = {}
    for provider, module_name in PROVIDERS.items():
        module = importlib.import_module(module_name)
        control_ids = set(getattr(module, "CONTROL_IDS", set()))
        provider_missing = sorted(control_ids - set(CONTROL_METADATA))
        if provider_missing:
            missing[provider] = provider_missing

    assert missing == {}


def test_webhook_filters_finding_objects_and_dicts():
    findings = [
        Finding("AWS-S3-001", "pass", Status.PASS, Severity.INFO, "r1", "ok"),
        Finding("AWS-S3-002", "fail", Status.FAIL, Severity.HIGH, "r2", "bad"),
        {"control_id": "NET-TLS-001", "status": "error"},
        {"control": "LEGACY-001", "status": "FAIL"},
    ]

    filtered = _filter_actionable(findings)
    assert len(filtered) == 3
    assert _summary(findings)["top_controls"] == [
        "AWS-S3-002",
        "NET-TLS-001",
        "LEGACY-001",
    ]


def test_notify_posts_only_when_actionable():
    with patch("cloud.webhooks.send_slack") as send_slack:
        notify(
            {"slack_url": "https://example.test/hook"},
            [Finding("AWS-S3-001", "pass", Status.PASS, Severity.INFO, "r", "ok")],
        )
    send_slack.assert_not_called()

    with patch("cloud.webhooks.send_slack") as send_slack:
        notify(
            {"slack_url": "https://example.test/hook"},
            [{"control_id": "AWS-S3-001", "status": "fail"}],
        )
    send_slack.assert_called_once()


def test_dashboard_uses_finding_dict_schema(tmp_path):
    finding = Finding(
        "DOCKER-IMG-001",
        "No latest tag in running containers",
        Status.FAIL,
        Severity.MEDIUM,
        "docker:containers",
        "latest_tag=web(latest)",
    )
    generate_dashboard([finding.to_dict()], tmp_path)

    controls = (tmp_path / "controls.html").read_text(encoding="utf-8")
    providers = (tmp_path / "providers.html").read_text(encoding="utf-8")
    index = (tmp_path / "index.html").read_text(encoding="utf-8")

    assert "DOCKER-IMG-001" in controls
    assert "latest_tag=web(latest)" in controls
    assert "docker" in providers
    assert "FAIL: 1" in index


def test_compliance_export_maps_registered_controls():
    evidence = json.loads(
        export_evidence(
            [
                Finding(
                    "NET-TLS-001",
                    "TLS 1.2 or higher",
                    Status.FAIL,
                    Severity.HIGH,
                    "example.com:443",
                    "tls_version=TLSv1.0",
                )
            ],
            "pci",
        )
    )

    item = evidence["evidence"][0]
    assert item["control_id"] == "NET-TLS-001"
    assert item["status"] == "fail"
    assert item["mapping"] != "unmapped"
    assert item["target"] == "Network endpoint"
