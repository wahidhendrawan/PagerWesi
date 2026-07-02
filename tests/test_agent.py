from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from cloud.agent import _new_fails, _run_providers
from cloud.core import Finding, Severity, Status


def test_agent_records_provider_errors(caplog):
    working = MagicMock()
    working.run_audit.return_value = [
        Finding("AWS-S3-001", "ok", Status.PASS, Severity.INFO, "aws:account:1", "ok")
    ]

    def fake_load_provider(provider):
        if provider == "broken":
            raise RuntimeError("missing dependency")
        return working

    with patch("cloud.main.load_provider", side_effect=fake_load_provider):
        findings = _run_providers(["aws", "broken"], SimpleNamespace())

    assert findings[0]["control_id"] == "AWS-S3-001"
    assert findings[1]["control_id"] == "AGENT-PROVIDER-001"
    assert findings[1]["status"] == "error"
    assert findings[1]["resource"] == "agent:broken"
    assert "Provider broken failed" in caplog.text


def test_agent_new_fails_includes_errors():
    previous = [
        {"control_id": "AWS-S3-001", "resource": "bucket-a", "status": "fail"},
    ]
    current = [
        {"control_id": "AWS-S3-001", "resource": "bucket-a", "status": "fail"},
        {"control_id": "AGENT-PROVIDER-001", "resource": "agent:gcp", "status": "error"},
    ]

    assert _new_fails(current, previous) == [current[1]]
