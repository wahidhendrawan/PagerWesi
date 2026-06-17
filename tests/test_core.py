import json
from io import StringIO

from cloud.core import (
    Finding,
    Severity,
    Status,
    change_manifest,
    exit_code,
    plan_manifest,
    render_json,
    render_sarif,
    summarize,
)


def test_summary_and_exit_codes():
    findings = [
        Finding("A", "pass", Status.PASS, Severity.INFO, "r", "e"),
        Finding("B", "fail", Status.FAIL, Severity.HIGH, "r", "e"),
    ]
    assert summarize(findings)["fail"] == 1
    assert exit_code(findings) == 1
    assert exit_code(findings + [Finding("C", "error", Status.ERROR, Severity.HIGH, "r", "e")]) == 2


def test_json_is_machine_readable():
    stream = StringIO()
    render_json([Finding("A", "title", Status.PASS, Severity.INFO, "r", "e")], stream)
    assert json.loads(stream.getvalue())["summary"]["pass"] == 1


def test_change_manifest_contains_only_actual_changes(monkeypatch):
    monkeypatch.delenv("GITHUB_ACTOR", raising=False)
    monkeypatch.setenv("USER", "auditor")
    findings = [
        Finding("A", "changed", Status.PASS, Severity.INFO, "r1", "e", changed=True),
        Finding("B", "unchanged", Status.PASS, Severity.INFO, "r2", "e"),
    ]
    manifest = change_manifest("aws", findings)
    assert manifest["actor"] == "auditor"
    assert manifest["change_count"] == 1
    assert manifest["changes"][0]["control_id"] == "A"


def test_plan_manifest_contains_before_and_after(monkeypatch):
    monkeypatch.delenv("GITHUB_ACTOR", raising=False)
    monkeypatch.setenv("USER", "planner")
    finding = Finding(
        "A",
        "planned",
        Status.FAIL,
        Severity.INFO,
        "r1",
        "e",
        planned=True,
        before={"enabled": False},
        after={"enabled": True},
    )
    manifest = plan_manifest("aws", [finding])
    assert manifest["plan_count"] == 1
    assert manifest["plans"][0]["before"] == {"enabled": False}
    assert manifest["plans"][0]["after"] == {"enabled": True}


def test_sarif_enriched_with_control_metadata():
    stream = StringIO()
    finding = Finding(
        "AWS-S3-001",
        "Block public S3 access at account level",
        Status.FAIL,
        Severity.HIGH,
        "aws:account:123456789012",
        "NoSuchPublicAccessBlockConfiguration",
        "Enable account-level S3 public access block.",
    )
    render_sarif([finding], stream)
    sarif = json.loads(stream.getvalue())
    driver = sarif["runs"][0]["tool"]["driver"]
    assert driver["version"] == "0.6.0"
    rule = driver["rules"][0]
    assert rule["helpUri"].startswith("https://")
    assert "tags" in rule["properties"]
    assert any("nist-csf/" in tag for tag in rule["properties"]["tags"])
    assert sarif["runs"][0]["results"][0]["properties"]["status"] == "fail"
