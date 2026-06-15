import json
from io import StringIO

from cloud.core import (
    Finding,
    Severity,
    Status,
    change_manifest,
    exit_code,
    render_json,
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
