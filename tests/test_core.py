import json
from io import StringIO

from cloud.core import Finding, Severity, Status, exit_code, render_json, summarize


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
