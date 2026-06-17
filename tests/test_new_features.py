import json
from io import StringIO
from types import SimpleNamespace

from cloud.core import Finding, Severity, Status
from cloud.custom_controls import load_custom_controls, run_custom_controls
from cloud.html_report import render_html
from cloud.remediation import generate_playbook


def test_custom_controls_valid(tmp_path):
    path = tmp_path / "controls.yml"
    path.write_text(
        "version: 1\ncontrols:\n"
        "  - id: CUSTOM-TEST-001\n"
        "    title: True always passes\n"
        "    check: 'true'\n",
        encoding="utf-8",
    )
    controls = load_custom_controls(path)
    assert len(controls) == 1
    assert controls[0]["id"] == "CUSTOM-TEST-001"


def test_custom_controls_run(tmp_path):
    path = tmp_path / "controls.yml"
    path.write_text(
        "version: 1\ncontrols:\n"
        "  - id: CUSTOM-TEST-001\n"
        "    title: True passes\n"
        "    check: 'true'\n"
        "  - id: CUSTOM-TEST-002\n"
        "    title: False fails\n"
        "    check: 'false'\n"
        "    severity: high\n"
        "    remediation: Fix it\n",
        encoding="utf-8",
    )
    args = SimpleNamespace(control=[], mode="audit")
    findings = run_custom_controls(path, args)
    assert findings[0].status == Status.PASS
    assert findings[1].status == Status.FAIL


def test_custom_controls_invalid_id(tmp_path):
    path = tmp_path / "controls.yml"
    path.write_text(
        "version: 1\ncontrols:\n"
        "  - id: BAD-ID\n"
        "    title: Bad\n"
        "    check: 'true'\n",
        encoding="utf-8",
    )
    try:
        load_custom_controls(path)
    except ValueError as exc:
        assert "CUSTOM-XXX-NNN" in str(exc)
    else:
        raise AssertionError("ValueError not raised")


def test_html_report():
    findings = [
        Finding("A", "title", Status.PASS, Severity.INFO, "r", "e"),
        Finding("B", "fail", Status.FAIL, Severity.HIGH, "r", "e", "fix"),
    ]
    stream = StringIO()
    render_html(findings, stream)
    html = stream.getvalue()
    assert "<html" in html
    assert "2 findings" in html
    assert "badge-pass" in html
    assert "badge-fail" in html


def test_remediation_terraform(tmp_path):
    manifest = tmp_path / "plan.json"
    manifest.write_text(json.dumps({
        "schema_version": "1.0",
        "plans": [
            {"control_id": "AWS-S3-001", "resource": "aws:account:123"},
            {"control_id": "AWS-EBS-001", "resource": "aws:region:us-east-1"},
        ],
    }), encoding="utf-8")
    output = generate_playbook(manifest, "terraform")
    assert "aws_s3_account_public_access_block" in output
    assert "aws_ebs_encryption_by_default" in output


def test_remediation_cfn(tmp_path):
    manifest = tmp_path / "plan.json"
    manifest.write_text(json.dumps({
        "schema_version": "1.0",
        "plans": [
            {"control_id": "AWS-S3-001", "resource": "aws:account:123"},
        ],
    }), encoding="utf-8")
    output = generate_playbook(manifest, "cloudformation")
    assert "AccountPublicAccessBlock" in output
