from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from cloud.aws_harden import _check_aws_services, run_audit
from cloud.core import Status


def options(control):
    return SimpleNamespace(control=[control], mode="audit")


def session_with(client):
    session = MagicMock()
    session.client.return_value = client
    return session


def test_cloudtrail_requires_active_multi_region_trail():
    client = MagicMock()
    client.describe_trails.return_value = {
        "trailList": [{"TrailARN": "arn:trail", "IsMultiRegionTrail": True}]
    }
    client.get_trail_status.return_value = {"IsLogging": True}
    findings = _check_aws_services(session_with(client), "123", options("AWS-CT-001"))
    assert findings[0].status == Status.PASS


def test_config_requires_active_recorder():
    client = MagicMock()
    client.describe_configuration_recorder_status.return_value = {
        "ConfigurationRecordersStatus": [{"recording": False}]
    }
    findings = _check_aws_services(session_with(client), "123", options("AWS-CONFIG-001"))
    assert findings[0].status == Status.FAIL


def test_guardduty_requires_detector():
    client = MagicMock()
    client.list_detectors.return_value = {"DetectorIds": []}
    findings = _check_aws_services(session_with(client), "123", options("AWS-GD-001"))
    assert findings[0].status == Status.FAIL


def test_kms_rotation_failure_is_reported():
    client = MagicMock()
    client.get_paginator.return_value.paginate.return_value = [
        {"Keys": [{"KeyId": "key-1"}]},
        {"Keys": [{"KeyId": "key-2"}]},
    ]
    client.describe_key.return_value = {
        "KeyMetadata": {"KeyManager": "CUSTOMER", "KeySpec": "SYMMETRIC_DEFAULT"}
    }
    client.get_key_rotation_status.return_value = {"KeyRotationEnabled": False}
    findings = _check_aws_services(session_with(client), "123", options("AWS-KMS-001"))
    assert findings[0].status == Status.FAIL
    assert "Eligible=2" in findings[0].evidence
    client.describe_key.assert_any_call(KeyId="key-2")


def audit_options(**overrides):
    values = {
        "control": ["AWS-IAM-001"],
        "profile": None,
        "profiles": None,
        "organization_role": None,
        "external_id": None,
        "region": "us-east-1",
        "regions": None,
        "workers": 2,
        "mode": "audit",
    }
    values.update(overrides)
    return SimpleNamespace(**values)


def test_run_audit_orchestrates_account_and_region():
    base = MagicMock(region_name="us-east-1")
    sts = MagicMock()
    sts.get_caller_identity.return_value = {"Account": "123"}
    base.client.return_value = sts
    regional = MagicMock()
    iam = MagicMock()
    iam.get_account_summary.return_value = {"SummaryMap": {"AccountMFAEnabled": 1}}
    regional.client.return_value = iam
    with patch("boto3.Session", side_effect=[base, regional]):
        findings = run_audit(audit_options())
    assert len(findings) == 1
    assert findings[0].status == Status.PASS
    assert findings[0].resource == "aws:account:123"


def test_run_audit_combines_named_profiles():
    first = MagicMock(region_name="us-east-1")
    first_sts = MagicMock()
    first_sts.get_caller_identity.return_value = {"Account": "111"}
    first.client.return_value = first_sts
    first_regional = MagicMock()
    first_iam = MagicMock()
    first_iam.get_account_summary.return_value = {"SummaryMap": {"AccountMFAEnabled": 1}}
    first_regional.client.return_value = first_iam

    second = MagicMock(region_name="us-east-1")
    second_sts = MagicMock()
    second_sts.get_caller_identity.return_value = {"Account": "222"}
    second.client.return_value = second_sts
    second_regional = MagicMock()
    second_iam = MagicMock()
    second_iam.get_account_summary.return_value = {"SummaryMap": {"AccountMFAEnabled": 0}}
    second_regional.client.return_value = second_iam

    with patch(
        "boto3.Session",
        side_effect=[first, first_regional, second, second_regional],
    ):
        findings = run_audit(audit_options(profiles="first,second"))
    assert {item.resource for item in findings} == {
        "aws:account:111",
        "aws:account:222",
    }
    assert {item.status for item in findings} == {Status.PASS, Status.FAIL}
