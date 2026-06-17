from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from cloud.aws_harden import _check_aws_services, run_audit
from cloud.core import Status
from cloud.providers.aws.services import check_aws_organization_services


def options(control, mode="audit", policy=None):
    return SimpleNamespace(control=[control], mode=mode, policy=policy)


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


def test_ebs_encryption_by_default_is_required():
    client = MagicMock()
    client.get_ebs_encryption_by_default.return_value = {"EbsEncryptionByDefault": False}
    findings = _check_aws_services(session_with(client), "123", options("AWS-EBS-001"))
    assert findings[0].status == Status.FAIL


def test_ebs_apply_enables_encryption_by_default():
    client = MagicMock()
    client.get_ebs_encryption_by_default.return_value = {"EbsEncryptionByDefault": False}
    findings = _check_aws_services(session_with(client), "123", options("AWS-EBS-001", "apply"))
    assert findings[0].changed is True
    client.enable_ebs_encryption_by_default.assert_called_once()


def test_rds_storage_encryption_reports_unencrypted_instances():
    client = MagicMock()
    client.get_paginator.return_value.paginate.return_value = [
        {
            "DBInstances": [
                {"DBInstanceIdentifier": "prod", "StorageEncrypted": True},
                {"DBInstanceIdentifier": "legacy", "StorageEncrypted": False},
            ]
        }
    ]
    findings = _check_aws_services(session_with(client), "123", options("AWS-RDS-001"))
    assert findings[0].status == Status.FAIL
    assert "legacy" in findings[0].evidence


def test_vpc_flow_logs_are_required_for_every_vpc():
    ec2 = MagicMock()
    ec2.get_paginator.side_effect = [
        MagicMock(
            paginate=MagicMock(return_value=[{"Vpcs": [{"VpcId": "vpc-1"}, {"VpcId": "vpc-2"}]}])
        ),
        MagicMock(
            paginate=MagicMock(
                return_value=[{"FlowLogs": [{"ResourceId": "vpc-1", "FlowLogStatus": "ACTIVE"}]}]
            )
        ),
    ]
    findings = _check_aws_services(session_with(ec2), "123", options("AWS-VPC-001"))
    assert findings[0].status == Status.FAIL
    assert "vpc-2" in findings[0].evidence


def test_vpc_flow_logs_apply_uses_policy_destination():
    ec2 = MagicMock()
    ec2.get_paginator.side_effect = [
        MagicMock(paginate=MagicMock(return_value=[{"Vpcs": [{"VpcId": "vpc-1"}]}])),
        MagicMock(paginate=MagicMock(return_value=[{"FlowLogs": []}])),
    ]
    policy = {"aws": {"vpc_flow_log_destination_arn": "arn:aws:s3:::logs"}}
    findings = _check_aws_services(
        session_with(ec2), "123", options("AWS-VPC-001", "apply", policy)
    )
    assert findings[0].changed is True
    ec2.create_flow_logs.assert_called_once()


def test_access_analyzer_requires_active_analyzer():
    client = MagicMock()
    client.list_analyzers.return_value = {"analyzers": [{"name": "account", "status": "ACTIVE"}]}
    findings = _check_aws_services(session_with(client), "123", options("AWS-IAM-002"))
    assert findings[0].status == Status.PASS


def test_access_analyzer_apply_creates_account_analyzer():
    client = MagicMock()
    client.list_analyzers.return_value = {"analyzers": []}
    findings = _check_aws_services(session_with(client), "123", options("AWS-IAM-002", "apply"))
    assert findings[0].changed is True
    client.create_analyzer.assert_called_once_with(
        analyzerName="automation-hardening-account", type="ACCOUNT"
    )


def test_organization_aggregate_controls_pass():
    session = MagicMock()
    cloudtrail = MagicMock()
    cloudtrail.describe_trails.return_value = {
        "trailList": [
            {
                "TrailARN": "arn:trail",
                "IsOrganizationTrail": True,
                "IsMultiRegionTrail": True,
            }
        ]
    }
    cloudtrail.get_trail_status.return_value = {"IsLogging": True}
    guardduty = MagicMock()
    guardduty.list_organization_admin_accounts.return_value = {
        "AdminAccounts": [{"AdminStatus": "ENABLED"}]
    }
    securityhub = MagicMock()
    securityhub.list_organization_admin_accounts.return_value = {"AdminAccounts": [{}]}
    config = MagicMock()
    config.describe_configuration_aggregators.return_value = {
        "ConfigurationAggregators": [{"OrganizationAggregationSource": {"RoleArn": "arn"}}]
    }
    session.client.side_effect = lambda name: {
        "cloudtrail": cloudtrail,
        "guardduty": guardduty,
        "securityhub": securityhub,
        "config": config,
    }[name]
    findings = check_aws_organization_services(
        session, "123", SimpleNamespace(control=[], mode="audit")
    )
    assert {finding.control_id for finding in findings} == {
        "AWS-ORG-CT-001",
        "AWS-ORG-GD-001",
        "AWS-ORG-SH-001",
        "AWS-ORG-CONFIG-001",
    }
    assert all(finding.status == Status.PASS for finding in findings)


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
