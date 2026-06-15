from types import SimpleNamespace
from unittest.mock import MagicMock

from botocore.exceptions import ClientError

from cloud.aws_harden import _check_account_public_block, _check_aws_services, _check_bucket
from cloud.core import Status


def options(mode="audit", controls=None):
    return SimpleNamespace(mode=mode, control=controls or [], workers=2, profile=None, region=None)


def configured_s3():
    s3 = MagicMock()
    s3.get_bucket_acl.return_value = {"Grants": []}
    s3.get_bucket_policy_status.return_value = {"PolicyStatus": {"IsPublic": False}}
    s3.get_public_access_block.return_value = {
        "PublicAccessBlockConfiguration": {
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        }
    }
    s3.get_bucket_encryption.return_value = {"ServerSideEncryptionConfiguration": {"Rules": [{}]}}
    s3.get_bucket_versioning.return_value = {"Status": "Enabled"}
    s3.get_bucket_logging.return_value = {"LoggingEnabled": {"TargetBucket": "logs"}}
    return s3


def test_compliant_bucket_passes_all_controls():
    findings = _check_bucket(configured_s3(), "private-bucket", options())
    assert len(findings) == 6
    assert all(item.status == Status.PASS for item in findings)


def test_public_acl_is_critical_failure():
    s3 = configured_s3()
    s3.get_bucket_acl.return_value = {
        "Grants": [{"Grantee": {"URI": "http://acs.amazonaws.com/groups/global/AllUsers"}}]
    }
    findings = _check_bucket(s3, "public-bucket", options(controls=["AWS-S3-002"]))
    assert findings[0].status == Status.FAIL
    assert findings[0].severity.value == "critical"


def test_apply_enables_versioning():
    s3 = configured_s3()
    s3.get_bucket_versioning.return_value = {}
    findings = _check_bucket(s3, "bucket", options("apply", ["AWS-S3-006"]))
    s3.put_bucket_versioning.assert_called_once()
    assert findings[0].status == Status.PASS


def test_plan_records_versioning_without_mutation():
    s3 = configured_s3()
    s3.get_bucket_versioning.return_value = {}
    findings = _check_bucket(s3, "bucket", options("plan", ["AWS-S3-006"]))
    s3.put_bucket_versioning.assert_not_called()
    assert findings[0].planned is True
    assert findings[0].before == "Disabled"
    assert findings[0].after == "Enabled"


def test_apply_sets_account_public_block():
    client = MagicMock()
    client.get_public_access_block.return_value = {"PublicAccessBlockConfiguration": {}}
    findings = _check_account_public_block(client, "123", options("apply"))
    client.put_public_access_block.assert_called_once()
    assert findings[0].status == Status.PASS


def test_apply_sets_missing_account_public_block():
    client = MagicMock()
    client.get_public_access_block.side_effect = ClientError(
        {"Error": {"Code": "NoSuchPublicAccessBlockConfiguration", "Message": "missing"}},
        "GetPublicAccessBlock",
    )
    findings = _check_account_public_block(client, "123", options("apply"))
    client.put_public_access_block.assert_called_once()
    assert findings[0].status == Status.PASS


def test_root_mfa_control_uses_account_summary():
    iam = MagicMock()
    iam.get_account_summary.return_value = {"SummaryMap": {"AccountMFAEnabled": 1}}
    session = MagicMock()
    session.client.return_value = iam
    findings = _check_aws_services(session, "123", options(controls=["AWS-IAM-001"]))
    assert len(findings) == 1
    assert findings[0].status == Status.PASS
