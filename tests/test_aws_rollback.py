import json
from unittest.mock import MagicMock

from cloud.core import Status
from cloud.providers.aws.rollback import rollback_manifest


def _manifest(tmp_path, changes):
    path = tmp_path / "changes.json"
    path.write_text(
        json.dumps({"schema_version": "1.0", "provider": "aws", "changes": changes}),
        encoding="utf-8",
    )
    return path


def test_rollback_restores_reversible_s3_settings(tmp_path):
    s3 = MagicMock()
    s3control = MagicMock()
    session = MagicMock()
    session.client.side_effect = lambda name: {"s3": s3, "s3control": s3control}[name]
    changes = [
        {
            "control_id": "AWS-S3-001",
            "resource": "aws:account:123456789012",
            "before": {},
            "after": {"BlockPublicAcls": True},
        },
        {
            "control_id": "AWS-S3-004",
            "resource": "arn:aws:s3:::bucket",
            "before": {"BlockPublicAcls": False},
            "after": {"BlockPublicAcls": True},
        },
        {
            "control_id": "AWS-S3-005",
            "resource": "arn:aws:s3:::bucket",
            "before": None,
            "after": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}],
        },
    ]
    findings = rollback_manifest(session, _manifest(tmp_path, changes))
    s3.delete_bucket_encryption.assert_called_once_with(Bucket="bucket")
    s3.put_public_access_block.assert_called_once_with(
        Bucket="bucket", PublicAccessBlockConfiguration={"BlockPublicAcls": False}
    )
    s3control.delete_public_access_block.assert_called_once_with(AccountId="123456789012")
    assert all(item.status == Status.PASS for item in findings)


def test_rollback_marks_versioning_as_manual(tmp_path):
    session = MagicMock()
    changes = [
        {
            "control_id": "AWS-S3-006",
            "resource": "arn:aws:s3:::bucket",
            "before": "Disabled",
            "after": "Enabled",
        }
    ]
    findings = rollback_manifest(session, _manifest(tmp_path, changes))
    assert findings[0].status == Status.MANUAL


def test_rollback_rejects_non_aws_manifest(tmp_path):
    path = tmp_path / "changes.json"
    path.write_text(
        json.dumps({"schema_version": "1.0", "provider": "gcp", "changes": []}),
        encoding="utf-8",
    )
    try:
        rollback_manifest(MagicMock(), path)
    except ValueError as exc:
        assert "AWS" in str(exc)
    else:
        raise AssertionError("ValueError was not raised")


def test_rollback_ebs_encryption(tmp_path):
    ec2 = MagicMock()
    session = MagicMock()
    session.client.side_effect = lambda name: {"ec2": ec2}[name]
    changes = [
        {
            "control_id": "AWS-EBS-001",
            "resource": "aws:account:123456789012",
            "before": False,
            "after": True,
        }
    ]
    findings = rollback_manifest(session, _manifest(tmp_path, changes))
    ec2.disable_ebs_encryption_by_default.assert_called_once()
    assert findings[0].status == Status.PASS


def test_rollback_access_analyzer(tmp_path):
    analyzer = MagicMock()
    session = MagicMock()
    session.client.side_effect = lambda name: {"accessanalyzer": analyzer}[name]
    changes = [
        {
            "control_id": "AWS-IAM-002",
            "resource": "aws:account:123456789012",
            "before": {"active_analyzers": 0},
            "after": {"active_analyzers": 1, "analyzer_name": "pagerwesi-account"},
        }
    ]
    findings = rollback_manifest(session, _manifest(tmp_path, changes))
    analyzer.delete_analyzer.assert_called_once_with(analyzerName="pagerwesi-account")
    assert findings[0].status == Status.PASS


def test_rollback_vpc_flow_logs(tmp_path):
    ec2 = MagicMock()
    session = MagicMock()
    session.client.side_effect = lambda name: {"ec2": ec2}[name]
    changes = [
        {
            "control_id": "AWS-VPC-001",
            "resource": "aws:account:123456789012",
            "before": {"missing_flow_logs": ["vpc-1"]},
            "after": {"flow_log_ids": ["fl-1", "fl-2"], "destination": "arn:aws:s3:::logs"},
        }
    ]
    findings = rollback_manifest(session, _manifest(tmp_path, changes))
    ec2.delete_flow_logs.assert_called_once_with(FlowLogIds=["fl-1", "fl-2"])
    assert findings[0].status == Status.PASS


def test_rollback_vpc_flow_logs_manual_when_no_ids(tmp_path):
    session = MagicMock()
    changes = [
        {
            "control_id": "AWS-VPC-001",
            "resource": "aws:account:123456789012",
            "before": {"missing_flow_logs": ["vpc-1"]},
            "after": {"destination": "arn:aws:s3:::logs"},
        }
    ]
    findings = rollback_manifest(session, _manifest(tmp_path, changes))
    assert findings[0].status == Status.MANUAL
