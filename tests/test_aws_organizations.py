from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from cloud.core import Finding, Severity, Status
from cloud.providers.aws.baseline import _audit_organization_accounts
from cloud.providers.aws.organizations import (
    assumed_session,
    discover_active_accounts,
    session_in_region,
)


def test_discovers_only_active_organization_accounts():
    paginator = MagicMock()
    paginator.paginate.return_value = [
        {
            "Accounts": [
                {"Id": "111", "Status": "ACTIVE"},
                {"Id": "222", "Status": "SUSPENDED"},
            ]
        },
        {"Accounts": [{"Id": "333", "State": "ACTIVE"}]},
    ]
    session = MagicMock()
    session.client.return_value.get_paginator.return_value = paginator
    assert discover_active_accounts(session) == ["111", "333"]


def test_assume_role_uses_external_id():
    sts = MagicMock()
    sts.assume_role.return_value = {
        "Credentials": {
            "AccessKeyId": "access",
            "SecretAccessKey": "secret",
            "SessionToken": "token",
        }
    }
    base = MagicMock(region_name="ap-southeast-1")
    base.client.return_value = sts
    with patch("boto3.Session") as session_class:
        assumed_session(base, "123", "AuditRole", "external")
    sts.assume_role.assert_called_once_with(
        RoleArn="arn:aws:iam::123:role/AuditRole",
        RoleSessionName="pagerwesi-audit",
        ExternalId="external",
    )
    session_class.assert_called_once_with(
        aws_access_key_id="access",
        aws_secret_access_key="secret",
        aws_session_token="token",
        region_name="ap-southeast-1",
    )


def test_clone_assumed_session_for_region():
    frozen = SimpleNamespace(access_key="a", secret_key="s", token="t")
    session = MagicMock()
    session.get_credentials.return_value.get_frozen_credentials.return_value = frozen
    with patch("boto3.Session") as session_class:
        session_in_region(session, "eu-west-1")
    session_class.assert_called_once_with(
        aws_access_key_id="a",
        aws_secret_access_key="s",
        aws_session_token="t",
        region_name="eu-west-1",
    )


def test_organization_audit_continues_after_assume_role_failure():
    args = SimpleNamespace(
        organization_role="AuditRole", external_id=None, control=[], mode="audit"
    )
    successful_session = MagicMock()
    success = Finding("AWS-IAM-001", "ok", Status.PASS, Severity.INFO, "aws:account:222", "ok")
    with (
        patch(
            "cloud.providers.aws.baseline.discover_active_accounts",
            return_value=["111", "222"],
        ),
        patch(
            "cloud.providers.aws.baseline.assumed_session",
            side_effect=[RuntimeError("denied"), successful_session],
        ),
    ):
        findings = _audit_organization_accounts(MagicMock(), args, lambda _: [success])
    assert [(item.resource, item.status) for item in findings] == [
        ("aws:account:111", Status.ERROR),
        ("aws:account:222", Status.PASS),
    ]
