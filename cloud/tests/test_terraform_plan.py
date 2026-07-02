"""Tests for the Terraform plan scanner module."""
from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from cloud.core import Status
from cloud.terraform_plan import (
    _check_iam_star,
    _check_open_cidr,
    _check_public_s3,
    _check_unencrypted,
    audit_plan,
    run_audit,
)


@pytest.fixture
def scan_args():
    return SimpleNamespace(control=[], mode="audit", path=None)


def _resource_change(rtype: str, address: str, after: dict, actions=None):
    """Helper to create a resource_changes entry."""
    return {
        "type": rtype,
        "address": address,
        "change": {
            "actions": actions or ["create"],
            "after": after,
        },
    }


class TestCheckOpenCIDR:
    def test_detects_unrestricted_ingress(self):
        """Should detect 0.0.0.0/0 in security group rules."""
        change = _resource_change(
            "aws_security_group_rule", "module.sg.rule",
            {"cidr_blocks": ["0.0.0.0/0"]},
        )
        result = _check_open_cidr(change)
        assert result is not None
        assert result.status == Status.FAIL
        assert result.control_id == "TF-SEC-001"

    def test_passes_restricted_cidr(self):
        """Should pass with restricted CIDR."""
        change = _resource_change(
            "aws_security_group_rule", "module.sg.rule",
            {"cidr_blocks": ["10.0.0.0/8"]},
        )
        result = _check_open_cidr(change)
        assert result is None

    def test_ignores_non_sg_resources(self):
        """Should ignore non-security-group resources."""
        change = _resource_change(
            "aws_instance", "module.ec2.instance",
            {"cidr_blocks": ["0.0.0.0/0"]},
        )
        result = _check_open_cidr(change)
        assert result is None


class TestCheckPublicS3:
    def test_detects_public_read_acl(self):
        """Should detect public-read ACL."""
        change = _resource_change(
            "aws_s3_bucket", "module.bucket",
            {"acl": "public-read"},
        )
        result = _check_public_s3(change)
        assert result is not None
        assert result.status == Status.FAIL
        assert result.severity.value == "critical"

    def test_detects_public_read_write(self):
        """Should detect public-read-write ACL."""
        change = _resource_change(
            "aws_s3_bucket", "module.bucket",
            {"acl": "public-read-write"},
        )
        result = _check_public_s3(change)
        assert result is not None
        assert result.status == Status.FAIL

    def test_passes_private_acl(self):
        """Should pass private ACL."""
        change = _resource_change(
            "aws_s3_bucket", "module.bucket",
            {"acl": "private"},
        )
        result = _check_public_s3(change)
        assert result is None


class TestCheckIAMStar:
    def test_detects_wildcard_actions(self):
        """Should detect Action:* in IAM policies."""
        change = _resource_change(
            "aws_iam_policy", "module.iam.admin",
            {"policy": '{"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}'},
        )
        result = _check_iam_star(change)
        assert result is not None
        assert result.status == Status.FAIL
        assert result.severity.value == "critical"

    def test_passes_specific_actions(self):
        """Should pass with specific actions."""
        policy = (
            '{"Statement": [{"Effect": "Allow",'
            ' "Action": "s3:GetObject", "Resource": "*"}]}'
        )
        change = _resource_change(
            "aws_iam_policy", "module.iam.reader",
            {"policy": policy},
        )
        result = _check_iam_star(change)
        assert result is None


class TestCheckUnencrypted:
    def test_detects_unencrypted_ebs(self):
        """Should detect unencrypted EBS volumes."""
        change = _resource_change(
            "aws_ebs_volume", "module.ebs.vol",
            {"size": 100},  # No encryption fields
        )
        result = _check_unencrypted(change)
        assert result is not None
        assert result.status == Status.FAIL

    def test_passes_encrypted_ebs(self):
        """Should pass encrypted EBS volumes."""
        change = _resource_change(
            "aws_ebs_volume", "module.ebs.vol",
            {"size": 100, "encrypted": True},
        )
        result = _check_unencrypted(change)
        assert result is None

    def test_passes_kms_encrypted(self):
        """Should pass KMS encrypted resources."""
        change = _resource_change(
            "aws_rds_instance", "module.rds.db",
            {"kms_key_id": "arn:aws:kms:us-east-1:123:key/abc"},
        )
        result = _check_unencrypted(change)
        assert result is None


class TestAuditPlan:
    def test_parses_valid_plan(self, tmp_path, scan_args):
        """Should parse and audit a valid Terraform plan."""
        plan = {
            "resource_changes": [
                _resource_change(
                    "aws_security_group", "module.sg",
                    {"cidr_blocks": ["0.0.0.0/0"]},
                ),
            ],
        }
        plan_file = tmp_path / "plan.json"
        plan_file.write_text(json.dumps(plan), encoding="utf-8")
        findings = audit_plan(str(plan_file), scan_args)
        assert len(findings) == 1
        assert findings[0].status == Status.FAIL

    def test_handles_invalid_json(self, tmp_path, scan_args):
        """Should return error for invalid JSON."""
        plan_file = tmp_path / "bad.json"
        plan_file.write_text("not json", encoding="utf-8")
        findings = audit_plan(str(plan_file), scan_args)
        assert len(findings) == 1
        assert findings[0].status == Status.ERROR

    def test_handles_missing_file(self, scan_args):
        """Should return error for missing file."""
        findings = audit_plan("/nonexistent/plan.json", scan_args)
        assert len(findings) == 1
        assert findings[0].status == Status.ERROR

    def test_skips_delete_actions(self, tmp_path, scan_args):
        """Should skip resources being deleted."""
        plan = {
            "resource_changes": [
                {
                    "type": "aws_security_group",
                    "address": "module.sg",
                    "change": {
                        "actions": ["delete"],
                        "after": {"cidr_blocks": ["0.0.0.0/0"]},
                    },
                },
            ],
        }
        plan_file = tmp_path / "plan.json"
        plan_file.write_text(json.dumps(plan), encoding="utf-8")
        findings = audit_plan(str(plan_file), scan_args)
        assert len(findings) == 0


class TestRunAudit:
    def test_requires_path(self, scan_args):
        """Should return error when no path provided."""
        findings = run_audit(scan_args)
        assert len(findings) == 1
        assert findings[0].status == Status.ERROR
        assert "path" in findings[0].evidence.lower()

    def test_uses_path_argument(self, tmp_path, scan_args):
        """Should use the path argument."""
        plan = {"resource_changes": []}
        plan_file = tmp_path / "plan.json"
        plan_file.write_text(json.dumps(plan), encoding="utf-8")
        scan_args.path = str(plan_file)
        findings = run_audit(scan_args)
        assert len(findings) == 0
