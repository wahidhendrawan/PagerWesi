"""Tests for the remediation playbook generation module."""
from __future__ import annotations

import json

from cloud.remediation import generate_playbook


class TestGeneratePlaybook:
    def test_terraform_format(self, tmp_path):
        """Should generate Terraform remediation code."""
        manifest = {
            "plans": [
                {
                    "control_id": "AWS-S3-001",
                    "resource": "aws:account:123456789012",
                    "remediation": "Enable public access block",
                },
            ],
        }
        manifest_path = tmp_path / "plan.json"
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

        result = generate_playbook(manifest_path, "terraform")
        assert "# Auto-generated Terraform" in result
        assert "aws_s3_account_public_access_block" in result

    def test_cloudformation_format(self, tmp_path):
        """Should generate CloudFormation remediation code."""
        manifest = {
            "plans": [
                {
                    "control_id": "AWS-S3-001",
                    "resource": "aws:account:123456789012",
                },
            ],
        }
        manifest_path = tmp_path / "plan.json"
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

        result = generate_playbook(manifest_path, "cloudformation")
        assert "# Auto-generated CloudFormation" in result
        assert "AccountPublicAccessBlock" in result

    def test_ebs_encryption_template(self, tmp_path):
        """Should generate EBS encryption Terraform."""
        manifest = {
            "plans": [
                {
                    "control_id": "AWS-EBS-001",
                    "resource": "aws:account:123456789012",
                },
            ],
        }
        manifest_path = tmp_path / "plan.json"
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

        result = generate_playbook(manifest_path, "terraform")
        assert "aws_ebs_encryption_by_default" in result

    def test_unknown_control_generates_comment(self, tmp_path):
        """Should add a comment for controls without templates."""
        manifest = {
            "plans": [
                {
                    "control_id": "UNKNOWN-001",
                    "resource": "unknown:resource",
                    "remediation": "Manual fix required",
                },
            ],
        }
        manifest_path = tmp_path / "plan.json"
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

        result = generate_playbook(manifest_path, "terraform")
        assert "no template available" in result
        assert "Manual fix required" in result

    def test_empty_manifest(self, tmp_path):
        """Should handle empty manifest gracefully."""
        manifest = {"plans": []}
        manifest_path = tmp_path / "plan.json"
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

        result = generate_playbook(manifest_path, "terraform")
        assert "# Auto-generated Terraform" in result

    def test_bucket_specific_template(self, tmp_path):
        """Should render bucket-specific resources."""
        manifest = {
            "plans": [
                {
                    "control_id": "AWS-S3-004",
                    "resource": "arn:aws:s3:::my-bucket",
                },
            ],
        }
        manifest_path = tmp_path / "plan.json"
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

        result = generate_playbook(manifest_path, "terraform")
        assert "my-bucket" in result
        assert "aws_s3_bucket_public_access_block" in result

    def test_vpc_flow_log_template(self, tmp_path):
        """Should render VPC flow log template."""
        manifest = {
            "plans": [
                {
                    "control_id": "AWS-VPC-001",
                    "resource": "aws:vpc",
                    "after": {
                        "missing_flow_logs": ["vpc-12345"],
                        "destination": "arn:aws:s3:::flow-logs",
                    },
                },
            ],
        }
        manifest_path = tmp_path / "plan.json"
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

        result = generate_playbook(manifest_path, "terraform")
        assert "aws_flow_log" in result

    def test_uses_changes_key(self, tmp_path):
        """Should also read from 'changes' key (apply manifests)."""
        manifest = {
            "changes": [
                {
                    "control_id": "AWS-EBS-001",
                    "resource": "aws:account:123456789012",
                },
            ],
        }
        manifest_path = tmp_path / "plan.json"
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

        result = generate_playbook(manifest_path, "terraform")
        assert "aws_ebs_encryption_by_default" in result
