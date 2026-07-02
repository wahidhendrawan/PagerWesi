"""Tests for the policy module."""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from cloud.policy import admin_ports, aws_setting, excluded, load_policy


class TestLoadPolicy:
    def test_none_returns_empty_dict(self):
        """None path should return empty dict."""
        assert load_policy(None) == {}

    def test_valid_policy_loads(self, tmp_path):
        """Should load a valid policy file."""
        policy_file = tmp_path / "policy.yml"
        policy_file.write_text(
            "version: 1\nnetwork:\n  azure_admin_ports: [22, 3389]\n",
            encoding="utf-8",
        )
        result = load_policy(policy_file)
        assert result["version"] == 1
        assert result["network"]["azure_admin_ports"] == [22, 3389]

    def test_rejects_missing_version(self, tmp_path):
        """Should reject policy without version."""
        policy_file = tmp_path / "policy.yml"
        policy_file.write_text("network:\n  ports: [22]\n", encoding="utf-8")
        with pytest.raises(ValueError, match="version"):
            load_policy(policy_file)

    def test_rejects_wrong_version(self, tmp_path):
        """Should reject policy with wrong version number."""
        policy_file = tmp_path / "policy.yml"
        policy_file.write_text("version: 2\n", encoding="utf-8")
        with pytest.raises(ValueError, match="version"):
            load_policy(policy_file)

    def test_rejects_oversized_policy(self, tmp_path):
        """Should reject policy exceeding 1 MiB."""
        policy_file = tmp_path / "policy.yml"
        policy_file.write_text("version: 1\n" + "x" * (1024 * 1024 + 1), encoding="utf-8")
        with pytest.raises(ValueError, match="1 MiB"):
            load_policy(policy_file)

    def test_rejects_non_mapping(self, tmp_path):
        """Should reject non-mapping YAML."""
        policy_file = tmp_path / "policy.yml"
        policy_file.write_text("- item1\n- item2\n", encoding="utf-8")
        with pytest.raises(ValueError, match="mapping"):
            load_policy(policy_file)


class TestAwsSetting:
    def test_returns_setting_value(self):
        """Should return aws setting value."""
        args = SimpleNamespace(
            policy={"aws": {"vpc_flow_log_destination_arn": "arn:aws:s3:::logs"}}
        )
        result = aws_setting(args, "vpc_flow_log_destination_arn")
        assert result == "arn:aws:s3:::logs"

    def test_returns_none_for_missing(self):
        """Should return None for missing keys."""
        args = SimpleNamespace(policy={"aws": {}})
        assert aws_setting(args, "nonexistent") is None

    def test_handles_empty_policy(self):
        """Should handle empty policy dict."""
        args = SimpleNamespace(policy={})
        assert aws_setting(args, "any_key") is None

    def test_handles_none_policy(self):
        """Should handle None policy."""
        args = SimpleNamespace(policy=None)
        assert aws_setting(args, "any_key") is None


class TestAdminPorts:
    def test_returns_policy_ports(self):
        """Should return ports from policy."""
        args = SimpleNamespace(policy={"network": {"azure_admin_ports": [22, 3389]}})
        result = admin_ports(args, "azure", {"22", "3389", "5985"})
        assert result == {"22", "3389"}

    def test_returns_defaults_when_no_policy(self):
        """Should return defaults when no policy override."""
        args = SimpleNamespace(policy={})
        defaults = {"22", "3389"}
        result = admin_ports(args, "azure", defaults)
        assert result == defaults


class TestExcluded:
    def test_matches_exact_pattern(self):
        """Should match exact resource patterns."""
        args = SimpleNamespace(policy={"exclude_resources": ["arn:aws:s3:::logs-*"]})
        assert excluded(args, "arn:aws:s3:::logs-bucket") is True
        assert excluded(args, "arn:aws:s3:::other-bucket") is False

    def test_no_exclusions(self):
        """Should return False with no exclusions."""
        args = SimpleNamespace(policy={})
        assert excluded(args, "any:resource") is False

    def test_wildcard_pattern(self):
        """Should support wildcard patterns."""
        args = SimpleNamespace(policy={"exclude_resources": ["*test*"]})
        assert excluded(args, "arn:aws:s3:::test-bucket") is True
