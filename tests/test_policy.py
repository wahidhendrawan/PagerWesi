from types import SimpleNamespace

from cloud.policy import admin_ports, aws_setting, excluded, load_policy


def test_policy_loads_ports_and_exclusions(tmp_path):
    path = tmp_path / "policy.yml"
    path.write_text(
        """version: 1
network:
  azure_admin_ports: [22, 8443]
exclude_resources:
  - 'arn:aws:s3:::public-*'
""",
        encoding="utf-8",
    )
    policy = load_policy(path)
    args = SimpleNamespace(policy=policy)
    assert admin_ports(args, "azure", {"22"}) == {"22", "8443"}
    assert excluded(args, "arn:aws:s3:::public-assets") is True


def test_policy_rejects_invalid_ports(tmp_path):
    path = tmp_path / "policy.yml"
    path.write_text(
        "version: 1\nnetwork:\n  gcp_admin_ports: [ssh]\n",
        encoding="utf-8",
    )
    try:
        load_policy(path)
    except ValueError as exc:
        assert "schema" in str(exc).lower() or "type" in str(exc).lower()
    else:
        raise AssertionError("ValueError was not raised")


def test_policy_honors_empty_port_override(tmp_path):
    path = tmp_path / "policy.yml"
    path.write_text(
        "version: 1\nnetwork:\n  azure_admin_ports: []\n",
        encoding="utf-8",
    )
    args = SimpleNamespace(policy=load_policy(path))
    assert admin_ports(args, "azure", {"22"}) == set()


def test_policy_loads_aws_apply_settings(tmp_path):
    path = tmp_path / "policy.yml"
    path.write_text(
        """version: 1
aws:
  vpc_flow_log_destination_arn: arn:aws:s3:::central-logs
""",
        encoding="utf-8",
    )
    args = SimpleNamespace(policy=load_policy(path))
    assert aws_setting(args, "vpc_flow_log_destination_arn") == "arn:aws:s3:::central-logs"
