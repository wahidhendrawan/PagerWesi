from __future__ import annotations

import fnmatch
from pathlib import Path

import yaml


def load_policy(path: Path | None) -> dict:
    if path is None:
        return {}
    content = path.read_text(encoding="utf-8")
    if len(content.encode("utf-8")) > 1024 * 1024:
        raise ValueError("Policy must not exceed 1 MiB")
    document = yaml.safe_load(content)
    if not isinstance(document, dict) or document.get("version") != 1:
        raise ValueError("Policy must be a mapping with version: 1")
    unknown = set(document) - {"version", "network", "aws", "exclude_resources"}
    if unknown:
        raise ValueError(f"Unknown policy key(s): {', '.join(sorted(unknown))}")
    network = document.get("network", {})
    aws = document.get("aws", {})
    exclusions = document.get("exclude_resources", [])
    if (
        not isinstance(network, dict)
        or not isinstance(aws, dict)
        or not isinstance(exclusions, list)
    ):
        raise ValueError(
            "Policy network and aws must be mappings and exclude_resources must be a list"
        )
    unknown_network = set(network) - {"azure_admin_ports", "gcp_admin_ports"}
    if unknown_network:
        raise ValueError(f"Unknown policy network key(s): {', '.join(sorted(unknown_network))}")
    for key in ("azure_admin_ports", "gcp_admin_ports"):
        values = network.get(key, [])
        if not isinstance(values, list) or any(
            not str(value).isdigit() or not 1 <= int(value) <= 65535 for value in values
        ):
            raise ValueError(f"Policy {key} must contain ports from 1 through 65535")
    if any(not isinstance(pattern, str) or not pattern for pattern in exclusions):
        raise ValueError("Policy exclude_resources entries must be non-empty strings")
    unknown_aws = set(aws) - {"vpc_flow_log_destination_arn", "vpc_flow_log_iam_role_arn"}
    if unknown_aws:
        raise ValueError(f"Unknown policy aws key(s): {', '.join(sorted(unknown_aws))}")
    for key in ("vpc_flow_log_destination_arn", "vpc_flow_log_iam_role_arn"):
        value = aws.get(key)
        if value is not None and (not isinstance(value, str) or not value.startswith("arn:")):
            raise ValueError(f"Policy aws.{key} must be an ARN string")
    return document


def aws_setting(args, key: str) -> str | None:
    policy = getattr(args, "policy", {}) or {}
    value = policy.get("aws", {}).get(key)
    return str(value) if value else None


def admin_ports(args, provider: str, defaults: set[str]) -> set[str]:
    policy = getattr(args, "policy", {}) or {}
    network = policy.get("network", {})
    key = f"{provider}_admin_ports"
    return {str(port) for port in network[key]} if key in network else defaults


def excluded(args, resource: str) -> bool:
    policy = getattr(args, "policy", {}) or {}
    return any(
        fnmatch.fnmatchcase(resource, pattern) for pattern in policy.get("exclude_resources", [])
    )
