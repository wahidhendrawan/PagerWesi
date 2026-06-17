from __future__ import annotations

import json

from cloud.core import Finding, Severity, Status

CONTROL_IDS = {"TF-SEC-001", "TF-SEC-002", "TF-SEC-003", "TF-SEC-004"}


def _finding(control_id, title, status, severity, resource, evidence, remediation=""):
    return Finding(
        control_id, title, status, severity, resource, evidence, remediation
    )


def _check_open_cidr(change: dict) -> Finding | None:
    """TF-SEC-001: SG rule allowing 0.0.0.0/0."""
    rtype = change.get("type", "")
    if "security_group_rule" not in rtype and "security_group" not in rtype:
        return None
    after = change.get("change", {}).get("after", {}) or {}
    cidrs = after.get("cidr_blocks", [])
    if isinstance(cidrs, list) and "0.0.0.0/0" in cidrs:
        return _finding(
            "TF-SEC-001",
            "Security group allows unrestricted ingress",
            Status.FAIL, Severity.HIGH,
            change.get("address", "unknown"),
            "cidr_blocks contains 0.0.0.0/0",
            "Restrict CIDR blocks to specific IP ranges.",
        )
    return None


def _check_public_s3(change: dict) -> Finding | None:
    """TF-SEC-002: Public S3 bucket."""
    if "aws_s3_bucket" not in change.get("type", ""):
        return None
    after = change.get("change", {}).get("after", {}) or {}
    acl = after.get("acl", "")
    if acl in ("public-read", "public-read-write"):
        return _finding(
            "TF-SEC-002",
            "S3 bucket with public ACL",
            Status.FAIL, Severity.CRITICAL,
            change.get("address", "unknown"),
            f"acl={acl}",
            "Set ACL to private and use bucket policies.",
        )
    return None


def _check_iam_star(change: dict) -> Finding | None:
    """TF-SEC-003: IAM policy with * actions."""
    if "iam_policy" not in change.get("type", ""):
        return None
    after = change.get("change", {}).get("after", {}) or {}
    policy_str = after.get("policy", "")
    if isinstance(policy_str, str) and '"Action":"*"' in policy_str.replace(
        " ", ""
    ).replace("'", '"'):
        return _finding(
            "TF-SEC-003",
            "IAM policy with wildcard actions",
            Status.FAIL, Severity.CRITICAL,
            change.get("address", "unknown"),
            "Action=* in policy document",
            "Restrict IAM actions to least privilege.",
        )
    return None


def _check_unencrypted(change: dict) -> Finding | None:
    """TF-SEC-004: Unencrypted resources."""
    after = change.get("change", {}).get("after", {}) or {}
    rtype = change.get("type", "")
    encrypt_fields = ["encrypted", "kms_key_id", "encryption_configuration"]
    if any(k in rtype for k in ("aws_ebs", "aws_rds", "aws_s3_bucket")):
        has_encryption = any(after.get(f) for f in encrypt_fields)
        if not has_encryption:
            return _finding(
                "TF-SEC-004",
                "Resource lacks encryption configuration",
                Status.FAIL, Severity.HIGH,
                change.get("address", "unknown"),
                "No encryption field set",
                "Enable encryption at rest for this resource.",
            )
    return None


def audit_plan(plan_path: str, args) -> list[Finding]:
    try:
        with open(plan_path, encoding="utf-8") as f:
            plan = json.load(f)
    except (OSError, json.JSONDecodeError) as exc:
        return [_finding(
            "TF-SEC-001", "Terraform plan parse",
            Status.ERROR, Severity.HIGH, plan_path,
            f"{type(exc).__name__}: {exc}",
        )]

    changes = plan.get("resource_changes", [])
    findings: list[Finding] = []
    checkers = [
        _check_open_cidr,
        _check_public_s3,
        _check_iam_star,
        _check_unencrypted,
    ]
    for change in changes:
        actions = change.get("change", {}).get("actions", [])
        if "create" not in actions and "update" not in actions:
            continue
        for checker in checkers:
            result = checker(change)
            if result:
                findings.append(result)
    return findings


def run_audit(args) -> list[Finding]:
    plan_path = getattr(args, "plan", None) or getattr(args, "path", None)
    if not plan_path:
        return [_finding(
            "TF-SEC-001", "Terraform plan path required",
            Status.ERROR, Severity.HIGH, "terraform:plan",
            "No --plan or --path argument provided.",
            "Provide path to terraform plan JSON output.",
        )]
    return audit_plan(plan_path, args)
