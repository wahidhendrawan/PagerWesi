from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from types import SimpleNamespace

from cloud.core import Finding, Severity, Status
from cloud.providers.aws.organizations import (
    assumed_session,
    discover_active_accounts,
    session_in_region,
)
from cloud.providers.aws.services import check_aws_services as _check_aws_services

ALL_USERS = "http://acs.amazonaws.com/groups/global/AllUsers"
AUTHENTICATED_USERS = "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"
PUBLIC_BLOCK = {
    "BlockPublicAcls": True,
    "IgnorePublicAcls": True,
    "BlockPublicPolicy": True,
    "RestrictPublicBuckets": True,
}
CONTROL_IDS = {
    "AWS-S3-001",
    "AWS-S3-002",
    "AWS-S3-003",
    "AWS-S3-004",
    "AWS-S3-005",
    "AWS-S3-006",
    "AWS-S3-007",
    "AWS-IAM-001",
    "AWS-CT-001",
    "AWS-CONFIG-001",
    "AWS-GD-001",
    "AWS-SH-001",
    "AWS-EC2-001",
    "AWS-KMS-001",
}


def _finding(
    control_id, title, status, severity, resource, evidence, remediation="", changed=False
):
    return Finding(
        control_id, title, status, severity, resource, evidence, remediation, changed=changed
    )


def _selected(args, control_id: str) -> bool:
    return not args.control or control_id in args.control


def _client_error_code(exc: Exception) -> str:
    return getattr(exc, "response", {}).get("Error", {}).get("Code", type(exc).__name__)


def _check_account_public_block(s3control, account_id: str, args) -> list[Finding]:
    control = "AWS-S3-001"
    if not _selected(args, control):
        return []
    try:
        config = s3control.get_public_access_block(AccountId=account_id)[
            "PublicAccessBlockConfiguration"
        ]
    except Exception as exc:
        code = _client_error_code(exc)
        if code == "NoSuchPublicAccessBlockConfiguration":
            config = {}
        else:
            return [
                _finding(
                    control,
                    "Account-level S3 public access is blocked",
                    Status.ERROR,
                    Severity.HIGH,
                    f"aws:account:{account_id}",
                    code,
                    "Grant s3:GetAccountPublicAccessBlock and review the account setting.",
                )
            ]
    compliant = all(config.get(key) is True for key in PUBLIC_BLOCK)
    applied = not compliant and args.mode == "apply"
    if applied:
        s3control.put_public_access_block(
            AccountId=account_id, PublicAccessBlockConfiguration=PUBLIC_BLOCK
        )
        config, compliant = PUBLIC_BLOCK, True
    status = Status.PASS if compliant else Status.FAIL
    prefix = "Applied; " if args.mode == "apply" and compliant else ""
    return [
        _finding(
            control,
            "Account-level S3 public access is blocked",
            status,
            Severity.HIGH,
            f"aws:account:{account_id}",
            prefix + json.dumps(config, sort_keys=True),
            "Enable all four account-level S3 Public Access Block settings.",
            changed=applied,
        )
    ]


def _check_bucket(s3, bucket: str, args) -> list[Finding]:
    findings: list[Finding] = []
    resource = f"arn:aws:s3:::{bucket}"

    if _selected(args, "AWS-S3-002"):
        try:
            grants = s3.get_bucket_acl(Bucket=bucket).get("Grants", [])
            public_grants = [
                grant
                for grant in grants
                if grant.get("Grantee", {}).get("URI") in {ALL_USERS, AUTHENTICATED_USERS}
            ]
            findings.append(
                _finding(
                    "AWS-S3-002",
                    "Bucket ACL does not grant public access",
                    Status.PASS if not public_grants else Status.FAIL,
                    Severity.CRITICAL,
                    resource,
                    "No public ACL grants"
                    if not public_grants
                    else f"{len(public_grants)} public ACL grant(s)",
                    "Remove grants to AllUsers and AuthenticatedUsers; prefer "
                    "bucket-owner-enforced ownership.",
                )
            )
        except Exception as exc:
            findings.append(
                _finding(
                    "AWS-S3-002",
                    "Bucket ACL does not grant public access",
                    Status.ERROR,
                    Severity.HIGH,
                    resource,
                    _client_error_code(exc),
                )
            )

    if _selected(args, "AWS-S3-003"):
        try:
            public = s3.get_bucket_policy_status(Bucket=bucket)["PolicyStatus"].get(
                "IsPublic", False
            )
            findings.append(
                _finding(
                    "AWS-S3-003",
                    "Bucket policy is not public",
                    Status.FAIL if public else Status.PASS,
                    Severity.CRITICAL,
                    resource,
                    f"PolicyStatus.IsPublic={public}",
                    "Restrict public principals and conditions in the bucket policy.",
                )
            )
        except Exception as exc:
            code = _client_error_code(exc)
            status = Status.PASS if code in {"NoSuchBucketPolicy", "NoSuchPolicy"} else Status.ERROR
            findings.append(
                _finding(
                    "AWS-S3-003",
                    "Bucket policy is not public",
                    status,
                    Severity.CRITICAL,
                    resource,
                    code,
                )
            )

    if _selected(args, "AWS-S3-004"):
        applied = False
        try:
            config = s3.get_public_access_block(Bucket=bucket)["PublicAccessBlockConfiguration"]
            compliant = all(config.get(key) is True for key in PUBLIC_BLOCK)
        except Exception as exc:
            config = {}
            compliant = False
            read_error = _client_error_code(exc)
        else:
            read_error = ""
        try:
            if not compliant and args.mode == "apply":
                s3.put_public_access_block(
                    Bucket=bucket, PublicAccessBlockConfiguration=PUBLIC_BLOCK
                )
                config, compliant, read_error = PUBLIC_BLOCK, True, ""
                applied = True
            findings.append(
                _finding(
                    "AWS-S3-004",
                    "Bucket-level public access is blocked",
                    Status.PASS if compliant else Status.FAIL,
                    Severity.HIGH,
                    resource,
                    json.dumps(config, sort_keys=True) if config else read_error,
                    "Enable all four bucket-level S3 Public Access Block settings.",
                    changed=applied,
                )
            )
        except Exception as exc:
            findings.append(
                _finding(
                    "AWS-S3-004",
                    "Bucket-level public access is blocked",
                    Status.ERROR,
                    Severity.HIGH,
                    resource,
                    _client_error_code(exc),
                )
            )

    if _selected(args, "AWS-S3-005"):
        applied = False
        try:
            rules = s3.get_bucket_encryption(Bucket=bucket)["ServerSideEncryptionConfiguration"][
                "Rules"
            ]
            encrypted = bool(rules)
        except Exception as exc:
            encrypted = False
            encryption_error = _client_error_code(exc)
        else:
            encryption_error = ""
        try:
            if not encrypted and args.mode == "apply":
                s3.put_bucket_encryption(
                    Bucket=bucket,
                    ServerSideEncryptionConfiguration={
                        "Rules": [
                            {
                                "ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"},
                                "BucketKeyEnabled": True,
                            }
                        ]
                    },
                )
                encrypted, encryption_error = True, "Applied AES256 default encryption"
                applied = True
            findings.append(
                _finding(
                    "AWS-S3-005",
                    "Default bucket encryption is enabled",
                    Status.PASS if encrypted else Status.FAIL,
                    Severity.MEDIUM,
                    resource,
                    encryption_error or f"Encryption rule count={len(rules)}",
                    "Enable default SSE-S3 or SSE-KMS encryption.",
                    changed=applied,
                )
            )
        except Exception as exc:
            findings.append(
                _finding(
                    "AWS-S3-005",
                    "Default bucket encryption is enabled",
                    Status.ERROR,
                    Severity.MEDIUM,
                    resource,
                    _client_error_code(exc),
                )
            )

    if _selected(args, "AWS-S3-006"):
        applied = False
        try:
            state = s3.get_bucket_versioning(Bucket=bucket).get("Status", "Disabled")
            if state != "Enabled" and args.mode == "apply":
                s3.put_bucket_versioning(
                    Bucket=bucket, VersioningConfiguration={"Status": "Enabled"}
                )
                state = "Enabled (applied)"
                applied = True
            findings.append(
                _finding(
                    "AWS-S3-006",
                    "Bucket versioning is enabled",
                    Status.PASS if state.startswith("Enabled") else Status.FAIL,
                    Severity.MEDIUM,
                    resource,
                    f"Versioning={state}",
                    "Enable S3 bucket versioning.",
                    changed=applied,
                )
            )
        except Exception as exc:
            findings.append(
                _finding(
                    "AWS-S3-006",
                    "Bucket versioning is enabled",
                    Status.ERROR,
                    Severity.MEDIUM,
                    resource,
                    _client_error_code(exc),
                )
            )

    if _selected(args, "AWS-S3-007"):
        try:
            logging = s3.get_bucket_logging(Bucket=bucket).get("LoggingEnabled")
            findings.append(
                _finding(
                    "AWS-S3-007",
                    "Server access logging is configured",
                    Status.PASS if logging else Status.FAIL,
                    Severity.LOW,
                    resource,
                    json.dumps(logging, sort_keys=True) if logging else "LoggingEnabled is absent",
                    "Send access logs to a dedicated, protected logging bucket.",
                )
            )
        except Exception as exc:
            findings.append(
                _finding(
                    "AWS-S3-007",
                    "Server access logging is configured",
                    Status.ERROR,
                    Severity.LOW,
                    resource,
                    _client_error_code(exc),
                )
            )

    return findings


def run_audit(args=None) -> list[Finding]:
    if args is None:
        args = SimpleNamespace(
            control=[],
            profile=None,
            profiles=None,
            organization_role=None,
            external_id=None,
            region=None,
            regions=None,
            workers=8,
            mode="audit",
        )
    try:
        import boto3
    except ImportError as exc:
        raise RuntimeError("Install the AWS dependencies with: pip install -e '.[aws]'") from exc

    configured_profiles = [
        item.strip() for item in (getattr(args, "profiles", None) or "").split(",") if item.strip()
    ]
    if configured_profiles:
        findings = []
        for profile in configured_profiles:
            profile_args = SimpleNamespace(**vars(args))
            profile_args.profile = profile
            profile_args.profiles = None
            findings.extend(run_audit(profile_args))
        return sorted(findings, key=lambda item: (item.resource, item.control_id))

    base_session = boto3.Session(profile_name=args.profile, region_name=args.region)
    if getattr(args, "organization_role", None):
        findings = []
        for account_id in discover_active_accounts(base_session):
            account_args = SimpleNamespace(**vars(args))
            account_args.organization_role = None
            account_args._session = assumed_session(
                base_session, account_id, args.organization_role, args.external_id
            )
            findings.extend(run_audit(account_args))
        return sorted(findings, key=lambda item: (item.resource, item.control_id))

    injected_session = getattr(args, "_session", None)
    if injected_session is not None:
        base_session = injected_session
    sts = base_session.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    configured_regions = [
        item.strip() for item in (getattr(args, "regions", None) or "").split(",") if item.strip()
    ]
    regions = configured_regions or [args.region or base_session.region_name or "us-east-1"]
    findings = []
    for region in regions:
        session = (
            session_in_region(base_session, region)
            if injected_session is not None
            else boto3.Session(profile_name=args.profile, region_name=region)
        )
        regional_args = SimpleNamespace(**vars(args))
        regional_args.region = region
        findings.extend(_check_aws_services(session, account_id, regional_args))
    s3_selected = not args.control or any(item.startswith("AWS-S3-") for item in args.control)
    if s3_selected:
        region = regions[0]
        s3 = base_session.client("s3", region_name=region)
        s3control = base_session.client("s3control", region_name=region)
        findings.extend(_check_account_public_block(s3control, account_id, args))
        buckets = [item["Name"] for item in s3.list_buckets().get("Buckets", [])]
    else:
        s3 = None
        buckets = []
    workers = max(1, min(args.workers, 32))
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = [executor.submit(_check_bucket, s3, bucket, args) for bucket in buckets]
        for future in as_completed(futures):
            findings.extend(future.result())
    return sorted(findings, key=lambda item: (item.control_id, item.resource))


def audit_s3_public_access():
    """Compatibility wrapper for the original public function."""
    findings = run_audit()
    for finding in findings:
        if finding.control_id in {"AWS-S3-002", "AWS-S3-003", "AWS-S3-004"}:
            marker = "+" if finding.status == Status.PASS else "!"
            print(f"[{marker}] {finding.resource}: {finding.evidence}")
