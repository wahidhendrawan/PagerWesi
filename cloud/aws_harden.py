from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor, as_completed

from cloud.core import Finding, Severity, Status

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


def _finding(control_id, title, status, severity, resource, evidence, remediation=""):
    return Finding(control_id, title, status, severity, resource, evidence, remediation)


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
        compliant = all(config.get(key) is True for key in PUBLIC_BLOCK)
        if not compliant and args.mode == "apply":
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
            )
        ]
    except Exception as exc:
        return [
            _finding(
                control,
                "Account-level S3 public access is blocked",
                Status.ERROR,
                Severity.HIGH,
                f"aws:account:{account_id}",
                _client_error_code(exc),
                "Grant s3:GetAccountPublicAccessBlock and review the account setting.",
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
            findings.append(
                _finding(
                    "AWS-S3-004",
                    "Bucket-level public access is blocked",
                    Status.PASS if compliant else Status.FAIL,
                    Severity.HIGH,
                    resource,
                    json.dumps(config, sort_keys=True) if config else read_error,
                    "Enable all four bucket-level S3 Public Access Block settings.",
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
            findings.append(
                _finding(
                    "AWS-S3-005",
                    "Default bucket encryption is enabled",
                    Status.PASS if encrypted else Status.FAIL,
                    Severity.MEDIUM,
                    resource,
                    encryption_error or f"Encryption rule count={len(rules)}",
                    "Enable default SSE-S3 or SSE-KMS encryption.",
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
        try:
            state = s3.get_bucket_versioning(Bucket=bucket).get("Status", "Disabled")
            if state != "Enabled" and args.mode == "apply":
                s3.put_bucket_versioning(
                    Bucket=bucket, VersioningConfiguration={"Status": "Enabled"}
                )
                state = "Enabled (applied)"
            findings.append(
                _finding(
                    "AWS-S3-006",
                    "Bucket versioning is enabled",
                    Status.PASS if state.startswith("Enabled") else Status.FAIL,
                    Severity.MEDIUM,
                    resource,
                    f"Versioning={state}",
                    "Enable S3 bucket versioning.",
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


def _check_aws_services(session, account_id: str, args) -> list[Finding]:
    findings: list[Finding] = []
    account = f"aws:account:{account_id}"

    if _selected(args, "AWS-IAM-001"):
        try:
            summary = session.client("iam").get_account_summary()["SummaryMap"]
            enabled = summary.get("AccountMFAEnabled", 0) == 1
            findings.append(
                _finding(
                    "AWS-IAM-001",
                    "Root account MFA is enabled",
                    Status.PASS if enabled else Status.FAIL,
                    Severity.CRITICAL,
                    account,
                    f"AccountMFAEnabled={summary.get('AccountMFAEnabled', 0)}",
                    "Enable phishing-resistant MFA for the AWS root user.",
                )
            )
        except Exception as exc:
            findings.append(
                _finding(
                    "AWS-IAM-001",
                    "Root account MFA is enabled",
                    Status.ERROR,
                    Severity.CRITICAL,
                    account,
                    _client_error_code(exc),
                )
            )

    if _selected(args, "AWS-CT-001"):
        try:
            client = session.client("cloudtrail")
            trails = client.describe_trails(includeShadowTrails=False).get("trailList", [])
            active = []
            for trail in trails:
                status = client.get_trail_status(Name=trail["TrailARN"])
                if trail.get("IsMultiRegionTrail") and status.get("IsLogging"):
                    active.append(trail["TrailARN"])
            findings.append(
                _finding(
                    "AWS-CT-001",
                    "A multi-region CloudTrail trail is logging",
                    Status.PASS if active else Status.FAIL,
                    Severity.HIGH,
                    account,
                    f"Active multi-region trails={len(active)}",
                    "Configure a protected multi-region organization trail.",
                )
            )
        except Exception as exc:
            findings.append(
                _finding(
                    "AWS-CT-001",
                    "A multi-region CloudTrail trail is logging",
                    Status.ERROR,
                    Severity.HIGH,
                    account,
                    _client_error_code(exc),
                )
            )

    if _selected(args, "AWS-CONFIG-001"):
        try:
            statuses = (
                session.client("config")
                .describe_configuration_recorder_status()
                .get("ConfigurationRecordersStatus", [])
            )
            recording = [item for item in statuses if item.get("recording")]
            findings.append(
                _finding(
                    "AWS-CONFIG-001",
                    "AWS Config recording is enabled",
                    Status.PASS if recording else Status.FAIL,
                    Severity.HIGH,
                    account,
                    f"Active recorders={len(recording)}",
                    "Enable AWS Config recording in every governed region.",
                )
            )
        except Exception as exc:
            findings.append(
                _finding(
                    "AWS-CONFIG-001",
                    "AWS Config recording is enabled",
                    Status.ERROR,
                    Severity.HIGH,
                    account,
                    _client_error_code(exc),
                )
            )

    if _selected(args, "AWS-GD-001"):
        try:
            detectors = session.client("guardduty").list_detectors().get("DetectorIds", [])
            findings.append(
                _finding(
                    "AWS-GD-001",
                    "GuardDuty is enabled",
                    Status.PASS if detectors else Status.FAIL,
                    Severity.HIGH,
                    account,
                    f"Detector count={len(detectors)}",
                    "Enable GuardDuty, preferably through delegated organization administration.",
                )
            )
        except Exception as exc:
            findings.append(
                _finding(
                    "AWS-GD-001",
                    "GuardDuty is enabled",
                    Status.ERROR,
                    Severity.HIGH,
                    account,
                    _client_error_code(exc),
                )
            )

    if _selected(args, "AWS-SH-001"):
        try:
            hub = session.client("securityhub").describe_hub()
            enabled = bool(hub.get("HubArn"))
            evidence = hub.get("HubArn", "Security Hub is not enabled")
            security_hub_status = Status.PASS if enabled else Status.FAIL
        except Exception as exc:
            code = _client_error_code(exc)
            evidence = code
            security_hub_status = (
                Status.FAIL
                if code in {"InvalidAccessException", "ResourceNotFoundException"}
                else Status.ERROR
            )
        findings.append(
            _finding(
                "AWS-SH-001",
                "Security Hub is enabled",
                security_hub_status,
                Severity.HIGH,
                account,
                evidence,
                "Enable Security Hub standards through organization administration.",
            )
        )

    if _selected(args, "AWS-EC2-001"):
        try:
            groups = session.client("ec2").describe_security_groups(
                Filters=[{"Name": "group-name", "Values": ["default"]}]
            )["SecurityGroups"]
            exposed = [
                group["GroupId"]
                for group in groups
                if group.get("IpPermissions") or group.get("IpPermissionsEgress")
            ]
            findings.append(
                _finding(
                    "AWS-EC2-001",
                    "Default security groups have no rules",
                    Status.FAIL if exposed else Status.PASS,
                    Severity.MEDIUM,
                    account,
                    f"Default groups with rules={','.join(exposed) or 'none'}",
                    "Remove ingress and egress rules from default security groups in every VPC.",
                )
            )
        except Exception as exc:
            findings.append(
                _finding(
                    "AWS-EC2-001",
                    "Default security groups have no rules",
                    Status.ERROR,
                    Severity.MEDIUM,
                    account,
                    _client_error_code(exc),
                )
            )

    if _selected(args, "AWS-KMS-001"):
        try:
            client = session.client("kms")
            keys = client.list_keys().get("Keys", [])
            customer_keys = []
            rotation_disabled = []
            for key in keys:
                key_id = key["KeyId"]
                metadata = client.describe_key(KeyId=key_id)["KeyMetadata"]
                if (
                    metadata.get("KeyManager") != "CUSTOMER"
                    or metadata.get("KeySpec") != "SYMMETRIC_DEFAULT"
                ):
                    continue
                customer_keys.append(key_id)
                if not client.get_key_rotation_status(KeyId=key_id).get("KeyRotationEnabled"):
                    rotation_disabled.append(key_id)
            findings.append(
                _finding(
                    "AWS-KMS-001",
                    "Customer-managed symmetric KMS keys rotate",
                    Status.PASS if not rotation_disabled else Status.FAIL,
                    Severity.MEDIUM,
                    account,
                    f"Eligible={len(customer_keys)}, rotation disabled={len(rotation_disabled)}",
                    "Enable automatic rotation for eligible customer-managed symmetric KMS keys.",
                )
            )
        except Exception as exc:
            findings.append(
                _finding(
                    "AWS-KMS-001",
                    "Customer-managed symmetric KMS keys rotate",
                    Status.ERROR,
                    Severity.MEDIUM,
                    account,
                    _client_error_code(exc),
                )
            )

    return findings


def run_audit(args=None) -> list[Finding]:
    if args is None:
        from types import SimpleNamespace

        args = SimpleNamespace(
            control=[],
            profile=None,
            profiles=None,
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
    sts = base_session.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    configured_regions = [
        item.strip() for item in (getattr(args, "regions", None) or "").split(",") if item.strip()
    ]
    regions = configured_regions or [args.region or base_session.region_name or "us-east-1"]
    findings = []
    for region in regions:
        session = boto3.Session(profile_name=args.profile, region_name=region)
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
