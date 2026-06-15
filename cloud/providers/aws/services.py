from __future__ import annotations

from cloud.core import Finding, Severity, Status


def _selected(args, control_id):
    return not args.control or control_id in args.control


def _error_code(exc):
    return getattr(exc, "response", {}).get("Error", {}).get("Code", type(exc).__name__)


def _finding(control, title, status, severity, account, evidence, remediation=""):
    return Finding(control, title, status, severity, account, evidence, remediation)


def check_aws_services(session, account_id: str, args) -> list[Finding]:
    findings = []
    account = f"aws:account:{account_id}"

    if _selected(args, "AWS-IAM-001"):
        title = "Root account MFA is enabled"
        try:
            summary = session.client("iam").get_account_summary()["SummaryMap"]
            enabled = summary.get("AccountMFAEnabled", 0) == 1
            findings.append(
                _finding(
                    "AWS-IAM-001",
                    title,
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
                    "AWS-IAM-001", title, Status.ERROR, Severity.CRITICAL, account, _error_code(exc)
                )
            )

    if _selected(args, "AWS-CT-001"):
        title = "A multi-region CloudTrail trail is logging"
        try:
            client = session.client("cloudtrail")
            trails = client.describe_trails(includeShadowTrails=False).get("trailList", [])
            active = [
                trail["TrailARN"]
                for trail in trails
                if trail.get("IsMultiRegionTrail")
                and client.get_trail_status(Name=trail["TrailARN"]).get("IsLogging")
            ]
            findings.append(
                _finding(
                    "AWS-CT-001",
                    title,
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
                    "AWS-CT-001", title, Status.ERROR, Severity.HIGH, account, _error_code(exc)
                )
            )

    if _selected(args, "AWS-CONFIG-001"):
        title = "AWS Config recording is enabled"
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
                    title,
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
                    "AWS-CONFIG-001", title, Status.ERROR, Severity.HIGH, account, _error_code(exc)
                )
            )

    if _selected(args, "AWS-GD-001"):
        title = "GuardDuty is enabled"
        try:
            detectors = session.client("guardduty").list_detectors().get("DetectorIds", [])
            findings.append(
                _finding(
                    "AWS-GD-001",
                    title,
                    Status.PASS if detectors else Status.FAIL,
                    Severity.HIGH,
                    account,
                    f"Detector count={len(detectors)}",
                    "Enable GuardDuty through delegated organization administration.",
                )
            )
        except Exception as exc:
            findings.append(
                _finding(
                    "AWS-GD-001", title, Status.ERROR, Severity.HIGH, account, _error_code(exc)
                )
            )

    if _selected(args, "AWS-SH-001"):
        title = "Security Hub is enabled"
        try:
            hub = session.client("securityhub").describe_hub()
            status = Status.PASS if hub.get("HubArn") else Status.FAIL
            evidence = hub.get("HubArn", "Security Hub is not enabled")
        except Exception as exc:
            evidence = _error_code(exc)
            status = (
                Status.FAIL
                if evidence in {"InvalidAccessException", "ResourceNotFoundException"}
                else Status.ERROR
            )
        findings.append(
            _finding(
                "AWS-SH-001",
                title,
                status,
                Severity.HIGH,
                account,
                evidence,
                "Enable Security Hub standards through organization administration.",
            )
        )

    if _selected(args, "AWS-EC2-001"):
        title = "Default security groups have no rules"
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
                    title,
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
                    "AWS-EC2-001", title, Status.ERROR, Severity.MEDIUM, account, _error_code(exc)
                )
            )

    if _selected(args, "AWS-KMS-001"):
        title = "Customer-managed symmetric KMS keys rotate"
        try:
            client = session.client("kms")
            keys = [
                key
                for page in client.get_paginator("list_keys").paginate()
                for key in page.get("Keys", [])
            ]
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
                    title,
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
                    "AWS-KMS-001", title, Status.ERROR, Severity.MEDIUM, account, _error_code(exc)
                )
            )
    return findings
