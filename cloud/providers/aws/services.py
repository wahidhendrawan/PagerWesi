from __future__ import annotations

from cloud.core import Finding, Severity, Status
from cloud.policy import aws_setting


def _selected(args, control_id):
    return not args.control or control_id in args.control


def _error_code(exc):
    return getattr(exc, "response", {}).get("Error", {}).get("Code", type(exc).__name__)


def _finding(
    control,
    title,
    status,
    severity,
    account,
    evidence,
    remediation="",
    changed=False,
    planned=False,
    before=None,
    after=None,
):
    return Finding(
        control,
        title,
        status,
        severity,
        account,
        evidence,
        remediation,
        changed=changed,
        planned=planned,
        before=before,
        after=after,
    )


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

    if _selected(args, "AWS-EBS-001"):
        title = "EBS encryption by default is enabled"
        try:
            client = session.client("ec2")
            enabled = bool(client.get_ebs_encryption_by_default().get("EbsEncryptionByDefault"))
            planned = not enabled and args.mode == "plan"
            applied = not enabled and args.mode == "apply"
            if applied:
                client.enable_ebs_encryption_by_default()
                enabled = True
            findings.append(
                _finding(
                    "AWS-EBS-001",
                    title,
                    Status.PASS if enabled else Status.FAIL,
                    Severity.HIGH,
                    account,
                    f"ebs_encryption_by_default={enabled}",
                    "Enable EBS encryption by default in every governed region.",
                    changed=applied,
                    planned=planned,
                    before=False if planned or applied else None,
                    after=True if planned or applied else None,
                )
            )
        except Exception as exc:
            findings.append(
                _finding(
                    "AWS-EBS-001", title, Status.ERROR, Severity.HIGH, account, _error_code(exc)
                )
            )

    if _selected(args, "AWS-RDS-001"):
        title = "RDS DB instances use storage encryption"
        try:
            client = session.client("rds")
            instances = [
                item
                for page in client.get_paginator("describe_db_instances").paginate()
                for item in page.get("DBInstances", [])
            ]
            unencrypted = [
                item.get("DBInstanceIdentifier", "unknown")
                for item in instances
                if not item.get("StorageEncrypted", False)
            ]
            findings.append(
                _finding(
                    "AWS-RDS-001",
                    title,
                    Status.PASS if not unencrypted else Status.FAIL,
                    Severity.HIGH,
                    account,
                    f"instances={len(instances)}, unencrypted={','.join(unencrypted) or 'none'}",
                    "Encrypt RDS storage and migrate unencrypted DB instances.",
                )
            )
        except Exception as exc:
            findings.append(
                _finding(
                    "AWS-RDS-001", title, Status.ERROR, Severity.HIGH, account, _error_code(exc)
                )
            )

    if _selected(args, "AWS-VPC-001"):
        title = "VPC Flow Logs are enabled for every VPC"
        try:
            client = session.client("ec2")
            vpcs = [
                item
                for page in client.get_paginator("describe_vpcs").paginate()
                for item in page.get("Vpcs", [])
            ]
            logged = {
                log.get("ResourceId")
                for page in client.get_paginator("describe_flow_logs").paginate()
                for log in page.get("FlowLogs", [])
                if str(log.get("FlowLogStatus", "")).upper() == "ACTIVE"
            }
            missing = [
                vpc.get("VpcId", "unknown") for vpc in vpcs if vpc.get("VpcId") not in logged
            ]
            destination = aws_setting(args, "vpc_flow_log_destination_arn")
            role_arn = aws_setting(args, "vpc_flow_log_iam_role_arn")
            planned = bool(missing) and args.mode == "plan"
            applied = False
            if missing and args.mode == "apply" and destination:
                kwargs = {
                    "ResourceIds": missing,
                    "ResourceType": "VPC",
                    "TrafficType": "ALL",
                    "LogDestination": destination,
                    "LogDestinationType": "s3",
                }
                if ":logs:" in destination:
                    kwargs["LogDestinationType"] = "cloud-watch-logs"
                    if role_arn:
                        kwargs["DeliverLogsPermissionArn"] = role_arn
                client.create_flow_logs(**kwargs)
                applied = True
                missing = []
            if missing and args.mode == "apply" and not destination:
                findings.append(
                    _finding(
                        "AWS-VPC-001",
                        title,
                        Status.MANUAL,
                        Severity.MEDIUM,
                        account,
                        "Apply requires policy aws.vpc_flow_log_destination_arn",
                        "Set aws.vpc_flow_log_destination_arn in the policy before applying.",
                    )
                )
            else:
                findings.append(
                    _finding(
                        "AWS-VPC-001",
                        title,
                        Status.PASS if not missing else Status.FAIL,
                        Severity.MEDIUM,
                        account,
                        f"vpcs={len(vpcs)}, missing_flow_logs={','.join(missing) or 'none'}",
                        "Enable VPC Flow Logs for every VPC and route them to a protected sink.",
                        changed=applied,
                        planned=planned,
                        before={"missing_flow_logs": missing} if planned or applied else None,
                        after={"missing_flow_logs": [], "destination": destination}
                        if planned or applied
                        else None,
                    )
                )
        except Exception as exc:
            findings.append(
                _finding(
                    "AWS-VPC-001", title, Status.ERROR, Severity.MEDIUM, account, _error_code(exc)
                )
            )

    if _selected(args, "AWS-IAM-002"):
        title = "IAM Access Analyzer is enabled"
        try:
            client = session.client("accessanalyzer")
            analyzers = client.list_analyzers().get("analyzers", [])
            active = [
                analyzer.get("arn", analyzer.get("name", "unknown"))
                for analyzer in analyzers
                if str(analyzer.get("status", "")).upper() == "ACTIVE"
            ]
            planned = not active and args.mode == "plan"
            applied = not active and args.mode == "apply"
            if applied:
                client.create_analyzer(analyzerName="automation-hardening-account", type="ACCOUNT")
                active = ["automation-hardening-account"]
            findings.append(
                _finding(
                    "AWS-IAM-002",
                    title,
                    Status.PASS if active else Status.FAIL,
                    Severity.HIGH,
                    account,
                    f"active_analyzers={len(active)}",
                    "Enable IAM Access Analyzer in every governed region or through AWS "
                    "Organizations.",
                    changed=applied,
                    planned=planned,
                    before={"active_analyzers": 0} if planned or applied else None,
                    after={"active_analyzers": 1} if planned or applied else None,
                )
            )
        except Exception as exc:
            findings.append(
                _finding(
                    "AWS-IAM-002", title, Status.ERROR, Severity.HIGH, account, _error_code(exc)
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


def check_aws_organization_services(session, account_id: str, args) -> list[Finding]:
    findings = []
    account = f"aws:account:{account_id}"

    if _selected(args, "AWS-ORG-CT-001"):
        title = "An organization CloudTrail trail is logging"
        try:
            client = session.client("cloudtrail")
            trails = client.describe_trails(includeShadowTrails=False).get("trailList", [])
            active = [
                trail["TrailARN"]
                for trail in trails
                if trail.get("IsOrganizationTrail")
                and trail.get("IsMultiRegionTrail")
                and client.get_trail_status(Name=trail["TrailARN"]).get("IsLogging")
            ]
            findings.append(
                _finding(
                    "AWS-ORG-CT-001",
                    title,
                    Status.PASS if active else Status.FAIL,
                    Severity.HIGH,
                    account,
                    f"active_organization_trails={len(active)}",
                    "Configure a protected multi-region organization trail.",
                )
            )
        except Exception as exc:
            findings.append(
                _finding(
                    "AWS-ORG-CT-001",
                    title,
                    Status.MANUAL,
                    Severity.HIGH,
                    account,
                    f"{_error_code(exc)}; verify from the AWS Organizations management account",
                )
            )

    if _selected(args, "AWS-ORG-GD-001"):
        title = "GuardDuty delegated administrator is configured"
        try:
            admins = (
                session.client("guardduty")
                .list_organization_admin_accounts()
                .get("AdminAccounts", [])
            )
            active = [
                admin for admin in admins if str(admin.get("AdminStatus", "")).upper() == "ENABLED"
            ]
            findings.append(
                _finding(
                    "AWS-ORG-GD-001",
                    title,
                    Status.PASS if active else Status.FAIL,
                    Severity.HIGH,
                    account,
                    f"enabled_admin_accounts={len(active)}",
                    "Delegate GuardDuty administration and enable organization auto-enrollment.",
                )
            )
        except Exception as exc:
            findings.append(
                _finding(
                    "AWS-ORG-GD-001",
                    title,
                    Status.MANUAL,
                    Severity.HIGH,
                    account,
                    f"{_error_code(exc)}; verify from the AWS Organizations management account",
                )
            )

    if _selected(args, "AWS-ORG-SH-001"):
        title = "Security Hub organization administrator is configured"
        try:
            admin = (
                session.client("securityhub")
                .list_organization_admin_accounts()
                .get("AdminAccounts", [])
            )
            findings.append(
                _finding(
                    "AWS-ORG-SH-001",
                    title,
                    Status.PASS if admin else Status.FAIL,
                    Severity.HIGH,
                    account,
                    f"admin_accounts={len(admin)}",
                    "Delegate Security Hub administration for the organization.",
                )
            )
        except Exception as exc:
            findings.append(
                _finding(
                    "AWS-ORG-SH-001",
                    title,
                    Status.MANUAL,
                    Severity.HIGH,
                    account,
                    f"{_error_code(exc)}; verify from the AWS Organizations management account",
                )
            )

    if _selected(args, "AWS-ORG-CONFIG-001"):
        title = "AWS Config aggregator is configured"
        try:
            aggregators = (
                session.client("config")
                .describe_configuration_aggregators()
                .get("ConfigurationAggregators", [])
            )
            org_aggregators = [
                item
                for item in aggregators
                if item.get("OrganizationAggregationSource")
                or item.get("AccountAggregationSources")
            ]
            findings.append(
                _finding(
                    "AWS-ORG-CONFIG-001",
                    title,
                    Status.PASS if org_aggregators else Status.FAIL,
                    Severity.HIGH,
                    account,
                    f"aggregators={len(org_aggregators)}",
                    "Configure an AWS Config aggregator for organization-wide visibility.",
                )
            )
        except Exception as exc:
            findings.append(
                _finding(
                    "AWS-ORG-CONFIG-001",
                    title,
                    Status.MANUAL,
                    Severity.HIGH,
                    account,
                    f"{_error_code(exc)}; verify from the AWS Organizations management account",
                )
            )

    return findings
