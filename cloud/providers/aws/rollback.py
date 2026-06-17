from __future__ import annotations

import json
import re
from pathlib import Path

from cloud.core import Finding, Severity, Status


def _error_code(exc: Exception) -> str:
    return getattr(exc, "response", {}).get("Error", {}).get("Code", type(exc).__name__)


def _bucket_name(resource: str) -> str:
    prefix = "arn:aws:s3:::"
    if not resource.startswith(prefix) or not resource[len(prefix) :]:
        raise ValueError(f"Unsupported S3 resource: {resource}")
    return resource[len(prefix) :]


def _restore_public_block(client, target: dict, *, account_id=None, bucket=None) -> None:
    before = target.get("before") or {}
    if account_id:
        if before:
            client.put_public_access_block(
                AccountId=account_id, PublicAccessBlockConfiguration=before
            )
        else:
            client.delete_public_access_block(AccountId=account_id)
    elif before:
        client.put_public_access_block(Bucket=bucket, PublicAccessBlockConfiguration=before)
    else:
        client.delete_public_access_block(Bucket=bucket)


def rollback_manifest(session, path: Path) -> list[Finding]:
    document = json.loads(path.read_text(encoding="utf-8"))
    if document.get("schema_version") != "1.0" or document.get("provider") != "aws":
        raise ValueError("Rollback manifest must be an AWS schema_version 1.0 change manifest")
    changes = document.get("changes")
    if not isinstance(changes, list):
        raise ValueError("Rollback manifest changes must be a list")

    clients: dict = {}

    def client(name: str):
        if name not in clients:
            clients[name] = session.client(name)
        return clients[name]

    findings = []
    for change in reversed(changes):
        if not isinstance(change, dict):
            raise ValueError("Rollback manifest change entries must be mappings")
        control = change.get("control_id", "AWS-ROLLBACK")
        resource = change.get("resource", "aws:unknown")
        try:
            if control == "AWS-S3-001":
                account_id = resource.rsplit(":", 1)[-1]
                if not re.fullmatch(r"\d{12}", account_id):
                    raise ValueError("Account-level rollback requires a 12-digit AWS account ID")
                _restore_public_block(client("s3control"), change, account_id=account_id)
            elif control == "AWS-S3-004":
                _restore_public_block(client("s3"), change, bucket=_bucket_name(resource))
            elif control == "AWS-S3-005":
                bucket = _bucket_name(resource)
                before = change.get("before")
                if before:
                    client("s3").put_bucket_encryption(
                        Bucket=bucket,
                        ServerSideEncryptionConfiguration={"Rules": before},
                    )
                else:
                    client("s3").delete_bucket_encryption(Bucket=bucket)
            elif control == "AWS-S3-006":
                findings.append(
                    Finding(
                        control,
                        "Bucket versioning rollback requires manual recovery",
                        Status.MANUAL,
                        Severity.HIGH,
                        resource,
                        "AWS cannot return an enabled bucket to the never-enabled Disabled state.",
                        "Review object versions and suspend versioning only after impact analysis.",
                    )
                )
                continue
            elif control == "AWS-EBS-001":
                if change.get("before") is False and change.get("after") is True:
                    client("ec2").disable_ebs_encryption_by_default()
                else:
                    findings.append(
                        Finding(
                            control,
                            "EBS encryption rollback is not applicable",
                            Status.SKIP,
                            Severity.INFO,
                            resource,
                            "Manifest does not describe an EBS encryption enablement.",
                        )
                    )
                    continue
            elif control == "AWS-IAM-002":
                analyzer_name = (change.get("after") or {}).get("analyzer_name")
                if analyzer_name and (change.get("before") or {}).get("active_analyzers") == 0:
                    client("accessanalyzer").delete_analyzer(analyzerName=analyzer_name)
                else:
                    findings.append(
                        Finding(
                            control,
                            "Access Analyzer rollback is not applicable",
                            Status.SKIP,
                            Severity.INFO,
                            resource,
                            "Manifest does not describe a tool-created analyzer.",
                        )
                    )
                    continue
            elif control == "AWS-VPC-001":
                flow_log_ids = (change.get("after") or {}).get("flow_log_ids") or []
                if flow_log_ids:
                    client("ec2").delete_flow_logs(FlowLogIds=flow_log_ids)
                else:
                    findings.append(
                        Finding(
                            control,
                            "VPC Flow Logs rollback requires manual recovery",
                            Status.MANUAL,
                            Severity.MEDIUM,
                            resource,
                            "Manifest does not include created flow_log_ids.",
                            "Delete only the Flow Logs created by the apply operation.",
                        )
                    )
                    continue
            else:
                findings.append(
                    Finding(
                        control,
                        "Rollback control is unsupported",
                        Status.SKIP,
                        Severity.INFO,
                        resource,
                        "No deterministic rollback handler is registered.",
                    )
                )
                continue
            findings.append(
                Finding(
                    control,
                    "Previous configuration was restored",
                    Status.PASS,
                    Severity.INFO,
                    resource,
                    "Restored from the change manifest before value.",
                    changed=True,
                    before=change.get("after"),
                    after=change.get("before"),
                )
            )
        except Exception as exc:
            findings.append(
                Finding(
                    control,
                    "Previous configuration could not be restored",
                    Status.ERROR,
                    Severity.HIGH,
                    resource,
                    _error_code(exc),
                )
            )
    return findings
