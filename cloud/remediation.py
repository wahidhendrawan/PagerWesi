"""Generate remediation playbooks from plan manifests."""
from __future__ import annotations

import json
from pathlib import Path

_TERRAFORM_TEMPLATES: dict[str, str] = {
    "AWS-S3-001": '''resource "aws_s3_account_public_access_block" "block" {{
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}}''',
    "AWS-S3-004": '''resource "aws_s3_bucket_public_access_block" "{bucket}" {{
  bucket                  = "{bucket}"
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}}''',
    "AWS-EBS-001": '''resource "aws_ebs_encryption_by_default" "enabled" {{
  enabled = true
}}''',
    "AWS-VPC-001": '''resource "aws_flow_log" "vpc" {{
  vpc_id          = "{vpc_id}"
  traffic_type    = "ALL"
  log_destination = "{destination}"
}}''',
}

_CFN_TEMPLATES: dict[str, str] = {
    "AWS-S3-001": '''  AccountPublicAccessBlock:
    Type: AWS::S3::AccountPublicAccessBlock
    Properties:
      BlockPublicAcls: true
      BlockPublicPolicy: true
      IgnorePublicAcls: true
      RestrictPublicBuckets: true''',
    "AWS-EBS-001": '''  # EBS encryption by default (requires AWS CLI/SDK, not natively CFN)
  # Use a custom resource or AWS Config rule to enforce.''',
}


def generate_playbook(
    manifest_path: Path, output_format: str = "terraform"
) -> str:
    """Generate remediation code from a plan or change manifest."""
    doc = json.loads(manifest_path.read_text(encoding="utf-8"))
    items = doc.get("plans") or doc.get("changes") or []
    templates = (
        _TERRAFORM_TEMPLATES if output_format == "terraform"
        else _CFN_TEMPLATES
    )

    lines: list[str] = []
    if output_format == "terraform":
        lines.append("# Auto-generated Terraform remediation playbook")
        lines.append(f"# Source: {manifest_path.name}\n")
    else:
        lines.append("# Auto-generated CloudFormation remediation")
        lines.append(f"# Source: {manifest_path.name}")
        lines.append("Resources:")

    for item in items:
        cid = item.get("control_id", "")
        resource = item.get("resource", "")
        template = templates.get(cid)
        if template:
            bucket = resource.split(":::")[-1] if "s3" in resource else ""
            vpc_id = ""
            destination = ""
            after = item.get("after") or {}
            if isinstance(after, dict):
                flow_logs = after.get("missing_flow_logs") or ["vpc-xxx"]
                vpc_id = flow_logs[0] if "missing" in str(after) else ""
                destination = after.get("destination", "")
            rendered = template.format(
                bucket=bucket or "example",
                vpc_id=vpc_id or "vpc-xxx",
                destination=destination or "arn:aws:s3:::logs",
            )
            lines.append(f"\n# {cid}: {resource}")
            lines.append(rendered)
        else:
            lines.append(f"\n# {cid}: {resource} — no template available")
            lines.append(f"# Remediation: {item.get('remediation', 'manual')}")

    return "\n".join(lines) + "\n"
