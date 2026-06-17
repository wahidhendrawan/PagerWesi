# Quickstart

Automation Hardening defaults to audit-only execution. Run plan/apply only after reviewing output
in a disposable or non-production environment.

## Install

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -e '.[aws]'
```

Install only the provider extras you need:

```bash
pip install -e '.[aws,azure,gcp]'
```

## Container

Run without local Python setup:

```bash
docker pull ghcr.io/wahidhendrawan/automation-hardening:latest
docker run --rm \
  -e AWS_ACCESS_KEY_ID -e AWS_SECRET_ACCESS_KEY -e AWS_DEFAULT_REGION \
  ghcr.io/wahidhendrawan/automation-hardening:latest \
  aws --format json --output /dev/stdout
```

## AWS

```bash
automation-hardening aws --format text
automation-hardening aws --regions us-east-1,ap-southeast-1 --format json --output reports/aws.json
automation-hardening aws --mode plan --plan-manifest reports/aws-plan.json
automation-hardening aws --mode apply --yes --change-manifest reports/aws-changes.json
automation-hardening aws --mode rollback --yes --rollback-manifest reports/aws-changes.json
```

AWS checks include S3, organization guardrails, CloudTrail, Config, GuardDuty, Security Hub, default
security groups, EBS encryption by default, RDS storage encryption, VPC Flow Logs, IAM Access
Analyzer, and KMS rotation. Apply mode supports S3 settings, EBS encryption by default, IAM Access
Analyzer, and VPC Flow Logs (with policy destination ARN). Rollback covers all applied changes when
manifest IDs are present.

## Azure

```bash
az login
automation-hardening azure --format json --output reports/azure.json
automation-hardening azure --mode plan --plan-manifest reports/azure-plan.json
```

Azure checks include Storage TLS/network rules, Key Vault public access, SQL auditing, NSG
administrative exposure, Defender plans, activity log export, and subscription diagnostic settings.
Plan mode generates non-mutating recommendations.

## GCP

```bash
gcloud auth application-default login
automation-hardening gcp --format json --output reports/gcp.json
automation-hardening gcp --mode plan --plan-manifest reports/gcp-plan.json
```

GCP checks include Cloud Storage public IAM, uniform bucket-level access, service-account
user-managed keys, Cloud KMS rotation, firewall administrative exposure, centralized logging sinks,
project audit logging, and Security Command Center manual posture. Plan mode generates non-mutating
recommendations.

## Policy Validation

```bash
automation-hardening policy validate --policy policy.example.yml
automation-hardening aws --policy policy.example.yml
```

Policy files can override Azure/GCP administrative ports and mark known resources as excluded.
Excluded resources are emitted as `SKIP` findings. Validation uses JSON Schema and reports precise
error paths. See [policy.schema.json](policy.schema.json) for the reusable policy schema.

## Permissions

See [provider-permissions.md](provider-permissions.md) for audit and apply permission examples.

## SARIF

```bash
automation-hardening aws --format sarif --output reports/aws.sarif
```

SARIF output includes NIST CSF, ISO 27001, and CIS framework tags for each rule, security-severity
scores, and help URIs linking to the control catalog.

## Optional LocalStack Contract Test

```bash
LOCALSTACK_ENDPOINT=http://localhost:4566 pytest tests/integration/test_aws_localstack_s3.py
```

This optional test exercises the S3 audit path against a LocalStack endpoint. It is skipped during
normal CI unless `LOCALSTACK_ENDPOINT` is set.
