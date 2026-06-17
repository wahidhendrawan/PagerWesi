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
Analyzer, and KMS rotation. Apply mode supports reversible S3 settings, EBS encryption by default,
and IAM Access Analyzer. VPC Flow Logs apply mode requires `aws.vpc_flow_log_destination_arn` in
the policy file. Rollback remains limited to supported S3 settings.

## Azure

```bash
az login
automation-hardening azure --format json --output reports/azure.json
```

Azure checks include Storage TLS/network rules, Key Vault public access, SQL auditing, NSG
administrative exposure, Defender plans, activity log export, and subscription diagnostic settings.

## GCP

```bash
gcloud auth application-default login
automation-hardening gcp --format json --output reports/gcp.json
```

GCP checks include Cloud Storage public IAM, uniform bucket-level access, service-account
user-managed keys, Cloud KMS rotation, firewall administrative exposure, centralized logging sinks,
project audit logging, and Security Command Center manual posture.

## Policy Validation

```bash
automation-hardening policy validate --policy policy.example.yml
automation-hardening aws --policy policy.example.yml
```

Policy files can override Azure/GCP administrative ports and mark known resources as excluded.
Excluded resources are emitted as `SKIP` findings.
See [policy.schema.json](policy.schema.json) for the reusable policy schema.

## Permissions

See [provider-permissions.md](provider-permissions.md) for audit and apply permission examples.

## Optional LocalStack Contract Test

```bash
LOCALSTACK_ENDPOINT=http://localhost:4566 pytest tests/integration/test_aws_localstack_s3.py
```

This optional test exercises the S3 audit path against a LocalStack endpoint. It is skipped during
normal CI unless `LOCALSTACK_ENDPOINT` is set.
