# Quickstart

PagerWesi defaults to audit-only execution. Run plan/apply only after reviewing output
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
docker pull ghcr.io/wahidhendrawan/pagerwesi:latest
docker run --rm \
  -e AWS_ACCESS_KEY_ID -e AWS_SECRET_ACCESS_KEY -e AWS_DEFAULT_REGION \
  ghcr.io/wahidhendrawan/pagerwesi:latest \
  aws --format json --output /dev/stdout
```

## AWS

```bash
pagerwesi aws --format text
pagerwesi aws --regions us-east-1,ap-southeast-1 --format json --output reports/aws.json
pagerwesi aws --mode plan --plan-manifest reports/aws-plan.json
pagerwesi aws --mode apply --yes --change-manifest reports/aws-changes.json
pagerwesi aws --mode rollback --yes --rollback-manifest reports/aws-changes.json
```

AWS checks include S3, organization guardrails, CloudTrail, Config, GuardDuty, Security Hub, default
security groups, EBS encryption by default, RDS storage encryption, VPC Flow Logs, IAM Access
Analyzer, and KMS rotation. Apply mode supports S3 settings, EBS encryption by default, IAM Access
Analyzer, and VPC Flow Logs (with policy destination ARN). Rollback covers all applied changes when
manifest IDs are present.

## Azure

```bash
az login
pagerwesi azure --format json --output reports/azure.json
pagerwesi azure --mode plan --plan-manifest reports/azure-plan.json
```

Azure checks include Storage TLS/network rules, Key Vault public access, SQL auditing, NSG
administrative exposure, Defender plans, activity log export, and subscription diagnostic settings.
Plan mode generates non-mutating recommendations.

## GCP

```bash
gcloud auth application-default login
pagerwesi gcp --format json --output reports/gcp.json
pagerwesi gcp --mode plan --plan-manifest reports/gcp-plan.json
```

GCP checks include Cloud Storage public IAM, uniform bucket-level access, service-account
user-managed keys, Cloud KMS rotation, firewall administrative exposure, centralized logging sinks,
project audit logging, and Security Command Center manual posture. Plan mode generates non-mutating
recommendations.

## Policy Validation

```bash
pagerwesi policy validate --policy policy.example.yml
pagerwesi aws --policy policy.example.yml
```

Policy files can override Azure/GCP administrative ports and mark known resources as excluded.
Excluded resources are emitted as `SKIP` findings. Validation uses JSON Schema and reports precise
error paths. See [policy.schema.json](policy.schema.json) for the reusable policy schema.

## Local Scanners

Run local scanners with an explicit scope:

```bash
pagerwesi docker --format json --output reports/docker.json

# Prefer a narrow source path in CI to avoid scanning build artifacts.
pagerwesi secrets --path ./src --format json --output reports/secrets.json

# Generate Terraform plan JSON before scanning.
terraform plan -out=tfplan
terraform show -json tfplan > tfplan.json
pagerwesi terraform --path tfplan.json --format json --output reports/terraform.json
pagerwesi network --endpoints example.com:443,api.example.com:443 \
  --format json --output reports/network.json
```

The `all` provider runs the core cloud provider set: AWS, Azure, GCP, and Kubernetes. Docker,
secrets, Terraform, and network/TLS checks stay explicit because they need a selected local path or
endpoint list.

## Machine-Readable Findings

Validate downstream ingestion against [finding.schema.json](finding.schema.json). JSON reports use
lowercase status and severity values and include stable fields for resource, evidence, remediation,
plan/change flags, and before/after values.

## Agent Mode

```bash
pagerwesi aws --agent --interval 300 --watch-providers aws,azure,gcp,k8s \
  --notify notify.yml
```

Agent mode records provider runtime failures as `AGENT-PROVIDER-001` error findings so alerting and
state comparison can detect broken credentials, missing dependencies, or provider outages.

## Permissions

See [provider-permissions.md](provider-permissions.md) for audit and apply permission examples.

## SARIF

```bash
pagerwesi aws --format sarif --output reports/aws.sarif
```

SARIF output includes NIST CSF, ISO 27001, and CIS framework tags for each rule, security-severity
scores, and help URIs linking to the control catalog.

## Optional LocalStack Contract Test

```bash
LOCALSTACK_ENDPOINT=http://localhost:4566 pytest tests/integration/test_aws_localstack_s3.py
```

This optional test exercises the S3 audit path against a LocalStack endpoint. It is skipped during
normal CI unless `LOCALSTACK_ENDPOINT` is set.
