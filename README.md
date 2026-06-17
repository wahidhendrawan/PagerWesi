# Automation Hardening

Security baseline auditing and controlled remediation for Linux, Windows, macOS, AWS, Azure,
and GCP. Every entry point defaults to **audit-only** behavior. Review findings and test changes
in a disposable environment before using apply mode.

Promotional website and documentation are published at
**<https://wahidhendrawan.github.io/Automation-Hardening/>** via the included GitHub Pages workflow.
Source assets are in [docs/index.html](docs/index.html).

For a short setup path, start with [docs/quickstart.md](docs/quickstart.md). Provider permission
examples are in [docs/provider-permissions.md](docs/provider-permissions.md).

## Capabilities

| Target | Audit | Plan | Apply | Machine output |
|---|---:|---:|---:|---:|
| Linux | Yes | Yes | Yes | Text |
| macOS | Yes | Yes | Yes | Text |
| Windows | Yes | Yes | Yes | JSON |
| FreeBSD | Yes | Yes | Yes | Text |
| Alpine/Container | Yes | Yes | Limited | Text |
| AWS | Yes | Yes | Limited | Text, JSON, SARIF, HTML |
| Azure | Yes | Yes | — | Text, JSON, SARIF, HTML |
| GCP | Yes | Yes | — | Text, JSON, SARIF, HTML |
| Kubernetes | Yes | Yes | — | Text, JSON, SARIF, HTML |
| Docker | Yes | Yes | — | Text, JSON, SARIF, HTML |
| Secrets | Yes | — | — | Text, JSON, SARIF, HTML |
| Terraform | Yes | — | — | Text, JSON, SARIF, HTML |
| Network/TLS | Yes | — | — | Text, JSON, SARIF, HTML |
| **All (unified)** | Yes | Yes | — | Text, JSON, SARIF, HTML |

Controls are project baselines inspired by common CIS recommendations. They are **not a claim of
CIS certification**. See [docs/controls.md](docs/controls.md) for scope and limitations.

## Cloud CLI

Python 3.10 or newer is required. Install only the providers you use:

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -e '.[aws]'
automation-hardening aws --format text
```

Useful examples:

```bash
# Machine-readable report
automation-hardening aws --format json --output reports/aws.json

# One control and a named AWS profile
automation-hardening aws --control AWS-S3-004 --profile production

# Run regional controls across multiple AWS regions
automation-hardening aws --regions us-east-1,ap-southeast-1,eu-west-1

# Audit multiple AWS accounts represented by named profiles
automation-hardening aws --profiles production,security-audit --regions us-east-1,ap-southeast-1

# Discover active AWS Organization accounts and assume a standard audit role
automation-hardening aws --organization-role AutomationHardeningAudit \
  --external-id approved-external-id --regions us-east-1,ap-southeast-1

# Preview/apply deterministic AWS remediations
automation-hardening aws --mode plan \
  --plan-manifest reports/aws-plan.json
automation-hardening aws --mode apply --yes \
  --change-manifest reports/aws-changes.json

# Restore reversible settings from an apply change manifest
automation-hardening aws --mode rollback --yes \
  --rollback-manifest reports/aws-changes.json

# Azure/GCP plan mode (non-mutating)
automation-hardening azure --mode plan --plan-manifest reports/azure-plan.json
automation-hardening gcp --mode plan --plan-manifest reports/gcp-plan.json

# Apply validated policy overrides and documented resource exclusions
automation-hardening policy validate --policy policy.example.yml
automation-hardening aws --policy policy.example.yml

# SARIF for GitHub code scanning ingestion
automation-hardening aws --format sarif --output reports/aws.sarif
```

Exit codes are `0` for no failed/error findings, `1` for failed controls, and `2` for execution or
permission errors. AWS also checks root MFA, CloudTrail, Config, GuardDuty, Security Hub, default
security groups, EBS encryption by default, RDS encryption, VPC Flow Logs, IAM Access Analyzer, and
KMS rotation. Named profiles or AWS Organizations role assumption support
multi-account audits. Run regional controls in every governed region. Apply mode currently changes
supported S3 settings, EBS encryption by default, IAM Access Analyzer, and VPC Flow Logs when a
policy destination ARN is configured. It does not rewrite bucket policies, ACLs, broader logging
architecture, or paid security service plans.

Plan manifests contain the proposed before/after values and do not call mutation APIs. Azure and GCP
plan mode generates non-mutating plan manifests showing recommended changes. During AWS
Organizations audits, an inaccessible member account is reported without stopping assessment of the
remaining accounts.

Rollback restores account/bucket Public Access Block, default encryption, EBS encryption-by-default
changes, tool-created IAM Access Analyzers, and VPC Flow Logs from manifest values. AWS cannot
return a versioned bucket to its never-enabled state, so versioning rollback is reported as `MANUAL`
with a nonzero exit code. Review the manifest and use least-privilege credentials before confirming
rollback.

Policy files use `version: 1` and can override Azure/GCP administrative ports or exclude resources
with shell-style patterns. Exclusions are emitted as `SKIP` findings rather than silently omitted;
see [policy.example.yml](policy.example.yml). Policy validation uses JSON Schema and reports precise
error paths.

Azure audits Storage TLS and network rules, Key Vault public access, SQL auditing, NSG
administrative exposure, Defender plans, activity log exports, and diagnostic settings. GCP audits
public bucket IAM, uniform bucket access, service-account user-managed keys, KMS rotation, firewall
administrative exposure, logging sinks, and audit logging; Security Command Center remains an
organization-level manual control.

## Container

A pre-built container image is published to GHCR on every version tag:

```bash
docker pull ghcr.io/wahidhendrawan/automation-hardening:latest

docker run --rm \
  -e AWS_ACCESS_KEY_ID -e AWS_SECRET_ACCESS_KEY -e AWS_DEFAULT_REGION \
  ghcr.io/wahidhendrawan/automation-hardening:latest \
  aws --format sarif --output /dev/stdout
```

## Kubernetes

```bash
pip install -e '.[k8s]'
automation-hardening k8s --format text
automation-hardening k8s --mode plan --plan-manifest reports/k8s-plan.json
```

Checks NetworkPolicy coverage, cluster-admin RBAC bindings, privileged pods, and Pod Security
Standards enforcement. Connects via in-cluster config or `~/.kube/config`.

## Multi-Cloud Unified Report

```bash
pip install -e '.[aws,azure,gcp,k8s]'
automation-hardening all --format json --output reports/unified.json
automation-hardening all --format sarif --output reports/unified.sarif
```

Runs all available providers sequentially and combines findings into a single report. Unavailable
providers are skipped gracefully.

## FreeBSD

```bash
sudo sh freebsd/harden.sh --mode audit
sudo sh freebsd/harden.sh --mode plan
sudo sh freebsd/harden.sh --mode apply
```

Checks PF firewall, SSH root login, empty passwords, and security patches.

## Alpine / Container OS

```bash
sh alpine/harden.sh --mode audit
sh alpine/harden.sh --mode plan
sh alpine/harden.sh --mode apply
```

Checks non-root user, vulnerable packages, read-only root filesystem, and unnecessary shells.

## Operating Systems

Audit is always the default:

```bash
sudo bash linux/harden.sh --mode audit
sudo bash linux/harden.sh --mode plan
sudo bash linux/harden.sh --mode apply

sudo bash macos/harden.sh --mode audit
sudo bash macos/harden.sh --mode plan
sudo bash macos/harden.sh --mode apply

powershell -File windows/harden.ps1 -Mode Audit -OutputPath report.json
powershell -File windows/harden.ps1 -Mode Plan
powershell -File windows/harden.ps1 -Mode Apply
```

Linux apply mode creates a timestamped SSH backup under
`/var/backups/automation-hardening/`. Restore it with:

```bash
sudo bash linux/harden.sh --rollback /var/backups/automation-hardening/TIMESTAMP
```

Linux firewall apply mode permits the service in `ALLOW_SSH` before enabling the firewall. For a
nonstandard service or rule, set it explicitly and verify the plan first:

```bash
sudo ALLOW_SSH=OpenSSH bash linux/harden.sh --mode plan
```

## Custom Controls

Define your own controls in YAML without forking:

```yaml
# my-controls.yml
version: 1
controls:
  - id: CUSTOM-DNS-001
    title: DNS resolver uses internal nameservers
    check: "grep -q 'nameserver 10\\.' /etc/resolv.conf"
    severity: medium
    remediation: "Configure internal DNS in /etc/resolv.conf"
```

```bash
automation-hardening aws --custom-controls my-controls.yml
```

## Remediation Playbooks

Generate Terraform or CloudFormation from plan manifests:

```bash
automation-hardening aws --generate-playbook reports/plan.json --output remediation.tf
automation-hardening aws --generate-playbook reports/plan.json \
  --playbook-format cloudformation --output remediation.yml
```

## HTML Dashboard

```bash
automation-hardening all --format html --output reports/dashboard.html
```

Produces a self-contained HTML file with pass/fail/error statistics and a findings table.

## Drift Detection

A scheduled workflow runs daily, audits all providers, and creates a GitHub Issue if controls
are failing. See `.github/workflows/drift-detection.yml`.

## Development

```bash
pip install -e '.[dev]'
make test
make lint
make security
make test-os
make docs
```

CI checks Python 3.10/3.12, Ruff, pytest coverage, ShellCheck, Linux audit/plan smoke tests,
PowerShell parsing, CodeQL, pull-request dependency review, and integration tests with LocalStack.
Version tags build a GitHub Release with Python artifacts, checksums, CycloneDX SBOM, container
image, and provenance attestation. See [CONTRIBUTING.md](CONTRIBUTING.md).

Control relationships to NIST CSF 2.0, ISO/IEC 27001:2022 Annex A, and CIS benchmark families are
documented in [docs/compliance-mapping.json](docs/compliance-mapping.json). These mappings are
informative and do not constitute certification.

## Safety

- Use least-privilege read-only cloud credentials for audit mode.
- Capture backups and test apply mode in a VM or disposable account first.
- Review network access before enabling a host firewall remotely.
- Use an approved recovery-key escrow process before enabling FileVault or BitLocker.
- Treat generated reports as sensitive because they contain resource identifiers and posture data.

This project is provided under the Apache-2.0 license without warranty.
