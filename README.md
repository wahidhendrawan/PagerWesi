# Automation Hardening

Security baseline auditing and controlled remediation for Linux, Windows, macOS, AWS, Azure,
and GCP. Every entry point defaults to **audit-only** behavior. Review findings and test changes
in a disposable environment before using apply mode.

Promotional website assets are available in [docs/index.html](docs/index.html) and can be deployed
through the included GitHub Pages workflow.

## Capabilities

| Target | Audit | Plan | Apply | Machine output |
|---|---:|---:|---:|---:|
| Linux | Yes | Yes | Yes | Text |
| macOS | Yes | Yes | Yes | Text |
| Windows | Yes | Yes | Yes | JSON |
| AWS | Yes | Yes | Limited | Text, JSON, SARIF |
| Azure | Inventory baseline | No changes | No changes | Text, JSON, SARIF |
| GCP | Inventory baseline | No changes | No changes | Text, JSON, SARIF |

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

# Apply validated policy overrides and documented resource exclusions
automation-hardening aws --policy policy.example.yml

# SARIF for GitHub code scanning ingestion
automation-hardening aws --format sarif --output reports/aws.sarif
```

Exit codes are `0` for no failed/error findings, `1` for failed controls, and `2` for execution or
permission errors. AWS also checks root MFA, CloudTrail, Config, GuardDuty, Security Hub, default
security groups, and KMS rotation. Named profiles or AWS Organizations role assumption support
multi-account audits. Run regional controls in every governed region. Apply mode currently changes
S3 Public Access Block, default encryption, and versioning. It does not rewrite bucket policies,
ACLs, logging architecture, or paid security services.

Plan manifests contain the proposed before/after values and do not call mutation APIs. During
AWS Organizations audits, an inaccessible member account is reported without stopping assessment
of the remaining accounts.

Rollback restores account/bucket Public Access Block and default encryption from manifest `before`
values. AWS cannot return a versioned bucket to its never-enabled state, so versioning rollback is
reported as `MANUAL` with a nonzero exit code. Review the manifest and use least-privilege
credentials before confirming rollback.

Policy files use `version: 1` and can override Azure/GCP administrative ports or exclude resources
with shell-style patterns. Exclusions are emitted as `SKIP` findings rather than silently omitted;
see [policy.example.yml](policy.example.yml).

Azure audits Storage TLS and network rules, NSG administrative exposure, Defender plans, and
subscription activity log exports. GCP audits public bucket IAM, uniform bucket access, firewall
administrative exposure, and logging sinks; Security Command Center remains an organization-level
manual control.

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

## Development

```bash
pip install -e '.[dev]'
make test
make lint
make security
make test-os
```

CI checks Python 3.10/3.12, Ruff, pytest coverage, ShellCheck, Linux audit/plan smoke tests,
PowerShell parsing, CodeQL, and pull-request dependency review. Version tags build a GitHub Release
with Python artifacts, checksums, CycloneDX SBOM, and provenance attestation. See
[CONTRIBUTING.md](CONTRIBUTING.md).

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
