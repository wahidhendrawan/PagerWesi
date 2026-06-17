# Changelog

## 0.4.0 - 2026-06-17

- Removed Node 20 warning by upgrading `actions/setup-python` to v6 across all workflows.
- Added AWS rollback handlers for EBS encryption by default, IAM Access Analyzer, and VPC Flow Logs.
- Added runtime JSON Schema validation for policy files with precise error paths (`jsonschema`).
- Added `pull_request` trigger with path filter to the LocalStack integration workflow.
- Enriched SARIF output with full descriptions, help URIs, NIST CSF / ISO 27001 / CIS framework
  tags, security-severity scores, markdown remediation guidance, and tool version metadata.
- Added non-mutating plan mode for Azure and GCP with plan manifest generation.
- Added `generate_control_docs.py` to produce `docs/controls.md` and `compliance-mapping.json`
  from the single-source control registry. CI enforces drift checks.
- Added GHCR container image publishing with provenance attestation in the release workflow.
- Updated GitHub Pages landing page to full English with container and plan mode sections.
- Updated README with container usage, expanded rollback boundaries, and Azure/GCP plan mode.

## 0.3.2 - 2026-06-17

- Added Node 24 transition flags across GitHub Actions workflows.
- Added optional scheduled/manual LocalStack integration workflow.
- Added policy schema and AWS policy settings for VPC Flow Logs apply mode.
- Added AWS apply support for EBS encryption by default and IAM Access Analyzer.
- Added AWS organization aggregate controls for CloudTrail, Config, GuardDuty, and Security Hub.
- Switched Azure subscription diagnostic settings to ARM REST lookup.
- Added provider permission examples and documentation version index.

## 0.3.1 - 2026-06-17

- Added a standalone quickstart guide and linked it from README and the promotional website.
- Added `automation-hardening policy validate --policy PATH`.
- Added AWS controls for EBS encryption by default, RDS storage encryption, VPC Flow Logs, and IAM
  Access Analyzer.
- Added Azure controls for Key Vault public access, SQL auditing, and diagnostic settings.
- Added GCP controls for service-account user-managed keys, Cloud KMS rotation, and audit logging.
- Added optional LocalStack S3 contract coverage and expanded Azure/GCP provider contract tests.

## 0.3.0 - 2026-06-15

- Added AWS rollback manifests for reversible S3 Public Access Block and encryption changes.
- Added explicit manual handling for irreversible S3 versioning transitions.
- Added validated YAML policy overrides for sensitive ports and resource exclusions.
- Added rollback and policy contract tests and a clean-wheel release smoke test.

## 0.2.1 - 2026-06-15

- Added deterministic plan manifests with before/after evidence for AWS remediations.
- Improved Azure and GCP public administrative-port detection for IPv6, lists, and ranges.
- Preserved the selected storage control ID when provider API access fails.
- Isolated AWS Organizations member-account failures so remaining accounts are still assessed.

## 0.2.0 - 2026-06-14

- Added audit/plan/apply execution modes and safe defaults.
- Added structured finding model with text, JSON, SARIF, and meaningful exit codes.
- Expanded AWS S3 coverage and deterministic remediation.
- Added authenticated Azure and GCP inventory adapters.
- Added safer Linux, macOS, and Windows baseline scripts.
- Added packaging, tests, linting, CI, CodeQL, dependency review, and Dependabot.
- Added multi-region AWS auditing, provider registry, provider tests, Linux smoke tests, and a
  provenance-attested release workflow.
- Added AWS Organizations account discovery and role assumption.
- Added Azure Storage, network, Defender, and activity log export controls.
- Added GCP Storage IAM, network firewall, and centralized logging controls.
- Added explicit apply-mode change manifests and informative compliance mappings.
- Raised minimum coverage to 80% and added Bats/Pester OS contract tests.
