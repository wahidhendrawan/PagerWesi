# Changelog

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
