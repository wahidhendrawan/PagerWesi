# Security Policy

## Supported versions

Only the latest release of PagerWesi gets security fixes. Please check that the problem still exists there before reporting.

## Reporting a vulnerability

Report privately through GitHub: **Security → Report a vulnerability** on this repository ([direct link](https://github.com/wahidhendrawan/PagerWesi/security/advisories/new)). Do not open a public issue, discussion or pull request, and do not post exploit details or credentials anywhere public.

Please include:

- the version or commit you tested, platform, and the provider or mode you ran (audit, plan, apply, rollback)
- the smallest steps or input that reproduce the problem
- what an attacker gains (data exposure, code execution, privilege escalation, denial of service, …)

Remove real credentials, customer data and sensitive logs from any evidence you share.

You should get a first reply within 7 days. Fixed issues are credited in the release notes unless you ask otherwise.

## In scope

- Source code in this repository (`cloud/`, OS harden scripts, workflows, the GitHub Action)
- Published container image `ghcr.io/wahidhendrawan/pagerwesi`
- Remediation that weakens a system or leaks credentials, and documented CLI, agent and webhook behaviour

## Out of scope

- Vulnerabilities in the cloud services being audited: report them to that provider
- Commands you put in a custom-controls file: they run by design, so only trusted people may supply that file
- Running apply mode with intentionally over-privileged credentials

## Safe harbor

Good-faith research that follows this policy will not be treated as a violation of the license or of this policy. Only test against your own deployment, access no more data than needed to show the issue, and do not degrade services for other people.
