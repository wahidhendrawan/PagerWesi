# Contributing

1. Create a focused branch and keep each control change independently reviewable.
2. Add tests for pass, fail, permission-error, and apply behavior.
3. Run `make lint` and `make test` before opening a pull request.
4. Document the control source, applicability, evidence, remediation, and rollback implications.
5. Never place credentials, account identifiers, or real cloud reports in fixtures.

New automatic remediation must be deterministic, idempotent, least privilege, and protected by an
explicit apply flag. Destructive or architecture-dependent remediation should remain report-only.

