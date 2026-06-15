"""Compatibility facade for the modular AWS provider."""

from cloud.providers.aws.baseline import (
    CONTROL_IDS,
    _check_account_public_block,
    _check_aws_services,
    _check_bucket,
    audit_s3_public_access,
    run_audit,
)

__all__ = [
    "CONTROL_IDS",
    "_check_account_public_block",
    "_check_aws_services",
    "_check_bucket",
    "audit_s3_public_access",
    "run_audit",
]
