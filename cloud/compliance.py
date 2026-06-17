"""Compliance evidence export — map findings to SOC2/PCI-DSS controls."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

SOC2_MAPPING: dict[str, str] = {
    "iam-mfa": "CC6.1",
    "iam-password-policy": "CC6.1",
    "logging-enabled": "CC7.2",
    "encryption-at-rest": "CC6.1",
    "network-segmentation": "CC6.6",
    "access-review": "CC6.2",
    "incident-response": "CC7.3",
    "backup-enabled": "CC7.5",
    "audit-trail": "CC7.2",
    "change-management": "CC8.1",
}

PCI_MAPPING: dict[str, str] = {
    "iam-mfa": "8.3",
    "iam-password-policy": "8.2",
    "logging-enabled": "10.2",
    "encryption-at-rest": "3.4",
    "network-segmentation": "1.1",
    "access-review": "7.1",
    "incident-response": "12.10",
    "backup-enabled": "9.5",
    "audit-trail": "10.2",
    "change-management": "6.4",
}


def export_evidence(
    findings: list[Any],
    framework: str = "soc2",
    output_path: str | None = None,
) -> str:
    """Export findings as compliance evidence JSON."""
    mapping = SOC2_MAPPING if framework == "soc2" else PCI_MAPPING
    evidence_items = []
    for f in findings:
        cid = getattr(f, "control_id", "unknown")
        evidence_items.append({
            "control_id": cid,
            "status": getattr(f, "status", "UNKNOWN"),
            "mapping": mapping.get(cid, "unmapped"),
        })
    result = json.dumps({
        "framework": framework,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "evidence": evidence_items,
    }, indent=2)
    if output_path:
        with open(output_path, "w") as fh:
            fh.write(result)
    return result
