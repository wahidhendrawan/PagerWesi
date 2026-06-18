"""Compliance evidence export — map findings to SOC2/PCI-DSS controls."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from cloud.control_registry import CONTROL_METADATA
from cloud.finding_utils import finding_control_id, finding_value, normalized_status

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


_SOC2_BY_NIST = {
    "PR.AA": "CC6.1",
    "PR.DS": "CC6.1",
    "PR.IR": "CC6.6",
    "PR.PS": "CC7.1",
    "DE.CM": "CC7.2",
    "ID.AM": "CC3.2",
}

_PCI_BY_NIST = {
    "PR.AA": "7.1",
    "PR.DS": "3.4",
    "PR.IR": "1.2",
    "PR.PS": "6.3",
    "DE.CM": "10.2",
    "ID.AM": "12.5",
}


def _framework_mapping(control_id: str, framework: str) -> str:
    explicit = SOC2_MAPPING if framework == "soc2" else PCI_MAPPING
    if control_id in explicit:
        return explicit[control_id]

    metadata = CONTROL_METADATA.get(control_id)
    if not metadata:
        return "unmapped"

    inferred = _SOC2_BY_NIST if framework == "soc2" else _PCI_BY_NIST
    for ref in metadata.nist_csf:
        if ref in inferred:
            return inferred[ref]
    return "unmapped"


def export_evidence(
    findings: list[Any],
    framework: str = "soc2",
    output_path: str | None = None,
) -> str:
    """Export findings as compliance evidence JSON."""
    mapping = SOC2_MAPPING if framework == "soc2" else PCI_MAPPING
    evidence_items = []
    for f in findings:
        cid = finding_control_id(f)
        metadata = CONTROL_METADATA.get(cid)
        evidence_items.append({
            "control_id": cid,
            "status": normalized_status(f) or "unknown",
            "mapping": mapping.get(cid, _framework_mapping(cid, framework)),
            "target": metadata.target if metadata else finding_value(f, "resource", "unknown"),
            "evidence": finding_value(f, "evidence", ""),
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
