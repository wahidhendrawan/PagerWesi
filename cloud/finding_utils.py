from __future__ import annotations

from enum import Enum
from typing import Any


def finding_value(finding: Any, key: str, default: Any = None) -> Any:
    """Read a Finding object or serialized finding dict consistently."""
    if isinstance(finding, dict):
        return finding.get(key, default)
    return getattr(finding, key, default)


def enum_value(value: Any) -> str:
    if isinstance(value, Enum):
        return str(value.value)
    if value is None:
        return ""
    return str(value)


def normalized_status(finding: Any) -> str:
    return enum_value(finding_value(finding, "status")).lower()


def normalized_severity(finding: Any) -> str:
    return enum_value(finding_value(finding, "severity")).lower()


def finding_control_id(finding: Any) -> str:
    return str(
        finding_value(
            finding,
            "control_id",
            finding_value(finding, "control", "unknown"),
        )
    )


def finding_provider(finding: Any) -> str:
    explicit = finding_value(finding, "provider")
    if explicit:
        return str(explicit)
    control_id = finding_control_id(finding)
    if "-" in control_id:
        return control_id.split("-", 1)[0].lower()
    resource = str(finding_value(finding, "resource", "unknown"))
    if ":" in resource:
        return resource.split(":", 1)[0].lower()
    return "unknown"


def actionable_findings(findings: list[Any]) -> list[Any]:
    return [f for f in findings if normalized_status(f) in {"fail", "error"}]
