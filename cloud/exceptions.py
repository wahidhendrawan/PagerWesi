"""Exception/waiver management — time-boxed waivers for findings."""
from __future__ import annotations

import copy
import fnmatch
from datetime import datetime, timezone
from typing import Any


def load_exceptions(path: str) -> list[dict[str, Any]]:
    """Load exception waivers from a YAML file."""
    import yaml  # type: ignore[import-untyped]

    with open(path) as fh:
        data = yaml.safe_load(fh)
    return data if isinstance(data, list) else []


def _is_active(exc: dict[str, Any]) -> bool:
    """Check if an exception has not expired."""
    expires = exc.get("expires")
    if expires is None:
        return True
    if isinstance(expires, str):
        expires = datetime.fromisoformat(expires)
    if expires.tzinfo is None:
        expires = expires.replace(tzinfo=timezone.utc)
    return datetime.now(timezone.utc) <= expires


def _matches(finding: Any, exc: dict[str, Any]) -> bool:
    """Check if a finding matches an exception rule."""
    if getattr(finding, "control_id", None) != exc.get("control_id"):
        return False
    resource = getattr(finding, "resource", "") or ""
    pattern = exc.get("resource_pattern", "*")
    return fnmatch.fnmatch(resource, pattern)


def apply_exceptions(
    findings: list[Any], exceptions: list[dict[str, Any]]
) -> list[Any]:
    """Apply active exceptions — FAIL findings matching a waiver become SKIP."""
    active = [e for e in exceptions if _is_active(e)]
    result: list[Any] = []
    for f in findings:
        if getattr(f, "status", None) == "FAIL":
            matched = next((e for e in active if _matches(f, e)), None)
            if matched:
                waived = copy.copy(f)
                waived.status = "SKIP"
                waived.evidence = (
                    f"Waived: {matched.get('reason', 'N/A')} "
                    f"(approver={matched.get('approver', 'N/A')})"
                )
                result.append(waived)
                continue
        result.append(f)
    return result
