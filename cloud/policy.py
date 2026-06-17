from __future__ import annotations

import fnmatch
import json
from pathlib import Path

import yaml

_SCHEMA_PATH = Path(__file__).resolve().parent.parent / "docs" / "policy.schema.json"


def _validate_schema(document: dict) -> None:
    """Validate policy document against JSON Schema with precise error paths."""
    try:
        import jsonschema
    except ModuleNotFoundError:  # pragma: no cover
        return
    schema = json.loads(_SCHEMA_PATH.read_text(encoding="utf-8"))
    validator = jsonschema.Draft202012Validator(schema)
    errors = sorted(validator.iter_errors(document), key=lambda e: list(e.absolute_path))
    if errors:
        messages = []
        for error in errors:
            path = ".".join(str(p) for p in error.absolute_path) or "(root)"
            messages.append(f"  {path}: {error.message}")
        raise ValueError("Policy schema validation failed:\n" + "\n".join(messages))


def load_policy(path: Path | None) -> dict:
    if path is None:
        return {}
    content = path.read_text(encoding="utf-8")
    if len(content.encode("utf-8")) > 1024 * 1024:
        raise ValueError("Policy must not exceed 1 MiB")
    document = yaml.safe_load(content)
    if not isinstance(document, dict) or document.get("version") != 1:
        raise ValueError("Policy must be a mapping with version: 1")
    _validate_schema(document)
    return document


def aws_setting(args, key: str) -> str | None:
    policy = getattr(args, "policy", {}) or {}
    value = policy.get("aws", {}).get(key)
    return str(value) if value else None


def admin_ports(args, provider: str, defaults: set[str]) -> set[str]:
    policy = getattr(args, "policy", {}) or {}
    network = policy.get("network", {})
    key = f"{provider}_admin_ports"
    return {str(port) for port in network[key]} if key in network else defaults


def excluded(args, resource: str) -> bool:
    policy = getattr(args, "policy", {}) or {}
    return any(
        fnmatch.fnmatchcase(resource, pattern) for pattern in policy.get("exclude_resources", [])
    )
