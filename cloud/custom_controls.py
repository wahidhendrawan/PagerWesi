"""Load and execute user-defined custom controls from YAML files."""
from __future__ import annotations

import re
import subprocess
from pathlib import Path

import yaml

from cloud.core import Finding, Severity, Status


def _severity(value: str) -> Severity:
    return Severity(value.lower()) if value else Severity.MEDIUM


def _run_check(command: str) -> tuple[int, str]:
    result = subprocess.run(
        command, shell=True, capture_output=True, text=True, timeout=30
    )
    return result.returncode, result.stdout.strip() or result.stderr.strip()


def load_custom_controls(path: Path) -> list[dict]:
    """Load custom controls from a YAML file."""
    content = path.read_text(encoding="utf-8")
    doc = yaml.safe_load(content)
    if not isinstance(doc, dict) or doc.get("version") != 1:
        raise ValueError("Custom controls file must have version: 1")
    controls = doc.get("controls", [])
    if not isinstance(controls, list):
        raise ValueError("controls must be a list")
    for ctrl in controls:
        if not isinstance(ctrl, dict):
            raise ValueError("Each control must be a mapping")
        required = {"id", "title", "check"}
        missing = required - set(ctrl)
        if missing:
            raise ValueError(f"Control missing keys: {missing}")
        if not re.fullmatch(r"CUSTOM-[A-Z0-9]+-\d{3}", ctrl["id"]):
            raise ValueError(
                f"Control ID must match CUSTOM-XXX-NNN: {ctrl['id']}"
            )
    return controls


def run_custom_controls(path: Path, args) -> list[Finding]:
    """Execute custom controls and return findings."""
    controls = load_custom_controls(path)
    findings: list[Finding] = []
    for ctrl in controls:
        cid = ctrl["id"]
        if args.control and cid not in args.control:
            continue
        severity = _severity(ctrl.get("severity", "medium"))
        try:
            rc, output = _run_check(ctrl["check"])
            expect = ctrl.get("expect", 0)
            passed = rc == expect
            is_plan = not passed and getattr(args, "mode", "audit") == "plan"
            findings.append(Finding(
                cid,
                ctrl["title"],
                Status.PASS if passed else Status.FAIL,
                severity,
                ctrl.get("target", "custom"),
                output[:200] or f"exit_code={rc}",
                ctrl.get("remediation", ""),
                planned=is_plan,
                before={"compliant": False} if is_plan else None,
                after={"compliant": True} if is_plan else None,
            ))
        except Exception as exc:
            findings.append(Finding(
                cid, ctrl["title"], Status.ERROR, severity,
                ctrl.get("target", "custom"), str(exc)[:200],
            ))
    return findings
