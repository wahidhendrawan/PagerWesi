from __future__ import annotations

import json
import os
from collections.abc import Iterable
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import TextIO

from cloud.control_registry import CONTROL_METADATA


class Status(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    ERROR = "error"
    SKIP = "skip"
    MANUAL = "manual"


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(frozen=True)
class Finding:
    control_id: str
    title: str
    status: Status
    severity: Severity
    resource: str
    evidence: str
    remediation: str = ""
    benchmark: str = "Project baseline v1"
    changed: bool = False
    planned: bool = False
    before: object | None = None
    after: object | None = None

    def to_dict(self) -> dict[str, object]:
        data = asdict(self)
        data["status"] = self.status.value
        data["severity"] = self.severity.value
        return data


def summarize(findings: Iterable[Finding]) -> dict[str, int]:
    summary = {status.value: 0 for status in Status}
    for finding in findings:
        summary[finding.status.value] += 1
    return summary


def exit_code(findings: Iterable[Finding]) -> int:
    statuses = {finding.status for finding in findings}
    if Status.ERROR in statuses:
        return 2
    if Status.FAIL in statuses:
        return 1
    return 0


def change_manifest(provider: str, findings: Iterable[Finding]) -> dict[str, object]:
    changes = [finding.to_dict() for finding in findings if finding.changed]
    return {
        "schema_version": "1.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "actor": os.getenv("GITHUB_ACTOR") or os.getenv("USER") or "unknown",
        "provider": provider,
        "changes": changes,
        "change_count": len(changes),
    }


def plan_manifest(provider: str, findings: Iterable[Finding]) -> dict[str, object]:
    plans = [finding.to_dict() for finding in findings if finding.planned]
    return {
        "schema_version": "1.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "actor": os.getenv("GITHUB_ACTOR") or os.getenv("USER") or "unknown",
        "provider": provider,
        "plans": plans,
        "plan_count": len(plans),
    }


def render_text(findings: list[Finding], stream: TextIO) -> None:
    symbols = {
        Status.PASS: "+",
        Status.FAIL: "!",
        Status.ERROR: "x",
        Status.SKIP: "-",
        Status.MANUAL: "?",
    }
    for finding in findings:
        stream.write(
            f"[{symbols[finding.status]}] {finding.control_id} "
            f"{finding.status.value.upper():6} {finding.resource}: {finding.title}\n"
        )
        stream.write(f"    Evidence: {finding.evidence}\n")
        if finding.planned:
            stream.write(f"    Planned change: {finding.before!r} -> {finding.after!r}\n")
        if finding.remediation and finding.status != Status.PASS:
            stream.write(f"    Remediation: {finding.remediation}\n")
    counts = summarize(findings)
    stream.write("Summary: " + ", ".join(f"{key}={value}" for key, value in counts.items()) + "\n")


def render_json(findings: list[Finding], stream: TextIO) -> None:
    json.dump(
        {"findings": [finding.to_dict() for finding in findings], "summary": summarize(findings)},
        stream,
        indent=2,
    )
    stream.write("\n")


def render_sarif(findings: list[Finding], stream: TextIO) -> None:
    level = {
        Severity.CRITICAL: "error",
        Severity.HIGH: "error",
        Severity.MEDIUM: "warning",
        Severity.LOW: "note",
        Severity.INFO: "note",
    }
    rules = {}
    results = []
    for finding in findings:
        metadata = CONTROL_METADATA.get(finding.control_id)
        rules[finding.control_id] = {
            "id": finding.control_id,
            "name": metadata.intent if metadata else finding.title,
            "shortDescription": {"text": metadata.intent if metadata else finding.title},
            "fullDescription": {
                "text": (
                    f"{finding.control_id}: {metadata.intent if metadata else finding.title}. "
                    f"Apply behavior: {metadata.apply_behavior if metadata else 'N/A'}."
                )
            },
            "help": {
                "text": finding.remediation or "Review the finding evidence.",
                "markdown": (
                    f"**Remediation**: {finding.remediation or 'Review the finding evidence.'}\n\n"
                    f"See [control catalog]({metadata.help_uri if metadata else 'https://wahidhendrawan.github.io/Automation-Hardening/controls.html'})."
                ),
            },
            "helpUri": (
                metadata.help_uri
                if metadata
                else "https://wahidhendrawan.github.io/Automation-Hardening/controls.html"
            ),
            "properties": {
                "target": metadata.target if metadata else finding.resource.split(":", 1)[0],
                "benchmark": finding.benchmark,
                "security-severity": {
                    Severity.CRITICAL: "9.0",
                    Severity.HIGH: "7.0",
                    Severity.MEDIUM: "5.0",
                    Severity.LOW: "3.0",
                    Severity.INFO: "1.0",
                }[finding.severity],
                "tags": [f"nist-csf/{ref}" for ref in (metadata.nist_csf if metadata else ())]
                + [f"iso27001/{ref}" for ref in (metadata.iso_27001 if metadata else ())]
                + ([f"cis/{metadata.cis}"] if metadata else []),
            },
        }
        if finding.status in {Status.FAIL, Status.ERROR, Status.MANUAL}:
            results.append(
                {
                    "ruleId": finding.control_id,
                    "level": level[finding.severity],
                    "message": {"text": f"{finding.resource}: {finding.evidence}"},
                    "properties": {"status": finding.status.value},
                }
            )
    document = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Automation-Hardening",
                        "version": "0.6.0",
                        "informationUri": "https://github.com/wahidhendrawan/Automation-Hardening",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }
    json.dump(document, stream, indent=2)
    stream.write("\n")
