from __future__ import annotations

import json
from collections.abc import Iterable
from dataclasses import asdict, dataclass
from enum import Enum
from typing import TextIO


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

    def to_dict(self) -> dict[str, str]:
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
        rules[finding.control_id] = {
            "id": finding.control_id,
            "name": finding.title,
            "shortDescription": {"text": finding.title},
            "help": {"text": finding.remediation or "Review the finding evidence."},
        }
        if finding.status in {Status.FAIL, Status.ERROR, Status.MANUAL}:
            results.append(
                {
                    "ruleId": finding.control_id,
                    "level": level[finding.severity],
                    "message": {"text": f"{finding.resource}: {finding.evidence}"},
                }
            )
    document = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "Automation-Hardening", "rules": list(rules.values())}},
                "results": results,
            }
        ],
    }
    json.dump(document, stream, indent=2)
    stream.write("\n")
