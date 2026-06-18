from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from cloud.control_registry import CONTROL_METADATA  # noqa: E402

_PREAMBLE = (
    "The benchmark field currently identifies `Project baseline v1`. "
    "Control mappings should be pinned\n"
    "to an exact licensed benchmark version before this project is used "
    "for formal compliance evidence."
)

_KNOWN_GAPS = """\
- AWS checks support named profiles, Organizations account discovery,
  role assumption, and multi-region assessment. Member-account failures
  are isolated and reported per account.
- Azure and GCP cover high-value storage, network, key management,
  monitoring, and logging baselines but do not yet represent complete
  provider benchmarks.
- Azure and GCP plan mode generates non-mutating plan manifests with
  recommended changes. Apply mode is not yet available for these providers.
- OS checks cover a high-value baseline, not a complete workstation/server
  benchmark.
- Linux rollback restores SSH configuration only; package and firewall
  state require platform-native recovery procedures.

Framework relationships are maintained in
[compliance-mapping.json](compliance-mapping.json). They are informative
and must be validated against the exact licensed benchmark and
organizational scope before being used as compliance evidence."""

_ROLLBACK = """\
AWS rollback manifests restore supported changes:

| Control | Rollback action |
|---|---|
| AWS-S3-001 | Restore or remove account Public Access Block |
| AWS-S3-004 | Restore or remove bucket Public Access Block |
| AWS-S3-005 | Restore or remove bucket default encryption |
| AWS-S3-006 | MANUAL — versioning cannot return to never-enabled state |
| AWS-EBS-001 | Disable EBS encryption by default if previously disabled |
| AWS-IAM-002 | Delete tool-created Access Analyzer if previously absent |
| AWS-VPC-001 | Delete Flow Logs created by the tool when IDs are in manifest |

Review the manifest and use least-privilege credentials before confirming
rollback."""

_CIS_DESC = (
    "Applicable CIS Benchmark family; verify exact "
    "licensed benchmark version and profile"
)

_DISCLAIMER = (
    "Informative mapping only. "
    "It is not certification or proof of full compliance."
)


def controls_markdown() -> str:
    lines = [
        "# Control Catalog",
        "",
        _PREAMBLE,
        "",
        "| ID | Target | Intent | Apply behavior |",
        "|---|---|---|---|",
    ]
    for control in CONTROL_METADATA.values():
        lines.append(
            f"| {control.control_id} | {control.target} "
            f"| {control.intent} | {control.apply_behavior} |"
        )
    lines.extend(
        [
            "",
            "## Known Gaps",
            "",
            _KNOWN_GAPS,
            "",
            "## Rollback Boundaries",
            "",
            _ROLLBACK,
        ]
    )
    return "\n".join(lines) + "\n"


def compliance_mapping() -> str:
    document = {
        "schema_version": "1.0",
        "disclaimer": _DISCLAIMER,
        "frameworks": {
            "nist_csf": "NIST Cybersecurity Framework 2.0",
            "iso_27001": "ISO/IEC 27001:2022 Annex A",
            "cis": _CIS_DESC,
        },
        "mappings": {
            control.control_id: {
                "nist_csf": list(control.nist_csf),
                "iso_27001": list(control.iso_27001),
                "cis": control.cis,
            }
            for control in CONTROL_METADATA.values()
        },
    }
    return json.dumps(document, indent=2) + "\n"


def main() -> int:
    docs = ROOT / "docs"
    docs.joinpath("controls.md").write_text(
        controls_markdown(), encoding="utf-8"
    )
    docs.joinpath("compliance-mapping.json").write_text(
        compliance_mapping(), encoding="utf-8"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
