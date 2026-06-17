from __future__ import annotations

import argparse
import importlib
import json
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import TextIO

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cloud.core import (
    Finding,
    change_manifest,
    exit_code,
    plan_manifest,
    render_json,
    render_sarif,
    render_text,
)
from cloud.html_report import render_html
from cloud.policy import load_policy
from cloud.providers import PROVIDERS


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Audit cloud resources against a security baseline"
    )
    parser.add_argument(
        "provider", choices=["aws", "azure", "gcp", "k8s", "all", "policy"]
    )
    parser.add_argument("policy_action", nargs="?", choices=["validate"])
    parser.add_argument("--mode", choices=["audit", "plan", "apply", "rollback"], default="audit")
    parser.add_argument("--format", choices=["text", "json", "sarif", "html"], default="text")
    parser.add_argument("--output", type=Path, help="Write the report to a file")
    parser.add_argument(
        "--control", action="append", default=[], help="Run one control ID; repeatable"
    )
    parser.add_argument(
        "--custom-controls", type=Path, help="YAML file with custom control definitions"
    )
    parser.add_argument(
        "--generate-playbook", type=Path,
        help="Generate remediation playbook from a plan/change manifest",
    )
    parser.add_argument(
        "--playbook-format", choices=["terraform", "cloudformation"],
        default="terraform",
    )
    parser.add_argument("--profile", help="AWS named profile")
    parser.add_argument(
        "--profiles",
        help="Comma-separated AWS named profiles for multi-account audit; overrides --profile",
    )
    parser.add_argument(
        "--organization-role",
        help="Discover active AWS Organization accounts and assume this role in each account",
    )
    parser.add_argument("--external-id", help="External ID used with --organization-role")
    parser.add_argument("--region", help="Cloud region override")
    parser.add_argument(
        "--regions",
        help="Comma-separated AWS regions for regional controls; overrides --region",
    )
    parser.add_argument("--workers", type=int, default=8, help="Maximum parallel checks")
    parser.add_argument("--policy", type=Path, help="Validated YAML policy overrides")
    parser.add_argument(
        "--change-manifest",
        type=Path,
        help="Write apply-mode change evidence to a JSON file",
    )
    parser.add_argument(
        "--plan-manifest",
        type=Path,
        help="Write plan-mode before/after evidence to a JSON file",
    )
    parser.add_argument(
        "--rollback-manifest",
        type=Path,
        help="Restore supported AWS settings from an apply-mode change manifest",
    )
    parser.add_argument(
        "--yes",
        action="store_true",
        help="Acknowledge changes when --mode apply or rollback is used",
    )
    return parser


def load_provider(name: str):
    try:
        return importlib.import_module(PROVIDERS[name])
    except ModuleNotFoundError as exc:
        expected = {f"cloud.{name}_harden", name + "_harden"}
        if exc.name in expected:
            raise RuntimeError(f"Provider module cloud.{name}_harden is not installed") from exc
        raise RuntimeError(f"A dependency required by {name} is missing: {exc.name}") from exc


def write_report(findings: list[Finding], report_format: str, stream: TextIO) -> None:
    renderers = {
        "text": render_text,
        "json": render_json,
        "sarif": render_sarif,
        "html": render_html,
    }
    renderers[report_format](findings, stream)


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.provider == "policy":
        if args.policy_action != "validate" or not args.policy:
            print("[x] usage: automation-hardening policy validate --policy PATH", file=sys.stderr)
            return 2
        try:
            load_policy(args.policy)
        except Exception as exc:
            print(f"[x] policy invalid: {exc}", file=sys.stderr)
            return 2
        print(f"[+] policy valid: {args.policy}")
        return 0
    if args.policy_action:
        print("[x] policy subcommands are only valid with provider 'policy'", file=sys.stderr)
        return 2
    if args.generate_playbook:
        from cloud.remediation import generate_playbook
        output = generate_playbook(args.generate_playbook, args.playbook_format)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(output, encoding="utf-8")
        else:
            sys.stdout.write(output)
        return 0
    if args.mode in {"apply", "rollback"} and not args.yes:
        print(f"[x] --mode {args.mode} requires --yes", file=sys.stderr)
        return 2
    if args.change_manifest and args.mode != "apply":
        print("[x] --change-manifest requires --mode apply", file=sys.stderr)
        return 2
    if args.plan_manifest and args.mode != "plan":
        print("[x] --plan-manifest requires --mode plan", file=sys.stderr)
        return 2
    if (args.mode == "rollback") != bool(args.rollback_manifest):
        print("[x] --mode rollback requires --rollback-manifest and vice versa", file=sys.stderr)
        return 2
    if args.mode == "rollback" and args.provider != "aws":
        print("[x] rollback is currently supported for AWS only", file=sys.stderr)
        return 2
    if args.mode == "apply" and args.provider in {"azure", "gcp"}:
        print(
            f"[x] apply mode is not yet supported for {args.provider}; use --mode plan",
            file=sys.stderr,
        )
        return 2

    if args.provider == "all":
        if args.mode in {"apply", "rollback"}:
            print(
                "[x] --mode apply/rollback is not supported with"
                " provider 'all'",
                file=sys.stderr,
            )
            return 2
        args.policy = load_policy(args.policy)
        findings: list[Finding] = []
        for prov in ("aws", "azure", "gcp", "k8s"):
            try:
                module = load_provider(prov)
                result = module.run_audit(args)
                if isinstance(result, list):
                    findings.extend(result)
            except RuntimeError as exc:
                print(
                    f"[!] skipping {prov}: {exc}",
                    file=sys.stderr,
                )
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            with args.output.open("w", encoding="utf-8") as stream:
                write_report(findings, args.format, stream)
        else:
            write_report(findings, args.format, sys.stdout)
        if args.plan_manifest:
            args.plan_manifest.parent.mkdir(parents=True, exist_ok=True)
            args.plan_manifest.write_text(
                json.dumps(
                    plan_manifest("all", findings), indent=2
                )
                + "\n",
                encoding="utf-8",
            )
        return exit_code(findings)

    try:
        args.policy = load_policy(args.policy)
        if args.mode == "rollback":
            import boto3

            from cloud.providers.aws.rollback import rollback_manifest

            session = boto3.Session(profile_name=args.profile, region_name=args.region)
            findings = rollback_manifest(session, args.rollback_manifest)
        else:
            module = load_provider(args.provider)
            supported: set[str] = getattr(module, "CONTROL_IDS", set())
            unknown = sorted(set(args.control) - set(supported))
            if unknown:
                raise ValueError(f"Unknown control ID(s) for {args.provider}: {', '.join(unknown)}")
            findings = module.run_audit(args)
        if not isinstance(findings, list):
            raise TypeError("provider run_audit() must return a list of Finding objects")
    except Exception as exc:
        print(f"[x] {exc}", file=sys.stderr)
        return 2

    if args.custom_controls:
        from cloud.custom_controls import run_custom_controls
        try:
            findings.extend(run_custom_controls(args.custom_controls, args))
        except Exception as exc:
            print(f"[!] custom controls error: {exc}", file=sys.stderr)

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with args.output.open("w", encoding="utf-8") as stream:
            write_report(findings, args.format, stream)
    else:
        write_report(findings, args.format, sys.stdout)
    if args.change_manifest:
        args.change_manifest.parent.mkdir(parents=True, exist_ok=True)
        args.change_manifest.write_text(
            json.dumps(change_manifest(args.provider, findings), indent=2) + "\n",
            encoding="utf-8",
        )
    if args.plan_manifest:
        args.plan_manifest.parent.mkdir(parents=True, exist_ok=True)
        args.plan_manifest.write_text(
            json.dumps(plan_manifest(args.provider, findings), indent=2) + "\n",
            encoding="utf-8",
        )
    code = exit_code(findings)
    if args.mode == "rollback" and any(item.status.value == "manual" for item in findings):
        return max(code, 1)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
