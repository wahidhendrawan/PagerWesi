from __future__ import annotations

import argparse
import importlib
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import TextIO

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cloud.core import Finding, exit_code, render_json, render_sarif, render_text
from cloud.providers import PROVIDERS


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Audit cloud resources against a security baseline"
    )
    parser.add_argument("provider", choices=["aws", "azure", "gcp"])
    parser.add_argument("--mode", choices=["audit", "plan", "apply"], default="audit")
    parser.add_argument("--format", choices=["text", "json", "sarif"], default="text")
    parser.add_argument("--output", type=Path, help="Write the report to a file")
    parser.add_argument(
        "--control", action="append", default=[], help="Run one control ID; repeatable"
    )
    parser.add_argument("--profile", help="AWS named profile")
    parser.add_argument(
        "--profiles",
        help="Comma-separated AWS named profiles for multi-account audit; overrides --profile",
    )
    parser.add_argument("--region", help="Cloud region override")
    parser.add_argument(
        "--regions",
        help="Comma-separated AWS regions for regional controls; overrides --region",
    )
    parser.add_argument("--workers", type=int, default=8, help="Maximum parallel checks")
    parser.add_argument(
        "--yes",
        action="store_true",
        help="Acknowledge changes when --mode apply is used",
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
    {"text": render_text, "json": render_json, "sarif": render_sarif}[report_format](
        findings, stream
    )


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.mode == "apply" and not args.yes:
        print("[x] --mode apply requires --yes", file=sys.stderr)
        return 2

    try:
        module = load_provider(args.provider)
        supported = getattr(module, "CONTROL_IDS", set())
        unknown = sorted(set(args.control) - set(supported))
        if unknown:
            raise ValueError(f"Unknown control ID(s) for {args.provider}: {', '.join(unknown)}")
        findings = module.run_audit(args)
        if not isinstance(findings, list):
            raise TypeError("provider run_audit() must return a list of Finding objects")
    except Exception as exc:
        print(f"[x] {exc}", file=sys.stderr)
        return 2

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with args.output.open("w", encoding="utf-8") as stream:
            write_report(findings, args.format, stream)
    else:
        write_report(findings, args.format, sys.stdout)
    return exit_code(findings)


if __name__ == "__main__":
    raise SystemExit(main())
