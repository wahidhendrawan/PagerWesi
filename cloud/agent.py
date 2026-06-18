from __future__ import annotations

import json
import signal
import sys
import time
from pathlib import Path
from types import SimpleNamespace

from cloud.core import Finding, Severity, Status
from cloud.finding_utils import normalized_status

STATE_FILE = Path(".automation-hardening-state.json")
_shutdown = False


def _handle_signal(signum, frame):
    global _shutdown
    _shutdown = True


def _load_state() -> list[dict]:
    if STATE_FILE.exists():
        return json.loads(STATE_FILE.read_text(encoding="utf-8"))
    return []


def _save_state(findings: list[dict]) -> None:
    STATE_FILE.write_text(json.dumps(findings, indent=2), encoding="utf-8")


def _run_providers(providers: list[str], args) -> list[dict]:
    from cloud.main import load_provider

    all_findings: list[dict] = []
    for prov in providers:
        try:
            module = load_provider(prov)
            findings = module.run_audit(args)
            all_findings.extend(f.to_dict() for f in findings)
        except Exception as exc:
            print(
                f"[agent] provider {prov} failed: {type(exc).__name__}: {exc}",
                file=sys.stderr,
            )
            all_findings.append(
                Finding(
                    "AGENT-PROVIDER-001",
                    "Agent provider audit failed",
                    Status.ERROR,
                    Severity.HIGH,
                    f"agent:{prov}",
                    f"{type(exc).__name__}: {exc}",
                    "Check provider credentials, dependencies, and runtime configuration.",
                ).to_dict()
            )
    return all_findings


def _new_fails(current: list[dict], previous: list[dict]) -> list[dict]:
    prev_keys = {
        (f.get("control_id"), f.get("resource"))
        for f in previous
        if normalized_status(f) in {"fail", "error"}
    }
    return [
        f for f in current
        if normalized_status(f) in {"fail", "error"}
        and (f.get("control_id"), f.get("resource")) not in prev_keys
    ]


def run_agent(args) -> int:
    """Run in agent/daemon mode with periodic audit and alerting."""
    signal.signal(signal.SIGINT, _handle_signal)
    signal.signal(signal.SIGTERM, _handle_signal)

    interval = getattr(args, "interval", 300)
    watch = getattr(args, "watch_providers", None)
    providers = watch.split(",") if watch else ["aws", "azure", "gcp", "k8s"]
    notify_cfg = None
    if getattr(args, "notify", None):
        import yaml
        notify_cfg = yaml.safe_load(args.notify.read_text(encoding="utf-8"))

    print(f"[agent] starting, interval={interval}s, providers={providers}")
    audit_args = SimpleNamespace(
        control=[], mode="audit", policy={},
        profile=None, region=None, regions=None,
        profiles=None, organization_role=None,
        external_id=None, workers=8, endpoints=None, path=None,
    )

    while not _shutdown:
        previous = _load_state()
        current = _run_providers(providers, audit_args)
        _save_state(current)
        new_fails = _new_fails(current, previous)
        if new_fails:
            print(f"[agent] {len(new_fails)} new failures detected")
            if notify_cfg:
                from cloud.webhooks import notify
                notify(notify_cfg, new_fails)
        else:
            print("[agent] no new failures")
        for _ in range(interval):
            if _shutdown:
                break
            time.sleep(1)

    print("[agent] shutting down")
    return 0
