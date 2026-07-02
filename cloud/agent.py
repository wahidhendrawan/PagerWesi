"""Agent/daemon mode — periodic audits with state diffing and alerting.

Runs periodic security audits across configured providers, detects new
failures, and sends webhook notifications. Includes state rotation
and structured logging.
"""
from __future__ import annotations

import json
import signal
import time
from pathlib import Path
from types import SimpleNamespace

from cloud.core import Finding, Severity, Status
from cloud.finding_utils import normalized_status
from cloud.logging_config import get_logger

logger = get_logger("agent")

STATE_FILE = Path(".pagerwesi-state.json")
STATE_HISTORY_DIR = Path(".pagerwesi-history")
MAX_STATE_HISTORY = 30  # Keep last 30 audit states

_shutdown = False


def _handle_signal(signum, frame):
    global _shutdown
    _shutdown = True
    logger.info("Received signal %d, initiating graceful shutdown", signum)


def _load_state() -> list[dict]:
    """Load previous audit state from disk."""
    if STATE_FILE.exists():
        try:
            content = STATE_FILE.read_text(encoding="utf-8")
            # Validate file size to prevent OOM
            if len(content) > 50 * 1024 * 1024:  # 50 MiB limit
                logger.warning("State file exceeds size limit, starting fresh")
                return []
            return json.loads(content)
        except (json.JSONDecodeError, OSError) as exc:
            logger.error("Failed to load state file: %s", exc)
            return []
    return []


def _save_state(findings: list[dict]) -> None:
    """Save current audit state to disk with rotation."""
    try:
        state_data = json.dumps(findings, indent=2)
        STATE_FILE.write_text(state_data, encoding="utf-8")

        # Rotate historical states
        _rotate_history(state_data)
    except OSError as exc:
        logger.error("Failed to save state: %s", exc)


def _rotate_history(state_data: str) -> None:
    """Keep a history of audit states for trend analysis."""
    try:
        STATE_HISTORY_DIR.mkdir(parents=True, exist_ok=True)
        timestamp = time.strftime("%Y%m%d-%H%M%S")
        history_file = STATE_HISTORY_DIR / f"state-{timestamp}.json"
        history_file.write_text(state_data, encoding="utf-8")

        # Clean up old history files
        history_files = sorted(STATE_HISTORY_DIR.glob("state-*.json"))
        while len(history_files) > MAX_STATE_HISTORY:
            oldest = history_files.pop(0)
            oldest.unlink(missing_ok=True)
            logger.debug("Removed old state file: %s", oldest.name)
    except OSError as exc:
        logger.warning("Failed to rotate history: %s", exc)


def _run_providers(providers: list[str], args) -> list[dict]:
    """Run audit across configured providers with error isolation."""
    from cloud.main import load_provider

    all_findings: list[dict] = []
    for prov in providers:
        try:
            logger.info("Auditing provider: %s", prov)
            module = load_provider(prov)
            findings = module.run_audit(args)
            all_findings.extend(f.to_dict() for f in findings)
            logger.info(
                "Provider %s: %d findings",
                prov,
                len(findings),
            )
        except Exception as exc:
            logger.error(
                "Provider %s failed: %s: %s",
                prov,
                type(exc).__name__,
                exc,
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
    """Identify new failures that weren't in the previous state."""
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


def _resolved_findings(current: list[dict], previous: list[dict]) -> list[dict]:
    """Identify findings that were failing before but now pass."""
    current_keys = {
        (f.get("control_id"), f.get("resource"))
        for f in current
        if normalized_status(f) == "pass"
    }
    return [
        f for f in previous
        if normalized_status(f) in {"fail", "error"}
        and (f.get("control_id"), f.get("resource")) in current_keys
    ]


def run_agent(args) -> int:
    """Run in agent/daemon mode with periodic audit and alerting.

    Args:
        args: CLI arguments namespace.

    Returns:
        Exit code (0 for clean shutdown).
    """
    signal.signal(signal.SIGINT, _handle_signal)
    signal.signal(signal.SIGTERM, _handle_signal)

    interval = getattr(args, "interval", 300)
    if interval < 30:
        logger.warning("Interval %ds is very short, using minimum of 30s", interval)
        interval = 30

    watch = getattr(args, "watch_providers", None)
    providers = watch.split(",") if watch else ["aws", "azure", "gcp", "k8s"]

    # Validate provider names
    valid_providers = {"aws", "azure", "gcp", "k8s", "docker", "secrets", "terraform", "network"}
    providers = [p.strip() for p in providers if p.strip() in valid_providers]
    if not providers:
        logger.error("No valid providers configured")
        return 2

    notify_cfg = None
    if getattr(args, "notify", None):
        try:
            import yaml
            notify_cfg = yaml.safe_load(args.notify.read_text(encoding="utf-8"))
        except Exception as exc:
            logger.error("Failed to load notification config: %s", exc)

    logger.info(
        "Agent starting: interval=%ds, providers=%s",
        interval,
        providers,
    )

    audit_args = SimpleNamespace(
        control=[], mode="audit", policy={},
        profile=None, region=None, regions=None,
        profiles=None, organization_role=None,
        external_id=None, workers=8, endpoints=None, path=None,
    )

    cycle_count = 0
    while not _shutdown:
        cycle_count += 1
        logger.info("Starting audit cycle #%d", cycle_count)

        previous = _load_state()
        current = _run_providers(providers, audit_args)
        _save_state(current)

        new_fails = _new_fails(current, previous)
        resolved = _resolved_findings(current, previous)

        total_fail = sum(1 for f in current if normalized_status(f) in {"fail", "error"})

        if new_fails:
            logger.warning(
                "Cycle #%d: %d new failures detected (total: %d)",
                cycle_count,
                len(new_fails),
                total_fail,
            )
            if notify_cfg:
                try:
                    from cloud.webhooks import notify
                    notify(notify_cfg, new_fails)
                except Exception as exc:
                    logger.error("Notification dispatch failed: %s", exc)
        else:
            logger.info(
                "Cycle #%d: no new failures (total: %d, resolved: %d)",
                cycle_count,
                total_fail,
                len(resolved),
            )

        # Sleep in 1-second intervals for responsive shutdown
        for _ in range(interval):
            if _shutdown:
                break
            time.sleep(1)

    logger.info("Agent shutting down after %d cycles", cycle_count)
    return 0
