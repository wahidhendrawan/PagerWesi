"""Webhook alert module — send findings alerts to Slack, Teams, PagerDuty.

Includes retry logic with exponential backoff, URL validation,
and secure payload handling.
"""
from __future__ import annotations

import json
import ssl
import urllib.request
from typing import Any

from cloud.finding_utils import actionable_findings, finding_control_id
from cloud.input_validator import validate_webhook_url
from cloud.logging_config import get_logger
from cloud.rate_limiter import retry_with_backoff

logger = get_logger("webhooks")

# Maximum payload size to prevent accidentally sending large data
_MAX_PAYLOAD_SIZE = 64 * 1024  # 64 KiB
_REQUEST_TIMEOUT = 15  # seconds


def _filter_actionable(findings: list[Any]) -> list[Any]:
    """Keep only FAIL/ERROR findings."""
    return actionable_findings(findings)


def _summary(findings: list[Any]) -> dict[str, Any]:
    """Build concise summary: count + top 5 control IDs."""
    filtered = _filter_actionable(findings)
    ids = [finding_control_id(f) for f in filtered]
    # Deduplicate while preserving order
    seen: set[str] = set()
    unique_ids: list[str] = []
    for cid in ids:
        if cid not in seen:
            seen.add(cid)
            unique_ids.append(cid)
    return {
        "total_failures": len(filtered),
        "top_controls": unique_ids[:5],
        "message": f"{len(filtered)} finding(s) failed. Top: {', '.join(unique_ids[:5])}",
    }


@retry_with_backoff(max_retries=3, base_delay=2.0)
def _post_json(url: str, payload: dict) -> None:
    """Post JSON payload to a URL with retry and size validation.

    Args:
        url: Target webhook URL (must be HTTPS).
        payload: JSON-serializable payload.

    Raises:
        ValueError: If payload exceeds size limit or URL is invalid.
        urllib.error.URLError: If the request fails after retries.
    """
    data = json.dumps(payload).encode("utf-8")
    if len(data) > _MAX_PAYLOAD_SIZE:
        raise ValueError(
            f"Payload size ({len(data)} bytes) exceeds maximum ({_MAX_PAYLOAD_SIZE} bytes)"
        )

    # Create a secure SSL context
    ssl_context = ssl.create_default_context()

    req = urllib.request.Request(
        url,
        data=data,
        headers={
            "Content-Type": "application/json",
            "User-Agent": "PagerWesi-Webhook/1.0",
        },
    )
    logger.debug("Sending webhook to %s (%d bytes)", url, len(data))
    urllib.request.urlopen(req, timeout=_REQUEST_TIMEOUT, context=ssl_context)
    logger.info("Webhook delivered successfully to %s", url)


def send_slack(url: str, findings: list[Any]) -> None:
    """Post findings summary to a Slack incoming webhook.

    Args:
        url: Slack webhook URL (must be HTTPS).
        findings: List of finding objects or dicts.
    """
    validated_url = validate_webhook_url(url)
    s = _summary(findings)
    payload = {
        "text": f":warning: PagerWesi Alert: {s['message']}",
        "blocks": [
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*PagerWesi Security Alert*\n{s['message']}",
                },
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Total Failures:*\n{s['total_failures']}"},
                    {"type": "mrkdwn", "text": f"*Top Controls:*\n{', '.join(s['top_controls'])}"},
                ],
            },
        ],
    }
    _post_json(validated_url, payload)


def send_teams(url: str, findings: list[Any]) -> None:
    """Post findings summary to a Microsoft Teams webhook.

    Args:
        url: Teams webhook URL (must be HTTPS).
        findings: List of finding objects or dicts.
    """
    validated_url = validate_webhook_url(url)
    s = _summary(findings)
    payload = {
        "@type": "MessageCard",
        "@context": "http://schema.org/extensions",
        "themeColor": "FF0000",
        "summary": f"PagerWesi Alert: {s['total_failures']} failures",
        "sections": [
            {
                "activityTitle": "PagerWesi Security Alert",
                "facts": [
                    {"name": "Total Failures", "value": str(s["total_failures"])},
                    {"name": "Top Controls", "value": ", ".join(s["top_controls"])},
                ],
                "markdown": True,
            }
        ],
    }
    _post_json(validated_url, payload)


def send_pagerduty(key: str, findings: list[Any]) -> None:
    """Trigger a PagerDuty event with findings summary.

    Args:
        key: PagerDuty routing/integration key.
        findings: List of finding objects or dicts.
    """
    if not key or len(key) < 10:
        raise ValueError("Invalid PagerDuty routing key")

    s = _summary(findings)
    severity = "critical" if s["total_failures"] > 5 else "error"
    payload = {
        "routing_key": key,
        "event_action": "trigger",
        "payload": {
            "summary": s["message"][:1024],  # PagerDuty limit
            "severity": severity,
            "source": "pagerwesi",
            "component": "security-audit",
            "custom_details": {
                "total_failures": s["total_failures"],
                "top_controls": s["top_controls"],
            },
        },
    }
    _post_json("https://events.pagerduty.com/v2/enqueue", payload)


def notify(config: dict[str, str], findings: list[Any]) -> None:
    """Dispatch alerts based on config keys: slack_url, teams_url, pagerduty_key.

    Args:
        config: Notification configuration dict.
        findings: List of finding objects or dicts.
    """
    if not isinstance(config, dict):
        logger.error("Notification config must be a dict, got %s", type(config).__name__)
        return

    if not _filter_actionable(findings):
        logger.info("No actionable findings; skipping notifications")
        return

    errors: list[str] = []

    if config.get("slack_url"):
        try:
            send_slack(config["slack_url"], findings)
        except Exception as exc:
            errors.append(f"Slack: {exc}")
            logger.error("Slack notification failed: %s", exc)

    if config.get("teams_url"):
        try:
            send_teams(config["teams_url"], findings)
        except Exception as exc:
            errors.append(f"Teams: {exc}")
            logger.error("Teams notification failed: %s", exc)

    if config.get("pagerduty_key"):
        try:
            send_pagerduty(config["pagerduty_key"], findings)
        except Exception as exc:
            errors.append(f"PagerDuty: {exc}")
            logger.error("PagerDuty notification failed: %s", exc)

    if errors:
        logger.warning("Some notifications failed: %s", "; ".join(errors))
