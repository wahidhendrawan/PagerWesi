"""Webhook alert module — send findings alerts to Slack, Teams, PagerDuty."""
from __future__ import annotations

import json
import urllib.request
from typing import Any


def _filter_actionable(findings: list[Any]) -> list[Any]:
    """Keep only FAIL/ERROR findings."""
    return [f for f in findings if getattr(f, "status", None) in ("FAIL", "ERROR")]


def _summary(findings: list[Any]) -> dict[str, Any]:
    """Build concise summary: count + top 5 control IDs."""
    filtered = _filter_actionable(findings)
    ids = [getattr(f, "control_id", "unknown") for f in filtered]
    return {
        "total_failures": len(filtered),
        "top_controls": ids[:5],
        "message": f"{len(filtered)} finding(s) failed. Top: {', '.join(ids[:5])}",
    }


def _post_json(url: str, payload: dict) -> None:
    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        url, data=data, headers={"Content-Type": "application/json"}
    )
    urllib.request.urlopen(req)


def send_slack(url: str, findings: list[Any]) -> None:
    """Post findings summary to a Slack incoming webhook."""
    s = _summary(findings)
    _post_json(url, {"text": s["message"]})


def send_teams(url: str, findings: list[Any]) -> None:
    """Post findings summary to a Microsoft Teams webhook."""
    s = _summary(findings)
    _post_json(url, {"text": s["message"]})


def send_pagerduty(key: str, findings: list[Any]) -> None:
    """Trigger a PagerDuty event with findings summary."""
    s = _summary(findings)
    payload = {
        "routing_key": key,
        "event_action": "trigger",
        "payload": {
            "summary": s["message"],
            "severity": "critical",
            "source": "automation-hardening",
        },
    }
    _post_json("https://events.pagerduty.com/v2/enqueue", payload)


def notify(config: dict[str, str], findings: list[Any]) -> None:
    """Dispatch alerts based on config keys: slack_url, teams_url, pagerduty_key."""
    if not _filter_actionable(findings):
        return
    if config.get("slack_url"):
        send_slack(config["slack_url"], findings)
    if config.get("teams_url"):
        send_teams(config["teams_url"], findings)
    if config.get("pagerduty_key"):
        send_pagerduty(config["pagerduty_key"], findings)
