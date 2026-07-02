"""Tests for the webhooks notification module."""
from __future__ import annotations

from unittest.mock import patch

import pytest

from cloud.core import Finding, Severity, Status
from cloud.input_validator import ValidationError
from cloud.webhooks import (
    _filter_actionable,
    _summary,
    notify,
    send_pagerduty,
    send_slack,
    send_teams,
)


def _make_finding(status=Status.FAIL, control_id="TEST-001"):
    return Finding(
        control_id=control_id,
        title="Test finding",
        status=status,
        severity=Severity.HIGH,
        resource="test:resource",
        evidence="test evidence",
    )


class TestFilterActionable:
    def test_keeps_fail_and_error(self):
        """Should keep FAIL and ERROR findings."""
        findings = [
            _make_finding(Status.PASS),
            _make_finding(Status.FAIL),
            _make_finding(Status.ERROR),
            _make_finding(Status.SKIP),
        ]
        result = _filter_actionable(findings)
        assert len(result) == 2

    def test_empty_list(self):
        """Should handle empty list."""
        assert _filter_actionable([]) == []


class TestSummary:
    def test_summary_counts(self):
        """Should count failures correctly."""
        findings = [_make_finding(Status.FAIL) for _ in range(3)]
        s = _summary(findings)
        assert s["total_failures"] == 3

    def test_top_controls_deduplicated(self):
        """Should deduplicate control IDs."""
        findings = [
            _make_finding(Status.FAIL, "CTRL-001"),
            _make_finding(Status.FAIL, "CTRL-001"),
            _make_finding(Status.FAIL, "CTRL-002"),
        ]
        s = _summary(findings)
        assert s["top_controls"] == ["CTRL-001", "CTRL-002"]

    def test_top_controls_limited_to_five(self):
        """Should limit to top 5 controls."""
        findings = [
            _make_finding(Status.FAIL, f"CTRL-{i:03d}") for i in range(10)
        ]
        s = _summary(findings)
        assert len(s["top_controls"]) == 5


class TestSendSlack:
    @patch("cloud.webhooks._post_json")
    def test_sends_to_valid_url(self, mock_post):
        """Should send to valid HTTPS URL."""
        findings = [_make_finding()]
        send_slack("https://hooks.slack.com/services/T00/B00/xxx", findings)
        mock_post.assert_called_once()
        payload = mock_post.call_args.args[1]
        assert "blocks" in payload
        assert "PagerWesi" in payload["text"]

    def test_rejects_http_url(self):
        """Should reject non-HTTPS URLs."""
        with pytest.raises(ValidationError):
            send_slack("http://insecure.example.com/hook", [_make_finding()])

    def test_rejects_private_ip(self):
        """Should reject private/internal IPs (SSRF protection)."""
        with pytest.raises(ValidationError):
            send_slack("https://192.168.1.1/hook", [_make_finding()])


class TestSendTeams:
    @patch("cloud.webhooks._post_json")
    def test_sends_message_card(self, mock_post):
        """Should send MessageCard format to Teams."""
        findings = [_make_finding()]
        send_teams("https://outlook.office.com/webhook/xxx", findings)
        mock_post.assert_called_once()
        payload = mock_post.call_args.args[1]
        assert payload["@type"] == "MessageCard"


class TestSendPagerDuty:
    @patch("cloud.webhooks._post_json")
    def test_sends_trigger_event(self, mock_post):
        """Should send trigger event to PagerDuty."""
        findings = [_make_finding()]
        send_pagerduty("valid_routing_key_1234567890", findings)
        mock_post.assert_called_once()
        payload = mock_post.call_args.args[1]
        assert payload["event_action"] == "trigger"
        assert payload["routing_key"] == "valid_routing_key_1234567890"

    def test_rejects_invalid_key(self):
        """Should reject too-short routing keys."""
        with pytest.raises(ValueError):
            send_pagerduty("short", [_make_finding()])

    @patch("cloud.webhooks._post_json")
    def test_critical_severity_for_many_failures(self, mock_post):
        """Should use critical severity when many failures."""
        findings = [_make_finding() for _ in range(10)]
        send_pagerduty("valid_routing_key_1234567890", findings)
        payload = mock_post.call_args.args[1]
        assert payload["payload"]["severity"] == "critical"


class TestNotify:
    @patch("cloud.webhooks.send_slack")
    @patch("cloud.webhooks.send_teams")
    @patch("cloud.webhooks.send_pagerduty")
    def test_dispatches_to_configured_channels(self, mock_pd, mock_teams, mock_slack):
        """Should dispatch to all configured channels."""
        config = {
            "slack_url": "https://hooks.slack.com/test",
            "teams_url": "https://outlook.office.com/test",
            "pagerduty_key": "valid_routing_key_1234567890",
        }
        findings = [_make_finding()]
        notify(config, findings)
        mock_slack.assert_called_once()
        mock_teams.assert_called_once()
        mock_pd.assert_called_once()

    @patch("cloud.webhooks.send_slack")
    def test_skips_when_no_actionable_findings(self, mock_slack):
        """Should skip notifications when all findings pass."""
        config = {"slack_url": "https://hooks.slack.com/test"}
        findings = [_make_finding(Status.PASS)]
        notify(config, findings)
        mock_slack.assert_not_called()

    @patch("cloud.webhooks.send_slack")
    def test_handles_notification_errors_gracefully(self, mock_slack):
        """Should continue even if one channel fails."""
        mock_slack.side_effect = Exception("Connection failed")
        config = {"slack_url": "https://hooks.slack.com/test"}
        findings = [_make_finding()]
        # Should not raise
        notify(config, findings)

    def test_rejects_non_dict_config(self):
        """Should handle non-dict config gracefully."""
        notify("not a dict", [_make_finding()])  # type: ignore
