"""Tests for the agent module."""
from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from cloud.agent import (
    _load_state,
    _new_fails,
    _resolved_findings,
    _rotate_history,
    _run_providers,
    _save_state,
    run_agent,
)
from cloud.core import Finding, Severity, Status


def _finding_dict(control_id="TEST-001", status="fail", resource="test:r"):
    return {
        "control_id": control_id,
        "status": status,
        "resource": resource,
        "evidence": "test",
    }


class TestNewFails:
    def test_detects_new_failures(self):
        """Should detect findings that are new failures."""
        previous = [_finding_dict("A-001", "pass")]
        current = [_finding_dict("A-001", "fail")]
        result = _new_fails(current, previous)
        assert len(result) == 1

    def test_ignores_existing_failures(self):
        """Should not report already-known failures."""
        previous = [_finding_dict("A-001", "fail")]
        current = [_finding_dict("A-001", "fail")]
        result = _new_fails(current, previous)
        assert len(result) == 0

    def test_empty_previous(self):
        """All current failures are new when previous is empty."""
        current = [_finding_dict("A-001", "fail")]
        result = _new_fails(current, [])
        assert len(result) == 1

    def test_ignores_pass(self):
        """Should not flag pass findings."""
        current = [_finding_dict("A-001", "pass")]
        result = _new_fails(current, [])
        assert len(result) == 0


class TestResolvedFindings:
    def test_detects_resolved(self):
        """Should detect findings that changed from fail to pass."""
        previous = [_finding_dict("A-001", "fail", "res1")]
        current = [_finding_dict("A-001", "pass", "res1")]
        result = _resolved_findings(current, previous)
        assert len(result) == 1

    def test_no_resolved(self):
        """Should return empty when nothing resolved."""
        previous = [_finding_dict("A-001", "fail")]
        current = [_finding_dict("A-001", "fail")]
        result = _resolved_findings(current, previous)
        assert len(result) == 0


class TestStateManagement:
    def test_save_and_load(self, tmp_path, monkeypatch):
        """Should save and load state correctly."""
        monkeypatch.chdir(tmp_path)
        import cloud.agent as agent_mod
        monkeypatch.setattr(agent_mod, "STATE_FILE", tmp_path / ".state.json")
        monkeypatch.setattr(agent_mod, "STATE_HISTORY_DIR", tmp_path / ".history")

        findings = [_finding_dict("A-001", "fail")]
        _save_state(findings)

        loaded = _load_state()
        assert loaded == findings

    def test_load_missing_file(self, tmp_path, monkeypatch):
        """Should return empty list when state file missing."""
        import cloud.agent as agent_mod
        monkeypatch.setattr(agent_mod, "STATE_FILE", tmp_path / "nonexistent.json")
        assert _load_state() == []


class TestRotateHistory:
    def test_creates_history_files(self, tmp_path, monkeypatch):
        """Should create history files."""
        import cloud.agent as agent_mod
        monkeypatch.setattr(agent_mod, "STATE_HISTORY_DIR", tmp_path / "history")
        _rotate_history('{"test": true}')
        files = list((tmp_path / "history").glob("state-*.json"))
        assert len(files) == 1

    def test_limits_history_count(self, tmp_path, monkeypatch):
        """Should clean up old history files."""
        import cloud.agent as agent_mod
        history_dir = tmp_path / "history"
        history_dir.mkdir()
        monkeypatch.setattr(agent_mod, "STATE_HISTORY_DIR", history_dir)
        monkeypatch.setattr(agent_mod, "MAX_STATE_HISTORY", 3)

        # Create 5 history files
        for i in range(5):
            (history_dir / f"state-2024010{i}-000000.json").write_text("{}")

        _rotate_history("{}")
        files = list(history_dir.glob("state-*.json"))
        assert len(files) <= 4  # 3 max + 1 new


class TestRunProviders:
    @patch("cloud.main.load_provider")
    def test_successful_audit(self, mock_load):
        """Should collect findings from providers."""
        module = MagicMock()
        module.run_audit.return_value = [
            Finding("T-001", "test", Status.PASS, Severity.HIGH, "r", "e")
        ]
        mock_load.return_value = module

        args = SimpleNamespace(control=[], mode="audit")
        results = _run_providers(["aws"], args)
        assert len(results) == 1
        assert results[0]["status"] == "pass"

    @patch("cloud.main.load_provider")
    def test_provider_failure_generates_error(self, mock_load):
        """Should generate error finding when provider fails."""
        mock_load.side_effect = RuntimeError("boto3 missing")

        args = SimpleNamespace(control=[], mode="audit")
        results = _run_providers(["aws"], args)
        assert len(results) == 1
        assert results[0]["control_id"] == "AGENT-PROVIDER-001"
        assert results[0]["status"] == "error"


class TestRunAgent:
    @patch("cloud.agent._run_providers")
    @patch("cloud.agent.time.sleep")
    def test_graceful_shutdown(self, mock_sleep, mock_providers, monkeypatch, tmp_path):
        """Should shut down gracefully on signal."""
        import cloud.agent as agent_mod
        monkeypatch.setattr(agent_mod, "STATE_FILE", tmp_path / ".state.json")
        monkeypatch.setattr(agent_mod, "STATE_HISTORY_DIR", tmp_path / ".history")
        monkeypatch.setattr(agent_mod, "_shutdown", False)

        # Simulate shutdown after first sleep
        call_count = 0
        def fake_sleep(t):
            nonlocal call_count
            call_count += 1
            if call_count > 1:
                agent_mod._shutdown = True

        mock_sleep.side_effect = fake_sleep
        mock_providers.return_value = []

        args = SimpleNamespace(
            interval=1, watch_providers="aws",
            notify=None,
        )
        exit_code = run_agent(args)
        assert exit_code == 0

    def test_minimum_interval(self, monkeypatch, tmp_path):
        """Should enforce minimum interval."""
        import cloud.agent as agent_mod
        monkeypatch.setattr(agent_mod, "_shutdown", True)  # Immediate shutdown
        monkeypatch.setattr(agent_mod, "STATE_FILE", tmp_path / ".state.json")
        monkeypatch.setattr(agent_mod, "STATE_HISTORY_DIR", tmp_path / ".history")

        args = SimpleNamespace(
            interval=5, watch_providers="aws",
            notify=None,
        )
        # Should not crash with low interval
        exit_code = run_agent(args)
        assert exit_code == 0
