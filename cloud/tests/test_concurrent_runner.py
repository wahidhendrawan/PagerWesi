"""Tests for the concurrent runner module."""
from __future__ import annotations

import time
from types import SimpleNamespace

from cloud.concurrent_runner import ConcurrentRunner, ProviderTask
from cloud.core import Finding, Severity, Status


def _make_finding(control_id="TEST-001", status=Status.PASS):
    return Finding(
        control_id=control_id,
        title="Test finding",
        status=status,
        severity=Severity.HIGH,
        resource="test:resource",
        evidence="test evidence",
    )


class TestConcurrentRunner:
    def test_empty_tasks(self):
        """Should handle empty task list."""
        runner = ConcurrentRunner(max_workers=4)
        results = runner.run_providers([])
        assert results == []

    def test_single_provider(self):
        """Should run a single provider successfully."""
        runner = ConcurrentRunner(max_workers=4)
        findings = [_make_finding()]

        task = ProviderTask(
            name="test-provider",
            audit_fn=lambda args: findings,
            args=SimpleNamespace(),
        )
        results = runner.run_providers([task])
        assert len(results) == 1
        assert results[0].success is True
        assert results[0].findings == findings

    def test_multiple_providers_concurrent(self):
        """Should run multiple providers concurrently."""
        runner = ConcurrentRunner(max_workers=4)
        call_times = []

        def slow_audit(args):
            call_times.append(time.monotonic())
            time.sleep(0.1)
            return [_make_finding()]

        tasks = [
            ProviderTask(name=f"provider-{i}", audit_fn=slow_audit, args=SimpleNamespace())
            for i in range(4)
        ]

        start = time.monotonic()
        results = runner.run_providers(tasks)
        elapsed = time.monotonic() - start

        assert len(results) == 4
        assert all(r.success for r in results)
        # Should take ~0.1s, not ~0.4s (proving concurrency)
        assert elapsed < 0.5

    def test_error_isolation(self):
        """Should isolate errors from one provider."""
        runner = ConcurrentRunner(max_workers=4)

        def failing_audit(args):
            raise RuntimeError("Provider crashed")

        def passing_audit(args):
            return [_make_finding()]

        tasks = [
            ProviderTask(name="failing", audit_fn=failing_audit, args=SimpleNamespace()),
            ProviderTask(name="passing", audit_fn=passing_audit, args=SimpleNamespace()),
        ]
        results = runner.run_providers(tasks)
        assert len(results) == 2

        failing_result = next(r for r in results if r.name == "failing")
        passing_result = next(r for r in results if r.name == "passing")

        assert failing_result.success is False
        assert failing_result.error is not None
        assert passing_result.success is True

    def test_failed_provider_generates_error_finding(self):
        """Should generate error finding for failed providers."""
        runner = ConcurrentRunner(max_workers=4)

        def failing_audit(args):
            raise RuntimeError("Network unreachable")

        task = ProviderTask(name="failing", audit_fn=failing_audit, args=SimpleNamespace())
        results = runner.run_providers([task])
        assert len(results[0].findings) == 1
        assert results[0].findings[0].status == Status.ERROR
        assert "Network unreachable" in results[0].findings[0].evidence

    def test_max_workers_capped(self):
        """Should cap max workers to limit."""
        runner = ConcurrentRunner(max_workers=100)
        assert runner._max_workers == 32

    def test_min_workers_is_one(self):
        """Should have at least 1 worker."""
        runner = ConcurrentRunner(max_workers=0)
        assert runner._max_workers == 1

    def test_duration_tracked(self):
        """Should track execution duration."""
        runner = ConcurrentRunner(max_workers=1)

        def slow_audit(args):
            time.sleep(0.05)
            return []

        task = ProviderTask(name="slow", audit_fn=slow_audit, args=SimpleNamespace())
        results = runner.run_providers([task])
        assert results[0].duration_seconds >= 0.04


class TestRunRegions:
    def test_runs_across_regions(self):
        """Should run audit across multiple regions."""
        runner = ConcurrentRunner(max_workers=4)
        findings_per_region: dict[str, list[Finding]] = {
            "us-east-1": [_make_finding("REGION-001")],
            "eu-west-1": [_make_finding("REGION-002")],
        }

        def region_audit(region, args):
            return findings_per_region.get(region, [])

        findings = runner.run_regions(
            ["us-east-1", "eu-west-1"],
            region_audit,
            SimpleNamespace(),
        )
        assert len(findings) == 2

    def test_region_failure_isolation(self):
        """Should handle region failures gracefully."""
        runner = ConcurrentRunner(max_workers=4)

        def flaky_region_audit(region, args):
            if region == "failing-region":
                raise RuntimeError("Region unavailable")
            return [_make_finding()]

        findings = runner.run_regions(
            ["us-east-1", "failing-region"],
            flaky_region_audit,
            SimpleNamespace(),
        )
        # Should have findings from us-east-1 + error finding from failing-region
        assert len(findings) == 2
        errors = [f for f in findings if f.status == Status.ERROR]
        assert len(errors) == 1
        assert "failing-region" in errors[0].resource

    def test_empty_regions(self):
        """Should handle empty region list."""
        runner = ConcurrentRunner(max_workers=4)
        findings = runner.run_regions([], lambda r, a: [], SimpleNamespace())
        assert findings == []
