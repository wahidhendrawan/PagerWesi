"""Concurrent provider execution for multi-provider and multi-region audits.

Provides thread-safe parallel execution of provider audits with
configurable concurrency, timeouts, and error isolation.
"""
from __future__ import annotations

import threading
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Any

from cloud.core import Finding, Severity, Status
from cloud.logging_config import get_logger

logger = get_logger("concurrent_runner")

# Reasonable defaults for concurrency
DEFAULT_MAX_WORKERS = 8
MAX_WORKERS_LIMIT = 32
DEFAULT_TIMEOUT = 300  # 5 minutes per provider


@dataclass
class ProviderTask:
    """Represents a single provider audit task."""

    name: str
    audit_fn: Callable[..., list[Finding]]
    args: Any
    timeout: float = DEFAULT_TIMEOUT


@dataclass
class ProviderResult:
    """Result of a provider audit execution."""

    name: str
    findings: list[Finding] = field(default_factory=list)
    error: Exception | None = None
    duration_seconds: float = 0.0

    @property
    def success(self) -> bool:
        return self.error is None


class ConcurrentRunner:
    """Execute multiple provider audits concurrently with error isolation.

    Each provider runs in its own thread. Failures in one provider
    do not affect others. Results are collected and returned together.
    """

    def __init__(self, max_workers: int = DEFAULT_MAX_WORKERS):
        """Initialize the concurrent runner.

        Args:
            max_workers: Maximum number of parallel threads.
        """
        self._max_workers = max(1, min(max_workers, MAX_WORKERS_LIMIT))
        self._lock = threading.Lock()

    def run_providers(self, tasks: list[ProviderTask]) -> list[ProviderResult]:
        """Execute multiple provider tasks concurrently.

        Args:
            tasks: List of provider tasks to execute.

        Returns:
            List of results, one per task, in completion order.
        """
        if not tasks:
            return []

        results: list[ProviderResult] = []
        workers = min(self._max_workers, len(tasks))

        logger.info(
            "Starting concurrent audit of %d providers with %d workers",
            len(tasks),
            workers,
        )

        with ThreadPoolExecutor(max_workers=workers) as executor:
            future_to_task = {}
            for task in tasks:
                future = executor.submit(self._execute_task, task)
                future_to_task[future] = task

            max_timeout = max(t.timeout for t in tasks)
            for future in as_completed(future_to_task, timeout=max_timeout):
                task = future_to_task[future]
                try:
                    result = future.result(timeout=task.timeout)
                    results.append(result)
                except Exception as exc:
                    logger.error(
                        "Provider %s raised unhandled exception: %s",
                        task.name,
                        exc,
                    )
                    results.append(
                        ProviderResult(
                            name=task.name,
                            error=exc,
                            findings=[
                                Finding(
                                    control_id="RUNNER-001",
                                    title=f"Provider {task.name} execution failed",
                                    status=Status.ERROR,
                                    severity=Severity.HIGH,
                                    resource=f"provider:{task.name}",
                                    evidence=f"{type(exc).__name__}: {exc}",
                                    remediation="Check provider configuration and dependencies.",
                                )
                            ],
                        )
                    )

        successful = sum(1 for r in results if r.success)
        logger.info(
            "Concurrent audit complete: %d/%d providers succeeded",
            successful,
            len(tasks),
        )

        return results

    def _execute_task(self, task: ProviderTask) -> ProviderResult:
        """Execute a single provider task with timing and error handling."""
        import time

        start = time.monotonic()
        try:
            logger.debug("Starting provider: %s", task.name)
            findings = task.audit_fn(task.args)
            duration = time.monotonic() - start
            logger.info(
                "Provider %s completed in %.1fs with %d findings",
                task.name,
                duration,
                len(findings),
            )
            return ProviderResult(
                name=task.name,
                findings=findings,
                duration_seconds=duration,
            )
        except Exception as exc:
            duration = time.monotonic() - start
            logger.error(
                "Provider %s failed after %.1fs: %s: %s",
                task.name,
                duration,
                type(exc).__name__,
                exc,
            )
            return ProviderResult(
                name=task.name,
                error=exc,
                duration_seconds=duration,
                findings=[
                    Finding(
                        control_id="RUNNER-001",
                        title=f"Provider {task.name} execution failed",
                        status=Status.ERROR,
                        severity=Severity.HIGH,
                        resource=f"provider:{task.name}",
                        evidence=f"{type(exc).__name__}: {exc}",
                        remediation="Check provider configuration and dependencies.",
                    )
                ],
            )

    def run_regions(
        self,
        regions: list[str],
        audit_fn: Callable[[str, Any], list[Finding]],
        args: Any,
    ) -> list[Finding]:
        """Execute an audit function across multiple regions concurrently.

        Args:
            regions: List of region identifiers.
            audit_fn: Function taking (region, args) and returning findings.
            args: Arguments to pass to the audit function.

        Returns:
            Combined findings from all regions.
        """
        if not regions:
            return []

        all_findings: list[Finding] = []
        workers = min(self._max_workers, len(regions))

        logger.info("Starting regional audit across %d regions", len(regions))

        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {
                executor.submit(audit_fn, region, args): region
                for region in regions
            }
            for future in as_completed(futures):
                region = futures[future]
                try:
                    findings = future.result(timeout=DEFAULT_TIMEOUT)
                    all_findings.extend(findings)
                except Exception as exc:
                    logger.error("Region %s failed: %s", region, exc)
                    all_findings.append(
                        Finding(
                            control_id="RUNNER-002",
                            title=f"Regional audit failed for {region}",
                            status=Status.ERROR,
                            severity=Severity.HIGH,
                            resource=f"region:{region}",
                            evidence=f"{type(exc).__name__}: {exc}",
                            remediation="Check region availability and permissions.",
                        )
                    )

        return all_findings
