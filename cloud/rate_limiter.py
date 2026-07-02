"""Rate limiting and retry utilities for API calls.

Provides exponential backoff retry logic and token-bucket rate limiting
to prevent API throttling and improve resilience.
"""
from __future__ import annotations

import functools
import threading
import time
from collections.abc import Callable
from typing import Any, TypeVar

from cloud.logging_config import get_logger

logger = get_logger("rate_limiter")

T = TypeVar("T")

# Default retry configuration
DEFAULT_MAX_RETRIES = 3
DEFAULT_BASE_DELAY = 1.0
DEFAULT_MAX_DELAY = 30.0
DEFAULT_BACKOFF_FACTOR = 2.0

# Retriable exception patterns (AWS, Azure, GCP)
RETRIABLE_ERROR_CODES = frozenset({
    "Throttling",
    "ThrottlingException",
    "TooManyRequestsException",
    "RequestLimitExceeded",
    "ServiceUnavailable",
    "InternalError",
    "RequestTimeout",
    "429",
    "503",
    "500",
})


class RateLimiter:
    """Token-bucket rate limiter for controlling API call frequency.

    Thread-safe implementation that limits calls to a maximum rate.
    """

    def __init__(self, calls_per_second: float = 10.0, burst: int = 20):
        """Initialize rate limiter.

        Args:
            calls_per_second: Maximum sustained call rate.
            burst: Maximum burst size (bucket capacity).
        """
        if calls_per_second <= 0:
            raise ValueError("calls_per_second must be positive")
        if burst <= 0:
            raise ValueError("burst must be positive")

        self._rate = calls_per_second
        self._capacity = burst
        self._tokens = float(burst)
        self._last_refill = time.monotonic()
        self._lock = threading.Lock()

    def acquire(self, timeout: float = 30.0) -> bool:
        """Acquire a token, blocking until available or timeout.

        Args:
            timeout: Maximum seconds to wait for a token.

        Returns:
            True if token acquired, False if timeout.
        """
        deadline = time.monotonic() + timeout
        while True:
            with self._lock:
                self._refill()
                if self._tokens >= 1.0:
                    self._tokens -= 1.0
                    return True
            if time.monotonic() >= deadline:
                return False
            # Wait for approximately one token worth of time
            time.sleep(min(1.0 / self._rate, deadline - time.monotonic()))

    def _refill(self) -> None:
        """Refill tokens based on elapsed time."""
        now = time.monotonic()
        elapsed = now - self._last_refill
        self._tokens = min(self._capacity, self._tokens + elapsed * self._rate)
        self._last_refill = now


def _is_retriable(exc: Exception) -> bool:
    """Determine if an exception is retriable."""
    # Check botocore/Azure/GCP error codes
    error_code = getattr(exc, "response", {}).get("Error", {}).get("Code", "")
    if error_code in RETRIABLE_ERROR_CODES:
        return True

    # Check HTTP status codes
    status_code = str(getattr(exc, "status_code", getattr(exc, "code", "")))
    if status_code in {"429", "500", "502", "503", "504"}:
        return True

    # Check exception type names
    exc_name = type(exc).__name__
    retriable_types = {
        "ThrottlingException",
        "TooManyRequestsException",
        "ServiceUnavailable",
        "ConnectionError",
        "TimeoutError",
        "ReadTimeoutError",
        "ConnectTimeoutError",
    }
    if exc_name in retriable_types:
        return True

    # Check for timeout-related errors
    if "timeout" in str(exc).lower() or "throttl" in str(exc).lower():
        return True

    return False


def retry_with_backoff(
    max_retries: int = DEFAULT_MAX_RETRIES,
    base_delay: float = DEFAULT_BASE_DELAY,
    max_delay: float = DEFAULT_MAX_DELAY,
    backoff_factor: float = DEFAULT_BACKOFF_FACTOR,
    retriable_check: Callable[[Exception], bool] | None = None,
) -> Callable:
    """Decorator for retrying functions with exponential backoff.

    Args:
        max_retries: Maximum number of retry attempts.
        base_delay: Initial delay in seconds.
        max_delay: Maximum delay between retries.
        backoff_factor: Multiplier for each retry delay.
        retriable_check: Custom function to determine if error is retriable.
    """
    check_fn = retriable_check or _is_retriable

    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> T:
            last_exception: Exception | None = None
            for attempt in range(max_retries + 1):
                try:
                    return func(*args, **kwargs)
                except Exception as exc:
                    last_exception = exc
                    if attempt >= max_retries or not check_fn(exc):
                        raise
                    delay = min(
                        base_delay * (backoff_factor ** attempt),
                        max_delay,
                    )
                    logger.warning(
                        "Attempt %d/%d failed for %s: %s. Retrying in %.1fs",
                        attempt + 1,
                        max_retries + 1,
                        func.__name__,
                        type(exc).__name__,
                        delay,
                    )
                    time.sleep(delay)
            # Should not reach here, but satisfy type checker
            raise last_exception  # type: ignore[misc]

        return wrapper

    return decorator


def retry_api_call(
    func: Callable[..., T],
    *args: Any,
    max_retries: int = DEFAULT_MAX_RETRIES,
    rate_limiter: RateLimiter | None = None,
    **kwargs: Any,
) -> T:
    """Execute a function with retry logic and optional rate limiting.

    Args:
        func: The function to call.
        *args: Positional arguments for the function.
        max_retries: Maximum retry attempts.
        rate_limiter: Optional rate limiter to apply before each call.
        **kwargs: Keyword arguments for the function.

    Returns:
        The function's return value.

    Raises:
        The last exception if all retries are exhausted.
    """
    last_exception: Exception | None = None
    for attempt in range(max_retries + 1):
        if rate_limiter and not rate_limiter.acquire():
            raise TimeoutError("Rate limiter timeout exceeded")
        try:
            return func(*args, **kwargs)
        except Exception as exc:
            last_exception = exc
            if attempt >= max_retries or not _is_retriable(exc):
                raise
            delay = min(
                DEFAULT_BASE_DELAY * (DEFAULT_BACKOFF_FACTOR ** attempt),
                DEFAULT_MAX_DELAY,
            )
            logger.warning(
                "API call attempt %d/%d failed: %s. Retrying in %.1fs",
                attempt + 1,
                max_retries + 1,
                type(exc).__name__,
                delay,
            )
            time.sleep(delay)
    raise last_exception  # type: ignore[misc]
