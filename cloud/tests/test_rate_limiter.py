"""Tests for the rate limiter and retry module."""
from __future__ import annotations

import time
from unittest.mock import MagicMock, patch

import pytest

from cloud.rate_limiter import (
    RateLimiter,
    _is_retriable,
    retry_api_call,
    retry_with_backoff,
)


class TestRateLimiter:
    def test_initial_burst(self):
        """Should allow burst number of immediate calls."""
        limiter = RateLimiter(calls_per_second=1.0, burst=5)
        for _ in range(5):
            assert limiter.acquire(timeout=0.1) is True

    def test_rate_limiting_blocks(self):
        """Should block when tokens exhausted."""
        limiter = RateLimiter(calls_per_second=1.0, burst=1)
        assert limiter.acquire(timeout=0.1) is True
        # Second call should timeout quickly
        assert limiter.acquire(timeout=0.05) is False

    def test_tokens_refill(self):
        """Should refill tokens over time."""
        limiter = RateLimiter(calls_per_second=100.0, burst=1)
        limiter.acquire(timeout=0.1)
        time.sleep(0.02)  # Wait for refill
        assert limiter.acquire(timeout=0.1) is True

    def test_rejects_invalid_rate(self):
        """Should reject non-positive rate."""
        with pytest.raises(ValueError, match="positive"):
            RateLimiter(calls_per_second=0)

    def test_rejects_invalid_burst(self):
        """Should reject non-positive burst."""
        with pytest.raises(ValueError, match="positive"):
            RateLimiter(calls_per_second=1.0, burst=0)


class TestIsRetriable:
    def test_throttling_is_retriable(self):
        """Should identify throttling exceptions as retriable."""
        exc = Exception("Throttling")
        exc.response = {"Error": {"Code": "Throttling"}}  # type: ignore
        assert _is_retriable(exc) is True

    def test_timeout_is_retriable(self):
        """Should identify timeout errors as retriable."""
        assert _is_retriable(TimeoutError("timed out")) is True

    def test_connection_error_is_retriable(self):
        """Should identify connection errors as retriable."""
        assert _is_retriable(ConnectionError("refused")) is True

    def test_value_error_not_retriable(self):
        """Should not retry ValueError."""
        assert _is_retriable(ValueError("bad value")) is False

    def test_generic_exception_not_retriable(self):
        """Should not retry generic exceptions."""
        assert _is_retriable(Exception("something")) is False


class TestRetryWithBackoff:
    @patch("cloud.rate_limiter.time.sleep")
    def test_retries_on_retriable_error(self, mock_sleep):
        """Should retry retriable errors."""
        call_count = 0

        @retry_with_backoff(max_retries=2, base_delay=0.1)
        def flaky_function():
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise TimeoutError("timeout")
            return "success"

        result = flaky_function()
        assert result == "success"
        assert call_count == 3

    def test_raises_non_retriable_immediately(self):
        """Should raise non-retriable errors immediately."""
        @retry_with_backoff(max_retries=3)
        def bad_function():
            raise ValueError("bad input")

        with pytest.raises(ValueError, match="bad input"):
            bad_function()

    @patch("cloud.rate_limiter.time.sleep")
    def test_exhausts_retries(self, mock_sleep):
        """Should raise after exhausting retries."""
        @retry_with_backoff(max_retries=2, base_delay=0.01)
        def always_fails():
            raise TimeoutError("always")

        with pytest.raises(TimeoutError):
            always_fails()

    def test_no_retry_on_success(self):
        """Should not retry on success."""
        call_count = 0

        @retry_with_backoff(max_retries=3)
        def good_function():
            nonlocal call_count
            call_count += 1
            return "ok"

        assert good_function() == "ok"
        assert call_count == 1


class TestRetryApiCall:
    @patch("cloud.rate_limiter.time.sleep")
    def test_successful_call(self, mock_sleep):
        """Should return result on success."""
        func = MagicMock(return_value="data")
        result = retry_api_call(func, "arg1", key="val1")
        assert result == "data"
        func.assert_called_once_with("arg1", key="val1")

    @patch("cloud.rate_limiter.time.sleep")
    def test_with_rate_limiter(self, mock_sleep):
        """Should acquire rate limiter before call."""
        limiter = MagicMock()
        limiter.acquire.return_value = True
        func = MagicMock(return_value="data")

        result = retry_api_call(func, rate_limiter=limiter)
        assert result == "data"
        limiter.acquire.assert_called_once()

    def test_rate_limiter_timeout_raises(self):
        """Should raise TimeoutError when rate limiter times out."""
        limiter = MagicMock()
        limiter.acquire.return_value = False
        func = MagicMock()

        with pytest.raises(TimeoutError, match="Rate limiter"):
            retry_api_call(func, rate_limiter=limiter)
