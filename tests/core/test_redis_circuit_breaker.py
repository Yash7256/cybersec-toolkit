import asyncio
import time
import pytest

from cybersec.core.redis_client import RedisCircuitBreaker


@pytest.mark.asyncio
async def test_breaker_closed_initially():
    breaker = RedisCircuitBreaker()
    assert not await breaker.is_open()


@pytest.mark.asyncio
async def test_breaker_opens_after_threshold():
    breaker = RedisCircuitBreaker(failure_threshold=3)
    await breaker.record_failure()
    await breaker.record_failure()
    assert not await breaker.is_open()  # Should still be closed
    await breaker.record_failure()
    assert await breaker.is_open()  # Now should be open


@pytest.mark.asyncio
async def test_breaker_half_opens_after_timeout(monkeypatch):
    breaker = RedisCircuitBreaker(failure_threshold=3, reset_timeout_seconds=30.0)
    # Record 3 failures to open the breaker
    await breaker.record_failure()
    await breaker.record_failure()
    await breaker.record_failure()
    assert await breaker.is_open()
    # Monkeypatch time.monotonic to simulate 31 seconds passing
    original_monotonic = time.monotonic
    monkeypatch.setattr(time, "monotonic", lambda: original_monotonic() + 31.0)
    # Breaker should now be half-open
    assert not await breaker.is_open()


@pytest.mark.asyncio
async def test_breaker_resets_on_success():
    breaker = RedisCircuitBreaker(failure_threshold=3)
    await breaker.record_failure()
    await breaker.record_failure()
    await breaker.record_failure()
    assert await breaker.is_open()
    await breaker.record_success()
    # After success, breaker should be reset
    assert not await breaker.is_open()
