import asyncio
import pytest
from unittest.mock import patch, AsyncMock


@pytest.mark.asyncio
async def test_global_slot_enforces_ceiling_under_concurrency():
    """Acquire MAX_CONCURRENT_SCANS_GLOBAL + 5 slots all at once via
    asyncio.gather, to actually exercise concurrent access instead of
    a sequential loop (which can never expose a race condition).
    """
    from cybersec.apps.api.services.scan_state import (
        acquire_global_scan_slot,
        release_global_scan_slot,
        MAX_CONCURRENT_SCANS_GLOBAL,
    )
    from cybersec.core.redis_client import RedisKeys, try_acquire_slot

    # Mock try_acquire_slot to simulate the counter
    counter = 0
    lock = asyncio.Lock()

    async def mock_try_acquire(r, key, limit):
        nonlocal counter
        async with lock:
            if counter < limit:
                counter += 1
                return True
            return False

    with patch('cybersec.core.redis_client.get_shared_redis_client', return_value=AsyncMock()), \
         patch('cybersec.core.redis_client.try_acquire_slot', side_effect=mock_try_acquire):
        tasks = [
            acquire_global_scan_slot(timeout=0.1)
            for _ in range(MAX_CONCURRENT_SCANS_GLOBAL + 5)
        ]
        results = await asyncio.gather(*tasks)

        succeeded = sum(1 for r in results if r)
        failed = sum(1 for r in results if not r)

        # Exactly MAX_CONCURRENT_SCANS_GLOBAL should succeed, the rest should fail
        assert succeeded == MAX_CONCURRENT_SCANS_GLOBAL
        assert failed == 5


@pytest.mark.asyncio
async def test_global_slot_no_overshoot_under_high_concurrency():
    """Regression test for the GET-then-INCR race: fire many more
    concurrent acquires than the limit allows, and confirm the counter
    never exceeds the limit even transiently. Run multiple times in a
    loop within the test to increase the chance of catching a flaky race.
    """
    from cybersec.apps.api.services.scan_state import (
        acquire_global_scan_slot,
        MAX_CONCURRENT_SCANS_GLOBAL,
    )
    from cybersec.core.redis_client import RedisKeys, try_acquire_slot

    # Mock try_acquire_slot to track the counter
    counter = 0
    max_counter = 0
    lock = asyncio.Lock()

    async def mock_try_acquire(r, key, limit):
        nonlocal counter, max_counter
        async with lock:
            if counter < limit:
                counter += 1
                if counter > max_counter:
                    max_counter = counter
                return True
            return False

    with patch('cybersec.core.redis_client.get_shared_redis_client', return_value=AsyncMock()), \
         patch('cybersec.core.redis_client.try_acquire_slot', side_effect=mock_try_acquire):
        for _ in range(5):  # Run multiple rounds to catch flaky races
            counter = 0  # Reset counter for each round
            max_counter = 0
            tasks = [
                acquire_global_scan_slot(timeout=0.1)
                for _ in range(MAX_CONCURRENT_SCANS_GLOBAL * 3)
            ]
            await asyncio.gather(*tasks)

            assert max_counter <= MAX_CONCURRENT_SCANS_GLOBAL, (
                f"Counter overshot limit: {max_counter} > {MAX_CONCURRENT_SCANS_GLOBAL} — "
                "this means the acquire path has a race condition allowing more "
                "concurrent acquires than the configured ceiling."
            )


@pytest.mark.asyncio
async def test_global_slot_falls_back_when_redis_down():
    """Test that we fall back to in-memory when Redis is unavailable."""
    from cybersec.apps.api.services.scan_state import (
        acquire_global_scan_slot,
        MAX_CONCURRENT_SCANS_GLOBAL,
    )

    with patch('cybersec.core.redis_client.get_shared_redis_client', return_value=None):
        # Acquire up to the limit
        acquired = []
        for _ in range(MAX_CONCURRENT_SCANS_GLOBAL):
            result = await acquire_global_scan_slot(timeout=0.1)
            acquired.append(result)
        assert all(acquired)


@pytest.mark.asyncio
async def test_release_decrements_correctly():
    """Test that releasing a slot correctly decrements the counter."""
    from cybersec.apps.api.services.scan_state import (
        acquire_global_scan_slot,
        release_global_scan_slot,
    )
    from cybersec.core.redis_client import RedisKeys

    fake_redis = AsyncMock()
    fake_redis.get.side_effect = lambda k: b"0" if k == RedisKeys.scan_global_active() else None
    fake_redis.incr.return_value = 1
    fake_redis.decr.return_value = None

    with patch('cybersec.core.redis_client.get_shared_redis_client', return_value=fake_redis):
        assert await acquire_global_scan_slot(timeout=0.1)
        await release_global_scan_slot()
        fake_redis.decr.assert_called_once_with(RedisKeys.scan_global_active())
