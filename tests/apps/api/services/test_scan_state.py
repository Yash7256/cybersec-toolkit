import asyncio
import pytest
from unittest.mock import patch, AsyncMock


@pytest.mark.asyncio
async def test_global_slot_enforces_ceiling():
    """Test that global slot enforces MAX_CONCURRENT_SCANS_GLOBAL limit."""
    from cybersec.apps.api.services.scan_state import (
        acquire_global_scan_slot,
        release_global_scan_slot,
        MAX_CONCURRENT_SCANS_GLOBAL,
    )
    from cybersec.core.redis_client import RedisKeys

    # Mock Redis
    mock_redis = AsyncMock()
    count = 0
    key = RedisKeys.scan_global_active()

    def mock_get(k):
        if k == key:
            return str(count).encode()
        return None

    def mock_incr(k):
        nonlocal count
        if k == key:
            count += 1
            return count
        return 0

    def mock_decr(k):
        nonlocal count
        if k == key:
            count -= 1

    mock_redis.get.side_effect = mock_get
    mock_redis.incr.side_effect = mock_incr
    mock_redis.decr.side_effect = mock_decr

    with patch('cybersec.core.redis_client.get_shared_redis_client', return_value=mock_redis):
        # Acquire up to the limit
        acquired = []
        for _ in range(MAX_CONCURRENT_SCANS_GLOBAL):
            result = await acquire_global_scan_slot(timeout=0.1)
            acquired.append(result)
        assert all(acquired)

        # Next acquire should time out
        result = await acquire_global_scan_slot(timeout=0.1)
        assert not result

        # Release one and try again
        await release_global_scan_slot()
        result = await acquire_global_scan_slot(timeout=0.1)
        assert result


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

    key = RedisKeys.scan_global_active()
    mock_redis = AsyncMock()
    mock_redis.get.side_effect = lambda k: b"0" if k == key else None
    mock_redis.incr.return_value = 1
    mock_redis.decr.return_value = None

    with patch('cybersec.core.redis_client.get_shared_redis_client', return_value=mock_redis):
        assert await acquire_global_scan_slot(timeout=0.1)
        await release_global_scan_slot()
        mock_redis.decr.assert_called_once_with(key)

