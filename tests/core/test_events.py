import asyncio
import pytest
from unittest.mock import patch, AsyncMock


@pytest.mark.asyncio
async def test_stream_key_ttl_set():
    """Test that publish_event sets a TTL on the stream key after xadd."""
    # Mock before importing anything else to prevent real connection attempts
    with patch('cybersec.core.redis_client._shared_client', None):
        # Patch aioredis.from_url to return our fake redis
        fake_redis = AsyncMock()
        fake_redis.xadd.return_value = b"1-0"
        fake_redis.expire.return_value = True
        
        # Create a mock breaker that's closed
        mock_breaker = AsyncMock()
        mock_breaker.is_open.return_value = False

        with patch('cybersec.core.redis_client.get_shared_redis_client', return_value=fake_redis), \
             patch('cybersec.core.redis_client.get_shared_breaker', return_value=mock_breaker), \
             patch('cybersec.core.redis_client.aioredis.from_url', return_value=fake_redis):

            from cybersec.core.events import publish_event, STREAM_KEY_TTL_SECONDS
            from cybersec.core.redis_client import RedisKeys

            scan_id = "test-scan-1"
            event = "test-event"

            await publish_event(scan_id, event)
            key = RedisKeys.scan_events(scan_id)
            # Verify that expire was called with the correct TTL
            fake_redis.expire.assert_called_once_with(key, STREAM_KEY_TTL_SECONDS)


@pytest.mark.asyncio
async def test_poll_loop_sends_failure_sentinel():
    """Test that _poll_loop sends REDIS_FAILURE_SENTINEL to the queue on xread failure."""
    from cybersec.core.events import subscribe_events, REDIS_FAILURE_SENTINEL

    fake_redis = AsyncMock()
    fake_redis.xread.side_effect = Exception("Redis connection error")

    with patch('cybersec.core.redis_client.get_shared_redis_client', return_value=fake_redis):
        q = await subscribe_events("test-scan-2")
        try:
            # Give the poll loop a little time to run
            event = await asyncio.wait_for(q.get(), timeout=2.0)
            assert event == REDIS_FAILURE_SENTINEL, "Expected failure sentinel"
        except asyncio.TimeoutError:
            pytest.fail("Did not get failure sentinel in time")
