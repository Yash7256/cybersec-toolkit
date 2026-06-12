"""Integration tests validating local memory and Redis cache behavior for whois_lookup."""
import asyncio
import json
import time
from unittest.mock import AsyncMock, patch
import pytest

from cybersec.core.tools import whois
from tests.core.tools.whois.conftest import _make_whois_obj


class MockRedis:
    """A simple in-memory Redis client mock for testing cache integration."""
    def __init__(self):
        self.store = {}
        self.setex_called = []
        self.get_called = []

    async def get(self, key):
        self.get_called.append(key)
        return self.store.get(key)

    async def setex(self, key, ttl, value):
        self.setex_called.append((key, ttl, value))
        self.store[key] = value


@pytest.mark.asyncio
async def test_cache_miss_then_hit_local_memory(clear_cache, mock_whois_response):
    """First lookup is a cache miss (cached=False). Second lookup is a memory cache hit (cached=True)."""
    # Arrange
    domain = "memory-cache.com"

    # Act - First lookup (Miss)
    with patch("cybersec.core.tools.whois.python_whois.whois", return_value=mock_whois_response) as mock_whois, \
         patch("cybersec.core.tools.whois._fetch_rdap", return_value=None), \
         patch("cybersec.core.tools.whois._get_redis", return_value=None):
        result_1 = await whois.whois_lookup(domain)
        
        # Second lookup (Hit)
        result_2 = await whois.whois_lookup(domain)

    # Assert
    assert result_1.cached is False
    assert result_2.cached is True
    assert mock_whois.call_count == 1
    # Check that they return the same data
    assert result_1.registrar == result_2.registrar
    assert result_1.target == result_2.target


@pytest.mark.asyncio
async def test_redis_cache_hit_populates_local_cache(clear_cache, mock_whois_response):
    """Local cache miss but Redis hit return cached=True and populates local memory cache."""
    # Arrange
    domain = "redis-hit.com"
    mock_redis = MockRedis()

    # Pre-populate Redis cache with a WHOISResult serialized string
    # We run lookup once to get a clean result object to serialize
    with patch("cybersec.core.tools.whois.python_whois.whois", return_value=mock_whois_response), \
         patch("cybersec.core.tools.whois._fetch_rdap", return_value=None), \
         patch("cybersec.core.tools.whois._get_redis", return_value=None):
        base_result = await whois.whois_lookup(domain)
    
    # Serialize it
    from dataclasses import asdict
    raw_json = json.dumps(asdict(base_result))
    mock_redis.store[f"whois:{domain}"] = raw_json

    # Clear memory cache to force Redis check
    whois._CACHE.clear()

    # Act - Call whois_lookup
    with patch("cybersec.core.tools.whois.python_whois.whois") as mock_whois, \
         patch("cybersec.core.tools.whois._fetch_rdap") as mock_rdap, \
         patch("cybersec.core.tools.whois._get_redis", return_value=mock_redis):
        result = await whois.whois_lookup(domain)

    # Assert
    assert result.cached is True
    assert mock_whois.call_count == 0  # didn't call external WHOIS
    assert mock_rdap.call_count == 0   # didn't call external RDAP
    assert f"whois:{domain}" in mock_redis.get_called

    # Verify memory cache is now populated
    assert domain in whois._CACHE


@pytest.mark.asyncio
async def test_cache_expiration_ttl(clear_cache, mock_whois_response):
    """Verify that when TTL expires, the cache is ignored and a fresh lookup occurs."""
    # Arrange
    domain = "expire-me.com"
    start_time = 1700000000.0

    # Act & Assert
    with patch("time.time", return_value=start_time), \
         patch("cybersec.core.tools.whois.python_whois.whois", return_value=mock_whois_response) as mock_whois, \
         patch("cybersec.core.tools.whois._fetch_rdap", return_value=None), \
         patch("cybersec.core.tools.whois._get_redis", return_value=None):
        
        # First lookup (Miss)
        res1 = await whois.whois_lookup(domain)
        assert res1.cached is False
        assert mock_whois.call_count == 1

        # Second lookup at same time (Hit)
        res2 = await whois.whois_lookup(domain)
        assert res2.cached is True
        assert mock_whois.call_count == 1

    # Advance time past TTL (e.g. settings.WHOIS_CACHE_TTL_SECONDS is 86400 by default)
    future_time = start_time + 90000.0
    with patch("time.time", return_value=future_time), \
         patch("cybersec.core.tools.whois.python_whois.whois", return_value=mock_whois_response) as mock_whois, \
         patch("cybersec.core.tools.whois._fetch_rdap", return_value=None), \
         patch("cybersec.core.tools.whois._get_redis", return_value=None):

        # Third lookup after expiry (Miss)
        res3 = await whois.whois_lookup(domain)
        assert res3.cached is False
        assert mock_whois.call_count == 1


@pytest.mark.asyncio
async def test_cache_eviction_when_max_size_reached(clear_cache, mock_whois_response):
    """Verify memory cache eviction happens when size exceeds MAX_CACHE_SIZE."""
    # Arrange
    domain_1 = "d1.com"
    domain_2 = "d2.com"
    domain_3 = "d3.com"

    # Set MAX_CACHE_SIZE to 2 for testing
    with patch("cybersec.core.tools.whois.MAX_CACHE_SIZE", 2), \
         patch("cybersec.core.tools.whois.python_whois.whois", return_value=mock_whois_response), \
         patch("cybersec.core.tools.whois._fetch_rdap", return_value=None), \
         patch("cybersec.core.tools.whois._get_redis", return_value=None):
        
        # Populate 1 and 2
        await whois.whois_lookup(domain_1)
        await whois.whois_lookup(domain_2)
        assert len(whois._CACHE) == 2
        assert domain_1 in whois._CACHE
        assert domain_2 in whois._CACHE

        # Populate 3 (should evict 1 because it's the oldest inserted)
        await whois.whois_lookup(domain_3)
        assert len(whois._CACHE) == 2
        assert domain_1 not in whois._CACHE
        assert domain_2 in whois._CACHE
        assert domain_3 in whois._CACHE


@pytest.mark.asyncio
async def test_redis_unavailable_fallback(clear_cache, mock_whois_response):
    """When Redis is unavailable or raises exception, lookup falls back to memory and finishes gracefully."""
    # Arrange
    domain = "redis-fail.com"
    mock_redis = MockRedis()
    # Mock Redis to raise connection error
    mock_redis.get = AsyncMock(side_effect=Exception("Redis connection error"))
    mock_redis.setex = AsyncMock(side_effect=Exception("Redis connection error"))

    # Act
    with patch("cybersec.core.tools.whois.python_whois.whois", return_value=mock_whois_response) as mock_whois, \
         patch("cybersec.core.tools.whois._fetch_rdap", return_value=None), \
         patch("cybersec.core.tools.whois._get_redis", return_value=mock_redis):
        result = await whois.whois_lookup(domain)

    # Assert
    assert result.cached is False
    assert result.registrar == "GoDaddy.com, LLC"
    assert result.error is None
    assert mock_whois.call_count == 1
