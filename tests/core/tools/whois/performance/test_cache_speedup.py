"""Performance tests validating that cache hits are faster than cache misses."""
import time
from unittest.mock import patch
import pytest

from cybersec.core.tools import whois


# Artificial delay (seconds) injected to simulate WHOIS I/O on a cache miss.
MOCK_IO_DELAY_S = 0.05


def _slow_whois(response):
    """Factory: returns a side-effect fn that sleeps before yielding *response*."""
    def _fn(*args, **kwargs):
        time.sleep(MOCK_IO_DELAY_S)
        return response
    return _fn


@pytest.mark.asyncio
async def test_cache_hit_is_faster_than_cache_miss(clear_cache, mock_whois_response):
    """Second lookup (cache hit) must complete faster than the first (cache miss)."""
    # Arrange
    slow = _slow_whois(mock_whois_response)

    with patch("cybersec.core.tools.whois.python_whois.whois", side_effect=slow), \
         patch("cybersec.core.tools.whois._fetch_rdap", return_value=None), \
         patch("cybersec.core.tools.whois._get_redis", return_value=None):

        # Act – first lookup (cache miss)
        start_miss = time.perf_counter()
        result_miss = await whois.whois_lookup("example.com")
        duration_miss = time.perf_counter() - start_miss

        # Act – second lookup (cache hit, no I/O)
        start_hit = time.perf_counter()
        result_hit = await whois.whois_lookup("example.com")
        duration_hit = time.perf_counter() - start_hit

    # Assert timing
    assert duration_hit < duration_miss, (
        f"Cache hit ({duration_hit:.4f}s) was not faster than cache miss ({duration_miss:.4f}s)"
    )

    # Assert cache flag
    assert result_miss.cached is False
    assert result_hit.cached is True

    # Assert data equivalence
    assert result_hit.domain == result_miss.domain
    assert result_hit.registrar == result_miss.registrar


@pytest.mark.asyncio
async def test_cache_hit_avoids_whois_call(clear_cache, mock_whois_response):
    """After priming the cache, a second call must NOT invoke python_whois.whois."""
    # Arrange – prime the cache
    with patch("cybersec.core.tools.whois.python_whois.whois", return_value=mock_whois_response), \
         patch("cybersec.core.tools.whois._fetch_rdap", return_value=None), \
         patch("cybersec.core.tools.whois._get_redis", return_value=None):
        await whois.whois_lookup("example.com")

    # Act – cache hit: patch should never be called
    with patch("cybersec.core.tools.whois.python_whois.whois") as mock_w, \
         patch("cybersec.core.tools.whois._fetch_rdap") as mock_rdap, \
         patch("cybersec.core.tools.whois._get_redis", return_value=None):
        result = await whois.whois_lookup("example.com")

    # Assert
    assert result.cached is True
    assert result.domain == "example.com"
    mock_w.assert_not_called()
    mock_rdap.assert_not_called()


@pytest.mark.asyncio
async def test_cache_speedup_ratio_is_significant(clear_cache, mock_whois_response):
    """Cache hit should be at least 2× faster than a simulated cache miss."""
    # Arrange
    slow = _slow_whois(mock_whois_response)

    with patch("cybersec.core.tools.whois.python_whois.whois", side_effect=slow), \
         patch("cybersec.core.tools.whois._fetch_rdap", return_value=None), \
         patch("cybersec.core.tools.whois._get_redis", return_value=None):

        start_miss = time.perf_counter()
        await whois.whois_lookup("example.com")
        duration_miss = time.perf_counter() - start_miss

        start_hit = time.perf_counter()
        result_hit = await whois.whois_lookup("example.com")
        duration_hit = time.perf_counter() - start_hit

    # Assert cache hit is at least 2× faster
    assert result_hit.cached is True
    speedup = duration_miss / duration_hit if duration_hit > 0 else float("inf")
    assert speedup >= 2.0, (
        f"Cache speedup was only {speedup:.1f}× "
        f"(miss={duration_miss:.4f}s, hit={duration_hit:.4f}s)"
    )


@pytest.mark.asyncio
async def test_cache_miss_data_identical_to_hit_data(clear_cache, mock_whois_response):
    """Data returned on a cache hit is logically identical to the original result."""
    # Arrange
    with patch("cybersec.core.tools.whois.python_whois.whois", return_value=mock_whois_response), \
         patch("cybersec.core.tools.whois._fetch_rdap", return_value=None), \
         patch("cybersec.core.tools.whois._get_redis", return_value=None):
        miss = await whois.whois_lookup("example.com")
        hit = await whois.whois_lookup("example.com")

    # Assert
    assert miss.cached is False
    assert hit.cached is True
    assert hit.domain == miss.domain
    assert hit.tld == miss.tld
    assert hit.registrar == miss.registrar
    assert hit.name_servers == miss.name_servers
    assert hit.status == miss.status
    assert hit.error == miss.error
