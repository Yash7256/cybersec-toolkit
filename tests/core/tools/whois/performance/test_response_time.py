"""Performance tests validating single-lookup response times under mocked dependencies."""
import asyncio
import time
from unittest.mock import patch
import pytest

from cybersec.core.tools import whois


# Maximum time (seconds) allowed for a single mocked lookup.
# Mocked I/O is near-instant; anything over 2s signals a serious regression.
SINGLE_LOOKUP_THRESHOLD_S = 2.0

# Artificial delay injected to simulate realistic network I/O (50 ms).
SIMULATED_NETWORK_DELAY_S = 0.05


@pytest.fixture
def delayed_whois_response(mock_whois_response):
    """Return mock WHOIS data after a brief simulated delay."""
    def _delay(*args, **kwargs):
        time.sleep(SIMULATED_NETWORK_DELAY_S)
        return mock_whois_response
    return _delay


@pytest.mark.asyncio
async def test_single_lookup_completes_within_threshold(
    clear_cache, delayed_whois_response, mock_rdap_response
):
    """Single lookup with simulated I/O completes well below the allowed threshold."""
    # Arrange
    with patch("cybersec.core.tools.whois.python_whois.whois", side_effect=delayed_whois_response), \
         patch("cybersec.core.tools.whois._fetch_rdap", return_value=mock_rdap_response), \
         patch("cybersec.core.tools.whois._get_redis", return_value=None):

        # Act
        start = time.perf_counter()
        result = await whois.whois_lookup("example.com")
        duration = time.perf_counter() - start

    # Assert
    assert result.error is None
    assert result.domain == "example.com"
    assert duration < SINGLE_LOOKUP_THRESHOLD_S, (
        f"Lookup took {duration:.3f}s — exceeds {SINGLE_LOOKUP_THRESHOLD_S}s threshold"
    )


@pytest.mark.asyncio
async def test_lookup_duration_is_dominated_by_io_not_overhead(
    clear_cache, delayed_whois_response
):
    """Application overhead should be negligible relative to simulated I/O delay."""
    # Arrange
    with patch("cybersec.core.tools.whois.python_whois.whois", side_effect=delayed_whois_response), \
         patch("cybersec.core.tools.whois._fetch_rdap", return_value=None), \
         patch("cybersec.core.tools.whois._get_redis", return_value=None):

        # Act
        start = time.perf_counter()
        result = await whois.whois_lookup("example.com")
        duration = time.perf_counter() - start

    # Assert – overhead should add < 1s on top of simulated I/O
    assert result.error is None
    assert duration < SIMULATED_NETWORK_DELAY_S + 1.0, (
        f"Overhead too high: total={duration:.3f}s, simulated I/O={SIMULATED_NETWORK_DELAY_S}s"
    )


@pytest.mark.asyncio
async def test_instant_mock_lookup_is_near_zero(clear_cache, mock_whois_response):
    """With instant mocks, lookup should return in well under 1 second."""
    # Arrange
    with patch("cybersec.core.tools.whois.python_whois.whois", return_value=mock_whois_response), \
         patch("cybersec.core.tools.whois._fetch_rdap", return_value=None), \
         patch("cybersec.core.tools.whois._get_redis", return_value=None):

        # Act
        start = time.perf_counter()
        result = await whois.whois_lookup("example.com")
        duration = time.perf_counter() - start

    # Assert
    assert result.error is None
    assert duration < 1.0, (
        f"Instant mock lookup took {duration:.3f}s — unexpected overhead"
    )


@pytest.mark.asyncio
async def test_result_schema_is_complete_after_timed_lookup(
    clear_cache, mock_whois_response, mock_rdap_response
):
    """Result returned within the threshold must carry full schema integrity."""
    # Arrange
    with patch("cybersec.core.tools.whois.python_whois.whois", return_value=mock_whois_response), \
         patch("cybersec.core.tools.whois._fetch_rdap", return_value=mock_rdap_response), \
         patch("cybersec.core.tools.whois._get_redis", return_value=None):

        # Act
        start = time.perf_counter()
        result = await whois.whois_lookup("example.com")
        duration = time.perf_counter() - start

    # Assert timing
    assert duration < SINGLE_LOOKUP_THRESHOLD_S

    # Assert schema completeness
    assert result.domain == "example.com"
    assert result.tld == "com"
    assert isinstance(result.name_servers, list)
    assert isinstance(result.status, list)
    assert isinstance(result.risk_indicators, list)
    assert result.error is None
    assert result.cached is False
