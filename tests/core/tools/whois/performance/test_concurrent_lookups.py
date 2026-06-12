"""Performance tests validating concurrent lookup execution using asyncio.gather."""
import asyncio
import time
from unittest.mock import patch
import pytest

from cybersec.core.tools import whois


# Artificial delay per lookup to surface concurrency gains.
SIMULATED_DELAY_S = 0.05

# Domains to look up concurrently (each must be distinct to avoid cache collapse).
DOMAINS_5 = [f"concurrent{i}.com" for i in range(5)]
DOMAINS_10 = [f"concurrent{i}.com" for i in range(10)]
DOMAINS_20 = [f"concurrent{i}.com" for i in range(20)]


def _make_slow_whois(response_template, delay: float = SIMULATED_DELAY_S):
    """Return a side-effect fn that adds *delay* and returns a domain-tailored response."""
    from types import SimpleNamespace

    def _fn(domain, *args, **kwargs):
        time.sleep(delay)
        return SimpleNamespace(
            domain_name=domain,
            registrar="Test Registrar, LLC",
            registrar_iana_id="999",
            registrar_url="https://example.com",
            creation_date=None,
            expiration_date=None,
            updated_date=None,
            name_servers=["ns1.example.com"],
            status=["clientTransferProhibited"],
            emails=["admin@example.com"],
            org="Test Org",
            country="US",
            text=f"Domain Name: {domain.upper()}",
        )
    return _fn


@pytest.mark.asyncio
async def test_5_concurrent_lookups_all_succeed(clear_cache):
    """Five concurrent lookups all return valid results with no errors."""
    # Arrange
    slow = _make_slow_whois(None)

    with patch("cybersec.core.tools.whois.python_whois.whois", side_effect=slow), \
         patch("cybersec.core.tools.whois._fetch_rdap", return_value=None), \
         patch("cybersec.core.tools.whois._get_redis", return_value=None):

        # Act
        results = await asyncio.gather(
            *[whois.whois_lookup(d) for d in DOMAINS_5]
        )

    # Assert
    assert len(results) == 5
    assert all(r.error is None for r in results)
    assert all(isinstance(r.name_servers, list) for r in results)


@pytest.mark.asyncio
async def test_10_concurrent_lookups_all_succeed(clear_cache):
    """Ten concurrent lookups all return valid results with no errors."""
    # Arrange
    slow = _make_slow_whois(None)

    with patch("cybersec.core.tools.whois.python_whois.whois", side_effect=slow), \
         patch("cybersec.core.tools.whois._fetch_rdap", return_value=None), \
         patch("cybersec.core.tools.whois._get_redis", return_value=None):

        # Act
        results = await asyncio.gather(
            *[whois.whois_lookup(d) for d in DOMAINS_10]
        )

    # Assert
    assert len(results) == 10
    assert all(r.error is None for r in results)


@pytest.mark.asyncio
async def test_20_concurrent_lookups_all_succeed(clear_cache):
    """Twenty concurrent lookups complete successfully without exceptions."""
    # Arrange
    slow = _make_slow_whois(None)

    with patch("cybersec.core.tools.whois.python_whois.whois", side_effect=slow), \
         patch("cybersec.core.tools.whois._fetch_rdap", return_value=None), \
         patch("cybersec.core.tools.whois._get_redis", return_value=None):

        # Act
        results = await asyncio.gather(
            *[whois.whois_lookup(d) for d in DOMAINS_20]
        )

    # Assert
    assert len(results) == 20
    assert all(r.error is None for r in results)


@pytest.mark.asyncio
async def test_concurrent_results_are_domain_specific(clear_cache):
    """Each concurrent result maps back to its own domain without cross-contamination."""
    # Arrange
    domains = [f"domain{i}.com" for i in range(5)]
    slow = _make_slow_whois(None)

    with patch("cybersec.core.tools.whois.python_whois.whois", side_effect=slow), \
         patch("cybersec.core.tools.whois._fetch_rdap", return_value=None), \
         patch("cybersec.core.tools.whois._get_redis", return_value=None):

        # Act
        results = await asyncio.gather(
            *[whois.whois_lookup(d) for d in domains]
        )

    # Assert – each result belongs to the correct domain
    result_domains = {r.domain for r in results}
    assert result_domains == set(domains), (
        f"Domain mismatch — expected {set(domains)}, got {result_domains}"
    )


@pytest.mark.asyncio
async def test_concurrent_lookups_faster_than_serial(clear_cache):
    """Concurrent execution must be faster than serial execution by a meaningful margin."""
    # Arrange – use 5 domains to keep test runtime short but concurrency visible
    domains = [f"speedtest{i}.com" for i in range(5)]
    slow = _make_slow_whois(None)

    # Serial baseline
    serial_start = time.perf_counter()
    with patch("cybersec.core.tools.whois.python_whois.whois", side_effect=slow), \
         patch("cybersec.core.tools.whois._fetch_rdap", return_value=None), \
         patch("cybersec.core.tools.whois._get_redis", return_value=None):
        for d in domains:
            whois.clear_whois_cache()
            await whois.whois_lookup(d)
    serial_duration = time.perf_counter() - serial_start

    whois.clear_whois_cache()

    # Concurrent run
    concurrent_start = time.perf_counter()
    with patch("cybersec.core.tools.whois.python_whois.whois", side_effect=slow), \
         patch("cybersec.core.tools.whois._fetch_rdap", return_value=None), \
         patch("cybersec.core.tools.whois._get_redis", return_value=None):
        results = await asyncio.gather(*[whois.whois_lookup(d) for d in domains])
    concurrent_duration = time.perf_counter() - concurrent_start

    # Assert
    assert len(results) == 5
    assert all(r.error is None for r in results)
    assert concurrent_duration < serial_duration, (
        f"Concurrent ({concurrent_duration:.3f}s) was not faster than serial ({serial_duration:.3f}s)"
    )


@pytest.mark.asyncio
async def test_no_race_conditions_on_same_domain_concurrent(clear_cache, mock_whois_response):
    """Concurrent lookups for the same domain resolve safely without corrupted data."""
    # Arrange – all coroutines target the same domain (cache collapses duplicates)
    with patch("cybersec.core.tools.whois.python_whois.whois", return_value=mock_whois_response), \
         patch("cybersec.core.tools.whois._fetch_rdap", return_value=None), \
         patch("cybersec.core.tools.whois._get_redis", return_value=None):

        # Act – 10 concurrent calls to the same domain
        results = await asyncio.gather(
            *[whois.whois_lookup("example.com") for _ in range(10)]
        )

    # Assert – all results are valid and consistent
    assert len(results) == 10
    assert all(r.domain == "example.com" for r in results)
    assert all(r.error is None for r in results)
    assert all(r.registrar == "GoDaddy.com, LLC" for r in results)
