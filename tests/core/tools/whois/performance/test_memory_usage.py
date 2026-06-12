"""Performance tests validating memory growth bounds under repeated lookups."""
import asyncio
import gc
import tracemalloc
from types import SimpleNamespace
from unittest.mock import patch
import pytest

from cybersec.core.tools import whois


# Maximum acceptable memory growth in bytes over the iteration set.
# 5 MB is a generous bound — legitimate repeated lookups should stay well below this.
MAX_MEMORY_GROWTH_BYTES = 5 * 1024 * 1024  # 5 MiB

# Number of iterations for the standard loop.
ITERATION_COUNT = 100


def _make_instant_whois(domain: str):
    """Return a minimal whois-like object for *domain* with no allocated state."""
    return SimpleNamespace(
        domain_name=domain,
        registrar="Test Registrar, LLC",
        registrar_iana_id=None,
        registrar_url=None,
        creation_date=None,
        expiration_date=None,
        updated_date=None,
        name_servers=["ns1.example.com"],
        status=["clientTransferProhibited"],
        emails=["admin@example.com"],
        org=None,
        country=None,
        text=f"Domain Name: {domain.upper()}",
    )


@pytest.mark.asyncio
async def test_repeated_lookups_do_not_leak_memory(clear_cache):
    """Repeated lookups against a single domain show bounded memory growth."""
    gc.collect()
    tracemalloc.start()
    snapshot_before = tracemalloc.take_snapshot()

    with patch("cybersec.core.tools.whois.python_whois.whois",
               side_effect=lambda d, *a, **kw: _make_instant_whois(d)), \
         patch("cybersec.core.tools.whois._fetch_rdap", return_value=None), \
         patch("cybersec.core.tools.whois._get_redis", return_value=None):

        for _ in range(ITERATION_COUNT):
            # Clear cache on each iteration so we exercise the full code path.
            whois.clear_whois_cache()
            result = await whois.whois_lookup("example.com")
            assert result.error is None

    gc.collect()
    snapshot_after = tracemalloc.take_snapshot()
    tracemalloc.stop()

    stats = snapshot_after.compare_to(snapshot_before, "lineno")
    total_growth = sum(s.size_diff for s in stats if s.size_diff > 0)

    assert total_growth < MAX_MEMORY_GROWTH_BYTES, (
        f"Memory grew by {total_growth / 1024:.1f} KiB over {ITERATION_COUNT} iterations "
        f"— exceeds {MAX_MEMORY_GROWTH_BYTES / 1024:.0f} KiB limit"
    )


@pytest.mark.asyncio
async def test_repeated_cached_lookups_do_not_grow_memory(clear_cache):
    """Repeated cache-hit lookups show negligible memory growth."""
    # Prime the cache once.
    with patch("cybersec.core.tools.whois.python_whois.whois",
               return_value=_make_instant_whois("example.com")), \
         patch("cybersec.core.tools.whois._fetch_rdap", return_value=None), \
         patch("cybersec.core.tools.whois._get_redis", return_value=None):
        await whois.whois_lookup("example.com")

    gc.collect()
    tracemalloc.start()
    snapshot_before = tracemalloc.take_snapshot()

    # All subsequent calls should be pure cache reads.
    with patch("cybersec.core.tools.whois._get_redis", return_value=None):
        for _ in range(ITERATION_COUNT):
            result = await whois.whois_lookup("example.com")
            assert result.cached is True

    gc.collect()
    snapshot_after = tracemalloc.take_snapshot()
    tracemalloc.stop()

    stats = snapshot_after.compare_to(snapshot_before, "lineno")
    total_growth = sum(s.size_diff for s in stats if s.size_diff > 0)

    # Cache hits should be extremely cheap – allow a tighter bound of 1 MiB.
    assert total_growth < 1 * 1024 * 1024, (
        f"Cache-hit memory grew by {total_growth / 1024:.1f} KiB over {ITERATION_COUNT} "
        "iterations — possible cache-clone leak"
    )


@pytest.mark.asyncio
async def test_multiple_domains_do_not_exhaust_memory(clear_cache):
    """Repeated lookups across many distinct domains stay within memory bounds."""
    gc.collect()
    tracemalloc.start()
    snapshot_before = tracemalloc.take_snapshot()

    domains = [f"memtest{i}.com" for i in range(ITERATION_COUNT)]

    with patch("cybersec.core.tools.whois.python_whois.whois",
               side_effect=lambda d, *a, **kw: _make_instant_whois(d)), \
         patch("cybersec.core.tools.whois._fetch_rdap", return_value=None), \
         patch("cybersec.core.tools.whois._get_redis", return_value=None):

        results = await asyncio.gather(*[whois.whois_lookup(d) for d in domains])

    gc.collect()
    snapshot_after = tracemalloc.take_snapshot()
    tracemalloc.stop()

    stats = snapshot_after.compare_to(snapshot_before, "lineno")
    total_growth = sum(s.size_diff for s in stats if s.size_diff > 0)

    assert len(results) == ITERATION_COUNT
    assert all(r.error is None for r in results)
    assert total_growth < MAX_MEMORY_GROWTH_BYTES, (
        f"Memory grew by {total_growth / 1024:.1f} KiB for {ITERATION_COUNT} distinct-domain lookups"
    )


@pytest.mark.asyncio
async def test_cache_does_not_grow_without_bound(clear_cache):
    """After many unique lookups, internal cache size stays bounded by max-size policy."""
    with patch("cybersec.core.tools.whois.python_whois.whois",
               side_effect=lambda d, *a, **kw: _make_instant_whois(d)), \
         patch("cybersec.core.tools.whois._fetch_rdap", return_value=None), \
         patch("cybersec.core.tools.whois._get_redis", return_value=None):

        # Overfill the cache with unique domains
        for i in range(500):
            await whois.whois_lookup(f"overflow{i}.com")

    # Verify cache size is bounded (the module defines _CACHE_MAX_SIZE = 512)
    with whois._CACHE_LOCK:
        cache_size = len(whois._CACHE)

    assert cache_size <= 512, (
        f"Cache grew to {cache_size} entries — size-bounding policy may be broken"
    )
