"""
Tests for cybersec/core/tools/traceroute.py

Coverage:
  (a) Private/loopback target with allow_private=False returns error result
      without calling create_subprocess_exec.
  (b) A subprocess whose communicate() hangs is killed after timeout, and an
      error result is returned within the test's time budget.
  (c) The constructed cmd list contains "--" immediately before the resolved IP
      on non-Windows.
  (d) A second traceroute() call sharing a hop IP with the first reuses the
      cached reverse-DNS result (gethostbyaddr called only once across both).
"""
import asyncio
import sys
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from cybersec.core.tools.traceroute import traceroute


# ---------------------------------------------------------------------------
# Minimal fake traceroute output for a single responding hop
# ---------------------------------------------------------------------------

def _fake_output(ip: str = "1.2.3.4") -> bytes:
    return (
        f"traceroute to example.com, 30 hops max\n"
        f" 1  {ip}  10.123 ms  11.456 ms  12.789 ms\n"
    ).encode()


def _make_process(stdout: bytes, hang: bool = False) -> MagicMock:
    proc = MagicMock()
    proc.kill = MagicMock()
    proc.wait = AsyncMock()
    if hang:
        async def _hang():
            await asyncio.sleep(9999)
        proc.communicate = _hang
    else:
        proc.communicate = AsyncMock(return_value=(stdout, b""))
    return proc


# ---------------------------------------------------------------------------
# (a) Private target blocked; create_subprocess_exec never called
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_private_target_blocked_by_default():
    with (
        patch("asyncio.get_running_loop") as mock_loop_factory,
        patch("asyncio.create_subprocess_exec") as mock_exec,
    ):
        mock_loop = MagicMock()
        mock_loop.getaddrinfo = AsyncMock(
            return_value=[(None, None, None, None, ("127.0.0.1", 0))]
        )
        mock_loop_factory.return_value = mock_loop

        result = await traceroute("localhost")  # allow_private defaults to False

    assert result.error is not None
    assert "not permitted" in result.error
    assert result.hops == []
    assert result.total_hops == 0
    mock_exec.assert_not_called()


# ---------------------------------------------------------------------------
# (b) Subprocess timeout: process.kill() called, error result returned
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_subprocess_timeout_kills_process():
    if sys.platform == "win32":
        pytest.skip("timeout behaviour identical on Windows but process mock differs")

    hanging_proc = _make_process(b"", hang=True)

    with (
        patch("asyncio.get_running_loop") as mock_loop_factory,
        patch("asyncio.create_subprocess_exec", return_value=hanging_proc),
        patch("cybersec.core.tools.traceroute.settings") as mock_settings,
    ):
        mock_settings.TRACEROUTE_TIMEOUT_SECONDS = 1  # very short for the test
        mock_settings.HOP_INFO_CACHE_TTL_SECONDS = 86400
        mock_loop = MagicMock()
        mock_loop.getaddrinfo = AsyncMock(
            return_value=[(None, None, None, None, ("93.184.216.34", 0))]
        )
        mock_loop_factory.return_value = mock_loop

        result = await traceroute("example.com", allow_private=True)

    assert result.error is not None
    assert "timed out" in result.error.lower()
    assert result.hops == []
    hanging_proc.kill.assert_called_once()
    hanging_proc.wait.assert_called_once()


# ---------------------------------------------------------------------------
# (c) cmd contains "--" before resolved IP on non-Windows
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_cmd_contains_separator_and_resolved_ip():
    if sys.platform == "win32":
        pytest.skip("-- separator is Linux/macOS-only")

    resolved_ip = "93.184.216.34"
    captured: list = []

    async def fake_exec(*args, **kwargs):
        captured.extend(args)
        return _make_process(_fake_output(resolved_ip))

    with (
        patch("asyncio.get_running_loop") as mock_loop_factory,
        patch("asyncio.create_subprocess_exec", side_effect=fake_exec),
        patch("cybersec.core.tools.traceroute.get_shared_redis_client", return_value=None),
        patch("cybersec.core.tools.traceroute._geoip_for_hop", new=AsyncMock(return_value={})),
    ):
        mock_loop = MagicMock()
        mock_loop.getaddrinfo = AsyncMock(
            return_value=[(None, None, None, None, (resolved_ip, 0))]
        )
        mock_loop.run_in_executor = AsyncMock(return_value=(None, [], []))
        mock_loop_factory.return_value = mock_loop

        await traceroute("example.com", allow_private=True)

    assert "--" in captured, "-- separator missing from traceroute cmd"
    sep_idx = captured.index("--")
    assert captured[sep_idx + 1] == resolved_ip
    assert "example.com" not in captured


# ---------------------------------------------------------------------------
# (d) Redis caches reverse-DNS: gethostbyaddr called once across two calls
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_reverse_dns_cached_in_redis():
    if sys.platform == "win32":
        pytest.skip("reverse-DNS caching test targets non-Windows path")

    hop_ip = "8.8.4.4"  # public IP — not filtered by _private_ip()
    fake_output = _fake_output(hop_ip)

    # Redis mock: acts as a real in-memory store so the cache-hit path works.
    _store: dict[str, str] = {}
    mock_redis = MagicMock()

    async def _redis_get(key):
        return _store.get(key)

    async def _redis_set(key, value, ex=None):
        _store[key] = value

    mock_redis.get = _redis_get
    mock_redis.set = _redis_set

    gethostbyaddr_mock = MagicMock(return_value=("router.example.net", [], [hop_ip]))

    async def fake_exec(*args, **kwargs):
        return _make_process(fake_output)

    with (
        patch("asyncio.get_running_loop") as mock_loop_factory,
        patch("asyncio.create_subprocess_exec", side_effect=fake_exec),
        patch("cybersec.core.tools.traceroute.get_shared_redis_client", return_value=mock_redis),
        patch("cybersec.core.tools.traceroute._geoip_for_hop", new=AsyncMock(return_value={})),
        patch("socket.gethostbyaddr", gethostbyaddr_mock),
    ):
        mock_loop = MagicMock()
        mock_loop.getaddrinfo = AsyncMock(
            return_value=[(None, None, None, None, ("93.184.216.34", 0))]
        )
        # Delegate run_in_executor to the real event loop so asyncio.wait_for works
        real_loop = asyncio.get_event_loop()
        mock_loop.run_in_executor = real_loop.run_in_executor
        mock_loop_factory.return_value = mock_loop

        # First call — cache miss, gethostbyaddr must be invoked
        await traceroute("example.com", allow_private=True)
        # Second call — Redis cache hit, gethostbyaddr must NOT be invoked again
        await traceroute("example.com", allow_private=True)

    assert gethostbyaddr_mock.call_count == 1, (
        f"gethostbyaddr called {gethostbyaddr_mock.call_count} times; "
        "expected 1 (second call should use Redis cache)"
    )
