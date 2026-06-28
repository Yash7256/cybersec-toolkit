"""
Tests for cybersec/core/tools/ping.py

Coverage:
  (a) Private/loopback target with allow_private=False returns error without
      ever calling create_subprocess_exec.
  (b) allow_private=True lets a private target proceed to the subprocess call.
  (c) Constructed cmd list contains '--' immediately before the IP on non-Windows,
      and uses the resolved IP (not the original hostname).
  (d) history_delta_ms is computed from a Redis value seeded before the call,
      and no module-level _PING_HISTORY dict exists on the module.
"""
import sys
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

import cybersec.core.tools.ping as ping_module
from cybersec.core.tools.ping import ping_host


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_FAKE_OUTPUT = (
    b"PING 127.0.0.1: 56 data bytes\n"
    b"64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=1.0 ms\n"
    b"64 bytes from 127.0.0.1: icmp_seq=2 ttl=64 time=2.0 ms\n"
    b"2 packets transmitted, 2 received, 0% packet loss\n"
    b"rtt min/avg/max/mdev = 1.000/1.500/2.000/0.500 ms\n"
)


def _make_process(stdout: bytes = _FAKE_OUTPUT) -> MagicMock:
    proc = MagicMock()
    proc.communicate = AsyncMock(return_value=(stdout, b""))
    return proc


# ---------------------------------------------------------------------------
# (a) Private target blocked; create_subprocess_exec never called
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_private_target_blocked_by_default():
    """Pinging 127.0.0.1 with allow_private=False must return an error result
    without ever launching a subprocess."""
    with (
        patch("asyncio.get_running_loop") as mock_loop_factory,
        patch("asyncio.create_subprocess_exec") as mock_exec,
    ):
        mock_loop = MagicMock()
        mock_loop.getaddrinfo = AsyncMock(
            return_value=[(None, None, None, None, ("127.0.0.1", 0))]
        )
        mock_loop_factory.return_value = mock_loop

        result = await ping_host("127.0.0.1")  # allow_private defaults to False

    assert result.error is not None
    assert "not permitted" in result.error
    assert result.packets_sent == 0
    assert result.packets_received == 0
    assert result.packet_loss_pct == 100.0
    mock_exec.assert_not_called()


# ---------------------------------------------------------------------------
# (b) allow_private=True lets a private target reach the subprocess
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_allow_private_permits_private_target():
    """With allow_private=True a private/loopback IP must proceed to
    create_subprocess_exec (mocked so no real shell-out happens)."""
    with (
        patch("asyncio.get_running_loop") as mock_loop_factory,
        patch("asyncio.create_subprocess_exec", return_value=_make_process()) as mock_exec,
        patch("cybersec.core.tools.ping.get_shared_redis_client", return_value=None),
        patch("cybersec.core.tools.ping._geo_for_ip", new=AsyncMock(return_value={})),
    ):
        mock_loop = MagicMock()
        mock_loop.getaddrinfo = AsyncMock(
            return_value=[(None, None, None, None, ("127.0.0.1", 0))]
        )
        mock_loop_factory.return_value = mock_loop

        result = await ping_host("127.0.0.1", allow_private=True)

    mock_exec.assert_called_once()
    assert result.error is None


# ---------------------------------------------------------------------------
# (c) cmd contains '--' before IP on non-Windows; uses resolved IP
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_subprocess_cmd_uses_resolved_ip_with_separator():
    """On non-Windows the argv must be ['ping', '-c', N, '--', RESOLVED_IP].
    The original hostname must NOT appear in the subprocess argv."""
    if sys.platform == "win32":
        pytest.skip("-- separator test is Linux/macOS-only")

    resolved_ip = "93.184.216.34"  # known IP, never actually contacted

    captured_cmd: list = []

    async def fake_exec(*args, **kwargs):
        captured_cmd.extend(args)
        return _make_process()

    with (
        patch("asyncio.get_running_loop") as mock_loop_factory,
        patch("asyncio.create_subprocess_exec", side_effect=fake_exec),
        patch("cybersec.core.tools.ping.get_shared_redis_client", return_value=None),
        patch("cybersec.core.tools.ping._geo_for_ip", new=AsyncMock(return_value={})),
    ):
        mock_loop = MagicMock()
        mock_loop.getaddrinfo = AsyncMock(
            return_value=[(None, None, None, None, (resolved_ip, 0))]
        )
        mock_loop_factory.return_value = mock_loop

        await ping_host("example.com", count=2, allow_private=True)

    assert "--" in captured_cmd, "-- separator missing from cmd"
    sep_idx = captured_cmd.index("--")
    assert captured_cmd[sep_idx + 1] == resolved_ip, "IP must follow -- in cmd"
    assert "example.com" not in captured_cmd, "hostname must not appear in subprocess argv"


# ---------------------------------------------------------------------------
# (d) history_delta_ms comes from Redis; no module-level _PING_HISTORY dict
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_history_delta_from_redis_not_module_dict():
    """history_delta_ms must be computed from a value seeded in Redis, and
    the module must not have a _PING_HISTORY dict attribute at all."""
    # Verify the module-level dict is gone
    assert not hasattr(ping_module, "_PING_HISTORY"), (
        "_PING_HISTORY module dict still present — it should have been removed"
    )

    resolved_ip = "8.8.8.8"
    previous_avg = 10.0  # seed Redis with this prior value

    mock_redis = MagicMock()
    mock_redis.get = AsyncMock(return_value=str(previous_avg))
    mock_redis.set = AsyncMock()

    with (
        patch("asyncio.get_running_loop") as mock_loop_factory,
        patch("asyncio.create_subprocess_exec", return_value=_make_process()) as _mock_exec,
        patch("cybersec.core.tools.ping.get_shared_redis_client", return_value=mock_redis),
        patch("cybersec.core.tools.ping._geo_for_ip", new=AsyncMock(return_value={})),
    ):
        mock_loop = MagicMock()
        mock_loop.getaddrinfo = AsyncMock(
            return_value=[(None, None, None, None, (resolved_ip, 0))]
        )
        mock_loop_factory.return_value = mock_loop

        result = await ping_host(resolved_ip, count=2, allow_private=True)

    # The ping output has avg=1.5ms; previous was 10.0ms → delta = 1.5 - 10.0 = -8.5
    assert result.history_delta_ms is not None, "history_delta_ms should be set"
    assert abs(result.history_delta_ms - (result.avg_ms - previous_avg)) < 0.01

    # Redis.set must have been called to persist the new value
    mock_redis.set.assert_called_once()
    set_call_args = mock_redis.set.call_args
    assert resolved_ip in set_call_args[0][0]  # key contains the IP
