"""
Tests for SSRF guard and redirect validation in check_http_headers().

Cases covered:
  (a) Private/loopback target → error returned, no HTTP request made.
  (b) Redirect chain that leads to a private IP on hop 2 → stops, error,
      blocked URL never requested.
  (c) Normal redirect chain to public IPs → followed, reported correctly.
"""
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

import httpx

from cybersec.core.tools.http_headers import check_http_headers


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_response(url: str, status: int, location: str | None = None) -> MagicMock:
    """Build a minimal mock httpx.Response."""
    resp = MagicMock(spec=httpx.Response)
    resp.url = httpx.URL(url)
    resp.status_code = status
    resp.http_version = "HTTP/1.1"
    resp.headers = MagicMock()
    resp.headers.get = lambda key, default=None: location if key == "location" else default
    resp.headers.get_list = lambda key: []
    resp.headers.items.return_value = []
    return resp


# ---------------------------------------------------------------------------
# (a) Private / loopback target blocked before any HTTP request
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
@pytest.mark.unit
class TestSsrfGuardInitialTarget:
    async def test_loopback_returns_error_without_request(self):
        with (
            patch("cybersec.core.tools.http_headers._resolve_host", return_value="127.0.0.1"),
            patch("cybersec.core.tools.http_headers.httpx.AsyncClient") as mock_client,
        ):
            result = await check_http_headers("http://localhost/", allow_private=False)

        assert result.error is not None
        assert "private" in result.error.lower() or "loopback" in result.error.lower() or "not permitted" in result.error.lower()
        mock_client.assert_not_called()

    async def test_private_rfc1918_returns_error_without_request(self):
        with (
            patch("cybersec.core.tools.http_headers._resolve_host", return_value="10.0.0.1"),
            patch("cybersec.core.tools.http_headers.httpx.AsyncClient") as mock_client,
        ):
            result = await check_http_headers("http://internal.corp/", allow_private=False)

        assert result.error is not None
        mock_client.assert_not_called()

    async def test_cloud_metadata_ip_blocked(self):
        with (
            patch("cybersec.core.tools.http_headers._resolve_host", return_value="169.254.169.254"),
            patch("cybersec.core.tools.http_headers.httpx.AsyncClient") as mock_client,
        ):
            result = await check_http_headers("http://169.254.169.254/", allow_private=False)

        assert result.error is not None
        mock_client.assert_not_called()

    async def test_allow_private_bypasses_guard(self):
        """allow_private=True must skip the SSRF check entirely."""
        final = _make_response("http://127.0.0.1/", 200)

        mock_resp = AsyncMock()
        mock_resp.__aenter__ = AsyncMock(return_value=mock_resp)
        mock_resp.__aexit__ = AsyncMock(return_value=False)
        mock_resp.get = AsyncMock(return_value=final)

        with patch("cybersec.core.tools.http_headers.httpx.AsyncClient", return_value=mock_resp):
            result = await check_http_headers("http://127.0.0.1/", allow_private=True)

        # Should NOT have an SSRF error (might have another error, but not the guard message)
        assert result.error != "Checking headers on private, loopback, or cloud-metadata addresses is not permitted"


# ---------------------------------------------------------------------------
# (b) Redirect chain leads to a private IP on hop 2 — stops, blocked URL never fetched
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
@pytest.mark.unit
class TestRedirectSsrfGuard:
    async def test_redirect_to_private_stopped_on_hop2(self):
        """
        Initial request to public IP succeeds with 301 → Location: http://internal/.
        _resolve_host for the redirect target returns 192.168.1.1.
        Expect: error returned, the private URL is never requested.
        """
        hop1_resp = _make_response("http://public.example.com/", 301, "http://internal.corp/secret")

        request_count = 0

        async def fake_get(url, **kwargs):
            nonlocal request_count
            request_count += 1
            return hop1_resp

        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.get = fake_get

        def fake_resolve(url: str) -> str:
            if "internal" in url:
                return "192.168.1.1"
            return "93.184.216.34"  # public

        with (
            patch("cybersec.core.tools.http_headers._resolve_host", side_effect=fake_resolve),
            patch("cybersec.core.tools.http_headers.httpx.AsyncClient", return_value=mock_client),
        ):
            result = await check_http_headers("http://public.example.com/", allow_private=False)

        assert result.error is not None
        assert "private" in result.error.lower() or "redirect" in result.error.lower()
        # Only the first hop should have been requested; the private URL must not be fetched
        assert request_count == 1


# ---------------------------------------------------------------------------
# (c) Normal redirect chain to public IPs is followed and reported
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
@pytest.mark.unit
class TestNormalRedirectChain:
    async def test_public_redirect_followed_and_reported(self):
        """
        hop1: 301 → http://www.example.com/
        hop2: 200 (final)
        Both hops are public; result should have no error and redirect_chain length 2.
        """
        hop1 = _make_response("http://example.com/", 301, "http://www.example.com/")
        hop2 = _make_response("http://www.example.com/", 200)

        urls_requested = []

        async def fake_get(url, **kwargs):
            urls_requested.append(url)
            if "www." in url:
                return hop2
            return hop1

        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.get = fake_get

        with (
            patch("cybersec.core.tools.http_headers._resolve_host", return_value="93.184.216.34"),
            patch("cybersec.core.tools.http_headers.httpx.AsyncClient", return_value=mock_client),
        ):
            result = await check_http_headers("http://example.com/", allow_private=False)

        assert result.error is None
        assert len(result.redirect_chain) == 2
        assert result.redirect_chain[0]["status_code"] == 301
        assert result.redirect_chain[1]["status_code"] == 200
        assert result.tls_verification_skipped is True
        # Both URLs were actually requested
        assert len(urls_requested) == 2

    async def test_no_redirect_single_entry_in_chain(self):
        """Non-redirecting 200 response produces a chain of length 1."""
        resp = _make_response("http://example.com/", 200)

        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.get = AsyncMock(return_value=resp)

        with (
            patch("cybersec.core.tools.http_headers._resolve_host", return_value="93.184.216.34"),
            patch("cybersec.core.tools.http_headers.httpx.AsyncClient", return_value=mock_client),
        ):
            result = await check_http_headers("http://example.com/", allow_private=False)

        assert result.error is None
        assert len(result.redirect_chain) == 1
