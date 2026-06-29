"""
Tests for WebAppScanner security hardening.

Cases:
  (a) Private/loopback target with allow_private=False → error result, crawl never called.
  (b) confirm_authorized=False on /start-scan and /scan routes → HTTP 400.
  (c) Scan exceeds WEBAPP_SCAN_MAX_DURATION_SECONDS → returns within budget with timeout
      error message in result; partial (zero-) results preserved.
  (d) Redirect to private IP during crawl() is not followed.
"""
import asyncio
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

import httpx

from cybersec.core.tools.webapp_scanner import WebAppScanner, WebAppScanResult


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_resp(url: str, status: int, location: str | None = None, text: str = "") -> MagicMock:
    resp = MagicMock(spec=httpx.Response)
    resp.url = httpx.URL(url)
    resp.status_code = status
    resp.text = text
    resp.headers = MagicMock()
    resp.headers.get = lambda key, default=None: (location if key == "location" else default)
    resp.headers.items.return_value = []
    return resp


# ---------------------------------------------------------------------------
# (a) Private/loopback target blocked before crawl() or AsyncClient opens
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
@pytest.mark.unit
class TestSsrfGuardBeforeCrawl:

    async def test_loopback_blocked_no_crawl_no_client(self):
        """127.0.0.1 → immediate error result; crawl and AsyncClient never called."""
        with (
            patch("cybersec.core.tools.webapp_scanner.WebAppScanner._resolve_ip", return_value="127.0.0.1"),
            patch("cybersec.core.tools.port_scanner._is_scan_target_allowed", return_value=False),
            patch("cybersec.core.tools.webapp_scanner.WebAppScanner.crawl", new_callable=AsyncMock) as mock_crawl,
            patch("cybersec.core.tools.webapp_scanner.httpx.AsyncClient") as mock_client_cls,
        ):
            scanner = WebAppScanner(max_pages=5)
            result = await scanner.scan("http://localhost/", allow_private=False)

        assert result.error is not None
        assert "not permitted" in result.error
        assert result.pages_crawled == 0
        assert result.vulnerabilities == []
        mock_crawl.assert_not_called()
        mock_client_cls.assert_not_called()

    async def test_private_rfc1918_blocked(self):
        with (
            patch("cybersec.core.tools.webapp_scanner.WebAppScanner._resolve_ip", return_value="10.0.0.1"),
            patch("cybersec.core.tools.port_scanner._is_scan_target_allowed", return_value=False),
            patch("cybersec.core.tools.webapp_scanner.httpx.AsyncClient") as mock_client_cls,
        ):
            scanner = WebAppScanner(max_pages=5)
            result = await scanner.scan("http://internal.corp/", allow_private=False)

        assert result.error is not None
        assert result.pages_crawled == 0
        mock_client_cls.assert_not_called()

    async def test_allow_private_bypasses_ssrf_guard(self):
        """allow_private=True must skip the guard and proceed to open the client."""
        mock_ctx = AsyncMock()
        mock_ctx.__aenter__ = AsyncMock(return_value=mock_ctx)
        mock_ctx.__aexit__ = AsyncMock(return_value=False)
        # crawl raises so we get an early exit without complex mocking
        mock_ctx.get = AsyncMock(side_effect=Exception("connection refused"))

        with (
            patch("cybersec.core.tools.webapp_scanner.httpx.AsyncClient", return_value=mock_ctx),
            patch("cybersec.core.tools.webapp_scanner.WebAppScanner._resolve_ip", return_value="127.0.0.1"),
        ):
            scanner = WebAppScanner(max_pages=1)
            result = await scanner.scan("http://localhost/", allow_private=True)

        # Guard was bypassed; error is connection-related, not the SSRF message
        assert result.error != "Scanning private, loopback, or cloud-metadata addresses is not permitted"
        mock_ctx.__aenter__.assert_called_once()


# ---------------------------------------------------------------------------
# (b) confirm_authorized=False → HTTP 400 on API routes
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
@pytest.mark.unit
class TestConfirmAuthorizedGate:

    @pytest.fixture
    def app(self):
        """Return the FastAPI app with webapp router mounted under /api/webapp,
        with DB and auth dependencies overridden so no real infrastructure is needed."""
        from fastapi import FastAPI
        from cybersec.apps.api.routes import webapp as webapp_module
        from cybersec.apps.api.deps import get_db, get_optional_user

        _app = FastAPI()
        _app.include_router(webapp_module.router, prefix="/api/webapp")

        # Override dependencies to avoid DB/auth setup
        _app.dependency_overrides[get_db] = lambda: (x for x in [None])
        _app.dependency_overrides[get_optional_user] = lambda: None

        return _app

    async def test_scan_route_returns_400_without_confirmation(self, app):
        from httpx import AsyncClient, ASGITransport
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
            resp = await ac.post("/api/webapp/scan", json={
                "target": "https://example.com",
                "max_pages": 5,
                "confirm_authorized": False,
            })
        assert resp.status_code == 400
        assert "authorized" in resp.json()["detail"].lower()

    async def test_start_scan_route_returns_400_without_confirmation(self, app):
        from httpx import AsyncClient, ASGITransport
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
            resp = await ac.post("/api/webapp/start-scan", json={
                "target": "https://example.com",
                "max_pages": 5,
                "confirm_authorized": False,
            })
        assert resp.status_code == 400
        assert "authorized" in resp.json()["detail"].lower()

    async def test_scan_route_missing_field_returns_422(self, app):
        """confirm_authorized has no default — omitting it should be a validation error."""
        from httpx import AsyncClient, ASGITransport
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
            resp = await ac.post("/api/webapp/scan", json={
                "target": "https://example.com",
                "max_pages": 5,
                # confirm_authorized intentionally omitted
            })
        assert resp.status_code == 422


# ---------------------------------------------------------------------------
# (c) Scan timeout — returns within budget with partial results + error message
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
@pytest.mark.unit
class TestScanDurationLimit:

    async def test_timeout_returns_partial_results_with_error(self):
        """Set WEBAPP_SCAN_MAX_DURATION_SECONDS to 0.05s so _do_scan times out
        immediately; assert the returned result carries the timeout error and
        the call itself completes well within the test's time budget."""
        import time
        from cybersec.config.settings import settings as real_settings

        async def _slow_crawl(*args, **kwargs):
            await asyncio.sleep(10)  # will be cancelled by wait_for
            return []

        original_timeout = real_settings.WEBAPP_SCAN_MAX_DURATION_SECONDS
        real_settings.WEBAPP_SCAN_MAX_DURATION_SECONDS = 0.05
        try:
            with (
                patch("cybersec.core.tools.webapp_scanner.WebAppScanner._resolve_ip", return_value="93.184.216.34"),
                patch("cybersec.core.tools.port_scanner._is_scan_target_allowed", return_value=True),
                patch("cybersec.core.tools.webapp_scanner.WebAppScanner.crawl", side_effect=_slow_crawl),
            ):
                scanner = WebAppScanner(max_pages=5)
                t0 = time.perf_counter()
                result = await scanner.scan("https://example.com", allow_private=False)
                elapsed = time.perf_counter() - t0
        finally:
            real_settings.WEBAPP_SCAN_MAX_DURATION_SECONDS = original_timeout

        # Must finish well within the 10s sleep
        assert elapsed < 2.0, f"Scan took {elapsed:.2f}s — timeout not enforced"
        assert result.error is not None
        assert "exceeded" in result.error.lower() or "incomplete" in result.error.lower()
        # pages_crawled may be 0 but result is a valid WebAppScanResult
        assert isinstance(result, WebAppScanResult)


# ---------------------------------------------------------------------------
# (d) Redirect to private IP during crawl() is not followed
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
@pytest.mark.unit
class TestCrawlRedirectSsrfGuard:

    async def test_redirect_to_private_ip_not_followed(self):
        """
        _safe_get called for 'http://public.example.com/' returns a 301 to
        'http://internal.corp/secret'. When _resolve_ip for the redirect target
        returns 10.0.0.1 (private), _safe_get returns None and the private URL
        is never requested.
        """
        hop1 = _make_resp("http://public.example.com/", 301, "http://internal.corp/secret")
        requested_urls: list[str] = []

        # Intercept the raw httpx client to record every GET attempt
        orig_safe_get = WebAppScanner._safe_get

        async def tracked_safe_get(self_inner, url, client, allow_private=False, **kwargs):
            requested_urls.append(url)
            return await orig_safe_get(self_inner, url, client, allow_private=allow_private, **kwargs)

        # raw client.get: first call returns hop1, any subsequent call should not happen
        raw_get_calls: list[str] = []

        async def mock_raw_get(url, **kwargs):
            raw_get_calls.append(url)
            return hop1  # always returns the redirect

        mock_client = AsyncMock()
        mock_client.get = mock_raw_get
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        def resolve_side_effect(url: str) -> str:
            if "internal" in url:
                return "10.0.0.1"
            return "93.184.216.34"

        with (
            patch.object(WebAppScanner, "_safe_get", tracked_safe_get),
            patch("cybersec.core.tools.webapp_scanner.WebAppScanner._resolve_ip", side_effect=resolve_side_effect),
            patch("cybersec.core.tools.port_scanner._is_scan_target_allowed",
                  side_effect=lambda ip: ip != "10.0.0.1"),
        ):
            scanner = WebAppScanner(max_pages=3)
            mock_client_instance = AsyncMock()
            mock_client_instance.get = mock_raw_get
            pages = await scanner.crawl(
                "http://public.example.com/", mock_client_instance, allow_private=False
            )

        # The private redirect URL must NOT appear in raw_get_calls
        private_fetches = [u for u in raw_get_calls if "internal" in u]
        assert private_fetches == [], (
            f"Private URL was fetched: {private_fetches} — redirect SSRF guard failed"
        )


# ---------------------------------------------------------------------------
# Regression Tests: allow_private threading and async resolver
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
@pytest.mark.unit
class TestCheckTlsAllowPrivate:

    async def test_check_tls_passes_allow_private_to_ssl_audit(self):
        """
        check_tls(base_url, allow_private=True) must pass allow_private=True to
        ssl_audit so private HTTPS targets aren't blocked during internal scans.

        Regression: check_tls() previously called ssl_audit(host, port) with no
        allow_private argument, causing it to always default to False.
        """
        from unittest.mock import AsyncMock, patch
        from cybersec.core.tools.ssl import SSLResult

        dummy_result = SSLResult(
            host="192.168.1.10", port=443,
            tls_version="TLSv1.3", cipher_suite="TLS_AES_256_GCM_SHA384",
            cert=None, is_self_signed=False,
            supports_tls12=True, supports_tls13=True, error=None,
        )
        ssl_mock = AsyncMock(return_value=dummy_result)

        scanner = WebAppScanner()
        # ssl_audit is imported locally inside check_tls — patch at source
        with patch("cybersec.core.tools.ssl.ssl_audit", ssl_mock):
            vulns = await scanner.check_tls("https://192.168.1.10/", allow_private=True)

        assert ssl_mock.call_count == 1
        _, kwargs = ssl_mock.call_args
        assert kwargs.get("allow_private") is True, (
            f"ssl_audit was not called with allow_private=True: {ssl_mock.call_args}"
        )
        assert not any(v.vuln_type == "TLS_ERROR" for v in vulns)

    async def test_check_tls_default_allow_private_false(self):
        """check_tls with default allow_private (False) passes False to ssl_audit."""
        from unittest.mock import AsyncMock, patch
        from cybersec.core.tools.ssl import SSLResult

        dummy_result = SSLResult(
            host="1.2.3.4", port=443,
            tls_version="TLSv1.3", cipher_suite="TLS_AES_256_GCM_SHA384",
            cert=None, is_self_signed=False,
            supports_tls12=True, supports_tls13=True, error=None,
        )
        ssl_mock = AsyncMock(return_value=dummy_result)

        scanner = WebAppScanner()
        with patch("cybersec.core.tools.ssl.ssl_audit", ssl_mock):
            await scanner.check_tls("https://1.2.3.4/")

        _, kwargs = ssl_mock.call_args
        assert kwargs.get("allow_private") is False


@pytest.mark.asyncio
@pytest.mark.unit
class TestResolveIpAsync:

    async def test_resolve_ip_uses_async_getaddrinfo(self):
        """
        _resolve_ip must use the async loop.getaddrinfo, not blocking
        socket.getaddrinfo, so it doesn't block the event loop.

        Regression: _resolve_ip was a @staticmethod using the synchronous
        socket.getaddrinfo() call.
        """
        import inspect
        from unittest.mock import AsyncMock, patch, MagicMock

        scanner = WebAppScanner()

        # _resolve_ip must be a coroutine function (async method)
        assert inspect.iscoroutinefunction(scanner._resolve_ip), (
            "_resolve_ip must be async (coroutinefunction)"
        )

        loop_mock = MagicMock()
        loop_mock.getaddrinfo = AsyncMock(
            return_value=[(None, None, None, None, ("93.184.216.34", 0))]
        )

        with patch("asyncio.get_event_loop", return_value=loop_mock):
            result = await scanner._resolve_ip("https://example.com/")

        # The async getaddrinfo was called, not the sync version
        loop_mock.getaddrinfo.assert_called_once()
        assert result == "93.184.216.34"

    async def test_resolve_ip_does_not_call_sync_socket_getaddrinfo(self):
        """socket.getaddrinfo (the blocking version) must NOT be called by _resolve_ip."""
        import socket as socket_mod
        from unittest.mock import AsyncMock, patch, MagicMock

        scanner = WebAppScanner()

        loop_mock = MagicMock()
        loop_mock.getaddrinfo = AsyncMock(
            return_value=[(None, None, None, None, ("93.184.216.34", 0))]
        )

        with (
            patch("asyncio.get_event_loop", return_value=loop_mock),
            patch.object(socket_mod, "getaddrinfo", side_effect=AssertionError(
                "Blocking socket.getaddrinfo() was called — must use async version"
            )),
        ):
            # Should not raise even though socket.getaddrinfo is poisoned
            result = await scanner._resolve_ip("https://example.com/")

        assert result == "93.184.216.34"
