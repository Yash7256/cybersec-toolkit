"""
Tests for capture_web_port_screenshots() in port_scanner.py.

All tests mock Playwright's async_playwright / browser / context / page objects so
no real browser is launched in CI.

Coverage:
  (a) screenshot_url is set on an OpenPortDetail for a port in SCREENSHOT_PORTS
      when the mocked page.screenshot() succeeds.
  (b) A failure on one port (exception during page.goto) does NOT prevent
      screenshot_url being set for a different port in the same call.
  (c) capture_web_port_screenshots() is a no-op when
      settings.ENABLE_PORT_SCREENSHOTS is False.
  (d) The function respects the 30-second overall cap: a hung page.goto
      (asyncio.sleep longer than the cap) causes the function to return rather
      than blocking the test indefinitely.
"""
import asyncio
import os
from dataclasses import dataclass, field
from typing import List
from unittest.mock import AsyncMock, MagicMock, patch, call

import pytest

from cybersec.core.tools.port_scanner import (
    OpenPortDetail,
    capture_web_port_screenshots,
    SCREENSHOT_PORTS,
    _SCREENSHOT_TOTAL_TIMEOUT,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_port(port_number: int) -> OpenPortDetail:
    return OpenPortDetail(
        port_number=port_number,
        service="http",
        status="open",
        risk_level="low",
        risk_reason="test",
    )


def _make_playwright_mocks(
    *,
    goto_side_effect=None,
    screenshot_side_effect=None,
):
    """
    Build a minimal Playwright mock hierarchy:
      async_playwright() -> pw
      pw.chromium.launch()    -> browser
      browser.new_context()   -> ctx
      ctx.new_page()          -> page
      page.goto()             -> (configured via goto_side_effect)
      page.screenshot()       -> (configured via screenshot_side_effect)
      page.on()               -> no-op
    """
    # Page
    page = AsyncMock()
    page.on = MagicMock()   # synchronous event registration
    page.close = AsyncMock()
    if goto_side_effect is not None:
        page.goto = AsyncMock(side_effect=goto_side_effect)
    else:
        page.goto = AsyncMock(return_value=None)
    if screenshot_side_effect is not None:
        page.screenshot = AsyncMock(side_effect=screenshot_side_effect)
    else:
        page.screenshot = AsyncMock(return_value=b"PNG")

    # Context
    ctx = AsyncMock()
    ctx.new_page = AsyncMock(return_value=page)
    ctx.close = AsyncMock()

    # Browser
    browser = AsyncMock()
    browser.new_context = AsyncMock(return_value=ctx)
    browser.close = AsyncMock()

    # Chromium launcher
    chromium = MagicMock()
    chromium.launch = AsyncMock(return_value=browser)

    # Playwright instance
    pw = MagicMock()
    pw.chromium = chromium

    # async_playwright() context manager
    pw_cm = AsyncMock()
    pw_cm.__aenter__ = AsyncMock(return_value=pw)
    pw_cm.__aexit__ = AsyncMock(return_value=False)

    return pw_cm, browser, ctx, page


# ---------------------------------------------------------------------------
# Test (a): screenshot_url set when screenshot succeeds
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_screenshot_url_set_on_success(tmp_path):
    """
    When Playwright succeeds for a port in SCREENSHOT_PORTS, screenshot and
    screenshot_url must be populated on the OpenPortDetail.
    """
    port = next(iter(SCREENSHOT_PORTS))   # e.g. 80
    port_detail = _make_port(port)
    pw_cm, browser, ctx, page = _make_playwright_mocks()

    with (
        patch("cybersec.core.tools.port_scanner.settings") as mock_settings,
        patch("cybersec.core.tools.port_scanner.async_playwright", return_value=pw_cm),
        patch("os.makedirs"),
    ):
        mock_settings.ENABLE_PORT_SCREENSHOTS = True

        await capture_web_port_screenshots(
            "example.com",
            [port_detail],
            screenshot_dir=str(tmp_path),
        )

    assert port_detail.screenshot is not None, "screenshot filename should be set"
    assert port_detail.screenshot_url is not None, "screenshot_url should be set"
    assert port_detail.screenshot_url.startswith("/screenshots/")
    # page.screenshot() must have been called with a real path
    page.screenshot.assert_called_once()
    called_kwargs = page.screenshot.call_args[1]
    assert "path" in called_kwargs


# ---------------------------------------------------------------------------
# Test (b): one port failing does not block other ports
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_failure_on_one_port_does_not_block_others(tmp_path):
    """
    If page.goto raises an exception for port A, port B must still get its
    screenshot_url set.
    """
    # Pick two distinct SCREENSHOT_PORTS entries; if only one exists use 80 + 8080
    ports_sorted = sorted(SCREENSHOT_PORTS)
    if len(ports_sorted) >= 2:
        port_a, port_b = ports_sorted[0], ports_sorted[1]
    else:
        port_a, port_b = 80, 8080

    detail_a = _make_port(port_a)
    detail_b = _make_port(port_b)

    call_count = 0

    async def _goto_side_effect(*args, **kwargs):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            raise RuntimeError("navigation failed for port A")
        # Second call succeeds
        return None

    pw_cm, browser, ctx, page = _make_playwright_mocks(goto_side_effect=_goto_side_effect)

    with (
        patch("cybersec.core.tools.port_scanner.settings") as mock_settings,
        patch("cybersec.core.tools.port_scanner.async_playwright", return_value=pw_cm),
        patch("os.makedirs"),
    ):
        mock_settings.ENABLE_PORT_SCREENSHOTS = True

        await capture_web_port_screenshots(
            "example.com",
            [detail_a, detail_b],
            screenshot_dir=str(tmp_path),
        )

    # Port A failed — no screenshot
    assert detail_a.screenshot_url is None, "failed port should not have screenshot_url"
    # Port B succeeded
    assert detail_b.screenshot_url is not None, "successful port must have screenshot_url set"


# ---------------------------------------------------------------------------
# Test (c): no-op when ENABLE_PORT_SCREENSHOTS is False
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_noop_when_screenshots_disabled():
    """
    capture_web_port_screenshots() must return immediately without importing or
    calling Playwright when settings.ENABLE_PORT_SCREENSHOTS is False.
    """
    port = next(iter(SCREENSHOT_PORTS))
    detail = _make_port(port)

    pw_cm, _, _, page = _make_playwright_mocks()

    with (
        patch("cybersec.core.tools.port_scanner.settings") as mock_settings,
        patch("cybersec.core.tools.port_scanner.async_playwright", return_value=pw_cm) as mock_pw,
    ):
        mock_settings.ENABLE_PORT_SCREENSHOTS = False

        await capture_web_port_screenshots("example.com", [detail])

    # async_playwright must never have been entered
    mock_pw.return_value.__aenter__.assert_not_called()
    # Fields remain unset
    assert detail.screenshot is None
    assert detail.screenshot_url is None


# ---------------------------------------------------------------------------
# Test (d): 30-second overall cap is respected
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_total_timeout_cap_respected(tmp_path):
    """
    If page.goto hangs indefinitely the function must return within
    _SCREENSHOT_TOTAL_TIMEOUT seconds (tested with a tiny custom cap via
    monkeypatching to keep CI fast).
    """
    import cybersec.core.tools.port_scanner as ps_mod

    port = next(iter(SCREENSHOT_PORTS))
    detail = _make_port(port)

    # Make page.goto sleep much longer than our patched cap
    SHORT_CAP = 0.15  # seconds — fast for CI

    async def _hung_goto(*args, **kwargs):
        await asyncio.sleep(SHORT_CAP * 10)   # would exceed cap by 10×

    pw_cm, browser, ctx, page = _make_playwright_mocks(goto_side_effect=_hung_goto)

    original_cap = ps_mod._SCREENSHOT_TOTAL_TIMEOUT
    ps_mod._SCREENSHOT_TOTAL_TIMEOUT = SHORT_CAP

    try:
        with (
            patch("cybersec.core.tools.port_scanner.settings") as mock_settings,
            patch("cybersec.core.tools.port_scanner.async_playwright", return_value=pw_cm),
            patch("os.makedirs"),
        ):
            mock_settings.ENABLE_PORT_SCREENSHOTS = True

            import time
            t0 = time.perf_counter()
            await capture_web_port_screenshots(
                "example.com",
                [detail],
                screenshot_dir=str(tmp_path),
            )
            elapsed = time.perf_counter() - t0
    finally:
        ps_mod._SCREENSHOT_TOTAL_TIMEOUT = original_cap

    # Must have returned promptly after the cap, not after the full sleep
    assert elapsed < SHORT_CAP * 5, (
        f"Function did not respect timeout cap: took {elapsed:.3f}s, "
        f"cap was {SHORT_CAP}s"
    )
    # No screenshot should have been set (goto never completed)
    assert detail.screenshot_url is None


# ---------------------------------------------------------------------------
# Test (e): empty open_ports list → no browser launched
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_no_browser_launch_when_no_web_ports():
    """
    If none of the open ports are in SCREENSHOT_PORTS, Playwright must not
    be started at all.
    """
    # Port 9999 is not in SCREENSHOT_PORTS
    detail = _make_port(9999)
    pw_cm, _, _, _ = _make_playwright_mocks()

    with (
        patch("cybersec.core.tools.port_scanner.settings") as mock_settings,
        patch("cybersec.core.tools.port_scanner.async_playwright", return_value=pw_cm) as mock_pw,
    ):
        mock_settings.ENABLE_PORT_SCREENSHOTS = True
        await capture_web_port_screenshots("example.com", [detail])

    mock_pw.return_value.__aenter__.assert_not_called()
    assert detail.screenshot_url is None
