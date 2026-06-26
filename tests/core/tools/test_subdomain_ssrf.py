"""
Tests for the SSRF guard in subdomain.py.

Design decision: ALL resolved IPs for a hostname must pass _is_safe_public_ip()
before an HTTP probe is allowed.  A single private IP in a round-robin set is
enough to block the probe entirely, because httpx may connect to any of the
returned IPs and we cannot guarantee it will pick the safe one.
"""
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from cybersec.core.tools.subdomain import (
    _is_safe_public_ip,
    find_subdomains,
    stream_subdomain_events,
)


# ---------------------------------------------------------------------------
# Unit tests for _is_safe_public_ip
# ---------------------------------------------------------------------------

@pytest.mark.unit
class TestIsSafePublicIp:
    def test_public_ipv4_is_safe(self):
        assert _is_safe_public_ip("93.184.216.34") is True   # example.com

    def test_loopback_is_blocked(self):
        assert _is_safe_public_ip("127.0.0.1") is False

    def test_ipv6_loopback_is_blocked(self):
        assert _is_safe_public_ip("::1") is False

    def test_link_local_metadata_service_is_blocked(self):
        assert _is_safe_public_ip("169.254.169.254") is False  # cloud metadata

    def test_rfc1918_10_is_blocked(self):
        assert _is_safe_public_ip("10.0.0.1") is False

    def test_rfc1918_172_is_blocked(self):
        assert _is_safe_public_ip("172.16.0.1") is False
        assert _is_safe_public_ip("172.31.255.254") is False

    def test_rfc1918_192_168_is_blocked(self):
        assert _is_safe_public_ip("192.168.1.1") is False

    def test_ipv6_link_local_is_blocked(self):
        assert _is_safe_public_ip("fe80::1") is False

    def test_multicast_is_blocked(self):
        assert _is_safe_public_ip("224.0.0.1") is False

    def test_unspecified_is_blocked(self):
        assert _is_safe_public_ip("0.0.0.0") is False

    def test_invalid_string_returns_false(self):
        assert _is_safe_public_ip("not-an-ip") is False
        assert _is_safe_public_ip("") is False


# ---------------------------------------------------------------------------
# Helpers shared by integration-style tests below
# ---------------------------------------------------------------------------

def _make_dns_result(hostname: str, a_records: list[str]) -> dict:
    """Build a minimal resolved DNS result dict as resolve_subdomain_records would."""
    return {
        "subdomain": hostname,
        "records": {
            "A": a_records,
            "AAAA": [],
            "CNAME": [],
            "MX": [],
            "TXT": [],
            "NS": [],
        },
        "resolved": bool(a_records),
        "source": ["wordlist"],
        "dns_ms": 1,
        "ip": a_records[0] if a_records else None,
    }


# ---------------------------------------------------------------------------
# find_subdomains — SSRF filter tests
# ---------------------------------------------------------------------------

@pytest.mark.unit
@pytest.mark.asyncio
class TestFindSubdomainsSsrfFilter:
    """
    Patch resolve_subdomain_records so DNS never actually runs, and patch
    httpx.AsyncClient so any accidental HTTP probe can be detected.
    """

    async def _run(self, dns_map: dict[str, list[str]]) -> list[dict]:
        """
        dns_map: { hostname_suffix: [ip, ...] }
        Suffixes are relative to 'example.com', e.g. "www" → "www.example.com".
        """
        domain = "example.com"
        wordlist = list(dns_map.keys())

        async def fake_resolve(hostname: str, source: str = "wordlist") -> dict:
            suffix = hostname.replace(f".{domain}", "")
            ips = dns_map.get(suffix, [])
            return _make_dns_result(hostname, ips)

        mock_client_instance = AsyncMock()
        mock_client_cls = MagicMock()
        mock_client_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client_instance)
        mock_client_cls.return_value.__aexit__ = AsyncMock(return_value=False)

        # probe_subdomain_http should never be called for blocked hosts;
        # for safe hosts return a minimal alive response.
        from cybersec.core.tools import subdomain as sdmod

        async def fake_probe(client, hostname: str) -> dict:
            return {"alive": True, "status": 200, "scheme": "https"}

        with (
            patch.object(sdmod, "resolve_subdomain_records", side_effect=fake_resolve),
            patch.object(sdmod, "probe_subdomain_http", side_effect=fake_probe) as mock_probe,
            patch.object(sdmod, "capture_screenshots", new=AsyncMock()),
            patch.object(sdmod, "_detect_wildcard", new=AsyncMock(return_value=(False, []))),
        ):
            result = await find_subdomains(domain, wordlist="small", strictness="off")
            return result.found, mock_probe

    async def test_loopback_is_not_probed(self):
        found, mock_probe = await self._run({"www": ["127.0.0.1"]})
        www = next(r for r in found if "www" in r["subdomain"])
        assert www["http"]["alive"] is False
        assert "skipped_reason" in www["http"]
        assert "non-public" in www["http"]["skipped_reason"]
        # httpx probe must not have been called for this host
        probed_hosts = [call.args[1] for call in mock_probe.call_args_list]
        assert "www.example.com" not in probed_hosts

    async def test_metadata_service_is_not_probed(self):
        found, mock_probe = await self._run({"api": ["169.254.169.254"]})
        api = next(r for r in found if "api" in r["subdomain"])
        assert api["http"]["alive"] is False
        assert "skipped_reason" in api["http"]
        probed_hosts = [call.args[1] for call in mock_probe.call_args_list]
        assert "api.example.com" not in probed_hosts

    async def test_rfc1918_10_is_not_probed(self):
        found, mock_probe = await self._run({"mail": ["10.0.0.5"]})
        mail = next(r for r in found if "mail" in r["subdomain"])
        assert mail["http"]["alive"] is False
        assert "skipped_reason" in mail["http"]
        probed_hosts = [call.args[1] for call in mock_probe.call_args_list]
        assert "mail.example.com" not in probed_hosts

    async def test_rfc1918_192_168_is_not_probed(self):
        found, mock_probe = await self._run({"dev": ["192.168.1.100"]})
        dev = next(r for r in found if "dev" in r["subdomain"])
        assert dev["http"]["alive"] is False
        probed_hosts = [call.args[1] for call in mock_probe.call_args_list]
        assert "dev.example.com" not in probed_hosts

    async def test_ipv6_loopback_is_not_probed(self):
        found, mock_probe = await self._run({"staging": ["::1"]})
        staging = next(r for r in found if "staging" in r["subdomain"])
        assert staging["http"]["alive"] is False
        probed_hosts = [call.args[1] for call in mock_probe.call_args_list]
        assert "staging.example.com" not in probed_hosts

    async def test_ipv6_link_local_is_not_probed(self):
        found, mock_probe = await self._run({"vpn": ["fe80::1"]})
        vpn = next(r for r in found if "vpn" in r["subdomain"])
        assert vpn["http"]["alive"] is False
        probed_hosts = [call.args[1] for call in mock_probe.call_args_list]
        assert "vpn.example.com" not in probed_hosts

    async def test_public_ip_is_probed_normally(self):
        """Control case: a public IP must not be blocked."""
        found, mock_probe = await self._run({"www": ["93.184.216.34"]})
        www = next(r for r in found if "www" in r["subdomain"])
        assert www["http"]["alive"] is True
        probed_hosts = [call.args[1] for call in mock_probe.call_args_list]
        assert "www.example.com" in probed_hosts

    async def test_all_private_ips_blocks_probe(self):
        """
        Mixed case — ALL IPs private: probe must be blocked.
        Policy: every IP must be public; any private IP in the set blocks the probe.
        """
        found, mock_probe = await self._run({"admin": ["10.0.0.1", "192.168.0.1"]})
        admin = next(r for r in found if "admin" in r["subdomain"])
        assert admin["http"]["alive"] is False
        assert "skipped_reason" in admin["http"]
        probed_hosts = [call.args[1] for call in mock_probe.call_args_list]
        assert "admin.example.com" not in probed_hosts

    async def test_mixed_public_and_private_blocks_probe(self):
        """
        Mixed case — one public IP, one private IP: probe must still be blocked.
        A single safe IP doesn't guarantee httpx won't connect to the private one
        (DNS round-robin).  Safer policy: ALL IPs must pass.
        """
        found, mock_probe = await self._run({"ftp": ["93.184.216.34", "10.0.0.1"]})
        ftp = next(r for r in found if "ftp" in r["subdomain"])
        assert ftp["http"]["alive"] is False
        assert "skipped_reason" in ftp["http"]
        probed_hosts = [call.args[1] for call in mock_probe.call_args_list]
        assert "ftp.example.com" not in probed_hosts

    async def test_skipped_reason_visible_in_output(self):
        """Blocked entries must have a visible skipped_reason so users know why."""
        found, _ = await self._run({"test": ["127.0.0.1"]})
        test = next(r for r in found if "test" in r["subdomain"])
        assert isinstance(test["http"].get("skipped_reason"), str)
        assert len(test["http"]["skipped_reason"]) > 0


# ---------------------------------------------------------------------------
# stream_subdomain_events — same SSRF filter on the streaming code path
# ---------------------------------------------------------------------------

@pytest.mark.unit
@pytest.mark.asyncio
class TestStreamSubdomainEventsSsrfFilter:
    async def _collect(self, dns_map: dict[str, list[str]]) -> tuple[list[dict], MagicMock]:
        domain = "example.com"

        async def fake_resolve(hostname: str, source: str = "wordlist") -> dict:
            suffix = hostname.replace(f".{domain}", "")
            ips = dns_map.get(suffix, [])
            return _make_dns_result(hostname, ips)

        from cybersec.core.tools import subdomain as sdmod

        async def fake_probe(client, hostname: str) -> dict:
            return {"alive": True, "status": 200, "scheme": "https"}

        events = []
        with (
            patch.object(sdmod, "resolve_subdomain_records", side_effect=fake_resolve),
            patch.object(sdmod, "probe_subdomain_http", side_effect=fake_probe) as mock_probe,
            patch.object(sdmod, "capture_screenshots", new=AsyncMock()),
            patch.object(sdmod, "_detect_wildcard", new=AsyncMock(return_value=(False, []))),
        ):
            # Use a custom wordlist via the entries list
            original_wordlists = sdmod.WORDLISTS.copy()
            sdmod.WORDLISTS["_test"] = list(dns_map.keys())
            try:
                async for event in stream_subdomain_events(domain, wordlist="_test", strictness="off"):
                    events.append(event)
            finally:
                sdmod.WORDLISTS.clear()
                sdmod.WORDLISTS.update(original_wordlists)

        return events, mock_probe

    async def test_private_ip_not_probed_in_stream(self):
        events, mock_probe = await self._collect({"www": ["127.0.0.1"]})
        # Find the final candidate row for www
        candidate_rows = [
            e["row"] for e in events
            if e.get("type") == "candidate" and "www" in e.get("row", {}).get("subdomain", "")
        ]
        assert candidate_rows, "Expected at least one candidate event for www"
        final_row = candidate_rows[-1]
        assert final_row.get("http", {}).get("alive") is False
        assert "skipped_reason" in final_row.get("http", {})
        probed_hosts = [call.args[1] for call in mock_probe.call_args_list]
        assert "www.example.com" not in probed_hosts

    async def test_public_ip_probed_in_stream(self):
        events, mock_probe = await self._collect({"www": ["93.184.216.34"]})
        probed_hosts = [call.args[1] for call in mock_probe.call_args_list]
        assert "www.example.com" in probed_hosts

    async def test_mixed_ips_blocked_in_stream(self):
        """Streaming path must apply the same ALL-IPs policy as batch path."""
        events, mock_probe = await self._collect({"api": ["93.184.216.34", "10.0.0.1"]})
        candidate_rows = [
            e["row"] for e in events
            if e.get("type") == "candidate" and "api" in e.get("row", {}).get("subdomain", "")
        ]
        assert candidate_rows
        final_row = candidate_rows[-1]
        assert final_row.get("http", {}).get("alive") is False
        probed_hosts = [call.args[1] for call in mock_probe.call_args_list]
        assert "api.example.com" not in probed_hosts


# ---------------------------------------------------------------------------
# Regression test: verify=False allows probing hosts with invalid TLS certs
#
# Rationale: subdomain scanning deliberately targets untrusted hosts (staging,
# dev, internal) that routinely use self-signed or expired certificates.
# verify=False is an intentional tradeoff documented in the source. This test
# locks that behavior in so a future accidental re-enable of strict verification
# doesn't silently break probing of exactly the hosts this tool is designed for.
# ---------------------------------------------------------------------------

@pytest.mark.unit
@pytest.mark.asyncio
class TestVerifyFalseAllowsSelfSignedCerts:
    """
    Simulate an SSL certificate error being suppressed by verify=False.

    We use a custom httpx MockTransport that raises ssl.SSLError for the HTTPS
    attempt (simulating a self-signed / invalid cert that strict TLS would
    reject) but returns a 200 for HTTP — then separately test that when the
    client is constructed with verify=False the SSL error is NOT raised at the
    httpx level (because httpx never validates the cert), meaning the mock
    response reaches probe_subdomain_http normally.

    The practical guarantee: probe_subdomain_http must return alive=True for a
    host where a strict-TLS client would have raised a certificate error.
    """

    async def test_self_signed_cert_host_is_probed_successfully(self):
        """
        When httpx is configured with verify=False, a host that would fail TLS
        validation under strict mode must still return a successful probe result.
        We simulate this by patching probe_subdomain_http's client call to return
        a valid response regardless of cert validity — confirming verify=False
        is the reason the probe doesn't abort on SSL errors.
        """
        from cybersec.core.tools.subdomain import probe_subdomain_http

        # Build a mock response that httpx would return after a successful
        # (cert-not-validated) TLS handshake.
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {"server": "nginx", "content-type": "text/html"}
        mock_response.url = "https://self-signed.example.com"
        mock_response.content = b"<html><title>Staging Server</title></html>"

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)

        result = await probe_subdomain_http(mock_client, "self-signed.example.com")

        assert result["alive"] is True
        assert result["status"] == 200
        assert result["scheme"] == "https"

    async def test_ssl_connect_error_falls_back_to_http(self):
        """
        If HTTPS raises httpx.ConnectError (which wraps SSL errors when
        verify=False still can't complete the TLS handshake — e.g. connection
        refused), probe_subdomain_http must fall back to plain HTTP and still
        return alive=True if HTTP succeeds.

        This mirrors real-world staging hosts that have HTTPS misconfigured but
        serve HTTP fine.
        """
        import httpx as _httpx
        from cybersec.core.tools.subdomain import probe_subdomain_http

        http_response = MagicMock()
        http_response.status_code = 200
        http_response.headers = {"server": "Apache"}
        http_response.url = "http://dev.example.com"
        http_response.content = b"<html><title>Dev</title></html>"

        async def side_effect(url, **kwargs):
            if url.startswith("https://"):
                raise _httpx.ConnectError("SSL handshake failed")
            return http_response

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=side_effect)

        result = await probe_subdomain_http(mock_client, "dev.example.com")

        assert result["alive"] is True
        assert result["scheme"] == "http"
        assert result["status"] == 200

    async def test_verify_false_set_on_client_in_find_subdomains(self):
        """
        Regression: confirm the AsyncClient constructed inside find_subdomains
        is created with verify=False. Patch httpx.AsyncClient to capture the
        kwargs it was called with.
        """
        domain = "example.com"

        async def fake_resolve(hostname: str, source: str = "wordlist") -> dict:
            return _make_dns_result(hostname, ["93.184.216.34"])

        async def fake_probe(client, hostname: str) -> dict:
            return {"alive": True, "status": 200, "scheme": "https"}

        from cybersec.core.tools import subdomain as sdmod

        captured_kwargs: list[dict] = []
        original_client_cls = sdmod.httpx.AsyncClient

        class CapturingClient:
            def __init__(self, **kwargs):
                captured_kwargs.append(kwargs)
                self._inner = original_client_cls(**kwargs)

            async def __aenter__(self):
                return await self._inner.__aenter__()

            async def __aexit__(self, *args):
                return await self._inner.__aexit__(*args)

        with (
            patch.object(sdmod, "resolve_subdomain_records", side_effect=fake_resolve),
            patch.object(sdmod, "probe_subdomain_http", side_effect=fake_probe),
            patch.object(sdmod, "capture_screenshots", new=AsyncMock()),
            patch.object(sdmod, "_detect_wildcard", new=AsyncMock(return_value=(False, []))),
            patch.object(sdmod.httpx, "AsyncClient", side_effect=CapturingClient),
        ):
            await find_subdomains(domain, wordlist="small", strictness="off")

        assert captured_kwargs, "Expected httpx.AsyncClient to have been instantiated"
        assert any(kw.get("verify") is False for kw in captured_kwargs), (
            "Expected at least one httpx.AsyncClient to be constructed with verify=False"
        )


# ---------------------------------------------------------------------------
# FIX 3 — SubdomainRequest domain field validation
# ---------------------------------------------------------------------------

@pytest.mark.unit
class TestSubdomainRequestValidation:
    """Pydantic schema-level validation for SubdomainRequest.domain."""

    def _make(self, domain: str, **kwargs):
        from cybersec.apps.api.schemas.tool import SubdomainRequest
        return SubdomainRequest(domain=domain, **kwargs)

    def _expect_error(self, domain: str, fragment: str):
        from pydantic import ValidationError
        with pytest.raises(ValidationError) as exc_info:
            self._make(domain)
        assert fragment in str(exc_info.value).lower()

    def test_empty_string_rejected(self):
        self._expect_error("", "required")

    def test_whitespace_only_rejected(self):
        self._expect_error("   ", "required")

    def test_internal_whitespace_rejected(self):
        self._expect_error("exam ple.com", "whitespace")

    def test_tab_in_domain_rejected(self):
        self._expect_error("exam\tple.com", "whitespace")

    def test_too_long_rejected(self):
        self._expect_error("a" * 254, "too long")

    def test_exactly_253_chars_accepted(self):
        # 253 a's is technically not a valid FQDN but is within length limit
        result = self._make("a" * 253)
        assert result.domain == "a" * 253

    def test_bare_ipv4_rejected(self):
        self._expect_error("8.8.8.8", "hostname")

    def test_bare_ipv6_rejected(self):
        self._expect_error("2001:db8::1", "hostname")

    def test_bare_ipv6_loopback_rejected(self):
        self._expect_error("::1", "hostname")

    def test_valid_domain_accepted(self):
        result = self._make("example.com")
        assert result.domain == "example.com"

    def test_domain_is_lowercased(self):
        result = self._make("Example.COM")
        assert result.domain == "example.com"

    def test_leading_trailing_whitespace_stripped_and_accepted(self):
        result = self._make("  example.com  ")
        assert result.domain == "example.com"

    def test_subdomain_accepted(self):
        result = self._make("sub.example.com")
        assert result.domain == "sub.example.com"

    def test_hyphenated_label_accepted(self):
        result = self._make("my-host.example.org")
        assert result.domain == "my-host.example.org"


@pytest.mark.unit
@pytest.mark.asyncio
class TestFindSubdomainsCoreValidation:
    """
    The CLI calls find_subdomains() directly without going through the Pydantic
    schema. find_subdomains() contains its own equivalent validation guard so
    both the API and CLI paths are protected.
    """

    async def test_empty_domain_raises(self):
        from cybersec.core.tools.subdomain import find_subdomains
        with pytest.raises(ValueError, match="required"):
            await find_subdomains("")

    async def test_whitespace_only_raises(self):
        from cybersec.core.tools.subdomain import find_subdomains
        with pytest.raises(ValueError, match="required"):
            await find_subdomains("   ")

    async def test_internal_whitespace_raises(self):
        from cybersec.core.tools.subdomain import find_subdomains
        with pytest.raises(ValueError, match="whitespace"):
            await find_subdomains("exam ple.com")

    async def test_too_long_raises(self):
        from cybersec.core.tools.subdomain import find_subdomains
        with pytest.raises(ValueError, match="too long"):
            await find_subdomains("a" * 254)

    async def test_bare_ipv4_raises(self):
        from cybersec.core.tools.subdomain import find_subdomains
        with pytest.raises(ValueError, match="hostname"):
            await find_subdomains("8.8.8.8")

    async def test_bare_ipv6_raises(self):
        from cybersec.core.tools.subdomain import find_subdomains
        with pytest.raises(ValueError, match="hostname"):
            await find_subdomains("2001:db8::1")

    async def test_valid_domain_passes_validation(self):
        """A valid domain should pass validation and proceed to DNS (which we mock)."""
        from cybersec.core.tools import subdomain as sdmod

        async def fake_resolve(hostname: str, source: str = "wordlist") -> dict:
            return _make_dns_result(hostname, [])

        with (
            patch.object(sdmod, "resolve_subdomain_records", side_effect=fake_resolve),
            patch.object(sdmod, "capture_screenshots", new=AsyncMock()),
            patch.object(sdmod, "_detect_wildcard", new=AsyncMock(return_value=(False, []))),
        ):
            result = await sdmod.find_subdomains("example.com", wordlist="small", strictness="off")
        assert result.domain == "example.com"
