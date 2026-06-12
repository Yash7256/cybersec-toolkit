"""Security tests validating that oversized, deeply nested, and unicode-heavy inputs
are handled safely (rejected or returned within time bounds) by whois_lookup()."""
import asyncio
import time
import pytest

from cybersec.core.tools import whois


# Maximum time any single call is permitted to take regardless of input size.
LONG_INPUT_TIMEOUT_S = 5.0


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(params=[
    "a" * 10_000,
    "a" * 50_000,
    "a" * 100_000,
])
def very_long_string(request):
    """Inputs far beyond the 253-character domain limit."""
    return request.param


@pytest.fixture(params=[
    "a" * 253 + ".com",          # 253-char label + TLD
    "a" * 500 + ".com",
    "a" * 10_000 + ".com",
])
def long_invalid_domain(request):
    """Valid-looking but over-long domain names."""
    return request.param


@pytest.fixture(params=[
    ".".join(["sub"] * 50) + ".example.com",   # 50 sub-labels
    ".".join(["sub"] * 100) + ".example.com",
    ".".join(["sub"] * 200) + ".example.com",
])
def deeply_nested_domain(request):
    """Deeply nested sub-domain chains."""
    return request.param


@pytest.fixture(params=[
    "😀😁😂🤣😃😄😅😆😉😊",
    "héllo.com",
    "こんにちは.com",
    "пример.рф",
    "مثال.إختبار",
    "𝓮𝔁𝓪𝓶𝓹𝓵𝓮.𝓬𝓸𝓶",
])
def unicode_heavy_input(request):
    """Emoji sequences and mixed Unicode input."""
    return request.param


@pytest.fixture(params=[
    "xn--nxasmq6b.com",          # Legitimate punycode
    "xn--" + "a" * 60 + ".com",  # Over-long punycode label
    "xn--" + "-" * 200 + ".com", # Invalid punycode padding
])
def punycode_like_input(request):
    """Punycode-style inputs including malformed ones."""
    return request.param


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _assert_long_input_safe(result, input_value: str):
    """Common assertions for any oversized or malformed input result."""
    assert isinstance(result.name_servers, list), "name_servers must always be a list"
    assert isinstance(result.status, list), "status must always be a list"
    assert isinstance(result.risk_indicators, list), "risk_indicators must always be a list"
    assert result.cached is False, "oversized-input results must never come from cache"

    # Either properly rejected or handled without schema corruption
    if result.domain is None:
        assert result.error is not None, (
            f"Rejected input must carry an error message — got None for {input_value[:80]!r}"
        )


# ---------------------------------------------------------------------------
# Very long strings
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_very_long_strings_rejected_without_hang(very_long_string):
    """Strings far beyond domain length limits must be rejected promptly."""
    start = time.perf_counter()
    result = await whois.whois_lookup(very_long_string)
    duration = time.perf_counter() - start

    assert duration < LONG_INPUT_TIMEOUT_S, (
        f"whois_lookup hung on input of length {len(very_long_string)}: "
        f"took {duration:.2f}s"
    )
    assert result.domain is None
    assert result.error is not None
    _assert_long_input_safe(result, very_long_string)


# ---------------------------------------------------------------------------
# Long invalid domains
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_long_invalid_domains_rejected_promptly(long_invalid_domain):
    """Over-long domain names must be caught by length validation immediately."""
    start = time.perf_counter()
    result = await whois.whois_lookup(long_invalid_domain)
    duration = time.perf_counter() - start

    assert duration < LONG_INPUT_TIMEOUT_S
    assert result.domain is None
    assert result.error is not None
    assert "long" in result.error.lower() or "invalid" in result.error.lower()
    _assert_long_input_safe(result, long_invalid_domain)


# ---------------------------------------------------------------------------
# Deeply nested sub-domains
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_deeply_nested_domains_handled_safely(deeply_nested_domain):
    """Sub-domain chains that exceed DNS nesting limits must not crash or hang."""
    start = time.perf_counter()
    result = await whois.whois_lookup(deeply_nested_domain)
    duration = time.perf_counter() - start

    assert duration < LONG_INPUT_TIMEOUT_S, (
        f"Lookup hung on deeply-nested domain ({len(deeply_nested_domain)} chars)"
    )
    _assert_long_input_safe(result, deeply_nested_domain)


# ---------------------------------------------------------------------------
# Unicode-heavy inputs
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_unicode_heavy_inputs_rejected_safely(unicode_heavy_input):
    """Emoji, CJK, and multi-script inputs are rejected by the ASCII-only validator."""
    start = time.perf_counter()
    result = await whois.whois_lookup(unicode_heavy_input)
    duration = time.perf_counter() - start

    assert duration < LONG_INPUT_TIMEOUT_S
    # Non-ASCII characters must be caught by the strict char regex
    assert result.domain is None
    assert result.error is not None
    _assert_long_input_safe(result, unicode_heavy_input)


# ---------------------------------------------------------------------------
# Punycode-like inputs
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_punycode_like_inputs_handled_safely(punycode_like_input):
    """Punycode-looking inputs (valid and malformed) must not crash the validator."""
    start = time.perf_counter()
    result = await whois.whois_lookup(punycode_like_input)
    duration = time.perf_counter() - start

    assert duration < LONG_INPUT_TIMEOUT_S
    # Schema must remain intact regardless of acceptance or rejection
    _assert_long_input_safe(result, punycode_like_input)


# ---------------------------------------------------------------------------
# Repeated character flood inputs
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("flood_input,label", [
    ("." * 1000, "dots"),
    ("-" * 1000, "hyphens"),
    ("a-" * 500, "alternating_ah"),
    ("a." * 500, "alternating_adot"),
])
@pytest.mark.asyncio
async def test_repeated_character_floods_rejected(flood_input, label):
    """Repeated-character flood inputs must be validated and rejected promptly."""
    start = time.perf_counter()
    result = await whois.whois_lookup(flood_input)
    duration = time.perf_counter() - start

    assert duration < LONG_INPUT_TIMEOUT_S, (
        f"whois_lookup hung on {label} flood ({len(flood_input)} chars)"
    )
    _assert_long_input_safe(result, flood_input)


# ---------------------------------------------------------------------------
# Concurrent oversized inputs (no deadlock or resource exhaustion)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_concurrent_oversized_inputs_do_not_deadlock():
    """Multiple oversized inputs submitted concurrently must all complete promptly."""
    payloads = [
        "a" * 10_000,
        "b" * 50_000,
        ".".join(["sub"] * 100) + ".example.com",
        "😀" * 500,
        "." * 1000,
    ]

    start = time.perf_counter()
    results = await asyncio.gather(*[whois.whois_lookup(p) for p in payloads])
    duration = time.perf_counter() - start

    assert duration < LONG_INPUT_TIMEOUT_S * 2, (
        f"Concurrent oversized inputs took {duration:.2f}s — possible deadlock"
    )
    assert len(results) == len(payloads)
    for result, payload in zip(results, payloads):
        _assert_long_input_safe(result, payload)
