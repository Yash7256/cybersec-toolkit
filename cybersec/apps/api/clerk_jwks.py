"""
JWKS cache for Clerk RS256 JWT validation.

Fetches Clerk's public RSA keys from the JWKS endpoint and caches them
in-memory with a 1-hour TTL. Avoids a network round-trip on every
authenticated request.

Requirements: 2.1, 2.2, 2.3, 2.4, 2.5, 2.6, 2.7, 2.8, 10.1, 10.2, 10.3
"""

import asyncio
import json
import logging
import time
from typing import Any

import httpx
import jwt

from cybersec.config.settings import settings

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Module-level cache state (shared across the process)
# ---------------------------------------------------------------------------

_jwks_cache: dict[str, Any] = {}
_cache_expiry: float = 0.0


class ClerkJWKSUnavailable(Exception):
    """Raised when the Clerk JWKS endpoint is unreachable after all retries."""


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

_MAX_RETRIES = 3
_RETRY_DELAY = 1.0  # seconds between attempts


async def refresh_jwks() -> None:
    """Fetch the Clerk JWKS endpoint and populate ``_jwks_cache``.

    Retries up to 3 times with a 1-second delay between attempts.

    On success:
    - ``_jwks_cache`` is populated with ``kid -> RSA public key`` entries.
    - ``_cache_expiry`` is set to ``now + 3600``.

    On failure (all retries exhausted):
    - If a stale cache already exists it is preserved so callers can
      continue using stale keys (Req 10.2).
    - Raises ``ClerkJWKSUnavailable``.
    """
    global _jwks_cache, _cache_expiry

    last_exc: Exception | None = None

    for attempt in range(1, _MAX_RETRIES + 1):
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                response = await client.get(settings.CLERK_JWKS_URL)
                response.raise_for_status()

            keys = response.json()["keys"]
            new_cache: dict[str, Any] = {}
            for key in keys:
                rsa_key = jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(key))
                new_cache[key["kid"]] = rsa_key

            # Atomically replace the cache only on full success
            _jwks_cache = new_cache
            _cache_expiry = time.time() + 3600
            logger.debug(
                "JWKS cache refreshed: %d key(s) loaded, expiry in 3600s.",
                len(_jwks_cache),
            )
            return

        except (httpx.RequestError, httpx.HTTPStatusError, Exception) as exc:
            last_exc = exc
            exc_detail = repr(exc) if not str(exc) else str(exc)
            if attempt < _MAX_RETRIES:
                logger.warning(
                    "JWKS fetch attempt %d/%d failed (%s). Retrying in %.1fs…",
                    attempt,
                    _MAX_RETRIES,
                    exc_detail,
                    _RETRY_DELAY,
                )
                await asyncio.sleep(_RETRY_DELAY)
            else:
                logger.error(
                    "All %d JWKS fetch attempts failed. Last error: %s",
                    _MAX_RETRIES,
                    exc_detail,
                )

    # All retries exhausted — preserve stale cache if it exists (Req 10.2)
    # so get_clerk_public_key can still serve stale keys.
    raise ClerkJWKSUnavailable(
        f"Clerk JWKS endpoint unreachable after {_MAX_RETRIES} attempts: {last_exc}"
    )


async def get_clerk_public_key(kid: str) -> Any:
    """Return the RSA public key for ``kid`` from the local cache.

    Refreshes the cache when it has expired or is empty (Req 2.3, 2.4).
    Raises ``KeyError`` immediately if ``kid`` is absent from a valid,
    non-expired cache (Req 2.5).
    Raises ``ClerkJWKSUnavailable`` (propagated from ``refresh_jwks``) when
    the JWKS endpoint cannot be reached and no cached keys exist (Req 10.1).

    Args:
        kid: The key identifier from the JWT header.

    Returns:
        An RSA public key object suitable for ``jwt.decode``.

    Raises:
        KeyError: ``kid`` is not found in the cache.
        ClerkJWKSUnavailable: JWKS endpoint is unreachable and cache is empty.
    """
    # Refresh if the cache is stale or empty (Req 2.4)
    if time.time() >= _cache_expiry or not _jwks_cache:
        await refresh_jwks()

    if kid not in _jwks_cache:
        raise KeyError(f"Unknown signing key kid={kid!r}")

    return _jwks_cache[kid]
