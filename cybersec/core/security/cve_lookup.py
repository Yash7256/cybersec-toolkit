"""
Enhanced CVE lookup with NVD API 2.0 integration.

Caching hierarchy:
  1. In-memory dict (fastest, process-local)
  2. Redis (shared across workers, with TTL)
  3. NVD API (slow, network call)

Deduplication: concurrent lookups for the same (service, version)
share a single in-flight NVD request.
"""
import asyncio
import json
import logging
from dataclasses import dataclass
from typing import Optional, List

from sqlalchemy.ext.asyncio import AsyncSession

from cybersec.core.security.nvd_client import EnhancedCVELookup
from cybersec.core.scanner.analysis.service_detect import ServiceDetectionResult
from cybersec.core.redis_client import get_shared_breaker, RedisKeys

logger = logging.getLogger(__name__)

CVE_CACHE_TTL = 3600           # 1 hour — for confirmed non-empty results
CVE_CACHE_TTL_EMPTY = 300      # 5 minutes — for empty/failed results
CVE_CACHE_MAX_LOCAL = 500      # per-process in-memory cap


@dataclass
class CVEEntry:
    id: str
    cvss_score: float
    severity: str
    description: str
    confidence: float = 1.0


def _to_dict(cve: CVEEntry) -> dict:
    return {"id": cve.id, "cvss_score": cve.cvss_score, "severity": cve.severity,
            "description": cve.description, "confidence": cve.confidence}


def _from_dict(d: dict) -> CVEEntry:
    return CVEEntry(id=d["id"], cvss_score=d.get("cvss_score", 0.0),
                    severity=d.get("severity", "UNKNOWN"),
                    description=d.get("description", ""),
                    confidence=d.get("confidence", 1.0))


class CVELookup:
    """CVE lookup with multi-tier cache (local → Redis → NVD)."""

    _local: dict[tuple[str, str | None], List[CVEEntry]] = {}
    _pending: dict[tuple[str, str | None], asyncio.Future] = {}

    def __init__(self, db_session: Optional[AsyncSession] = None):
        self.enhanced_lookup = EnhancedCVELookup(db_session)

    async def _get_redis(self):
        from cybersec.core.redis_client import get_shared_redis_client
        return get_shared_redis_client()

    async def lookup(self, service: str, version: Optional[str] = None) -> List[CVEEntry]:
        """Lookup CVEs for (service, version).

        1. Check in-memory cache (instant)
        2. Check Redis cache (fast, shared across workers)
        3. Deduplicate in-flight NVD requests
        4. Fetch from NVD API, cache in Redis + local
        """
        key = (service, version)

        # ── Tier 1: in-memory ────────────────────────────────────────
        cached = self._local.get(key)
        if cached is not None:
            return cached

        # ── Tier 2: Redis (shared across workers) ────────────────────
        breaker = get_shared_breaker()
        if not await breaker.is_open():
            r = await self._get_redis()
            if r is not None:
                try:
                    raw = await r.get(RedisKeys.cve(service, version))
                    await breaker.record_success()
                    if raw is not None:
                        entries = [_from_dict(d) for d in json.loads(raw)]
                        if len(self._local) < CVE_CACHE_MAX_LOCAL:
                            self._local[key] = entries
                        return entries
                except Exception as e:
                    await breaker.record_failure()
                    logger.debug("Redis CVE cache read failed: %s", e)

        # ── Tier 3: deduplicate in-flight NVD requests ───────────────
        pending = self._pending.get(key)
        if pending is not None:
            return await pending

        # ── Tier 4: fetch from NVD ───────────────────────────────────
        fut = asyncio.ensure_future(self._fetch_and_cache(key, service, version))
        self._pending[key] = fut
        try:
            return await fut
        finally:
            self._pending.pop(key, None)

    async def _fetch_and_cache(self, key: tuple, service: str, version: Optional[str]) -> List[CVEEntry]:
        """Fetch from NVD, store in both caches."""
        lookup_failed = False
        try:
            cve_dicts = await self.enhanced_lookup.lookup(service, version)
        except Exception as e:
            logger.error("NVD lookup failed for %s/%s: %s", service, version, e)
            cve_dicts = []
            lookup_failed = True

        entries = [CVEEntry(
            id=c.get("id", ""),
            cvss_score=c.get("cvss_score", 0.0),
            severity=c.get("severity", "UNKNOWN"),
            description=c.get("description", ""),
            confidence=c.get("confidence", 0.9),
        ) for c in cve_dicts]

        # Only populate the local cache on a real (non-failed) result.
        # A failed lookup should not poison the in-memory cache either —
        # the next call should retry NVD, not silently reuse a failure.
        if not lookup_failed and len(self._local) < CVE_CACHE_MAX_LOCAL:
            self._local[key] = entries

        # Populate Redis cache (best-effort)
        breaker = get_shared_breaker()
        if not await breaker.is_open():
            r = await self._get_redis()
            if r is not None:
                try:
                    raw = json.dumps([_to_dict(e) for e in entries])
                    ttl = CVE_CACHE_TTL_EMPTY if (lookup_failed or not entries) else CVE_CACHE_TTL
                    await r.setex(RedisKeys.cve(service, version), ttl, raw)
                    await breaker.record_success()
                except Exception as e:
                    await breaker.record_failure()
                    logger.debug("Redis CVE cache write failed: %s", e)

        return entries

    async def lookup_for_service_result(self, service_result) -> List[dict]:
        """Convenience: lookup CVEs from a ServiceDetectionResult."""
        return [_to_dict(e) for e in await self.lookup(
            service_result.service_name,
            service_result.service_version,
        )]
