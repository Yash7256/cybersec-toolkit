"""
NVD API 2.0 Client with rate limiting and caching.
"""
import asyncio
import json
import logging
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any
from urllib.parse import quote

import httpx
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, text

from cybersec.config.settings import settings
from cybersec.database.models import NVDCveCache

logger = logging.getLogger(__name__)


@dataclass
class CVEResult:
    """CVE result from NVD API 2.0."""
    cve_id: str
    description: str
    published: str
    last_modified: str
    vuln_status: str
    cvss_v3_score: Optional[float]
    cvss_v3_severity: Optional[str]
    cvss_v2_score: Optional[float]
    cvss_v3_vector: Optional[str]
    references: List[str]
    source: str = "NVD"


class NVDClient:
    """Async NVD API 2.0 client with rate limiting and caching."""
    
    def __init__(
        self,
        api_key: Optional[str] = None,
        rate_limit_delay: float = 6.0,
        timeout: int = 30
    ):
        self.api_key = api_key or settings.NVD_API_KEY
        self.base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.timeout = timeout
        
        # Auto-adjust rate limit based on API key presence
        if self.api_key:
            self.rate_limit_delay = 0.6  # 50 requests per 30 seconds
        else:
            self.rate_limit_delay = rate_limit_delay  # Default 6 seconds (5 per 30 sec)
        
        self._rate_limit_lock = asyncio.Lock()
        self._last_request_time = 0.0
        
        logger.info(f"NVD Client initialized - API Key: {'Yes' if self.api_key else 'No'}, "
                   f"Rate Limit: {self.rate_limit_delay}s")
    
    async def _enforce_rate_limit(self):
        """Enforce NVD API rate limiting."""
        async with self._rate_limit_lock:
            current_time = asyncio.get_event_loop().time()
            time_since_last = current_time - self._last_request_time
            
            if time_since_last < self.rate_limit_delay:
                sleep_time = self.rate_limit_delay - time_since_last
                logger.debug(f"Rate limiting: sleeping {sleep_time:.2f}s")
                await asyncio.sleep(sleep_time)
            
            self._last_request_time = asyncio.get_event_loop().time()
    
    def _parse_cve_entry(self, cve_data: Dict[str, Any]) -> CVEResult:
        """Parse a single CVE entry from NVD API response."""
        cve = cve_data.get("cve", {})
        
        # Basic fields
        cve_id = cve.get("id", "")
        published = cve.get("published", "")
        last_modified = cve.get("lastModified", "")
        vuln_status = cve.get("vulnStatus", "")
        
        # Description (English only)
        description = ""
        for desc in cve.get("descriptions", []):
            if desc.get("lang") == "en":
                description = desc.get("value", "")
                break
        
        # CVSS metrics
        cvss_v3_score = None
        cvss_v3_severity = None
        cvss_v3_vector = None
        cvss_v2_score = None
        
        metrics = cve.get("metrics", {})
        
        # CVSS v3.1
        cvss_v31_metrics = metrics.get("cvssMetricV31", [])
        if cvss_v31_metrics:
            cvss_data = cvss_v31_metrics[0].get("cvssData", {})
            cvss_v3_score = cvss_data.get("baseScore")
            cvss_v3_severity = cvss_data.get("baseSeverity")
            cvss_v3_vector = cvss_data.get("vectorString")
        
        # CVSS v2 (fallback)
        if cvss_v3_score is None:
            cvss_v2_metrics = metrics.get("cvssMetricV2", [])
            if cvss_v2_metrics:
                cvss_data = cvss_v2_metrics[0].get("cvssData", {})
                cvss_v2_score = cvss_data.get("baseScore")
        
        # References (URLs only)
        references = []
        for ref in cve.get("references", []):
            url = ref.get("url", "")
            if url:
                references.append(url)
        
        return CVEResult(
            cve_id=cve_id,
            description=description,
            published=published,
            last_modified=last_modified,
            vuln_status=vuln_status,
            cvss_v3_score=cvss_v3_score,
            cvss_v3_severity=cvss_v3_severity,
            cvss_v2_score=cvss_v2_score,
            cvss_v3_vector=cvss_v3_vector,
            references=references,
            source="NVD"
        )
    
    async def _make_request(self, url: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """Make a rate-limited request to NVD API."""
        await self._enforce_rate_limit()
        
        headers = {}
        if self.api_key:
            headers["apiKey"] = self.api_key
        
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.get(url, params=params, headers=headers)
                
                # Handle specific HTTP errors
                if response.status_code == 403:
                    logger.error("NVD rate limit hit (403)")
                    raise Exception("NVD rate limit exceeded")
                elif response.status_code == 404:
                    logger.debug(f"NVD 404 for URL: {url}")
                    return {"vulnerabilities": []}
                elif response.status_code >= 500:
                    logger.warning(f"NVD server error {response.status_code}")
                    return {"vulnerabilities": []}
                
                response.raise_for_status()
                return response.json()
        
        except json.JSONDecodeError as e:
            logger.error(f"NVD JSON decode failed: {e}")
            return {"vulnerabilities": []}
        except Exception as e:
            logger.error(f"NVD request failed: {e}")
            return {"vulnerabilities": []}
    
    async def get_cve_by_id(self, cve_id: str) -> Optional[CVEResult]:
        """Get a specific CVE by ID."""
        params = {"cveId": cve_id}
        url = f"{self.base_url}"
        
        response_data = await self._make_request(url, params)
        vulnerabilities = response_data.get("vulnerabilities", [])
        
        if vulnerabilities:
            return self._parse_cve_entry(vulnerabilities[0])
        return None
    
    async def search_cves_by_keyword(self, keyword: str, max_results: int = 20) -> List[CVEResult]:
        """Search CVEs by keyword."""
        params = {
            "keywordSearch": keyword,
            "resultsPerPage": min(max_results, 200)  # NVD max is 200
        }
        url = f"{self.base_url}"
        
        response_data = await self._make_request(url, params)
        vulnerabilities = response_data.get("vulnerabilities", [])
        
        results = []
        for vuln in vulnerabilities[:max_results]:
            try:
                cve_result = self._parse_cve_entry(vuln)
                results.append(cve_result)
            except Exception as e:
                logger.error(f"Failed to parse CVE entry: {e}")
                continue
        
        return results
    
    async def search_cves_by_cpename(self, cpe_name: str, max_results: int = 20) -> List[CVEResult]:
        """Search CVEs by CPE name."""
        params = {
            "cpeName": cpe_name,
            "resultsPerPage": min(max_results, 200)  # NVD max is 200
        }
        url = f"{self.base_url}"
        
        response_data = await self._make_request(url, params)
        vulnerabilities = response_data.get("vulnerabilities", [])
        
        results = []
        for vuln in vulnerabilities[:max_results]:
            try:
                cve_result = self._parse_cve_entry(vuln)
                results.append(cve_result)
            except Exception as e:
                logger.error(f"Failed to parse CVE entry: {e}")
                continue
        
        return results
    
    async def lookup_cves_for_service(
        self,
        service_name: str,
        service_version: str = "",
        db_session: Optional[AsyncSession] = None
    ) -> List[CVEResult]:
        """
        Look up CVEs for a detected service.
        
        This method combines keyword search with filtering and caching.
        """
        # Skip unknown and overly generic services
        if not service_name or service_name.lower() in ["unknown", "", "http", "http-alt", "https"]:
            # For generic HTTP services, only do CVE lookup if we have a version
            if service_name.lower() in ["http", "http-alt", "https"] and not service_version:
                return []
            elif service_name.lower() in ["unknown", ""]:
                return []
        
        # Build search keyword
        keyword = f"{service_name} {service_version}".strip()
        
        # Search NVD
        cves = await self.search_cves_by_keyword(keyword, max_results=50)
        
        # Filter by CVSS score and recency
        min_score = settings.NVD_MIN_CVSS_SCORE
        min_date = datetime.now() - timedelta(days=365 * 10)  # 10 years ago
        filtered_cves = []
        for cve in cves:
            score = cve.cvss_v3_score or cve.cvss_v2_score or 0.0
            if score >= min_score:
                # Filter out very old CVEs (unless they have very high CVSS)
                try:
                    published_date = datetime.fromisoformat(cve.published.replace('Z', '+00:00'))
                    if published_date >= min_date or score >= 9.0:  # Keep critical CVEs regardless of age
                        filtered_cves.append(cve)
                except (ValueError, AttributeError):
                    # If date parsing fails, include if high score
                    if score >= 7.0:
                        filtered_cves.append(cve)
        
        # Sort by CVSS v3 score (highest first), fallback to v2
        filtered_cves.sort(
            key=lambda x: (x.cvss_v3_score or x.cvss_v2_score or 0.0),
            reverse=True
        )
        
        # Cap results
        max_results = settings.NVD_MAX_RESULTS_PER_SERVICE
        return filtered_cves[:max_results]


class NVDCacheManager:
    """Manages NVD cache using PostgreSQL."""
    
    def __init__(self, db_session: AsyncSession):
        self.db_session = db_session
    
    async def get_cached_cve(self, cve_id: str) -> Optional[CVEResult]:
        """Get cached CVE if not expired."""
        try:
            result = await self.db_session.execute(
                select(NVDCveCache).where(
                    NVDCveCache.cve_id == cve_id,
                    NVDCveCache.expires_at > datetime.utcnow()
                )
            )
            cache_entry = result.scalar_one_or_none()
            
            if cache_entry:
                # Convert JSON back to CVEResult
                data = cache_entry.data
                return CVEResult(**data)
            
            return None
        except Exception as e:
            logger.error(f"Cache get failed for {cve_id}: {e}")
            return None
    
    async def cache_cve(self, cve_result: CVEResult):
        """Cache a CVE result."""
        try:
            # Calculate expiry time
            ttl_hours = settings.NVD_CACHE_TTL_HOURS
            expires_at = datetime.utcnow() + timedelta(hours=ttl_hours)
            
            # Convert to dict for JSON storage
            data = {
                "cve_id": cve_result.cve_id,
                "description": cve_result.description,
                "published": cve_result.published,
                "last_modified": cve_result.last_modified,
                "vuln_status": cve_result.vuln_status,
                "cvss_v3_score": cve_result.cvss_v3_score,
                "cvss_v3_severity": cve_result.cvss_v3_severity,
                "cvss_v2_score": cve_result.cvss_v2_score,
                "cvss_v3_vector": cve_result.cvss_v3_vector,
                "references": cve_result.references,
                "source": cve_result.source
            }
            
            # Upsert cache entry
            cache_entry = NVDCveCache(
                cve_id=cve_result.cve_id,
                data=data,
                fetched_at=datetime.utcnow(),
                expires_at=expires_at
            )
            
            await self.db_session.merge(cache_entry)
            await self.db_session.commit()
            
        except Exception as e:
            logger.error(f"Cache set failed for {cve_result.cve_id}: {e}")
            await self.db_session.rollback()


class EnhancedCVELookup:
    """Enhanced CVE lookup with NVD API 2.0 integration."""
    
    def __init__(self, db_session: Optional[AsyncSession] = None):
        self.nvd_client = NVDClient()
        self.db_session = db_session
        self.cache_manager = NVDCveManager(db_session) if db_session else None
    
    async def lookup(
        self,
        service: str,
        version: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Enhanced CVE lookup with NVD API integration.
        
        Returns list of CVE dictionaries for compatibility with existing code.
        """
        try:
            # Use NVD client for service lookup
            cve_results = await self.nvd_client.lookup_cves_for_service(
                service, version or "", self.db_session
            )
            
            # Convert CVEResult objects to dictionaries for compatibility
            cve_dicts = []
            for cve in cve_results:
                cve_dict = {
                    "id": cve.cve_id,
                    "cvss_score": cve.cvss_v3_score or cve.cvss_v2_score or 0.0,
                    "severity": cve.cvss_v3_severity or "UNKNOWN",
                    "description": cve.description,
                    "confidence": 0.9,  # High confidence from NVD
                    "published": cve.published,
                    "last_modified": cve.last_modified,
                    "vuln_status": cve.vuln_status,
                    "cvss_v3_vector": cve.cvss_v3_vector,
                    "references": cve.references,
                    "source": cve.source
                }
                cve_dicts.append(cve_dict)
            
            return cve_dicts
            
        except Exception as e:
            logger.error(f"Enhanced CVE lookup failed for {service}: {e}")
            return []
