"""
Enhanced CVE lookup with NVD API 2.0 integration.

This module provides backward compatibility while using the new NVD client
for live CVE data fetching.
"""
from dataclasses import dataclass
from typing import Optional, List
from sqlalchemy.ext.asyncio import AsyncSession

from cybersec.core.security.nvd_client import EnhancedCVELookup, CVEResult
from cybersec.core.scanner.analysis.service_detect import ServiceDetectionResult


@dataclass
class CVEEntry:
    """Legacy CVE entry for backward compatibility."""
    id: str
    cvss_score: float
    severity: str
    description: str
    confidence: float = 1.0


class CVELookup:
    """Enhanced CVE lookup with NVD API 2.0 integration."""
    
    def __init__(self, db_session: Optional[AsyncSession] = None):
        self.enhanced_lookup = EnhancedCVELookup(db_session)
    
    async def _fetch_from_nvd(self, service: str, version: Optional[str] = None) -> List[CVEEntry]:
        """Fetch CVEs from NVD API - legacy method."""
        cve_dicts = await self.enhanced_lookup.lookup(service, version)
        
        # Convert to legacy CVEEntry format
        cve_entries = []
        for cve_dict in cve_dicts:
            cve_entry = CVEEntry(
                id=cve_dict.get("id", ""),
                cvss_score=cve_dict.get("cvss_score", 0.0),
                severity=cve_dict.get("severity", "UNKNOWN"),
                description=cve_dict.get("description", ""),
                confidence=cve_dict.get("confidence", 0.9)
            )
            cve_entries.append(cve_entry)
        
        return cve_entries
    
    async def lookup(self, service: str, version: Optional[str] = None) -> List[CVEEntry]:
        """Lookup CVEs with NVD API integration."""
        return await self._fetch_from_nvd(service, version)
    
    def _local_lookup(self, service: str, version: Optional[str] = None) -> List[CVEEntry]:
        """Local lookup - deprecated, use NVD API."""
        # This method is kept for backward compatibility but should not be used
        return []
    
    async def lookup_for_service_result(self, service_result: ServiceDetectionResult) -> List[dict]:
        """
        Lookup CVEs for a service detection result.
        
        Returns list of CVE dictionaries compatible with scan results.
        """
        return await self.enhanced_lookup.lookup(
            service_result.service_name,
            service_result.service_version
        )
