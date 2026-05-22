import re
import httpx
from dataclasses import dataclass
from typing import List, Optional, Dict
import asyncio
from functools import lru_cache


@dataclass
class CVE:
    """Represents a Common Vulnerability and Exposure."""
    cve_id: str
    description: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    cvss_score: Optional[float]
    cvss_vector: Optional[str]
    published_date: Optional[str]
    url: str


@dataclass
class CVEResult:
    """Result of CVE lookup for a service version."""
    service_name: str
    version: str
    cves: List[CVE]
    total_count: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int


# Common service name mappings for CVE lookup
SERVICE_CPE_MAPPINGS = {
    "apache": "apache",
    "nginx": "nginx",
    "openssh": "openssh",
    "ssh": "openssh",
    "mysql": "mysql",
    "postgresql": "postgresql",
    "postgres": "postgresql",
    "redis": "redis",
    "mongodb": "mongodb",
    "tomcat": "apache_tomcat",
    "jetty": "jetty",
    "lighttpd": "lighttpd",
    "iis": "microsoft_iis",
    "ftp": "ftp",
    "vsftpd": "vsftpd",
    "proftpd": "proftpd",
    "smtp": "smtp",
    "sendmail": "sendmail",
    "postfix": "postfix",
    "exim": "exim",
    "dovecot": "dovecot",
    "bind": "bind",
    "dns": "bind",
    "openssl": "openssl",
    "libssl": "openssl",
}


def normalize_service_name(service: str) -> str:
    """Normalize service name for CVE lookup."""
    service_lower = service.lower().strip()
    return SERVICE_CPE_MAPPINGS.get(service_lower, service_lower)


def parse_version_string(version_str: str) -> Optional[tuple[str, str]]:
    """
    Parse version string to extract service name and version.
    Returns (service_name, version) or None if parsing fails.
    
    Examples:
        "Apache/2.4.49" -> ("apache", "2.4.49")
        "nginx/1.18.0" -> ("nginx", "1.18.0")
        "OpenSSH_8.2p1" -> ("openssh", "8.2")
        "MySQL 5.7.33" -> ("mysql", "5.7.33")
    """
    if not version_str:
        return None
    
    # Pattern: Service/Version or Service Version
    patterns = [
        r'^([a-zA-Z][a-zA-Z0-9_-]*)[/\s]+([0-9][0-9.]*[a-zA-Z0-9.-]*)',
        r'^([a-zA-Z][a-zA-Z0-9_-]*)(?:[_-])([0-9][0-9.]*[a-zA-Z0-9.-]*)',
    ]
    
    for pattern in patterns:
        match = re.match(pattern, version_str.strip())
        if match:
            service, version = match.groups()
            # Clean version - remove trailing non-numeric characters
            version = re.sub(r'[^0-9.].*$', '', version)
            if version:
                return (normalize_service_name(service), version)
    
    return None


def construct_cpe_query(service: str, version: str) -> str:
    """
    Construct a CPE query string for NVD API.
    This is a simplified approach - in production, you'd use proper CPE strings.
    """
    # For NVD API v2, we can search by product name and version
    # This is a simplified search that works for many common cases
    return f"{service}:{version}"


def cvss_score_to_severity(score: Optional[float]) -> str:
    """Convert CVSS score to severity level."""
    if score is None:
        return "UNKNOWN"
    if score >= 9.0:
        return "CRITICAL"
    elif score >= 7.0:
        return "HIGH"
    elif score >= 4.0:
        return "MEDIUM"
    elif score > 0:
        return "LOW"
    return "NONE"


class CVEDetector:
    """CVE detection using NVD API."""
    
    def __init__(self, timeout: float = 10.0):
        self.timeout = timeout
        self.base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        # Simple in-memory cache to avoid rate limiting
        self._cache: Dict[str, CVEResult] = {}
    
    async def search_cves(
        self,
        service: str,
        version: str
    ) -> CVEResult:
        """
        Search for CVEs affecting a specific service version.
        
        Args:
            service: Service name (e.g., "apache", "nginx")
            version: Version string (e.g., "2.4.49", "1.18.0")
        
        Returns:
            CVEResult with list of CVEs and severity counts
        """
        cache_key = f"{service}:{version}"
        if cache_key in self._cache:
            return self._cache[cache_key]
        
        try:
            cves = await self._query_nvd_api(service, version)
            result = self._build_result(service, version, cves)
            self._cache[cache_key] = result
            return result
        except Exception as e:
            # If API fails, return empty result
            print(f"[CVE] API lookup failed for {service} {version}: {e}")
            return CVEResult(
                service_name=service,
                version=version,
                cves=[],
                total_count=0,
                critical_count=0,
                high_count=0,
                medium_count=0,
                low_count=0
            )
    
    async def _query_nvd_api(self, service: str, version: str) -> List[CVE]:
        """Query NVD API for CVEs."""
        # Construct search query - search for product name in description
        # This is a simplified approach. For production, use proper CPE matching.
        query = f"{service} {version}"
        
        params = {
            "resultsPerPage": 20,
            "startIndex": 0,
        }
        
        # Add keyword search parameter
        if query:
            params["keywordSearch"] = query
        
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            try:
                response = await client.get(self.base_url, params=params)
                response.raise_for_status()
                data = response.json()
                return self._parse_nvd_response(data)
            except httpx.HTTPStatusError as e:
                if e.response.status_code == 403:
                    # Rate limited - return empty
                    print("[CVE] NVD API rate limited")
                    return []
                raise
            except Exception as e:
                print(f"[CVE] NVD API error: {e}")
                return []
    
    def _parse_nvd_response(self, data: dict) -> List[CVE]:
        """Parse NVD API response into CVE objects."""
        cves = []
        
        if "vulnerabilities" not in data:
            return cves
        
        for vuln in data["vulnerabilities"]:
            try:
                cve_item = vuln.get("cve", {})
                cve_id = cve_item.get("id", "")
                
                # Get description
                descriptions = cve_item.get("descriptions", [])
                description = ""
                for desc in descriptions:
                    if desc.get("lang") == "en":
                        description = desc.get("value", "")
                        break
                
                # Get CVSS score
                metrics = cve_item.get("metrics", {})
                cvss_score = None
                cvss_vector = None
                
                # Try CVSS v3.1 first
                if "cvssMetricV31" in metrics:
                    cvss_data = metrics["cvssMetricV31"][0]
                    cvss_score = cvss_data.get("cvssData", {}).get("baseScore")
                    cvss_vector = cvss_data.get("cvssData", {}).get("vectorString")
                # Fall back to CVSS v3.0
                elif "cvssMetricV30" in metrics:
                    cvss_data = metrics["cvssMetricV30"][0]
                    cvss_score = cvss_data.get("cvssData", {}).get("baseScore")
                    cvss_vector = cvss_data.get("cvssData", {}).get("vectorString")
                # Fall back to CVSS v2
                elif "cvssMetricV2" in metrics:
                    cvss_data = metrics["cvssMetricV2"][0]
                    cvss_score = cvss_data.get("cvssData", {}).get("baseScore")
                
                # Get published date
                published_date = cve_item.get("published")
                
                severity = cvss_score_to_severity(cvss_score)
                
                # Construct URL
                url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
                
                cve = CVE(
                    cve_id=cve_id,
                    description=description[:500],  # Truncate long descriptions
                    severity=severity,
                    cvss_score=cvss_score,
                    cvss_vector=cvss_vector,
                    published_date=published_date,
                    url=url
                )
                cves.append(cve)
            except Exception as e:
                print(f"[CVE] Error parsing CVE item: {e}")
                continue
        
        return cves
    
    def _build_result(self, service: str, version: str, cves: List[CVE]) -> CVEResult:
        """Build CVEResult from CVE list."""
        critical = sum(1 for c in cves if c.severity == "CRITICAL")
        high = sum(1 for c in cves if c.severity == "HIGH")
        medium = sum(1 for c in cves if c.severity == "MEDIUM")
        low = sum(1 for c in cves if c.severity == "LOW")
        
        return CVEResult(
            service_name=service,
            version=version,
            cves=cves,
            total_count=len(cves),
            critical_count=critical,
            high_count=high,
            medium_count=medium,
            low_count=low
        )


# Global detector instance
_cve_detector = CVEDetector()


async def detect_cves_for_version(version_string: str) -> Optional[CVEResult]:
    """
    Detect CVEs for a version string.
    
    Args:
        version_string: Version string like "Apache/2.4.49" or "nginx/1.18.0"
    
    Returns:
        CVEResult or None if version cannot be parsed
    """
    parsed = parse_version_string(version_string)
    if not parsed:
        return None
    
    service, version = parsed
    return await _cve_detector.search_cves(service, version)


async def detect_cves_batch(version_strings: List[str]) -> Dict[str, CVEResult]:
    """
    Detect CVEs for multiple version strings in parallel.
    
    Args:
        version_strings: List of version strings
    
    Returns:
        Dict mapping version_string -> CVEResult
    """
    tasks = []
    for version_str in version_strings:
        task = detect_cves_for_version(version_str)
        tasks.append(task)
    
    results = await asyncio.gather(*tasks, return_exceptions=True)
    
    output = {}
    for version_str, result in zip(version_strings, results):
        if isinstance(result, Exception):
            print(f"[CVE] Error processing {version_str}: {result}")
            continue
        if result is not None:
            output[version_str] = result
    
    return output


def get_cve_summary(cve_result: CVEResult) -> str:
    """Get a human-readable summary of CVE results."""
    if cve_result.total_count == 0:
        return f"No known CVEs for {cve_result.service_name} {cve_result.version}"
    
    parts = []
    if cve_result.critical_count > 0:
        parts.append(f"{cve_result.critical_count} CRITICAL")
    if cve_result.high_count > 0:
        parts.append(f"{cve_result.high_count} HIGH")
    if cve_result.medium_count > 0:
        parts.append(f"{cve_result.medium_count} MEDIUM")
    if cve_result.low_count > 0:
        parts.append(f"{cve_result.low_count} LOW")
    
    severity_str = ", ".join(parts)
    return f"{cve_result.total_count} CVEs found ({severity_str})"
