"""
CVE detection for discovered service versions.

Delegates all NVD API calls to cybersec.core.security.nvd_client.NVDClient,
which provides proper rate limiting (API-key-aware), and Postgres-backed caching
via NVDCacheManager / the NVDCveCache table.

The public API (CVE, CVEResult dataclasses, detect_cves_for_version,
detect_cves_batch, parse_version_string) is unchanged so port_scanner.py and
its callers need no modifications.

NVDClient is imported lazily (inside functions) to avoid a circular import via
cybersec.core.security.__init__ → cve_lookup → scanner → port_scanner.
"""
import re
import asyncio
import logging
from dataclasses import dataclass
from typing import List, Optional, Dict, TYPE_CHECKING

from sqlalchemy.ext.asyncio import AsyncSession

if TYPE_CHECKING:
    # Only imported for type hints during static analysis — not at runtime,
    # so the circular chain is never triggered.
    from cybersec.core.security.nvd_client import NVDClient as _NVDClientT

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Public dataclass shapes (consumed by port_scanner.py)
# ---------------------------------------------------------------------------

@dataclass
class CVE:
    """Represents a Common Vulnerability and Exposure."""
    cve_id: str
    description: str
    severity: str          # CRITICAL, HIGH, MEDIUM, LOW
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


# ---------------------------------------------------------------------------
# Service-name normalisation (unchanged from original)
# ---------------------------------------------------------------------------

SERVICE_CPE_MAPPINGS: Dict[str, str] = {
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
    Parse a banner version string into (service_name, version).

    Examples::

        "Apache/2.4.49"   -> ("apache", "2.4.49")
        "nginx/1.18.0"    -> ("nginx", "1.18.0")
        "OpenSSH_8.2p1"   -> ("openssh", "8.2")
        "MySQL 5.7.33"    -> ("mysql", "5.7.33")
    """
    if not version_str:
        return None

    patterns = [
        r'^([a-zA-Z][a-zA-Z0-9_-]*)[/\s]+([0-9][0-9.]*[a-zA-Z0-9.-]*)',
        r'^([a-zA-Z][a-zA-Z0-9_-]*)(?:[_-])([0-9][0-9.]*[a-zA-Z0-9.-]*)',
    ]

    for pattern in patterns:
        match = re.match(pattern, version_str.strip())
        if match:
            service, version = match.groups()
            version = re.sub(r'[^0-9.].*$', '', version)
            if version:
                return (normalize_service_name(service), version)

    return None


def cvss_score_to_severity(score: Optional[float]) -> str:
    """Convert CVSS score to severity level."""
    if score is None:
        return "UNKNOWN"
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return "NONE"


# ---------------------------------------------------------------------------
# Adapter: nvd_client.CVEResult list  →  cve_detect.CVEResult
# ---------------------------------------------------------------------------

def _nvd_results_to_cve_result(
    service: str,
    version: str,
    nvd_cves: list,
) -> CVEResult:
    """Map a list of nvd_client.CVEResult objects into a cve_detect.CVEResult."""
    cves: List[CVE] = []
    for n in nvd_cves:
        score = n.cvss_v3_score or n.cvss_v2_score
        severity = (n.cvss_v3_severity or "").upper() or cvss_score_to_severity(score)
        cve = CVE(
            cve_id=n.cve_id,
            description=(n.description or "")[:500],
            severity=severity,
            cvss_score=score,
            cvss_vector=n.cvss_v3_vector,
            published_date=n.published or None,
            url=f"https://nvd.nist.gov/vuln/detail/{n.cve_id}",
        )
        cves.append(cve)

    critical = sum(1 for c in cves if c.severity == "CRITICAL")
    high     = sum(1 for c in cves if c.severity == "HIGH")
    medium   = sum(1 for c in cves if c.severity == "MEDIUM")
    low      = sum(1 for c in cves if c.severity == "LOW")

    return CVEResult(
        service_name=service,
        version=version,
        cves=cves,
        total_count=len(cves),
        critical_count=critical,
        high_count=high,
        medium_count=medium,
        low_count=low,
    )


# ---------------------------------------------------------------------------
# Module-level NVDClient singleton — lazy-initialised to avoid circular imports
# ---------------------------------------------------------------------------

_nvd_client: Optional["_NVDClientT"] = None


def _get_nvd_client() -> "NVDClient":  # type: ignore[name-defined]
    global _nvd_client
    if _nvd_client is None:
        # Lazy import breaks the circular dependency:
        # cve_detect → nvd_client → security/__init__ → cve_lookup → scanner → port_scanner
        from cybersec.core.security.nvd_client import NVDClient  # noqa: PLC0415
        _nvd_client = NVDClient()
    return _nvd_client  # type: ignore[return-value]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

async def detect_cves_for_version(
    version_string: str,
    db_session: Optional[AsyncSession] = None,
) -> Optional[CVEResult]:
    """
    Detect CVEs for a version string such as "Apache/2.4.49".

    Delegates to NVDClient.lookup_cves_for_service which handles rate limiting
    and (when *db_session* is supplied) Postgres-backed TTL caching.

    Returns None when the version string cannot be parsed.
    """
    parsed = parse_version_string(version_string)
    if not parsed:
        return None

    service, version = parsed
    client = _get_nvd_client()
    try:
        nvd_cves = await client.lookup_cves_for_service(service, version, db_session)
    except Exception as exc:
        logger.warning("CVE lookup failed for %s %s: %s", service, version, exc)
        return CVEResult(
            service_name=service,
            version=version,
            cves=[],
            total_count=0,
            critical_count=0,
            high_count=0,
            medium_count=0,
            low_count=0,
        )

    return _nvd_results_to_cve_result(service, version, nvd_cves)


async def detect_cves_batch(
    version_strings: List[str],
    db_session: Optional[AsyncSession] = None,
) -> Dict[str, CVEResult]:
    """
    Detect CVEs for multiple version strings.

    Queries are dispatched concurrently but each individual NVDClient call
    still honours the configured rate-limit delay (enforced inside NVDClient
    via an asyncio.Lock so concurrent coroutines queue up rather than fire
    simultaneously).

    Args:
        version_strings: Banner strings e.g. ["Apache/2.4.51", "nginx/1.21.0"]
        db_session:      Optional AsyncSession for Postgres-backed caching.
                         Pass None for CLI / direct callers without a DB.

    Returns:
        Mapping of version_string → CVEResult for every string that was parsed
        successfully.
    """
    tasks = [
        detect_cves_for_version(vs, db_session)
        for vs in version_strings
    ]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    output: Dict[str, CVEResult] = {}
    for version_str, result in zip(version_strings, results):
        if isinstance(result, Exception):
            logger.warning("CVE batch error for %s: %s", version_str, result)
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
