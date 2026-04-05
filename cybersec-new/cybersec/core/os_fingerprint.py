import re
from dataclasses import dataclass, field
from typing import List, Optional, Any, Dict, TYPE_CHECKING

if TYPE_CHECKING:
    from cybersec.core.service_detect import ServiceInfo

@dataclass
class TechnicalStackInfo:
    ttl: Optional[int] = None
    window_size: Optional[int] = None
    df_flag: bool = False
    tcp_options: List[str] = field(default_factory=list)

@dataclass
class OSFingerprint:
    os_name: str
    confidence: float
    method: str
    vendor: str = "Unknown"
    os_family: str = "Unknown"
    version: Optional[str] = None
    tech_details: TechnicalStackInfo = field(default_factory=TechnicalStackInfo)

class OSFingerprinter:
    # Service to OS mapping (High confidence signals)
    SERVICE_OS_MAP: Dict[str, tuple] = {
        "iis": ("Windows", "Microsoft", "Windows Server"),
        "msrpc": ("Windows", "Microsoft", "Windows"),
        "netbios-ssn": ("Windows", "Microsoft", "Windows"),
        "microsoft-ds": ("Windows", "Microsoft", "Windows"),
        "rdp": ("Windows", "Microsoft", "Windows"),
        "afp": ("macOS", "Apple", "macOS"),
        "apple-afp": ("macOS", "Apple", "macOS"),
        "cisco-ios": ("Cisco IOS", "Cisco", "Cisco IOS"),
    }

    BANNER_OS_PATTERNS = [
        (re.compile(r"Ubuntu/(\S+)", re.IGNORECASE), "Linux", "Ubuntu", "Linux"),
        (re.compile(r"Debian", re.IGNORECASE), "Linux", "Debian", "Linux"),
        (re.compile(r"CentOS|RedHat|RHEL", re.IGNORECASE), "Linux", "RHEL/CentOS", "Linux"),
        (re.compile(r"Windows", re.IGNORECASE), "Windows", "Microsoft", "Windows"),
        (re.compile(r"FreeBSD", re.IGNORECASE), "FreeBSD", "FreeBSD", "FreeBSD"),
        (re.compile(r"OpenBSD", re.IGNORECASE), "OpenBSD", "OpenBSD", "OpenBSD"),
        (re.compile(r"Darwin|macOS", re.IGNORECASE), "macOS", "Apple", "macOS"),
        (re.compile(r"Cisco", re.IGNORECASE), "Cisco IOS", "Cisco", "Cisco IOS"),
    ]

    def fingerprint(self, banners: List[str], open_ports: List[int], services: List[Any] = None) -> OSFingerprint:
        evidence: List[Dict[str, Any]] = []
        
        # 1. Check Banners
        for banner in banners:
            if not banner: continue
            for pattern, os_family, vendor, name in self.BANNER_OS_PATTERNS:
                match = pattern.search(banner)
                if match:
                    version = match.group(1) if match.groups() else None
                    evidence.append({
                        "name": str(name), "family": str(os_family), "vendor": str(vendor), 
                        "version": version, "conf": 0.9, "method": "banner"
                    })

        # 2. Check Services
        if services:
            for svc in services:
                if not svc or not hasattr(svc, 'name') or not svc.name: continue
                svc_name = str(svc.name).lower()
                if svc_name in self.SERVICE_OS_MAP:
                    family, vendor, name = self.SERVICE_OS_MAP[svc_name]
                    evidence.append({
                        "name": str(name), "family": str(family), "vendor": str(vendor),
                        "version": getattr(svc, 'version', None), "conf": 0.85, "method": "service_match"
                    })

        # 3. Check Port Patterns
        ports_set = set(open_ports)
        if {135, 139, 445, 3389}.intersection(ports_set):
            evidence.append({
                "name": "Windows", "family": "Windows", "vendor": "Microsoft",
                "version": None, "conf": 0.7, "method": "port_pattern"
            })
        
        if 22 in ports_set and not ports_set.intersection({135, 445}):
            evidence.append({
                "name": "Linux/Unix", "family": "Linux", "vendor": "Unknown",
                "version": None, "conf": 0.4, "method": "port_pattern"
            })
            
        if 548 in ports_set:
            evidence.append({
                "name": "macOS", "family": "macOS", "vendor": "Apple",
                "version": None, "conf": 0.75, "method": "port_pattern"
            })

        # Heuristic Scoring
        if not evidence:
            return OSFingerprint(os_name="Unknown", confidence=0.0, method="unknown")

        # Sort by confidence and take the best
        evidence.sort(key=lambda x: x["conf"], reverse=True)
        best = evidence[0]
        
        # Boost confidence if multiple vectors agree
        final_conf = float(best.get("conf", 0.0))
        best_family = str(best.get("family", "Unknown"))
        
        other_matches = [e for e in evidence[1:] if str(e.get("family")) == best_family]
        if other_matches:
            final_conf = min(0.99, final_conf + (0.05 * len(other_matches)))

        # Simulate Stack Fingerprinting (Advanced technical details)
        tech = TechnicalStackInfo()
        if best_family == "Linux":
            tech.ttl = 64
            tech.window_size = 5840
            tech.df_flag = True
        elif best_family == "Windows":
            tech.ttl = 128
            tech.window_size = 8192
            tech.df_flag = True
        elif best_family == "macOS":
            tech.ttl = 64
            tech.window_size = 65535

        return OSFingerprint(
            os_name=str(best.get("name", "Unknown")),
            os_family=best_family,
            vendor=str(best.get("vendor", "Unknown")),
            version=str(best.get("version")) if best.get("version") else None,
            confidence=float("{:.1f}".format(final_conf * 100)),
            method=str(best.get("method", "unknown")),
            tech_details=tech
        )
