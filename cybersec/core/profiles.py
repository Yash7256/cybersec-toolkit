"""
Scan profiles — named presets that abstract away raw port ranges and tuning.

Users specify a profile name instead of raw port ranges:
  - "quick"         → 100 most common ports, fast timeout
  - "web-audit"     → HTTP/HTTPS + API ports, deep enrichment
  - "database"      → database service ports, deep banner grab
  - "remote-access" → SSH/RDP/VNC/Telnet, OS fingerprint
  - "full-tcp"      → top 1000 ports, full enrichment
  - "stealth"       → 17 common ports, low rate, no enrichment
"""

from dataclasses import dataclass, field
from typing import Optional

from cybersec.core.scanner.utils import parse_ports


@dataclass
class ScanProfile:
    name: str
    description: str
    ports: list[int]
    timeout: float = 3.0
    rate_preset: str = "normal"
    concurrency: Optional[int] = None   # None = use adaptive
    enrich: bool = True
    scan_mode: str = "connect"


PROFILES: dict[str, ScanProfile] = {}


def _reg(p: ScanProfile) -> ScanProfile:
    PROFILES[p.name] = p
    return p


QUICK = _reg(ScanProfile(
    name="quick",
    description="Fast scan of 100 most common ports",
    ports=parse_ports("top100"),
    timeout=1.5,
    rate_preset="aggressive",
    concurrency=500,
    enrich=False,
))

WEB_AUDIT = _reg(ScanProfile(
    name="web-audit",
    description="Comprehensive web service audit with banner grabbing",
    ports=sorted(set(
        parse_ports("top100") +
        [3000, 4000, 5000, 7000, 9000, 9090, 3001, 5001, 7001, 7443, 9443,
         1313, 8001, 9001, 30000, 50000, 60000, 60001, 60002]
    )),
    timeout=5.0,
    rate_preset="normal",
    enrich=True,
))

DATABASE = _reg(ScanProfile(
    name="database",
    description="Database service discovery with deep banner grabbing",
    ports=sorted(set([
        3306, 5432, 5433, 6379, 27017, 27018, 27019, 9200, 9300,
        11211, 1433, 1434, 1521, 1830, 2483, 2484, 3050, 3351, 4040,
        4041, 4500, 5050, 5060, 5061, 5500, 5555, 5556, 5672, 5673,
        61616, 61617, 7001, 7002, 7077, 7676, 7777, 8222, 8444, 8445,
        8446, 8447, 8448, 8449, 8450, 8889, 9000, 9042, 9092, 9100,
        9160, 27001, 27002, 27003, 27004, 27005, 27006, 27007, 27008,
        27009, 27010, 27011, 27012, 27013, 27014, 27015, 27016,
    ])),
    timeout=5.0,
    rate_preset="normal",
    enrich=True,
))

REMOTE_ACCESS = _reg(ScanProfile(
    name="remote-access",
    description="Remote access service audit with OS fingerprinting",
    ports=sorted(set([
        22, 23, 3389, 5900, 5901, 5902, 5903, 5800, 5801,
        5631, 5632, 4172, 3283, 3388, 3390, 5938, 5985, 5986,
        2222, 22222, 22223, 22224, 22225, 22226, 22227, 22228, 22229,
        3390, 3391, 3392, 3393, 3394, 3395, 3396, 3397, 3398, 3399,
    ])),
    timeout=5.0,
    rate_preset="stealth",
    enrich=True,
))

FULL_TCP = _reg(ScanProfile(
    name="full-tcp",
    description="Comprehensive TCP scan of top 1000 ports",
    ports=parse_ports("top1000"),
    timeout=3.0,
    rate_preset="normal",
    enrich=True,
))

STEALTH = _reg(ScanProfile(
    name="stealth",
    description="Minimal footprint scan — low rate, common ports only",
    ports=parse_ports("common"),
    timeout=5.0,
    rate_preset="stealth",
    concurrency=50,
    enrich=False,
))


def resolve_profile(value: str) -> ScanProfile:
    """Resolve a profile name or raw port spec to a ScanProfile.

    Args:
        value: Profile name ("quick", "web-audit", etc.) or raw port
               spec ("80,443", "1-1000", "common", etc.).

    Returns:
        ScanProfile with resolved ports and settings.
    """
    name = value.lower().replace("_", "-")

    if name in PROFILES:
        return PROFILES[name]

    if name in ("common", "top100", "top250", "top1000", "all"):
        return ScanProfile(
            name=name,
            description=f"Raw port range: {name}",
            ports=parse_ports(name),
        )

    if name.startswith("top-"):
        return ScanProfile(
            name=name,
            description=f"Custom top-N ports: {name}",
            ports=parse_ports(name),
        )

    # Treat as raw comma/range port spec
    try:
        ports = parse_ports(value)
        return ScanProfile(
            name="custom",
            description=f"Custom port list ({len(ports)} ports)",
            ports=ports,
        )
    except ValueError:
        raise ValueError(
            f"Unknown scan profile '{value}'. "
            f"Available profiles: {', '.join(sorted(PROFILES))}"
        )


_PROFILE_NAMES = list(PROFILES.keys())
