"""Port risk classification for scan results."""

from __future__ import annotations

from cybersec.core.tools.port_registry import PORT_REGISTRY

_SERVICE_RISK_KEYWORDS: list[tuple[str, str, str]] = [
    ("telnet", "high", "Telnet service detected"),
    ("rdp", "high", "Remote Desktop service"),
    ("vnc", "high", "VNC remote desktop"),
    ("redis", "high", "Redis in-memory datastore"),
    ("mongodb", "high", "MongoDB database"),
    ("smb", "high", "SMB file sharing"),
    ("microsoft-ds", "high", "SMB / Microsoft-DS"),
    ("ftp", "medium", "FTP file transfer"),
    ("smtp", "medium", "SMTP mail service"),
    ("mysql", "medium", "MySQL database"),
    ("postgresql", "medium", "PostgreSQL database"),
    ("http-proxy", "medium", "HTTP proxy or alternate web port"),
    ("https-alt", "medium", "Alternate HTTPS service"),
]


def classify_port_risk(port: int, service: str | None = None) -> tuple[str, str]:
    """
    Classify open-port risk.

    Returns:
        (level, reason) where level is ``low``, ``medium``, or ``high``.
    """
    info = PORT_REGISTRY.get(port)
    if info is not None:
        return info.risk_level, info.risk_reason

    service_key = (service or "").lower()
    for needle, level, reason in _SERVICE_RISK_KEYWORDS:
        if needle in service_key:
            return level, reason

    # Registered ports (1–1023) not in our lists: often system services
    if 1 <= port <= 1023:
        return "medium", f"Well-known port {port} exposed — verify service hardening"

    # High ephemeral / custom ports: unknown service
    return "medium", f"Port {port} open — review exposed service and firewall rules"
