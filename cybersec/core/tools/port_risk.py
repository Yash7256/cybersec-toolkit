"""Port risk classification for scan results."""

from __future__ import annotations

# High — dangerous or commonly exploited when exposed
HIGH_RISK_PORTS: dict[int, str] = {
    23: "Telnet transmits credentials in cleartext",
    69: "TFTP has no authentication",
    111: "RPC portmapper can expose internal services",
    135: "Microsoft RPC endpoint mapper",
    139: "NetBIOS session service",
    445: "SMB file sharing — frequent ransomware/lateral movement target",
    512: "rexec — legacy remote execution",
    513: "rlogin — legacy remote login",
    514: "rsh — legacy remote shell",
    1433: "Microsoft SQL Server — high-value database target",
    1524: "Often abused bind/backdoor port",
    2049: "NFS exports may leak sensitive files",
    2375: "Docker API — unauthenticated remote control risk",
    3389: "RDP — common brute-force and exploit target",
    4444: "Metasploit default listener port",
    5900: "VNC — often weak or missing authentication",
    5901: "VNC alternate display",
    5984: "CouchDB — historical unauthenticated admin APIs",
    6379: "Redis — frequently exposed without auth",
    9200: "Elasticsearch — cluster data exposure risk",
    11211: "Memcached — amplification and data leak risk",
    27017: "MongoDB — frequent unauthenticated deployments",
}

# Medium — admin, mail, database, or non-standard service ports
MEDIUM_RISK_PORTS: dict[int, str] = {
    21: "FTP — cleartext credentials and file transfer",
    22: "SSH — remote administration surface",
    25: "SMTP — mail relay and user enumeration risk",
    53: "DNS — zone transfer and recursion misconfigurations",
    110: "POP3 — cleartext mail retrieval",
    143: "IMAP — mail access and credential exposure",
    161: "SNMP — community strings may leak device info",
    389: "LDAP — directory authentication target",
    636: "LDAPS — directory authentication target",
    1433: "MSSQL administration port",
    1521: "Oracle database listener",
    2048: "AWS EFS/NFS-related exposure",
    3306: "MySQL — database administration port",
    3388: "RDP alternate / clustered remote desktop",
    5432: "PostgreSQL — database administration port",
    5902: "VNC session port",
    8000: "Alternate HTTP — often admin or dev panels",
    8080: "HTTP proxy or alternate web admin interface",
    8443: "Alternate HTTPS — admin or application portal",
    8888: "Alternate HTTP — common dev/management UI",
    9000: "SonarQube / PHP-FPM / management services",
    3000: "Node.js dev server — often unhardened",
    5000: "Flask/dev or Docker registry UI",
}

# Low — common internet-facing services when properly maintained
LOW_RISK_PORTS: dict[int, str] = {
    80: "HTTP — standard web service",
    443: "HTTPS — encrypted web service",
    993: "IMAPS — encrypted mail",
    995: "POP3S — encrypted mail",
}

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
    if port in HIGH_RISK_PORTS:
        return "high", HIGH_RISK_PORTS[port]
    if port in MEDIUM_RISK_PORTS:
        return "medium", MEDIUM_RISK_PORTS[port]
    if port in LOW_RISK_PORTS:
        return "low", LOW_RISK_PORTS[port]

    service_key = (service or "").lower()
    for needle, level, reason in _SERVICE_RISK_KEYWORDS:
        if needle in service_key:
            return level, reason

    # Registered ports (1–1023) not in our lists: often system services
    if 1 <= port <= 1023:
        return "medium", f"Well-known port {port} exposed — verify service hardening"

    # High ephemeral / custom ports: unknown service
    return "medium", f"Port {port} open — review exposed service and firewall rules"
