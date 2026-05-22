"""Human-readable port service descriptions for tooltips and UI."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class PortDescription:
    name: str
    purpose: str
    security_concern: str


PORT_DESCRIPTIONS: dict[int, PortDescription] = {
    21: PortDescription(
        "FTP",
        "File Transfer Protocol for uploading and downloading files.",
        "Credentials and data travel in cleartext; anonymous uploads may be enabled.",
    ),
    22: PortDescription(
        "SSH",
        "Secure remote login protocol for shell access and tunneling.",
        "Can be brute-forced if exposed publicly or weak keys/passwords are used.",
    ),
    23: PortDescription(
        "Telnet",
        "Legacy remote terminal access to network devices and servers.",
        "All traffic including passwords is sent unencrypted — high interception risk.",
    ),
    25: PortDescription(
        "SMTP",
        "Simple Mail Transfer Protocol for sending email between servers.",
        "Open relays and user enumeration can enable spam or phishing abuse.",
    ),
    53: PortDescription(
        "DNS",
        "Domain Name System for resolving hostnames to IP addresses.",
        "Zone transfers and recursion misconfigurations may leak internal network data.",
    ),
    80: PortDescription(
        "HTTP",
        "Unencrypted web traffic for websites and APIs.",
        "Traffic can be intercepted or modified; outdated web apps increase exploit risk.",
    ),
    110: PortDescription(
        "POP3",
        "Post Office Protocol for downloading email from a mail server.",
        "Usernames and passwords are often transmitted without encryption.",
    ),
    143: PortDescription(
        "IMAP",
        "Internet Message Access Protocol for remote mailbox management.",
        "Cleartext login exposes mail credentials on untrusted networks.",
    ),
    443: PortDescription(
        "HTTPS",
        "Encrypted web traffic using TLS for websites and APIs.",
        "Certificate or TLS misconfiguration can still weaken confidentiality.",
    ),
    445: PortDescription(
        "SMB",
        "Server Message Block for Windows file and printer sharing.",
        "Frequent target for ransomware and lateral movement (e.g. EternalBlue).",
    ),
    993: PortDescription(
        "IMAPS",
        "IMAP over TLS for encrypted remote mailbox access.",
        "Weak TLS settings or expired certificates reduce protection.",
    ),
    995: PortDescription(
        "POP3S",
        "POP3 over TLS for encrypted mail download.",
        "Misconfigured TLS or credential stuffing still pose login risk.",
    ),
    3306: PortDescription(
        "MySQL",
        "Popular relational database server for application data storage.",
        "Exposed databases are scanned for weak credentials and SQL injection chains.",
    ),
    3389: PortDescription(
        "RDP",
        "Remote Desktop Protocol for graphical Windows administration.",
        "Common brute-force and exploit target when reachable from the internet.",
    ),
    5432: PortDescription(
        "PostgreSQL",
        "Advanced open-source relational database server.",
        "Public exposure invites credential attacks and privilege escalation attempts.",
    ),
    5900: PortDescription(
        "VNC",
        "Virtual Network Computing for remote desktop viewing and control.",
        "Often protected only by a password; many instances lack encryption.",
    ),
    6379: PortDescription(
        "Redis",
        "In-memory key-value store used for caching and messaging.",
        "Frequently left without authentication, allowing remote command execution.",
    ),
    8080: PortDescription(
        "HTTP-Proxy",
        "Alternate HTTP port for proxies, dev servers, or admin panels.",
        "May expose management interfaces or unpatched application backends.",
    ),
    8443: PortDescription(
        "HTTPS-Alt",
        "Alternate HTTPS port for web apps, proxies, or admin UIs.",
        "Non-standard TLS services are easy to misconfigure or forget to patch.",
    ),
    27017: PortDescription(
        "MongoDB",
        "Document-oriented NoSQL database for modern applications.",
        "Historically many deployments allowed unauthenticated access from the internet.",
    ),
}

_SERVICE_FALLBACKS: list[tuple[str, PortDescription]] = [
    ("ssh", PORT_DESCRIPTIONS[22]),
    ("ftp", PORT_DESCRIPTIONS[21]),
    ("telnet", PORT_DESCRIPTIONS[23]),
    ("http", PORT_DESCRIPTIONS[80]),
    ("https", PORT_DESCRIPTIONS[443]),
    ("mysql", PORT_DESCRIPTIONS[3306]),
    ("redis", PORT_DESCRIPTIONS[6379]),
    ("mongodb", PORT_DESCRIPTIONS[27017]),
    ("rdp", PORT_DESCRIPTIONS[3389]),
    ("vnc", PORT_DESCRIPTIONS[5900]),
    ("smtp", PORT_DESCRIPTIONS[25]),
    ("dns", PORT_DESCRIPTIONS[53]),
]


def get_port_description(port: int, service: str | None = None) -> PortDescription:
    if port in PORT_DESCRIPTIONS:
        return PORT_DESCRIPTIONS[port]
    service_key = (service or "").lower()
    for needle, desc in _SERVICE_FALLBACKS:
        if needle in service_key:
            return PortDescription(
                desc.name,
                desc.purpose,
                desc.security_concern,
            )
    label = service or "Unknown"
    return PortDescription(
        label,
        f"Network service listening on port {port} ({label}).",
        "Review whether this port must be internet-facing and keep the service patched.",
    )
