"""Human-readable port service descriptions for tooltips and UI."""

from __future__ import annotations

from dataclasses import dataclass

from cybersec.core.tools.port_registry import PORT_REGISTRY


@dataclass(frozen=True)
class PortDescription:
    name: str
    purpose: str
    security_concern: str


_SERVICE_FALLBACKS: list[tuple[str, PortDescription]] = [
    ("ssh", PortDescription(
        "SSH",
        "Secure remote login protocol for shell access and tunneling.",
        "Can be brute-forced if exposed publicly or weak keys/passwords are used.",
    )),
    ("ftp", PortDescription(
        "FTP",
        "File Transfer Protocol for uploading and downloading files.",
        "Credentials and data travel in cleartext; anonymous uploads may be enabled.",
    )),
    ("telnet", PortDescription(
        "Telnet",
        "Legacy remote terminal access to network devices and servers.",
        "All traffic including passwords is sent unencrypted — high interception risk.",
    )),
    ("http", PortDescription(
        "HTTP",
        "Unencrypted web traffic for websites and APIs.",
        "Traffic can be intercepted or modified; outdated web apps increase exploit risk.",
    )),
    ("https", PortDescription(
        "HTTPS",
        "Encrypted web traffic using TLS for websites and APIs.",
        "Certificate or TLS misconfiguration can still weaken confidentiality.",
    )),
    ("mysql", PortDescription(
        "MySQL",
        "Popular relational database server for application data storage.",
        "Exposed databases are scanned for weak credentials and SQL injection chains.",
    )),
    ("redis", PortDescription(
        "Redis",
        "In-memory key-value store used for caching and messaging.",
        "Frequently left without authentication, allowing remote command execution.",
    )),
    ("mongodb", PortDescription(
        "MongoDB",
        "Document-oriented NoSQL database for modern applications.",
        "Historically many deployments allowed unauthenticated access from the internet.",
    )),
    ("rdp", PortDescription(
        "RDP",
        "Remote Desktop Protocol for graphical Windows administration.",
        "Common brute-force and exploit target when reachable from the internet.",
    )),
    ("vnc", PortDescription(
        "VNC",
        "Virtual Network Computing for remote desktop viewing and control.",
        "Often protected only by a password; many instances lack encryption.",
    )),
    ("smtp", PortDescription(
        "SMTP",
        "Simple Mail Transfer Protocol for sending email between servers.",
        "Open relays and user enumeration can enable spam or phishing abuse.",
    )),
    ("dns", PortDescription(
        "DNS",
        "Domain Name System for resolving hostnames to IP addresses.",
        "Zone transfers and recursion misconfigurations may leak internal network data.",
    )),
]


def get_port_description(port: int, service: str | None = None) -> PortDescription:
    info = PORT_REGISTRY.get(port)
    if info is not None:
        return PortDescription(info.service, info.purpose, info.security_concern)

    service_key = (service or "").lower()
    for needle, desc in _SERVICE_FALLBACKS:
        if needle in service_key:
            return PortDescription(desc.name, desc.purpose, desc.security_concern)

    label = service or "Unknown"
    return PortDescription(
        label,
        f"Network service listening on port {port} ({label}).",
        "Review whether this port must be internet-facing and keep the service patched.",
    )
