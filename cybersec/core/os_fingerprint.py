import logging
import re

logger = logging.getLogger(__name__)


class OSFingerprinter:
    WINDOWS_BANNERS = [
        (re.compile(r"^SMB", re.IGNORECASE), "Windows (SMB)"),
        (re.compile(r"microsoft-ds", re.IGNORECASE), "Windows (SMB)"),
        (re.compile(r"rdp", re.IGNORECASE), "Windows (RDP)"),
        (re.compile(r"mssql", re.IGNORECASE), "Windows (MSSQL)"),
        (re.compile(r"msrpc", re.IGNORECASE), "Windows"),
        (re.compile(r"netbios", re.IGNORECASE), "Windows (NetBIOS)"),
    ]

    UNIX_BANNERS = [
        (re.compile(r"^SSH-([\d.]+)-OpenSSH[_-](\d+)", re.IGNORECASE), "Unix/Linux"),
        (re.compile(r"OpenSSH[_-](\d+)", re.IGNORECASE), "Unix/Linux"),
        (re.compile(r"Ubuntu", re.IGNORECASE), "Ubuntu Linux"),
        (re.compile(r"Debian", re.IGNORECASE), "Debian Linux"),
        (re.compile(r"CentOS", re.IGNORECASE), "CentOS Linux"),
        (re.compile(r"Red Hat", re.IGNORECASE), "Red Hat Linux"),
        (re.compile(r"Fedora", re.IGNORECASE), "Fedora Linux"),
        (re.compile(r"FreeBSD", re.IGNORECASE), "FreeBSD"),
        (re.compile(r"OpenBSD", re.IGNORECASE), "OpenBSD"),
        (re.compile(r"NetBSD", re.IGNORECASE), "NetBSD"),
    ]

    APPLIANCE_BANNERS = [
        (re.compile(r"Apache", re.IGNORECASE), "Web Server (Generic)"),
        (re.compile(r"nginx", re.IGNORECASE), "Web Server (Nginx)"),
        (re.compile(r"lighttpd", re.IGNORECASE), "Web Server (Lighttpd)"),
        (re.compile(r"caddy", re.IGNORECASE), "Web Server (Caddy)"),
        (re.compile(r"Cisco", re.IGNORECASE), "Cisco Device"),
        (re.compile(r"MikroTik", re.IGNORECASE), "MikroTik Router"),
    ]

    def fingerprint(self, banner: str, port: int) -> str | None:
        if not banner:
            return None

        combined_banners = (
            self.WINDOWS_BANNERS + self.UNIX_BANNERS + self.APPLIANCE_BANNERS
        )

        for pattern, os_hint in combined_banners:
            if pattern.search(banner):
                return os_hint

        if port in {22} and "SSH" in banner:
            return "Unix/Linux"
        if port in {21} and ("220" in banner or "FTP" in banner):
            return "Unix/Linux"
        if port in {25, 587} and ("ESMTP" in banner or "220" in banner):
            return "Mail Server"
        if port in {3306}:
            return "Database Server"
        if port in {5432}:
            return "PostgreSQL Server"
        if port in {6379}:
            return "Redis Server"
        if port in {27017}:
            return "MongoDB Server"
        if port in {9200}:
            return "Elasticsearch Server"
        if port in {11211}:
            return "Memcached Server"

        return None
