"""
Service detection logic.
"""
import asyncio
import re
from dataclasses import dataclass
from typing import Optional

@dataclass
class ServiceInfo:
    name: str
    version: Optional[str] = None
    banner: Optional[str] = None

class ServiceDetector:
    PORT_SERVICE_MAP = {
        21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
        110: "pop3", 143: "imap", 443: "https", 445: "smb", 3306: "mysql",
        3389: "rdp", 5432: "postgresql", 5900: "vnc", 6379: "redis",
        8080: "http", 8443: "https", 27017: "mongodb", 9200: "elasticsearch",
        11211: "memcached"
    }

    BANNER_PATTERNS = [
        (re.compile(r"SSH-(\S+)"), "ssh"),
        (re.compile(r"220.*FTP", re.IGNORECASE), "ftp"),
        (re.compile(r"220.*SMTP|220.*mail", re.IGNORECASE), "smtp"),
        (re.compile(r"HTTP/\d", re.IGNORECASE), "http"),
        (re.compile(r"mysql|MariaDB", re.IGNORECASE), "mysql"),
        (re.compile(r"PostgreSQL", re.IGNORECASE), "postgresql"),
        (re.compile(r"\+PONG|-ERR|REDIS", re.IGNORECASE), "redis"),
        (re.compile(r"MongoDB", re.IGNORECASE), "mongodb"),
        (re.compile(r"login:|telnet", re.IGNORECASE), "telnet"),
    ]
    TIMEOUT_PROFILE = {
        (80, 80): 1.5,
        (443, 443): 1.5,
        (22, 22): 1.5,
        (23, 23): 5.0,
        (21, 21): 5.0,
        (137, 137): 5.0,
    }

    def get_timeout(self, port: int) -> float:
        for (start, end), timeout in self.TIMEOUT_PROFILE.items():
            if start <= port <= end:
                return timeout
        return 3.0

    SERVICE_PROBES = {
        22: ("ssh", b"SSH-2.0-OpenSSH_Probe\r\n"),
        21: ("ftp", b""),
        25: ("smtp", b"EHLO probe.local\r\n"),
        3306: ("mysql", b"\x00\x00\x00\x00"),  # MySQL handshake
        6379: ("redis", b"PING\r\n"),
        27017: ("mongodb", b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xd4\x07\x00\x00\x00\x00\x00\x00admin.$cmd\x00\x00\x00\x00\x00\x01\x00\x00\x00\x1f\x00\x00\x00\x01ismaster\x00\x01\x00\x00\x00\x00"),  # MongoDB handshake
        23: ("telnet", b"\xff\xfd\x01"),  # IAC DONT
        3389: ("rdp", b""),  # RDP detected by port + TLS
    }

    async def probe_protocol(self, host: str, port: int) -> Optional[ServiceInfo]:
        if port not in self.SERVICE_PROBES:
            return None
        service_name, payload = self.SERVICE_PROBES[port]
        adaptive_timeout = self.get_timeout(port)
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), adaptive_timeout)
            if payload:
                writer.write(payload)
                await asyncio.wait_for(writer.drain(), adaptive_timeout)
            data = await asyncio.wait_for(reader.read(1024), adaptive_timeout)
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            banner = data.decode('utf-8', errors='ignore').replace('\x00', '').strip()
            # Parse based on service
            if service_name == "ssh" and banner.startswith("SSH-"):
                version = banner.split()[0].split('-')[1] if '-' in banner.split()[0] else None
                return ServiceInfo(name=service_name, version=version, banner=banner)
            elif service_name == "ftp" and "220" in banner:
                return ServiceInfo(name=service_name, version=None, banner=banner)
            elif service_name == "smtp" and "250" in banner:
                return ServiceInfo(name=service_name, version=None, banner=banner)
            elif service_name == "mysql" and data:
                # Parse MySQL server version
                version = None
                if len(data) > 4:
                    version_len = data[3]
                    if len(data) > 4 + version_len:
                        version = data[4:4+version_len].decode('utf-8', errors='ignore')
                return ServiceInfo(name=service_name, version=version, banner=banner)
            elif service_name == "redis" and "+PONG" in banner:
                return ServiceInfo(name=service_name, version=None, banner=banner)
            elif service_name == "mongodb" and data:
                # Parse MongoDB response
                return ServiceInfo(name=service_name, version=None, banner=banner)
            elif service_name == "telnet":
                return ServiceInfo(name=service_name, version=None, banner=banner)
            elif service_name == "rdp":
                # For RDP, check if TLS handshake succeeds
                return ServiceInfo(name=service_name, version=None, banner=banner)
            return ServiceInfo(name=service_name, version=None, banner=banner)
        except Exception:
            return None
    async def detect(self, host: str, port: int, timeout: float = 3.0) -> ServiceInfo:
        adaptive_timeout = self.get_timeout(port)
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), adaptive_timeout)
            
            if port in [80, 8080, 8443, 443]:
                writer.write(b"HEAD / HTTP/1.0\r\n\r\n")
            else:
                writer.write(b"\r\n")
            await asyncio.wait_for(writer.drain(), adaptive_timeout)
            
            data = await asyncio.wait_for(reader.read(1024), adaptive_timeout)
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
                
            # Decode banner and strip null bytes that break UTF-8 inserts into Postgres
            banner = data.decode('utf-8', errors='ignore').replace('\x00', '').strip()
            
            for pattern, service_name in self.BANNER_PATTERNS:
                match = pattern.search(banner)
                if match:
                    version = match.group(1) if match.groups() else None
                    return ServiceInfo(name=service_name, version=version, banner=banner)
                    
            if port in self.PORT_SERVICE_MAP:
                return ServiceInfo(name=self.PORT_SERVICE_MAP[port], version=None, banner=banner)
                
            return ServiceInfo(name="unknown", version=None, banner=banner)
        except Exception:
            # If banner grab failed, try protocol-specific probe
            probed = await self.probe_protocol(host, port)
            if probed:
                return probed
            return ServiceInfo(name="unknown", version=None, banner=None)
