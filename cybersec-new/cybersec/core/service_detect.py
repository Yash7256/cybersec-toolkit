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

    async def detect(self, host: str, port: int, timeout: float = 3.0) -> ServiceInfo:
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout)
            
            if port in [80, 8080, 8443, 443]:
                writer.write(b"HEAD / HTTP/1.0\r\n\r\n")
            else:
                writer.write(b"\r\n")
            await asyncio.wait_for(writer.drain(), timeout)
            
            data = await asyncio.wait_for(reader.read(1024), timeout)
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
            return ServiceInfo(name="unknown", version=None, banner=None)
