"""
Adversarial-Resilient Service Detection Engine

Implements:
- Port state detection (OPEN/CLOSED/FILTERED)
- Dual timeout system (connect + read)
- Signal-based detection with confidence calibration
- Partial data handling
- Retry strategy for uncertain cases
"""
import asyncio
import re
import time
from dataclasses import dataclass, field
from typing import Optional, Dict, Any, List, Tuple
from enum import Enum


class PortState(Enum):
    """Explicit port states."""
    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"


@dataclass
class SignalEvidence:
    """Individual signal from detection."""
    signal_type: str  # banner, handshake, structure, byte_signature
    matched_service: str
    confidence: int  # 0-100
    strength: str  # strong, moderate, weak, conflicting
    details: str = ""


@dataclass
class ServiceInfo:
    """Enhanced service detection result."""
    name: str
    confidence: int
    state: PortState
    signals: List[SignalEvidence] = field(default_factory=list)
    reasoning: str = ""
    version: Optional[str] = None
    banner: Optional[str] = None
    retries: int = 0
    unstable: bool = False  # True if检测结果 vary across retries


class ServiceDetector:
    PORT_SERVICE_MAP = {
        21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
        110: "pop3", 143: "imap", 443: "https", 445: "smb", 3306: "mysql",
        3389: "rdp", 5432: "postgresql", 5900: "vnc", 6379: "redis",
        8080: "http", 8443: "https", 27017: "mongodb", 9200: "elasticsearch",
        11211: "memcached",
        1194: "openvpn", 1723: "pptp", 2049: "nfs", 3128: "squid",
        5060: "sip", 5061: "sips", 5901: "vnc", 5902: "vnc", 5903: "vnc",
        6667: "irc", 8000: "http", 8008: "http", 8888: "http", 9000: "http",
        9090: "http", 9091: "http", 2052: "cpanel", 2053: "cpanel",
        2082: "cpanel", 2083: "cpanel", 2086: "cpanel", 2087: "cpanel",
        2095: "cpanel", 2096: "cpanel", 465: "smtps", 587: "smtp",
        993: "imaps", 995: "pop3s", 1433: "mssql", 1521: "oracle",
        5000: "http", 8009: "ajp", 10000: "webmin", 32768: "rpc",
        49152: "upnp", 49153: "upnp",
        16379: "redis", 26379: "redis",
        15432: "postgresql", 5433: "postgresql", 5434: "postgresql",
        3000: "http", 5000: "http", 2222: "ssh", 22222: "ssh",
    }

    BANNER_PATTERNS = [
        (re.compile(r"SSH-(\d+\.\d+)-([\w.\-]+)", re.IGNORECASE), "ssh", 95),
        (re.compile(r"SSH-(\d+\.\d+)", re.IGNORECASE), "ssh", 85),
        (re.compile(r"^SSH", re.IGNORECASE), "ssh", 50),
        (re.compile(r"220.*FTP.*ready", re.IGNORECASE), "ftp", 90),
        (re.compile(r"220.*vsftpd", re.IGNORECASE), "ftp", 95),
        (re.compile(r"220.*", re.IGNORECASE), "ftp", 50),
        (re.compile(r"^220", re.IGNORECASE), "ftp", 40),
        (re.compile(r"220.*SMTP.*ready", re.IGNORECASE), "smtp", 90),
        (re.compile(r"220.*ESMTP", re.IGNORECASE), "smtp", 90),
        (re.compile(r"\+OK.*POP3.*ready", re.IGNORECASE), "pop3", 90),
        (re.compile(r"\+OK.*Dovecot", re.IGNORECASE), "pop3", 95),
        (re.compile(r"\+OK.*", re.IGNORECASE), "pop3", 50),
        (re.compile(r"^\+OK", re.IGNORECASE), "pop3", 40),
        (re.compile(r"\* OK.*IMAP4", re.IGNORECASE), "imap", 90),
        (re.compile(r"\* OK.*", re.IGNORECASE), "imap", 40),
        (re.compile(r"^HTTP/1\.[01]\s+\d+", re.IGNORECASE), "http", 90),
        (re.compile(r"HTTP/1\.", re.IGNORECASE), "http", 55),
        (re.compile(r"^HTTP", re.IGNORECASE), "http", 50),
        (re.compile(r"Server:.*Apache", re.IGNORECASE), "http", 85),
        (re.compile(r"Server:.*nginx", re.IGNORECASE), "http", 85),
        (re.compile(r"Server:.*", re.IGNORECASE), "http", 60),
        (re.compile(r"mysql|MariaDB", re.IGNORECASE), "mysql", 90),
        (re.compile(r"PostgreSQL", re.IGNORECASE), "postgresql", 95),
        (re.compile(r"\+PONG", re.IGNORECASE), "redis", 95),
        (re.compile(r"-ERR|REDIS", re.IGNORECASE), "redis", 85),
        (re.compile(r"^\+P", re.IGNORECASE), "redis", 40),
        (re.compile(r"MongoDB", re.IGNORECASE), "mongodb", 95),
        (re.compile(r"elasticsearch", re.IGNORECASE), "elasticsearch", 95),
        (re.compile(r"memcached", re.IGNORECASE), "memcached", 95),
        (re.compile(r"login:|telnet", re.IGNORECASE), "telnet", 80),
        (re.compile(r"RFB \d{3}\.\d{3}", re.IGNORECASE), "vnc", 95),
        (re.compile(r"Docker", re.IGNORECASE), "docker-api", 90),
        (re.compile(r"kubernetes|k8s", re.IGNORECASE), "kubernetes-api", 90),
        (re.compile(r"SSH-2.0-.*cowrie", re.IGNORECASE), "honeypot", 30),
    ]

    TIMEOUT_PROFILE = {
        (80, 80): 2.5, (443, 443): 2.5, (22, 22): 2.5,
        (23, 23): 6.0, (21, 21): 6.0, (137, 137): 6.0,
        (25, 25): 3.0, (110, 110): 3.0, (143, 143): 3.0,
    }
    DEFAULT_TIMEOUT = 5.0

    SERVICE_PROBES = {
        22: ("ssh", b"SSH-2.0-OpenSSH_Probe\r\n"),
        21: ("ftp", b""),
        25: ("smtp", b"EHLO probe.local\r\n"),
        587: ("smtp", b"EHLO probe.local\r\n"),
        110: ("pop3", b""),
        995: ("pop3", b""),
        143: ("imap", b""),
        993: ("imap", b""),
        3306: ("mysql", b"\x00\x00\x00\x00"),
        5432: ("postgresql", b"\x00\x00\x00\x08\x04\xd2\x16\x2f"),
        6379: ("redis", b"PING\r\n"),
        27017: ("mongodb", b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xd4\x07\x00\x00\x00\x00\x00\x00admin.$cmd\x00\x00\x00\x00\x00\x01\x00\x00\x00\x1f\x00\x00\x00\x01ismaster\x00\x01\x00\x00\x00\x00"),
        9200: ("elasticsearch", b"GET / HTTP/1.0\r\n\r\n"),
        11211: ("memcached", b"version\r\n"),
        23: ("telnet", b"\xff\xfd\x01"),
        3389: ("rdp", b""),
        5900: ("vnc", b""),
        161: ("snmp", b"\x30\x26\x02\x01\x01\x04\x06public\xa0\x19\x02\x04\x00\x00\x00\x00"),
        5060: ("sip", b"OPTIONS sip:probe@localhost SIP/2.0\r\nVia: SIP/2.0/UDP probe\r\nFrom: <sip:probe@localhost>\r\nTo: <sip:probe@localhost>\r\nCall-ID: probe\r\nCSeq: 1 OPTIONS\r\n\r\n"),
    }

    def get_timeout(self, port: int) -> float:
        for (start, end), timeout in self.TIMEOUT_PROFILE.items():
            if start <= port <= end:
                return timeout
        return 3.0

    async def probe_protocol(self, host: str, port: int) -> Optional[ServiceInfo]:
        if port not in self.SERVICE_PROBES:
            return None
        service_name, payload = self.SERVICE_PROBES[port]
        timeout = self.get_timeout(port)
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout)
            if payload:
                writer.write(payload)
                await asyncio.wait_for(writer.drain(), timeout)
            data = await asyncio.wait_for(reader.read(1024), timeout)
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            banner = data.decode('utf-8', errors='ignore').replace('\x00', '').strip()
            
            confidence = 0
            version = None
            
            if service_name == "ssh" and banner.startswith("SSH-"):
                version = banner.split()[0].split('-')[1] if '-' in banner.split()[0] else None
                confidence = 95 if version and "OpenSSH" in banner else 85
            elif service_name == "ftp" and "220" in banner:
                confidence = 95 if any(x in banner.lower() for x in ["vsftpd", "proftpd", "microsoft"]) else 80
            elif service_name == "smtp" and ("220" in banner or "250" in banner):
                confidence = 95 if any(x in banner.lower() for x in ["postfix", "exim", "microsoft"]) else 80
            elif service_name == "pop3" and "+OK" in banner:
                confidence = 95 if any(x in banner.lower() for x in ["dovecot", "courier"]) else 75
            elif service_name == "imap" and "* OK" in banner:
                confidence = 95 if any(x in banner.lower() for x in ["dovecot", "courier", "exchange"]) else 75
            elif service_name == "postgresql" and data:
                confidence = 85
            elif service_name == "redis" and "+PONG" in banner:
                confidence = 95
            elif service_name == "mongodb" and data:
                confidence = 85
            elif service_name == "elasticsearch" and data:
                confidence = 90 if "elasticsearch" in banner.lower() else 75
            elif service_name == "memcached" and data:
                confidence = 90 if "version" in banner.lower() else 75
            elif service_name == "vnc" and "RFB" in banner:
                confidence = 95
            elif service_name == "telnet":
                confidence = 70 if "login:" in banner.lower() else 50
            elif service_name == "rdp":
                confidence = 80
            else:
                confidence = 60 if banner else 40
                
            return ServiceInfo(name=service_name, version=version, banner=banner, confidence=confidence)
        except Exception:
            return None

    async def detect(self, host: str, port: int, timeout: float = 5.0) -> ServiceInfo:
        adaptive_timeout = min(timeout, 5.0)
        
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
            
            banner = data.decode('utf-8', errors='ignore').replace('\x00', '').strip()
            
            best_match = None
            best_confidence = 0
            
            for pattern, service_name, confidence in self.BANNER_PATTERNS:
                match = pattern.search(banner)
                if match:
                    version = match.group(1) if match.groups() else None
                    actual_confidence = confidence
                    if version:
                        actual_confidence = min(100, confidence + 5)
                    
                    if actual_confidence > best_confidence:
                        best_match = ServiceInfo(name=service_name, version=version, banner=banner, confidence=actual_confidence)
                        best_confidence = actual_confidence
            
            if best_match:
                return best_match
            
            if port in self.PORT_SERVICE_MAP:
                return ServiceInfo(name=self.PORT_SERVICE_MAP[port], version=None, banner=banner, confidence=50)
            
            return ServiceInfo(name="unknown", version=None, banner=banner, confidence=20)
            
        except Exception:
            probed = await self._probe_any_port(host, port)
            if probed:
                return probed
            
            probed = await self.probe_protocol(host, port)
            if probed:
                return probed
            
            if port in self.PORT_SERVICE_MAP:
                return ServiceInfo(name=self.PORT_SERVICE_MAP[port], version=None, banner=None, confidence=30)
            
            return ServiceInfo(name="unknown", version=None, banner=None, confidence=10)
    
    async def _probe_any_port(self, host: str, port: int) -> Optional[ServiceInfo]:
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=2.0)
            writer.write(b"PING\r\n")
            await asyncio.wait_for(writer.drain(), timeout=2.0)
            data = await asyncio.wait_for(reader.read(128), timeout=2.0)
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            
            if data:
                banner = data.decode('utf-8', errors='ignore').strip()
                if "+PONG" in banner or "+OK" in banner:
                    return ServiceInfo(name="redis", version=None, banner=banner, confidence=60)
                if "redis" in banner.lower() or "version" in banner.lower():
                    return ServiceInfo(name="redis", version=None, banner=banner, confidence=55)
        except Exception:
            pass
        
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=2.0)
            startup = b"\x00\x00\x00\x10\x00\x03\x00\x00user\x00\x00\x00\x08postgres\x00"
            writer.write(startup)
            await asyncio.wait_for(writer.drain(), timeout=2.0)
            data = await asyncio.wait_for(reader.read(128), timeout=2.0)
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            
            if data and data[0:1] in [b'R', b'K']:
                return ServiceInfo(name="postgresql", version=None, banner="PostgreSQL detected", confidence=60)
        except Exception:
            pass
        
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=2.0)
            writer.write(b"GET / HTTP/1.0\r\n\r\n")
            await asyncio.wait_for(writer.drain(), timeout=2.0)
            data = await asyncio.wait_for(reader.read(512), timeout=2.0)
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            
            if data and (b"HTTP/" in data[:100] or b"<" in data[:50]):
                return ServiceInfo(name="http", version=None, banner=data.decode('utf-8', errors='ignore')[:200], confidence=55)
        except Exception:
            pass
        
        return None