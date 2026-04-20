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
    confidence: int = 0  # 0-100% confidence score

class ServiceDetector:
    PORT_SERVICE_MAP = {
        21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
        110: "pop3", 143: "imap", 443: "https", 445: "smb", 3306: "mysql",
        3389: "rdp", 5432: "postgresql", 5900: "vnc", 6379: "redis",
        8080: "http", 8443: "https", 27017: "mongodb", 9200: "elasticsearch",
        11211: "memcached"
    }

    BANNER_PATTERNS = [
        # SSH - High confidence patterns
        (re.compile(r"SSH-(\d+\.\d+)-([\w\.\-]+)", re.IGNORECASE), "ssh", 95),
        (re.compile(r"SSH-(\d+\.\d+)", re.IGNORECASE), "ssh", 85),
        
        # FTP - High confidence patterns
        (re.compile(r"220.*FTP.*ready", re.IGNORECASE), "ftp", 90),
        (re.compile(r"220.*File Transfer Protocol", re.IGNORECASE), "ftp", 90),
        (re.compile(r"220.*vsftpd", re.IGNORECASE), "ftp", 95),
        (re.compile(r"220.*Microsoft FTP Service", re.IGNORECASE), "ftp", 95),
        (re.compile(r"220.*", re.IGNORECASE), "ftp", 60),  # Generic FTP response
        
        # SMTP - High confidence patterns
        (re.compile(r"220.*SMTP.*ready", re.IGNORECASE), "smtp", 90),
        (re.compile(r"220.*ESMTP", re.IGNORECASE), "smtp", 90),
        (re.compile(r"220.*Postfix", re.IGNORECASE), "smtp", 95),
        (re.compile(r"220.*Microsoft ESMTP", re.IGNORECASE), "smtp", 95),
        (re.compile(r"220.*mail", re.IGNORECASE), "smtp", 70),
        
        # POP3 - High confidence patterns
        (re.compile(r"\+OK.*POP3.*ready", re.IGNORECASE), "pop3", 90),
        (re.compile(r"\+OK.*POP3 server", re.IGNORECASE), "pop3", 90),
        (re.compile(r"\+OK.*Dovecot", re.IGNORECASE), "pop3", 95),
        (re.compile(r"\+OK.*Courier", re.IGNORECASE), "pop3", 95),
        (re.compile(r"\+OK.*", re.IGNORECASE), "pop3", 50),  # Generic POP3 response
        
        # IMAP - High confidence patterns
        (re.compile(r"\* OK.*IMAP4.*ready", re.IGNORECASE), "imap", 90),
        (re.compile(r"\* OK.*IMAP4rev1", re.IGNORECASE), "imap", 90),
        (re.compile(r"\* OK.*Dovecot", re.IGNORECASE), "imap", 95),
        (re.compile(r"\* OK.*Courier", re.IGNORECASE), "imap", 95),
        (re.compile(r"\* OK.*Microsoft Exchange", re.IGNORECASE), "imap", 95),
        (re.compile(r"\* OK.*", re.IGNORECASE), "imap", 40),  # Generic IMAP response
        
        # HTTP/HTTPS - High confidence patterns
        (re.compile(r"HTTP/1\.[01]\s+\d+.*", re.IGNORECASE), "http", 90),
        (re.compile(r"Server:.*Apache", re.IGNORECASE), "http", 85),
        (re.compile(r"Server:.*nginx", re.IGNORECASE), "http", 85),
        (re.compile(r"Server:.*IIS", re.IGNORECASE), "http", 85),
        
        # Database services
        (re.compile(r"mysql|MariaDB", re.IGNORECASE), "mysql", 90),
        (re.compile(r"PostgreSQL", re.IGNORECASE), "postgresql", 95),
        (re.compile(r"\+PONG", re.IGNORECASE), "redis", 95),
        (re.compile(r"-ERR|REDIS", re.IGNORECASE), "redis", 85),
        (re.compile(r"MongoDB", re.IGNORECASE), "mongodb", 95),
        
        # Search and caching services
        (re.compile(r"elasticsearch|Elastic", re.IGNORECASE), "elasticsearch", 95),
        (re.compile(r"memcached", re.IGNORECASE), "memcached", 95),
        
        # Remote access services
        (re.compile(r"login:|telnet", re.IGNORECASE), "telnet", 80),
        (re.compile(r"RFB \d{3}\.\d{3}", re.IGNORECASE), "vnc", 95),  # VNC Remote Frame Buffer
        (re.compile(r"RDP", re.IGNORECASE), "rdp", 85),
        
        # Network management
        (re.compile(r"SNMP", re.IGNORECASE), "snmp", 85),
        
        # Real-time and communication
        (re.compile(r"SIP/2\.0", re.IGNORECASE), "sip", 95),
        (re.compile(r"RTSP/1\.0", re.IGNORECASE), "rtsp", 95),
        
        # Container and orchestration APIs
        (re.compile(r"Docker", re.IGNORECASE), "docker-api", 90),
        (re.compile(r"kubernetes|k8s", re.IGNORECASE), "kubernetes-api", 90),
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
        # SSH
        22: ("ssh", b"SSH-2.0-OpenSSH_Probe\r\n"),
        
        # FTP
        21: ("ftp", b""),  # FTP sends banner immediately
        
        # SMTP
        25: ("smtp", b"EHLO probe.local\r\n"),
        587: ("smtp", b"EHLO probe.local\r\n"),  # SMTP submission
        
        # POP3
        110: ("pop3", b""),  # POP3 sends banner immediately
        995: ("pop3", b""),  # POP3S
        
        # IMAP
        143: ("imap", b""),  # IMAP sends banner immediately
        993: ("imap", b""),  # IMAPS
        
        # Database services
        3306: ("mysql", b"\x00\x00\x00\x00"),  # MySQL handshake
        5432: ("postgresql", b"\x00\x00\x00\x08\x04\xd2\x16\x2f"),  # PostgreSQL startup
        6379: ("redis", b"PING\r\n"),
        27017: ("mongodb", b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xd4\x07\x00\x00\x00\x00\x00\x00admin.$cmd\x00\x00\x00\x00\x00\x01\x00\x00\x00\x1f\x00\x00\x00\x01ismaster\x00\x01\x00\x00\x00\x00"),  # MongoDB ismaster
        
        # Search and caching
        9200: ("elasticsearch", b"GET / HTTP/1.0\r\n\r\n"),
        11211: ("memcached", b"version\r\n"),
        
        # Remote access
        23: ("telnet", b"\xff\xfd\x01"),  # IAC DONT
        3389: ("rdp", b""),  # RDP detected by port + TLS
        5900: ("vnc", b""),  # VNC sends RFB version immediately
        
        # Network management
        161: ("snmp", b"\x30\x26\x02\x01\x01\x04\x06public\xa0\x19\x02\x04\x00\x00\x00\x00"),  # SNMP GET request
        162: ("snmp", b"\x30\x26\x02\x01\x01\x04\x06public\xa0\x19\x02\x04\x00\x00\x00\x00"),  # SNMP trap
        
        # Real-time communication
        5060: ("sip", b"OPTIONS sip:probe@localhost SIP/2.0\r\nVia: SIP/2.0/UDP probe\r\nFrom: <sip:probe@localhost>\r\nTo: <sip:probe@localhost>\r\nCall-ID: probe\r\nCSeq: 1 OPTIONS\r\n\r\n"),
        5061: ("sip", b"OPTIONS sip:probe@localhost SIP/2.0\r\nVia: SIP/2.0/TCP probe\r\nFrom: <sip:probe@localhost>\r\nTo: <sip:probe@localhost>\r\nCall-ID: probe\r\nCSeq: 1 OPTIONS\r\n\r\n"),
        554: ("rtsp", b"OPTIONS rtsp://localhost/ RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: probe\r\n\r\n"),
        
        # Container and orchestration APIs
        2375: ("docker-api", b"GET /version HTTP/1.1\r\nHost: localhost\r\n\r\n"),  # Docker API
        2376: ("docker-api", b"GET /version HTTP/1.1\r\nHost: localhost\r\n\r\n"),  # Docker API TLS
        6443: ("kubernetes-api", b"GET /api HTTP/1.1\r\nHost: localhost\r\n\r\n"),  # Kubernetes API
        8080: ("kubernetes-api", b"GET /api HTTP/1.1\r\nHost: localhost\r\n\r\n"),  # Kubernetes API alternative
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
            
            # Enhanced parsing with confidence calculation
            confidence = 0
            version = None
            
            if service_name == "ssh" and banner.startswith("SSH-"):
                version = banner.split()[0].split('-')[1] if '-' in banner.split()[0] else None
                confidence = 95 if version and "OpenSSH" in banner else 85
            elif service_name == "ftp" and "220" in banner:
                confidence = 95 if any(impl in banner.lower() for impl in ["vsftpd", "proftpd", "microsoft"]) else 80
            elif service_name == "smtp" and ("220" in banner or "250" in banner):
                confidence = 95 if any(impl in banner.lower() for impl in ["postfix", "exim", "microsoft"]) else 80
            elif service_name == "pop3" and "+OK" in banner:
                confidence = 95 if any(impl in banner.lower() for impl in ["dovecot", "courier"]) else 75
            elif service_name == "imap" and "* OK" in banner:
                confidence = 95 if any(impl in banner.lower() for impl in ["dovecot", "courier", "exchange"]) else 75
            elif service_name == "mysql" and data:
                # Parse MySQL server version
                if len(data) > 4:
                    version_len = data[3]
                    if len(data) > 4 + version_len:
                        version = data[4:4+version_len].decode('utf-8', errors='ignore')
                confidence = 90 if version else 75
            elif service_name == "postgresql" and data:
                confidence = 85  # PostgreSQL binary response
            elif service_name == "redis" and "+PONG" in banner:
                confidence = 95
            elif service_name == "mongodb" and data:
                confidence = 85  # MongoDB binary response
            elif service_name == "elasticsearch" and data:
                confidence = 90 if "elasticsearch" in banner.lower() else 75
            elif service_name == "memcached" and data:
                confidence = 90 if "version" in banner.lower() else 75
            elif service_name == "vnc" and "RFB" in banner:
                confidence = 95
            elif service_name == "telnet":
                confidence = 70 if "login:" in banner.lower() else 50
            elif service_name == "rdp":
                confidence = 80  # RDP detected by successful connection
            elif service_name == "snmp" and data:
                confidence = 75  # SNMP binary response
            elif service_name == "sip" and "SIP" in banner:
                confidence = 90
            elif service_name == "rtsp" and "RTSP" in banner:
                confidence = 90
            elif service_name == "docker-api" and data:
                confidence = 90 if "docker" in banner.lower() else 75
            elif service_name == "kubernetes-api" and data:
                confidence = 90 if "kubernetes" in banner.lower() or "k8s" in banner.lower() else 75
            else:
                confidence = 60 if banner else 40
                
            return ServiceInfo(name=service_name, version=version, banner=banner, confidence=confidence)
        except Exception:
            return None
    async def detect(self, host: str, port: int, timeout: float = 3.0) -> ServiceInfo:
        adaptive_timeout = self.get_timeout(port)
        
        # Stage 1: Banner grab with pattern matching
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
            
            # Enhanced pattern matching with confidence scoring
            best_match = None
            best_confidence = 0
            
            for pattern, service_name, confidence in self.BANNER_PATTERNS:
                match = pattern.search(banner)
                if match:
                    version = match.group(1) if match.groups() else None
                    # Boost confidence for version matches
                    actual_confidence = confidence
                    if version:
                        actual_confidence = min(100, confidence + 5)
                    
                    if actual_confidence > best_confidence:
                        best_match = ServiceInfo(name=service_name, version=version, banner=banner, confidence=actual_confidence)
                        best_confidence = actual_confidence
            
            if best_match:
                return best_match
                
            # Fallback to port-based detection with lower confidence
            if port in self.PORT_SERVICE_MAP:
                return ServiceInfo(name=self.PORT_SERVICE_MAP[port], version=None, banner=banner, confidence=50)
                
            return ServiceInfo(name="unknown", version=None, banner=banner, confidence=20)
                
        except Exception:
            # Stage 2: Protocol-specific probe if banner grab failed
            probed = await self.probe_protocol(host, port)
            if probed:
                return probed
            
            # Stage 3: Final fallback - port-based guess with very low confidence
            if port in self.PORT_SERVICE_MAP:
                return ServiceInfo(name=self.PORT_SERVICE_MAP[port], version=None, banner=None, confidence=30)
                
            return ServiceInfo(name="unknown", version=None, banner=None, confidence=10)
