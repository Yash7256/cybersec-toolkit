import asyncio
import re
import shutil
import logging
from dataclasses import dataclass

logger = logging.getLogger(__name__)

@dataclass
class ServiceDetectionResult:
    port: int
    state: str
    service_name: str
    service_version: str        # empty string if unknown
    detection_method: str       # "banner", "probe", "port_lookup", "nmap"
    banner_snippet: str         # first 80 chars of raw banner, empty if none
    confidence: float           # 1.0 = certain, 0.8 = probe match, 0.5 = port lookup


class ServiceDetector:
    PORT_SERVICE_MAP = {
        21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
        110: "pop3", 143: "imap", 443: "https", 445: "smb", 3306: "mysql",
        3389: "rdp", 5432: "postgresql", 5900: "vnc", 6379: "redis",
        8080: "http", 8443: "https", 27017: "mongodb", 9200: "elasticsearch",
        11211: "memcached", 8000: "http-alt", 9000: "http-alt", 8008: "http",
        8888: "http-alt"
    }

    # Stage 2 patterns
    SERVICE_PATTERNS = [
        ("redis", re.compile(r"^\*\d+\r\n", re.IGNORECASE)),
        ("redis", re.compile(r"-ERR|PONG|\+OK", re.IGNORECASE)),
        ("postgresql", re.compile(r"invalid packet length|pg_hba|PostgreSQL|FATAL", re.IGNORECASE)),
        ("ssh", re.compile(r"^SSH-\d+\.\d+", re.IGNORECASE)),
        ("ftp", re.compile(r"^220[\s-].*FTP|FileZilla|vsftpd|ProFTPD", re.IGNORECASE)),
        ("smtp", re.compile(r"^220[\s-].*SMTP|Postfix|Sendmail|ESMTP", re.IGNORECASE)),
        ("http", re.compile(r"^HTTP/\d|Content-Type:|Server:", re.IGNORECASE)),
        ("mysql", re.compile(r"^\x4a\x00\x00\x00|\x00\x00\x00", re.IGNORECASE)),
        ("mysql", re.compile(r"mysql_native_password", re.IGNORECASE)),
        ("mongodb", re.compile(r"mongod|MongoDB", re.IGNORECASE)),
        ("telnet", re.compile(r"^\xff[\xfb-\xfe]", re.IGNORECASE)),
    ]

    # Stage 3 probes
    PROBES = [
        (b"PING\r\n", "redis", b"+PONG"),
        (b"HEAD / HTTP/1.0\r\n\r\n", "http", b"HTTP/"),
        (b"\x00\x00\x00\x08\x04\xd2\x16\x2f", "postgresql", b"N"), # N or E
        (b"\x00\x00\x00\x08\x04\xd2\x16\x2f", "postgresql", b"E"),
        (b"\x0e\x00\x00\x00\x0a", "mysql", b""), # Check mysql greeting logic below
        (b"", "ssh", b"SSH-"), # SSH sends immediately
    ]

    async def detect(self, host: str, port: int, timeout: float = 3.0) -> ServiceDetectionResult:
        # We will track state and fallback
        state = "open"
        banner_bytes = b""
        banner_snippet = ""
        service_name = ""
        service_version = ""
        detection_method = ""
        confidence = 0.0

        # STAGE 1: Banner Grabbing
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
            
            # Send generic HTTP probe
            http_probe = f"GET / HTTP/1.0\r\nHost: {host}\r\n\r\n".encode()
            writer.write(http_probe)
            await writer.drain()
            
            try:
                banner_bytes = await asyncio.wait_for(reader.read(1024), timeout=3.0)
            except asyncio.TimeoutError:
                banner_bytes = b""
                
            if not banner_bytes:
                # Send null byte probe
                writer.write(b"\x00")
                await writer.drain()
                try:
                    banner_bytes = await asyncio.wait_for(reader.read(1024), timeout=3.0)
                except asyncio.TimeoutError:
                    banner_bytes = b""

            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
                
        except Exception:
            state = "filtered"

        if banner_bytes:
            decoded_banner = banner_bytes.decode(errors='replace')
            banner_snippet = decoded_banner[:80]
            
            # STAGE 2: Banner Pattern Matching
            for svc, pattern in self.SERVICE_PATTERNS:
                # We can match on decoded string or raw bytes. Pattern library is string based.
                if pattern.search(decoded_banner):
                    service_name = svc
                    detection_method = "banner"
                    confidence = 1.0
                    break
            
            if not service_name and banner_snippet.strip():
                # Netcat / Raw generic fallback
                service_name = f"unknown-service (banner: {banner_snippet[:40]})"
                detection_method = "banner"
                confidence = 0.9

        # STAGE 3: Protocol Probing
        if not service_name and state == "open":
            for probe_payload, svc, expected_response in self.PROBES:
                try:
                    reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
                    if probe_payload:
                        writer.write(probe_payload)
                        await writer.drain()
                    
                    probe_resp = await asyncio.wait_for(reader.read(1024), timeout=2.0)
                    
                    writer.close()
                    try:
                        await writer.wait_closed()
                    except Exception:
                        pass
                        
                    if not probe_resp:
                        continue
                        
                    if svc == "mysql" and b"mysql_native_password" in probe_resp:
                        service_name = "mysql"
                        detection_method = "probe"
                        confidence = 0.8
                        banner_snippet = probe_resp.decode(errors='replace')[:80]
                        break
                    elif expected_response and probe_resp.startswith(expected_response):
                        service_name = svc
                        detection_method = "probe"
                        confidence = 0.8
                        banner_snippet = probe_resp.decode(errors='replace')[:80]
                        break
                        
                except Exception:
                    continue

        # STAGE 4: Port Number Fallback
        if not service_name and state == "open":
            if port in self.PORT_SERVICE_MAP:
                service_name = self.PORT_SERVICE_MAP[port]
                detection_method = "port_lookup"
                confidence = 0.5

        # STAGE 5: NMAP Service Probe Database Fallback
        if not service_name and state == "open":
            nmap_path = shutil.which('nmap')
            if nmap_path:
                try:
                    # Run nmap version detection
                    cmd = [nmap_path, "-sV", "-p", str(port), host, "--version-intensity", "5", "-oX", "-"]
                    proc = await asyncio.create_subprocess_exec(
                        *cmd,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE
                    )
                    stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=15.0)
                    
                    if stdout:
                        xml_output = stdout.decode(errors='ignore')
                        # Regex to parse XML for service name and version
                        svc_match = re.search(r'<service name="([^"]+)"', xml_output)
                        ver_match = re.search(r'version="([^"]+)"', xml_output)
                        
                        if svc_match:
                            service_name = svc_match.group(1)
                            detection_method = "nmap"
                            confidence = 0.7
                            if ver_match:
                                service_version = ver_match.group(1)
                except Exception:
                    pass

        # If everything fails
        if not service_name:
            service_name = "unknown"
            detection_method = "unknown"
            confidence = 0.0

        return ServiceDetectionResult(
            port=port,
            state=state,
            service_name=service_name,
            service_version=service_version,
            detection_method=detection_method,
            banner_snippet=banner_snippet,
            confidence=confidence
        )
