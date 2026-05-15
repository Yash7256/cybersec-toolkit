"""
Service detection with proper TLS/HTTPS support.

Ports 443/8443 (and other TLS ports) now perform a real TLS handshake
with SNI, ALPN negotiation, and certificate extraction before sending
the HTTP probe over the encrypted connection.
"""
import asyncio
import re
import ssl
import logging
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class ServiceDetectionResult:
    port: int
    state: str
    service_name: str
    service_version: str
    detection_method: str
    banner_snippet: str
    confidence: float
    tls_version: str = ""
    alpn: str = ""
    cert_subject: str = ""
    cert_issuer: str = ""


CONNECT_TIMEOUT = 3.0
READ_DEADLINE = 1.5
TOTAL_DETECT_TIMEOUT = 5.0
MAX_BANNER_BYTES = 1024

HTTP_PORTS = {80, 8080, 8000, 8008, 8888, 9200}
TLS_PORTS = {443, 8443}
PASSIVE_PORTS = {22, 23, 25, 110, 143, 445, 993, 995, 3306, 5432, 6379, 27017}


class ServiceDetector:
    PORT_SERVICE_MAP = {
        21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
        110: "pop3", 143: "imap", 443: "https", 445: "smb", 3306: "mysql",
        3389: "rdp", 5432: "postgresql", 5900: "vnc", 6379: "redis",
        8080: "http-alt", 8443: "https", 27017: "mongodb", 9200: "elasticsearch",
        11211: "memcached", 8000: "http-alt", 9000: "http-alt", 8008: "http",
        8888: "http-alt",
    }

    SERVICE_PATTERNS = [
        ("redis", re.compile(r"^\*\d+\r\n", re.IGNORECASE)),
        ("redis", re.compile(r"-ERR|PONG|\+OK", re.IGNORECASE)),
        ("postgresql", re.compile(r"PostgreSQL|FATAL|pg_hba", re.IGNORECASE)),
        ("ssh", re.compile(r"^SSH-\d+\.\d+", re.IGNORECASE)),
        ("ftp", re.compile(r"^220[\s-].*FTP|FileZilla|vsftpd|ProFTPD", re.IGNORECASE)),
        ("smtp", re.compile(r"^220[\s-].*SMTP|Postfix|Sendmail|ESMTP", re.IGNORECASE)),
        ("http", re.compile(r"^HTTP/\d|Content-Type:|Server:", re.IGNORECASE)),
        ("mysql", re.compile(r"mysql_native_password", re.IGNORECASE)),
        ("mongodb", re.compile(r"MongoDB|mongod", re.IGNORECASE)),
        ("telnet", re.compile(r"^\xff[\xfb-\xfe]", re.IGNORECASE)),
        ("tomcat", re.compile(r"Apache-Coyote|Tomcat|javax\.servlet", re.IGNORECASE)),
        ("spring-boot", re.compile(r"Spring.*Boot|Whitelabel.*Error", re.IGNORECASE)),
    ]

    def __init__(self):
        self._tls_ctx = self._build_tls_context()

    @staticmethod
    def _build_tls_context() -> ssl.SSLContext:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.set_alpn_protocols(["h2", "http/1.1", "http/1.0"])
        try:
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        except AttributeError:
            pass
        return ctx

    async def detect(self, host: str, port: int, timeout: float = CONNECT_TIMEOUT) -> ServiceDetectionResult:
        try:
            return await asyncio.wait_for(
                self._detect(host, port, timeout),
                timeout=TOTAL_DETECT_TIMEOUT,
            )
        except asyncio.TimeoutError:
            logger.debug("Service detection timed out for %s:%d", host, port)
            return self._fallback_result(port, "timeout")

    async def _detect(self, host: str, port: int, timeout: float) -> ServiceDetectionResult:
        banner_bytes = b""
        service_name = ""
        service_version = ""
        detection_method = ""
        confidence = 0.0
        tls_version = ""
        alpn = ""
        cert_subject = ""
        cert_issuer = ""

        if port in TLS_PORTS:
            banner_bytes, grabbed, tls_info = await self._grab_tls_banner(host, port, timeout)
            if tls_info:
                tls_version = tls_info.get("version", "")
                alpn = tls_info.get("alpn", "")
                cert_subject = tls_info.get("subject", "")
                cert_issuer = tls_info.get("issuer", "")
        else:
            banner_bytes, grabbed = await self._grab_banner(host, port, timeout)

        if banner_bytes:
            decoded = banner_bytes.decode(errors="replace")
            banner_snippet = decoded[:80]

            for svc, pat in self.SERVICE_PATTERNS:
                if pat.search(decoded):
                    service_name = svc
                    detection_method = "banner"
                    confidence = 1.0
                    break

            if not service_name and banner_snippet.strip():
                service_name = f"unknown-service (banner: {banner_snippet[:40]})"
                detection_method = "banner"
                confidence = 0.9
        else:
            banner_snippet = ""

        if not service_name:
            if port in self.PORT_SERVICE_MAP:
                service_name = self.PORT_SERVICE_MAP[port]
                detection_method = "port_lookup"
                confidence = 0.5

        if not service_name:
            service_name = "unknown"
            detection_method = "unknown"
            confidence = 0.0

        return ServiceDetectionResult(
            port=port,
            state="open",
            service_name=service_name,
            service_version=service_version,
            detection_method=detection_method,
            banner_snippet=banner_snippet,
            confidence=confidence,
            tls_version=tls_version,
            alpn=alpn,
            cert_subject=cert_subject,
            cert_issuer=cert_issuer,
        )

    async def _grab_tls_banner(self, host: str, port: int, timeout: float) -> tuple:
        """Perform TLS handshake, extract cert/ALPN, then send HTTP probe.

        Returns (banner_bytes, grabbed_ok, tls_info_dict).
        """
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=self._tls_ctx, server_hostname=host),
                timeout=timeout,
            )
        except Exception:
            # TLS handshake failed — fall back to plaintext probe
            return await self._grab_banner(host, port, timeout), {}

        tls_info = {}
        try:
            transport = writer.transport
            ssl_obj = transport.get_extra_info("ssl_object")
            if ssl_obj:
                tls_info["version"] = ssl_obj.version()
                tls_info["alpn"] = ssl_obj.selected_alpn_protocol() or ""
                try:
                    cert = ssl_obj.getpeercert()
                    if cert:
                        subject = dict(x[0] for x in cert.get("subject", []))
                        issuer = dict(x[0] for x in cert.get("issuer", []))
                        tls_info["subject"] = subject.get("commonName", "")
                        tls_info["issuer"] = issuer.get("commonName", "")
                        tls_info["san"] = cert.get("subjectAltName", [])
                except Exception:
                    pass

            probe = f"GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode()
            writer.write(probe)
            await writer.drain()

            data = await asyncio.wait_for(
                reader.read(MAX_BANNER_BYTES),
                timeout=READ_DEADLINE,
            )
            return data, bool(data), tls_info

        except asyncio.TimeoutError:
            return b"", False, tls_info
        except Exception:
            return b"", False, tls_info
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    async def _grab_banner(self, host: str, port: int, timeout: float) -> tuple:
        """Open a plaintext TCP connection, send probe, read banner."""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=timeout,
            )
        except Exception:
            return b"", False

        try:
            if port in HTTP_PORTS:
                probe = f"GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode()
                writer.write(probe)
                await writer.drain()
            elif port in PASSIVE_PORTS:
                pass
            else:
                writer.write(b"\x00")
                await writer.drain()

            data = await asyncio.wait_for(
                reader.read(MAX_BANNER_BYTES),
                timeout=READ_DEADLINE,
            )
            return data, bool(data)

        except asyncio.TimeoutError:
            return b"", False
        except Exception:
            return b"", False
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    def _fallback_result(self, port: int, reason: str) -> ServiceDetectionResult:
        name = self.PORT_SERVICE_MAP.get(port, "unknown")
        return ServiceDetectionResult(
            port=port,
            state="open",
            service_name=name,
            service_version="",
            detection_method="port_lookup" if name != "unknown" else "unknown",
            banner_snippet="",
            confidence=0.5 if name != "unknown" else 0.0,
        )
