import asyncio
import logging
import re
import socket
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class ServiceInfo:
    name: str
    version: str | None
    banner: str


class ServiceDetector:
    PROBE_SIGNATURES = [
        (
            re.compile(rb"^SSH-([\d.]+)", re.MULTILINE),
            "ssh",
            lambda m: f"SSH {m.group(1).decode()}",
        ),
        (
            re.compile(rb"^220[- ](.+?)(?:\r?\n|\r)", re.MULTILINE),
            "ftp",
            lambda m: f"FTP - {m.group(1).decode().strip()}",
        ),
        (
            re.compile(rb"^220[- ](.+?)(?:\r?\n|\r)", re.MULTILINE),
            "smtp",
            lambda m: f"SMTP - {m.group(1).decode().strip()}",
        ),
        (
            re.compile(rb"^220[- ](.+?)(?:\r?\n|\r)", re.MULTILINE),
            "http",
            lambda m: f"HTTP - {m.group(1).decode().strip()}",
        ),
        (
            re.compile(rb"HTTP/[\d.]+\s+(\d+)", re.MULTILINE),
            "http",
            lambda m: f"HTTP {m.group(1).decode()}",
        ),
        (
            re.compile(rb"<title>([^<]+)</title>", re.IGNORECASE),
            "http",
            lambda m: f"HTTP - {m.group(1).decode()}",
        ),
        (
            re.compile(rb"^MySQL|version\s+([\d.]+)", re.IGNORECASE),
            "mysql",
            lambda m: "MySQL",
        ),
        (
            re.compile(rb"^PostgreSQL", re.MULTILINE),
            "postgresql",
            lambda m: "PostgreSQL",
        ),
        (
            re.compile(rb"MongoDB[\s\w]*version:?\s*([\d.]+)", re.IGNORECASE),
            "mongodb",
            lambda m: f"MongoDB {m.group(1).decode()}",
        ),
        (
            re.compile(rb"^Redis\s+version:\s*([\d.]+)", re.IGNORECASE),
            "redis",
            lambda m: f"Redis {m.group(1).decode()}",
        ),
        (
            re.compile(rb"^RFB\s+([\d.]+)", re.MULTILINE),
            "vnc",
            lambda m: f"VNC {m.group(1).decode()}",
        ),
        (
            re.compile(rb"<xmpp", re.IGNORECASE),
            "xmpp",
            lambda m: "XMPP",
        ),
        (
            re.compile(rb"SIP/[\d.]+\s+(\d+)", re.MULTILINE),
            "sip",
            lambda m: f"SIP {m.group(1).decode()}",
        ),
        (
            re.compile(rb"^220[- ]", re.MULTILINE),
            "ftp",
            lambda m: "FTP",
        ),
        (
            re.compile(rb"^[23]\d\d\s", re.MULTILINE),
            "smtp",
            lambda m: "SMTP",
        ),
        (
            re.compile(rb"SSH-2.0-", re.MULTILINE),
            "ssh",
            lambda m: "SSH",
        ),
        (
            re.compile(rb"<html", re.IGNORECASE),
            "http",
            lambda m: "HTTP",
        ),
    ]

    PORT_SERVICE_FALLBACK: dict[int, str] = {
        21: "ftp",
        22: "ssh",
        23: "telnet",
        25: "smtp",
        53: "dns",
        80: "http",
        110: "pop3",
        111: "rpcbind",
        135: "msrpc",
        139: "netbios-ssn",
        143: "imap",
        161: "snmp",
        162: "snmptrap",
        389: "ldap",
        443: "https",
        445: "microsoft-ds",
        465: "smtps",
        587: "submission",
        636: "ldaps",
        993: "imaps",
        995: "pop3s",
        1433: "mssql",
        1521: "oracle",
        3306: "mysql",
        3389: "rdp",
        5432: "postgresql",
        5900: "vnc",
        5901: "vnc",
        6379: "redis",
        8080: "http-proxy",
        8443: "https-alt",
        27017: "mongodb",
        27018: "mongodb",
        27019: "mongodb",
        11211: "memcached",
    }

    HTTP_PROBE = b"GET / HTTP/1.0\r\n\r\n"
    BINARY_PROBE = b"\x00\x00\x00\x00"

    async def detect(
        self, host: str, port: int, protocol: str = "tcp", timeout: float = 2.0
    ) -> ServiceInfo:
        if protocol.lower() == "tcp":
            return await self._detect_tcp(host, port, timeout)
        else:
            return await self._detect_udp(host, port, timeout)

    async def _detect_tcp(self, host: str, port: int, timeout: float) -> ServiceInfo:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=timeout,
            )

            banner = b""
            service_name = self.PORT_SERVICE_FALLBACK.get(port, "unknown")

            try:
                writer.write(self.HTTP_PROBE)
                await writer.drain()
            except OSError:
                pass

            try:
                banner = await asyncio.wait_for(
                    reader.read(1024),
                    timeout=timeout,
                )
            except asyncio.TimeoutError:
                pass
            except OSError:
                pass

            if banner:
                decoded_banner = banner.decode("utf-8", errors="replace")
                service_name = self._match_banner(banner, decoded_banner, port)

                version = self._extract_version(decoded_banner, service_name)
                return ServiceInfo(
                    name=service_name,
                    version=version,
                    banner=decoded_banner[:500],
                )

            writer.close()
            await writer.wait_closed()

            return ServiceInfo(
                name=service_name,
                version=None,
                banner="",
            )

        except asyncio.TimeoutError:
            return ServiceInfo(
                name=self.PORT_SERVICE_FALLBACK.get(port, "unknown"),
                version=None,
                banner="",
            )
        except ConnectionRefusedError:
            return ServiceInfo(
                name=self.PORT_SERVICE_FALLBACK.get(port, "unknown"),
                version=None,
                banner="",
            )
        except OSError as e:
            if e.errno in (111, 113):
                return ServiceInfo(
                    name=self.PORT_SERVICE_FALLBACK.get(port, "unknown"),
                    version=None,
                    banner="",
                )
            logger.warning(
                f"Service detection on {host}:{port}: {type(e).__name__}: {e}"
            )
            return ServiceInfo(
                name=self.PORT_SERVICE_FALLBACK.get(port, "unknown"),
                version=None,
                banner="",
            )
        except Exception as e:
            logger.warning(
                f"Service detection on {host}:{port}: {type(e).__name__}: {e}"
            )
            return ServiceInfo(
                name=self.PORT_SERVICE_FALLBACK.get(port, "unknown"),
                version=None,
                banner="",
            )

    async def _detect_udp(self, host: str, port: int, timeout: float) -> ServiceInfo:
        loop = asyncio.get_event_loop()

        def sync_udp_probe():
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(timeout)
                sock.sendto(self.BINARY_PROBE, (host, port))
                data, _ = sock.receivefrom(1024)
                sock.close()
                return data
            except socket.timeout:
                sock.close()
                return b""
            except OSError:
                sock.close()
                return b""

        try:
            banner = await asyncio.wait_for(
                loop.run_in_executor(None, sync_udp_probe),
                timeout=timeout + 0.5,
            )

            if banner:
                decoded_banner = banner.decode("utf-8", errors="replace")
                service_name = self._match_banner(banner, decoded_banner, port)
                return ServiceInfo(
                    name=service_name,
                    version=None,
                    banner=decoded_banner[:500],
                )

        except asyncio.TimeoutError:
            pass
        except Exception as e:
            logger.warning(f"UDP service detection on {host}:{port}: {type(e).__name__}: {e}")

        return ServiceInfo(
            name=self.PORT_SERVICE_FALLBACK.get(port, "unknown"),
            version=None,
            banner="",
        )

    def _match_banner(self, raw_banner: bytes, decoded_banner: str, port: int) -> str:
        for pattern, service, _ in self.PROBE_SIGNATURES:
            match = pattern.search(raw_banner)
            if match:
                try:
                    return service + " " if callable(_) else service
                except (TypeError, AttributeError):
                    return service

        if port == 80 or port == 8080 or port == 8000:
            if b"<html" in raw_banner.lower() or b"<!DOCTYPE" in raw_banner.lower():
                return "http"
        elif port == 443 or port == 8443:
            return "https"

        return self.PORT_SERVICE_FALLBACK.get(port, "unknown")

    def _extract_version(self, banner: str, service: str) -> str | None:
        patterns = {
            "ssh": r"SSH-([\d.]+)",
            "ftp": r"220[- ]*(.+?)(?:\r|\n|$)",
            "smtp": r"220[- ]*(.+?)(?:\r|\n|$)",
            "mysql": r"([\d.]+)",
            "postgresql": r"([\d.]+)",
            "http": r"HTTP/[\d.]+\s+\d+\s+(.+?)(?:\r|\n|$)",
        }

        if service.split()[0] in patterns:
            pattern = patterns[service.split()[0]]
            match = re.search(pattern, banner)
            if match:
                return match.group(1).strip()

        return None
