import asyncio
import dataclasses
import logging
import socket
import struct
import time
from typing import Optional

logger = logging.getLogger(__name__)


@dataclasses.dataclass(slots=True)
class Hop:
    hop_number: int
    ip: Optional[str] = None
    hostname: Optional[str] = None
    rtt_ms: Optional[float] = None


@dataclasses.dataclass(slots=True)
class TracerouteResult:
    target: str
    hops: list[Hop] = dataclasses.field(default_factory=list)
    total_hops: int = 0
    completed: bool = False
    error: Optional[str] = None


class TracerouteTool:
    ICMP_ECHO_REQUEST = 8
    ICMP_ECHO_REPLY = 0
    ICMP_TIME_EXCEEDED = 11
    ICMP_CODE_NET_UNREACHABLE = 0
    ICMP_CODE_HOST_UNREACHABLE = 1

    def __init__(self) -> None:
        self._raw_socket = None
        self._has_raw_socket = False

    def _create_raw_socket(self) -> Optional[socket.socket]:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            sock.setsockopt(socket.SOL_IP, socket.IP_TTL, 1)
            sock.settimeout(2.0)
            return sock
        except (PermissionError, OSError) as e:
            logger.debug(f"Cannot create raw socket: {e}")
            return None

    def _checksum(self, data: bytes) -> int:
        checksum = 0
        for i in range(0, len(data), 2):
            if i + 1 < len(data):
                checksum += (data[i] << 8) + data[i + 1]
            else:
                checksum += data[i] << 8
        checksum = (checksum >> 16) + (checksum & 0xFFFF)
        checksum += checksum >> 16
        return ~checksum & 0xFFFF

    def _build_icmp_packet(self, seq: int) -> bytes:
        identifier = (id(self) >> 16) & 0xFFFF
        payload = struct.pack("!d", time.time())
        header = struct.pack("!BBHHH", self.ICMP_ECHO_REQUEST, 0, 0, identifier, seq)
        packet = header + payload
        checksum = self._checksum(packet)
        header = struct.pack("!BBHHH", self.ICMP_ECHO_REQUEST, 0, checksum, identifier, seq)
        return header + payload

    def _parse_icmp_response(self, data: bytes, sent_time: float) -> tuple[Optional[str], Optional[str], float]:
        ip_header_len = (data[0] & 0x0F) * 4
        icmp_data = data[ip_header_len:]
        icmp_type = icmp_data[0]

        if icmp_type == self.ICMP_TIME_EXCEEDED or icmp_type == self.ICMP_ECHO_REPLY:
            src_ip = socket.inet_ntoa(data[12:16])

            if icmp_type == self.ICMP_TIME_EXCEEDED:
                inner_ip_header = icmp_data[8:]
                if len(inner_ip_header) >= 20:
                    src_ip = socket.inet_ntoa(inner_ip_header[12:16])

            hostname = None
            try:
                hostname = socket.gethostbyaddr(src_ip)[0]
            except (socket.herror, socket.gaierror, socket.timeout):
                pass

            rtt = (time.time() - sent_time) * 1000
            return src_ip, hostname, rtt

        return None, None, 0.0

    def _sync_trace(self, target: str, max_hops: int, timeout: float) -> TracerouteResult:
        result = TracerouteResult(target=target)

        try:
            target_ip = socket.gethostbyname(target)
        except socket.gaierror as e:
            result.error = f"Cannot resolve target: {e}"
            return result

        sock = self._create_raw_socket()
        if not sock:
            return self._udp_fallback(target, target_ip, max_hops, timeout)

        hops: list[Hop] = []
        dest_addr = socket.gethostbyname(target)

        try:
            for ttl in range(1, max_hops + 1):
                sock.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)

                packet = self._build_icmp_packet(ttl)
                send_time = time.time()

                try:
                    sock.sendto(packet, (dest_addr, 0))
                    recv_data, addr = sock.recvfrom(1024)

                    src_ip, hostname, rtt = self._parse_icmp_response(recv_data, send_time)

                    if src_ip:
                        hop = Hop(
                            hop_number=ttl,
                            ip=src_ip,
                            hostname=hostname,
                            rtt_ms=round(rtt, 2),
                        )
                    else:
                        hop = Hop(hop_number=ttl)

                    hops.append(hop)

                    if addr[0] == dest_addr:
                        result.completed = True
                        break

                except socket.timeout:
                    hops.append(Hop(hop_number=ttl))
                except OSError as e:
                    logger.debug(f"ICMP error at hop {ttl}: {e}")
                    hops.append(Hop(hop_number=ttl))

        except Exception as e:
            result.error = str(e)
        finally:
            sock.close()

        result.hops = hops
        result.total_hops = len(hops)
        return result

    def _udp_fallback(self, target: str, target_ip: str, max_hops: int, timeout: float) -> TracerouteResult:
        result = TracerouteResult(target=target)
        result.error = "Raw socket unavailable, using UDP fallback"

        hops: list[Hop] = []
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        try:
            sock.settimeout(timeout)

            for ttl in range(1, max_hops + 1):
                sock.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)
                port = 33434 + ttl

                send_time = time.time()
                try:
                    sock.sendto(b"", (target_ip, port))
                    recv_data, addr = sock.recvfrom(512)
                    recv_time = time.time()
                    rtt = (recv_time - send_time) * 1000

                    hop = Hop(
                        hop_number=ttl,
                        ip=addr[0],
                        rtt_ms=round(rtt, 2),
                    )
                    hops.append(hop)

                    if addr[0] == target_ip:
                        result.completed = True
                        break

                except socket.timeout:
                    hops.append(Hop(hop_number=ttl))
                except OSError:
                    hops.append(Hop(hop_number=ttl))

        except Exception as e:
            result.error = f"UDP fallback failed: {e}"
        finally:
            sock.close()

        result.hops = hops
        result.total_hops = len(hops)
        return result

    async def trace(self, target: str, max_hops: int = 30, timeout: float = 2.0) -> TracerouteResult:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._sync_trace, target, max_hops, timeout)
