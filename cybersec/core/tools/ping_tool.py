import asyncio
import dataclasses
import logging
import socket
import struct
import subprocess
import time
from typing import Optional

logger = logging.getLogger(__name__)


@dataclasses.dataclass(slots=True)
class PingResult:
    target: str
    ip: Optional[str] = None
    packets_sent: int = 0
    packets_received: int = 0
    packet_loss_pct: float = 100.0
    min_rtt_ms: Optional[float] = None
    avg_rtt_ms: Optional[float] = None
    max_rtt_ms: Optional[float] = None
    is_alive: bool = False
    raw_output: Optional[str] = None
    error: Optional[str] = None


class PingTool:
    ICMP_ECHO_REQUEST = 8
    ICMP_ECHO_REPLY = 0

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

    def _build_icmp_packet(self, identifier: int, seq: int) -> bytes:
        payload = struct.pack("!d", time.time())
        header = struct.pack("!BBHHH", self.ICMP_ECHO_REQUEST, 0, 0, identifier, seq)
        packet = header + payload
        checksum = self._checksum(packet)
        header = struct.pack("!BBHHH", self.ICMP_ECHO_REQUEST, 0, checksum, identifier, seq)
        return header + payload

    def _raw_ping(self, target: str, count: int, timeout: float) -> PingResult:
        result = PingResult(target=target)

        try:
            result.ip = socket.gethostbyname(target)
        except socket.gaierror as e:
            result.error = f"Cannot resolve target: {e}"
            return result

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            sock.settimeout(timeout)
        except (PermissionError, OSError) as e:
            logger.debug(f"Cannot create raw socket for ping: {e}")
            return self._subprocess_ping(target, count, timeout)

        identifier = (id(self) >> 16) & 0xFFFF
        rtt_times: list[float] = []
        packets_received = 0

        try:
            for seq in range(1, count + 1):
                packet = self._build_icmp_packet(identifier, seq)
                send_time = time.time()
                result.packets_sent += 1

                try:
                    sock.sendto(packet, (result.ip, 0))

                    while True:
                        recv_data, addr = sock.recvfrom(1024)
                        recv_time = time.time()

                        ip_header_len = (recv_data[0] & 0x0F) * 4
                        icmp_data = recv_data[ip_header_len:]
                        icmp_type = icmp_data[0]

                        if icmp_type == self.ICMP_ECHO_REPLY:
                            recv_identifier = struct.unpack("!H", icmp_data[4:6])[0]
                            recv_seq = struct.unpack("!H", icmp_data[6:8])[0]

                            if recv_identifier == identifier and recv_seq == seq:
                                rtt = (recv_time - send_time) * 1000
                                rtt_times.append(rtt)
                                packets_received += 1
                                break

                except socket.timeout:
                    pass
                except OSError as e:
                    logger.debug(f"Ping packet error: {e}")

                if seq < count:
                    time.sleep(0.2)

        except Exception as e:
            result.error = str(e)
        finally:
            sock.close()

        return self._process_ping_result(result, rtt_times, packets_received)

    def _subprocess_ping(self, target: str, count: int, timeout: float) -> PingResult:
        result = PingResult(target=target)

        try:
            result.ip = socket.gethostbyname(target)
        except socket.gaierror as e:
            result.error = f"Cannot resolve target: {e}"
            return result

        try:
            cmd = ["ping", "-c", str(count), "-W", str(int(timeout)), target]
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout * count + 5,
            )
            result.raw_output = proc.stdout

            lines = proc.stdout.strip().split("\n")
            for line in lines:
                if "packets transmitted" in line:
                    parts = line.split(",")
                    if len(parts) >= 1:
                        sent_part = parts[0].split()[0]
                        result.packets_sent = int(sent_part)
                    if len(parts) >= 2:
                        recv_part = parts[1].split()[0]
                        result.packets_received = int(recv_part)
                    if len(parts) >= 3:
                        loss_part = parts[2].split()[0].replace("%", "")
                        result.packet_loss_pct = float(loss_part)

                elif "rtt min/avg/max/mdev" in line or "round-trip min/avg/max" in line:
                    values = line.split("=")[1].strip().split("/")
                    if len(values) >= 4:
                        result.min_rtt_ms = float(values[0])
                        result.avg_rtt_ms = float(values[1])
                        result.max_rtt_ms = float(values[2])

            result.is_alive = result.packets_received > 0

        except FileNotFoundError:
            result.error = "ping command not found"
        except subprocess.TimeoutExpired:
            result.error = "Ping command timed out"
        except Exception as e:
            logger.warning(f"Subprocess ping failed: {e}")
            result.error = str(e)

        return result

    def _process_ping_result(
        self, result: PingResult, rtt_times: list[float], packets_received: int
    ) -> PingResult:
        result.packets_received = packets_received
        result.is_alive = packets_received > 0

        if packets_received > 0:
            result.packet_loss_pct = round(
                ((result.packets_sent - packets_received) / result.packets_sent) * 100, 2
            )
            result.min_rtt_ms = round(min(rtt_times), 2)
            result.avg_rtt_ms = round(sum(rtt_times) / len(rtt_times), 2)
            result.max_rtt_ms = round(max(rtt_times), 2)
        else:
            result.packet_loss_pct = 100.0

        return result

    async def ping(self, target: str, count: int = 4, timeout: float = 2.0) -> PingResult:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._raw_ping, target, count, timeout)
