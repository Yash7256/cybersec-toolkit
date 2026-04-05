import asyncio
from asyncio import subprocess as asy_sub
import sys
import re
import socket
from dataclasses import dataclass

@dataclass
class PingResult:
    target: str
    ip: str | None
    packets_sent: int
    packets_received: int
    packet_loss_pct: float
    min_ms: float | None
    avg_ms: float | None
    max_ms: float | None
    error: str | None

async def ping_host(target: str, count: int = 4) -> PingResult:
    count = max(1, min(100, count))
    try:
        ip = socket.gethostbyname(target)
    except Exception as e:
        return PingResult(target, None, 0, 0, 0.0, None, None, None, f"DNS resolution failed: {e}")

    if sys.platform == "win32":
        cmd = ["ping", "-n", str(count), target]
    else:
        cmd = ["ping", "-c", str(count), target]

    try:
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asy_sub.PIPE,
            stderr=asy_sub.PIPE
        )
        stdout, stderr = await process.communicate()
        out_str = stdout.decode('utf-8', errors='ignore')

        packets_sent = 0
        packets_received = 0
        loss_pct = 0.0
        min_ms = avg_ms = max_ms = None

        if sys.platform != "win32":
            m_packets = re.search(r"(\d+) packets transmitted, (\d+) received", out_str)
            if m_packets:
                packets_sent = int(m_packets.group(1))
                packets_received = int(m_packets.group(2))
            
            m_loss = re.search(r"([\d.]+)% packet loss", out_str)
            if m_loss:
                loss_pct = float(m_loss.group(1))
                
            m_rtt = re.search(r"rtt min/avg/max/mdev\s*=\s*([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+)", out_str)
            if m_rtt:
                vals = [float(m_rtt.group(1)), float(m_rtt.group(2)), float(m_rtt.group(3))]
                # Standard is [min, avg, max]
                min_ms = min(vals)
                max_ms = max(vals)
                avg_ms = vals[1] if len(vals) > 1 else vals[0]
        else:
            m_packets = re.search(r"Sent = (\d+), Received = (\d+)", out_str)
            if m_packets:
                packets_sent = int(m_packets.group(1))
                packets_received = int(m_packets.group(2))
                if packets_sent > 0:
                    loss_pct = ((packets_sent - packets_received) / packets_sent) * 100
                    
            m_rtt = re.search(r"Minimum = (\d+)ms.*?Maximum = (\d+)ms.*?Average = (\d+)ms", out_str, re.DOTALL)
            if m_rtt:
                min_ms = float(m_rtt.group(1))
                max_ms = float(m_rtt.group(2))
                avg_ms = float(m_rtt.group(3))
                # Final safety check
                if min_ms and max_ms and min_ms > max_ms:
                    min_ms, max_ms = max_ms, min_ms

        return PingResult(target, ip, packets_sent, packets_received, loss_pct, min_ms, avg_ms, max_ms, None)
    except Exception as e:
        return PingResult(target, ip, 0, 0, 0.0, None, None, None, str(e))
