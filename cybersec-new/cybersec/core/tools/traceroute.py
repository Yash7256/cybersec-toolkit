import asyncio
import sys
import re
from dataclasses import dataclass

@dataclass
class TracerouteHop:
    hop: int
    ip: str | None
    hostname: str | None
    rtt_ms: float | None

@dataclass
class TracerouteResult:
    target: str
    hops: list[TracerouteHop]
    total_hops: int
    error: str | None

async def traceroute(target: str, max_hops: int = 30) -> TracerouteResult:
    max_hops = max(1, min(64, max_hops))
    
    if sys.platform == "win32":
        cmd = ["tracert", "-h", str(max_hops), "-d", target]
    else:
        cmd = ["traceroute", "-m", str(max_hops), "-n", target]

    try:
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await process.communicate()
        out_str = stdout.decode('utf-8', errors='ignore')

        hops = []
        
        for line in out_str.splitlines():
            line = line.strip()
            if not line or not line[0].isdigit():
                continue
                
            if sys.platform != "win32":
                if "* * *" in line:
                    hop_num = int(line.split()[0])
                    hops.append(TracerouteHop(hop=hop_num, ip=None, hostname=None, rtt_ms=None))
                else:
                    m = re.match(r"^\s*(\d+)\s+([\d.]+|\*)\s+(?:([\d.]+)\s*ms)?", line)
                    if m:
                        hop_num = int(m.group(1))
                        ip = m.group(2)
                        rtt_ms = float(m.group(3)) if m.group(3) else None
                        if ip != "*":
                            hops.append(TracerouteHop(hop=hop_num, ip=ip, hostname=None, rtt_ms=rtt_ms))
            else:
                parts = line.split()
                if len(parts) >= 4 and parts[0].isdigit():
                    hop_num = int(parts[0])
                    if "*" in line:
                        hops.append(TracerouteHop(hop=hop_num, ip=None, hostname=None, rtt_ms=None))
                    else:
                        rtt_str = parts[-2]
                        if rtt_str.isdigit():
                            rtt_ms = float(rtt_str)
                            ip = parts[-1]
                            hops.append(TracerouteHop(hop=hop_num, ip=ip, hostname=None, rtt_ms=rtt_ms))

        return TracerouteResult(target, hops, len(hops), None)
    except Exception as e:
        return TracerouteResult(target, [], 0, str(e))
