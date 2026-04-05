"""
Core utility functions.
"""
import socket
from urllib.parse import urlparse

def resolve_target(target: str) -> str:
    # Strip scheme if provided (e.g., http://example.com)
    parsed = urlparse(target)
    host = parsed.hostname or target

    blocked_ips = {"127.0.0.1", "localhost", "0.0.0.0", "255.255.255.255", "::1"}
    if host in blocked_ips or host.startswith("169.254."):
        raise ValueError("Invalid or blocked target")

    try:
        # Prefer IPv4 but fall back to IPv6 if needed
        addr_info = socket.getaddrinfo(host, None)
        ipv4 = next((info[4][0] for info in addr_info if info[0] == socket.AF_INET), None)
        if ipv4:
            return ipv4
        ipv6 = next((info[4][0] for info in addr_info if info[0] == socket.AF_INET6), None)
        if ipv6:
            return ipv6
        raise ValueError("Could not resolve target")
    except socket.gaierror:
        raise ValueError("Could not resolve target")

def parse_ports(port_range: str) -> list[int]:
    common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 6379, 8080, 8443, 27017]
    # We provide 1 to 1000 range to stand in for top1000 based on standard conventions
    top1000 = list(range(1, 1001)) 

    if port_range == "common":
        ports = common_ports
    elif port_range == "top1000":
        ports = top1000
    elif port_range == "all":
        ports = list(range(1, 65536))
    else:
        ports = []
        parts = port_range.split(",")
        for part in parts:
            part = part.strip()
            if "-" in part:
                try:
                    start_str, end_str = part.split("-")
                    start_p = int(start_str)
                    end_p = int(end_str)
                    if start_p > end_p:
                        raise ValueError()
                    ports.extend(range(start_p, end_p + 1))
                except Exception:
                    raise ValueError("Invalid port format")
            elif part:
                try:
                    ports.append(int(part))
                except Exception:
                    raise ValueError("Invalid port format")
                    
    ports = sorted(list(set(ports)))
    for p in ports:
        if p < 1 or p > 65535:
            raise ValueError("Port out of range")
    return ports

def format_duration(seconds: float) -> str:
    secs = int(seconds)
    hours = secs // 3600
    mins = (secs % 3600) // 60
    rem_secs = secs % 60
    
    parts = []
    if hours > 0:
        parts.append(f"{hours}h")
    if mins > 0 or hours > 0:
        parts.append(f"{mins}m")
    parts.append(f"{rem_secs}s")
    
    return " ".join(parts).lstrip("0m ").strip() or "0s"
