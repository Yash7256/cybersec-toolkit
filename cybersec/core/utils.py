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
    private_ranges = [
        ("10.0.0.0", "10.255.255.255"),
        ("172.16.0.0", "172.31.255.255"), 
        ("192.168.0.0", "192.168.255.255"),
        ("169.254.0.0", "169.254.255.255")  # Link-local
    ]
    
    if host in blocked_ips:
        raise ValueError("Invalid or blocked target")
    
    # Check for private IP ranges
    try:
        ip = socket.inet_aton(host)
        ip_int = int.from_bytes(ip, 'big')
        for start, end in private_ranges:
            start_int = int.from_bytes(socket.inet_aton(start), 'big')
            end_int = int.from_bytes(socket.inet_aton(end), 'big')
            if start_int <= ip_int <= end_int:
                raise ValueError("Private IP ranges are not allowed for security reasons")
    except socket.error:
        pass  # Not an IP, continue with hostname resolution
    
    # DNS rebinding protection: resolve and check if it resolves to private
    try:
        resolved_ip = socket.gethostbyname(host)
        resolved_int = int.from_bytes(socket.inet_aton(resolved_ip), 'big')
        for start, end in private_ranges:
            start_int = int.from_bytes(socket.inet_aton(start), 'big')
            end_int = int.from_bytes(socket.inet_aton(end), 'big')
            if start_int <= resolved_int <= end_int:
                raise ValueError("DNS rebinding to private IP detected")
    except socket.error:
        pass

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

def resolve_target_ipv6(target: str) -> str:
    parsed = urlparse(target)
    host = parsed.hostname or target
    
    blocked_ips = {"::1", "localhost", "0.0.0.0"}
    if host in blocked_ips:
        raise ValueError("Invalid or blocked target")
    
    try:
        addr_info = socket.getaddrinfo(host, None, socket.AF_INET6)
        ipv6 = next((info[4][0] for info in addr_info if info[0] == socket.AF_INET6), None)
        if ipv6:
            return ipv6
    except socket.gaierror:
        pass
    
    try:
        resolved = socket.getaddrinfo(host, None)
        ipv6 = next((info[4][0] for info in resolved if info[0] == socket.AF_INET6), None)
        if ipv6:
            return ipv6
    except socket.gaierror:
        pass
    
    raise ValueError("Could not resolve target to IPv6")


def parse_ports(port_range: str) -> list[int]:
    common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 6379, 8080, 8443, 27017]
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
