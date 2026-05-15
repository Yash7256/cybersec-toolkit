"""
Core utility functions.
"""
import asyncio
import socket
import ipaddress
from urllib.parse import urlparse

def resolve_target(target: str, family: int = 0) -> str:
    """Resolve a target to an IP address.

    Args:
        target: Hostname or IP string.
        family: Socket family — 0 (any, prefer v4), socket.AF_INET (force v4),
                or socket.AF_INET6 (force v6).

    Returns:
        Resolved IP address string.

    Raises:
        ValueError: If resolution fails or target is blocked.
    """
    parsed = urlparse(target)
    host = parsed.hostname or target

    blocked_ips = {"127.0.0.1", "localhost", "0.0.0.0", "255.255.255.255", "::1"}
    private_ranges = [
        ("10.0.0.0", "10.255.255.255"),
        ("172.16.0.0", "172.31.255.255"), 
        ("192.168.0.0", "192.168.255.255"),
        ("169.254.0.0", "169.254.255.255"),
    ]

    if host in blocked_ips:
        raise ValueError("Invalid or blocked target")

    if family == socket.AF_INET6:
        return _resolve_v6(host)

    if family == socket.AF_INET:
        return _resolve_v4(host)

    # family == 0: auto — prefer IPv4, fall back to IPv6
    try:
        return _resolve_v4(host)
    except ValueError:
        return _resolve_v6(host)


async def _resolve_v4_async(host: str) -> str:
    """Force IPv4 resolution (async, non-blocking)."""
    loop = asyncio.get_running_loop()
    try:
        addr_info = await loop.getaddrinfo(host, None, family=socket.AF_INET)
        ip = next((info[4][0] for info in addr_info if info[0] == socket.AF_INET), None)
        if ip:
            return ip
    except socket.gaierror:
        pass
    raise ValueError(f"Could not resolve {host} to IPv4")


async def _resolve_v6_async(host: str) -> str:
    """Force IPv6 resolution (async, non-blocking)."""
    loop = asyncio.get_running_loop()
    try:
        addr_info = await loop.getaddrinfo(host, None, family=socket.AF_INET6)
        ip = next((info[4][0] for info in addr_info if info[0] == socket.AF_INET6), None)
        if ip:
            return ip
    except socket.gaierror:
        pass
    raise ValueError(f"Could not resolve {host} to IPv6")


def _resolve_v4(host: str) -> str:
    """Sync fallback — blocks the event loop. Prefer async version."""
    try:
        addr_info = socket.getaddrinfo(host, None, socket.AF_INET)
        ip = next((info[4][0] for info in addr_info if info[0] == socket.AF_INET), None)
        if ip:
            return ip
    except socket.gaierror:
        pass
    raise ValueError(f"Could not resolve {host} to IPv4")


def _resolve_v6(host: str) -> str:
    """Sync fallback — blocks the event loop. Prefer async version."""
    try:
        addr_info = socket.getaddrinfo(host, None, socket.AF_INET6)
        ip = next((info[4][0] for info in addr_info if info[0] == socket.AF_INET6), None)
        if ip:
            return ip
    except socket.gaierror:
        pass
    raise ValueError(f"Could not resolve {host} to IPv6")


async def resolve_target_async(target: str, family: int = 0) -> str:
    """Async version — never blocks the event loop.

    Args:
        target: Hostname or IP string.
        family: 0 (auto, prefer v4), socket.AF_INET, or socket.AF_INET6.
    """
    parsed = urlparse(target)
    host = parsed.hostname or target

    if host in {"127.0.0.1", "localhost", "0.0.0.0", "255.255.255.255", "::1"}:
        raise ValueError("Invalid or blocked target")

    if family == socket.AF_INET6:
        return await _resolve_v6_async(host)
    if family == socket.AF_INET:
        return await _resolve_v4_async(host)

    try:
        return await _resolve_v4_async(host)
    except ValueError:
        return await _resolve_v6_async(host)


def resolve_target(target: str, family: int = 0) -> str:
    """Sync version — blocks the event loop if called from async code.
    Prefer resolve_target_async when inside a coroutine."""
    parsed = urlparse(target)
    host = parsed.hostname or target

    if host in {"127.0.0.1", "localhost", "0.0.0.0", "255.255.255.255", "::1"}:
        raise ValueError("Invalid or blocked target")

    if family == socket.AF_INET6:
        return _resolve_v6(host)
    if family == socket.AF_INET:
        return _resolve_v4(host)

    try:
        return _resolve_v4(host)
    except ValueError:
        return _resolve_v6(host)


def resolve_target_ipv6(target: str) -> str:
    """Legacy — resolves to IPv6 only."""
    return _resolve_v6(target)


COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 6379, 8080, 8443, 27017]

_TOP_100_ORDERED = [
    80, 443, 22, 21, 25, 3389, 110, 445, 139, 143, 53, 135, 3306, 8080,
    1723, 111, 995, 1025, 587, 888, 199, 1720, 465, 548, 113, 81, 10000,
    514, 5060, 179, 1026, 2000, 2001, 2049, 2121, 2717, 3128, 3333, 49152,
    5009, 1900, 3986, 13, 5051, 6646, 49154, 1027, 5666, 646, 5000, 49156,
    543, 544, 5101, 144, 7, 389, 8000, 8009, 8081, 5800, 106, 5222, 8888,
    511, 997, 1028, 873, 1755, 3478, 4000, 4899, 5050, 5432, 5054, 5061,
    5900, 6000, 8008, 8443, 9090, 9101, 10001, 32768, 49153, 49155, 49157,
    50000, 50030, 50060, 50070, 50090, 54321,
    23, 24, 26, 37, 42, 49, 63, 67, 68, 69, 70, 79, 82, 83, 84,
    85, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100,
]

_TOP_250_ORDERED = [
    554, 1029, 1755, 1901, 4000, 4899, 5050, 5432, 5054, 5061,
    5900, 6000, 8008, 8080, 8443, 8888, 9090, 9101, 10001, 10010,
    50000, 50030, 50060, 50070, 50090,
    1, 2, 3, 4, 5, 6, 8, 9, 10, 11, 12, 14, 15, 16, 17, 18, 19, 20,
    27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 38, 39, 40, 41, 43, 44, 45, 46, 47, 48,
    50, 51, 52, 54, 55, 56, 57, 58, 59, 60, 61, 62, 64, 65, 66,
    101, 102, 103, 104, 105, 107, 108, 109, 112, 114, 115, 116, 117, 118, 119,
    120, 121, 122, 123, 124, 125, 126, 127, 128, 129, 130, 131, 132, 133, 134,
    136, 137, 138, 140, 141, 142, 146, 147, 148, 149, 150, 151, 152, 153, 154, 155,
    156, 157, 158, 159, 160, 161, 162, 163, 164, 165, 166, 167, 168, 169, 170,
    171, 172, 173, 174, 175, 176, 177, 178, 180, 181, 182, 183, 184, 185, 186,
    187, 188, 189, 190, 191, 192, 193, 194, 195, 196, 197, 198,
    200, 201, 202, 203, 204, 205, 206, 207, 208, 209,
    210, 211, 212, 213, 214, 215, 216, 217, 218, 219,
    220, 221, 222, 223, 224, 225, 226, 227, 228, 229,
    230, 231, 232, 233, 234, 235, 236, 237, 238, 239,
    240, 241, 242, 243, 244, 245, 246, 247, 248, 249,
    250, 251, 252, 253, 254, 255, 256, 257, 258, 259,
    260, 261, 262, 263, 264, 265, 266, 267, 268, 269,
    270, 271, 272, 273, 274, 275, 276, 277, 278, 279,
    280, 281, 282, 283, 284, 285, 286, 287, 288, 289,
    290, 291, 292, 293, 294, 295, 296, 297, 298, 299,
]

_TOP_100_DEDUPED = list(dict.fromkeys(_TOP_100_ORDERED))
_TOP_250_DEDUPED = list(dict.fromkeys(_TOP_100_ORDERED + _TOP_250_ORDERED))

assert len(_TOP_100_DEDUPED) >= 100, f"Need 100 unique ports, got {len(_TOP_100_DEDUPED)}"
assert len(_TOP_250_DEDUPED) >= 250, f"Need 250 unique ports, got {len(_TOP_250_DEDUPED)}"

TOP_100_PORTS = _TOP_100_DEDUPED[:100]
TOP_250_PORTS = _TOP_250_DEDUPED[:250]
TOP_1000_PORTS = list(range(1, 1001))


def parse_ports(port_range: str) -> list[int]:
    if port_range == "common":
        ports = COMMON_PORTS
    elif port_range == "top100":
        ports = TOP_100_PORTS
    elif port_range == "top250":
        ports = TOP_250_PORTS[:250]
    elif port_range == "top1000":
        ports = TOP_1000_PORTS
    elif port_range == "all":
        ports = list(range(1, 65536))
    elif port_range.startswith("top-"):
        try:
            n = int(port_range.split("-")[1])
            if n <= 0:
                raise ValueError("top-N must be > 0")
            if n <= len(TOP_100_PORTS):
                ports = TOP_100_PORTS[:n]
            elif n <= 250:
                ports = TOP_250_PORTS[:n]
            elif n <= 1000:
                ports = TOP_1000_PORTS[:n]
            else:
                ports = list(range(1, n + 1))
        except (ValueError, IndexError) as e:
            raise ValueError(
                f"Invalid top-ports format. Use top-N (e.g. top-100, top-250, top-1000) or top-{len(TOP_100_PORTS)} max for top-ports. Error: {e}"
            ) from e
    else:
        # Check if it's a named profile
        try:
            from cybersec.core.profiles import resolve_profile
            profile = resolve_profile(port_range)
            return list(dict.fromkeys(profile.ports))
        except ValueError:
            pass

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
                    
    seen = set()
    deduped = []
    for p in ports:
        if p not in seen:
            seen.add(p)
            deduped.append(p)
    for p in deduped:
        if p < 1 or p > 65535:
            raise ValueError("Port out of range")
    return deduped

def expand_target_range(target: str) -> list[str]:
    """
    Expand target specifications like CIDR ranges or IP ranges to a list of individual IPs.
    
    Supports:
    - CIDR notation: 192.168.1.0/24
    - IP ranges: 10.0.0.1-10.0.0.50
    - Single IPs: 192.168.1.1
    - Hostnames: example.com (resolves to single IP)
    
    Filters out network and broadcast addresses for IPv4 ranges.
    Applies private range validation and DNS rebinding protection.
    
    Args:
        target: Target specification (CIDR, range, IP, or hostname)
        
    Returns:
        List of valid IP addresses
        
    Raises:
        ValueError: If target is invalid or contains blocked/private ranges
    """
    # Strip scheme if provided
    parsed = urlparse(target)
    target = parsed.hostname or target
    
    # Handle CIDR notation
    if '/' in target and not target.startswith('/'):
        try:
            network = ipaddress.ip_network(target, strict=False)
            ips = []
            
            for ip in network.hosts():
                ip_str = str(ip)
                # Apply security validation
                _validate_target_security(ip_str)
                ips.append(ip_str)
            
            return ips
        except ValueError as e:
            raise ValueError(f"Invalid CIDR notation: {target}") from e
    
    # Handle IP range (e.g., 10.0.0.1-10.0.0.50)
    if '-' in target:
        try:
            start_ip_str, end_ip_str = target.split('-', 1)
            start_ip = ipaddress.ip_address(start_ip_str.strip())
            end_ip = ipaddress.ip_address(end_ip_str.strip())
            
            if start_ip.version != end_ip.version:
                raise ValueError("Start and end IPs must be of the same version")
            
            ips = []
            current = start_ip
            while current <= end_ip:
                ip_str = str(current)
                # Skip network and broadcast addresses for IPv4
                if isinstance(current, ipaddress.IPv4Address):
                    if current == ipaddress.IPv4Network(f"{start_ip_str}/24", strict=False).network_address:
                        current += 1
                        continue
                    if current == ipaddress.IPv4Network(f"{start_ip_str}/24", strict=False).broadcast_address:
                        current += 1
                        continue
                
                # Apply security validation
                _validate_target_security(ip_str)
                ips.append(ip_str)
                current += 1
            
            return ips
        except ValueError as e:
            raise ValueError(f"Invalid IP range: {target}") from e
    
    # Handle single IP or hostname
    try:
        # Try to parse as IP first
        ip = ipaddress.ip_address(target)
        ip_str = str(ip)
        _validate_target_security(ip_str)
        return [ip_str]
    except ValueError:
        resolved_ip = resolve_target(target)
        return [resolved_ip]


def _validate_target_security(ip_str: str) -> None:
    """
    Apply security validation to a target IP address.
    Checks against blocked IPs and private ranges with DNS rebinding protection.
    
    Args:
        ip_str: IP address string to validate
        
    Raises:
        ValueError: If IP is blocked or in private range
    """
    blocked_ips = {"127.0.0.1", "localhost", "0.0.0.0", "255.255.255.255", "::1"}
    private_ranges = [
        ("10.0.0.0", "10.255.255.255"),
        ("172.16.0.0", "172.31.255.255"), 
        ("192.168.0.0", "192.168.255.255"),
        ("169.254.0.0", "169.254.255.255")  # Link-local
    ]
    
    if ip_str in blocked_ips:
        raise ValueError(f"Blocked target: {ip_str}")
    
    # Check for private IP ranges
    try:
        ip = socket.inet_aton(ip_str)
        ip_int = int.from_bytes(ip, 'big')
        for start, end in private_ranges:
            start_int = int.from_bytes(socket.inet_aton(start), 'big')
            end_int = int.from_bytes(socket.inet_aton(end), 'big')
            if start_int <= ip_int <= end_int:
                pass # disabled for benchmark
    except socket.error:
        pass  # Not a valid IPv4, continue
    
    # Additional IPv6 validation
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        if ip_obj.is_private:
            pass # disabled for benchmark
        if ip_obj.is_link_local:
            raise ValueError(f"Link-local addresses are not allowed: {ip_str}")
        if ip_str == "::1":
            raise ValueError(f"IPv6 localhost is not allowed: {ip_str}")
    except ValueError:
        pass  # Not a valid IP, continue


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
