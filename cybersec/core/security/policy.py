"""
Security policy for scan targets — CIDR restrictions, limits, and validation.

Enforced at scan submission time to prevent abuse of the scanner infrastructure.
"""
import asyncio
import ipaddress
import socket
import logging

logger = logging.getLogger(__name__)

# ── Blocked IPs and ranges ────────────────────────────────────────────────────
BLOCKED_IPS = {
    "0.0.0.0",
    "127.0.0.1",
    "255.255.255.255",
    "::1",
    "localhost",
}

# Networks that MUST never be scanned from cloud infra
RESTRICTED_NETWORKS = [
    # RFC 1918 private
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    # Link-local
    ipaddress.ip_network("169.254.0.0/16"),
    # Carrier-grade NAT (CGNAT) — RFC 6598
    ipaddress.ip_network("100.64.0.0/10"),
    # Cloud metadata endpoints
    ipaddress.ip_network("169.254.169.254/32"),
    ipaddress.ip_network("fd00:ec2::/32"),       # AWS IMDSv2 IPv6
    # Loopback
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
    # Documentation / benchmark ranges (should never be real targets)
    ipaddress.ip_network("192.0.2.0/24"),         # TEST-NET-1
    ipaddress.ip_network("198.51.100.0/24"),      # TEST-NET-2
    ipaddress.ip_network("203.0.113.0/24"),       # TEST-NET-3
    # IPv6 unique-local
    ipaddress.ip_network("fc00::/7"),
    # IPv6 link-local
    ipaddress.ip_network("fe80::/10"),
    # Multicast
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("ff00::/8"),
]

# ── Hard limits ──────────────────────────────────────────────────────────────
MAX_TARGETS_PER_SCAN = 256        # CIDR /24 equivalent
MAX_PORTS_PER_SCAN = 10_000       # prevent port-range abuse
MAX_HOSTNAME_LENGTH = 255


async def validate_target_async(target: str) -> str:
    """Async version — resolve DNS without blocking the event loop."""
    if len(target) > MAX_HOSTNAME_LENGTH:
        raise ValueError(f"Target too long ({len(target)} > {MAX_HOSTNAME_LENGTH})")

    try:
        ip = ipaddress.ip_address(target)
        return _check_ip(ip, target)
    except ValueError:
        pass

    loop = asyncio.get_running_loop()
    try:
        addrinfo = await loop.getaddrinfo(target, None)
    except socket.gaierror:
        raise ValueError(f"Could not resolve target: {target}")

    checked = []
    for info in addrinfo:
        raw = info[4][0]
        try:
            ip = ipaddress.ip_address(raw)
            checked.append(_check_ip(ip, target))
        except ValueError:
            continue

    if not checked:
        raise ValueError(f"All resolved IPs for {target} are blocked")

    if len(checked) > 1 and len(set(checked)) > 1:
        logger.warning("Target %s resolves to multiple IPs: %s", target, checked)

    return checked[0]


def validate_target(target: str) -> str:
    """Sync version — blocks the event loop. Prefer validate_target_async in coroutines."""
    if len(target) > MAX_HOSTNAME_LENGTH:
        raise ValueError(f"Target too long ({len(target)} > {MAX_HOSTNAME_LENGTH})")

    try:
        ip = ipaddress.ip_address(target)
        return _check_ip(ip, target)
    except ValueError:
        pass

    try:
        addrinfo = socket.getaddrinfo(target, None)
    except socket.gaierror:
        raise ValueError(f"Could not resolve target: {target}")

    checked = []
    for info in addrinfo:
        raw = info[4][0]
        try:
            ip = ipaddress.ip_address(raw)
            checked.append(_check_ip(ip, target))
        except ValueError:
            continue

    if not checked:
        raise ValueError(f"All resolved IPs for {target} are blocked")

    if len(checked) > 1 and len(set(checked)) > 1:
        logger.warning("Target %s resolves to multiple IPs: %s", target, checked)

    return checked[0]


def validate_targets(targets: list[str]) -> list[str]:
    """Validate a list of targets. Returns resolved IPs."""
    if len(targets) > MAX_TARGETS_PER_SCAN:
        raise ValueError(
            f"Too many targets ({len(targets)} > {MAX_TARGETS_PER_SCAN})"
        )
    return [validate_target(t) for t in targets]


def validate_port_count(n: int) -> None:
    """Validate total number of ports to scan."""
    if n > MAX_PORTS_PER_SCAN:
        raise ValueError(
            f"Too many ports ({n} > {MAX_PORTS_PER_SCAN})"
        )


def _check_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address, original: str) -> str:
    """Check a single IP against all restriction rules."""
    if str(ip) in BLOCKED_IPS:
        raise ValueError(f"Blocked target: {original}")

    if ip.is_loopback:
        raise ValueError(f"Loopback address not allowed: {original}")
    if ip.is_multicast:
        raise ValueError(f"Multicast address not allowed: {original}")
    if ip.is_unspecified:
        raise ValueError(f"Unspecified address not allowed: {original}")

    for net in RESTRICTED_NETWORKS:
        if ip in net:
            raise ValueError(
                f"Target {original} ({ip}) falls in restricted network {net}"
            )

    return str(ip)
