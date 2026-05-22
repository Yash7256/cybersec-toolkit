import asyncio
import sys
import re
import socket
from dataclasses import dataclass
from ipaddress import ip_address

from cybersec.core.tools.geoip import geoip_lookup

@dataclass
class TracerouteHop:
    hop: int
    ip: str | None
    hostname: str | None
    rtt_ms: float | None
    rtt_samples_ms: list[float]
    packet_loss_pct: float
    quality: str
    quality_color: str
    latency_added_ms: float | None
    is_hidden: bool
    hidden_reason: str | None
    is_private: bool
    provider: str | None
    asn: str | None
    hop_type: str
    city: str | None
    region: str | None
    country: str | None
    country_code: str | None
    lat: float | None
    lon: float | None
    cdn_provider: str | None
    is_cdn: bool
    insight: str | None

@dataclass
class TracerouteResult:
    target: str
    hops: list[TracerouteHop]
    total_hops: int
    error: str | None
    destination_ip: str | None = None
    route_stability_score: int | None = None
    route_efficiency: str | None = None
    health_indicators: list[str] | None = None
    autonomous_system_path: list[str] | None = None
    ownership_chain: list[str] | None = None
    bottlenecks: list[dict] | None = None
    hidden_hops: int = 0
    packet_loss_hops: int = 0
    international_route: bool = False
    cdn_detected: str | None = None
    route_risk: str | None = None
    route_risk_factors: list[str] | None = None
    routing_intelligence: list[str] | None = None
    ai_summary: str | None = None
    security_insights: list[str] | None = None


_CDN_PATTERNS: dict[str, tuple[str, ...]] = {
    "Cloudflare": ("cloudflare", "as13335"),
    "Akamai": ("akamai", "as20940", "as16625"),
    "Fastly": ("fastly", "as54113"),
    "Amazon CloudFront": ("cloudfront", "amazon", "aws", "as16509"),
    "Google": ("google", "as15169"),
    "Microsoft Azure": ("azure", "microsoft", "as8075"),
}


def _quality_for_latency(rtt_ms: float | None) -> tuple[str, str]:
    if rtt_ms is None:
        return "Filtered", "gray"
    if rtt_ms <= 10:
        return "Excellent", "green"
    if rtt_ms <= 40:
        return "Good", "cyan"
    if rtt_ms <= 100:
        return "Moderate", "yellow"
    return "Poor", "red"


def _private_ip(ip: str | None) -> bool:
    if not ip:
        return False
    try:
        parsed = ip_address(ip)
        return parsed.is_private or parsed.is_loopback or parsed.is_link_local
    except ValueError:
        return False


async def _reverse_dns(ip: str | None) -> str | None:
    if not ip or _private_ip(ip):
        return None
    loop = asyncio.get_running_loop()
    try:
        hostname, _, _ = await loop.run_in_executor(None, socket.gethostbyaddr, ip)
        return hostname
    except (socket.herror, socket.gaierror, OSError):
        return None


async def _geoip_for_hop(ip: str | None) -> dict:
    if not ip or _private_ip(ip):
        return {}
    try:
        result = await asyncio.wait_for(geoip_lookup(ip), timeout=3.0)
    except Exception:
        return {}
    if result.error:
        return {}
    return {
        "city": result.city,
        "region": result.region,
        "country": result.country,
        "country_code": result.country_code,
        "lat": result.lat,
        "lon": result.lon,
        "provider": result.org or result.isp,
        "asn": result.asn,
        "cdn_provider": result.cdn_provider,
        "is_cdn": result.is_cdn,
    }


def _detect_provider(ip: str | None, hostname: str | None) -> tuple[str | None, str | None, str | None, bool, str]:
    haystack = f"{ip or ''} {hostname or ''}".lower()
    cdn_provider = None
    for provider, needles in _CDN_PATTERNS.items():
        if any(needle in haystack for needle in needles):
            cdn_provider = provider
            break

    if cdn_provider:
        return cdn_provider, None, cdn_provider, True, "CDN Edge"
    if any(token in haystack for token in ("google", "1e100", "googleusercontent")):
        return "Google", "AS15169", "Google", True, "Cloud Network"
    if any(token in haystack for token in ("amazon", "aws", "compute")):
        return "Amazon Web Services", "AS16509", "Amazon CloudFront", True, "Cloud Network"
    if any(token in haystack for token in ("cloudflare", "cf")):
        return "Cloudflare", "AS13335", "Cloudflare", True, "CDN Edge"
    if _private_ip(ip):
        return "Private network", None, None, False, "Residential Router" if ip and ip.startswith(("192.168.", "10.")) else "Private Transit"
    if hostname:
        return hostname.split(".")[-2].title() if "." in hostname else hostname, None, None, False, "ISP Backbone"
    return None, None, None, False, "Public Router" if ip else "Filtered Hop"


def _empty_hop(hop_num: int) -> TracerouteHop:
    quality, color = _quality_for_latency(None)
    return TracerouteHop(
        hop=hop_num,
        ip=None,
        hostname=None,
        rtt_ms=None,
        rtt_samples_ms=[],
        packet_loss_pct=100.0,
        quality=quality,
        quality_color=color,
        latency_added_ms=None,
        is_hidden=True,
        hidden_reason="No ICMP response. This hop is likely filtered by a firewall or configured to suppress traceroute probes.",
        is_private=False,
        provider=None,
        asn=None,
        hop_type="Filtered Hop",
        city=None,
        region=None,
        country=None,
        country_code=None,
        lat=None,
        lon=None,
        cdn_provider=None,
        is_cdn=False,
        insight="No response from this router; later hops may still be reachable.",
    )


async def _enrich_hop(hop_num: int, ip: str, samples: list[float], previous_rtt: float | None) -> TracerouteHop:
    hostname = await _reverse_dns(ip)
    rtt_ms = round(sum(samples) / len(samples), 3) if samples else None
    packet_loss_pct = round(((3 - min(len(samples), 3)) / 3) * 100, 1)
    quality, color = _quality_for_latency(rtt_ms)
    latency_added = round(rtt_ms - previous_rtt, 3) if rtt_ms is not None and previous_rtt is not None else None
    provider, asn, cdn_provider, is_cdn, hop_type = _detect_provider(ip, hostname)
    insight = None
    if latency_added is not None and latency_added >= 40:
        insight = f"Hop {hop_num} added {latency_added:.1f}ms, which looks like a routing or congestion spike."
    elif packet_loss_pct:
        insight = f"Hop {hop_num} dropped {packet_loss_pct:.0f}% of traceroute probes."
    elif is_cdn:
        insight = f"Traffic appears to enter {cdn_provider} edge infrastructure here."

    return TracerouteHop(
        hop=hop_num,
        ip=ip,
        hostname=hostname,
        rtt_ms=rtt_ms,
        rtt_samples_ms=[round(sample, 3) for sample in samples],
        packet_loss_pct=packet_loss_pct,
        quality=quality,
        quality_color=color,
        latency_added_ms=latency_added,
        is_hidden=False,
        hidden_reason=None,
        is_private=_private_ip(ip),
        provider=provider,
        asn=asn,
        hop_type=hop_type,
        city=None,
        region=None,
        country=None,
        country_code=None,
        lat=None,
        lon=None,
        cdn_provider=cdn_provider,
        is_cdn=is_cdn,
        insight=insight,
    )


async def _apply_geoip_to_hops(hops: list[TracerouteHop]) -> None:
    public_hops = [hop for hop in hops if hop.ip and not hop.is_private and not hop.is_hidden][:16]
    if not public_hops:
        return

    async def lookup(hop: TracerouteHop) -> tuple[TracerouteHop, dict]:
        return hop, await _geoip_for_hop(hop.ip)

    results = await asyncio.gather(*(lookup(hop) for hop in public_hops), return_exceptions=True)
    for item in results:
        if isinstance(item, Exception):
            continue
        hop, geo = item
        if not geo:
            continue
        hop.city = geo.get("city")
        hop.region = geo.get("region")
        hop.country = geo.get("country")
        hop.country_code = geo.get("country_code")
        hop.lat = geo.get("lat")
        hop.lon = geo.get("lon")
        hop.provider = geo.get("provider") or hop.provider
        hop.asn = geo.get("asn") or hop.asn
        hop.cdn_provider = geo.get("cdn_provider") or hop.cdn_provider
        hop.is_cdn = bool(geo.get("is_cdn") or hop.is_cdn)
        if hop.is_cdn:
            hop.hop_type = "CDN Edge"
        elif geo.get("provider") and hop.hop_type == "Public Router":
            hop.hop_type = "ISP Backbone"
        if hop.is_cdn and not hop.insight:
            hop.insight = f"Traffic appears to enter {hop.cdn_provider} edge infrastructure here."


def _build_route_intelligence(target: str, hops: list[TracerouteHop], destination_ip: str | None) -> dict:
    visible = [hop for hop in hops if hop.rtt_ms is not None]
    hidden_hops = sum(1 for hop in hops if hop.is_hidden)
    packet_loss_hops = sum(1 for hop in hops if hop.packet_loss_pct > 0)
    bottlenecks = [
        {
            "hop": hop.hop,
            "ip": hop.ip,
            "latency_added_ms": hop.latency_added_ms,
            "reason": "Large per-hop latency increase",
        }
        for hop in hops
        if hop.latency_added_ms is not None and hop.latency_added_ms >= 40
    ]
    countries = [hop.country_code for hop in hops if hop.country_code]
    international_route = len(set(countries)) > 1
    cdn_detected = next((hop.cdn_provider for hop in hops if hop.cdn_provider), None)
    ownership_chain = []
    for hop in hops:
        owner = hop.cdn_provider or hop.provider or hop.asn
        if owner and owner not in ownership_chain:
            ownership_chain.append(owner)
    autonomous_system_path = []
    for hop in hops:
        asn = hop.asn or hop.provider
        if asn and asn not in autonomous_system_path:
            autonomous_system_path.append(asn)

    rtts = [hop.rtt_ms for hop in visible if hop.rtt_ms is not None]
    if rtts:
        avg = sum(rtts) / len(rtts)
        variance = sum((value - avg) ** 2 for value in rtts) / len(rtts)
    else:
        variance = 0
    stability_score = max(
        0,
        min(
            100,
            round(
                100
                - min(35, hidden_hops * 7)
                - min(25, packet_loss_hops * 6)
                - min(25, variance ** 0.5 / 3)
                - min(20, len(bottlenecks) * 10)
            ),
        ),
    )
    if stability_score >= 88:
        route_efficiency = "Excellent"
    elif stability_score >= 72:
        route_efficiency = "Good"
    elif stability_score >= 50:
        route_efficiency = "Moderate"
    else:
        route_efficiency = "Poor"

    routing_intelligence = []
    security_insights = []
    risk_factors = []
    if cdn_detected:
        routing_intelligence.append(f"Traffic appears to traverse {cdn_detected} edge or cloud infrastructure.")
    if hidden_hops:
        security_insights.append(f"{hidden_hops} intermediate hop(s) suppress ICMP replies.")
        risk_factors.append("Filtered intermediate routers reduce route visibility.")
    if bottlenecks:
        routing_intelligence.append(f"Possible bottleneck detected at hop {bottlenecks[0]['hop']}.")
        risk_factors.append("A large latency jump indicates congestion or long-distance transit.")
    if international_route:
        routing_intelligence.append("Cross-border routing detected.")
        risk_factors.append("Traffic crosses multiple geographic regions.")
    if not routing_intelligence:
        routing_intelligence.append("Route appears direct with no major inferred transit anomaly.")
    if not security_insights:
        security_insights.append("No obvious traceroute security anomaly detected.")

    health_indicators = [
        "HEALTHY" if stability_score >= 80 else "WATCH",
        "LOW CONGESTION" if not bottlenecks else "CONGESTION SIGNAL",
        "OPTIMAL ROUTE" if route_efficiency in ("Excellent", "Good") else "SUBOPTIMAL ROUTE",
    ]
    route_risk = "Low"
    if len(risk_factors) >= 2 or stability_score < 55:
        route_risk = "High"
    elif risk_factors:
        route_risk = "Medium"

    final_rtt = visible[-1].rtt_ms if visible else None
    ai_summary_parts = [
        f"Traceroute to {target} reached {len(visible)} visible hop(s)"
        + (f" with final observed latency near {final_rtt:.1f}ms." if final_rtt is not None else ".")
    ]
    if bottlenecks:
        ai_summary_parts.append(f"A notable latency increase occurs around hop {bottlenecks[0]['hop']}.")
    if hidden_hops:
        ai_summary_parts.append(f"{hidden_hops} hop(s) are hidden or filtered, which is common on hardened network paths.")
    if cdn_detected:
        ai_summary_parts.append(f"The route likely uses {cdn_detected} infrastructure.")

    return {
        "destination_ip": destination_ip,
        "route_stability_score": stability_score,
        "route_efficiency": route_efficiency,
        "health_indicators": health_indicators,
        "autonomous_system_path": autonomous_system_path,
        "ownership_chain": ownership_chain,
        "bottlenecks": bottlenecks,
        "hidden_hops": hidden_hops,
        "packet_loss_hops": packet_loss_hops,
        "international_route": international_route,
        "cdn_detected": cdn_detected,
        "route_risk": route_risk,
        "route_risk_factors": risk_factors,
        "routing_intelligence": routing_intelligence,
        "ai_summary": " ".join(ai_summary_parts),
        "security_insights": security_insights,
    }

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
        previous_rtt = None
        destination_ip = None
        
        for line in out_str.splitlines():
            line = line.strip()
            if not line or not line[0].isdigit():
                continue
                
            if sys.platform != "win32":
                if "* * *" in line:
                    hop_num = int(line.split()[0])
                    hops.append(_empty_hop(hop_num))
                else:
                    m = re.match(r"^\s*(\d+)\s+([0-9a-fA-F:.]+|\*)", line)
                    if m:
                        hop_num = int(m.group(1))
                        ip = m.group(2)
                        if ip != "*":
                            samples = [float(value) for value in re.findall(r"(\d+(?:\.\d+)?)\s*ms", line)]
                            hop = await _enrich_hop(hop_num, ip, samples, previous_rtt)
                            hops.append(hop)
                            previous_rtt = hop.rtt_ms if hop.rtt_ms is not None else previous_rtt
                            destination_ip = ip
            else:
                parts = line.split()
                if len(parts) >= 4 and parts[0].isdigit():
                    hop_num = int(parts[0])
                    if "*" in line:
                        hops.append(_empty_hop(hop_num))
                    else:
                        ip = parts[-1].strip("[]")
                        samples = [float(value) for value in re.findall(r"<?(\d+)\s*ms", line)]
                        hop = await _enrich_hop(hop_num, ip, samples, previous_rtt)
                        hops.append(hop)
                        previous_rtt = hop.rtt_ms if hop.rtt_ms is not None else previous_rtt
                        destination_ip = ip

        await _apply_geoip_to_hops(hops)
        intelligence = _build_route_intelligence(target, hops, destination_ip)
        return TracerouteResult(target, hops, len(hops), None, **intelligence)
    except Exception as e:
        return TracerouteResult(target, [], 0, str(e))
