import asyncio
import re
import socket
import statistics
import sys
import time
from asyncio import subprocess as asy_sub
from dataclasses import dataclass, field

from cybersec.core.tools.geoip import geoip_lookup


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
    dns_lookup_ms: float | None = None
    ttl: int | None = None
    likely_os_family: str | None = None
    estimated_hops: str | None = None
    connection_quality: str | None = None
    jitter_ms: float | None = None
    jitter_label: str | None = None
    packet_loss_severity: str | None = None
    stability_score: int | None = None
    std_deviation_ms: float | None = None
    variance_ms: float | None = None
    latency_distribution: str | None = None
    suitable_for: list[str] = field(default_factory=list)
    response_timeline: list[dict] = field(default_factory=list)
    latency_trend: str | None = None
    availability_pct: float | None = None
    status_badges: list[str] = field(default_factory=list)
    heat_indicator: str | None = None
    health_summary: str | None = None
    recommendations: list[str] = field(default_factory=list)
    security_insights: list[str] = field(default_factory=list)
    network_type_guess: str | None = None
    route_insight: str | None = None
    geo: dict = field(default_factory=dict)
    history_delta_ms: float | None = None
    last_checked: str | None = None


_PING_HISTORY: dict[str, float] = {}


def _round(value: float | None, digits: int = 2) -> float | None:
    return round(value, digits) if value is not None else None


def _quality(avg_ms: float | None) -> str:
    if avg_ms is None:
        return "Unknown"
    if avg_ms <= 20:
        return "Excellent"
    if avg_ms <= 50:
        return "Good"
    if avg_ms <= 100:
        return "Moderate"
    return "Poor"


def _loss_severity(loss_pct: float) -> str:
    if loss_pct <= 0:
        return "Stable"
    if loss_pct <= 2:
        return "Minor"
    if loss_pct <= 5:
        return "Noticeable"
    return "Severe"


def _jitter_label(jitter_ms: float | None) -> str:
    if jitter_ms is None:
        return "Unknown"
    if jitter_ms <= 5:
        return "Stable"
    if jitter_ms <= 20:
        return "Variable"
    return "Unstable"


def _ttl_guess(ttl: int | None) -> tuple[str | None, str | None]:
    if ttl is None:
        return None, None
    initial = 64 if ttl <= 64 else 128 if ttl <= 128 else 255
    hops = max(0, initial - ttl)
    distance = "0-4 network hops" if hops <= 4 else f"{max(0, hops - 3)}-{hops + 3} network hops"
    if initial == 64:
        return "Linux/Unix-like", distance
    if initial == 128:
        return "Windows", distance
    return "Network appliance or Unix-like", distance


def _distribution(times: list[float]) -> str | None:
    if not times:
        return None
    if len(times) == 1:
        return f"Single response at {times[0]:.1f}ms"
    median = statistics.median(times)
    near = [value for value in sorted(times) if abs(value - median) <= max(2.0, median * 0.12)]
    if len(near) >= max(2, len(times) // 2):
        return f"Most responses between {min(near):.1f}-{max(near):.1f}ms"
    return f"Responses ranged from {min(times):.1f}-{max(times):.1f}ms"


def _trend(times: list[float], loss_pct: float) -> str:
    if loss_pct >= 5:
        return "Packet loss detected"
    if len(times) < 3:
        return "Insufficient samples"
    baseline = statistics.median(times)
    if any(value > baseline * 1.8 and value - baseline > 20 for value in times):
        return "Latency spike detected"
    if times[-1] > times[0] + max(15, times[0] * 0.4):
        return "Connection becoming slower"
    if max(times) - min(times) <= max(3, baseline * 0.15):
        return "Consistent latency"
    return "Minor latency variation"


def _stability_score(avg_ms: float | None, jitter_ms: float | None, loss_pct: float, stddev: float | None) -> int:
    score = 100.0
    score -= min(55, loss_pct * 9)
    if jitter_ms is not None:
        score -= min(25, jitter_ms * 1.5)
    if stddev is not None:
        score -= min(15, stddev)
    if avg_ms is not None and avg_ms > 100:
        score -= min(20, (avg_ms - 100) / 10)
    return max(0, min(100, round(score)))


def _suitable_for(avg_ms: float | None, jitter_ms: float | None, loss_pct: float) -> list[str]:
    if avg_ms is None or loss_pct > 5:
        return []
    jitter = jitter_ms or 0.0
    labels = []
    if avg_ms <= 50 and jitter <= 10 and loss_pct <= 1:
        labels.append("Gaming")
    if avg_ms <= 100 and jitter <= 20 and loss_pct <= 2:
        labels.append("Video Calls")
    if avg_ms <= 150 and loss_pct <= 3:
        labels.append("Streaming")
    if avg_ms <= 200 and loss_pct <= 5:
        labels.append("Browsing")
    return labels


def _network_type(geo: dict, jitter_ms: float | None, avg_ms: float | None) -> str:
    if geo.get("is_cdn"):
        return "Likely CDN edge"
    if geo.get("is_hosting") or str(geo.get("asn_type") or "").lower() == "hosting":
        return "Likely data center host"
    if avg_ms is not None and avg_ms < 30 and (jitter_ms or 0) < 5:
        return "Nearby optimized network"
    return "Public internet host"


def _route_insight(geo: dict) -> str | None:
    provider = geo.get("cdn_provider") or geo.get("org") or geo.get("isp")
    if not provider:
        return None
    if geo.get("is_cdn"):
        return f"Route appears to terminate at {provider} edge/proxy infrastructure."
    return f"Route appears to terminate on {provider} public network infrastructure."


def _recommendations(avg_ms: float | None, jitter_ms: float | None, loss_pct: float, geo: dict) -> list[str]:
    recs = []
    if avg_ms is not None and avg_ms > 100:
        recs.append("High latency detected. Possible causes include server distance, VPN routing, or congestion.")
    if jitter_ms is not None and jitter_ms > 20:
        recs.append("High jitter detected. Real-time voice, video, and gaming may feel unstable.")
    if loss_pct > 2:
        recs.append("Packet loss is noticeable. Check local connectivity, Wi-Fi quality, firewall rules, or upstream routing.")
    if geo.get("is_cdn"):
        recs.append("Target is behind CDN/proxy infrastructure; latency reflects the edge node, not necessarily the origin server.")
    if not recs:
        recs.append("Connection looks healthy. No immediate network action is recommended.")
    return recs


def _summary(target: str, quality: str, loss_pct: float, jitter_state: str, avg_ms: float | None) -> str:
    if avg_ms is None:
        return f"{target} did not provide enough timing data for a full quality assessment."
    if loss_pct == 0 and quality in {"Excellent", "Good"} and jitter_state == "Stable":
        return f"{target} responded consistently with {quality.lower()} latency and no packet loss. Connection quality appears stable."
    return f"{target} shows {quality.lower()} latency with {loss_pct:.1f}% packet loss and {jitter_state.lower()} jitter."


def _parse_reply_line(line: str) -> dict | None:
    if "time" not in line.lower():
        return None
    seq_match = re.search(r"(?:icmp_seq|seq)[=\s](\d+)", line, re.IGNORECASE)
    ttl_match = re.search(r"ttl[=\s](\d+)", line, re.IGNORECASE)
    time_match = re.search(r"time[=<]\s*([\d.]+)\s*ms", line, re.IGNORECASE)
    if not time_match:
        return None
    return {
        "packet": int(seq_match.group(1)) if seq_match else None,
        "latency_ms": float(time_match.group(1)),
        "ttl": int(ttl_match.group(1)) if ttl_match else None,
    }


def _build_result(
    *,
    target: str,
    ip: str,
    packets_sent: int,
    packets_received: int,
    loss_pct: float,
    min_ms: float | None,
    avg_ms: float | None,
    max_ms: float | None,
    dns_lookup_ms: float | None,
    replies: list[dict],
    geo_data: dict,
) -> PingResult:
    if replies and not packets_received:
        packets_received = len(replies)
    if not packets_sent:
        packets_sent = len(replies) or 1
    if packets_sent and loss_pct == 0 and packets_received < packets_sent:
        loss_pct = max(0.0, ((packets_sent - packets_received) / packets_sent) * 100)

    received_by_seq = {reply["packet"]: reply for reply in replies if reply.get("packet") is not None}
    timeline = []
    for seq in range(1, packets_sent + 1):
        reply = received_by_seq.get(seq) or (replies[seq - 1] if seq - 1 < len(replies) else None)
        if reply:
            timeline.append({"packet": seq, "latency_ms": _round(reply.get("latency_ms")), "ttl": reply.get("ttl"), "status": "received"})
        else:
            timeline.append({"packet": seq, "latency_ms": None, "ttl": None, "status": "dropped"})

    times = [float(item["latency_ms"]) for item in timeline if item.get("latency_ms") is not None]
    if times and avg_ms is None:
        min_ms = min(times)
        avg_ms = sum(times) / len(times)
        max_ms = max(times)

    ttl = next((reply.get("ttl") for reply in replies if reply.get("ttl") is not None), None)
    likely_os_family, estimated_hops = _ttl_guess(ttl)
    jitter_ms = None
    if len(times) >= 2:
        jitter_ms = sum(abs(curr - prev) for prev, curr in zip(times, times[1:])) / (len(times) - 1)
    stddev = statistics.pstdev(times) if len(times) >= 2 else 0.0 if times else None
    variance = statistics.pvariance(times) if len(times) >= 2 else 0.0 if times else None
    quality = _quality(avg_ms)
    jitter_state = _jitter_label(jitter_ms)
    stability_score = _stability_score(avg_ms, jitter_ms, loss_pct, stddev)
    heat = "green" if stability_score >= 85 else "yellow" if stability_score >= 65 else "red"
    badges = ["ONLINE" if packets_received else "OFFLINE"]
    if packets_received:
        badges.append("STABLE" if stability_score >= 85 else "VARIABLE" if stability_score >= 65 else "UNSTABLE")
    if avg_ms is not None and avg_ms <= 50:
        badges.append("LOW LATENCY")
    elif avg_ms is not None and avg_ms > 100:
        badges.append("HIGH LATENCY")

    history_key = ip or target
    previous_avg = _PING_HISTORY.get(history_key)
    history_delta = (avg_ms - previous_avg) if avg_ms is not None and previous_avg is not None else None
    if avg_ms is not None:
        _PING_HISTORY[history_key] = avg_ms

    return PingResult(
        target=target,
        ip=ip,
        packets_sent=packets_sent,
        packets_received=packets_received,
        packet_loss_pct=_round(loss_pct, 2) or 0.0,
        min_ms=_round(min_ms),
        avg_ms=_round(avg_ms),
        max_ms=_round(max_ms),
        error=None,
        dns_lookup_ms=dns_lookup_ms,
        ttl=ttl,
        likely_os_family=likely_os_family,
        estimated_hops=estimated_hops,
        connection_quality=quality,
        jitter_ms=_round(jitter_ms),
        jitter_label=jitter_state,
        packet_loss_severity=_loss_severity(loss_pct),
        stability_score=stability_score,
        std_deviation_ms=_round(stddev),
        variance_ms=_round(variance),
        latency_distribution=_distribution(times),
        suitable_for=_suitable_for(avg_ms, jitter_ms, loss_pct),
        response_timeline=timeline,
        latency_trend=_trend(times, loss_pct),
        availability_pct=_round((packets_received / packets_sent) * 100 if packets_sent else 0, 1),
        status_badges=badges,
        heat_indicator=heat,
        health_summary=_summary(target, quality, loss_pct, jitter_state, avg_ms),
        recommendations=_recommendations(avg_ms, jitter_ms, loss_pct, geo_data),
        security_insights=[
            "ICMP echo replies are enabled publicly." if packets_received else "Target blocks ICMP echo replies or is unreachable.",
            "TTL-based OS inference is approximate and affected by routing distance." if ttl is not None else "TTL was not observed in ping replies.",
        ],
        network_type_guess=_network_type(geo_data, jitter_ms, avg_ms),
        route_insight=_route_insight(geo_data),
        geo=geo_data,
        history_delta_ms=_round(history_delta),
        last_checked="just now",
    )


async def _geo_for_ip(ip: str) -> dict:
    try:
        geo = await geoip_lookup(ip)
    except Exception:
        return {}
    if geo.error:
        return {}
    return {
        "country": geo.country,
        "country_code": geo.country_code,
        "region": geo.region,
        "city": geo.city,
        "isp": geo.isp,
        "org": geo.org,
        "asn": geo.asn,
        "asn_type": geo.asn_type,
        "cdn_provider": geo.cdn_provider,
        "is_cdn": geo.is_cdn,
        "is_hosting": geo.is_hosting,
        "is_proxy": geo.is_proxy,
        "reverse_dns": geo.reverse_dns,
    }


async def ping_host(target: str, count: int = 4) -> PingResult:
    count = max(1, min(100, count))
    dns_start = time.perf_counter()
    try:
        loop = asyncio.get_running_loop()
        ip = (await loop.getaddrinfo(target, None, family=socket.AF_INET))[0][4][0]
    except Exception as exc:
        return PingResult(
            target,
            None,
            0,
            0,
            0.0,
            None,
            None,
            None,
            f"DNS resolution failed: {exc}",
            dns_lookup_ms=_round((time.perf_counter() - dns_start) * 1000),
            last_checked="just now",
        )
    dns_lookup_ms = _round((time.perf_counter() - dns_start) * 1000)

    cmd = ["ping", "-n", str(count), target] if sys.platform == "win32" else ["ping", "-c", str(count), target]

    try:
        process = await asyncio.create_subprocess_exec(*cmd, stdout=asy_sub.PIPE, stderr=asy_sub.PIPE)
        stdout, _stderr = await asyncio.wait_for(process.communicate(), timeout=max(5, count + 3))
        out_str = stdout.decode("utf-8", errors="ignore")

        packets_sent = 0
        packets_received = 0
        loss_pct = 0.0
        min_ms = avg_ms = max_ms = None
        replies = [reply for reply in (_parse_reply_line(line) for line in out_str.splitlines()) if reply]

        if sys.platform != "win32":
            m_packets = re.search(r"(\d+) packets transmitted, (\d+) (?:packets )?received", out_str)
            if m_packets:
                packets_sent = int(m_packets.group(1))
                packets_received = int(m_packets.group(2))
            m_loss = re.search(r"([\d.]+)% packet loss", out_str)
            if m_loss:
                loss_pct = float(m_loss.group(1))
            m_rtt = re.search(r"(?:rtt|round-trip) min/avg/max/(?:mdev|stddev)\s*=\s*([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+)", out_str)
            if m_rtt:
                min_ms = float(m_rtt.group(1))
                avg_ms = float(m_rtt.group(2))
                max_ms = float(m_rtt.group(3))
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
                if min_ms > max_ms:
                    min_ms, max_ms = max_ms, min_ms

        geo_data = await _geo_for_ip(ip)
        return _build_result(
            target=target,
            ip=ip,
            packets_sent=packets_sent or count,
            packets_received=packets_received,
            loss_pct=loss_pct,
            min_ms=min_ms,
            avg_ms=avg_ms,
            max_ms=max_ms,
            dns_lookup_ms=dns_lookup_ms,
            replies=replies,
            geo_data=geo_data,
        )
    except asyncio.TimeoutError:
        return PingResult(
            target,
            ip,
            count,
            0,
            100.0,
            None,
            None,
            None,
            "Ping command timed out",
            dns_lookup_ms=dns_lookup_ms,
            packet_loss_severity="Severe",
            stability_score=0,
            availability_pct=0.0,
            status_badges=["OFFLINE"],
            heat_indicator="red",
            last_checked="just now",
        )
    except Exception as exc:
        return PingResult(target, ip, 0, 0, 0.0, None, None, None, str(exc), dns_lookup_ms=dns_lookup_ms, last_checked="just now")
