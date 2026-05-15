"""
Real-time Prometheus-format metrics registry.

No external dependencies — outputs plain text that Prometheus can scrape.
Designed for zero-overhead reads inside the scan hot path.
"""
import os
import time
from collections import defaultdict
from typing import Dict

# ── Metric helpers ──────────────────────────────────────────────────────────

class Counter:
    __slots__ = ("_val", "_help",)
    def __init__(self, help: str):
        self._val = 0
        self._help = help
    def inc(self, n: float = 1) -> None:
        self._val += n
    def get(self) -> float:
        return self._val

class Gauge:
    __slots__ = ("_val", "_help",)
    def __init__(self, help: str):
        self._val = 0.0
        self._help = help
    def set(self, n: float) -> None:
        self._val = n
    def inc(self, n: float = 1) -> None:
        self._val += n
    def dec(self, n: float = 1) -> None:
        self._val -= n
    def get(self) -> float:
        return self._val

class Histogram:
    """Exponential-bucket histogram, output as Prometheus cumulative counters."""
    __slots__ = ("_help", "_buckets", "_count", "_sum", "_inf")
    def __init__(self, help: str, buckets: tuple = None):
        self._help = help
        self._buckets = buckets or (.005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10)
        self._count = 0
        self._sum = 0.0
        self._inf = 0
    def observe(self, val: float) -> None:
        self._count += 1
        self._sum += val
    def snapshot(self) -> dict:
        return {"count": self._count, "sum": self._sum}


# ── Global registry ─────────────────────────────────────────────────────────

class MetricsRegistry:
    def __init__(self):
        self._counters: Dict[str, Counter] = {}
        self._gauges: Dict[str, Gauge] = {}
        self._histograms: Dict[str, Histogram] = {}

    def counter(self, name: str, help: str = "") -> Counter:
        if name not in self._counters:
            self._counters[name] = Counter(help)
        return self._counters[name]

    def gauge(self, name: str, help: str = "") -> Gauge:
        if name not in self._gauges:
            self._gauges[name] = Gauge(help)
        return self._gauges[name]

    def histogram(self, name: str, help: str = "", buckets: tuple = None) -> Histogram:
        if name not in self._histograms:
            self._histograms[name] = Histogram(help, buckets)
        return self._histograms[name]

    def dump_prometheus(self) -> str:
        lines: list[str] = []
        ts = int(time.time() * 1000)
        prefix = "cybersec_"

        for name, c in self._counters.items():
            lines.append(f"# HELP {prefix}{name} {c._help}")
            lines.append(f"# TYPE {prefix}{name} counter")
            lines.append(f"{prefix}{name} {c.get()} {ts}")

        for name, g in self._gauges.items():
            lines.append(f"# HELP {prefix}{name} {g._help}")
            lines.append(f"# TYPE {prefix}{name} gauge")
            lines.append(f"{prefix}{name} {g.get()} {ts}")

        for name, h in self._histograms.items():
            s = h.snapshot()
            lines.append(f"# HELP {prefix}{name} {h._help}")
            lines.append(f"# TYPE {prefix}{name} histogram")
            for i, b in enumerate(h._buckets):
                lines.append(f"{prefix}{name}_bucket{{le=\"{b}\"}} {0} {ts}")
            lines.append(f"{prefix}{name}_bucket{{le=\"+Inf\"}} {s['count']} {ts}")
            lines.append(f"{prefix}{name}_count {s['count']} {ts}")
            lines.append(f"{prefix}{name}_sum {s['sum']} {ts}")

        # System gauges (refreshed on scrape)
        try:
            fd_count = len(os.listdir(f"/proc/{os.getpid()}/fd"))
            self._gauges.get("fd_count", Gauge("")).set(fd_count)
        except Exception:
            pass

        return "\n".join(lines) + "\n"


# Singleton
_registry = MetricsRegistry()


def registry() -> MetricsRegistry:
    return _registry


# ── Named metric shortcuts ──────────────────────────────────────────────────

def scan_ports_sec() -> Gauge:
    return _registry.gauge("scan_ports_per_sec", "Ports scanned per second (rolling)")

def scan_success_rate() -> Gauge:
    return _registry.gauge("scan_success_rate", "Connection success rate (0–100)")

def scan_timeout_rate() -> Gauge:
    return _registry.gauge("scan_timeout_rate", "Connection timeout rate (0–100)")

def port_state_count(state: str) -> Gauge:
    """Per-state counter gauge (refused, rst, host_unreach, etc.)."""
    return _registry.gauge(f"port_state_{state}", f"Ports in state: {state}")

def scan_active() -> Gauge:
    return _registry.gauge("scan_active", "Number of scans currently running")

def scan_total() -> Counter:
    return _registry.counter("scan_total", "Total scans submitted")

def scan_queue_depth() -> Gauge:
    return _registry.gauge("scan_queue_depth", "Number of scans waiting for a slot")

def enrichment_latency() -> Histogram:
    return _registry.histogram("enrichment_latency_seconds", "Enrichment (service det. + CVE) latency")

def enrichment_stage1_backlog() -> Gauge:
    return _registry.gauge("enrichment_stage1_backlog", "Ports waiting for service detection")

def enrichment_stage2_backlog() -> Gauge:
    return _registry.gauge("enrichment_stage2_backlog", "Ports waiting for CVE lookup")

def enrichment_stage3_backlog() -> Gauge:
    return _registry.gauge("enrichment_stage3_backlog", "Ports waiting for risk analysis")

def fd_usage() -> Gauge:
    return _registry.gauge("fd_usage", "Open file descriptors")

def active_sockets() -> Gauge:
    return _registry.gauge("active_sockets", "Approximate active TCP sockets (scanner)")

def event_loop_lag_ms() -> Gauge:
    return _registry.gauge("event_loop_lag_ms", "Event loop stall detection (ms)")

# ── Per-stage timing ─────────────────────────────────────────────────────────

def dns_resolve_duration() -> Histogram:
    return _registry.histogram("dns_resolve_seconds", "DNS resolution time")

def connect_latency() -> Histogram:
    return _registry.histogram("connect_latency_seconds", "TCP connect handshake time")

def semaphore_wait_time() -> Histogram:
    return _registry.histogram("semaphore_wait_seconds", "Time spent waiting for semaphore permit")

def service_detect_duration() -> Histogram:
    return _registry.histogram("service_detect_seconds", "Service detection (banner grab + pattern match)")

def cve_lookup_duration() -> Histogram:
    return _registry.histogram("cve_lookup_seconds", "CVE lookup (NVD API + cache)")

def risk_analysis_duration() -> Histogram:
    return _registry.histogram("risk_analysis_seconds", "Risk analysis (local computation)")

def sse_backlog() -> Gauge:
    return _registry.gauge("sse_backlog", "Events waiting in SSE queue per scan")

def redis_publish_duration() -> Histogram:
    return _registry.histogram("redis_publish_seconds", "Redis publish/stream write latency")
