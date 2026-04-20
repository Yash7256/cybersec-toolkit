"""
Performance metrics collection for port scanning operations.
Tracks timing, packet statistics, retry behavior, and resource usage.
"""
import time
from dataclasses import dataclass, field
from typing import Dict, Any, Optional
from datetime import datetime, timezone


@dataclass
class ScanMetrics:
    """Comprehensive performance metrics for a scan operation."""
    
    # Timing metrics
    start_time: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    end_time: Optional[datetime] = None
    total_duration: Optional[float] = None  # seconds
    
    # Packet statistics
    packets_sent: int = 0
    packets_received: int = 0
    packets_filtered: int = 0
    packets_timeout: int = 0
    
    # Port statistics
    total_ports_scanned: int = 0
    open_ports_found: int = 0
    closed_ports_found: int = 0
    filtered_ports_found: int = 0
    
    # Retry statistics
    total_retries: int = 0
    timeout_retries: int = 0
    connection_reset_retries: int = 0
    host_unreachable_failures: int = 0
    permission_denied_failures: int = 0
    retry_success_rate: float = 0.0  # percentage
    
    # Response time statistics
    avg_response_time_ms: Optional[float] = None
    min_response_time_ms: Optional[float] = None
    max_response_time_ms: Optional[float] = None
    response_times: list[float] = field(default_factory=list)
    
    # Concurrency metrics
    peak_concurrency_reached: int = 0
    avg_concurrency: float = 0.0
    
    # Rate limiting metrics
    rate_limiter_throttle_events: int = 0
    rate_limiter_wait_time_total: float = 0.0  # total time spent waiting for rate limiter
    
    # Resource usage
    memory_peak_mb: Optional[float] = None
    cpu_peak_percent: Optional[float] = None
    
    # Error statistics
    total_errors: int = 0
    network_errors: int = 0
    timeout_errors: int = 0
    permission_errors: int = 0
    other_errors: int = 0
    
    def start_scan(self) -> None:
        """Initialize scan start time."""
        self.start_time = datetime.now(timezone.utc)
    
    def end_scan(self) -> None:
        """Finalize scan metrics."""
        self.end_time = datetime.now(timezone.utc)
        if self.start_time:
            self.total_duration = (self.end_time - self.start_time).total_seconds()
        
        # Calculate derived metrics
        self._calculate_derived_metrics()
    
    def _calculate_derived_metrics(self) -> None:
        """Calculate derived metrics from collected data."""
        # Retry success rate
        if self.total_retries > 0:
            successful_retries = self.total_retries - (
                self.timeout_retries + 
                self.connection_reset_retries + 
                self.host_unreachable_failures + 
                self.permission_denied_failures
            )
            self.retry_success_rate = (successful_retries / self.total_retries) * 100
        
        # Response time statistics
        if self.response_times:
            self.avg_response_time_ms = sum(self.response_times) / len(self.response_times)
            self.min_response_time_ms = min(self.response_times)
            self.max_response_time_ms = max(self.response_times)
        
        # Packet statistics
        self.packets_received = self.open_ports_found + self.closed_ports_found
        self.packets_filtered = self.filtered_ports_found
        self.packets_timeout = self.timeout_errors
    
    def record_packet_sent(self) -> None:
        """Record a packet being sent."""
        self.packets_sent += 1
    
    def record_packet_received(self, response_time_ms: float) -> None:
        """Record a successful packet response."""
        self.packets_received += 1
        self.response_times.append(response_time_ms)
    
    def record_port_result(self, state: str) -> None:
        """Record a port scan result."""
        self.total_ports_scanned += 1
        
        if state == "open":
            self.open_ports_found += 1
        elif state == "closed":
            self.closed_ports_found += 1
        elif state in ["filtered", "error"]:
            self.filtered_ports_found += 1
    
    def record_retry(self, retry_type: str) -> None:
        """Record a retry attempt."""
        self.total_retries += 1
        
        if retry_type == "timeout":
            self.timeout_retries += 1
        elif retry_type == "connection_reset":
            self.connection_reset_retries += 1
        elif retry_type == "host_unreachable":
            self.host_unreachable_failures += 1
        elif retry_type == "permission_denied":
            self.permission_denied_failures += 1
    
    def record_error(self, error_type: str) -> None:
        """Record an error occurrence."""
        self.total_errors += 1
        
        if error_type in ["network", "connection"]:
            self.network_errors += 1
        elif error_type == "timeout":
            self.timeout_errors += 1
        elif error_type in ["permission", "access"]:
            self.permission_errors += 1
        else:
            self.other_errors += 1
    
    def record_concurrency_peak(self, concurrency: int) -> None:
        """Record peak concurrency reached."""
        if concurrency > self.peak_concurrency_reached:
            self.peak_concurrency_reached = concurrency
    
    def record_rate_limiter_throttle(self, wait_time_ms: float) -> None:
        """Record rate limiter throttling event."""
        self.rate_limiter_throttle_events += 1
        self.rate_limiter_wait_time_total += wait_time_ms / 1000.0  # Convert to seconds
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert metrics to dictionary format for JSON serialization."""
        return {
            "timing": {
                "start_time": self.start_time.isoformat() if self.start_time else None,
                "end_time": self.end_time.isoformat() if self.end_time else None,
                "total_duration_seconds": self.total_duration,
            },
            "packet_statistics": {
                "packets_sent": self.packets_sent,
                "packets_received": self.packets_received,
                "packets_filtered": self.packets_filtered,
                "packets_timeout": self.packets_timeout,
                "packet_success_rate": (self.packets_received / max(self.packets_sent, 1)) * 100,
            },
            "port_statistics": {
                "total_ports_scanned": self.total_ports_scanned,
                "open_ports_found": self.open_ports_found,
                "closed_ports_found": self.closed_ports_found,
                "filtered_ports_found": self.filtered_ports_found,
                "open_port_rate": (self.open_ports_found / max(self.total_ports_scanned, 1)) * 100,
            },
            "retry_statistics": {
                "total_retries": self.total_retries,
                "timeout_retries": self.timeout_retries,
                "connection_reset_retries": self.connection_reset_retries,
                "host_unreachable_failures": self.host_unreachable_failures,
                "permission_denied_failures": self.permission_denied_failures,
                "retry_success_rate_percent": self.retry_success_rate,
            },
            "response_time_statistics": {
                "avg_response_time_ms": self.avg_response_time_ms,
                "min_response_time_ms": self.min_response_time_ms,
                "max_response_time_ms": self.max_response_time_ms,
                "total_response_samples": len(self.response_times),
            },
            "concurrency_metrics": {
                "peak_concurrency_reached": self.peak_concurrency_reached,
                "avg_concurrency": self.avg_concurrency,
            },
            "rate_limiting_metrics": {
                "throttle_events": self.rate_limiter_throttle_events,
                "total_wait_time_seconds": self.rate_limiter_wait_time_total,
                "avg_wait_time_per_throttle_ms": (
                    (self.rate_limiter_wait_time_total * 1000) / max(self.rate_limiter_throttle_events, 1)
                ),
            },
            "resource_usage": {
                "memory_peak_mb": self.memory_peak_mb,
                "cpu_peak_percent": self.cpu_peak_percent,
            },
            "error_statistics": {
                "total_errors": self.total_errors,
                "network_errors": self.network_errors,
                "timeout_errors": self.timeout_errors,
                "permission_errors": self.permission_errors,
                "other_errors": self.other_errors,
            }
        }
    
    def print_summary(self) -> None:
        """Print a human-readable summary of scan metrics."""
        if not self.end_time:
            print("Scan still in progress...")
            return
        
        print("\n" + "="*60)
        print("SCAN PERFORMANCE SUMMARY")
        print("="*60)
        
        # Timing
        print(f"Duration: {self.total_duration:.2f} seconds")
        print(f"Started: {self.start_time.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Ended: {self.end_time.strftime('%Y-%m-%d %H:%M:%S')}")
        
        # Port statistics
        print(f"\nPort Statistics:")
        print(f"  Total scanned: {self.total_ports_scanned}")
        print(f"  Open ports: {self.open_ports_found} ({(self.open_ports_found/max(self.total_ports_scanned,1)*100):.1f}%)")
        print(f"  Closed ports: {self.closed_ports_found} ({(self.closed_ports_found/max(self.total_ports_scanned,1)*100):.1f}%)")
        print(f"  Filtered ports: {self.filtered_ports_found} ({(self.filtered_ports_found/max(self.total_ports_scanned,1)*100):.1f}%)")
        
        # Packet statistics
        print(f"\nPacket Statistics:")
        print(f"  Packets sent: {self.packets_sent}")
        print(f"  Packets received: {self.packets_received}")
        print(f"  Success rate: {(self.packets_received/max(self.packets_sent,1)*100):.1f}%")
        
        # Response times
        if self.avg_response_time_ms:
            print(f"\nResponse Times:")
            print(f"  Average: {self.avg_response_time_ms:.2f} ms")
            print(f"  Min: {self.min_response_time_ms:.2f} ms")
            print(f"  Max: {self.max_response_time_ms:.2f} ms")
        
        # Retries
        if self.total_retries > 0:
            print(f"\nRetry Statistics:")
            print(f"  Total retries: {self.total_retries}")
            print(f"  Success rate: {self.retry_success_rate:.1f}%")
            print(f"  Timeout retries: {self.timeout_retries}")
            print(f"  Connection resets: {self.connection_reset_retries}")
        
        # Rate limiting
        if self.rate_limiter_throttle_events > 0:
            print(f"\nRate Limiting:")
            print(f"  Throttle events: {self.rate_limiter_throttle_events}")
            print(f"  Total wait time: {self.rate_limiter_wait_time_total:.2f} seconds")
        
        # Errors
        if self.total_errors > 0:
            print(f"\nError Summary:")
            print(f"  Total errors: {self.total_errors}")
            print(f"  Network errors: {self.network_errors}")
            print(f"  Timeout errors: {self.timeout_errors}")
            print(f"  Permission errors: {self.permission_errors}")
        
        # Concurrency
        print(f"\nConcurrency:")
        print(f"  Peak reached: {self.peak_concurrency_reached}")
        print(f"  Average: {self.avg_concurrency:.1f}")
        
        print("="*60)


class MetricsCollector:
    """Global metrics collector for tracking scan performance across the application."""
    
    def __init__(self):
        self._active_metrics: Dict[str, ScanMetrics] = {}
        self._completed_metrics: Dict[str, ScanMetrics] = {}
    
    def start_scan(self, scan_id: str) -> ScanMetrics:
        """Start tracking metrics for a new scan."""
        metrics = ScanMetrics()
        metrics.start_scan()
        self._active_metrics[scan_id] = metrics
        return metrics
    
    def end_scan(self, scan_id: str) -> Optional[ScanMetrics]:
        """End tracking for a scan and move to completed."""
        if scan_id in self._active_metrics:
            metrics = self._active_metrics[scan_id]
            metrics.end_scan()
            self._completed_metrics[scan_id] = metrics
            del self._active_metrics[scan_id]
            return metrics
        return None
    
    def get_active_metrics(self, scan_id: str) -> Optional[ScanMetrics]:
        """Get metrics for an active scan."""
        return self._active_metrics.get(scan_id)
    
    def get_completed_metrics(self, scan_id: str) -> Optional[ScanMetrics]:
        """Get metrics for a completed scan."""
        return self._completed_metrics.get(scan_id)
    
    def get_all_completed(self) -> Dict[str, ScanMetrics]:
        """Get all completed scan metrics."""
        return self._completed_metrics.copy()
    
    def cleanup_old_metrics(self, max_age_hours: int = 24) -> int:
        """Clean up old completed metrics and return count of removed items."""
        cutoff_time = datetime.now(timezone.utc).timestamp() - (max_age_hours * 3600)
        
        to_remove = []
        for scan_id, metrics in self._completed_metrics.items():
            if metrics.end_time and metrics.end_time.timestamp() < cutoff_time:
                to_remove.append(scan_id)
        
        for scan_id in to_remove:
            del self._completed_metrics[scan_id]
        
        return len(to_remove)


# Global metrics collector instance
metrics_collector = MetricsCollector()
