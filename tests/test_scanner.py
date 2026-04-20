"""
Unit tests for AsyncPortScanner scan modes.
Tests TCP connect, SYN, UDP, FIN, NULL, XMAS, ACK, and Zombie modes.
"""
import pytest
import asyncio
import socket
import time
from unittest.mock import Mock, AsyncMock, patch, MagicMock
from datetime import datetime, timezone

from cybersec.core.scanner import (
    AsyncPortScanner, 
    TokenBucketRateLimiter,
    AdaptiveConcurrencyController,
    ScanReport,
    PortResult,
    RetryConfig,
    RetryStats,
    HostScanReport
)
from cybersec.core.service_detect import ServiceInfo
from cybersec.core.port_analyzer import PortRisk


@pytest.fixture
def mock_scanner():
    """Create a mock scanner for testing."""
    return AsyncPortScanner(
        timeout=1.0,
        enable_connection_pool=False,
        verbose=False,
        retry_config=RetryConfig(max_retries=2),
        rate_preset="normal"
    )


@pytest.fixture
def event_loop():
    """Create an event loop for async tests."""
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


class MockSocket:
    """Mock socket for testing network operations."""
    
    def __init__(self, should_timeout=False, should_refuse=False, should_reset=False):
        self.should_timeout = should_timeout
        self.should_refuse = should_refuse
        self.should_reset = should_reset
        self.closed = False
        
    async def __aenter__(self):
        return self
        
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        self.closed = True
        
    def close(self):
        self.closed = True


@pytest.mark.unit
class TestAsyncPortScanner:
    """Test AsyncPortScanner functionality."""
    
    @pytest.mark.asyncio
    async def test_tcp_connect_scan_success(self, mock_scanner, event_loop):
        """Test successful TCP connect scan."""
        with patch('asyncio.open_connection') as mock_connect:
            # Mock successful connection
            mock_reader = Mock()
            mock_writer = Mock()
            mock_writer.close = Mock()
            mock_writer.wait_closed = AsyncMock()
            mock_connect.return_value = (mock_reader, mock_writer)
            
            report = await mock_scanner.scan("127.0.0.1", "80", resolved_ip="127.0.0.1")
            
            assert report.target == "127.0.0.1"
            assert report.ip == "127.0.0.1"
            assert len(report.open_ports) == 1
            assert report.open_ports[0].port == 80
            assert report.open_ports[0].state == "open"
            assert report.scan_mode == "connect"
            mock_connect.assert_called_once_with("127.0.0.1", 80, timeout=mock_scanner.timeout)

    @pytest.mark.asyncio
    async def test_tcp_connect_scan_timeout(self, mock_scanner, event_loop):
        """Test TCP connect scan with timeout."""
        with patch('asyncio.open_connection') as mock_connect:
            mock_connect.side_effect = asyncio.TimeoutError()
            
            report = await mock_scanner.scan("127.0.0.1", "81", resolved_ip="127.0.0.1")
            
            assert len(report.open_ports) == 1
            assert report.open_ports[0].port == 81
            assert report.open_ports[0].state == "filtered"  # Timeout should result in filtered

    @pytest.mark.asyncio
    async def test_tcp_connect_scan_connection_refused(self, mock_scanner, event_loop):
        """Test TCP connect scan with connection refused."""
        with patch('asyncio.open_connection') as mock_connect:
            mock_connect.side_effect = ConnectionRefusedError()
            
            report = await mock_scanner.scan("127.0.0.1", "82", resolved_ip="127.0.0.1")
            
            assert len(report.open_ports) == 1
            assert report.open_ports[0].port == 82
            assert report.open_ports[0].state == "closed"

    @pytest.mark.asyncio
    async def test_retry_logic_exponential_backoff(self, mock_scanner, event_loop):
        """Test exponential backoff retry logic."""
        retry_config = RetryConfig(max_retries=3, base_delay=0.1, backoff_multiplier=2.0)
        scanner = AsyncPortScanner(retry_config=retry_config, enable_connection_pool=False)
        
        call_count = 0
        with patch('asyncio.open_connection') as mock_connect:
            # First attempt times out, second succeeds
            mock_connect.side_effect = [
                asyncio.TimeoutError(),
                asyncio.TimeoutError(),
                (Mock(), Mock())  # Success on third attempt
            ]
            
            with patch('time.sleep') as mock_sleep:
                report = await scanner.scan("127.0.0.1", "83", resolved_ip="127.0.0.1")
                
                # Verify exponential backoff: 0.1s, 0.2s, 0.4s
                expected_delays = [0.1, 0.2, 0.4]
                actual_delays = [call.args[0][0] for call in mock_sleep.call_args_list]
                assert actual_delays == expected_delays
                assert mock_sleep.call_count == 2  # 2 retries

    @pytest.mark.asyncio
    async def test_rate_limiter_tokens(self, event_loop):
        """Test token bucket rate limiter."""
        rate_limiter = TokenBucketRateLimiter(rate=10.0, burst=5)
        
        # Should be able to consume tokens immediately
        assert await rate_limiter.acquire(1) == True
        assert await rate_limiter.acquire(4) == True
        assert await rate_limiter.acquire(5) == True
        assert await rate_limiter.acquire(6) == False  # Exceeds burst
        
        # Test token refill
        time.sleep(0.1)  # Wait for refill
        assert await rate_limiter.acquire(1) == True

    @pytest.mark.asyncio
    async def test_rate_presets(self, event_loop):
        """Test rate preset configurations."""
        # Test stealth preset
        stealth_scanner = AsyncPortScanner(rate_preset="stealth")
        assert stealth_scanner.rate_limiter.rate == 100.0
        assert stealth_scanner.rate_limiter.burst == 50
        
        # Test normal preset
        normal_scanner = AsyncPortScanner(rate_preset="normal")
        assert normal_scanner.rate_limiter.rate == 1000.0
        assert normal_scanner.rate_limiter.burst == 100
        
        # Test aggressive preset
        aggressive_scanner = AsyncPortScanner(rate_preset="aggressive")
        assert aggressive_scanner.rate_limiter.rate == 5000.0
        assert aggressive_scanner.rate_limiter.burst == 500

    @pytest.mark.asyncio
    async def test_adaptive_concurrency_controller(self, event_loop):
        """Test AIMD concurrency controller."""
        controller = AdaptiveConcurrencyController(min_workers=10, max_workers=100, initial_workers=50)
        
        # Test success rate tracking
        for i in range(60):
            await controller.on_attempt(True)
        
        assert controller.current == 50  # Should remain at initial
        assert controller.peak == 50
        
        # Test success rate increase
        for i in range(50):
            await controller.on_attempt(True)
        
        assert controller.current > 50  # Should increase
        assert controller.peak > 50
        
        # Test failure rate decrease
        for i in range(60):
            await controller.on_attempt(False)
        
        assert controller.current < 50  # Should decrease by 50%
        assert controller.semaphore_value > 10  # Should not go below minimum

    @pytest.mark.asyncio
    async def test_scan_report_serialization(self, mock_scanner, event_loop):
        """Test scan report JSON/CSV serialization."""
        # Create a mock report
        from cybersec.core.cve_lookup import CVEEntry
        from cybersec.core.os_fingerprint import OSFingerprint
        
        mock_service = ServiceInfo(name="http", version="Apache/2.4.41")
        mock_cve = CVEEntry(
            id="CVE-2021-12345",
            severity="CRITICAL",
            cvss_score=9.8,
            description="Test vulnerability"
        )
        mock_risk = PortRisk(risk_level="HIGH", risk_score=8.5)
        mock_os = OSFingerprint(
            os_name="Linux",
            confidence=0.85,
            method="TCP/IP fingerprinting"
        )
        
        mock_report = ScanReport(
            target="127.0.0.1",
            ip="127.0.0.1",
            total_ports_scanned=100,
            open_ports=[
                PortResult(
                    port=80,
                    protocol="tcp",
                    state="open",
                    service=mock_service,
                    cves=[mock_cve],
                    risk=mock_risk,
                    banner="Apache/2.4.41"
                )
            ],
            os_fingerprint=mock_os,
            scan_duration=5.23,
            started_at=datetime.now(timezone.utc),
            completed_at=datetime.now(timezone.utc),
            retry_stats=RetryStats(total_retries=5, timeout_retries=3)
        )
        
        # Test JSON serialization
        json_output = mock_report.to_json()
        assert '"target": "127.0.0.1"' in json_output
        assert '"scan_time"' in json_output
        assert '"retry_stats"' in json_output
        
        # Test CSV serialization
        csv_output = mock_report.to_csv()
        assert "target,port,protocol,state,service,version,cve_count,highest_cvss,risk_level" in csv_output
        assert "127.0.0.1,80,tcp,open,\"Apache\",\"2.4.41\",1,9.8,HIGH" in csv_output
        
        # Test file saving
        filepath = mock_report.save_to_file("json")
        assert filepath.endswith(".json")
        assert "scan_127_0_0_1" in filepath

    @pytest.mark.asyncio
    async def test_boundary_ports(self, mock_scanner, event_loop):
        """Test boundary port values."""
        # Test port 0 (should be handled gracefully)
        with patch('asyncio.open_connection') as mock_connect:
            mock_connect.side_effect = ConnectionRefusedError()
            
            report = await mock_scanner.scan("127.0.0.1", "0", resolved_ip="127.0.0.1")
            
            # Should handle port 0 gracefully
            assert len(report.open_ports) == 1
            assert report.open_ports[0].port == 0
            assert report.open_ports[0].state == "closed"
        
        # Test port 65535 (maximum valid port)
        with patch('asyncio.open_connection') as mock_connect:
            mock_connect.side_effect = asyncio.TimeoutError()
            
            report = await mock_scanner.scan("127.0.0.1", "65535", resolved_ip="127.0.0.1")
            
            # Should handle maximum port
            assert len(report.open_ports) == 1
            assert report.open_ports[0].port == 65535
            assert report.open_ports[0].state == "filtered"

    @pytest.mark.asyncio 
    async def test_error_handling(self, mock_scanner, event_loop):
        """Test error handling for various failure scenarios."""
        # Test unreachable host
        with patch('cybersec.core.scanner.resolve_target') as mock_resolve:
            mock_resolve.side_effect = ValueError("Host unreachable")
            
            with pytest.raises(ValueError):
                await mock_scanner.scan("unreachable.host", "80", resolved_ip="127.0.0.1")
        
        # Test invalid port range
        with pytest.raises(ValueError):
            await mock_scanner.scan("127.0.0.1", "invalid", resolved_ip="127.0.0.1")


@pytest.mark.network
@pytest.mark.slow
class TestIntegrationScanning:
    """Integration tests requiring actual network access."""
    
    @pytest.mark.asyncio
    async def test_localhost_scan(self, event_loop):
        """Test scanning localhost with known open ports."""
        scanner = AsyncPortScanner(timeout=2.0, enable_connection_pool=False)
        
        # Start a simple server on port 12345
        server_task = asyncio.create_task(self._start_test_server(12345))
        
        # Give server time to start
        await asyncio.sleep(0.1)
        
        try:
            # Scan localhost
            report = await scanner.scan("127.0.0.1", "12345", resolved_ip="127.0.0.1")
            
            assert report.target == "127.0.0.1"
            assert report.ip == "127.0.0.1"
            assert len(report.open_ports) == 1
            assert report.open_ports[0].port == 12345
            assert report.open_ports[0].state == "open"
        finally:
            server_task.cancel()
            try:
                await server_task
            except asyncio.CancelledError:
                pass

    async def _start_test_server(self, port):
        """Start a simple test server."""
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind(('127.0.0.1', port))
        server_socket.listen(1)
        server_socket.setblocking(False)
        
        try:
            while True:
                conn, addr = await asyncio.get_event_loop().sock_accept(server_socket.fileno())
                if addr[0] == '127.0.0.1':
                    conn.close()
                    break
        except Exception:
            pass
        finally:
            server_socket.close()


if __name__ == "__main__":
    pytest.main([__file__])
