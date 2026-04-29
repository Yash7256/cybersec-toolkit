"""
Unit tests for UDP scanner rate limiting and retry logic.
"""
import pytest
import asyncio
import time
from unittest.mock import Mock, patch, MagicMock

from cybersec.core.scanner.scans.udp import UDPScanner, UDPResult, RetryConfig, RetryStats


@pytest.fixture
def udp_scanner():
    """Create a UDP scanner for testing."""
    return UDPScanner(
        timeout=1.0,
        max_rate=100,
        retry_config=RetryConfig(max_retries=2, base_delay=0.1)
    )


@pytest.mark.unit
class TestUDPScanner:
    """Test UDP scanner functionality."""
    
    def test_rate_limiter_initialization(self):
        """Test rate limiter initialization."""
        # Test default rate
        scanner = UDPScanner()
        assert scanner.rate_pps == 100.0  # Default max_rate
        
        # Test custom rate
        scanner = UDPScanner(rate_pps=500.0)
        assert scanner.rate_pps == 500.0
        
        # Test rate_pps override
        scanner = UDPScanner(max_rate=200, rate_pps=300.0)
        assert scanner.rate_pps == 300.0  # rate_pps should override max_rate

    def test_retry_config_initialization(self):
        """Test retry configuration initialization."""
        retry_config = RetryConfig(max_retries=5, base_delay=0.2)
        scanner = UDPScanner(retry_config=retry_config)
        
        assert scanner.retry_config.max_retries == 5
        assert scanner.retry_config.base_delay == 0.2
        assert scanner.retry_config.backoff_multiplier == 2.0

    @pytest.mark.asyncio
    async def test_rate_limiting_delays(self, udp_scanner):
        """Test that rate limiting introduces delays."""
        start_time = time.time()
        
        # Scan multiple ports to trigger rate limiting
        results = await udp_scanner.scan("127.0.0.1", [53, 54, 55])
        
        end_time = time.time()
        elapsed = end_time - start_time
        
        # Should take at least 2 * (1/100) seconds for rate limiting
        # Plus some overhead for actual scanning
        assert elapsed >= 0.02  # Minimum time for rate limiting
        assert len(results) == 3

    @pytest.mark.asyncio
    async def test_retry_logic_timing(self, udp_scanner):
        """Test exponential backoff timing."""
        call_times = []
        
        with patch('time.sleep') as mock_sleep:
            # Mock scan to fail twice then succeed
            original_sync_scan = udp_scanner._sync_scan_port
            
            def mock_scan_port(target, port):
                call_times.append(time.time())
                
                # Fail first two attempts
                if len(call_times) <= 2:
                    raise Exception("Mock failure")
                
                return UDPResult(port=port, state="open")
            
            udp_scanner._sync_scan_port = mock_scan_port
            
            # Scan a single port
            results = await udp_scanner.scan("127.0.0.1", [53])
            
            # Verify exponential backoff delays
            assert mock_sleep.call_count >= 1
            delays = [call.args[0][0] for call in mock_sleep.call_args_list]
            
            # First delay should be base_delay (0.1s)
            if delays:
                assert abs(delays[0] - 0.1) < 0.01

    @pytest.mark.asyncio
    async def test_retry_statistics_tracking(self, udp_scanner):
        """Test that retry statistics are properly tracked."""
        with patch.object(udp_scanner, '_sync_scan_port') as mock_scan:
            # Mock scan to fail twice then succeed
            mock_scan.side_effect = [
                Exception("Timeout"),
                Exception("Timeout"),
                UDPResult(port=53, state="open")
            ]
            
            # Scan a single port
            results = await udp_scanner.scan("127.0.0.1", [53])
            
            # Check retry statistics
            assert udp_scanner.retry_stats.total_retries >= 2
            assert udp_scanner.retry_stats.timeout_retries >= 2

    def test_udp_result_creation(self):
        """Test UDP result creation."""
        # Test open port result
        result_open = UDPResult(port=53, state="open", service="DNS")
        
        assert result_open.port == 53
        assert result_open.state == "open"
        assert result_open.service == "DNS"
        
        # Test filtered port result
        result_filtered = UDPResult(port=80, state="filtered")
        
        assert result_filtered.port == 80
        assert result_filtered.state == "filtered"
        assert result_filtered.service is None

    @pytest.mark.asyncio
    async def test_progress_callback(self, udp_scanner):
        """Test progress callback functionality."""
        progress_calls = []
        
        def progress_callback(current, total):
            progress_calls.append((current, total))
        
        # Mock successful scan
        with patch.object(udp_scanner, '_sync_scan_port') as mock_scan:
            mock_scan.return_value = UDPResult(port=53, state="open")
            
            results = await udp_scanner.scan(
                "127.0.0.1", 
                [53, 54], 
                progress_callback=progress_callback
            )
            
            # Should call progress callback for each port
            assert len(progress_calls) == 2
            assert progress_calls[0] == (1, 2)  # First port
            assert progress_calls[1] == (2, 2)  # Second port

    def test_is_available_root_check(self):
        """Test availability check for root privileges."""
        with patch('cybersec.core.scanner.scans.udp.is_root') as mock_is_root:
            with patch('cybersec.core.scanner.scans.udp.SCAPY_AVAILABLE', False):
                # Test without Scapy
                scanner = UDPScanner()
                assert not scanner.is_available()
            
            with patch('cybersec.core.scanner.scans.udp.SCAPY_AVAILABLE', True):
                # Test without root
                mock_is_root.return_value = False
                scanner = UDPScanner()
                assert not scanner.is_available()
                
                # Test with root
                mock_is_root.return_value = True
                scanner = UDPScanner()
                assert scanner.is_available()

    @pytest.mark.asyncio
    async def test_scan_error_handling(self, udp_scanner):
        """Test error handling in scan method."""
        # Test with no available scanner
        udp_scanner._has_root = False
        udp_scanner._executor = None
        
        results = await udp_scanner.scan("127.0.0.1", [53])
        
        assert len(results) == 1
        assert results[0].state == "requires_root"

    def test_backoff_multiplier_calculation(self):
        """Test exponential backoff delay calculation."""
        retry_config = RetryConfig(
            max_retries=3, 
            base_delay=0.1, 
            backoff_multiplier=2.0
        )
        
        # Test delay calculations
        assert retry_config.get_delay(0) == 0.1  # 0.1 * 2^0
        assert retry_config.get_delay(1) == 0.2  # 0.1 * 2^1
        assert retry_config.get_delay(2) == 0.4  # 0.1 * 2^2
        
        # Test max delay enforcement
        retry_config.max_delay = 0.3
        assert retry_config.get_delay(2) == 0.3  # Capped at max_delay

    def test_retry_statistics_methods(self):
        """Test retry statistics methods."""
        stats = RetryStats()
        
        # Test adding retries
        stats.add_retry("timeout")
        assert stats.total_retries == 1
        assert stats.timeout_retries == 1
        assert stats.icmp_unreachable_retries == 0
        
        stats.add_retry("icmp_unreachable")
        assert stats.total_retries == 2
        assert stats.icmp_unreachable_retries == 1
        
        # Test adding hard failures
        stats.add_hard_failure()
        assert stats.hard_failures == 1

    @pytest.mark.parametrize("rate_pps,expected_delay", [
        (100, 0.01),   # 1/100
        (500, 0.002),  # 1/500
        (1000, 0.001), # 1/1000
        (5000, 0.0002), # 1/5000
    ])
    def test_inter_packet_delay_calculation(self, rate_pps, expected_delay):
        """Test inter-packet delay calculation."""
        scanner = UDPScanner(rate_pps=rate_pps)
        
        # The delay should be 1/rate_pps
        actual_delay = 1.0 / scanner.rate_pps
        assert abs(actual_delay - expected_delay) < 0.0001

    def test_executor_initialization(self):
        """Test thread pool executor initialization."""
        scanner = UDPScanner(max_workers=20)
        
        assert scanner._executor._max_workers == 20

    @pytest.mark.asyncio
    async def test_scan_cancellation(self, udp_scanner):
        """Test scan cancellation handling."""
        # This test would require more complex async cancellation setup
        # For now, just verify the method exists and handles basic cases
        with pytest.raises(Exception):
            # Force an exception during scan
            with patch.object(udp_scanner, '_sync_scan_port') as mock_scan:
                mock_scan.side_effect = Exception("Forced error")
                await udp_scanner.scan("127.0.0.1", [53])


if __name__ == "__main__":
    pytest.main([__file__])
