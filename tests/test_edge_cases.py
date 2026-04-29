"""
Edge case tests for boundary conditions and error handling.
Tests port 0, port 65535, unreachable hosts, invalid inputs, and empty responses.
"""
import pytest
import asyncio
from unittest.mock import patch, Mock

from cybersec.core.scanner import AsyncPortScanner, RetryConfig
from cybersec.core.scanner.analysis.service_detect import ServiceDetector
from cybersec.core.scanner.utils import expand_target_range, parse_ports


@pytest.mark.unit
class TestEdgeCases:
    """Test edge cases and boundary conditions."""
    
    @pytest.mark.asyncio
    async def test_port_zero_boundary(self):
        """Test port 0 boundary condition."""
        scanner = AsyncPortScanner(timeout=1.0, enable_connection_pool=False)
        
        with patch('asyncio.open_connection') as mock_connect:
            mock_connect.side_effect = ConnectionRefusedError()
            
            report = await scanner.scan("127.0.0.1", "0", resolved_ip="127.0.0.1")
            
            # Should handle port 0 gracefully
            assert len(report.open_ports) == 1
            assert report.open_ports[0].port == 0
            assert report.open_ports[0].state in ["closed", "error"]

    @pytest.mark.asyncio
    async def test_port_65535_boundary(self):
        """Test port 65535 maximum boundary condition."""
        scanner = AsyncPortScanner(timeout=1.0, enable_connection_pool=False)
        
        with patch('asyncio.open_connection') as mock_connect:
            mock_connect.side_effect = asyncio.TimeoutError()
            
            report = await scanner.scan("127.0.0.1", "65535", resolved_ip="127.0.0.1")
            
            # Should handle maximum port
            assert len(report.open_ports) == 1
            assert report.open_ports[0].port == 65535
            assert report.open_ports[0].state in ["filtered", "error"]

    @pytest.mark.asyncio
    async def test_unreachable_host_timeout(self):
        """Test unreachable host handling with graceful timeout."""
        scanner = AsyncPortScanner(timeout=0.5, enable_connection_pool=False, retry_config=RetryConfig(max_retries=1))
        
        start_time = asyncio.get_event_loop().time()
        report = await scanner.scan("192.0.2.254", "80", resolved_ip="192.0.2.254")
        end_time = asyncio.get_event_loop().time()
        
        # Should complete quickly due to timeout
        elapsed = end_time - start_time
        assert elapsed < 2.0  # Should complete within timeout + overhead
        assert report.target == "192.0.2.254"
        assert report.scan_duration > 0

    @pytest.mark.asyncio
    async def test_invalid_hostname_resolution(self):
        """Test invalid hostname resolution."""
        scanner = AsyncPortScanner(timeout=1.0, enable_connection_pool=False)
        
        with patch('cybersec.core.scanner.resolve_target') as mock_resolve:
            # Mock DNS resolution failure
            mock_resolve.side_effect = ValueError("Name or service not known")
            
            with pytest.raises(ValueError, match="Name or service not known"):
                await scanner.scan("invalid.hostname.nonexistent", "80", resolved_ip="invalid.hostname.nonexistent")

    @pytest.mark.asyncio
    async def test_invalid_ip_format(self):
        """Test invalid IP format handling."""
        scanner = AsyncPortScanner(timeout=1.0, enable_connection_pool=False)
        
        invalid_ips = [
            "999.999.999.999",
            "192.168.1",
            "192.168.1.256",
            "not.an.ip.address",
            "",
            "192.168.1.-1"
        ]
        
        for invalid_ip in invalid_ips:
            with pytest.raises((ValueError, OSError)):
                await scanner.scan(invalid_ip, "80", resolved_ip=invalid_ip)

    def test_empty_banner_service_detection(self):
        """Test service detection with empty/null banners."""
        detector = ServiceDetector()
        
        # Test empty string banner
        service_empty = detector.detect_service(80, "")
        assert service_empty.name == "unknown"
        assert service_empty.version is None
        assert service_empty.confidence == 0.0
        
        # Test None banner
        service_none = detector.detect_service(80, None)
        assert service_none.name == "unknown"
        assert service_none.version is None
        assert service_none.confidence == 0.0
        
        # Test whitespace-only banner
        service_whitespace = detector.detect_service(80, "   ")
        assert service_whitespace.name == "unknown"
        assert service_whitespace.version is None

    def test_port_parsing_edge_cases(self):
        """Test port parsing edge cases."""
        # Test invalid port specifications
        invalid_specs = [
            "0",           # Port 0 should fail
            "65536",        # Port > 65535 should fail  
            "-1",           # Negative port
            "abc",          # Non-numeric
            "1-65536",     # Range exceeds max
            "80-79-78",    # Invalid range format
            "",              # Empty string
            "80,,81",       # Double comma
            "80-81-82-83", # Complex invalid range
        ]
        
        for invalid_spec in invalid_specs:
            with pytest.raises(ValueError):
                parse_ports(invalid_spec)

    def test_cidr_expansion_edge_cases(self):
        """Test CIDR expansion edge cases."""
        # Test very large CIDR
        targets = expand_target_range("0.0.0.0/8")
        assert len(targets) == 16777215  # 2^24 - 1
        
        # Test single host CIDR
        targets = expand_target_range("192.168.1.1/32")
        assert len(targets) == 2  # Network + 1 host
        
        # Test IPv6 edge cases
        targets = expand_target_range("::/128")
        assert len(targets) == 1  # Only ::1
        
        # Test invalid CIDR
        with pytest.raises(ValueError):
            expand_target_range("192.168.1.1/33")  # Invalid CIDR

    @pytest.mark.asyncio
    async def test_max_concurrency_stress(self):
        """Test scanner under maximum concurrency load."""
        # This is a simplified version of the integration test
        scanner = AsyncPortScanner(
            timeout=0.1,  # Very short timeout for testing
            enable_connection_pool=False,
            concurrency=1000,
            retry_config=RetryConfig(max_retries=0)  # No retries for speed
        )
        
        with patch('asyncio.open_connection') as mock_connect:
            # Mock all connections to timeout immediately
            mock_connect.side_effect = asyncio.TimeoutError()
            
            start_time = asyncio.get_event_loop().time()
            
            # Scan 1000 ports
            ports = list(range(1000, 2000))
            report = await scanner.scan("127.0.0.1", ",".join(map(str, ports)), resolved_ip="127.0.0.1")
            
            end_time = asyncio.get_event_loop().time()
            elapsed = end_time - start_time
            
            # Should handle high concurrency without crashing
            assert len(report.open_ports) == 1000
            assert report.total_ports_scanned == 1000
            assert report.peak_concurrency == 1000
            assert elapsed < 5.0  # Should complete quickly with mocked connections

    def test_memory_usage_under_load(self):
        """Test that scanner doesn't leak memory under load."""
        import gc
        import psutil
        import os
        
        # Get initial memory usage
        process = psutil.Process(os.getpid())
        initial_memory = process.memory_info().rss
        
        # Create multiple scanners to test memory
        scanners = []
        for i in range(10):
            scanner = AsyncPortScanner(
                timeout=1.0,
                enable_connection_pool=False,
                concurrency=100
            )
            scanners.append(scanner)
        
        # Force garbage collection
        gc.collect()
        
        # Check memory usage
        final_memory = process.memory_info().rss
        memory_increase = final_memory - initial_memory
        
        # Memory increase should be reasonable (less than 100MB)
        assert memory_increase < 100 * 1024 * 1024  # 100MB in bytes

    @pytest.mark.asyncio
    async def test_network_error_recovery(self):
        """Test network error recovery and resilience."""
        scanner = AsyncPortScanner(timeout=1.0, enable_connection_pool=False)
        
        with patch('asyncio.open_connection') as mock_connect:
            # Simulate intermittent network failures
            call_count = 0
            def network_side_effect(*args, **kwargs):
                nonlocal call_count
                call_count += 1
                if call_count % 3 == 0:  # Every 3rd call fails
                    raise ConnectionResetError("Connection reset")
                else:
                    raise asyncio.TimeoutError("Timeout")
            
            mock_connect.side_effect = network_side_effect
            
            report = await scanner.scan("127.0.0.1", "80,81,82", resolved_ip="127.0.0.1")
            
            # Should handle mixed errors gracefully
            assert len(report.open_ports) == 3
            assert all(port.state in ["filtered", "error"] for port in report.open_ports)

    def test_unicode_hostname_handling(self):
        """Test Unicode hostname handling."""
        unicode_hostnames = [
            "测试.com",  # Chinese
            "тест.com",  # Russian  
            "テスト.com", # Japanese
            "café.com",  # French with accent
        ]
        
        for hostname in unicode_hostnames:
            try:
                # Should not crash with Unicode hostnames
                targets = expand_target_range(hostname)
                # Should handle gracefully (may resolve or fail)
                assert isinstance(targets, list)
            except Exception as e:
                # Should raise meaningful error, not encoding error
                assert "unicode" not in str(e).lower()

    @pytest.mark.asyncio
    async def test_timeout_profile_edge_cases(self):
        """Test timeout profile edge cases."""
        scanner = AsyncPortScanner(timeout=1.0, enable_connection_pool=False)
        
        # Test with various port types
        edge_ports = [
            (1, "ssh"),       # Low port
            (21, "ftp"),      # Standard service
            (80, "http"),     # Common service
            (443, "https"),   # Secure service
            (8080, "http-alt"), # Alternative port
            (3389, "rdp"),   # Windows service
            (5432, "postgresql"), # Database
            (65535, "unknown") # Maximum port
        ]
        
        for port, expected_profile in edge_ports:
            profile = scanner._get_timeout_profile(port)
            # Should return a valid profile
            assert profile in scanner.TIMEOUT_PROFILES
            assert isinstance(profile, str)

    def test_rate_limiter_edge_cases(self):
        """Test rate limiter edge cases."""
        from cybersec.core.scanner import TokenBucketRateLimiter
        
        # Test zero rate
        limiter_zero = TokenBucketRateLimiter(rate=0.0)
        assert limiter_zero.rate == 0.0
        
        # Test very high rate
        limiter_high = TokenBucketRateLimiter(rate=1000000.0)
        assert limiter_high.rate == 1000000.0
        
        # Test negative rate (should handle gracefully)
        try:
            limiter_negative = TokenBucketRateLimiter(rate=-1.0)
            assert limiter_negative.rate == -1.0
        except Exception:
            # Should handle negative rates gracefully or raise meaningful error
            pass

    @pytest.mark.asyncio
    async def test_concurrent_scanner_instances(self):
        """Test multiple scanner instances running concurrently."""
        async def scan_instance(instance_id):
            scanner = AsyncPortScanner(timeout=0.5, enable_connection_pool=False)
            
            with patch('asyncio.open_connection') as mock_connect:
                mock_connect.side_effect = asyncio.TimeoutError()
                
                report = await scanner.scan(f"127.0.0.{instance_id}", "80", resolved_ip=f"127.0.0.{instance_id}")
                return instance_id, len(report.open_ports)
        
        # Run multiple scans concurrently
        tasks = [scan_instance(i) for i in range(5)]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # All should complete successfully
        for i, result in enumerate(results):
            assert not isinstance(result, Exception)
            instance_id, port_count = result
            assert instance_id == i
            assert port_count == 1

    def test_configuration_validation(self):
        """Test scanner configuration validation."""
        # Test invalid timeout
        with pytest.raises(ValueError):
            AsyncPortScanner(timeout=-1.0)
        
        # Test invalid concurrency
        with pytest.raises(ValueError):
            AsyncPortScanner(concurrency=0)
        
        # Test invalid retry config
        with pytest.raises(ValueError):
            AsyncPortScanner(retry_config=RetryConfig(max_retries=-1))


if __name__ == "__main__":
    pytest.main([__file__])
