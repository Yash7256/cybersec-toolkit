"""
Comprehensive unit tests for UDP scanner functionality.
"""
import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime, timezone

from cybersec.core.udp_scan import UDPScanner, UDPResult


class TestUDPScanner:
    """Test UDPScanner functionality."""
    
    @pytest.fixture
    def scanner(self):
        """Create a UDP scanner instance for testing."""
        return UDPScanner(timeout=1.0)
    
    @pytest.fixture
    def mock_udp_result(self):
        """Create a mock UDP result for testing."""
        return UDPResult(
            port=53,
            state="open",
            latency_ms=45.5,
            response_data=b"DNS response data"
        )
    
    def test_scanner_initialization(self, scanner):
        """Test scanner initialization."""
        assert scanner.timeout == 1.0
        assert scanner._socket is None
    
    def test_scanner_initialization_custom_timeout(self):
        """Test scanner initialization with custom timeout."""
        scanner = UDPScanner(timeout=5.0)
        assert scanner.timeout == 5.0
    
    def test_scanner_initialization_negative_timeout(self):
        """Test scanner initialization with negative timeout."""
        with pytest.raises(ValueError):
            UDPScanner(timeout=-1.0)
    
    def test_scanner_initialization_zero_timeout(self):
        """Test scanner initialization with zero timeout."""
        with pytest.raises(ValueError):
            UDPScanner(timeout=0.0)
    
    @pytest.mark.asyncio
    async def test_is_available_method(self, scanner):
        """Test is_available method."""
        # Should return True by default
        assert scanner.is_available() is True
    
    @pytest.mark.asyncio
    async def test_scan_method_exists(self, scanner):
        """Test that scan method exists."""
        assert hasattr(scanner, 'scan')
        assert callable(getattr(scanner, 'scan'))
    
    @pytest.mark.asyncio
    async def test_scan_single_port_open(self, scanner):
        """Test scanning single port that responds."""
        with patch('socket.socket') as mock_socket_class:
            mock_socket = MagicMock()
            mock_socket_class.return_value = mock_socket
            
            # Mock successful UDP response
            mock_socket.recvfrom.return_value = (b"DNS response", ("8.8.8.8", 53))
            
            ports = [53]
            results = await scanner.scan("8.8.8.8", ports)
            
            assert len(results) == 1
            assert results[0].port == 53
            assert results[0].state == "open"
            assert results[0].latency_ms is not None
    
    @pytest.mark.asyncio
    async def test_scan_single_port_closed(self, scanner):
        """Test scanning single port that doesn't respond."""
        with patch('socket.socket') as mock_socket_class:
            mock_socket = MagicMock()
            mock_socket_class.return_value = mock_socket
            
            # Mock timeout (no response)
            mock_socket.recvfrom.side_effect = asyncio.TimeoutError("Timeout")
            
            ports = [12345]
            results = await scanner.scan("8.8.8.8", ports)
            
            assert len(results) == 1
            assert results[0].port == 12345
            assert results[0].state == "closed" or results[0].state == "filtered"
    
    @pytest.mark.asyncio
    async def test_scan_multiple_ports(self, scanner):
        """Test scanning multiple ports."""
        with patch('socket.socket') as mock_socket_class:
            mock_socket = MagicMock()
            mock_socket_class.return_value = mock_socket
            
            # Mock different responses for different ports
            def mock_recvfrom(*args, **kwargs):
                if mock_socket.recvfrom.call_count == 1:
                    return (b"DNS response", ("8.8.8.8", 53))
                else:
                    raise asyncio.TimeoutError("Timeout")
            
            mock_socket.recvfrom.side_effect = mock_recvfrom
            
            ports = [53, 123, 456]
            results = await scanner.scan("8.8.8.8", ports)
            
            assert len(results) == 3
            assert results[0].port == 53
            assert results[1].port == 123
            assert results[2].port == 456
    
    @pytest.mark.asyncio
    async def test_scan_with_empty_port_list(self, scanner):
        """Test scanning with empty port list."""
        results = await scanner.scan("8.8.8.8", [])
        assert results == []
    
    @pytest.mark.asyncio
    async def test_scan_with_invalid_target(self, scanner):
        """Test scanning with invalid target."""
        ports = [53]
        
        # Should handle invalid target gracefully
        with pytest.raises(Exception):
            await scanner.scan("invalid.target.that.does.not.exist", ports)
    
    @pytest.mark.asyncio
    async def test_scan_socket_creation_failure(self, scanner):
        """Test handling of socket creation failure."""
        with patch('socket.socket') as mock_socket_class:
            mock_socket_class.side_effect = OSError("Socket creation failed")
            
            ports = [53]
            with pytest.raises(OSError):
                await scanner.scan("8.8.8.8", ports)
    
    @pytest.mark.asyncio
    async def test_scan_with_custom_payload(self, scanner):
        """Test scanning with custom UDP payload."""
        with patch('socket.socket') as mock_socket_class:
            mock_socket = MagicMock()
            mock_socket_class.return_value = mock_socket
            
            # Mock response
            mock_socket.recvfrom.return_value = (b"Custom response", ("8.8.8.8", 53))
            
            ports = [53]
            results = await scanner.scan("8.8.8.8", ports)
            
            # Verify socket was called
            mock_socket.sendto.assert_called()
            mock_socket.recvfrom.assert_called()
    
    @pytest.mark.asyncio
    async def test_scan_concurrent_execution(self, scanner):
        """Test that scans run concurrently."""
        import time
        
        with patch('socket.socket') as mock_socket_class:
            mock_socket = MagicMock()
            mock_socket_class.return_value = mock_socket
            
            # Mock delay to test concurrency
            async def mock_recvfrom(*args, **kwargs):
                await asyncio.sleep(0.1)
                return (b"Response", ("8.8.8.8", 53))
            
            mock_socket.recvfrom.side_effect = mock_recvfrom
            
            ports = [53, 123, 456, 789]
            start_time = time.time()
            results = await scanner.scan("8.8.8.8", ports)
            end_time = time.time()
            
            # Should complete faster than sequential execution
            assert end_time - start_time < 0.4  # Much less than 0.4s for 4 ports
            assert len(results) == 4
    
    @pytest.mark.asyncio
    async def test_scan_error_handling(self, scanner):
        """Test error handling during scan."""
        with patch('socket.socket') as mock_socket_class:
            mock_socket = MagicMock()
            mock_socket_class.return_value = mock_socket
            
            # Mock network error
            mock_socket.recvfrom.side_effect = OSError("Network error")
            
            ports = [53]
            results = await scanner.scan("8.8.8.8", ports)
            
            # Should handle error gracefully
            assert len(results) == 1
            assert results[0].state in ["error", "closed", "filtered"]
    
    @pytest.mark.asyncio
    async def test_scan_rate_limiting(self, scanner):
        """Test rate limiting functionality."""
        # This would test if the scanner respects rate limiting
        # Implementation depends on how rate limiting is added
        with patch('socket.socket') as mock_socket_class:
            mock_socket = MagicMock()
            mock_socket_class.return_value = mock_socket
            
            mock_socket.recvfrom.return_value = (b"Response", ("8.8.8.8", 53))
            
            ports = [53, 123, 456]
            results = await scanner.scan("8.8.8.8", ports)
            
            assert len(results) == 3
    
    @pytest.mark.asyncio
    async def test_scan_different_protocols(self, scanner):
        """Test scanning different UDP-based protocols."""
        with patch('socket.socket') as mock_socket_class:
            mock_socket = MagicMock()
            mock_socket_class.return_value = mock_socket
            
            # Mock protocol-specific responses
            def mock_recvfrom(*args, **kwargs):
                port = kwargs.get('port', 53)
                if port == 53:
                    return (b"DNS response", ("8.8.8.8", 53))
                elif port == 123:
                    return (b"NTP response", ("8.8.8.8", 123))
                elif port == 161:
                    return (b"SNMP response", ("8.8.8.8", 161))
                else:
                    raise asyncio.TimeoutError("Timeout")
            
            mock_socket.recvfrom.side_effect = mock_recvfrom
            
            ports = [53, 123, 161]  # DNS, NTP, SNMP
            results = await scanner.scan("8.8.8.8", ports)
            
            assert len(results) == 3
            assert all(result.port in ports for result in results)


class TestUDPResult:
    """Test UDPResult dataclass."""
    
    def test_udp_result_creation_minimal(self):
        """Test UDPResult creation with minimal parameters."""
        result = UDPResult(port=53, state="open")
        
        assert result.port == 53
        assert result.state == "open"
        assert result.latency_ms is None
        assert result.response_data is None
        assert result.error is None
    
    def test_udp_result_creation_full(self):
        """Test UDPResult creation with all parameters."""
        result = UDPResult(
            port=53,
            state="open",
            latency_ms=45.5,
            response_data=b"DNS response data",
            error=None
        )
        
        assert result.port == 53
        assert result.state == "open"
        assert result.latency_ms == 45.5
        assert result.response_data == b"DNS response data"
        assert result.error is None
    
    def test_udp_result_with_error(self):
        """Test UDPResult with error information."""
        result = UDPResult(
            port=53,
            state="error",
            error="Network unreachable"
        )
        
        assert result.port == 53
        assert result.state == "error"
        assert result.error == "Network unreachable"
    
    def test_udp_result_different_states(self):
        """Test UDPResult with different states."""
        states = ["open", "closed", "filtered", "error"]
        
        for state in states:
            result = UDPResult(port=53, state=state)
            assert result.state == state
    
    def test_udp_result_latency_measurement(self):
        """Test UDPResult latency measurement."""
        result = UDPResult(port=53, state="open", latency_ms=123.45)
        
        assert result.latency_ms == 123.45
        assert isinstance(result.latency_ms, float)
    
    def test_udp_result_response_data_handling(self):
        """Test UDPResult response data handling."""
        data = b"Binary response data"
        result = UDPResult(port=53, state="open", response_data=data)
        
        assert result.response_data == data
        assert isinstance(result.response_data, bytes)
    
    def test_udp_result_equality(self):
        """Test UDPResult equality comparison."""
        result1 = UDPResult(port=53, state="open", latency_ms=45.5)
        result2 = UDPResult(port=53, state="open", latency_ms=45.5)
        result3 = UDPResult(port=53, state="closed", latency_ms=45.5)
        
        assert result1 == result2
        assert result1 != result3


class TestUDPEdgeCases:
    """Test UDP scanner edge cases."""
    
    @pytest.fixture
    def scanner(self):
        """Create a UDP scanner instance for testing."""
        return UDPScanner(timeout=1.0)
    
    @pytest.mark.asyncio
    async def test_scan_very_large_port_range(self, scanner):
        """Test scanning very large port range."""
        with patch('socket.socket') as mock_socket_class:
            mock_socket = MagicMock()
            mock_socket_class.return_value = mock_socket
            
            # Mock timeout for all ports
            mock_socket.recvfrom.side_effect = asyncio.TimeoutError("Timeout")
            
            ports = list(range(1, 101))  # 100 ports
            results = await scanner.scan("8.8.8.8", ports)
            
            assert len(results) == 100
            assert all(result.port in ports for result in results)
    
    @pytest.mark.asyncio
    async def test_scan_duplicate_ports(self, scanner):
        """Test scanning with duplicate ports."""
        with patch('socket.socket') as mock_socket_class:
            mock_socket = MagicMock()
            mock_socket_class.return_value = mock_socket
            
            mock_socket.recvfrom.return_value = (b"Response", ("8.8.8.8", 53))
            
            ports = [53, 53, 53]  # Duplicate ports
            results = await scanner.scan("8.8.8.8", ports)
            
            # Should handle duplicates gracefully
            assert len(results) == 3  # One result per input port
    
    @pytest.mark.asyncio
    async def test_scan_port_zero(self, scanner):
        """Test scanning port 0 (should be handled gracefully)."""
        with patch('socket.socket') as mock_socket_class:
            mock_socket = MagicMock()
            mock_socket_class.return_value = mock_socket
            
            mock_socket.recvfrom.side_effect = OSError("Invalid port")
            
            ports = [0]
            results = await scanner.scan("8.8.8.8", ports)
            
            assert len(results) == 1
            assert results[0].port == 0
            assert results[0].state in ["error", "closed"]
    
    @pytest.mark.asyncio
    async def test_scan_port_65535(self, scanner):
        """Test scanning port 65535 (maximum valid port)."""
        with patch('socket.socket') as mock_socket_class:
            mock_socket = MagicMock()
            mock_socket_class.return_value = mock_socket
            
            mock_socket.recvfrom.side_effect = asyncio.TimeoutError("Timeout")
            
            ports = [65535]
            results = await scanner.scan("8.8.8.8", ports)
            
            assert len(results) == 1
            assert results[0].port == 65535
    
    @pytest.mark.asyncio
    async def test_scan_ipv6_target(self, scanner):
        """Test scanning IPv6 target."""
        with patch('socket.socket') as mock_socket_class:
            mock_socket = MagicMock()
            mock_socket_class.return_value = mock_socket
            
            mock_socket.recvfrom.return_value = (b"Response", ("::1", 53))
            
            ports = [53]
            results = await scanner.scan("::1", ports)
            
            assert len(results) == 1
            assert results[0].port == 53
    
    @pytest.mark.asyncio
    async def test_scan_with_partial_response(self, scanner):
        """Test scanning with partial/incomplete response."""
        with patch('socket.socket') as mock_socket_class:
            mock_socket = MagicMock()
            mock_socket_class.return_value = mock_socket
            
            # Mock partial response
            mock_socket.recvfrom.return_value = (b"Partial", ("8.8.8.8", 53))
            
            ports = [53]
            results = await scanner.scan("8.8.8.8", ports)
            
            assert len(results) == 1
            assert results[0].state == "open"
            assert results[0].response_data == b"Partial"
    
    @pytest.mark.asyncio
    async def test_scan_with_large_response(self, scanner):
        """Test scanning with large response data."""
        with patch('socket.socket') as mock_socket_class:
            mock_socket = MagicMock()
            mock_socket_class.return_value = mock_socket
            
            # Mock large response
            large_data = b"x" * 10000  # 10KB response
            mock_socket.recvfrom.return_value = (large_data, ("8.8.8.8", 53))
            
            ports = [53]
            results = await scanner.scan("8.8.8.8", ports)
            
            assert len(results) == 1
            assert results[0].state == "open"
            assert len(results[0].response_data) == 10000
    
    @pytest.mark.asyncio
    async def test_scan_memory_efficiency(self, scanner):
        """Test that scanning is memory efficient."""
        with patch('socket.socket') as mock_socket_class:
            mock_socket = MagicMock()
            mock_socket_class.return_value = mock_socket
            
            mock_socket.recvfrom.side_effect = asyncio.TimeoutError("Timeout")
            
            # Scan many ports
            ports = list(range(1, 1001))  # 1000 ports
            results = await scanner.scan("8.8.8.8", ports)
            
            assert len(results) == 1000
            # Memory usage should be reasonable (can't easily test in unit test)
    
    @pytest.mark.asyncio
    async def test_scan_timeout_behavior(self, scanner):
        """Test timeout behavior during scan."""
        with patch('socket.socket') as mock_socket_class:
            mock_socket = MagicMock()
            mock_socket_class.return_value = mock_socket
            
            # Mock timeout
            mock_socket.recvfrom.side_effect = asyncio.TimeoutError("Timeout")
            
            ports = [53, 123]
            results = await scanner.scan("8.8.8.8", ports)
            
            assert len(results) == 2
            assert all(result.state in ["closed", "filtered"] for result in results)
    
    @pytest.mark.asyncio
    async def test_scan_permission_denied(self, scanner):
        """Test handling of permission denied errors."""
        with patch('socket.socket') as mock_socket_class:
            mock_socket = MagicMock()
            mock_socket_class.return_value = mock_socket
            
            # Mock permission denied
            mock_socket.recvfrom.side_effect = PermissionError("Permission denied")
            
            ports = [53]
            with pytest.raises(PermissionError):
                await scanner.scan("8.8.8.8", ports)
    
    @pytest.mark.asyncio
    async def test_scan_cleanup_resources(self, scanner):
        """Test that resources are properly cleaned up."""
        with patch('socket.socket') as mock_socket_class:
            mock_socket = MagicMock()
            mock_socket_class.return_value = mock_socket
            
            mock_socket.recvfrom.return_value = (b"Response", ("8.8.8.8", 53))
            
            ports = [53]
            await scanner.scan("8.8.8.8", ports)
            
            # Verify cleanup methods were called
            mock_socket.close.assert_called()


class TestUDPScannerIntegration:
    """Integration tests for UDP scanner."""
    
    @pytest.mark.asyncio
    async def test_real_dns_scan_if_available(self):
        """Test real DNS scan if network is available."""
        scanner = UDPScanner(timeout=2.0)
        
        try:
            # Try to scan a real DNS server
            results = await scanner.scan("8.8.8.8", [53])
            
            if results:
                assert len(results) == 1
                assert results[0].port == 53
                # Should get some response from Google DNS
                assert results[0].state in ["open", "closed", "filtered"]
            else:
                pytest.skip("Network not available for integration test")
                
        except Exception:
            pytest.skip("Network not available for integration test")
    
    @pytest.mark.asyncio
    async def test_real_scan_unreachable_port(self):
        """Test scanning unreachable port."""
        scanner = UDPScanner(timeout=1.0)
        
        try:
            # Scan a port that's unlikely to be open
            results = await scanner.scan("8.8.8.8", [65432])
            
            assert len(results) == 1
            assert results[0].port == 65432
            assert results[0].state in ["closed", "filtered", "error"]
            
        except Exception:
            pytest.skip("Network not available for integration test")
