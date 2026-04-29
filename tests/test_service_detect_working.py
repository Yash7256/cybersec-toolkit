"""
Working unit tests for ServiceDetector.
Tests the actual methods available in the ServiceDetector class.
"""
import pytest
import asyncio
from unittest.mock import patch, Mock, AsyncMock

from cybersec.core.scanner.analysis.service_detect import ServiceDetector, ServiceInfo


@pytest.fixture
def service_detector():
    """Create a ServiceDetector instance for testing."""
    return ServiceDetector()


@pytest.mark.unit
class TestServiceDetector:
    """Test ServiceDetector functionality."""
    
    def test_port_service_map_exists(self, service_detector):
        """Test that port service mapping exists."""
        assert len(service_detector.PORT_SERVICE_MAP) > 0
        assert 80 in service_detector.PORT_SERVICE_MAP  # HTTP
        assert 22 in service_detector.PORT_SERVICE_MAP  # SSH
        assert 21 in service_detector.PORT_SERVICE_MAP  # FTP

    def test_banner_patterns_exist(self, service_detector):
        """Test that banner patterns are loaded."""
        assert len(service_detector.BANNER_PATTERNS) > 0
        
        # Check for SSH patterns
        ssh_patterns = [p for p in service_detector.BANNER_PATTERNS if p[1] == "ssh"]
        assert len(ssh_patterns) > 0
        
        # Check for FTP patterns
        ftp_patterns = [p for p in service_detector.BANNER_PATTERNS if p[1] == "ftp"]
        assert len(ftp_patterns) > 0

    def test_get_timeout_method(self, service_detector):
        """Test timeout configuration for different ports."""
        # Test HTTP timeout
        http_timeout = service_detector.get_timeout(80)
        assert http_timeout > 0
        
        # Test SSH timeout
        ssh_timeout = service_detector.get_timeout(22)
        assert ssh_timeout > 0
        
        # Test unknown port timeout
        unknown_timeout = service_detector.get_timeout(12345)
        assert unknown_timeout > 0

    @pytest.mark.asyncio
    async def test_detect_method_with_http_banner(self, service_detector):
        """Test the async detect method with HTTP banner."""
        with patch('asyncio.open_connection') as mock_connect:
            # Mock successful connection with HTTP banner
            mock_reader = Mock()
            mock_reader.read = AsyncMock(return_value=b"HTTP/1.1 200 OK\r\nServer: Apache/2.4.41 (Ubuntu)\r\n\r\n")
            mock_writer = Mock()
            mock_writer.write = Mock()
            mock_writer.drain = AsyncMock()
            mock_writer.close = Mock()
            mock_writer.wait_closed = AsyncMock()
            mock_connect.return_value = (mock_reader, mock_writer)
            
            service = await service_detector.detect("127.0.0.1", 80)
            
            assert service.name == "http"
            assert service.banner is not None
            assert "Apache" in service.banner
            assert service.confidence > 0

    @pytest.mark.asyncio
    async def test_detect_method_with_ssh_banner(self, service_detector):
        """Test the async detect method with SSH banner."""
        with patch('asyncio.open_connection') as mock_connect:
            # Mock successful connection with SSH banner
            mock_reader = Mock()
            mock_reader.read = AsyncMock(return_value=b"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu2.2\r\n")
            mock_writer = Mock()
            mock_writer.write = Mock()
            mock_writer.drain = AsyncMock()
            mock_writer.close = Mock()
            mock_writer.wait_closed = AsyncMock()
            mock_connect.return_value = (mock_reader, mock_writer)
            
            service = await service_detector.detect("127.0.0.1", 22)
            
            assert service.name == "ssh"
            assert service.banner is not None
            assert "OpenSSH" in service.banner
            assert service.confidence > 0

    @pytest.mark.asyncio
    async def test_detect_method_with_ftp_banner(self, service_detector):
        """Test the async detect method with FTP banner."""
        with patch('asyncio.open_connection') as mock_connect:
            # Mock successful connection with FTP banner
            mock_reader = Mock()
            mock_reader.read = AsyncMock(return_value=b"220 vsftpd 3.0.3\r\n")
            mock_writer = Mock()
            mock_writer.write = Mock()
            mock_writer.drain = AsyncMock()
            mock_writer.close = Mock()
            mock_writer.wait_closed = AsyncMock()
            mock_connect.return_value = (mock_reader, mock_writer)
            
            service = await service_detector.detect("127.0.0.1", 21)
            
            assert service.name == "ftp"
            assert service.banner is not None
            assert "vsftpd" in service.banner
            assert service.confidence > 0

    @pytest.mark.asyncio
    async def test_detect_method_with_empty_response(self, service_detector):
        """Test the async detect method with empty response."""
        with patch('asyncio.open_connection') as mock_connect:
            # Mock successful connection with empty response
            mock_reader = Mock()
            mock_reader.read = AsyncMock(return_value=b"")
            mock_writer = Mock()
            mock_writer.write = Mock()
            mock_writer.drain = AsyncMock()
            mock_writer.close = Mock()
            mock_writer.wait_closed = AsyncMock()
            mock_connect.return_value = (mock_reader, mock_writer)
            
            service = await service_detector.detect("127.0.0.1", 12345)
            
            assert service.name == "unknown"
            assert service.confidence <= 20  # May have some base confidence

    @pytest.mark.asyncio
    async def test_detect_method_with_timeout(self, service_detector):
        """Test the async detect method with timeout."""
        with patch('asyncio.open_connection') as mock_connect:
            # Mock connection timeout
            mock_connect.side_effect = asyncio.TimeoutError()
            
            service = await service_detector.detect("127.0.0.1", 12345)
            
            assert service.name == "unknown"
            assert service.confidence <= 15  # May have some base confidence

    @pytest.mark.asyncio
    async def test_detect_method_with_connection_refused(self, service_detector):
        """Test the async detect method with connection refused."""
        with patch('asyncio.open_connection') as mock_connect:
            # Mock connection refused
            mock_connect.side_effect = ConnectionRefusedError()
            
            service = await service_detector.detect("127.0.0.1", 12345)
            
            assert service.name == "unknown"
            assert service.confidence <= 15  # May have some base confidence

    @pytest.mark.asyncio
    async def test_probe_protocol_method(self, service_detector):
        """Test the probe_protocol method for specific services."""
        with patch('asyncio.open_connection') as mock_connect:
            # Mock successful connection with data
            mock_reader = Mock()
            mock_reader.read = AsyncMock(return_value=b"SSH-2.0-OpenSSH_8.2p1")
            mock_writer = Mock()
            mock_writer.write = Mock()
            mock_writer.drain = AsyncMock()
            mock_writer.close = Mock()
            mock_writer.wait_closed = AsyncMock()
            mock_connect.return_value = (mock_reader, mock_writer)
            
            service = await service_detector.probe_protocol("127.0.0.1", 22)
            
            assert service is not None
            assert service.name == "ssh"
            assert service.confidence > 0

    def test_service_info_dataclass(self):
        """Test ServiceInfo dataclass functionality."""
        # Test with all fields
        service = ServiceInfo(
            name="http",
            version="Apache/2.4.41",
            banner="Apache/2.4.41 (Ubuntu)",
            confidence=95
        )
        
        assert service.name == "http"
        assert service.version == "Apache/2.4.41"
        assert service.banner == "Apache/2.4.41 (Ubuntu)"
        assert service.confidence == 95
        
        # Test with minimal fields
        service_min = ServiceInfo(name="unknown")
        
        assert service_min.name == "unknown"
        assert service_min.version is None
        assert service_min.banner is None
        assert service_min.confidence == 0

    @pytest.mark.parametrize("port,expected_service", [
        (21, "ftp"),
        (22, "ssh"),
        (80, "http"),
        (443, "https"),
        (3306, "mysql"),
        (5432, "postgresql"),
        (6379, "redis"),
        (27017, "mongodb"),
        (9200, "elasticsearch"),
    ])
    def test_port_service_mapping(self, service_detector, port, expected_service):
        """Test port to service mapping."""
        assert service_detector.PORT_SERVICE_MAP[port] == expected_service


if __name__ == "__main__":
    pytest.main([__file__])
