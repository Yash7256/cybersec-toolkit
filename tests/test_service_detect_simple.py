"""
Simplified unit tests for ServiceDetector pattern matching.
Tests the core pattern matching functionality without network calls.
"""
import pytest
from unittest.mock import patch

from cybersec.core.service_detect import ServiceDetector


@pytest.fixture
def service_detector():
    """Create a ServiceDetector instance for testing."""
    return ServiceDetector()


@pytest.mark.unit
class TestServiceDetector:
    """Test ServiceDetector functionality."""
    
    def test_service_patterns_exist(self, service_detector):
        """Test that service patterns are loaded."""
        assert len(service_detector.service_patterns) > 0
        assert 80 in service_detector.service_patterns  # HTTP
        assert 22 in service_detector.service_patterns  # SSH
        assert 21 in service_detector.service_patterns  # FTP

    def test_http_pattern_matching(self, service_detector):
        """Test HTTP pattern matching."""
        # Test Apache banner
        apache_banner = "Apache/2.4.41 (Ubuntu)"
        service_info = service_detector._match_banner(80, apache_banner)
        
        assert service_info is not None
        assert service_info.name == "http"
        assert "Apache" in service_info.version
        assert "2.4.41" in service_info.version
        assert service_info.confidence > 0.8
        
        # Test Nginx banner
        nginx_banner = "nginx/1.18.0"
        service_info = service_detector._match_banner(80, nginx_banner)
        
        assert service_info is not None
        assert service_info.name == "http"
        assert "nginx" in service_info.version
        assert "1.18.0" in service_info.version

    def test_ssh_pattern_matching(self, service_detector):
        """Test SSH pattern matching."""
        # Test OpenSSH banner
        openssh_banner = "OpenSSH_8.2p1 Ubuntu-4ubuntu2.2"
        service_info = service_detector._match_banner(22, openssh_banner)
        
        assert service_info is not None
        assert service_info.name == "ssh"
        assert "OpenSSH" in service_info.version
        assert "8.2p1" in service_info.version

    def test_ftp_pattern_matching(self, service_detector):
        """Test FTP pattern matching."""
        # Test ProFTPD banner
        proftpd_banner = "ProFTPD 1.3.6a Server"
        service_info = service_detector._match_banner(21, proftpd_banner)
        
        assert service_info is not None
        assert service_info.name == "ftp"
        assert "ProFTPD" in service_info.version
        assert "1.3.6a" in service_info.version
        
        # Test vsftpd banner
        vsftpd_banner = "vsftpd 3.0.3"
        service_info = service_detector._match_banner(21, vsftpd_banner)
        
        assert service_info is not None
        assert service_info.name == "ftp"
        assert "vsftpd" in service_info.version

    def test_unknown_service_handling(self, service_detector):
        """Test unknown service detection."""
        unknown_banner = "SomeRandomService 1.0"
        service_info = service_detector._match_banner(12345, unknown_banner)
        
        assert service_info is not None
        assert service_info.name == "unknown"
        assert service_info.version == "1.0"
        assert service_info.confidence == 0.0

    def test_empty_banner_handling(self, service_detector):
        """Test handling of empty banners."""
        # Test empty banner
        service_info = service_detector._match_banner(80, "")
        
        assert service_info is not None
        assert service_info.name == "unknown"
        assert service_info.version is None
        assert service_info.confidence == 0.0
        
        # Test None banner
        service_info = service_detector._match_banner(80, None)
        
        assert service_info is not None
        assert service_info.name == "unknown"
        assert service_info.version is None
        assert service_info.confidence == 0.0

    def test_banner_case_sensitivity(self, service_detector):
        """Test case-insensitive banner matching."""
        # Test lowercase Apache banner
        apache_lower = "apache/2.4.41"
        service_info = service_detector._match_banner(80, apache_lower)
        
        assert service_info is not None
        assert service_info.name == "http"
        assert "apache" in service_info.version.lower()

    def test_confidence_scoring(self, service_detector):
        """Test confidence scoring based on banner quality."""
        # High confidence match
        high_conf_banner = "Apache/2.4.41 (Ubuntu)"
        service_high = service_detector._match_banner(80, high_conf_banner)
        assert service_high.confidence > 0.8
        
        # Low confidence match
        low_conf_banner = "something http"
        service_low = service_detector._match_banner(80, low_conf_banner)
        assert service_low.confidence < 0.5
        
        # Medium confidence match
        med_conf_banner = "HTTP Server"
        service_med = service_detector._match_banner(80, med_conf_banner)
        assert 0.5 <= service_med.confidence <= 0.8

    def test_timeout_configuration(self, service_detector):
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
    async def test_detect_method_with_mock(self, service_detector):
        """Test the async detect method with mocked network calls."""
        with patch('asyncio.open_connection') as mock_connect:
            # Mock successful connection with banner
            mock_reader = Mock()
            mock_reader.read = AsyncMock(return_value=b"Apache/2.4.41 (Ubuntu)")
            mock_writer = Mock()
            mock_writer.close = Mock()
            mock_writer.wait_closed = AsyncMock()
            mock_connect.return_value = (mock_reader, mock_writer)
            
            service = await service_detector.detect("127.0.0.1", 80)
            
            assert service.name == "http"
            assert "Apache" in service.version
            mock_connect.assert_called_once()

    @pytest.mark.parametrize("port,banner,expected_service", [
        (22, "SSH-2.0-OpenSSH", "ssh"),
        (80, "nginx/1.0.0", "http"),
        (21, "FileZilla Server 0.9.60", "ftp"),
        (25, "Microsoft ESMTP", "smtp"),
        (53, "BIND 9.16.1", "dns"),
        (3306, "5.7.33", "mysql"),
        (5432, "PostgreSQL 13.3", "postgresql"),
        (6379, "Redis 6.2.6", "redis"),
    ])
    def test_various_service_detection(self, service_detector, port, banner, expected_service):
        """Parametrized test for various service detection."""
        service_info = service_detector._match_banner(port, banner)
        
        assert service_info is not None
        assert service_info.name == expected_service


if __name__ == "__main__":
    pytest.main([__file__])
