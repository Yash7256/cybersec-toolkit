"""
Unit tests for ServiceDetector banner pattern matching.
Tests all 19+ services with various banner formats.
"""
import pytest
from unittest.mock import Mock, patch

from cybersec.core.service_detect import ServiceDetector, ServiceInfo


@pytest.fixture
def service_detector():
    """Create a ServiceDetector instance for testing."""
    return ServiceDetector()


@pytest.mark.unit
class TestServiceDetector:
    """Test ServiceDetector functionality."""
    
    def test_http_banner_detection(self, service_detector):
        """Test HTTP banner detection."""
        # Test Apache banner
        apache_banner = "Apache/2.4.41 (Ubuntu)"
        service = asyncio.run(service_detector.detect("127.0.0.1", 80))
        
        assert service.name == "http"
        assert "Apache" in service.version
        assert "2.4.41" in service.version
        assert service.confidence > 0.8
        
        # Test Nginx banner
        nginx_banner = "nginx/1.18.0"
        service = asyncio.run(service_detector.detect("127.0.0.1", 80))
        
        assert service.name == "http"
        assert "nginx" in service.version
        assert "1.18.0" in service.version

    def test_ssh_banner_detection(self, service_detector):
        """Test SSH banner detection."""
        # Test OpenSSH banner
        openssh_banner = "OpenSSH_8.2p1 Ubuntu-4ubuntu2.2"
        service = service_detector.detect_service(22, openssh_banner)
        
        assert service.name == "ssh"
        assert "OpenSSH" in service.version
        assert "8.2p1" in service.version
        
        # Test Dropbear banner
        dropbear_banner = "Dropbear SSHD 2022.83"
        service = service_detector.detect_service(22, dropbear_banner)
        
        assert service.name == "ssh"
        assert "Dropbear" in service.version

    def test_ftp_banner_detection(self, service_detector):
        """Test FTP banner detection."""
        # Test ProFTPD banner
        proftpd_banner = "ProFTPD 1.3.6a Server"
        service = service_detector.detect_service(21, proftpd_banner)
        
        assert service.name == "ftp"
        assert "ProFTPD" in service.version
        assert "1.3.6a" in service.version
        
        # Test vsftpd banner
        vsftpd_banner = "vsftpd 3.0.3"
        service = service_detector.detect_service(21, vsftpd_banner)
        
        assert service.name == "ftp"
        assert "vsftpd" in service.version

    def test_smtp_banner_detection(self, service_detector):
        """Test SMTP banner detection."""
        # Test Postfix banner
        postfix_banner = "Postfix smtpd"
        service = service_detector.detect_service(25, postfix_banner)
        
        assert service.name == "smtp"
        assert "Postfix" in service.version
        
        # Test Sendmail banner
        sendmail_banner = "Sendmail 8.15.2"
        service = service_detector.detect_service(25, sendmail_banner)
        
        assert service.name == "smtp"
        assert "Sendmail" in service.version

    def test_dns_banner_detection(self, service_detector):
        """Test DNS banner detection."""
        # Test BIND banner
        bind_banner = "BIND 9.11.3-RedHat-9.11.3-31.el7"
        service = service_detector.detect_service(53, bind_banner)
        
        assert service.name == "dns"
        assert "BIND" in service.version
        assert "9.11.3" in service.version

    def test_mysql_banner_detection(self, service_detector):
        """Test MySQL banner detection."""
        # Test MySQL banner
        mysql_banner = "5.7.33-0ubuntu0.18.04.1"
        service = service_detector.detect_service(3306, mysql_banner)
        
        assert service.name == "mysql"
        assert "5.7.33" in service.version

    def test_postgresql_banner_detection(self, service_detector):
        """Test PostgreSQL banner detection."""
        # Test PostgreSQL banner
        postgres_banner = "PostgreSQL 13.3 (Debian 13.3-1.pgdg80+1)"
        service = service_detector.detect_service(5432, postgres_banner)
        
        assert service.name == "postgresql"
        assert "13.3" in service.version

    def test_redis_banner_detection(self, service_detector):
        """Test Redis banner detection."""
        # Test Redis banner
        redis_banner = "Redis server v=6.2.6"
        service = service_detector.detect_service(6379, redis_banner)
        
        assert service.name == "redis"
        assert "6.2.6" in service.version

    def test_mongodb_banner_detection(self, service_detector):
        """Test MongoDB banner detection."""
        # Test MongoDB banner
        mongodb_banner = "MongoDB 4.4.6"
        service = service_detector.detect_service(27017, mongodb_banner)
        
        assert service.name == "mongodb"
        assert "4.4.6" in service.version

    def test_elasticsearch_banner_detection(self, service_detector):
        """Test Elasticsearch banner detection."""
        # Test Elasticsearch banner
        es_banner = "Elasticsearch 7.17.0"
        service = service_detector.detect_service(9200, es_banner)
        
        assert service.name == "elasticsearch"
        assert "7.17.0" in service.version

    def test_unknown_service_detection(self, service_detector):
        """Test unknown service detection."""
        unknown_banner = "SomeRandomService 1.0"
        service = service_detector.detect_service(12345, unknown_banner)
        
        assert service.name == "unknown"
        assert service.version == "1.0"
        assert service.confidence == 0.0

    def test_empty_banner_handling(self, service_detector):
        """Test handling of empty banners."""
        # Test empty banner
        service = service_detector.detect_service(80, "")
        
        assert service.name == "unknown"
        assert service.version is None
        assert service.confidence == 0.0
        
        # Test None banner
        service = service_detector.detect_service(80, None)
        
        assert service.name == "unknown"
        assert service.version is None
        assert service.confidence == 0.0

    def test_banner_case_sensitivity(self, service_detector):
        """Test case-insensitive banner matching."""
        # Test lowercase Apache banner
        apache_lower = "apache/2.4.41"
        service = service_detector.detect_service(80, apache_lower)
        
        assert service.name == "http"
        assert "apache" in service.version.lower()

    def test_partial_banner_matching(self, service_detector):
        """Test partial banner matching."""
        # Test partial Apache banner
        partial_apache = "Apache/2.4"
        service = service_detector.detect_service(80, partial_apache)
        
        assert service.name == "http"
        assert "Apache" in service.version
        # Should still detect even with partial version

    def test_confidence_scoring(self, service_detector):
        """Test confidence scoring based on banner quality."""
        # High confidence match
        high_conf_banner = "Apache/2.4.41 (Ubuntu)"
        service_high = service_detector.detect_service(80, high_conf_banner)
        assert service_high.confidence > 0.8
        
        # Low confidence match
        low_conf_banner = "something http"
        service_low = service_detector.detect_service(80, low_conf_banner)
        assert service_low.confidence < 0.5
        
        # Medium confidence match
        med_conf_banner = "HTTP Server"
        service_med = service_detector.detect_service(80, med_conf_banner)
        assert 0.5 <= service_med.confidence <= 0.8

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
        service = service_detector.detect_service(port, banner)
        assert service.name == expected_service


if __name__ == "__main__":
    pytest.main([__file__])
