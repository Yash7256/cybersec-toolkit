"""
Unit tests for utility functions.
Tests CIDR expansion, IP validation, DNS rebinding protection, and private IP blocking.
"""
import pytest
import ipaddress
from unittest.mock import patch

from cybersec.core.utils import (
    expand_target_range, 
    resolve_target, 
    parse_ports,
    _validate_target_security
)


@pytest.mark.unit
class TestUtils:
    """Test utility functions."""
    
    def test_expand_cidr_range_ipv4(self):
        """Test IPv4 CIDR range expansion."""
        # Test /24 network
        targets = expand_target_range("192.168.1.0/24")
        
        assert len(targets) == 254  # 256 total - 2 (network + broadcast)
        assert "192.168.1.1" in targets
        assert "192.168.1.254" in targets
        assert "192.168.1.0" not in targets  # Network address excluded
        assert "192.168.1.255" not in targets  # Broadcast address excluded
        
        # Test /30 network
        targets = expand_target_range("10.0.0.0/30")
        assert len(targets) == 30  # /30 has 32 addresses, exclude network + broadcast
        assert "10.0.0.1" in targets
        assert "10.0.0.30" in targets
        
        # Test /32 network
        targets = expand_target_range("172.16.0.0/32")
        assert len(targets) == 2  # Only 2 usable addresses
        assert "172.16.0.1" in targets
        assert "172.16.0.2" in targets

    def test_expand_cidr_range_ipv6(self):
        """Test IPv6 CIDR range expansion."""
        # Test IPv6 /124 network
        targets = expand_target_range("2001:db8::/124")
        
        assert len(targets) == 126  # /124 has 128 addresses, exclude network address
        assert "2001:db8::1" in targets
        assert "2001:db8::ffff:ffff" not in targets  # Should be filtered out

    def test_expand_ip_range(self):
        """Test IP range expansion."""
        # Test simple range
        targets = expand_target_range("192.168.1.1-192.168.1.5")
        
        assert len(targets) == 5
        assert targets == ["192.168.1.1", "192.168.1.2", "192.168.1.3", "192.168.1.4", "192.168.1.5"]
        
        # Test reverse range
        targets = expand_target_range("10.0.0.5-10.0.0.1")
        
        assert len(targets) == 4
        assert targets == ["10.0.0.5", "10.0.0.4", "10.0.0.3", "10.0.0.2"]

    def test_expand_single_ip(self):
        """Test single IP expansion."""
        targets = expand_target_range("192.168.1.1")
        
        assert len(targets) == 1
        assert targets == ["192.168.1.1"]

    def test_expand_hostname(self):
        """Test hostname expansion."""
        with patch('socket.gethostbyname') as mock_gethost:
            mock_gethost.return_value = "93.184.216.34"
            
            targets = expand_target_range("example.com")
            
            assert len(targets) == 1
            assert targets == ["93.184.216.34"]
            mock_gethost.assert_called_once_with("example.com")

    def test_validate_private_ipv4_blocking(self):
        """Test private IPv4 address blocking."""
        private_ranges = [
            ("10.0.0.0", "10.255.255.255"),
            ("172.16.0.0", "172.31.255.255"),
            ("192.168.0.0", "192.168.255.255"),
            ("169.254.0.0", "169.254.255.255")
        ]
        
        for start_ip, end_ip in private_ranges:
            with pytest.raises(ValueError, match="Private IP ranges are not allowed"):
                _validate_target_security(start_ip)
            
            with pytest.raises(ValueError, match="Private IP ranges are not allowed"):
                _validate_target_security(end_ip)

    def test_validate_private_ipv6_blocking(self):
        """Test private IPv6 address blocking."""
        private_ipv6 = [
            "fc00::/7",
            "fe80::/10",
            "::1",
            "2001:db8::/1"
        ]
        
        for ipv6 in private_ipv6:
            with pytest.raises(ValueError, match="Private IP ranges are not allowed"):
                _validate_target_security(ipv6)

    def test_validate_blocked_ips(self):
        """Test blocked IP addresses."""
        blocked_ips = ["127.0.0.1", "localhost", "0.0.0.0", "255.255.255.255", "::1"]
        
        for blocked_ip in blocked_ips:
            with pytest.raises(ValueError, match="Invalid or blocked target"):
                _validate_target_security(blocked_ip)

    def test_dns_rebinding_protection(self):
        """Test DNS rebinding protection."""
        with patch('socket.gethostbyname') as mock_gethost:
            # Mock DNS resolving to private IP
            mock_gethost.return_value = "192.168.1.100"
            
            with pytest.raises(ValueError, match="DNS rebinding to private IP detected"):
                _validate_target_security("example.com")

    def test_validate_public_ip_allowed(self):
        """Test that public IPs are allowed."""
        public_ips = ["8.8.8.8", "1.1.1.1", "2001:db8::2"]
        
        for public_ip in public_ips:
            # Should not raise any exceptions
            try:
                _validate_target_security(public_ip)
            except ValueError:
                pytest.fail(f"Public IP {public_ip} should be allowed")

    def test_parse_ports_common(self):
        """Test common ports parsing."""
        ports = parse_ports("common")
        
        # Should include typical common ports
        assert 21 in ports  # FTP
        assert 22 in ports  # SSH
        assert 23 in ports  # Telnet
        assert 25 in ports  # SMTP
        assert 53 in ports  # DNS
        assert 80 in ports  # HTTP
        assert 443 in ports  # HTTPS
        assert 3306 in ports  # MySQL
        assert 5432 in ports  # PostgreSQL
        assert 3389 in ports  # RDP

    def test_parse_ports_top100(self):
        """Test top100 ports parsing."""
        ports = parse_ports("top100")
        
        assert len(ports) == 100
        assert all(1 <= p <= 65535 for p in ports)

    def test_parse_ports_all(self):
        """Test all ports parsing."""
        ports = parse_ports("all")
        
        assert len(ports) == 65535
        assert ports[0] == 1
        assert ports[-1] == 65535

    def test_parse_port_ranges(self):
        """Test port range parsing."""
        # Test single port
        ports = parse_ports("80")
        assert ports == [80]
        
        # Test comma-separated
        ports = parse_ports("80,443,8080")
        assert ports == [80, 443, 8080]
        
        # Test range
        ports = parse_ports("1-100")
        assert len(ports) == 100
        assert ports[0] == 1
        assert ports[-1] == 100

    def test_parse_ports_invalid(self):
        """Test invalid port specifications."""
        with pytest.raises(ValueError):
            parse_ports("invalid")
        
        with pytest.raises(ValueError):
            parse_ports("0")  # Port 0 should fail
        
        with pytest.raises(ValueError):
            parse_ports("65536")  # Port > 65535 should fail

    @pytest.mark.parametrize("target,expected_count", [
        ("192.168.1.0/30", 30),
        ("10.0.0.0/24", 254),
        ("172.16.0.0/28", 14),
        ("2001:db8::/124", 126),
        ("192.168.1.1-192.168.1.100", 100),
        ("example.com", 1),
    ])
    def test_expand_target_range_comprehensive(self, target, expected_count):
        """Comprehensive test of target range expansion."""
        targets = expand_target_range(target)
        assert len(targets) == expected_count
        
        # All targets should be valid IP addresses
        for target_ip in targets:
            try:
                ipaddress.ip_address(target_ip)
            except ValueError:
                pytest.fail(f"Target {target_ip} is not a valid IP address")

    def test_edge_cases(self):
        """Test edge cases for target expansion."""
        # Test very large CIDR range
        targets = expand_target_range("0.0.0.0/8")
        assert len(targets) == 16777215  # 2^24 - 2
        
        # Test single IP in /32
        targets = expand_target_range("192.168.1.1/32")
        assert len(targets) == 1
        assert targets[0] == "192.168.1.1"


if __name__ == "__main__":
    pytest.main([__file__])
