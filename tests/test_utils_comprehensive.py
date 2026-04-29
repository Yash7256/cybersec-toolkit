"""
Comprehensive unit tests for utils module functions.
"""
import pytest
import socket
from unittest.mock import patch, MagicMock

from cybersec.core.scanner.utils import (
    resolve_target, parse_ports, expand_target_range,
    _validate_target_security, format_duration
)


class TestResolveTarget:
    """Test target resolution functionality."""
    
    def test_resolve_target_public_ip(self):
        """Test resolving a public IP address."""
        result = resolve_target("8.8.8.8")
        assert result == "8.8.8.8"
    
    def test_resolve_target_public_domain(self):
        """Test resolving a public domain."""
        result = resolve_target("google.com")
        assert result is not None
        # Should be a valid IP address
        assert isinstance(result, str)
        assert len(result.split('.')) == 4
    
    def test_resolve_target_blocked_localhost(self):
        """Test that localhost is blocked."""
        with pytest.raises(ValueError, match="Invalid or blocked target"):
            resolve_target("127.0.0.1")
    
    def test_resolve_target_blocked_localhost_name(self):
        """Test that localhost name is blocked."""
        with pytest.raises(ValueError, match="Invalid or blocked target"):
            resolve_target("localhost")
    
    def test_resolve_target_blocked_zero_address(self):
        """Test that 0.0.0.0 is blocked."""
        with pytest.raises(ValueError, match="Invalid or blocked target"):
            resolve_target("0.0.0.0")
    
    def test_resolve_target_blocked_broadcast(self):
        """Test that broadcast address is blocked."""
        with pytest.raises(ValueError, match="Invalid or blocked target"):
            resolve_target("255.255.255.255")
    
    def test_resolve_target_blocked_ipv6_localhost(self):
        """Test that IPv6 localhost is blocked."""
        with pytest.raises(ValueError, match="Invalid or blocked target"):
            resolve_target("::1")
    
    def test_resolve_target_blocked_private_ip_10(self):
        """Test that 10.0.0.0/8 range is blocked."""
        with pytest.raises(ValueError, match="Private IP ranges are not allowed"):
            resolve_target("10.0.0.1")
    
    def test_resolve_target_blocked_private_ip_172(self):
        """Test that 172.16.0.0/12 range is blocked."""
        with pytest.raises(ValueError, match="Private IP ranges are not allowed"):
            resolve_target("172.16.0.1")
    
    def test_resolve_target_blocked_private_ip_192(self):
        """Test that 192.168.0.0/16 range is blocked."""
        with pytest.raises(ValueError, match="Private IP ranges are not allowed"):
            resolve_target("192.168.1.1")
    
    def test_resolve_target_blocked_link_local(self):
        """Test that link-local range is blocked."""
        with pytest.raises(ValueError, match="Private IP ranges are not allowed"):
            resolve_target("169.254.0.1")
    
    def test_resolve_target_invalid_domain(self):
        """Test resolving invalid domain."""
        with pytest.raises(ValueError, match="Could not resolve target"):
            resolve_target("this.domain.does.not.exist.12345")
    
    def test_resolve_target_empty_string(self):
        """Test resolving empty string."""
        with pytest.raises(ValueError, match="Could not resolve target"):
            resolve_target("")
    
    def test_resolve_target_whitespace_only(self):
        """Test resolving whitespace only."""
        with pytest.raises(ValueError, match="Could not resolve target"):
            resolve_target("   ")
    
    def test_resolve_target_with_scheme(self):
        """Test resolving target with URL scheme."""
        result = resolve_target("http://example.com")
        assert result is not None
        assert result != "http://example.com"  # Scheme should be stripped
    
    def test_resolve_target_invalid_ip_format(self):
        """Test resolving invalid IP format."""
        with pytest.raises(ValueError, match="Could not resolve target"):
            resolve_target("999.999.999.999")
    
    def test_resolve_target_negative_octet(self):
        """Test resolving IP with negative octet."""
        with pytest.raises(ValueError, match="Could not resolve target"):
            resolve_target("192.168.1.-1")
    
    def test_resolve_target_large_octet(self):
        """Test resolving IP with large octet."""
        with pytest.raises(ValueError, match="Could not resolve target"):
            resolve_target("192.168.1.256")


class TestParsePorts:
    """Test port parsing functionality."""
    
    def test_parse_ports_common(self):
        """Test parsing 'common' ports."""
        ports = parse_ports("common")
        assert isinstance(ports, list)
        assert len(ports) > 0
        assert 80 in ports
        assert 443 in ports
        assert 22 in ports
    
    def test_parse_ports_top1000(self):
        """Test parsing 'top1000' ports."""
        ports = parse_ports("top1000")
        assert isinstance(ports, list)
        assert len(ports) == 1000
        assert 80 in ports
        assert 443 in ports
    
    def test_parse_ports_all(self):
        """Test parsing 'all' ports."""
        ports = parse_ports("all")
        assert isinstance(ports, list)
        assert len(ports) == 65535
        assert 1 in ports
        assert 65535 in ports
    
    def test_parse_ports_single_port(self):
        """Test parsing single port."""
        ports = parse_ports("80")
        assert ports == [80]
    
    def test_parse_port_range(self):
        """Test parsing port range."""
        ports = parse_ports("80-85")
        assert ports == [80, 81, 82, 83, 84, 85]
    
    def test_parse_port_range_single_to_single(self):
        """Test parsing range with same start and end."""
        ports = parse_ports("80-80")
        assert ports == [80]
    
    def test_parse_comma_separated_ports(self):
        """Test parsing comma-separated ports."""
        ports = parse_ports("80,443,8080")
        assert ports == [80, 443, 8080]
    
    def test_parse_mixed_format(self):
        """Test parsing mixed format (ranges and singles)."""
        ports = parse_ports("80-82,443,8080-8082")
        expected = [80, 81, 82, 443, 8080, 8081, 8082]
        assert ports == expected
    
    def test_parse_ports_invalid_zero(self):
        """Test parsing port 0 (should be invalid)."""
        with pytest.raises(ValueError, match="Port out of range"):
            parse_ports("0")
    
    def test_parse_ports_invalid_too_high(self):
        """Test parsing port > 65535."""
        with pytest.raises(ValueError, match="Port out of range"):
            parse_ports("65536")
    
    def test_parse_ports_invalid_negative(self):
        """Test parsing negative port."""
        with pytest.raises(ValueError, match="Invalid port format"):
            parse_ports("-1")
    
    def test_parse_ports_invalid_non_numeric(self):
        """Test parsing non-numeric port."""
        with pytest.raises(ValueError, match="Invalid port format"):
            parse_ports("abc")
    
    def test_parse_ports_invalid_range_too_high(self):
        """Test parsing range with end > 65535."""
        with pytest.raises(ValueError, match="Port out of range"):
            parse_ports("80-65536")
    
    def test_parse_ports_invalid_range_negative(self):
        """Test parsing range with negative start."""
        with pytest.raises(ValueError, match="Invalid port format"):
            parse_ports("-1-100")
    
    def test_parse_ports_invalid_range_reversed(self):
        """Test parsing range with start > end."""
        with pytest.raises(ValueError, match="Invalid port range"):
            parse_ports("100-80")
    
    def test_parse_ports_invalid_in_list(self):
        """Test parsing list with invalid port."""
        with pytest.raises(ValueError, match="Port out of range"):
            parse_ports("80,443,99999")
    
    def test_parse_ports_empty_string(self):
        """Test parsing empty string."""
        with pytest.raises(ValueError, match="Invalid port format"):
            parse_ports("")
    
    def test_parse_ports_duplicate_removal(self):
        """Test that duplicate ports are removed."""
        ports = parse_ports("80,80,443,443")
        assert ports == [80, 443]
    
    def test_parse_ports_sorting(self):
        """Test that ports are returned sorted."""
        ports = parse_ports("443,80,8080")
        assert ports == [80, 443, 8080]


class TestExpandTargetRange:
    """Test target range expansion functionality."""
    
    def test_expand_single_ip(self):
        """Test expanding single IP."""
        targets = expand_target_range("8.8.8.8")
        assert targets == ["8.8.8.8"]
    
    def test_expand_single_domain(self):
        """Test expanding single domain."""
        targets = expand_target_range("google.com")
        assert len(targets) == 1
        # Should resolve to an IP
        assert targets[0] != "google.com"
    
    def test_expand_cidr_range_small(self):
        """Test expanding small CIDR range."""
        targets = expand_target_range("8.8.8.0/30")
        assert len(targets) == 2  # 8.8.8.1 and 8.8.8.2 (excluding network and broadcast)
        assert "8.8.8.1" in targets
        assert "8.8.8.2" in targets
    
    def test_expand_cidr_range_medium(self):
        """Test expanding medium CIDR range."""
        targets = expand_target_range("8.8.8.0/29")
        assert len(targets) == 6  # 8 usable IPs from /29
    
    def test_expand_multiple_targets(self):
        """Test expanding multiple targets."""
        targets = expand_target_range("8.8.8.8,1.1.1.1")
        assert targets == ["8.8.8.8", "1.1.1.1"]
    
    def test_expand_mixed_targets(self):
        """Test expanding mixed targets (IPs, domains, CIDR)."""
        targets = expand_target_range("8.8.8.8,google.com,8.8.8.0/30")
        assert len(targets) >= 4  # 8.8.8.8 + google.com + 2 from CIDR
        assert "8.8.8.8" in targets
        assert "8.8.8.1" in targets
        assert "8.8.8.2" in targets
    
    def test_expand_invalid_cidr(self):
        """Test expanding invalid CIDR."""
        with pytest.raises(Exception):
            expand_target_range("8.8.8.0/33")
    
    def test_expand_empty_string(self):
        """Test expanding empty string."""
        with pytest.raises(Exception):
            expand_target_range("")
    
    def test_expand_private_cidr_filtered(self):
        """Test that private CIDR ranges are filtered out."""
        # This should be filtered by resolve_target
        targets = expand_target_range("192.168.1.0/30")
        # Should either be empty or contain only public IPs
        for target in targets:
            assert not target.startswith("192.168.")


class TestValidationFunctions:
    """Test validation utility functions."""
    
    def test_validate_target_valid_public_ip(self):
        """Test validating valid public IP."""
        assert validate_target("8.8.8.8") is True
    
    def test_validate_target_valid_domain(self):
        """Test validating valid domain."""
        assert validate_target("google.com") is True
    
    def test_validate_target_private_ip(self):
        """Test validating private IP (should be invalid)."""
        assert validate_target("192.168.1.1") is False
    
    def test_validate_target_localhost(self):
        """Test validating localhost (should be invalid)."""
        assert validate_target("127.0.0.1") is False
    
    def test_validate_target_invalid(self):
        """Test validating invalid target."""
        assert validate_target("invalid.target") is False
    
    def test_is_private_ip_private_ranges(self):
        """Test private IP detection."""
        assert is_private_ip("10.0.0.1") is True
        assert is_private_ip("172.16.0.1") is True
        assert is_private_ip("192.168.1.1") is True
        assert is_private_ip("169.254.0.1") is True  # Link-local
    
    def test_is_private_ip_public_ranges(self):
        """Test public IP detection."""
        assert is_private_ip("8.8.8.8") is False
        assert is_private_ip("1.1.1.1") is False
        assert is_private_ip("93.184.216.34") is False
    
    def test_is_private_ip_special_addresses(self):
        """Test special IP addresses."""
        assert is_private_ip("127.0.0.1") is True  # Loopback
        assert is_private_ip("0.0.0.0") is True     # Unspecified
        assert is_private_ip("255.255.255.255") is True  # Broadcast
    
    def test_is_private_ip_invalid_format(self):
        """Test invalid IP format."""
        assert is_private_ip("invalid.ip") is False
        assert is_private_ip("999.999.999.999") is False
    
    def test_is_valid_port_valid_ports(self):
        """Test valid port numbers."""
        assert is_valid_port(80) is True
        assert is_valid_port(443) is True
        assert is_valid_port(1) is True
        assert is_valid_port(65535) is True
    
    def test_is_valid_port_invalid_ports(self):
        """Test invalid port numbers."""
        assert is_valid_port(0) is False
        assert is_valid_port(-1) is False
        assert is_valid_port(65536) is False
        assert is_valid_port(100000) is False


class TestUtilityFunctions:
    """Test other utility functions."""
    
    def test_format_port_list_empty(self):
        """Test formatting empty port list."""
        result = format_port_list([])
        assert result == ""
    
    def test_format_port_list_single(self):
        """Test formatting single port."""
        result = format_port_list([80])
        assert result == "80"
    
    def test_format_port_list_multiple(self):
        """Test formatting multiple ports."""
        result = format_port_list([80, 443, 8080])
        assert result == "80,443,8080"
    
    def test_format_port_list_unsorted(self):
        """Test formatting unsorted port list."""
        result = format_port_list([8080, 80, 443])
        assert result == "80,443,8080"  # Should be sorted
    
    def test_format_port_list_with_duplicates(self):
        """Test formatting port list with duplicates."""
        result = format_port_list([80, 443, 80, 443])
        assert result == "80,443"  # Duplicates should be removed
    
    def test_get_common_ports(self):
        """Test getting common ports list."""
        ports = get_common_ports()
        assert isinstance(ports, list)
        assert len(ports) > 0
        assert 80 in ports
        assert 443 in ports
        assert 22 in ports
        assert 21 in ports
        assert 25 in ports
    
    def test_get_top_1000_ports(self):
        """Test getting top 1000 ports list."""
        ports = get_top_1000_ports()
        assert isinstance(ports, list)
        assert len(ports) == 1000
        assert 80 in ports
        assert 443 in ports
        assert 22 in ports
    
    def test_common_ports_subset_of_top1000(self):
        """Test that common ports are subset of top 1000."""
        common = get_common_ports()
        top1000 = get_top_1000_ports()
        
        for port in common:
            assert port in top1000
    
    def test_port_lists_are_sorted(self):
        """Test that port lists are returned sorted."""
        common = get_common_ports()
        top1000 = get_top_1000_ports()
        
        assert common == sorted(common)
        assert top1000 == sorted(top1000)
    
    def test_port_lists_no_duplicates(self):
        """Test that port lists have no duplicates."""
        common = get_common_ports()
        top1000 = get_top_1000_ports()
        
        assert len(common) == len(set(common))
        assert len(top1000) == len(set(top1000))


class TestEdgeCases:
    """Test edge cases and error conditions."""
    
    def test_resolve_target_dns_timeout(self):
        """Test DNS timeout handling."""
        with patch('socket.gethostbyname') as mock_gethostbyname:
            mock_gethostbyname.side_effect = socket.gaierror("Timed out")
            
            with pytest.raises(ValueError, match="Could not resolve target"):
                resolve_target("timeout.example.com")
    
    def test_resolve_target_dns_rebinding_protection(self):
        """Test DNS rebinding protection."""
        # Mock DNS that resolves to private IP
        with patch('socket.gethostbyname') as mock_gethostbyname:
            mock_gethostbyname.return_value = "192.168.1.100"
            
            with pytest.raises(ValueError, match="Private IP ranges are not allowed"):
                resolve_target("malicious.example.com")
    
    def test_parse_ports_large_range_memory(self):
        """Test parsing large port range doesn't cause memory issues."""
        # This should handle large ranges efficiently
        ports = parse_ports("1-1000")
        assert len(ports) == 1000
        assert ports[0] == 1
        assert ports[-1] == 1000
    
    def test_expand_target_large_cidr(self):
        """Test expanding large CIDR range."""
        # This should handle large CIDR ranges
        targets = expand_target_range("8.8.8.0/24")
        assert len(targets) == 254  # 256 total - network and broadcast
    
    def test_malformed_input_handling(self):
        """Test handling of various malformed inputs."""
        malformed_targets = [
            "",  # Empty
            "   ",  # Whitespace only
            "http://",  # Incomplete URL
            "ftp://example.com",  # Different scheme
            "https://example.com/path",  # URL with path
        ]
        
        for target in malformed_targets:
            with pytest.raises(ValueError):
                resolve_target(target)
    
    def test_unicode_handling(self):
        """Test handling of unicode characters in input."""
        # Should handle unicode gracefully
        with pytest.raises(ValueError):
            resolve_target("tëst.exãmple.com")
    
    def test_very_long_input(self):
        """Test handling of very long input strings."""
        very_long_port = ",".join(str(i) for i in range(1, 1000))
        ports = parse_ports(very_long_port)
        assert len(ports) == 999
