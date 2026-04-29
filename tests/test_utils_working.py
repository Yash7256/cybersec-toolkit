"""
Working unit tests for utils module functions that actually exist.
"""
import pytest
import socket
from unittest.mock import patch, MagicMock

from cybersec.core.scanner.utils import (
    resolve_target, parse_ports, expand_target_range,
    format_duration
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


class TestFormatDuration:
    """Test duration formatting functionality."""
    
    def test_format_duration_seconds_only(self):
        """Test formatting duration with seconds only."""
        result = format_duration(45.5)
        assert result == "45s"
    
    def test_format_duration_minutes_only(self):
        """Test formatting duration with minutes only."""
        result = format_duration(120.0)
        assert result == "2m 0s"
    
    def test_format_duration_hours_only(self):
        """Test formatting duration with hours only."""
        result = format_duration(3600.0)
        assert result == "1h 0m 0s"
    
    def test_format_duration_complex(self):
        """Test formatting duration with hours, minutes, seconds."""
        result = format_duration(3665.5)
        assert result == "1h 1m 5s"
    
    def test_format_duration_zero(self):
        """Test formatting zero duration."""
        result = format_duration(0.0)
        assert result == "0s"
    
    def test_format_duration_large(self):
        """Test formatting large duration."""
        result = format_duration(7325.5)  # 2h 2m 5s
        assert result == "2h 2m 5s"
    
    def test_format_duration_fractional_seconds(self):
        """Test formatting duration with fractional seconds."""
        result = format_duration(45.9)
        assert result == "45s"  # Should truncate fractional part


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
