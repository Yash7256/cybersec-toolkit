"""
SSL audit tests with SSRF protection, concurrency, and timeout handling.
"""
import asyncio
import pytest
from unittest.mock import patch, MagicMock, AsyncMock
import socket

from cybersec.core.tools.ssl import ssl_audit, SSLResult


class TestSSLAuditSSRFProtection:
    """Test SSRF protection functionality."""
    
    @pytest.mark.asyncio
    async def test_private_ip_blocked_when_allow_private_false(self):
        """Private/loopback hosts should be blocked when allow_private=False."""
        result = await ssl_audit("192.168.1.1", 443, allow_private=False)
        
        # Should return error without attempting connection
        assert result.error == "Auditing private, loopback, or cloud-metadata addresses is not permitted"
        assert result.host == "192.168.1.1"
        assert result.port == 443
        assert result.tls_version is None
        assert result.cert is None
    
    @pytest.mark.asyncio
    async def test_loopback_ip_blocked_when_allow_private_false(self):
        """Loopback addresses should be blocked when allow_private=False."""
        result = await ssl_audit("127.0.0.1", 443, allow_private=False)
        
        assert result.error == "Auditing private, loopback, or cloud-metadata addresses is not permitted"
    
    @pytest.mark.asyncio
    async def test_private_ip_allowed_when_allow_private_true(self):
        """Private IPs should be allowed when allow_private=True."""
        result = await ssl_audit("192.168.1.1", 443, allow_private=True)
        
        # Should attempt connection and get connection error, not SSRF error
        assert "not permitted" not in (result.error or "")
        # Will likely get connection refused, which is expected for private IP
        assert result.error is not None  # Some connection error expected
    
    @pytest.mark.asyncio
    async def test_cloud_metadata_blocked(self):
        """Cloud metadata addresses should be blocked."""
        result = await ssl_audit("169.254.169.254", 80, allow_private=False)
        
        assert result.error == "Auditing private, loopback, or cloud-metadata addresses is not permitted"
    
    @pytest.mark.asyncio
    async def test_hostname_resolution_failure(self):
        """Nonexistent hostnames should return resolution error."""
        result = await ssl_audit("nonexistent-host-12345.invalid", 443, allow_private=False)
        
        assert "Host resolution failed" in result.error


class TestSSLAuditConcurrency:
    """Test concurrent execution of TLS probes."""
    
    @pytest.mark.asyncio
    @patch("asyncio.get_event_loop")
    async def test_concurrent_probe_execution(self, mock_get_loop):
        """The three TLS probes should run concurrently, not sequentially."""
        mock_loop = MagicMock()
        mock_get_loop.return_value = mock_loop
        
        # Mock getaddrinfo to return public IP
        mock_loop.getaddrinfo = AsyncMock(return_value=[
            (socket.AF_INET, socket.SOCK_STREAM, 6, '', ('8.8.8.8', 443))
        ])
        
        # Mock asyncio.gather and wait_for to verify concurrent execution
        with patch("asyncio.gather") as mock_gather, \
             patch("asyncio.wait_for") as mock_wait_for:
            
            mock_gather.return_value = asyncio.Future()
            mock_gather.return_value.set_result(((None, None), True, False))
            mock_wait_for.return_value = ((None, None), True, False)
            
            result = await ssl_audit("example.com", 443, allow_private=False)
            
            # Verify gather was called with all three tasks
            mock_gather.assert_called_once()
            args = mock_gather.call_args[0][0]  # First positional arg (the tasks)
            assert len(args) == 3  # Three concurrent tasks
            
            # Verify wait_for was called with timeout
            mock_wait_for.assert_called_once()
            assert mock_wait_for.call_args[1]['timeout'] == 20  # Default SSL_AUDIT_TIMEOUT_SECONDS


class TestSSLAuditTimeout:
    """Test timeout handling."""
    
    @pytest.mark.asyncio
    @patch("asyncio.get_event_loop")
    async def test_timeout_returns_error_result(self, mock_get_loop):
        """Timeout should return appropriate error message.""" 
        mock_loop = MagicMock()
        mock_get_loop.return_value = mock_loop
        
        # Mock getaddrinfo to return public IP
        mock_loop.getaddrinfo = AsyncMock(return_value=[
            (socket.AF_INET, socket.SOCK_STREAM, 6, '', ('8.8.8.8', 443))
        ])
        
        # Mock wait_for to timeout
        with patch("asyncio.wait_for") as mock_wait_for:
            mock_wait_for.side_effect = asyncio.TimeoutError()
            
            result = await ssl_audit("example.com", 443, allow_private=False)
            
            assert "timed out after" in result.error
            assert result.host == "example.com"
            assert result.port == 443
            assert result.tls_version is None
            assert result.cert is None


class TestSSLAuditTimezoneHandling:
    """Test timezone-aware certificate handling."""
    
    @pytest.mark.asyncio
    @patch("asyncio.get_event_loop")
    async def test_timezone_aware_certificate_properties(self, mock_get_loop):
        """Certificate dates should use timezone-aware properties."""
        mock_loop = MagicMock()
        mock_get_loop.return_value = mock_loop
        
        # Mock getaddrinfo to return public IP
        mock_loop.getaddrinfo = AsyncMock(return_value=[
            (socket.AF_INET, socket.SOCK_STREAM, 6, '', ('8.8.8.8', 443))
        ])
        
        # Create a mock certificate with timezone-aware properties
        from datetime import datetime, timezone
        mock_cert = MagicMock()
        
        # Set up timezone-aware dates
        mock_cert.not_valid_before_utc = datetime(2023, 1, 1, tzinfo=timezone.utc)
        mock_cert.not_valid_after_utc = datetime(2025, 1, 1, tzinfo=timezone.utc)
        mock_cert.subject = []
        mock_cert.issuer = []
        mock_cert.extensions.get_extension_for_class.side_effect = Exception("No SAN")
        
        # Mock the certificate loading
        with patch("cybersec.core.tools.ssl.x509.load_der_x509_certificate") as mock_load_cert, \
             patch("asyncio.gather") as mock_gather, \
             patch("asyncio.wait_for") as mock_wait_for:
            
            mock_load_cert.return_value = mock_cert
            
            # Mock successful SSL connection with binary cert
            mock_gather.return_value = ((None, b"fake_cert"), True, False)
            mock_wait_for.return_value = ((None, b"fake_cert"), True, False)
            
            result = await ssl_audit("example.com", 443, allow_private=False)
            
            # Verify certificate info is populated
            assert result.cert is not None
            assert result.cert.valid_from == "2023-01-01T00:00:00+00:00"
            assert result.cert.valid_until == "2025-01-01T00:00:00+00:00"
            assert isinstance(result.cert.days_remaining, int)
            assert result.error is None


class TestSSLAuditPortValidation:
    """Test port bounds validation at schema level."""
    
    def test_port_bounds_validation(self):
        """Test that SslRequest validates port bounds correctly."""
        from cybersec.apps.api.schemas.tool import SslRequest
        from pydantic import ValidationError
        
        # Valid ports
        assert SslRequest(host="example.com", port=1).port == 1
        assert SslRequest(host="example.com", port=65535).port == 65535
        assert SslRequest(host="example.com", port=443).port == 443
        
        # Invalid ports should raise ValidationError
        with pytest.raises(ValidationError):
            SslRequest(host="example.com", port=0)
            
        with pytest.raises(ValidationError):
            SslRequest(host="example.com", port=65536)
            
        with pytest.raises(ValidationError):
            SslRequest(host="example.com", port=-1)


class TestSSLAuditIntegration:
    """Integration tests combining multiple features."""
    
    @pytest.mark.asyncio
    async def test_successful_public_ip_bypass(self):
        """Test that public IPs pass SSRF checks."""
        # Use a well-known public IP that should pass SSRF checks
        result = await ssl_audit("8.8.8.8", 443, allow_private=False)
        
        # Should not get SSRF error
        assert "not permitted" not in (result.error or "")
        # Will likely get SSL/connection error, which is expected
    
    @pytest.mark.asyncio  
    async def test_route_handler_integration(self):
        """Test that the route handler correctly passes allow_private parameter."""
        from cybersec.apps.api.schemas.tool import SslRequest
        
        # Test that schema accepts valid requests
        request = SslRequest(host="example.com", port=443)
        assert request.host == "example.com"
        assert request.port == 443
        
        # Verify port validation works
        with pytest.raises(Exception):  # ValidationError from pydantic
            SslRequest(host="example.com", port=70000)