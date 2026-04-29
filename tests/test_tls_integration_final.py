"""
Final integration test for TLS fingerprinting functionality.
Tests TLS fingerprinting against google.com:443 and validates JA3 hash and certificate info.
"""
import pytest
import asyncio
from cybersec.core.scanner.analysis.tls_fingerprint import TLSFingerprinter, TLSInfo


class TestTLSFingerprintingIntegration:
    """Integration tests for TLS fingerprinting."""
    
    @pytest.fixture
    def fingerprinter(self):
        """Create a TLS fingerprinter instance."""
        return TLSFingerprinter()
    
    @pytest.mark.asyncio
    async def test_tls_fingerprinting_google_com_integration(self, fingerprinter):
        """
        Test TLS fingerprinting against google.com:443.
        
        This test validates that:
        1. JA3 hash is generated and returned
        2. Certificate information is extracted and populated
        3. Google's certificate contains expected information
        4. TLS connection is established successfully
        """
        # Target for TLS fingerprinting
        target = "google.com"
        port = 443
        
        try:
            # Perform TLS fingerprinting
            result = await fingerprinter.get_tls_info(target, port)
            
            # Assert result is TLSInfo object
            assert isinstance(result, TLSInfo)
            
            # Assert JA3 hash is populated
            assert result.ja3_hash is not None
            assert isinstance(result.ja3_hash, str)
            assert len(result.ja3_hash) == 32  # MD5 hash length
            assert all(c in '0123456789abcdef' for c in result.ja3_hash.lower())
            
            # Assert certificate info is populated
            assert result.certificate is not None
            assert isinstance(result.certificate, dict)
            
            # Check essential certificate fields
            cert_info = result.certificate
            assert 'subject' in cert_info
            assert 'issuer' in cert_info
            assert 'serial' in cert_info
            assert 'not_before' in cert_info
            assert 'not_after' in cert_info
            
            # Check subject information
            subject = cert_info['subject']
            assert isinstance(subject, str)
            # Google should have CN in subject
            assert 'CN=' in subject
            assert 'google.com' in subject
            
            # Check issuer information (should be a trusted CA)
            issuer = cert_info['issuer']
            assert isinstance(issuer, str)
            # Google's certificate should be issued by a known CA
            assert 'CN=' in issuer
            assert 'Google' in issuer or 'Trust Services' in issuer
            
            # Check certificate validity
            assert cert_info['not_before'] is not None
            assert cert_info['not_after'] is not None
            
            # Check serial number is present
            assert cert_info['serial'] is not None
            assert isinstance(cert_info['serial'], int)
            
            # Validate specific Google certificate properties
            assert '*.google.com' in subject  # Wildcard certificate
            assert 'WE2' in issuer  # Google's intermediate CA
            
            print(f"TLS Fingerprinting Results:")
            print(f"  Target: {target}:{port}")
            print(f"  JA3 Hash: {result.ja3_hash}")
            print(f"  Version: {result.version}")
            print(f"  Subject: {subject}")
            print(f"  Issuer: {issuer}")
            print(f"  Serial: {cert_info['serial']}")
            print(f"  Valid: {cert_info['not_before']} to {cert_info['not_after']}")
            
        except Exception as e:
            # If network is unavailable, skip the test
            if any(keyword in str(e).lower() for keyword in ["network", "connection", "timeout", "unreachable"]):
                pytest.skip(f"Network unavailable for TLS fingerprinting: {e}")
            else:
                raise
    
    def test_tls_fingerprinter_initialization(self, fingerprinter):
        """Test TLS fingerprinter initialization."""
        assert fingerprinter is not None
        assert hasattr(fingerprinter, 'get_tls_info')
        assert callable(getattr(fingerprinter, 'get_tls_info'))
        
        # Test with custom timeout
        custom_fingerprinter = TLSFingerprinter(timeout=10.0)
        assert custom_fingerprinter is not None
        assert hasattr(custom_fingerprinter, 'get_tls_info')
    
    def test_tls_info_dataclass(self):
        """Test TLSInfo dataclass."""
        # Test minimal creation
        tls_info1 = TLSInfo()
        assert tls_info1.version is None
        assert tls_info1.cipher_suites == []
        assert tls_info1.extensions == []
        assert tls_info1.ja3_hash is None
        assert tls_info1.certificate is None
        assert tls_info1.is_self_signed is False
        assert tls_info1.tls_fingerprint is None
        
        # Test creation with JA3 hash and certificate
        cert_info = {
            'subject': 'CN=*.google.com',
            'issuer': 'CN=Google Trust Services',
            'serial': 123456789,
            'not_before': '2023-01-01T00:00:00',
            'not_after': '2024-01-01T00:00:00'
        }
        
        tls_info2 = TLSInfo(
            version="TLSv1.3",
            ja3_hash="abcd1234567890abcd1234567890abcd",
            certificate=cert_info,
            is_self_signed=False
        )
        
        assert tls_info2.version == "TLSv1.3"
        assert tls_info2.ja3_hash == "abcd1234567890abcd1234567890abcd"
        assert tls_info2.certificate == cert_info
        assert tls_info2.is_self_signed is False
