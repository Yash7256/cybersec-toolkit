"""
Integration test for TLS fingerprinting functionality.
Tests TLS fingerprinting against google.com:443 and validates JA3 hash and certificate info.
"""
import pytest
import asyncio
import ssl
import socket
from unittest.mock import patch, MagicMock

from cybersec.core.scanner.analysis.tls_fingerprint import TLSFingerprinter, TLSInfo


class TestTLSFingerprintingIntegration:
    """Integration tests for TLS fingerprinting."""
    
    @pytest.fixture
    def fingerprinter(self):
        """Create a TLS fingerprinter instance."""
        return TLSFingerprinter()
    
    @pytest.mark.asyncio
    async def test_tls_fingerprinting_google_com_integration(self, fingerprinter):
        """Test TLS fingerprinting against google.com:443."""
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
            assert 'version' in cert_info
            assert 'serial_number' in cert_info
            assert 'not_before' in cert_info
            assert 'not_after' in cert_info
            
            # Check subject information
            subject = cert_info['subject']
            assert isinstance(subject, dict)
            # Google should have common name or CN in subject
            assert 'commonName' in subject or 'CN' in subject
            
            # Check issuer information (should be a trusted CA)
            issuer = cert_info['issuer']
            assert isinstance(issuer, dict)
            # Google's certificate should be issued by a known CA
            assert 'commonName' in issuer or 'CN' in issuer
            
            # Check certificate validity
            assert cert_info['not_before'] is not None
            assert cert_info['not_after'] is not None
            
            # Check certificate version (should be 3 for modern certs)
            assert cert_info['version'] in [2, 3]  # X.509 v2 or v3
            
            # Check serial number is present
            assert cert_info['serial_number'] is not None
            assert isinstance(cert_info['serial_number'], (str, int))
            
            print(f"TLS Fingerprinting Results:")
            print(f"  Target: {target}:{port}")
            print(f"  JA3 Hash: {result.ja3_hash}")
            print(f"  Subject: {subject.get('commonName', subject.get('CN', 'Unknown'))}")
            print(f"  Issuer: {issuer.get('commonName', issuer.get('CN', 'Unknown'))}")
            print(f"  Valid: {cert_info['not_before']} to {cert_info['not_after']}")
            
        except Exception as e:
            # If network is unavailable, create a mock result for testing
            if "network" in str(e).lower() or "connection" in str(e).lower():
                pytest.skip(f"Network unavailable for TLS fingerprinting: {e}")
            else:
                raise
    
    @pytest.mark.asyncio
    async def test_tls_fingerprinting_certificate_details(self, fingerprinter):
        """Test detailed certificate information extraction."""
        target = "google.com"
        port = 443
        
        try:
            result = await fingerprinter.get_tls_info(target, port)
            
            # Test detailed certificate parsing
            cert_info = result.certificate
            
            # Test subject alternative names (SAN)
            if 'subject_alt_name' in cert_info:
                san = cert_info['subject_alt_name']
                assert isinstance(san, list)
                # Google's cert should include google.com and www.google.com
                san_domains = [name for name in san if isinstance(name, str) and '.' in name]
                assert len(san_domains) > 0
                assert any('google.com' in domain.lower() for domain in san_domains)
            
            # Test signature algorithm
            if 'signature_algorithm' in cert_info:
                sig_algo = cert_info['signature_algorithm']
                assert isinstance(sig_algo, str)
                # Should be a modern algorithm
                assert any(algo in sig_algo.upper() for algo in ['SHA256', 'SHA384', 'SHA512'])
            
            # Test public key info
            if 'public_key' in cert_info:
                pub_key = cert_info['public_key']
                assert isinstance(pub_key, dict)
                assert 'algorithm' in pub_key
                assert 'key_size' in pub_key
                assert pub_key['key_size'] >= 2048  # Modern key sizes
            
            print(f"Certificate Details:")
            if 'signature_algorithm' in cert_info:
                print(f"  Signature Algorithm: {cert_info['signature_algorithm']}")
            if 'public_key' in cert_info:
                print(f"  Public Key: {cert_info['public_key']['algorithm']} ({cert_info['public_key']['key_size']} bits)")
            if 'subject_alt_name' in cert_info:
                print(f"  SAN: {cert_info['subject_alt_name'][:3]}...")  # First 3 SANs
            
        except Exception as e:
            if "network" in str(e).lower() or "connection" in str(e).lower():
                pytest.skip(f"Network unavailable for detailed certificate testing: {e}")
            else:
                raise
    
    @pytest.mark.asyncio
    async def test_tls_fingerprinting_ja3_components(self, fingerprinter):
        """Test JA3 hash components are properly extracted."""
        target = "google.com"
        port = 443
        
        try:
            result = await fingerprinter.fingerprint(target, port)
            
            # Test JA3 components if available
            if hasattr(result, 'ja3_components') and result.ja3_components:
                components = result.ja3_components
                assert isinstance(components, dict)
                
                # Check essential JA3 components
                required_components = ['version', 'ciphers', 'extensions', 'elliptic_curves', 'elliptic_curve_format']
                for component in required_components:
                    assert component in components
                    assert components[component] is not None
                
                print(f"JA3 Components:")
                for comp_name, comp_value in components.items():
                    print(f"  {comp_name}: {comp_value}")
            
        except Exception as e:
            if "network" in str(e).lower() or "connection" in str(e).lower():
                pytest.skip(f"Network unavailable for JA3 component testing: {e}")
            else:
                raise
    
    @pytest.mark.asyncio
    async def test_tls_fingerprinting_multiple_targets(self, fingerprinter):
        """Test TLS fingerprinting against multiple targets."""
        targets = [
            ("google.com", 443),
            ("github.com", 443),
            ("stackoverflow.com", 443)
        ]
        
        results = []
        
        for target, port in targets:
            try:
                result = await fingerprinter.fingerprint(target, port)
                results.append(result)
                
                # Basic validation for each result
                assert isinstance(result, TLSFingerprint)
                assert result.ja3_hash is not None
                assert result.certificate_info is not None
                assert len(result.ja3_hash) == 32
                
            except Exception as e:
                if "network" in str(e).lower() or "connection" in str(e).lower():
                    print(f"Skipping {target}:{port} due to network issues: {e}")
                    continue
                else:
                    raise
        
        # If we got any results, validate they're different
        if len(results) > 1:
            # JA3 hashes should be different for different services
            ja3_hashes = [result.ja3_hash for result in results]
            assert len(set(ja3_hashes)) == len(ja3_hashes), "JA3 hashes should be unique"
            
            print(f"Successfully fingerprinted {len(results)} targets:")
            for result in results:
                print(f"  {result.target}:{result.port} -> {result.ja3_hash}")
        else:
            pytest.skip("No successful TLS fingerprinting results")
    
    @pytest.mark.asyncio
    async def test_tls_fingerprinting_error_handling(self, fingerprinter):
        """Test TLS fingerprinting error handling."""
        # Test with invalid target
        try:
            result = await fingerprinter.fingerprint("invalid.target.that.does.not.exist", 443)
            # Should either return None or raise an appropriate exception
            assert result is None or isinstance(result, TLSFingerprint)
        except Exception:
            # Expected for invalid target
            pass
        
        # Test with invalid port
        try:
            result = await fingerprinter.fingerprint("google.com", 99999)
            # Should handle gracefully
            assert result is None or isinstance(result, TLSFingerprint)
        except Exception:
            # Expected for invalid port
            pass
        
        # Test with timeout
        try:
            # Create fingerprinter with very short timeout
            fast_fingerprinter = TLSFingerprinter(timeout=0.001)
            result = await fast_fingerprinter.fingerprint("google.com", 443)
            # Should timeout gracefully
            assert result is None or isinstance(result, TLSFingerprint)
        except Exception:
            # Expected for timeout
            pass
    
    def test_tls_fingerprinter_initialization(self, fingerprinter):
        """Test TLS fingerprinter initialization."""
        assert fingerprinter is not None
        assert hasattr(fingerprinter, 'fingerprint')
        assert callable(getattr(fingerprinter, 'fingerprint'))
        
        # Test with custom timeout
        custom_fingerprinter = TLSFingerprinter(timeout=10.0)
        assert custom_fingerprinter is not None
        assert hasattr(custom_fingerprinter, 'fingerprint')
    
    def test_tls_fingerprint_dataclass(self):
        """Test TLSFingerprint dataclass."""
        # Test minimal creation
        fp1 = TLSFingerprint(
            target="test.com",
            port=443,
            ja3_hash="abcd1234567890abcd1234567890abcd",
            certificate_info={}
        )
        
        assert fp1.target == "test.com"
        assert fp1.port == 443
        assert fp1.ja3_hash == "abcd1234567890abcd1234567890abcd"
        assert fp1.certificate_info == {}
        
        # Test full creation
        cert_info = {
            'subject': {'commonName': 'test.com'},
            'issuer': {'commonName': 'Test CA'},
            'version': 3,
            'serial_number': '12345',
            'not_before': '2023-01-01T00:00:00Z',
            'not_after': '2024-01-01T00:00:00Z'
        }
        
        fp2 = TLSFingerprint(
            target="full.com",
            port=443,
            ja3_hash="1234567890abcd1234567890abcd1234",
            certificate_info=cert_info
        )
        
        assert fp2.target == "full.com"
        assert fp2.certificate_info == cert_info
        assert fp2.certificate_info['subject']['commonName'] == 'test.com'
        
        # Test equality
        fp3 = TLSFingerprint(
            target="test.com",
            port=443,
            ja3_hash="abcd1234567890abcd1234567890abcd",
            certificate_info={}
        )
        
        assert fp1 == fp3
        assert fp1 != fp2


class TestTLSFingerprintingMocked:
    """Mocked TLS fingerprinting tests for CI/CD environments."""
    
    @pytest.mark.asyncio
    async def test_tls_fingerprinting_with_mock(self):
        """Test TLS fingerprinting with mocked network calls."""
        fingerprinter = TLSFingerprinter()
        
        # Mock the SSL socket connection
        mock_ssl_context = MagicMock()
        mock_socket = MagicMock()
        mock_cert = MagicMock()
        
        # Mock certificate data
        mock_cert.subject.return_value = [('commonName', 'google.com')]
        mock_cert.issuer.return_value = [('commonName', 'Google Trust Services')]
        mock_cert.version.return_value = 3
        mock_cert.serial_number.return_value = 123456789
        mock_cert.not_before.return_value = '20230101000000Z'
        mock_cert.not_after.return_value = '20240101000000Z'
        
        # Mock SSL context
        mock_ssl_context.wrap_socket.return_value = mock_socket
        mock_socket.getpeercert.return_value = {
            'subject': [('commonName', 'google.com')],
            'issuer': [('commonName', 'Google Trust Services')],
            'version': 3,
            'serialNumber': '123456789',
            'notBefore': 'Jan  1 00:00:00 2023 GMT',
            'notAfter': 'Jan  1 00:00:00 2024 GMT'
        }
        
        # Mock cipher information for JA3
        mock_socket.cipher.return_value = ('TLS_AES_256_GCM_SHA384', 'TLSv1.3', 256)
        mock_socket.shared_ciphers.return_value = [
            ('ECDHE-RSA-AES128-GCM-SHA256', 'TLSv1.2', 128),
            ('ECDHE-RSA-AES256-GCM-SHA384', 'TLSv1.2', 256)
        ]
        
        with patch('ssl.create_default_context', return_value=mock_ssl_context):
            with patch('socket.create_connection', return_value=mock_socket):
                result = await fingerprinter.fingerprint("google.com", 443)
        
        # Validate mocked result
        assert isinstance(result, TLSFingerprint)
        assert result.target == "google.com"
        assert result.port == 443
        assert result.ja3_hash is not None
        assert result.certificate_info is not None
        
        # Validate certificate info
        cert_info = result.certificate_info
        assert 'subject' in cert_info
        assert 'issuer' in cert_info
        assert cert_info['subject']['commonName'] == 'google.com'
        assert cert_info['issuer']['commonName'] == 'Google Trust Services'
