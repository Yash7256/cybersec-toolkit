import asyncio
import socket
import ssl as ssl_lib
from datetime import datetime, timezone
from dataclasses import dataclass
from cryptography import x509

@dataclass
class CertInfo:
    subject: dict
    issuer: dict
    valid_from: str
    valid_until: str
    days_remaining: int
    is_expired: bool
    san: list[str]

@dataclass
class SSLResult:
    host: str
    port: int
    tls_version: str | None
    cipher_suite: str | None
    cert: CertInfo | None
    is_self_signed: bool
    supports_tls12: bool
    supports_tls13: bool
    error: str | None

async def ssl_audit(host: str, port: int = 443, allow_private: bool = False) -> SSLResult:
    from cybersec.config.settings import settings
    
    # SSRF protection - resolve host and check if IP is allowed
    try:
        addrinfo = await asyncio.get_event_loop().getaddrinfo(host, port)
        if not addrinfo:
            return SSLResult(host, port, None, None, None, False, False, False, "Failed to resolve host")
        
        ip = addrinfo[0][4][0]  # First resolved IP
        
        if not allow_private:
            # Lazy import to avoid circular dependency
            from cybersec.core.tools.port_scanner import _is_scan_target_allowed
            if not _is_scan_target_allowed(ip):
                return SSLResult(host, port, None, None, None, False, False, False, 
                               "Auditing private, loopback, or cloud-metadata addresses is not permitted")
    except Exception as e:
        return SSLResult(host, port, None, None, None, False, False, False, f"Host resolution failed: {e}")
    
    loop = asyncio.get_event_loop()
    
    def fetch_ssl_info():
        ctx = ssl_lib.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl_lib.CERT_NONE
        
        try:
            with socket.create_connection((host, port), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as conn:
                    cipher_info = conn.cipher()
                    binary_cert = conn.getpeercert(binary_form=True)
                    return cipher_info, binary_cert
        except Exception as e:
            return e
            
    def check_tls12():
        try:
            ctx = ssl_lib.SSLContext(ssl_lib.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl_lib.CERT_NONE
            ctx.minimum_version = ssl_lib.TLSVersion.TLSv1_2
            ctx.maximum_version = ssl_lib.TLSVersion.TLSv1_2
            with socket.create_connection((host, port), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as conn:
                    return True
        except Exception:
            return False

    def check_tls13():
        try:
            ctx = ssl_lib.SSLContext(ssl_lib.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl_lib.CERT_NONE
            ctx.minimum_version = ssl_lib.TLSVersion.TLSv1_3
            ctx.maximum_version = ssl_lib.TLSVersion.TLSv1_3
            with socket.create_connection((host, port), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as conn:
                    return True
        except Exception:
            return False

    try:
        # Run three probes concurrently with timeout
        cert_task = loop.run_in_executor(None, fetch_ssl_info)
        tls12_task = loop.run_in_executor(None, check_tls12)
        tls13_task = loop.run_in_executor(None, check_tls13)
        
        cert_res, supports_tls12, supports_tls13 = await asyncio.wait_for(
            asyncio.gather(cert_task, tls12_task, tls13_task),
            timeout=settings.SSL_AUDIT_TIMEOUT_SECONDS
        )
        
        if isinstance(cert_res, Exception):
            raise cert_res
            
        cipher_info, binary_cert = cert_res
        tls_version = cipher_info[1] if cipher_info else None
        cipher_suite = cipher_info[0] if cipher_info else None
        
        cert = None
        is_self_signed = False
        
        if binary_cert:
            cert_obj = x509.load_der_x509_certificate(binary_cert)
            
            subject = {attr.oid._name: attr.value for attr in cert_obj.subject}
            issuer = {attr.oid._name: attr.value for attr in cert_obj.issuer}
            
            # Use timezone-aware properties
            valid_from = cert_obj.not_valid_before_utc
            valid_until = cert_obj.not_valid_after_utc
            
            days_remaining = (valid_until - datetime.now(timezone.utc)).days
            is_expired = datetime.now(timezone.utc) > valid_until
            
            san = []
            try:
                ext = cert_obj.extensions.get_extension_for_class(x509.SubjectAlternativeName)
                san = ext.value.get_values_for_type(x509.DNSName)
            except x509.ExtensionNotFound:
                pass
                
            is_self_signed = (cert_obj.subject == cert_obj.issuer)
            
            cert = CertInfo(
                subject=subject,
                issuer=issuer,
                valid_from=valid_from.isoformat(),
                valid_until=valid_until.isoformat(),
                days_remaining=days_remaining,
                is_expired=is_expired,
                san=san
            )
            
        return SSLResult(
            host=host,
            port=port,
            tls_version=tls_version,
            cipher_suite=cipher_suite,
            cert=cert,
            is_self_signed=is_self_signed,
            supports_tls12=supports_tls12,
            supports_tls13=supports_tls13,
            error=None
        )
    except asyncio.TimeoutError:
        return SSLResult(host, port, None, None, None, False, False, False, 
                        f"TLS audit timed out after {settings.SSL_AUDIT_TIMEOUT_SECONDS}s")
    except Exception as e:
        return SSLResult(host, port, None, None, None, False, False, False, str(e))
