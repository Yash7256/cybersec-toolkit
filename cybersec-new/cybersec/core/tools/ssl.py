import asyncio
import socket
import ssl as ssl_lib
from datetime import datetime
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

async def ssl_audit(host: str, port: int = 443) -> SSLResult:
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
            
    def check_tls(version, max_version=None):
        try:
            ctx = ssl_lib.SSLContext(ssl_lib.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl_lib.CERT_NONE
            ctx.minimum_version = version
            if max_version:
                ctx.maximum_version = max_version
            else:
                ctx.maximum_version = version
            with socket.create_connection((host, port), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as conn:
                    return True
        except Exception:
            return False

    def do_audit():
        res = fetch_ssl_info()
        if isinstance(res, Exception):
            raise res
            
        cipher_info, binary_cert = res
        tls_version = cipher_info[1] if cipher_info else None
        cipher_suite = cipher_info[0] if cipher_info else None
        
        cert = None
        is_self_signed = False
        
        if binary_cert:
            cert_obj = x509.load_der_x509_certificate(binary_cert)
            
            subject = {attr.oid._name: attr.value for attr in cert_obj.subject}
            issuer = {attr.oid._name: attr.value for attr in cert_obj.issuer}
            
            valid_from = cert_obj.not_valid_before
            valid_until = cert_obj.not_valid_after
            
            days_remaining = (valid_until - datetime.utcnow()).days
            is_expired = datetime.utcnow() > valid_until
            
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
            
        supports_tls12 = check_tls(ssl_lib.TLSVersion.TLSv1_2)
        supports_tls13 = check_tls(ssl_lib.TLSVersion.TLSv1_3)
            
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

    try:
        return await loop.run_in_executor(None, do_audit)
    except Exception as e:
        return SSLResult(host, port, None, None, None, False, False, False, str(e))
