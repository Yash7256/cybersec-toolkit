import asyncio
import dataclasses
import logging
import socket
import ssl
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger(__name__)


@dataclasses.dataclass(slots=True)
class SSLResult:
    host: str
    port: int
    cn: Optional[str] = None
    sans: list[str] = dataclasses.field(default_factory=list)
    issuer: Optional[str] = None
    valid_from: Optional[str] = None
    valid_to: Optional[str] = None
    is_expired: bool = False
    days_until_expiry: int = 0
    is_self_signed: bool = False
    serial_number: Optional[str] = None
    signature_algorithm: Optional[str] = None
    public_key_bits: Optional[int] = None
    tls_versions: list[str] = dataclasses.field(default_factory=list)
    cipher_suite: Optional[str] = None
    raw_pem: Optional[str] = None
    error: Optional[str] = None


class SSLTool:
    def _sync_inspect(self, host: str, port: int) -> SSLResult:
        result = SSLResult(host=host, port=port)

        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        try:
            with socket.create_connection((host, port), timeout=5.0) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert_der = ssock.getpeercert(binary_form=True)

                    try:
                        cert = x509.load_der_x509_certificate(cert_der, default_backend())
                    except Exception as e:
                        logger.warning(f"Failed to parse certificate: {e}")
                        result.error = f"Certificate parse error: {e}"
                        return result

                    try:
                        result.cn = str(cert.subject.rfc4514_string())
                    except Exception:
                        pass

                    try:
                        san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
                        result.sans = [str(name) for name in san_ext.value]
                    except x509.ExtensionNotFound:
                        pass

                    try:
                        result.issuer = str(cert.issuer.rfc4514_string())
                        result.is_self_signed = cert.issuer == cert.subject
                    except Exception:
                        pass

                    result.valid_from = cert.not_valid_before_utc.isoformat()
                    result.valid_to = cert.not_valid_after_utc.isoformat()

                    now = datetime.now(timezone.utc)
                    if cert.not_valid_after_utc < now:
                        result.is_expired = True
                        result.days_until_expiry = 0
                    else:
                        result.is_expired = False
                        delta = cert.not_valid_after_utc - now
                        result.days_until_expiry = delta.days

                    result.serial_number = str(cert.serial_number)
                    result.signature_algorithm = cert.signature_algorithm_oid._name

                    try:
                        if hasattr(cert.public_key(), "key_size"):
                            result.public_key_bits = cert.public_key().key_size
                    except Exception:
                        pass

                    result.raw_pem = cert.public_bytes(x509.encoding.Encoding.PEM).decode("utf-8")

                    cipher = ssock.cipher()
                    if cipher:
                        result.cipher_suite = cipher[0]
                        result.tls_versions = [ssock.version()]

        except socket.timeout:
            result.error = "Connection timeout"
        except ConnectionRefusedError:
            result.error = "Connection refused"
        except ssl.SSLError as e:
            result.error = f"SSL error: {e}"
        except OSError as e:
            result.error = f"Network error: {e}"
        except Exception as e:
            logger.warning(f"SSL inspection failed for {host}:{port}: {type(e).__name__}: {e}")
            result.error = str(e)

        return result

    async def inspect(self, host: str, port: int = 443) -> SSLResult:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._sync_inspect, host, port)
