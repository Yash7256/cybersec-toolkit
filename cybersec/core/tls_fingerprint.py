"""
TLS/SSL fingerprinting module for JA3 hash generation and certificate analysis.
"""
import ssl
import struct
import hashlib
import asyncio
from dataclasses import dataclass
from typing import Optional, Dict, List, Any
from dataclasses import field

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization, hashes
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False

@dataclass
class TLSInfo:
    version: Optional[str] = None
    cipher_suites: List[str] = field(default_factory=list)
    extensions: List[str] = field(default_factory=list)
    ja3_hash: Optional[str] = None
    certificate: Optional[Dict[str, Any]] = field(default_factory=None)
    is_self_signed: bool = False
    tls_fingerprint: Optional[str] = None

JA3_SIGNATURES = {
    "771,4865-4866-4867-157-156-47-53-5-10-23-65281": ("Chrome 80+", "Browser"),
    "771,4865-4866-4867-157-156-53-47-5-10-23-65281": ("Firefox 75+", "Browser"),
    "771,4865-4866-4867-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53-10-255": ("iOS 13+", "Mobile"),
    "771,4865-4866-4867-49195-49199-49196-49200-52393-49162-49161-49171-49172-156-157-47-53-10-255": ("Safari 13+", "Browser"),
    "771,49200-49196-49188-49192-49172-49162-159-158-157-156-107-103-255": ("curl 7.50+", "Library"),
    "771,49200-49196-49192-49162-159-158-157-156-53-47-10-255": ("Python 3.9+", "Library"),
    "771,49196-49195-49192-49162-49172-159-158-157-156-53-47-10": ("Go 1.13+", "Library"),
    "771,49196-49195-49192-49162-159-158-157-156-53-47-10-65037": ("Java 11+", "Library"),
    "769,4-5-10-9-100-98-3-6-19-18-99-101": ("Windows 10 Edge", "Browser"),
    "769,47-53-4-5-10-9-100-98-3-6-19-18-99-101": ("Windows 10 IE11", "Browser"),
    "769,47-53-4-5-10-9-100-98-3-6-19-18-99-101-102": ("Windows 7 IE11", "Browser"),
    "769,4-5-10-9-3-100-98-6-19-18-99-101": ("Windows 8.1 IE11", "Browser"),
    "771,49196-49195-49192-49162-49172-49152-159-158-157-156-47-53-10-255": ("OpenSSL 1.1.1", "Library"),
    "771,49196-49195-49192-49162-49172-49152-159-158-157-156-47-53-10": ("OpenSSL 1.0.x", "Library"),
    "771,49196-49195-49192-49162-49172-49152-159-158-157-156-47-53-10-65037": ("Node.js 12+", "Library"),
    "771,49196-49195-49192-49162-49172-49152-159-158-157-156-47-53-10-27-13-45": ("Nginx 1.18+", "Server"),
    "771,49196-49195-49192-49162-49172-49152-159-158-157-156-47-53-10-27-13": ("Apache 2.4+", "Server"),
    "769,47-53-4-5-10-9-3-100-98-6-19-18-99-101-102-22": ("Windows 7 Chrome", "Browser"),
    "771,4865-4866-4867-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53-10": ("Android 11+", "Mobile"),
}

CIPHER_SUITE_MAP = {
    0x002F: "TLS_RSA_WITH_AES_128_CBC_SHA",
    0x0035: "TLS_RSA_WITH_AES_256_CBC_SHA",
    0x003C: "TLS_RSA_WITH_AES_128_CBC_SHA256",
    0x003D: "TLS_RSA_WITH_AES_256_CBC_SHA256",
    0xC02F: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    0xC030: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    0xC02B: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    0xC02C: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    0xCCA9: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    0xCCA8: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
    0x1301: "TLS_AES_128_GCM_SHA256",
    0x1302: "TLS_AES_256_GCM_SHA384",
    0x1303: "TLS_CHACHA20_POLY1305_SHA256",
    0x0005: "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
    0x000A: "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
}

EXTENSION_MAP = {
    0: "server_name",
    1: "max_fragment_length",
    5: "status_request",
    10: "supported_groups",
    11: "ec_point_formats",
    13: "signature_algorithms",
    15: "use_srtp",
    16: "application_layer_protocol_negotiation",
    21: "padding",
    23: "extended_master_secret",
    27: "compress_certificate",
    28: "record_size_limit",
    35: "session_ticket",
    41: "pre_shared_key",
    42: "early_data",
    43: "supported_versions",
    44: "cookie",
    45: "psk_key_exchange_modes",
    47: "auth_method",
    48: "public_key_encryption_preferences",
    51: "key_share",
    57: "quic_transport_parameters",
    13172: "next_protocol_negotiation",
    17513: "application_settings",
    65281: "renegotiation_info",
}

class TLSFingerprinter:
    def __init__(self, timeout: float = 5.0):
        self.timeout = timeout
        self._crypto_available = CRYPTO_AVAILABLE

    def parse_tls_client_hello(self, data: bytes) -> Optional[Dict[str, Any]]:
        if len(data) < 6:
            return None
        
        try:
            if data[0] != 0x16:
                return None
            
            version = struct.unpack(">H", data[1:3])[0]
            length = struct.unpack(">H", data[3:5])[0]
            
            if len(data) < 5 + length:
                return None
            
            offset = 5
            
            if data[offset] != 0x01:
                return None
            offset += 1
            
            hello_len = struct.unpack(">I", b"\x00" + data[offset:offset+3])[0]
            offset += 3
            
            client_version = struct.unpack(">H", data[offset:offset+2])[0]
            offset += 32
            
            session_id_len = data[offset]
            offset += 1 + session_id_len
            
            cipher_suites_len = struct.unpack(">H", data[offset:offset+2])[0]
            offset += 2
            cipher_suites = []
            for i in range(0, cipher_suites_len, 2):
                cipher = struct.unpack(">H", data[offset+i:offset+i+2])[0]
                cipher_suites.append(cipher)
            offset += cipher_suites_len
            
            compression_len = data[offset]
            offset += 1 + compression_len
            
            extensions = {}
            extensions_len = struct.unpack(">H", data[offset:offset+2])[0]
            offset += 2
            
            ext_offset = 0
            while ext_offset < extensions_len:
                if offset + ext_offset + 4 > len(data):
                    break
                ext_type = struct.unpack(">H", data[offset+ext_offset:offset+ext_offset+2])[0]
                ext_len = struct.unpack(">H", data[offset+ext_offset+2:offset+ext_offset+4])[0]
                extensions[ext_type] = ext_len
                ext_offset += 4 + ext_len
            
            return {
                "version": version,
                "client_version": client_version,
                "cipher_suites": cipher_suites,
                "extensions": list(extensions.keys()),
            }
        except Exception:
            return None

    def generate_ja3(self, version: int, cipher_suites: List[int], extensions: List[int], 
                    elliptic_curves: List[int] = None, ec_point_formats: List[int] = None) -> str:
        ja3_string = f"{version},"
        ja3_string += ",".join(str(c) for c in cipher_suites) + ","
        ja3_string += ",".join(str(e) for e in extensions) + ","
        ja3_string += ",".join(str(c) for c in (elliptic_curves or [])) + ","
        ja3_string += ",".join(str(f) for f in (ec_point_formats or []))
        
        return hashlib.md5(ja3_string.encode()).hexdigest()

    def match_ja3(self, ja3_hash: str) -> Optional[tuple]:
        if ja3_hash in JA3_SIGNATURES:
            return JA3_SIGNATURES[ja3_hash]
        return None

    async def get_tls_info(self, host: str, port: int) -> TLSInfo:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=ctx),
                timeout=self.timeout
            )
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            
            if not hasattr(writer, 'getpeercert'):
                return TLSInfo()
            
            cert_data = writer.getpeercert(binary_form=True)
            
            tls_info = TLSInfo(
                version="TLSv1.2+",
                is_self_signed=False,
            )
            
            if cert_data:
                cert_dict = {}
                try:
                    cert = x509.load_der_x509_certificate(cert_data)
                    cert_dict = {
                        "subject": cert.subject.rfc4514_string(),
                        "issuer": cert.issuer.rfc4514_string(),
                        "serial": cert.serial_number,
                        "not_before": cert.not_valid_before.isoformat(),
                        "not_after": cert.not_valid_after.isoformat(),
                        "is_self_signed": cert.subject == cert.issuer,
                    }
                    tls_info.certificate = cert_dict
                    tls_info.is_self_signed = cert_dict.get("is_self_signed", False)
                except Exception:
                    pass
            
            return tls_info
            
        except Exception:
            return TLSInfo()
