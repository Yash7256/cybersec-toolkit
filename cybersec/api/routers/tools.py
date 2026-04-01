import asyncio
import logging
import socket
import ssl
import subprocess
from typing import Any, Dict

import whois
from fastapi import APIRouter

from cybersec.api.deps import DBSession, OptionalUser
from cybersec.api.schemas.tool import (
    DNSRequest,
    WHOISRequest,
    SSLRequest,
    HTTPHeadersRequest,
    TracerouteRequest,
    PingRequest,
    SubdomainRequest,
    GeoIPRequest,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/tools", tags=["tools"])


async def run_dns_lookup(target: str, record_type: str = "A") -> Dict[str, Any]:
    try:
        import dns.resolver

        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 10

        all_types = (
            ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]
            if record_type == "ALL"
            else [record_type]
        )
        result = {
            "target": target,
            "status": "success",
        }

        for rt in all_types:
            try:
                answers = resolver.resolve(target, rt)
                records = [str(rdata) for rdata in answers]
                if records:
                    key = f"{rt.lower()}_records"
                    result[key] = records
            except Exception:
                pass

        return result
    except Exception as e:
        logger.warning(f"DNS lookup failed for {target}: {e}")
        return {
            "target": target,
            "error": str(e),
            "status": "failed",
        }


async def run_whois_lookup(target: str) -> Dict[str, Any]:
    loop = asyncio.get_event_loop()

    def sync_whois():
        try:
            w = whois.whois(target)
            return {
                "target": target,
                "domain_name": w.domain_name,
                "registrar": w.registrar,
                "creation_date": str(w.creation_date) if w.creation_date else None,
                "expiration_date": str(w.expiration_date)
                if w.expiration_date
                else None,
                "name_servers": w.name_servers,
                "status": w.status,
                "status_code": "success",
            }
        except Exception as e:
            return {
                "target": target,
                "error": str(e),
                "status": "failed",
            }

    return await loop.run_in_executor(None, sync_whois)


async def run_ssl_check(target: str, port: int = 443) -> Dict[str, Any]:
    loop = asyncio.get_event_loop()

    def sync_ssl_check():
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection((target, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=target) as ssock:
                    cert = ssock.getpeercert(binary_form=True)
                    cipher = ssock.cipher()

                    from cryptography import x509

                    try:
                        x509_cert = x509.load_der_x509_certificate(cert)
                    except Exception as e:
                        return {
                            "target": f"{target}:{port}",
                            "error": f"Failed to parse certificate: {str(e)}",
                            "status": "failed",
                        }

                    cn = None
                    try:
                        for attr in x509_cert.subject:
                            if attr.oid == x509.oid.NameOID.COMMON_NAME:
                                cn = attr.value
                                break
                    except Exception:
                        pass

                    return {
                        "target": f"{target}:{port}",
                        "cipher_suite": cipher[0] if cipher else None,
                        "tls_versions": [ssock.version()],
                        "cn": cn or x509_cert.subject.rfc4514_string(),
                        "issuer": x509_cert.issuer.rfc4514_string(),
                        "valid_from": x509_cert.not_valid_before_utc.isoformat(),
                        "valid_to": x509_cert.not_valid_after_utc.isoformat(),
                        "status": "success",
                    }
        except ssl.SSLError as e:
            return {
                "target": f"{target}:{port}",
                "error": str(e),
                "status": "ssl_error",
            }
        except socket.timeout:
            return {
                "target": f"{target}:{port}",
                "error": "Connection timeout",
                "status": "failed",
            }
        except Exception as e:
            return {"target": f"{target}:{port}", "error": str(e), "status": "failed"}

    return await loop.run_in_executor(None, sync_ssl_check)


async def run_http_headers(target: str, path: str = "/") -> Dict[str, Any]:
    import httpx

    try:
        url = f"http://{target}{path}"
        async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
            response = await client.get(url)
            return {
                "target": target,
                "url": str(response.url),
                "status_code": response.status_code,
                "headers": dict(response.headers),
                "content_length": len(response.content),
                "status": "success",
            }
    except httpx.TimeoutException:
        return {"target": target, "error": "Request timeout", "status": "timeout"}
    except Exception as e:
        return {"target": target, "error": str(e), "status": "failed"}


async def run_traceroute(target: str, max_hops: int = 30) -> Dict[str, Any]:
    loop = asyncio.get_event_loop()

    def sync_traceroute():
        try:
            cmd = ["traceroute", "-m", str(max_hops), "-n", target]
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60,
            )
            lines = result.stdout.strip().split("\n")
            hops = []
            for line in lines:
                parts = line.strip().split()
                if parts and parts[0].isdigit():
                    hop_number = int(parts[0])
                    rest = " ".join(parts[1:])
                    if rest.startswith("*") or rest == "* * *":
                        hops.append(
                            {
                                "hop_number": hop_number,
                                "ip": None,
                                "hostname": None,
                                "rtt_ms": None,
                            }
                        )
                    else:
                        addr_parts = rest.split()
                        hops.append(
                            {
                                "hop_number": hop_number,
                                "ip": addr_parts[0] if addr_parts else None,
                                "hostname": None,
                                "rtt_ms": None,
                            }
                        )
            return {
                "target": target,
                "max_hops": max_hops,
                "hops": hops,
                "status": "success",
            }
        except FileNotFoundError:
            return {
                "target": target,
                "error": "traceroute command not found",
                "status": "failed",
            }
        except subprocess.TimeoutExpired:
            return {
                "target": target,
                "error": "Traceroute timeout",
                "status": "timeout",
            }
        except Exception as e:
            return {"target": target, "error": str(e), "status": "failed"}

    return await loop.run_in_executor(None, sync_traceroute)


async def run_ping(target: str, count: int = 4) -> Dict[str, Any]:
    loop = asyncio.get_event_loop()

    def sync_ping():
        try:
            cmd = ["ping", "-c", str(count), target]
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30,
            )
            lines = result.stdout.strip().split("\n")
            packet_loss = "0%"
            min_ms = avg_ms = max_ms = None

            for line in lines:
                if "packets transmitted" in line:
                    parts = line.split(",")
                    if len(parts) >= 3:
                        packet_loss = parts[2].split()[0]
                elif "rtt min/avg/max/mdev" in line or "round-trip min/avg/max" in line:
                    values = line.split("=")[1].strip().split("/")
                    if len(values) >= 4:
                        min_ms = float(values[0])
                        avg_ms = float(values[1])
                        max_ms = float(values[2])

            return {
                "target": target,
                "count": count,
                "packet_loss": packet_loss,
                "min_ms": min_ms,
                "avg_ms": avg_ms,
                "max_ms": max_ms,
                "raw_output": result.stdout,
                "status": "success",
            }
        except FileNotFoundError:
            return {
                "target": target,
                "error": "ping command not found",
                "status": "failed",
            }
        except subprocess.TimeoutExpired:
            return {"target": target, "error": "Ping timeout", "status": "timeout"}
        except Exception as e:
            return {"target": target, "error": str(e), "status": "failed"}

    return await loop.run_in_executor(None, sync_ping)


async def run_subdomain_enum(domain: str, wordlist: str = None) -> Dict[str, Any]:
    common_subdomains = [
        "www",
        "mail",
        "ftp",
        "localhost",
        "webmail",
        "smtp",
        "pop",
        "ns1",
        "webdisk",
        "ns2",
        "cpanel",
        "whm",
        "autodiscover",
        "autoconfig",
        "m",
        "imap",
        "test",
        "ns",
        "blog",
        "pop3",
        "dev",
        "www2",
        "admin",
        "forum",
        "news",
        "vpn",
        "ns3",
        "mail2",
        "new",
        "mysql",
        "old",
        "lists",
        "support",
        "mobile",
        "mx",
        "static",
        "docs",
        "beta",
        "shop",
        "sql",
        "secure",
        "demo",
        "v2",
        "api",
        "cdn",
        "stats",
    ]

    loop = asyncio.get_event_loop()
    found: list[str] = []

    def check_subdomain(subdomain: str) -> str | None:
        full_domain = f"{subdomain}.{domain}"
        try:
            socket.gethostbyname(full_domain)
            return full_domain
        except socket.gaierror:
            return None
        except OSError:
            return None

    for sub in common_subdomains:
        result = await loop.run_in_executor(None, lambda s=sub: check_subdomain(s))
        if result:
            found.append(result)

    return {
        "domain": domain,
        "subdomains_found": found,
        "total_found": len(found),
        "status": "success",
    }


async def run_geoip_lookup(target: str) -> Dict[str, Any]:
    try:
        import httpx

        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(f"http://ip-api.com/json/{target}")
            if response.status_code == 200:
                data = response.json()
                if data.get("status") == "success":
                    return {
                        "target": target,
                        "ip": data.get("query"),
                        "country": data.get("country"),
                        "country_code": data.get("countryCode"),
                        "region": data.get("regionName"),
                        "city": data.get("city"),
                        "zip": data.get("zip"),
                        "lat": data.get("lat"),
                        "lon": data.get("lon"),
                        "timezone": data.get("timezone"),
                        "isp": data.get("isp"),
                        "org": data.get("org"),
                        "asn": data.get("as"),
                        "status": "success",
                    }
            return {
                "target": target,
                "error": "GeoIP lookup failed",
                "status": "failed",
            }
    except Exception as e:
        return {"target": target, "error": str(e), "status": "failed"}


@router.post("/dns")
async def dns_tool(
    request: DNSRequest,
    db: DBSession,
    current_user: OptionalUser,
) -> Dict[str, Any]:
    return await run_dns_lookup(request.target, request.record_type)


@router.post("/whois")
async def whois_tool(
    request: WHOISRequest,
    db: DBSession,
    current_user: OptionalUser,
) -> Dict[str, Any]:
    return await run_whois_lookup(request.target)


@router.post("/ssl")
async def ssl_tool(
    request: SSLRequest,
    db: DBSession,
    current_user: OptionalUser,
) -> Dict[str, Any]:
    host = request.host or request.target
    return await run_ssl_check(host, request.port)


@router.post("/http_headers")
async def http_headers_tool(
    request: HTTPHeadersRequest,
    db: DBSession,
    current_user: OptionalUser,
) -> Dict[str, Any]:
    return await run_http_headers(request.target, request.path)


@router.post("/traceroute")
async def traceroute_tool(
    request: TracerouteRequest,
    db: DBSession,
    current_user: OptionalUser,
) -> Dict[str, Any]:
    return await run_traceroute(request.target, request.max_hops)


@router.post("/ping")
async def ping_tool(
    request: PingRequest,
    db: DBSession,
    current_user: OptionalUser,
) -> Dict[str, Any]:
    return await run_ping(request.target, request.count)


@router.post("/subdomain")
async def subdomain_tool(
    request: SubdomainRequest,
    db: DBSession,
    current_user: OptionalUser,
) -> Dict[str, Any]:
    return await run_subdomain_enum(request.domain, request.wordlist)


@router.post("/geoip")
async def geoip_tool(
    request: GeoIPRequest,
    db: DBSession,
    current_user: OptionalUser,
) -> Dict[str, Any]:
    return await run_geoip_lookup(request.target)
