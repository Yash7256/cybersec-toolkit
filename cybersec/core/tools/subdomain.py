import asyncio
import socket
from dataclasses import dataclass

@dataclass
class SubdomainResult:
    domain: str
    found: list[dict]
    total_checked: int
    total_found: int
    error: str | None

WORDLISTS = {
    "small": ["www", "mail", "ftp", "api", "dev", "staging", "test", "admin", "blog", "shop", "app", "portal", "vpn", "remote", "secure"],
    "medium": ["www", "mail", "ftp", "api", "dev", "staging", "test", "admin", "blog", "shop", "app", "portal", "vpn", "remote", "secure", "db", "ns1", "ns2", "smtp", "pop", "imap", "m", "mobile", "cdn"],
    "large": ["www", "mail", "ftp", "api", "dev", "staging", "test", "admin", "blog", "shop", "app", "portal", "vpn", "remote", "secure", "db", "ns1", "ns2", "smtp", "pop", "imap", "m", "mobile", "cdn", "beta", "alpha", "docs", "help", "support", "forum"]
}

async def find_subdomains(domain: str, wordlist: str = "small") -> SubdomainResult:
    entries = WORDLISTS.get(wordlist, WORDLISTS["small"])
    
    async def resolve_subdomain(sub: str) -> dict | None:
        full = f"{sub}.{domain}"
        loop = asyncio.get_event_loop()
        try:
            ip = await loop.run_in_executor(None, socket.gethostbyname, full)
            return {"subdomain": full, "ip": ip}
        except Exception:
            return None

    tasks = [resolve_subdomain(sub) for sub in entries]
    results = await asyncio.gather(*tasks)
    
    found = [r for r in results if r is not None]
    
    return SubdomainResult(
        domain=domain,
        found=found,
        total_checked=len(entries),
        total_found=len(found),
        error=None
    )
