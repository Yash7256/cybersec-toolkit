import asyncio
from dataclasses import dataclass
import whois as python_whois
from datetime import datetime

@dataclass
class WHOISResult:
    target: str
    registrar: str | None
    creation_date: str | None
    expiration_date: str | None
    updated_date: str | None
    name_servers: list[str]
    status: list[str]
    emails: list[str]
    org: str | None
    country: str | None
    raw_text: str | None
    error: str | None

async def whois_lookup(target: str) -> WHOISResult:
    loop = asyncio.get_event_loop()
    try:
        w = await loop.run_in_executor(None, python_whois.whois, target)
        
        def extract_date(d):
            if d is None: return None
            if isinstance(d, list): d = d[0]
            if isinstance(d, datetime): return d.isoformat()
            return str(d)
        
        def extract_list(l):
            if not l: return []
            if isinstance(l, str): return [l]
            return list(set(l))
            
        def extract_ns(l):
            ns = extract_list(l)
            return list(set(n.lower() for n in ns))

        return WHOISResult(
            target=target,
            registrar=str(w.registrar) if w.registrar else None,
            creation_date=extract_date(w.creation_date),
            expiration_date=extract_date(w.expiration_date),
            updated_date=extract_date(w.updated_date),
            name_servers=extract_ns(w.name_servers),
            status=extract_list(w.status),
            emails=extract_list(w.emails),
            org=str(w.org) if w.org else None,
            country=str(w.country) if w.country else None,
            raw_text=str(w.text) if w.text else None,
            error=None
        )
    except Exception as e:
        return WHOISResult(
            target=target,
            registrar=None, creation_date=None, expiration_date=None, updated_date=None,
            name_servers=[], status=[], emails=[], org=None, country=None, raw_text=None,
            error=str(e)
        )
