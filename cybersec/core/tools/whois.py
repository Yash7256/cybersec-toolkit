import asyncio
import re
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

import httpx
import whois as python_whois


WHOIS_CACHE_TTL_SECONDS = 3600
_CACHE: dict[str, tuple[float, "WHOISResult"]] = {}

PRIVACY_PATTERNS = (
    "privacy",
    "redacted",
    "whoisguard",
    "domains by proxy",
    "contact privacy",
    "data protected",
    "private registration",
    "withheld",
)

SUSPICIOUS_STATUS_TOKENS = (
    "hold",
    "pendingdelete",
    "redemptionperiod",
    "serverdeleteprohibited",
    "clienthold",
)

COMMON_TLDS = {
    "com", "org", "net", "edu", "gov", "io", "co", "in", "uk", "de", "fr", "au",
    "ca", "us", "info", "biz", "dev", "app", "ai", "me", "xyz",
}

STATUS_EXPLANATIONS = {
    "clienttransferprohibited": "Domain transfer is locked by the registrar.",
    "servertransferprohibited": "Registry-level transfer lock is active.",
    "clientupdateprohibited": "Registrar prevents domain updates.",
    "serverupdateprohibited": "Registry prevents domain updates.",
    "clientdeleteprohibited": "Registrar prevents domain deletion.",
    "serverdeleteprohibited": "Registry prevents domain deletion.",
    "clienthold": "Registrar has placed the domain on hold; DNS may not resolve.",
    "serverhold": "Registry has placed the domain on hold; DNS may not resolve.",
    "pendingdelete": "Domain is pending deletion.",
    "redemptionperiod": "Domain is in redemption period after expiry/deletion.",
    "ok": "No restrictions are currently indicated.",
}

REGISTRY_HINTS = {
    "com": "Verisign",
    "net": "Verisign",
    "org": "Public Interest Registry",
    "edu": "Educause",
    "gov": "Cybersecurity and Infrastructure Security Agency",
    "uk": "Nominet",
    "in": "National Internet Exchange of India",
}


@dataclass
class WHOISResult:
    target: str
    domain: str | None
    tld: str | None
    registrar: str | None
    registrar_iana_id: str | None
    registrar_url: str | None
    registrar_abuse_email: str | None
    registrar_abuse_phone: str | None
    creation_date: str | None
    expiration_date: str | None
    updated_date: str | None
    domain_age_days: int | None
    days_until_expiry: int | None
    expiry_status: str | None
    name_servers: list[str]
    dnssec: str | None
    status: list[str]
    status_explanations: list[dict[str, str]]
    emails: list[str]
    registrant_org: str | None
    registrant_country: str | None
    admin_contact: dict[str, Any] | None
    tech_contact: dict[str, Any] | None
    abuse_contact: dict[str, Any] | None
    privacy_protected: bool
    raw_text: str | None
    rdap: dict[str, Any] | None
    rdap_available: bool
    registry: str | None
    iana: dict[str, Any] | None
    available: bool | None
    historical_whois: dict[str, Any]
    related_domains: dict[str, Any]
    risk_indicators: list[dict[str, str]]
    summary: str | None
    normalized: dict[str, Any]
    cached: bool
    error: str | None


def clear_whois_cache() -> None:
    _CACHE.clear()


def _normalize_target(target: str) -> str:
    normalized = target.strip().lower()
    normalized = re.sub(r"^https?://", "", normalized)
    normalized = normalized.split("/")[0].split(":")[0].strip(".")
    if not normalized:
        raise ValueError("Target is required")
    if len(normalized) > 253:
        raise ValueError("Target is too long")
    if any(ch.isspace() for ch in normalized):
        raise ValueError("Target must be a single domain")
    return normalized


def _tld(domain: str) -> str | None:
    parts = domain.rsplit(".", 1)
    return parts[1] if len(parts) == 2 else None


def _to_list(value: Any) -> list:
    if not value:
        return []
    if isinstance(value, str):
        return [value]
    try:
        return list(value)
    except TypeError:
        return [value]


def _unique_strings(value: Any, *, lower: bool = False) -> list[str]:
    items = []
    seen = set()
    for item in _to_list(value):
        if item is None:
            continue
        text = str(item).strip()
        if not text:
            continue
        if lower:
            text = text.lower()
        key = text.lower()
        if key not in seen:
            seen.add(key)
            items.append(text)
    return items


def _first(value: Any) -> Any:
    items = _to_list(value)
    return items[0] if items else None


def _parse_date(value: Any) -> datetime | None:
    value = _first(value)
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.replace(tzinfo=value.tzinfo or timezone.utc)
    text = str(value).strip()
    for fmt in ("%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
        try:
            parsed = datetime.strptime(text.replace("Z", "+0000"), fmt)
            return parsed.replace(tzinfo=parsed.tzinfo or timezone.utc)
        except ValueError:
            continue
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00")).replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def _date_text(value: Any) -> str | None:
    parsed = _parse_date(value)
    return parsed.isoformat() if parsed else (str(_first(value)) if _first(value) else None)


def _days_between(start: datetime | None, end: datetime | None) -> int | None:
    if not start or not end:
        return None
    return (end - start).days


def _status_key(status: str) -> str:
    status = status.split()[0].split("#")[0].strip()
    return re.sub(r"[^a-z]", "", status.lower())


def _status_explanations(statuses: list[str]) -> list[dict[str, str]]:
    explained = []
    for status in statuses:
        key = _status_key(status)
        explained.append({
            "status": status,
            "meaning": STATUS_EXPLANATIONS.get(key, "Registry status code reported by WHOIS/RDAP."),
        })
    return explained


def _privacy_detected(*values: Any) -> bool:
    haystack = " ".join(str(value).lower() for value in values if value)
    return any(pattern in haystack for pattern in PRIVACY_PATTERNS)


def _expiry_status(expiry: datetime | None, now: datetime) -> str | None:
    if not expiry:
        return None
    days = (expiry - now).days
    if days < 0:
        return "expired"
    if days <= 30:
        return "expiring_soon"
    return "healthy"


def _risk_indicators(
    *,
    creation: datetime | None,
    updated: datetime | None,
    expiry_status: str | None,
    privacy_protected: bool,
    statuses: list[str],
    tld: str | None,
    now: datetime,
) -> list[dict[str, str]]:
    risks = []
    if creation and (now - creation).days <= 30:
        risks.append({"id": "newly_registered", "severity": "medium", "label": "Newly registered domain"})
    if expiry_status == "expired":
        risks.append({"id": "expired", "severity": "high", "label": "Domain appears expired"})
    elif expiry_status == "expiring_soon":
        risks.append({"id": "expiring_soon", "severity": "medium", "label": "Domain expires soon"})
    if privacy_protected:
        risks.append({"id": "privacy_protected", "severity": "info", "label": "Registrant details appear privacy-protected or redacted"})
    if updated and (now - updated).days <= 14:
        risks.append({"id": "recently_updated", "severity": "info", "label": "WHOIS record was recently updated"})
    if any(any(token in _status_key(status) for token in SUSPICIOUS_STATUS_TOKENS) for status in statuses):
        risks.append({"id": "suspicious_status", "severity": "high", "label": "Domain has a restrictive or suspicious registry status"})
    if tld and tld not in COMMON_TLDS:
        risks.append({"id": "unusual_tld", "severity": "info", "label": f"Less common TLD: .{tld}"})
    return risks


def _contact(email: str | None = None, phone: str | None = None, name: str | None = None, org: str | None = None) -> dict[str, Any] | None:
    data = {"name": name, "organization": org, "email": email, "phone": phone}
    return data if any(data.values()) else None


def _extract_rdap_contact(entities: list[dict] | None, role: str) -> dict[str, Any] | None:
    if not entities:
        return None
    for entity in entities:
        roles = {str(item).lower() for item in entity.get("roles", [])}
        nested = _extract_rdap_contact(entity.get("entities"), role)
        if role not in roles and nested:
            return nested
        if role not in roles:
            continue
        name = org = email = phone = None
        for item in entity.get("vcardArray", [None, []])[1]:
            if len(item) < 4:
                continue
            key = item[0]
            if key == "fn":
                name = item[3]
            elif key == "org":
                org = item[3]
            elif key == "email":
                email = item[3]
            elif key == "tel":
                phone = item[3]
        return _contact(email=email, phone=phone, name=name, org=org)
    return None


async def _fetch_rdap(domain: str) -> dict[str, Any] | None:
    url = f"https://rdap.org/domain/{domain}"
    async with httpx.AsyncClient(timeout=8) as client:
        resp = await client.get(url)
    if resp.status_code == 404:
        return None
    if resp.status_code == 429:
        raise RuntimeError("RDAP rate limit reached")
    resp.raise_for_status()
    return resp.json()


def _rdap_date(rdap: dict[str, Any] | None, action: str) -> str | None:
    if not rdap:
        return None
    for event in rdap.get("events", []):
        if event.get("eventAction") == action:
            return event.get("eventDate")
    return None


def _rdap_statuses(rdap: dict[str, Any] | None) -> list[str]:
    return _unique_strings((rdap or {}).get("status"))


def _iana_metadata(tld: str | None, registry: str | None) -> dict[str, Any] | None:
    if not tld:
        return None
    return {
        "tld": tld,
        "iana_url": f"https://www.iana.org/domains/root/db/{tld}.html",
        "registry_hint": registry or REGISTRY_HINTS.get(tld),
        "metadata_source": "local mapping plus IANA root-db link",
    }


def _empty_result(target: str, error: str) -> WHOISResult:
    return WHOISResult(
        target=target,
        domain=None,
        tld=None,
        registrar=None,
        registrar_iana_id=None,
        registrar_url=None,
        registrar_abuse_email=None,
        registrar_abuse_phone=None,
        creation_date=None,
        expiration_date=None,
        updated_date=None,
        domain_age_days=None,
        days_until_expiry=None,
        expiry_status=None,
        name_servers=[],
        dnssec=None,
        status=[],
        status_explanations=[],
        emails=[],
        registrant_org=None,
        registrant_country=None,
        admin_contact=None,
        tech_contact=None,
        abuse_contact=None,
        privacy_protected=False,
        raw_text=None,
        rdap=None,
        rdap_available=False,
        registry=None,
        iana=None,
        available=None,
        historical_whois={"available": False, "reason": "Requires a paid historical WHOIS provider"},
        related_domains={"available": False, "reason": "Requires a paid reverse WHOIS provider"},
        risk_indicators=[],
        summary=None,
        normalized={},
        cached=False,
        error=error,
    )


def _clone(result: WHOISResult, *, cached: bool) -> WHOISResult:
    data = result.__dict__.copy()
    data["name_servers"] = list(result.name_servers)
    data["status"] = list(result.status)
    data["status_explanations"] = [dict(item) for item in result.status_explanations]
    data["emails"] = list(result.emails)
    data["rdap"] = dict(result.rdap) if result.rdap else None
    data["iana"] = dict(result.iana) if result.iana else None
    data["historical_whois"] = dict(result.historical_whois)
    data["related_domains"] = dict(result.related_domains)
    data["risk_indicators"] = [dict(item) for item in result.risk_indicators]
    data["normalized"] = dict(result.normalized)
    data["cached"] = cached
    return WHOISResult(**data)


async def whois_lookup(target: str) -> WHOISResult:
    try:
        domain = _normalize_target(target)
    except ValueError as exc:
        return _empty_result(target, str(exc))

    now_ts = time.time()
    cached = _CACHE.get(domain)
    if cached and cached[0] > now_ts:
        return _clone(cached[1], cached=True)

    loop = asyncio.get_event_loop()
    now = datetime.now(timezone.utc)
    try:
        w = await loop.run_in_executor(None, python_whois.whois, domain)
    except Exception as exc:
        w = None
        whois_error = str(exc)
    else:
        whois_error = None

    rdap = None
    rdap_error = None
    try:
        rdap = await _fetch_rdap(domain)
    except Exception as exc:
        rdap_error = str(exc)

    tld = _tld(domain)
    rdap_entities = (rdap or {}).get("entities", [])
    creation = _parse_date(getattr(w, "creation_date", None) if w else None) or _parse_date(_rdap_date(rdap, "registration"))
    expiration = _parse_date(getattr(w, "expiration_date", None) if w else None) or _parse_date(_rdap_date(rdap, "expiration"))
    updated = _parse_date(getattr(w, "updated_date", None) if w else None) or _parse_date(_rdap_date(rdap, "last changed"))

    registrar_contact = _extract_rdap_contact(rdap_entities, "registrar")
    abuse_contact = _extract_rdap_contact(rdap_entities, "abuse")
    admin_contact = _extract_rdap_contact(rdap_entities, "administrative")
    tech_contact = _extract_rdap_contact(rdap_entities, "technical")

    registrar = (
        str(getattr(w, "registrar", "")) if w and getattr(w, "registrar", None) else None
    ) or (registrar_contact or {}).get("organization") or (registrar_contact or {}).get("name")
    statuses = _unique_strings(getattr(w, "status", None) if w else None) or _rdap_statuses(rdap)
    emails = _unique_strings(getattr(w, "emails", None) if w else None)
    name_servers = _unique_strings(getattr(w, "name_servers", None) if w else None, lower=True)
    if not name_servers and rdap:
        name_servers = _unique_strings([ns.get("ldhName") for ns in rdap.get("nameservers", [])], lower=True)

    raw_text = str(getattr(w, "text", "")) if w and getattr(w, "text", None) else None
    registrant_org = str(getattr(w, "org", "")) if w and getattr(w, "org", None) else None
    registrant_country = str(getattr(w, "country", "")) if w and getattr(w, "country", None) else None
    privacy_protected = _privacy_detected(registrant_org, emails, raw_text, admin_contact, tech_contact)
    expiry_status = _expiry_status(expiration, now)
    risks = _risk_indicators(
        creation=creation,
        updated=updated,
        expiry_status=expiry_status,
        privacy_protected=privacy_protected,
        statuses=statuses,
        tld=tld,
        now=now,
    )
    registry = REGISTRY_HINTS.get(tld or "")
    rdap_port43 = (rdap or {}).get("port43")
    if rdap_port43 and not registry:
        registry = rdap_port43

    available = None
    if whois_error and any(term in whois_error.lower() for term in ("no match", "not found", "available")):
        available = True
    elif w or rdap:
        available = False

    domain_age_days = _days_between(creation, now)
    days_until_expiry = _days_between(now, expiration)
    registrar_abuse_email = (abuse_contact or {}).get("email")
    registrar_abuse_phone = (abuse_contact or {}).get("phone")
    dnssec = (rdap or {}).get("secureDNS", {}).get("delegationSigned") if rdap else None
    if dnssec is not None:
        dnssec = "signed" if dnssec else "unsigned"

    summary = None
    if available is True:
        summary = f"{domain} appears available based on WHOIS response."
    elif registrar or creation or expiration:
        summary = f"{domain} is registered"
        if registrar:
            summary += f" with {registrar}"
        if expiration:
            summary += f" and expires in {days_until_expiry} days" if days_until_expiry is not None else ""
        summary += "."

    result = WHOISResult(
        target=target,
        domain=domain,
        tld=tld,
        registrar=registrar,
        registrar_iana_id=str(getattr(w, "registrar_iana_id", "")) if w and getattr(w, "registrar_iana_id", None) else None,
        registrar_url=str(getattr(w, "registrar_url", "")) if w and getattr(w, "registrar_url", None) else None,
        registrar_abuse_email=registrar_abuse_email,
        registrar_abuse_phone=registrar_abuse_phone,
        creation_date=creation.isoformat() if creation else _date_text(_rdap_date(rdap, "registration")),
        expiration_date=expiration.isoformat() if expiration else _date_text(_rdap_date(rdap, "expiration")),
        updated_date=updated.isoformat() if updated else _date_text(_rdap_date(rdap, "last changed")),
        domain_age_days=domain_age_days,
        days_until_expiry=days_until_expiry,
        expiry_status=expiry_status,
        name_servers=name_servers,
        dnssec=dnssec,
        status=statuses,
        status_explanations=_status_explanations(statuses),
        emails=emails,
        registrant_org=registrant_org,
        registrant_country=registrant_country,
        admin_contact=admin_contact,
        tech_contact=tech_contact,
        abuse_contact=abuse_contact,
        privacy_protected=privacy_protected,
        raw_text=raw_text,
        rdap=rdap,
        rdap_available=rdap is not None,
        registry=registry,
        iana=_iana_metadata(tld, registry),
        available=available,
        historical_whois={"available": False, "reason": "Requires a paid historical WHOIS provider"},
        related_domains={"available": False, "reason": "Requires a paid reverse WHOIS provider"},
        risk_indicators=risks,
        summary=summary,
        normalized={
            "source_priority": "WHOIS with RDAP fallback/enrichment",
            "rdap_error": rdap_error,
            "whois_error": whois_error,
        },
        cached=False,
        error=None if (w or rdap or available is True) else whois_error or rdap_error or "WHOIS lookup failed",
    )
    _CACHE[domain] = (now_ts + WHOIS_CACHE_TTL_SECONDS, _clone(result, cached=False))
    return result
