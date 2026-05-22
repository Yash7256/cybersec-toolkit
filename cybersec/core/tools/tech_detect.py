"""Detect web and service technologies from banners and HTTP responses."""

from __future__ import annotations

import re
from dataclasses import dataclass

# (display name, compiled regex) — order matters for stable UI sorting by priority
_TECH_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("Cloudflare", re.compile(r"cloudflare|cf-ray|cf-cache-status|__cf_bm", re.I)),
    ("WordPress", re.compile(r"wordpress|wp-content|wp-includes|/xmlrpc\.php", re.I)),
    ("Drupal", re.compile(r"drupal|x-drupal-|/sites/default/", re.I)),
    ("Joomla", re.compile(r"joomla|/components/com_", re.I)),
    ("Shopify", re.compile(r"shopify|x-shopid|cdn\.shopify", re.I)),
    ("Apache", re.compile(r"apache[/\s]|apache-coyote|mod_ssl|mod_php", re.I)),
    ("Nginx", re.compile(r"nginx[/\s]", re.I)),
    ("IIS", re.compile(r"microsoft-iis|asp\.net", re.I)),
    ("LiteSpeed", re.compile(r"litespeed", re.I)),
    ("Caddy", re.compile(r"\bcaddy\b", re.I)),
    ("Tomcat", re.compile(r"apache-coyote|tomcat|servlet", re.I)),
    ("Jetty", re.compile(r"jetty", re.I)),
    ("PHP", re.compile(r"\bphp[/\s\d]|x-powered-by:\s*php", re.I)),
    ("Node.js", re.compile(r"node\.?js[/\s\da-z.]*|x-powered-by:\s*node", re.I)),
    ("Express", re.compile(r"\bexpress\b|x-powered-by:\s*express", re.I)),
    ("Django", re.compile(r"django|csrftoken=|wsgi", re.I)),
    ("Laravel", re.compile(r"laravel|x-powered-by:\s*laravel", re.I)),
    ("Ruby on Rails", re.compile(r"ruby on rails|rails|x-runtime:.*rails", re.I)),
    ("React", re.compile(r"react-dom|__react|data-reactroot|/_next/static", re.I)),
    ("Vue.js", re.compile(r"vue\.js|__vue__|data-v-[a-f0-9]", re.I)),
    ("Angular", re.compile(r"angular|ng-version=", re.I)),
    ("jQuery", re.compile(r"jquery[./-]\d|jquery\.min\.js", re.I)),
    ("Bootstrap", re.compile(r"bootstrap[./-]\d|bootstrap\.min", re.I)),
    ("AWS", re.compile(r"amazonaws|x-amz-|awselb", re.I)),
    ("Google Cloud", re.compile(r"google frontend|gfe|x-cloud-trace", re.I)),
    ("Azure", re.compile(r"microsoft-azure|x-azure-ref", re.I)),
    ("Varnish", re.compile(r"varnish|x-varnish", re.I)),
    ("HAProxy", re.compile(r"haproxy", re.I)),
    ("OpenSSH", re.compile(r"openssh[_\s]", re.I)),
    ("MySQL", re.compile(r"\bmysql\b|mariadb", re.I)),
    ("PostgreSQL", re.compile(r"\bpostgresql\b", re.I)),
    ("Redis", re.compile(r"\bredis\b", re.I)),
    ("MongoDB", re.compile(r"\bmongodb\b", re.I)),
    ("Elasticsearch", re.compile(r"elasticsearch|kibana", re.I)),
]


@dataclass(frozen=True)
class TechnologyMatch:
    name: str


def _normalize_text(raw: bytes | str | None) -> str:
    if not raw:
        return ""
    if isinstance(raw, bytes):
        return raw.decode("utf-8", errors="replace")
    return raw


def detect_technologies(
    raw: bytes | str | None,
    *,
    extra_text: str | None = None,
) -> list[str]:
    """
    Return unique technology names found in HTTP/SSH banner data.
    """
    text = _normalize_text(raw)
    if extra_text:
        text = f"{text}\n{extra_text}"
    if not text.strip():
        return []

    # Cap body scan size for performance
    if len(text) > 65536:
        text = text[:65536]

    found: list[str] = []
    seen: set[str] = set()
    for name, pattern in _TECH_PATTERNS:
        if name in seen:
            continue
        if pattern.search(text):
            found.append(name)
            seen.add(name)

    return found


def merge_technologies(*lists: list[str]) -> list[str]:
    """Unique technologies preserving first-seen order."""
    merged: list[str] = []
    seen: set[str] = set()
    for items in lists:
        for name in items:
            if name not in seen:
                merged.append(name)
                seen.add(name)
    return merged
