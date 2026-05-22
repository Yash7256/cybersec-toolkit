"""Parse service versions from banners and HTTP response headers."""

from __future__ import annotations

import re

# SSH banner: SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu0.13
_OPENSSH_RE = re.compile(r"OpenSSH[_\s]([\d.p\w.-]+)", re.I)

# HTTP Server / X-Powered-By headers
_APACHE_RE = re.compile(r"Apache[/\s]([\d.]+)", re.I)
_NGINX_RE = re.compile(r"nginx[/\s]([\d.]+)", re.I)
_PHP_RE = re.compile(r"PHP[/\s]([\d.]+)", re.I)
_IIS_RE = re.compile(r"Microsoft-IIS[/\s]([\d.]+)", re.I)
_NODE_RE = re.compile(
    r"(?:Node\.js[/\s]([\d.]+)|Express(?:[/\s]([\d.]+))?|(?:^|[\s,])Node(?:[/\s]([\d.]+))?)",
    re.I,
)


def parse_ssh_banner(banner: bytes | str) -> str | None:
    text = banner.decode("utf-8", errors="replace") if isinstance(banner, bytes) else banner
    match = _OPENSSH_RE.search(text)
    if match:
        return f"OpenSSH {match.group(1)}"
    return None


def parse_http_response(raw: bytes | str) -> str | None:
    text = raw.decode("utf-8", errors="replace") if isinstance(raw, bytes) else raw
    header_block = text.split("\r\n\r\n", 1)[0]
    versions: list[str] = []

    for line in header_block.splitlines():
        if ":" not in line:
            continue
        name, _, value = line.partition(":")
        if name.lower() not in ("server", "x-powered-by"):
            continue
        versions.extend(_extract_http_versions(value.strip()))

    return ", ".join(versions) if versions else None


def _extract_http_versions(header_value: str) -> list[str]:
    found: list[str] = []

    for pattern, label in (
        (_APACHE_RE, "Apache"),
        (_NGINX_RE, "nginx"),
        (_IIS_RE, "IIS"),
        (_PHP_RE, "PHP"),
    ):
        match = pattern.search(header_value)
        if match:
            found.append(f"{label} {match.group(1)}")

    node_match = _NODE_RE.search(header_value)
    if node_match:
        ver = node_match.group(1) or node_match.group(2) or node_match.group(3)
        if ver:
            found.append(f"Node.js {ver}")
        elif "express" in header_value.lower():
            found.append("Express")
        else:
            found.append("Node.js")

    return found
