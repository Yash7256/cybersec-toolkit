"""Banner grabbing for open ports (welcome messages, HTTP responses, raw data)."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass

MAX_BANNER_BYTES = 4096


@dataclass
class BannerInfo:
    raw_banner: str | None = None
    welcome_message: str | None = None
    server_response: str | None = None


def _decode(data: bytes) -> str:
    return data.decode("utf-8", errors="replace").rstrip()


def _first_line(text: str) -> str | None:
    for line in text.replace("\r\n", "\n").split("\n"):
        line = line.strip()
        if line:
            return line
    return None


def _truncate(text: str, limit: int = MAX_BANNER_BYTES) -> str:
    if len(text) <= limit:
        return text
    return text[:limit] + "\n… [truncated]"


def from_bytes(data: bytes, *, server_response: str | None = None) -> BannerInfo:
    if not data:
        return BannerInfo()
    text = _truncate(_decode(data))
    welcome = _first_line(text)
    return BannerInfo(
        raw_banner=text or None,
        welcome_message=welcome,
        server_response=server_response or None,
    )


def from_http_response(data: bytes) -> BannerInfo:
    if not data:
        return BannerInfo()
    text = _truncate(_decode(data))
    welcome = _first_line(text)
    header_block = text.split("\r\n\r\n", 1)[0]
    if not header_block and "\n\n" in text:
        header_block = text.split("\n\n", 1)[0]
    return BannerInfo(
        raw_banner=text or None,
        welcome_message=welcome,
        server_response=header_block or text or None,
    )


async def read_passive_banner(
    reader: asyncio.StreamReader,
    timeout: float,
    limit: int = MAX_BANNER_BYTES,
) -> bytes:
    try:
        return await asyncio.wait_for(reader.read(limit), timeout=timeout)
    except (asyncio.TimeoutError, OSError):
        return b""


async def grab_http_banner(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    hostname: str,
    timeout: float,
) -> BannerInfo:
    request = (
        f"GET / HTTP/1.1\r\n"
        f"Host: {hostname}\r\n"
        f"User-Agent: CyberSec-PortScanner/1.0\r\n"
        f"Connection: close\r\n\r\n"
    ).encode()
    try:
        writer.write(request)
        await writer.drain()
        data = await asyncio.wait_for(reader.read(MAX_BANNER_BYTES), timeout=timeout)
        return from_http_response(data)
    except (asyncio.TimeoutError, OSError):
        return BannerInfo()
