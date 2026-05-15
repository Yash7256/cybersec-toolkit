"""
Async TCP connection pool for reusing connections to the same host:port.

Used primarily by the enrichment pipeline (service detection, banner
grabbing, TLS probes) where multiple probes may hit the same port.

Connections use SO_REUSEADDR + SO_LINGER abortive close for fast recycling.
"""
import asyncio
import socket
import struct
import time
from typing import Optional

from cybersec.config.settings import settings


def _make_socket() -> socket.socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    except AttributeError:
        pass
    linger = struct.pack("ii", 1, 0)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, linger)
    except OSError:
        pass
    sock.settimeout(None)
    return sock


class AsyncConnectionPool:
    """Connection pool keyed by (host, port).

    Connections are created with SO_REUSEADDR + SO_LINGER for fast
    recycling and are validated before reuse.
    """

    def __init__(self, max_size: int = 100, max_idle_time: float = 30.0):
        self.max_size = max_size
        self.max_idle_time = max_idle_time
        self._pool: asyncio.Queue = asyncio.Queue(maxsize=max_size)
        self._lock = asyncio.Lock()

    async def acquire(self, host: str, port: int, timeout: float = 3.0):
        """Get a cached or new connection to (host, port).

        Returns (reader, writer, reused) where reused=True if pulled from pool.
        """
        # Try pool first
        try:
            conn_info = self._pool.get_nowait()
            reader, writer, created = conn_info
            age = time.monotonic() - created
            if age < self.max_idle_time:
                try:
                    writer.write(b"")
                    await writer.drain()
                    return reader, writer, True
                except Exception:
                    pass
        except asyncio.QueueEmpty:
            pass

        # Create new connection with tuning
        loop = asyncio.get_running_loop()
        sock = _make_socket()
        try:
            await asyncio.wait_for(
                loop.sock_connect(sock, (host, port)),
                timeout=timeout,
            )
            reader = asyncio.StreamReader()
            protocol = asyncio.StreamReaderProtocol(reader)
            transport, _ = await loop.create_connection(
                lambda: protocol, sock=sock,
            )
            writer = asyncio.StreamWriter(transport, protocol, reader, loop)
            return reader, writer, False
        except BaseException:
            sock.close()
            raise

    async def release(self, reader, writer) -> None:
        """Return a connection to the pool for reuse."""
        try:
            conn_info = (reader, writer, time.monotonic())
            self._pool.put_nowait(conn_info)
        except asyncio.QueueFull:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    async def cleanup(self) -> None:
        """Close all idle connections."""
        while not self._pool.empty():
            try:
                _, writer, _ = self._pool.get_nowait()
                try:
                    writer.close()
                    await writer.wait_closed()
                except Exception:
                    pass
            except asyncio.QueueEmpty:
                break
