"""
Async TCP connection pool for reusing connections to the same host.
Reduces connection overhead and improves scan performance.
"""
import asyncio
import time
from typing import Optional, Tuple


class AsyncConnectionPool:
    def __init__(self, max_size: int = 100, max_idle_time: float = 30.0):
        self.max_size = max_size
        self.max_idle_time = max_idle_time
        self._pool = asyncio.Queue(maxsize=max_size)
        self._active_connections = {}
        self._lock = asyncio.Lock()
        self._connection_id_counter = 0
        
    async def get_connection(self, host: str, port: int, timeout: float) -> Tuple[Tuple, bool]:
        connection_key = f"{host}:{port}"
        
        try:
            conn_info = self._pool.get_nowait()
            conn, created_time = conn_info
            
            if (time.monotonic() - created_time) < self.max_idle_time:
                try:
                    conn.writer.write(b"")
                    await conn.writer.drain()
                    return conn, False
                except Exception:
                    pass
        except asyncio.QueueEmpty:
            pass
        
        conn_id = self._connection_id_counter
        self._connection_id_counter += 1
        
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=timeout
            )
            
            async with self._lock:
                self._active_connections[conn_id] = (reader, writer, time.monotonic())
            
            return (reader, writer, conn_id), True
            
        except Exception as e:
            raise e
    
    async def return_connection(self, connection_id: int):
        async with self._lock:
            if connection_id in self._active_connections:
                reader, writer, created_time = self._active_connections[connection_id]
                
                if (time.monotonic() - created_time) < self.max_idle_time:
                    try:
                        conn_info = (reader, writer, created_time)
                        self._pool.put_nowait(conn_info)
                    except asyncio.QueueFull:
                        pass
                
                del self._active_connections[connection_id]
    
    async def cleanup(self):
        current_time = time.monotonic()
        expired_connections = []
        
        async with self._lock:
            for conn_id, (reader, writer, created_time) in list(self._active_connections.items()):
                if (current_time - created_time) > self.max_idle_time:
                    expired_connections.append(conn_id)
                    del self._active_connections[conn_id]
                    
                    try:
                        conn_info = (reader, writer, created_time)
                        self._pool.put_nowait(conn_info)
                    except asyncio.QueueFull:
                        pass
        
        for conn_id in expired_connections:
            if conn_id in self._active_connections:
                reader, writer, _ = self._active_connections[conn_id]
                try:
                    writer.close()
                except Exception:
                    pass