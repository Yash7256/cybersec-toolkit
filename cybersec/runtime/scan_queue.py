import asyncio

scan_queue = asyncio.Queue(maxsize=1000)


async def get_queue_stats() -> dict:
    """Get queue statistics."""
    return {
        "size": scan_queue.qsize(),
        "maxsize": scan_queue.maxsize,
        "full": scan_queue.full(),
        "empty": scan_queue.empty()
    }


async def enqueue_scan(target: str, port_range: str = "common", **opts) -> bool:
    """Enqueue a scan request. Returns True if successful."""
    try:
        scan_queue.put_nowait({
            "target": target,
            "port_range": port_range,
            "opts": opts
        })
        return True
    except asyncio.QueueFull:
        return False


async def dequeue_scan() -> dict:
    """Dequeue a scan request. Returns None if empty."""
    try:
        return scan_queue.get_nowait()
    except asyncio.QueueEmpty:
        return None