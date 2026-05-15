"""
Standalone scan worker process.

Connects to Redis, consumes scan jobs from the stream,
executes them, and publishes results back.

Usage:
    python -m cybersec.apps.worker.main [--workers 4]

Can be scaled horizontally — each worker gets its own asyncio loop,
FD table, and ephemeral port budget.
"""
import asyncio
import logging
import os
import signal
import sys

from cybersec.core.queue.backend import ensure_stream_group, close_redis
from cybersec.core.queue.consumer import consume_scan_jobs

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("worker")


async def main(worker_count: int = 1):
    await ensure_stream_group()
    logger.info("Starting %d scan worker(s)", worker_count)

    # Recover orphaned scans from previous run
    try:
        from cybersec.core.recovery import recover_orphaned_scans
        orphaned = await recover_orphaned_scans(f"stream-worker-{os.getpid()}")
        if orphaned:
            logger.info("Marked %d orphaned scans as timed_out", len(orphaned))
    except Exception as e:
        logger.debug("Recovery check skipped: %s", e)

    workers = [asyncio.create_task(consume_scan_jobs(i)) for i in range(worker_count)]

    # Event loop stall detector — updates Prometheus gauge & logs
    async def _loop_monitor():
        from cybersec.core.metrics_registry import event_loop_lag_ms
        loop = asyncio.get_running_loop()
        while True:
            start = loop.time()
            await asyncio.sleep(1)
            lag = loop.time() - start - 1.0
            lag_ms = lag * 1000
            event_loop_lag_ms().set(lag_ms)
            if lag > 0.1:
                logger.warning("Event loop lag: %.0fms", lag_ms)

    monitor = asyncio.create_task(_loop_monitor())
    workers.append(monitor)

    stop = asyncio.Future()

    def _shutdown():
        if not stop.done():
            stop.set_result(None)

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, _shutdown)
        except NotImplementedError:
            pass

    try:
        await stop
    except asyncio.CancelledError:
        pass

    logger.info("Shutting down workers...")
    for w in workers:
        w.cancel()
    await asyncio.gather(*workers, return_exceptions=True)
    await close_redis()
    logger.info("Worker shut down complete")


if __name__ == "__main__":
    worker_count = int(sys.argv[sys.argv.index("--workers") + 1]) if "--workers" in sys.argv else 1
    asyncio.run(main(worker_count))
