import asyncio
from typing import Optional
from cybersec.core.scan_queue import scan_queue
from cybersec.core.scanner import AsyncPortScanner
from cybersec.core import job_store as js

WORKER_COUNT = 10


async def worker(worker_id: int):
    """Worker that processes scan jobs from the queue."""
    print(f"[Worker {worker_id}] Started")
    
    while True:
        try:
            job = await scan_queue.get()
            
            if job is None:
                break
            
            job_id = job.get("job_id")
            target = job.get("target")
            port_range = job.get("port_range", "common")
            opts = job.get("opts", {})
            future = job.get("future")
            
            if job_id:
                js.update_job(job_id, status=js.JobStatus.RUNNING)
            
            scanner = AsyncPortScanner(
                timeout=opts.get("timeout", 3.0),
                rate_preset=opts.get("rate_preset", "normal"),
                rate_pps=opts.get("rate_pps")
            )
            
            result = await scanner.scan(target, port_range)
            
            if job_id:
                js.update_job(
                    job_id,
                    status=js.JobStatus.COMPLETED,
                    result={
                        "open_ports": [
                            {"port": p.port, "state": p.state, "service": str(p.service)}
                            for p in result.open_ports
                        ],
                        "metrics": result.metrics
                    }
                )
            
            if future and not future.done():
                future.set_result(result)
            
        except asyncio.CancelledError:
            break
        except Exception as e:
            print(f"[Worker {worker_id}] Error: {e}")
            if job_id:
                js.update_job(job_id, status=js.JobStatus.FAILED, error=str(e))
            if future and not future.done():
                future.set_exception(e)
        finally:
            try:
                scan_queue.task_done()
            except ValueError:
                pass
    
    print(f"[Worker {worker_id}] Stopped")


class WorkerPool:
    """Manages a pool of scan workers."""
    
    def __init__(self, count: int = WORKER_COUNT):
        self._count = count
        self._workers: list = []
        self._running = False
    
    async def start(self):
        """Start all workers."""
        if self._running:
            return
            
        self._running = True
        self._workers = []
        
        for i in range(self._count):
            task = asyncio.create_task(worker(i))
            self._workers.append(task)
        
        print(f"[WorkerPool] Started {self._count} workers")
    
    async def stop(self):
        """Stop all workers gracefully."""
        if not self._running:
            return
            
        self._running = False
        
        for _ in range(self._count):
            scan_queue.put_nowait(None)
        
        await asyncio.gather(*self._workers, return_exceptions=True)
        self._workers.clear()
        
        print(f"[WorkerPool] Stopped")
    
    @property
    def is_running(self) -> bool:
        return self._running
    
    @property
    def worker_count(self) -> int:
        return self._count


_worker_pool: Optional[WorkerPool] = None


async def get_worker_pool() -> WorkerPool:
    """Get the global worker pool instance."""
    global _worker_pool
    if _worker_pool is None:
        _worker_pool = WorkerPool()
    return _worker_pool


async def start_workers():
    """Start the global worker pool."""
    pool = await get_worker_pool()
    await pool.start()


async def stop_workers():
    """Stop the global worker pool."""
    global _worker_pool
    if _worker_pool:
        await _worker_pool.stop()
        _worker_pool = None