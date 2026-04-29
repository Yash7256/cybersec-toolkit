"""
Core security logic (scanner, OS fingerprinting, etc.)
"""
from cybersec.core.scan_queue import scan_queue, get_queue_stats, enqueue_scan, dequeue_scan
from cybersec.core.scan_workers import WorkerPool, get_worker_pool, start_workers, stop_workers
from cybersec.core import job_store
