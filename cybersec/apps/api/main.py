"""
FastAPI application main entry point.
"""
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware

from cybersec.config import settings

# Import routers
from cybersec.apps.api.routes import auth, scan_jobs, scan_results, scan_security, scans, tools, ai, reports, webapp

@asynccontextmanager
async def lifespan(app: FastAPI):
    from cybersec.runtime.scan_workers import start_workers, stop_workers
    from cybersec.database.session import init_db
    import logging
    
    logger = logging.getLogger("lifespan")

    # ── Event loop stall detector ─────────────────────────────────────
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
            if lag > 0.5:
                logger.error("Event loop severely stalled: %.0fms", lag_ms)

    monitor_task = asyncio.create_task(_loop_monitor())
    
    try:
        await init_db()
        logger.info("Database tables initialized")
    except Exception as e:
        logger.warning("Database init: %s", e)
    
    # ── Worker heartbeat + reaper ─────────────────────────────────
    import os
    worker_id = f"api-{os.getpid()}"
    try:
        from cybersec.core.recovery import (
            register_worker, start_reaper, reap_stale_workers,
            unregister_worker, worker_heartbeat,
        )
        await register_worker(worker_id)
        await reap_stale_workers()
        reaper_task = await start_reaper()

        # Worker heartbeat loop (updates own liveness every 30s)
        async def _worker_hb():
            while True:
                await asyncio.sleep(30)
                await worker_heartbeat(worker_id)
    except Exception as e:
        logger.warning("Recovery setup skipped: %s", e)
        reaper_task = None
        _worker_hb = None

    hb_task = asyncio.create_task(_worker_hb()) if _worker_hb else None
    
    await start_workers()
    logger.info("Scan workers started")
    
    yield
    
    if hb_task:
        hb_task.cancel()
        try:
            await hb_task
        except asyncio.CancelledError:
            pass
    if reaper_task:
        reaper_task.cancel()
        try:
            await reaper_task
        except asyncio.CancelledError:
            pass
    try:
        await unregister_worker(worker_id)
    except Exception:
        pass
    
    monitor_task.cancel()
    try:
        await monitor_task
    except asyncio.CancelledError:
        pass
    
    await stop_workers()
    logger.info("Scan workers stopped")

def create_app() -> FastAPI:
    app = FastAPI(
        lifespan=lifespan,
        title="CyberSec Port Scanner API",
        description="""Comprehensive port scanning and network reconnaissance API.
        
        ## Features
        - **Multiple Scan Modes**: TCP connect, SYN, UDP, FIN, NULL, XMAS, ACK, Zombie
        - **Rate Limiting**: Configurable packets per second with presets
        - **Retry Logic**: Exponential backoff with configurable parameters
        - **Service Detection**: Automatic banner grabbing and service identification
        - **OS Fingerprinting**: Passive and active OS detection
        - **Export Formats**: JSON, CSV, HTML output options
        - **Real-time Streaming**: Server-sent events for live scan results
        - **Multi-host Scanning**: CIDR range and multiple target support
        
        ## Authentication
        Most endpoints require authentication via JWT tokens. Use `/api/auth/login` to obtain tokens.
        
        ## Rate Limiting
        API is rate-limited to 100 requests per minute per IP address.
        
        ## Error Handling
        - `400 Bad Request`: Invalid parameters
        - `401 Unauthorized`: Authentication required
        - `404 Not Found`: Resource not found
        - `429 Too Many Requests`: Rate limit exceeded
        - `500 Internal Server Error`: Server error
        - `503 Service Unavailable`: Database unavailable
        """,
        version="2.0.0",
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/openapi.json",
        contact={
            "name": "CyberSec Team",
            "email": "support@cybersec.com",
        },
        license_info={
            "name": "MIT",
            "url": "https://opensource.org/licenses/MIT",
        },
        servers=[
            {
                "url": "http://localhost:8000",
                "description": "Development server"
            },
            {
                "url": "https://api.cybersec.com",
                "description": "Production server"
            }
        ]
    )

    # Rate limiting
    limiter = Limiter(key_func=get_remote_address, default_limits=["100/minute"])
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
    app.add_middleware(SlowAPIMiddleware)

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins_list,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # API Routes
    app.include_router(auth.router, prefix="/api/auth")
    app.include_router(scan_jobs.router, prefix="/api/scans")
    app.include_router(scan_security.router, prefix="/api/scans")
    app.include_router(scan_results.router, prefix="/api/scans")
    app.include_router(scans.router, prefix="/api/scans")
    app.include_router(tools.router, prefix="/api/tools")
    app.include_router(ai.router, prefix="/api/ai", tags=["ai"])
    app.include_router(reports.router, prefix="/api/reports", tags=["reports"])
    app.include_router(webapp.router, prefix="/api/webapp", tags=["webapp"])

    @app.get("/api/health", tags=["health"])
    async def health_check():
        return {"status": "ok", "app": settings.APP_NAME}

    @app.get("/api/metrics", tags=["observability"])
    async def prometheus_metrics():
        from cybersec.core.metrics_registry import registry
        from fastapi.responses import PlainTextResponse
        return PlainTextResponse(registry().dump_prometheus())

    # Mount static files at /static/ path
    # Note: the directory 'cybersec/web/static' handles the static site
    # This must be mounted last so it doesn't mask API routes
    try:
        app.mount("/static", StaticFiles(directory="cybersec/web/static", html=True), name="static")
        # Serve index.html at root
        from fastapi.responses import FileResponse
        import os
        
        @app.get("/", include_in_schema=False)
        async def read_index():
            return FileResponse("cybersec/web/static/index.html")
    except RuntimeError:
        pass # Handle case where directory may not exist yet in tests/init

    return app

app = create_app()

# TODO: implement additional startup/shutdown events
