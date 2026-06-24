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
from cybersec.apps.api.routes import auth, tools, ai, reports, webapp
from cybersec.runtime.scan_workers import start_workers, stop_workers

@asynccontextmanager
async def lifespan(app: FastAPI):
    from cybersec.database.session import init_db
    import asyncio
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
    
    # ── Scan state safety check ─────────────────────────────────────
    from cybersec.config import settings
    from cybersec.core.redis_client import get_shared_redis_client
    if settings.WORKERS > 1:
        r = get_shared_redis_client()
        if r is None:
            logger.critical(
                "Running with multiple workers but Redis is unavailable — "
                "scan quota enforcement will NOT work correctly across "
                "workers. Fix Redis connectivity before scaling beyond 1 worker."
            )
    
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
    
    # Close shared Redis client
    try:
        from cybersec.core.redis_client import close_shared_redis_client
        await close_shared_redis_client()
        logger.info("Shared Redis client closed")
    except Exception as e:
        logger.warning("Failed to close Redis client: %s", e)

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

    # Mount React frontend (Vite build output).
    # Run `npm run build` inside cybersec/web/ui before starting, or let
    # the Dockerfile handle it via `RUN cd cybersec/web/ui && npm run build`.
    import os
    from fastapi.responses import FileResponse, PlainTextResponse
    from fastapi.staticfiles import StaticFiles

    from cybersec.core.tools.subdomain import SCREENSHOT_DIR

    os.makedirs(SCREENSHOT_DIR, exist_ok=True)
    app.mount("/screenshots", StaticFiles(directory=SCREENSHOT_DIR), name="screenshots")

    from pathlib import Path
    
    current_dir = Path(__file__).resolve().parent
    react_dist = current_dir.parent.parent / "web" / "ui" / "dist"
    react_public = current_dir.parent.parent / "web" / "ui" / "public"
    favicon_candidates = [
        react_dist / "favicon.ico",
        react_public / "favicon.ico",
        react_dist / "assets" / "logo.svg",
        react_public / "assets" / "logo.svg",
    ]

    def _favicon_path() -> Path | None:
        return next((path for path in favicon_candidates if path.is_file()), None)

    @app.get("/favicon.ico", include_in_schema=False)
    @app.get("/favicon.svg", include_in_schema=False)
    async def favicon():
        icon = _favicon_path()
        if icon:
            media_type = "image/x-icon" if icon.suffix.lower() == ".ico" else "image/svg+xml"
            return FileResponse(str(icon), media_type=media_type)
        return PlainTextResponse("", status_code=204)

    if not react_dist.is_dir():
        import logging
        logging.getLogger("startup").warning(
            "React dist not found at %s — run `npm run build` inside cybersec/web/ui", react_dist
        )
    else:
        # Serve all static assets (JS/CSS/images) under /assets
        app.mount(
            "/assets",
            StaticFiles(directory=str(react_dist / "assets")),
            name="assets",
        )

        # Serve the React SPA index.html for every non-API route
        @app.get("/{full_path:path}", include_in_schema=False)
        async def serve_react(full_path: str):
            index = str(react_dist / "index.html")
            return FileResponse(index, headers={"Cache-Control": "no-cache"})

    return app


app = create_app()

# TODO: implement additional startup/shutdown events
