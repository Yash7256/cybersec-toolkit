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

# Import routers (they are stubs for now)
from cybersec.api.routers import auth, scans, tools, ai, reports, webapp

@asynccontextmanager
async def lifespan(app: FastAPI):
    try:
        from cybersec.database.session import init_db
        await init_db()
        print("Database tables initialized successfully")
    except Exception as e:
        print(f"Database init warning: {e}")
    yield

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
    app.include_router(scans.router, prefix="/api/scans")
    app.include_router(tools.router, prefix="/api/tools")
    app.include_router(ai.router, prefix="/api/ai", tags=["ai"])
    app.include_router(reports.router, prefix="/api/reports", tags=["reports"])
    app.include_router(webapp.router, prefix="/api/webapp", tags=["webapp"])

    @app.get("/api/health", tags=["health"])
    async def health_check():
        return {"status": "ok", "app": settings.APP_NAME}

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
