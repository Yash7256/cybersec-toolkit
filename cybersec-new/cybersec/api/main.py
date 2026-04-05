"""
FastAPI application main entry point.
"""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from cybersec.config import settings

# Import routers (they are stubs for now)
from cybersec.api.routers import auth, scans, tools, ai, reports, webapp

def create_app() -> FastAPI:
    app = FastAPI(title=settings.APP_NAME)

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins_list,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # API Routes
    app.include_router(auth.router, prefix="/api/auth", tags=["auth"])
    app.include_router(scans.router, prefix="/api/scans", tags=["scans"])
    app.include_router(tools.router, prefix="/api/tools", tags=["tools"])
    app.include_router(ai.router, prefix="/api/ai", tags=["ai"])
    app.include_router(reports.router, prefix="/api/reports", tags=["reports"])
    app.include_router(webapp.router, prefix="/api/webapp", tags=["webapp"])

    @app.get("/api/health", tags=["health"])
    async def health_check():
        return {"status": "ok", "app": settings.APP_NAME}

    # Mount static files at the root
    # Note: the directory 'cybersec/web/static' handles the static site
    # This must be mounted last so it doesn't mask API routes
    try:
        app.mount("/", StaticFiles(directory="cybersec/web/static", html=True), name="static")
    except RuntimeError:
        pass # Handle case where directory may not exist yet in tests/init

    return app

app = create_app()

# TODO: implement additional startup/shutdown events
