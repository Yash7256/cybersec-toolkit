from contextlib import asynccontextmanager
from pathlib import Path
from typing import AsyncGenerator

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

from cybersec.api.routers import auth, scans, tools, reports, ai
from cybersec.config import get_settings


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    yield


def create_app() -> FastAPI:
    settings = get_settings()

    app = FastAPI(
        title=settings.api.name,
        debug=settings.api.debug,
        lifespan=lifespan,
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors.origins_list,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Mount static files - relative to package location
    static_path = Path(__file__).parent.parent / "web" / "static"
    if static_path.exists():
        app.mount("/static", StaticFiles(directory=str(static_path)), name="assets")

        @app.get("/")
        @app.get("/{path:path}")
        async def serve_spa(path: str = ""):
            index_path = static_path / "index.html"
            if index_path.exists():
                return FileResponse(str(index_path))

    # Add /api prefix to all routers
    app.include_router(auth.router, prefix="/api")
    app.include_router(scans.router, prefix="/api")
    app.include_router(tools.router, prefix="/api")
    app.include_router(reports.router, prefix="/api")
    app.include_router(ai.router, prefix="/api")

    return app


app = create_app()


@app.get("/health")
async def health_check() -> dict[str, str]:
    return {"status": "ok"}
