from contextlib import asynccontextmanager
from pathlib import Path
from typing import AsyncGenerator

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

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

    app.include_router(auth.router)
    app.include_router(scans.router)
    app.include_router(tools.router)
    app.include_router(reports.router)
    app.include_router(ai.router)

    # Mount static files
    static_path = Path("/home/yash/cybersec/public")
    if static_path.exists():
        app.mount(
            "/", StaticFiles(directory=str(static_path), html=True), name="static"
        )
        app.mount("/static", StaticFiles(directory=str(static_path)), name="assets")

    return app


app = create_app()


@app.get("/health")
async def health_check() -> dict[str, str]:
    return {"status": "ok"}
