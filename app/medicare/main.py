from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware

from medicare.auth.router import router as auth_router
from medicare.common.errors import register_error_handlers
from medicare.config import Settings
from medicare.db import create_db

STATIC_DIR = Path(__file__).resolve().parent / "static"


def create_app(settings: Settings | None = None) -> FastAPI:
    if settings is None:
        settings = Settings()
    app = FastAPI(
        title="MediCare HMS", docs_url=None, redoc_url=None, openapi_url=None
    )
    app.state.settings = settings
    app.state.engine, app.state.session_factory = create_db(settings.database_url)

    app.add_middleware(
        SessionMiddleware,
        secret_key=settings.secret_key.get_secret_value(),
        session_cookie="medicare_session",
        max_age=settings.session_max_age,
        same_site="lax",
        https_only=settings.env == "production",
    )
    register_error_handlers(app)
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
    app.include_router(auth_router)

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    return app
