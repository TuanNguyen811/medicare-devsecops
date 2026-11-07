from fastapi import FastAPI

from medicare.config import Settings
from medicare.db import create_db


def create_app(settings: Settings | None = None) -> FastAPI:
    if settings is None:
        settings = Settings()
    app = FastAPI(
        title="MediCare HMS", docs_url=None, redoc_url=None, openapi_url=None
    )
    app.state.settings = settings
    app.state.engine, app.state.session_factory = create_db(settings.database_url)
    app.state.engine, app.state.session_factory = create_db(settings.database_url)

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    return app
