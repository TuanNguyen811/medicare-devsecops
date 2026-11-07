from fastapi import FastAPI

from medicare.config import Settings


def create_app(settings: Settings | None = None) -> FastAPI:
    if settings is None:
        settings = Settings()
    app = FastAPI(title="MediCare HMS")
    app.state.settings = settings

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    return app
