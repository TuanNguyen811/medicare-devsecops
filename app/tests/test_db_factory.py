from unittest.mock import patch

from medicare import main
from medicare.config import Settings
from medicare.db import create_db, get_db
from medicare.main import create_app

URL = "postgresql+psycopg://u:p@h/db"


def test_create_app_builds_engine_once():
    with patch.object(main, "create_db", wraps=create_db) as spy:
        app = create_app(Settings(env="test", database_url=URL, secret_key="x" * 32))
    assert spy.call_count == 1
    app.state.engine.dispose()


def test_engine_hides_parameters_and_get_db_uses_app_engine():
    app = create_app(Settings(env="test", database_url=URL, secret_key="x" * 32))
    assert app.state.engine.hide_parameters is True

    class Req:
        pass

    req = Req()
    req.app = app
    gen = get_db(req)  # type: ignore[arg-type]
    session = next(gen)
    assert session.get_bind() is app.state.engine
    gen.close()
    app.state.engine.dispose()
