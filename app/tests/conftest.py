import os
import re
from pathlib import Path

# Testcontainers reads these at import time, so they must be set before it is imported.
# Ryuk (the reaper container) is unreliable on Windows Docker Desktop; the session fixture
# below stops the container through its context manager, so the reaper is not needed.
os.environ.setdefault("TESTCONTAINERS_RYUK_DISABLED", "true")
# On Windows "localhost" can resolve to ::1 first, where Docker Desktop port mappings hang.
os.environ.setdefault("TESTCONTAINERS_HOST_OVERRIDE", "127.0.0.1")

import pytest
from alembic import command
from alembic.config import Config
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from testcontainers.community.postgres import PostgresContainer

from medicare.config import Settings
from medicare.db import get_db
from medicare.main import create_app
from tests.factories import TEST_PASSWORD

APP_DIR = Path(__file__).resolve().parent.parent


@pytest.fixture(scope="session")
def database_url():
    with PostgresContainer("postgres:16-alpine", driver="psycopg") as pg:
        yield pg.get_connection_url()


@pytest.fixture(scope="session")
def engine(database_url):
    cfg = Config(str(APP_DIR / "alembic.ini"))
    cfg.set_main_option("script_location", str(APP_DIR / "migrations"))
    cfg.set_main_option("sqlalchemy.url", database_url.replace("%", "%%"))
    command.upgrade(cfg, "head")
    eng = create_engine(database_url)
    yield eng
    eng.dispose()


@pytest.fixture
def db(engine):
    conn = engine.connect()
    trans = conn.begin()
    session = Session(bind=conn, join_transaction_mode="create_savepoint")
    yield session
    session.close()
    trans.rollback()
    conn.close()


@pytest.fixture
def app(db, database_url):
    application = create_app(
        Settings(env="test", database_url=database_url, secret_key="x" * 32)
    )
    application.dependency_overrides[get_db] = lambda: db
    yield application
    application.state.engine.dispose()


@pytest.fixture
def client(app):
    return TestClient(app, raise_server_exceptions=False)


def csrf_token(client, path="/login") -> str:
    html = client.get(path).text
    m = re.search(r'<meta name="csrf-token" content="([^"]+)"', html)
    assert m, f"no csrf-token meta tag on {path}"
    return m.group(1)


def login(client, user) -> None:
    r = client.post(
        "/login",
        data={
            "username": user.username,
            "password": TEST_PASSWORD,
            "csrf_token": csrf_token(client),
        },
        follow_redirects=False,
    )
    assert r.status_code == 303
