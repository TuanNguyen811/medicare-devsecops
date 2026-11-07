import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from medicare.config import Settings
from medicare.main import create_app

KEY = "x" * 32

def test_health_ok():
    app = create_app(Settings(env="test", database_url="postgresql+psycopg://u:p@h/db", secret_key=KEY))
    r = TestClient(app).get("/health")
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}

def test_settings_require_secret_key(monkeypatch):
    monkeypatch.delenv("SECRET_KEY", raising=False)
    with pytest.raises(ValidationError):
        Settings(database_url="postgresql+psycopg://u:p@h/db")

def test_secret_key_min_length():
    with pytest.raises(ValidationError):
        Settings(database_url="postgresql+psycopg://u:p@h/db", secret_key="short")
