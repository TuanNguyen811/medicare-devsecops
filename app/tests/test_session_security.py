"""Session revocation and brute-force counter integrity (Task 3 review findings)."""

from datetime import UTC, datetime

from fastapi.testclient import TestClient
from sqlalchemy import event

from medicare.auth.models import Role
from medicare.common import auth as auth_module
from medicare.common.auth import authenticate
from tests.conftest import csrf_token, login
from tests.factories import TEST_PASSWORD, make_patient, make_user


def _second_client(app, client) -> TestClient:
    """Another browser holding a copy of `client`'s session cookie (e.g. a stolen cookie)."""
    other = TestClient(app, raise_server_exceptions=False)
    other.cookies.update(client.cookies)
    return other


def test_authenticate_locks_user_row_against_concurrent_guesses(db, engine):
    user = make_user(db, Role.NURSE)
    statements: list[str] = []

    def capture(conn, cursor, statement, *args):
        statements.append(statement)

    event.listen(engine, "before_cursor_execute", capture)
    try:
        authenticate(db, user.username, "wrong", datetime.now(UTC))
    finally:
        event.remove(engine, "before_cursor_execute", capture)
    user_selects = [s for s in statements if s.lstrip().upper().startswith("SELECT")
                    and "FROM users" in s]
    assert user_selects and all("FOR UPDATE" in s for s in user_selects)


def test_stolen_cookie_rejected_after_logout(app, client, db):
    login(client, make_user(db, Role.DOCTOR))
    thief = _second_client(app, client)
    assert thief.get("/", follow_redirects=False).status_code == 200
    client.post("/logout", data={"csrf_token": csrf_token(client, "/")})
    assert thief.get("/", follow_redirects=False).status_code == 303


def test_other_sessions_revoked_after_password_change(app, client, db):
    user = make_user(db, Role.NURSE)
    login(client, user)
    other_device = _second_client(app, client)
    r = client.post(
        "/account/password",
        data={
            "current_password": TEST_PASSWORD,
            "new_password": "Brand-new-pass-1",
            "confirm_password": "Brand-new-pass-1",
            "csrf_token": csrf_token(client, "/account/password"),
        },
        follow_redirects=False,
    )
    assert r.status_code == 303
    assert client.get("/", follow_redirects=False).status_code == 200  # current session kept
    assert other_device.get("/", follow_redirects=False).status_code == 303


def test_session_has_absolute_lifetime(app, client, db, monkeypatch):
    login(client, make_user(db, Role.DOCTOR))
    max_age = app.state.settings.session_max_age
    real_now = auth_module._now
    monkeypatch.setattr(auth_module, "_now", lambda: real_now() + max_age + 1)
    assert client.get("/", follow_redirects=False).status_code == 303


def _login_for_shift(client, user, shift):
    r = client.post(
        "/login",
        data={"username": user.username, "password": TEST_PASSWORD, "shift": shift,
              "csrf_token": csrf_token(client)},
        follow_redirects=False,
    )
    assert r.status_code == 303


def test_duty_shift_keeps_session_for_24_hours(app, client, db, monkeypatch):
    _login_for_shift(client, make_user(db, Role.DOCTOR), "24h")
    real_now = auth_module._now
    monkeypatch.setattr(auth_module, "_now", lambda: real_now() + 20 * 3600)
    assert client.get("/", follow_redirects=False).status_code == 200
    monkeypatch.setattr(auth_module, "_now", lambda: real_now() + 24 * 3600 + 1)
    assert client.get("/", follow_redirects=False).status_code == 303


def test_twelve_hour_shift_lifetime(app, client, db, monkeypatch):
    _login_for_shift(client, make_user(db, Role.NURSE), "12h")
    real_now = auth_module._now
    monkeypatch.setattr(auth_module, "_now", lambda: real_now() + 12 * 3600 + 1)
    assert client.get("/", follow_redirects=False).status_code == 303


def test_patient_session_uses_default_lifetime(app, client, db, monkeypatch):
    patient_user = make_user(db, Role.PATIENT, patient=make_patient(db))
    _login_for_shift(client, patient_user, "24h")
    real_now = auth_module._now
    max_age = app.state.settings.session_max_age
    monkeypatch.setattr(auth_module, "_now", lambda: real_now() + max_age + 1)
    assert client.get("/", follow_redirects=False).status_code == 303


def test_expired_session_does_not_query_users(app, client, db, engine, monkeypatch):
    login(client, make_user(db, Role.DOCTOR))
    real_now = auth_module._now
    max_age = app.state.settings.session_max_age
    monkeypatch.setattr(auth_module, "_now", lambda: real_now() + max_age + 1)
    statements: list[str] = []

    def capture(conn, cursor, statement, *args):
        statements.append(statement)

    event.listen(engine, "before_cursor_execute", capture)
    try:
        assert client.get("/", follow_redirects=False).status_code == 303
    finally:
        event.remove(engine, "before_cursor_execute", capture)
    assert not any("FROM users" in s for s in statements)
