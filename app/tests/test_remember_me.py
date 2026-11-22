import hashlib
from datetime import UTC, datetime, timedelta

from fastapi.testclient import TestClient
from sqlalchemy import select

from medicare.auth.models import RememberToken, Role
from medicare.auth.remember import COOKIE
from tests.conftest import csrf_token, login
from tests.factories import TEST_PASSWORD, make_user


def login_remembered(client, user):
    return client.post(
        "/login",
        data={
            "username": user.username,
            "password": TEST_PASSWORD,
            "remember_me": "on",
            "csrf_token": csrf_token(client),
        },
        follow_redirects=False,
    )


def new_browser(app, remember_value) -> TestClient:
    """The same machine on a later day: only the long-lived cookie is left."""
    browser = TestClient(app, raise_server_exceptions=False)
    browser.cookies.set(COOKIE, remember_value)
    return browser


def test_login_page_offers_remember_me(client):
    assert 'name="remember_me"' in client.get("/login").text


def test_remember_me_sets_long_lived_httponly_cookie(client, db):
    r = login_remembered(client, make_user(db, Role.DOCTOR))
    assert r.status_code == 303
    cookie = next(c for c in r.headers.get_list("set-cookie") if c.startswith(COOKIE))
    assert "httponly" in cookie.lower() and "samesite=lax" in cookie.lower()
    assert "max-age=2592000" in cookie.lower()


def test_plain_login_sets_no_remember_cookie(client, db):
    login(client, make_user(db, Role.DOCTOR))
    assert COOKIE not in client.cookies


def test_only_token_hash_is_stored(client, db):
    user = make_user(db, Role.NURSE)
    login_remembered(client, user)
    raw = client.cookies[COOKIE]
    token = db.scalar(select(RememberToken).where(RememberToken.user_id == user.id))
    assert token.token_hash == hashlib.sha256(raw.encode()).hexdigest() != raw


def test_remembered_browser_is_signed_in_again(app, client, db):
    user = make_user(db, Role.DOCTOR)
    login_remembered(client, user)
    browser = new_browser(app, client.cookies[COOKIE])
    r = browser.get("/", follow_redirects=False)
    assert r.status_code == 200 and user.full_name in r.text


def test_expired_remember_token_is_rejected(app, client, db):
    user = make_user(db, Role.DOCTOR)
    login_remembered(client, user)
    token = db.scalar(select(RememberToken).where(RememberToken.user_id == user.id))
    token.expires_at = datetime.now(UTC) - timedelta(minutes=1)
    db.flush()
    browser = new_browser(app, client.cookies[COOKIE])
    assert browser.get("/", follow_redirects=False).status_code == 303


def test_password_change_forgets_other_browsers(app, client, db):
    user = make_user(db, Role.NURSE)
    login_remembered(client, user)
    browser = new_browser(app, client.cookies[COOKIE])
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
    assert browser.get("/", follow_redirects=False).status_code == 303


def test_deactivated_account_is_not_remembered(app, client, db):
    user = make_user(db, Role.DOCTOR)
    login_remembered(client, user)
    browser = new_browser(app, client.cookies[COOKIE])
    user.is_active = False
    db.flush()
    assert browser.get("/", follow_redirects=False).status_code == 303
