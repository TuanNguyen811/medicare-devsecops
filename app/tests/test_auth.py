
from medicare.auth.models import Role
from tests.conftest import csrf_token, login
from tests.factories import TEST_PASSWORD, make_user

GENERIC = "Tên đăng nhập hoặc mật khẩu không đúng"


def test_login_success_redirects_home(client, db):
    u = make_user(db, Role.DOCTOR)
    login(client, u)
    assert client.get("/").status_code == 200


def test_login_wrong_password_generic_message(client, db):
    u = make_user(db, Role.DOCTOR)
    r = client.post(
        "/login",
        data={"username": u.username, "password": "bad", "csrf_token": csrf_token(client)},
    )
    assert r.status_code == 200 and GENERIC in r.text


def test_unknown_user_same_message(client):
    r = client.post(
        "/login",
        data={"username": "nobody", "password": "x", "csrf_token": csrf_token(client)},
    )
    assert GENERIC in r.text


def test_lockout_after_five_failures(client, db):
    u = make_user(db, Role.NURSE)
    for _ in range(5):
        client.post(
            "/login",
            data={"username": u.username, "password": "bad", "csrf_token": csrf_token(client)},
        )
    r = client.post(
        "/login",
        data={
            "username": u.username,
            "password": TEST_PASSWORD,
            "csrf_token": csrf_token(client),
        },
        follow_redirects=False,
    )
    assert r.status_code == 200  # still rejected even with the right password


def test_post_without_csrf_is_403(client, db):
    u = make_user(db, Role.DOCTOR)
    r = client.post("/login", data={"username": u.username, "password": TEST_PASSWORD})
    assert r.status_code == 403


def test_anonymous_html_redirects_and_api_401(client):
    assert client.get("/", follow_redirects=False).headers["location"] == "/login"
    assert client.get("/api/v1/appointments").status_code == 401


def test_anonymous_html_redirects_to_login(client):
    r = client.get("/", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/login"


def test_deactivated_user_session_is_rejected(client, db):
    u = make_user(db, Role.DOCTOR)
    login(client, u)
    u.is_active = False
    db.flush()
    assert client.get("/", follow_redirects=False).status_code == 303


def test_session_cookie_flags(client, db):
    u = make_user(db, Role.DOCTOR)
    r = client.post(
        "/login",
        data={
            "username": u.username,
            "password": TEST_PASSWORD,
            "csrf_token": csrf_token(client),
        },
        follow_redirects=False,
    )
    cookie = r.headers["set-cookie"].lower()
    assert "httponly" in cookie and "samesite=lax" in cookie


def test_password_hash_is_argon2(db):
    assert make_user(db, Role.ADMIN).password_hash.startswith("$argon2id$")


def test_logout_clears_session(client, db):
    login(client, make_user(db, Role.DOCTOR))
    r = client.post("/logout", data={"csrf_token": csrf_token(client, "/")}, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/login"
    assert client.get("/", follow_redirects=False).status_code == 303


def test_logout_without_csrf_is_403(client, db):
    login(client, make_user(db, Role.DOCTOR))
    assert client.post("/logout").status_code == 403


def test_authenticate_resets_counter_and_inactive_fails(db):
    from datetime import UTC, datetime, timedelta

    from medicare.common.auth import authenticate

    now = datetime.now(UTC)
    u = make_user(db, Role.DOCTOR)
    assert authenticate(db, u.username, "bad", now) is None
    assert u.failed_login_count == 1
    assert authenticate(db, u.username, TEST_PASSWORD, now) is u
    assert u.failed_login_count == 0
    for _ in range(5):
        authenticate(db, u.username, "bad", now)
    assert u.locked_until == now + timedelta(minutes=15)
    assert authenticate(db, u.username, TEST_PASSWORD, now) is None
    assert authenticate(db, u.username, TEST_PASSWORD, now + timedelta(minutes=16)) is u
    u.is_active = False
    assert authenticate(db, u.username, TEST_PASSWORD, now + timedelta(minutes=16)) is None


def test_change_password(client, db):
    u = make_user(db, Role.DOCTOR)
    login(client, u)
    tok = csrf_token(client, "/account/password")
    r = client.post(
        "/account/password",
        data={"current_password": "wrong", "new_password": "NewPassw0rd!!",
              "confirm_password": "NewPassw0rd!!", "csrf_token": tok},
    )
    assert r.status_code == 200 and "Mật khẩu hiện tại không đúng" in r.text
    r = client.post(
        "/account/password",
        data={"current_password": TEST_PASSWORD, "new_password": "short",
              "confirm_password": "short", "csrf_token": tok},
    )
    assert r.status_code == 200 and "ít nhất 10 ký tự" in r.text
    r = client.post(
        "/account/password",
        data={"current_password": TEST_PASSWORD, "new_password": "NewPassw0rd!!",
              "confirm_password": "NewPassw0rd!!", "csrf_token": tok},
        follow_redirects=False,
    )
    assert r.status_code == 303
    db.refresh(u)
    from medicare.common.passwords import verify_password

    assert verify_password(u.password_hash, "NewPassw0rd!!")
