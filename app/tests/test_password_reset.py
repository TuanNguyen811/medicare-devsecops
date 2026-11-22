import hashlib
import logging
import re

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from medicare.auth.models import PasswordResetToken, Role, User
from medicare.common import mailer
from medicare.common.passwords import verify_password
from tests.conftest import csrf_token, login
from tests.factories import make_department, make_user

NEW_PASSWORD = "Moi-mat-khau-2024"


@pytest.fixture(autouse=True)
def empty_outbox():
    mailer.outbox.clear()
    yield
    mailer.outbox.clear()


def user_with_email(db, email="nv.an@medicare.local"):
    user = make_user(db, Role.NURSE, department=make_department(db))
    user.email = email
    db.flush()
    return user


def request_link(client, email):
    data = {"email": email, "csrf_token": csrf_token(client, "/forgot-password")}
    return client.post("/forgot-password", data=data, follow_redirects=False)


def token_from_mail() -> str:
    m = re.search(r"/reset-password\?token=([A-Za-z0-9_-]+)", mailer.outbox[-1].body)
    assert m
    return m.group(1)


def set_password(client, token, new=NEW_PASSWORD, confirm=None):
    data = {"token": token, "new_password": new,
            "confirm_password": new if confirm is None else confirm,
            "csrf_token": csrf_token(client, "/forgot-password")}
    return client.post("/reset-password", data=data, follow_redirects=False)


def test_login_page_links_to_forgot_password(client):
    assert 'href="/forgot-password"' in client.get("/login").text


def test_reset_link_is_mailed_to_account_email(client, db):
    user = user_with_email(db)
    r = request_link(client, "  NV.An@medicare.local ")
    assert r.status_code == 303 and r.headers["location"] == "/login"
    mail = mailer.outbox[-1]
    assert mail.to == user.email and mail.subject == "Đặt lại mật khẩu MediCare"
    assert "http://localhost:8000/reset-password?token=" in mail.body


def test_token_is_random_and_stored_hashed(client, db):
    user = user_with_email(db)
    request_link(client, user.email)
    request_link(client, user.email)
    first, second = re.findall(r"token=([A-Za-z0-9_-]+)", " ".join(m.body for m in mailer.outbox))
    assert first != second and len(first) >= 43
    stored = db.scalars(select(PasswordResetToken.token_hash)
                        .where(PasswordResetToken.user_id == user.id)).all()
    assert hashlib.sha256(first.encode()).hexdigest() in stored and first not in stored


def test_reset_password_with_mailed_link(app, client, db):
    user = user_with_email(db)
    request_link(client, user.email)
    token = token_from_mail()
    page = client.get(f"/reset-password?token={token}")
    assert page.status_code == 200 and 'name="new_password"' in page.text
    r = set_password(client, token)
    assert r.status_code == 303 and r.headers["location"] == "/login"
    db.refresh(user)
    assert verify_password(user.password_hash, NEW_PASSWORD)
    fresh = TestClient(app, raise_server_exceptions=False)
    r = fresh.post("/login", data={"username": user.username, "password": NEW_PASSWORD,
                                   "csrf_token": csrf_token(fresh)}, follow_redirects=False)
    assert r.status_code == 303


def test_reset_signs_out_existing_sessions(app, client, db):
    user = user_with_email(db)
    other = TestClient(app, raise_server_exceptions=False)
    login(other, user)
    assert other.get("/").status_code == 200
    request_link(client, user.email)
    set_password(client, token_from_mail())
    r = other.get("/", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/login"


def test_new_password_rules_apply(client, db):
    user = user_with_email(db)
    request_link(client, user.email)
    token = token_from_mail()
    r = set_password(client, token, new="short")
    assert r.status_code == 200 and "ít nhất 10 ký tự" in r.text
    r = set_password(client, token, confirm="Khac-mat-khau-2024")
    assert r.status_code == 200 and "Mật khẩu xác nhận không khớp" in r.text
    db.refresh(user)
    assert not verify_password(user.password_hash, NEW_PASSWORD)


def test_unknown_token_is_rejected(client, db):
    r = client.get("/reset-password?token=abc")
    assert r.status_code == 400 and "không hợp lệ hoặc đã hết hạn" in r.text
    assert set_password(client, "abc").status_code == 400
    assert client.get("/reset-password").status_code == 400


def test_forgot_password_requires_csrf(client, db):
    user_with_email(db)
    r = client.post("/forgot-password", data={"email": "nv.an@medicare.local"})
    assert r.status_code == 403 and not mailer.outbox


def test_reset_link_never_logged(client, db, caplog):
    user = user_with_email(db)
    with caplog.at_level(logging.DEBUG):
        request_link(client, user.email)
    token = token_from_mail()
    assert token not in caplog.text and user.email not in caplog.text


def test_admin_sets_account_email(client, db):
    login(client, make_user(db, Role.ADMIN))
    data = {"username": "letan.moi", "full_name": "Lễ tân Mới", "role": "RECEPTIONIST",
            "email": "LeTan.Moi@MediCare.local", "department_id": "", "patient_id": "",
            "password": NEW_PASSWORD, "csrf_token": csrf_token(client, "/admin/users")}
    assert client.post("/admin/users", data=data, follow_redirects=False).status_code == 303
    created = db.scalar(select(User).where(User.username == "letan.moi"))
    assert created.email == "letan.moi@medicare.local"
    r = client.post("/admin/users", data=data | {"username": "letan.hai"})
    assert r.status_code == 400 and "Email đã được dùng" in r.text
    r = client.post("/admin/users", data=data | {"username": "letan.ba", "email": "khong-hop-le"})
    assert r.status_code == 400 and "Email: không đúng định dạng" in r.text
