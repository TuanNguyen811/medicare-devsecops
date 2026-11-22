import pytest

from medicare.auth.models import Role
from tests.conftest import csrf_token, login
from tests.factories import make_department, make_patient, make_user


def save_profile(client, **fields):
    data = {"full_name": "Nguyễn Văn An", "phone": ""} | fields
    data["csrf_token"] = csrf_token(client, "/account/profile")
    return client.post("/account/profile", data=data, follow_redirects=False)


@pytest.mark.parametrize("role", list(Role))
def test_every_role_can_edit_own_profile(client, db, role):
    kwargs = {}
    if role in (Role.DOCTOR, Role.NURSE):
        kwargs["department"] = make_department(db)
    if role == Role.PATIENT:
        kwargs["patient"] = make_patient(db)
    user = make_user(db, role, **kwargs)
    login(client, user)
    r = save_profile(client, full_name="  Trần Thị Bình ", phone="0912345678")
    assert r.status_code == 303 and r.headers["location"] == "/account/profile"
    db.refresh(user)
    assert user.full_name == "Trần Thị Bình" and user.phone == "0912345678"
    assert "Trần Thị Bình" in client.get("/").text


def test_profile_page_shows_current_values(client, db):
    user = make_user(db, Role.RECEPTIONIST)
    user.phone = "0987654321"
    db.flush()
    login(client, user)
    html = client.get("/account/profile").text
    assert user.full_name in html and "0987654321" in html and user.username in html


def test_blank_phone_clears_it(client, db):
    user = make_user(db, Role.NURSE, department=make_department(db))
    user.phone = "0987654321"
    db.flush()
    login(client, user)
    assert save_profile(client, full_name=user.full_name, phone=" ").status_code == 303
    db.refresh(user)
    assert user.phone is None


@pytest.mark.parametrize("fields", [{"full_name": ""}, {"phone": "12345"},
                                    {"full_name": "x" * 101}])
def test_invalid_profile_rejected(client, db, fields):
    user = make_user(db, Role.RECEPTIONIST)
    name = user.full_name
    login(client, user)
    assert save_profile(client, **fields).status_code == 400
    db.refresh(user)
    assert user.full_name == name and user.phone is None


def test_profile_requires_login_and_csrf(client, db):
    assert client.get("/account/profile", follow_redirects=False).status_code == 303
    login(client, make_user(db, Role.RECEPTIONIST))
    r = client.post("/account/profile", data={"full_name": "Lê Văn C"})
    assert r.status_code == 403


def test_profile_link_in_account_menu(client, db):
    login(client, make_user(db, Role.DOCTOR, department=make_department(db)))
    assert 'href="/account/profile"' in client.get("/").text
