from sqlalchemy import select

from medicare.auth.models import Role
from medicare.department.models import Department
from tests.conftest import csrf_token, login
from tests.factories import make_department, make_user


def post(client, path, **data):
    data["csrf_token"] = csrf_token(client, "/admin/departments")
    return client.post(path, data=data, follow_redirects=False)


def test_admin_creates_department(client, db):
    make_department(db, "NOI")
    login(client, make_user(db, Role.ADMIN))
    assert "Khoa NOI" in client.get("/admin/departments").text
    r = post(client, "/admin/departments", code="mat", name="Khoa Mắt", description="Nhãn khoa")
    assert r.status_code == 303
    dept = db.scalar(select(Department).where(Department.code == "MAT"))
    assert (dept.name, dept.description) == ("Khoa Mắt", "Nhãn khoa")
    assert 'href="/admin/departments"' in client.get("/").text


def test_create_rejects_invalid_or_duplicate(client, db):
    make_department(db, "NOI")
    login(client, make_user(db, Role.ADMIN))
    assert post(client, "/admin/departments", code="NOI", name="Khoa khác").status_code == 400
    assert post(client, "/admin/departments", code="NOI2", name="khoa noi").status_code == 400
    assert post(client, "/admin/departments", code="X", name="Khoa X").status_code == 400
    assert post(client, "/admin/departments", code="DAI", name="Khoa Dài",
                description="x" * 501).status_code == 400


def test_admin_edits_department(client, db):
    make_department(db, "NOI")
    dept = make_department(db, "NHI")
    login(client, make_user(db, Role.ADMIN))
    assert "Khoa NHI" in client.get(f"/admin/departments/{dept.id}/edit").text
    r = post(client, f"/admin/departments/{dept.id}/edit", name="Khoa NOI")
    assert r.status_code == 400 and "Tên khoa đã tồn tại" in r.text
    r = post(client, f"/admin/departments/{dept.id}/edit", name="Khoa Nhi", description="Trẻ em")
    assert r.status_code == 303
    db.refresh(dept)
    assert (dept.code, dept.name, dept.description) == ("NHI", "Khoa Nhi", "Trẻ em")
    assert client.get("/admin/departments/999999/edit").status_code == 404


def test_non_admin_cannot_manage_departments(client, db):
    dept = make_department(db)
    login(client, make_user(db, Role.DOCTOR, department=dept))
    assert client.get("/admin/departments").status_code == 403
    r = client.post(f"/admin/departments/{dept.id}/edit",
                    data={"name": "Khoa mới", "csrf_token": csrf_token(client, "/")})
    assert r.status_code == 403
    db.refresh(dept)
    assert dept.name == "Khoa NOI"
