import csv
import io

from sqlalchemy import select

from medicare.audit.models import AuditLog
from medicare.auth.models import Role
from tests.conftest import login
from tests.factories import make_department, make_patient, make_user


def read_csv(response) -> list[list[str]]:
    assert response.content.startswith(b"\xef\xbb\xbf")
    return list(csv.reader(io.StringIO(response.content.decode("utf-8-sig"))))


def test_receptionist_exports_patient_list(client, db):
    dept = make_department(db)
    doc = make_user(db, Role.DOCTOR, department=dept)
    p = make_patient(db, department=dept, attending=doc)
    login(client, make_user(db, Role.RECEPTIONIST))
    r = client.get("/patients/export")
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/csv")
    assert r.headers["content-disposition"].startswith('attachment; filename="benh-nhan-')
    rows = read_csv(r)
    assert rows[0][:5] == ["Mã BN", "Họ tên", "Ngày sinh", "Giới tính", "CCCD"]
    row = next(row for row in rows if row[0] == p.code)
    assert row == [p.code, p.full_name, "01/01/1990", "Nam", p.national_id, p.insurance_number,
                   p.phone, "Hà Nội", dept.name, doc.full_name]


def test_export_follows_search_filter(client, db):
    p = make_patient(db)
    other = make_patient(db)
    login(client, make_user(db, Role.ADMIN))
    codes = [row[0] for row in read_csv(client.get(f"/patients/export?q={p.code}"))[1:]]
    assert codes == [p.code] and other.code not in codes


def test_patient_without_insurance_exports_empty_cell(client, db):
    p = make_patient(db, insurance_number=None)
    login(client, make_user(db, Role.RECEPTIONIST))
    rows = read_csv(client.get(f"/patients/export?q={p.code}"))
    assert rows[1][5] == ""


def test_each_export_is_audited(client, db):
    a, b = make_patient(db), make_patient(db)
    user = make_user(db, Role.RECEPTIONIST)
    login(client, user)
    client.get("/patients/export")
    logged = db.scalars(select(AuditLog.entity_id).where(
        AuditLog.actor_id == user.id, AuditLog.action == "EXPORT_PATIENT",
        AuditLog.entity_type == "patient")).all()
    assert {a.id, b.id} <= set(logged)


def test_export_link_on_patient_list(client, db):
    login(client, make_user(db, Role.RECEPTIONIST))
    assert 'href="/patients/export?q=Nguy%E1%BB%85n"' in client.get("/patients?q=Nguyễn").text


def test_patient_role_cannot_export(client, db):
    me = make_patient(db)
    login(client, make_user(db, Role.PATIENT, patient=me))
    assert client.get("/patients/export").status_code == 403


def test_export_requires_login(client):
    r = client.get("/patients/export", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/login"
