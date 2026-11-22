from sqlalchemy import select

from medicare.audit.models import AuditLog
from medicare.auth.models import Role
from medicare.record.models import SlipTemplate
from tests.conftest import csrf_token, login
from tests.factories import make_department, make_patient, make_record, make_user

CUSTOM = """<h3>KHOA NỘI - PHIẾU KHÁM</h3>
<p>{{ patient.code }} / {{ patient.full_name }}</p>
<p>{{ record.diagnosis_code }}: {{ record.diagnosis_text }}</p>
"""


def ward(db, code="NOI"):
    dept = make_department(db, code)
    doc = make_user(db, Role.DOCTOR, department=dept)
    patient = make_patient(db, department=dept, attending=doc)
    return dept, doc, patient, make_record(db, patient, doc)


def save(client, body):
    data = {"body": body, "csrf_token": csrf_token(client, "/account/print-template")}
    return client.post("/account/print-template", data=data, follow_redirects=False)


def test_default_slip(client, db):
    _, doc, patient, record = ward(db)
    login(client, doc)
    r = client.get(f"/records/{record.id}/print")
    assert r.status_code == 200
    assert "PHIẾU KHÁM BỆNH" in r.text and patient.full_name in r.text
    assert "J06.9 - Viêm đường hô hấp trên cấp" in r.text and "Khoa NOI" in r.text
    assert patient.national_id not in r.text


def test_printing_is_audited(client, db):
    _, doc, _, record = ward(db)
    login(client, doc)
    client.get(f"/records/{record.id}/print")
    rows = list(db.scalars(select(AuditLog).where(AuditLog.action == "VIEW_RECORD",
                                                  AuditLog.entity_id == record.id)))
    assert len(rows) == 1 and rows[0].actor_id == doc.id


def test_doctor_saves_custom_template_and_prints_with_it(client, db):
    _, doc, patient, record = ward(db)
    login(client, doc)
    r = save(client, CUSTOM)
    assert r.status_code == 303 and r.headers["location"] == "/account/print-template"
    assert db.get(SlipTemplate, doc.id).body == CUSTOM
    slip = client.get(f"/records/{record.id}/print").text
    assert "KHOA NỘI - PHIẾU KHÁM" in slip
    assert f"{patient.code} / {patient.full_name}" in slip
    assert "PHIẾU KHÁM BỆNH" not in slip


def test_template_is_per_doctor(client, db):
    dept, doc, _, record = ward(db)
    db.add(SlipTemplate(doctor_id=doc.id, body=CUSTOM))
    db.flush()
    login(client, make_user(db, Role.DOCTOR, department=dept))
    slip = client.get(f"/records/{record.id}/print").text
    assert "PHIẾU KHÁM BỆNH" in slip and "KHOA NỘI - PHIẾU KHÁM" not in slip


def test_empty_template_restores_default(client, db):
    _, doc, _, _ = ward(db)
    db.add(SlipTemplate(doctor_id=doc.id, body=CUSTOM))
    db.flush()
    login(client, doc)
    assert save(client, "   ").status_code == 303
    assert db.get(SlipTemplate, doc.id) is None


def test_template_with_syntax_error_rejected(client, db):
    _, doc, _, _ = ward(db)
    login(client, doc)
    r = save(client, "<p>{{ patient.full_name </p>")
    assert r.status_code == 400 and "sai cú pháp" in r.text
    assert db.get(SlipTemplate, doc.id) is None


def test_settings_page_shows_default_and_variables(client, db):
    _, doc, _, _ = ward(db)
    login(client, doc)
    page = client.get("/account/print-template")
    assert page.status_code == 200 and "Mặc định" in page.text
    assert "patient.full_name" in page.text and "record.diagnosis_code" in page.text
    assert 'href="/account/print-template"' in client.get("/").text


def test_only_doctors_customize(client, db):
    dept, _, _, _ = ward(db)
    for role in (Role.NURSE, Role.RECEPTIONIST, Role.ADMIN):
        client.cookies.clear()
        login(client, make_user(db, role, department=dept))
        assert client.get("/account/print-template").status_code == 403
        r = client.post("/account/print-template",
                        data={"body": CUSTOM, "csrf_token": csrf_token(client, "/")})
        assert r.status_code == 403


def test_print_follows_record_access(client, db):
    _, _, patient, record = ward(db)
    other_doc = make_user(db, Role.DOCTOR, department=make_department(db, "NGOAI"))
    login(client, other_doc)
    assert client.get(f"/records/{record.id}/print").status_code == 404
    client.cookies.clear()
    login(client, make_user(db, Role.PATIENT, patient=patient))
    assert client.get(f"/records/{record.id}/print").status_code == 200
    client.cookies.clear()
    login(client, make_user(db, Role.RECEPTIONIST))
    assert client.get(f"/records/{record.id}/print").status_code == 404
