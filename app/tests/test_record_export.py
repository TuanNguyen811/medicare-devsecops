from sqlalchemy import select

from medicare.audit.models import AuditLog
from medicare.auth.models import Role
from tests.conftest import login
from tests.factories import make_department, make_patient, make_record, make_user


def ward(db):
    dept = make_department(db)
    doc = make_user(db, Role.DOCTOR, department=dept)
    patient = make_patient(db, department=dept, attending=doc)
    return dept, doc, patient, make_record(db, patient, doc)


def test_doctor_exports_printable_html(client, db):
    _, doc, patient, record = ward(db)
    login(client, doc)
    r = client.get(f"/records/{record.id}/export")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/html")
    assert f'filename="benh-an-{record.id}-' in r.headers["content-disposition"]
    assert "BỆNH VIỆN ĐA KHOA MEDICARE" in r.text
    assert patient.full_name in r.text and "Viêm đường hô hấp trên cấp" in r.text
    assert patient.national_id not in r.text


def test_export_plain_text_with_letterhead(client, db):
    dept, _, _, record = ward(db)
    login(client, make_user(db, Role.NURSE, department=dept))
    r = client.get(f"/records/{record.id}/export",
                   params={"format": "txt", "letterhead": "phong-kham-ngoai-gio.txt"})
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/plain")
    assert r.text.startswith("BỆNH VIỆN ĐA KHOA MEDICARE\nPHÒNG KHÁM NGOÀI GIỜ")
    assert f"PHIẾU KHÁM BỆNH #{record.id}" in r.text and "J06.9" in r.text


def test_unknown_format_falls_back_to_html(client, db):
    _, doc, _, record = ward(db)
    login(client, doc)
    r = client.get(f"/records/{record.id}/export", params={"format": "docx"})
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/html")


def test_patient_exports_own_record(client, db):
    _, _, patient, record = ward(db)
    login(client, make_user(db, Role.PATIENT, patient=patient))
    r = client.get(f"/records/{record.id}/export", params={"format": "txt"})
    assert r.status_code == 200 and patient.full_name in r.text


def test_export_is_audited(client, db):
    _, doc, _, record = ward(db)
    login(client, doc)
    client.get(f"/records/{record.id}/export")
    rows = list(db.scalars(select(AuditLog).where(AuditLog.action == "EXPORT_RECORD")))
    assert len(rows) == 1 and rows[0].entity_id == record.id and rows[0].actor_id == doc.id


def test_reception_and_admin_cannot_export(client, db):
    _, _, _, record = ward(db)
    for role in (Role.RECEPTIONIST, Role.ADMIN):
        client.cookies.clear()
        login(client, make_user(db, role))
        assert client.get(f"/records/{record.id}/export").status_code == 403


def test_export_missing_record_404(client, db):
    _, doc, _, _ = ward(db)
    login(client, doc)
    assert client.get("/records/999999/export").status_code == 404


def test_record_page_offers_export_form(client, db):
    _, doc, _, record = ward(db)
    login(client, doc)
    html = client.get(f"/records/{record.id}").text
    assert f'action="/records/{record.id}/export"' in html
    assert 'value="benh-vien.txt"' in html and 'value="phong-kham-ngoai-gio.txt"' in html
