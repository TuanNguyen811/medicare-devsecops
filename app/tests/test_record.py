import logging
from datetime import date

from sqlalchemy import func, select

from medicare.audit.models import AuditLog
from medicare.auth.models import Role
from medicare.record.models import MedicalRecord
from tests.conftest import csrf_token, login
from tests.factories import make_department, make_patient, make_record, make_user

FORM = {
    "visit_date": date.today().isoformat(),
    "symptoms": "Ho kéo dài, sốt",
    "diagnosis_code": "J18.9",
    "diagnosis_text": "Viêm phổi",
    "notes": "Tái khám sau 7 ngày",
}


def ward(db):
    """A department with an attending doctor and one of their patients."""
    dept = make_department(db)
    doc = make_user(db, Role.DOCTOR, department=dept)
    patient = make_patient(db, department=dept, attending=doc)
    return dept, doc, patient


def audit_rows(db, action, entity_id=None):
    stmt = select(AuditLog).where(AuditLog.action == action)
    if entity_id is not None:
        stmt = stmt.where(AuditLog.entity_id == entity_id)
    return list(db.scalars(stmt))


def create(client, patient, **overrides):
    data = FORM | overrides
    data["csrf_token"] = csrf_token(client, f"/patients/{patient.id}/records/new")
    return client.post(f"/patients/{patient.id}/records", data=data, follow_redirects=False)


def test_attending_doctor_creates_record_and_audit_logged(client, db):
    _, doc, patient = ward(db)
    login(client, doc)
    r = create(client, patient)
    assert r.status_code == 303
    rec = db.scalar(select(MedicalRecord).where(MedicalRecord.patient_id == patient.id))
    assert rec is not None and rec.doctor_id == doc.id
    rows = audit_rows(db, "CREATE_RECORD", rec.id)
    assert len(rows) == 1 and rows[0].actor_id == doc.id and rows[0].entity_type == "record"


def test_invalid_icd10_rejected_400(client, db):
    _, doc, patient = ward(db)
    login(client, doc)
    assert create(client, patient, diagnosis_code="not-icd").status_code == 400


def test_view_record_writes_audit_for_html_and_api(client, db):
    _, doc, patient = ward(db)
    rec = make_record(db, patient, doc)
    login(client, doc)
    assert client.get(f"/records/{rec.id}").status_code == 200
    assert client.get(f"/api/v1/records/{rec.id}").status_code == 200
    rows = audit_rows(db, "VIEW_RECORD", rec.id)
    assert len(rows) == 2 and all(r.actor_id == doc.id and r.ip for r in rows)


def test_listing_records_is_audited(client, db):
    dept, doc, patient = ward(db)
    make_record(db, patient, doc)
    login(client, make_user(db, Role.NURSE, department=dept))
    assert client.get(f"/patients/{patient.id}/records").status_code == 200
    assert len(audit_rows(db, "LIST_RECORDS", patient.id)) == 1


def test_same_department_doctor_can_view_not_edit(client, db):
    dept, doc, patient = ward(db)
    rec = make_record(db, patient, doc)
    colleague = make_user(db, Role.DOCTOR, department=dept)
    login(client, colleague)
    assert client.get(f"/records/{rec.id}").status_code == 200
    r = client.post(
        f"/records/{rec.id}/edit",
        data=FORM | {"diagnosis_text": "Sửa trái phép", "csrf_token": csrf_token(client, "/")},
    )
    assert r.status_code == 404
    db.refresh(rec)
    assert rec.diagnosis_text != "Sửa trái phép"
    assert create(client, patient).status_code == 404


def test_attending_doctor_edits_record_and_audit_logged(client, db):
    _, doc, patient = ward(db)
    rec = make_record(db, patient, doc)
    login(client, doc)
    r = client.post(
        f"/records/{rec.id}/edit",
        data=FORM | {"diagnosis_text": "Viêm phế quản",
                     "csrf_token": csrf_token(client, f"/records/{rec.id}/edit")},
        follow_redirects=False,
    )
    assert r.status_code == 303
    db.refresh(rec)
    assert rec.diagnosis_text == "Viêm phế quản"
    assert len(audit_rows(db, "UPDATE_RECORD", rec.id)) == 1


def test_receptionist_cannot_view_record(client, db):
    _, doc, patient = ward(db)
    rec = make_record(db, patient, doc)
    login(client, make_user(db, Role.RECEPTIONIST))
    assert client.get(f"/records/{rec.id}").status_code == 404
    assert client.get(f"/api/v1/records/{rec.id}").status_code == 404
    assert client.get(f"/patients/{patient.id}/records").status_code == 404
    assert db.scalar(select(func.count()).select_from(AuditLog)) == 0


def test_admin_cannot_view_record(client, db):
    _, doc, patient = ward(db)
    rec = make_record(db, patient, doc)
    login(client, make_user(db, Role.ADMIN))
    assert client.get(f"/records/{rec.id}").status_code == 404


def test_patient_sees_own_record_not_others(client, db):
    _, doc, patient = ward(db)
    mine = make_record(db, patient, doc)
    other = make_record(db, make_patient(db), doc)
    login(client, make_user(db, Role.PATIENT, patient=patient))
    assert client.get(f"/api/v1/records/{mine.id}").status_code == 200
    assert client.get(f"/api/v1/records/{other.id}").status_code == 404


def test_patient_cannot_view_other_patient_record_via_api(client, db):
    _, doc, patient = ward(db)
    rec = make_record(db, patient, doc)
    login(client, make_user(db, Role.PATIENT, patient=make_patient(db)))
    a = client.get(f"/api/v1/records/{rec.id}")
    b = client.get("/api/v1/records/999999")
    assert a.status_code == b.status_code == 404 and a.json() == b.json()


def test_nurse_cannot_create_record(client, db):
    dept, _, patient = ward(db)
    login(client, make_user(db, Role.NURSE, department=dept))
    assert create(client, patient).status_code == 403


def test_notes_are_escaped(client, db):
    _, doc, patient = ward(db)
    login(client, doc)
    create(client, patient, notes="<script>alert(1)</script>")
    rec = db.scalar(select(MedicalRecord).where(MedicalRecord.patient_id == patient.id))
    html = client.get(f"/records/{rec.id}").text
    assert "&lt;script&gt;" in html and "<script>alert" not in html


def test_record_creation_does_not_log_pii(client, db, caplog):
    _, doc, patient = ward(db)
    login(client, doc)
    caplog.set_level(logging.DEBUG)
    assert create(client, patient, diagnosis_text="Ung thư phổi").status_code == 303
    assert "Ung thư phổi" not in caplog.text
    assert patient.national_id not in caplog.text
