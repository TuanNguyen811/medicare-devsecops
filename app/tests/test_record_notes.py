from sqlalchemy import select

from medicare.audit.models import AuditLog
from medicare.auth.models import Role
from medicare.record.models import RecordNote
from tests.conftest import csrf_token, login
from tests.factories import make_department, make_patient, make_record, make_user

NOTE = "<p><b>Theo dõi</b> huyết áp 2 lần/ngày</p><ul><li>Hạn chế muối</li></ul>"


def ward(db):
    dept = make_department(db)
    doc = make_user(db, Role.DOCTOR, department=dept)
    patient = make_patient(db, department=dept, attending=doc)
    return dept, doc, patient, make_record(db, patient, doc)


def add(client, record, body=NOTE, token=None):
    token = token or csrf_token(client, f"/records/{record.id}")
    return client.post(f"/records/{record.id}/notes", data={"body": body, "csrf_token": token},
                       follow_redirects=False)


def notes(db, record):
    return list(db.scalars(select(RecordNote).where(RecordNote.record_id == record.id)))


def test_attending_doctor_adds_formatted_note(client, db):
    _, doc, _, record = ward(db)
    login(client, doc)
    r = add(client, record)
    assert r.status_code == 303 and r.headers["location"] == f"/records/{record.id}#notes"
    saved = notes(db, record)
    assert len(saved) == 1 and saved[0].author_id == doc.id and saved[0].body == NOTE
    page = client.get(f"/records/{record.id}").text
    assert "<b>Theo dõi</b> huyết áp" in page and "<li>Hạn chế muối</li>" in page


def test_adding_note_is_audited(client, db):
    _, doc, _, record = ward(db)
    login(client, doc)
    add(client, record)
    rows = list(db.scalars(select(AuditLog).where(AuditLog.action == "ADD_RECORD_NOTE")))
    assert len(rows) == 1 and rows[0].entity_type == "record"
    assert rows[0].entity_id == record.id and rows[0].actor_id == doc.id


def test_empty_note_rejected(client, db):
    _, doc, _, record = ward(db)
    login(client, doc)
    assert add(client, record, body="   ").status_code == 303
    assert notes(db, record) == []


def test_editor_shown_to_attending_only(client, db):
    dept, doc, _, record = ward(db)
    login(client, doc)
    assert f'action="/records/{record.id}/notes"' in client.get(f"/records/{record.id}").text
    client.cookies.clear()
    login(client, make_user(db, Role.NURSE, department=dept))
    page = client.get(f"/records/{record.id}").text
    assert "Ghi chú của bác sĩ" in page and f'action="/records/{record.id}/notes"' not in page


def test_same_department_doctor_cannot_add_note(client, db):
    dept, _, _, record = ward(db)
    login(client, make_user(db, Role.DOCTOR, department=dept))
    assert add(client, record).status_code == 404
    assert notes(db, record) == []


def test_nurse_and_reception_cannot_add_note(client, db):
    dept, _, _, record = ward(db)
    for role in (Role.NURSE, Role.RECEPTIONIST):
        client.cookies.clear()
        login(client, make_user(db, role, department=dept))
        assert add(client, record, token=csrf_token(client, "/")).status_code == 403
    assert notes(db, record) == []


def test_note_requires_csrf_token(client, db):
    _, doc, _, record = ward(db)
    login(client, doc)
    r = client.post(f"/records/{record.id}/notes", data={"body": NOTE})
    assert r.status_code == 403 and notes(db, record) == []


def test_patient_sees_notes_on_own_record(client, db):
    _, doc, patient, record = ward(db)
    db.add(RecordNote(record_id=record.id, author_id=doc.id, body=NOTE))
    db.flush()
    login(client, make_user(db, Role.PATIENT, patient=patient))
    page = client.get(f"/records/{record.id}").text
    assert "Hạn chế muối" in page and doc.full_name in page
