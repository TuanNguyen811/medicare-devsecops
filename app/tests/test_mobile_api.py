from datetime import UTC, datetime, timedelta

from sqlalchemy import select

from medicare.appointment.models import Appointment, AppointmentStatus
from medicare.audit.models import AuditLog
from medicare.auth.models import Role
from tests.factories import (
    TEST_PASSWORD,
    make_department,
    make_patient,
    make_record,
    make_user,
)


def ward(db, code="NOI"):
    dept = make_department(db, code)
    doc = make_user(db, Role.DOCTOR, department=dept)
    patient = make_patient(db, department=dept, attending=doc)
    return dept, doc, patient, make_record(db, patient, doc)


def token_for(client, user, password=TEST_PASSWORD):
    return client.post("/api/v1/mobile/token",
                       json={"username": user.username, "password": password})


def bearer(client, user) -> dict:
    r = token_for(client, user)
    assert r.status_code == 200
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


def test_token_issued_for_valid_credentials(client, db):
    _, doc, _, _ = ward(db)
    r = token_for(client, doc)
    assert r.status_code == 200
    body = r.json()
    assert body["token_type"] == "bearer" and body["expires_in"] == 3600
    assert body["access_token"].count(".") == 2


def test_wrong_password_and_unknown_user_get_same_error(client, db):
    _, doc, _, _ = ward(db)
    wrong = token_for(client, doc, password="Sai-mat-khau-1")
    unknown = client.post("/api/v1/mobile/token",
                                 json={"username": "khong-ton-tai", "password": "x" * 10})
    assert wrong.status_code == unknown.status_code == 401
    assert wrong.json() == unknown.json()


def test_failed_token_requests_count_toward_lockout(client, db):
    _, doc, _, _ = ward(db)
    for _ in range(5):
        token_for(client, doc, password="Sai-mat-khau-1")
    db.refresh(doc)
    assert doc.locked_until is not None
    assert token_for(client, doc).status_code == 401


def test_me_requires_bearer_token(client, db):
    assert client.get("/api/v1/mobile/me").status_code == 401
    r = client.get("/api/v1/mobile/me", headers={"Authorization": "Basic abc"})
    assert r.status_code == 401 and r.headers["www-authenticate"] == "Bearer"


def test_me_returns_profile(client, db):
    dept, doc, _, _ = ward(db)
    r = client.get("/api/v1/mobile/me", headers=bearer(client, doc))
    assert r.status_code == 200
    body = r.json()
    assert (body["id"], body["role"], body["department"]) == (doc.id, "DOCTOR", dept.name)


def test_patient_reads_own_record_and_access_is_audited(client, db):
    _, _, patient, record = ward(db)
    user = make_user(db, Role.PATIENT, patient=patient)
    headers = bearer(client, user)
    r = client.get(f"/api/v1/mobile/records/{record.id}", headers=headers)
    assert r.status_code == 200 and r.json()["diagnosis_code"] == "J06.9"
    rows = list(db.scalars(select(AuditLog).where(AuditLog.action == "VIEW_RECORD",
                                                  AuditLog.entity_id == record.id)))
    assert len(rows) == 1 and rows[0].actor_id == user.id


def test_patient_cannot_read_other_patients_record(client, db):
    _, _, patient, _ = ward(db)
    _, _, _, other_record = ward(db, "NGOAI")
    headers = bearer(client, make_user(db, Role.PATIENT, patient=patient))
    assert client.get(f"/api/v1/mobile/records/{other_record.id}",
                      headers=headers).status_code == 404


def test_receptionist_cannot_read_records(client, db):
    _, _, patient, record = ward(db)
    headers = bearer(client, make_user(db, Role.RECEPTIONIST))
    assert client.get(f"/api/v1/mobile/records/{record.id}", headers=headers).status_code == 404
    assert client.get(f"/api/v1/mobile/patients/{patient.id}/records",
                      headers=headers).status_code == 404


def test_nurse_lists_department_patient_records(client, db):
    dept, _, patient, record = ward(db)
    headers = bearer(client, make_user(db, Role.NURSE, department=dept))
    r = client.get(f"/api/v1/mobile/patients/{patient.id}/records", headers=headers)
    assert r.status_code == 200 and [row["id"] for row in r.json()] == [record.id]


def test_appointments_scoped_to_patient(client, db):
    _, doc, patient, _ = ward(db)
    _, _, other, _ = ward(db, "NGOAI")
    when = datetime.now(UTC).replace(minute=0, second=0, microsecond=0) + timedelta(days=2)
    for i, p in enumerate((patient, other)):
        db.add(Appointment(patient_id=p.id, doctor_id=doc.id,
                           scheduled_at=when + timedelta(hours=i), reason="Tái khám",
                           status=AppointmentStatus.REQUESTED, created_by_id=doc.id))
    db.flush()
    headers = bearer(client, make_user(db, Role.PATIENT, patient=patient))
    r = client.get("/api/v1/mobile/appointments", headers=headers)
    assert r.status_code == 200 and [a["patient_code"] for a in r.json()] == [patient.code]


def test_logout_revokes_mobile_token(client, db):
    _, doc, _, _ = ward(db)
    headers = bearer(client, doc)
    doc.session_version += 1
    db.flush()
    assert client.get("/api/v1/mobile/me", headers=headers).status_code == 401
