from datetime import date, datetime, timedelta

from sqlalchemy import select

from medicare.appointment.models import Appointment, AppointmentStatus
from medicare.auth.models import Role
from medicare.common.templating import VN_TZ
from tests.conftest import csrf_token, login
from tests.factories import make_department, make_patient, make_user


def slot(days: int = 1, hour: int = 9, minute: int = 0) -> str:
    """datetime-local form value (Vietnam wall-clock time)."""
    d = date.today() + timedelta(days=days)
    return f"{d.isoformat()}T{hour:02d}:{minute:02d}"


def slot_dt(days: int = 1, hour: int = 9, minute: int = 0) -> datetime:
    return datetime.fromisoformat(slot(days, hour, minute)).replace(tzinfo=VN_TZ)


def make_appt(db, patient, doctor, status=AppointmentStatus.REQUESTED, days=1, hour=9):
    appt = Appointment(
        patient_id=patient.id,
        doctor_id=doctor.id,
        scheduled_at=slot_dt(days, hour),
        reason="Khám định kỳ",
        status=status,
        created_by_id=doctor.id,
    )
    db.add(appt)
    db.flush()
    return appt


def setup_doctor(db):
    return make_user(db, Role.DOCTOR, department=make_department(db))


def book(client, **data):
    data.setdefault("reason", "Đau đầu")
    data["csrf_token"] = csrf_token(client, "/appointments/new")
    return client.post("/appointments", data=data, follow_redirects=False)


def test_patient_books_own_appointment(client, db):
    doc = setup_doctor(db)
    me = make_patient(db)
    user = make_user(db, Role.PATIENT, patient=me)
    login(client, user)
    r = book(client, doctor_id=str(doc.id), scheduled_at=slot())
    assert r.status_code == 303
    appt = db.scalar(select(Appointment).where(Appointment.patient_id == me.id))
    assert appt.status == AppointmentStatus.REQUESTED
    assert appt.scheduled_at == slot_dt() and appt.created_by_id == user.id


def test_patient_cannot_book_for_other_patient(client, db):
    doc = setup_doctor(db)
    other = make_patient(db)
    login(client, make_user(db, Role.PATIENT, patient=make_patient(db)))
    r = book(client, patient_id=str(other.id), doctor_id=str(doc.id), scheduled_at=slot())
    assert r.status_code == 404
    assert db.scalar(select(Appointment).where(Appointment.patient_id == other.id)) is None


def test_booking_in_past_rejected_400(client, db):
    doc = setup_doctor(db)
    login(client, make_user(db, Role.PATIENT, patient=make_patient(db)))
    assert book(client, doctor_id=str(doc.id), scheduled_at=slot(days=-1)).status_code == 400


def test_booking_off_slot_rejected_400(client, db):
    doc = setup_doctor(db)
    login(client, make_user(db, Role.PATIENT, patient=make_patient(db)))
    r = book(client, doctor_id=str(doc.id), scheduled_at=slot(minute=15))
    assert r.status_code == 400


def test_booking_with_non_doctor_rejected_400(client, db):
    nurse = make_user(db, Role.NURSE, department=make_department(db))
    login(client, make_user(db, Role.PATIENT, patient=make_patient(db)))
    assert book(client, doctor_id=str(nurse.id), scheduled_at=slot()).status_code == 400


def test_double_booking_rejected_at_db_level(client, db):
    doc = setup_doctor(db)
    p1, p2 = make_patient(db), make_patient(db)
    login(client, make_user(db, Role.RECEPTIONIST))
    first = book(client, patient_id=str(p1.id), doctor_id=str(doc.id), scheduled_at=slot())
    second = book(client, patient_id=str(p2.id), doctor_id=str(doc.id), scheduled_at=slot())
    assert first.status_code == 303 and second.status_code == 409


def test_cancelled_slot_can_be_rebooked(client, db):
    doc = setup_doctor(db)
    make_appt(db, make_patient(db), doc, status=AppointmentStatus.CANCELLED)
    login(client, make_user(db, Role.RECEPTIONIST))
    r = book(client, patient_id=str(make_patient(db).id), doctor_id=str(doc.id),
             scheduled_at=slot())
    assert r.status_code == 303


def test_receptionist_confirms_patient_cannot(client, db):
    doc = setup_doctor(db)
    me = make_patient(db)
    appt = make_appt(db, me, doc)
    login(client, make_user(db, Role.PATIENT, patient=me))
    token = csrf_token(client, "/appointments")
    assert client.post(f"/appointments/{appt.id}/confirm",
                       data={"csrf_token": token}).status_code == 403
    client.post("/logout", data={"csrf_token": token})
    login(client, make_user(db, Role.RECEPTIONIST))
    r = client.post(f"/appointments/{appt.id}/confirm",
                    data={"csrf_token": csrf_token(client, "/appointments")},
                    follow_redirects=False)
    assert r.status_code == 303
    db.refresh(appt)
    assert appt.status == AppointmentStatus.CONFIRMED


def test_confirm_requires_csrf(client, db):
    appt = make_appt(db, make_patient(db), setup_doctor(db))
    login(client, make_user(db, Role.RECEPTIONIST))
    assert client.post(f"/appointments/{appt.id}/confirm").status_code == 403


def test_patient_cancels_only_requested_own(client, db):
    doc = setup_doctor(db)
    me = make_patient(db)
    mine = make_appt(db, me, doc, hour=9)
    mine_confirmed = make_appt(db, me, doc, status=AppointmentStatus.CONFIRMED, hour=10)
    theirs = make_appt(db, make_patient(db), doc, hour=11)
    login(client, make_user(db, Role.PATIENT, patient=me))
    token = csrf_token(client, "/appointments")

    def cancel(a):
        return client.post(f"/appointments/{a.id}/cancel", data={"csrf_token": token},
                           follow_redirects=False)

    assert cancel(mine).status_code == 303
    assert cancel(mine_confirmed).status_code == 403
    assert cancel(theirs).status_code == 404
    db.refresh(mine)
    db.refresh(theirs)
    assert mine.status == AppointmentStatus.CANCELLED
    assert theirs.status == AppointmentStatus.REQUESTED


def test_api_lists_only_own(client, db):
    doc = setup_doctor(db)
    me = make_patient(db)
    mine = make_appt(db, me, doc, hour=9)
    theirs = make_appt(db, make_patient(db), doc, hour=10)
    login(client, make_user(db, Role.PATIENT, patient=me))
    ids = [a["id"] for a in client.get("/api/v1/appointments").json()]
    assert ids == [mine.id] and theirs.id not in ids


def test_doctor_list_shows_only_own(client, db):
    dept = make_department(db)
    doc, colleague = (make_user(db, Role.DOCTOR, department=dept) for _ in range(2))
    p_mine, p_theirs = make_patient(db), make_patient(db)
    make_appt(db, p_mine, doc)
    make_appt(db, p_theirs, colleague)
    login(client, doc)
    html = client.get("/appointments").text
    assert p_mine.code in html and p_theirs.code not in html


def test_nurse_list_scoped_to_department(client, db):
    noi, ngoai = make_department(db, "NOI"), make_department(db, "NGOAI")
    doc = make_user(db, Role.DOCTOR, department=noi)
    p_noi, p_ngoai = make_patient(db, department=noi), make_patient(db, department=ngoai)
    make_appt(db, p_noi, doc, hour=9)
    make_appt(db, p_ngoai, doc, hour=10)
    login(client, make_user(db, Role.NURSE, department=noi))
    html = client.get("/appointments").text
    assert p_noi.code in html and p_ngoai.code not in html
