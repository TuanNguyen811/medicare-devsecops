from decimal import Decimal

from sqlalchemy import select

from medicare.audit.models import AuditLog
from medicare.auth.models import Role
from medicare.prescription.models import Medicine, Prescription, PrescriptionItem
from medicare.prescription.service import prescription_total
from tests.conftest import csrf_token, login
from tests.factories import make_department, make_medicine, make_patient, make_record, make_user


def ward(db):
    dept = make_department(db)
    doc = make_user(db, Role.DOCTOR, department=dept)
    patient = make_patient(db, department=dept, attending=doc)
    record = make_record(db, patient, doc)
    return dept, doc, patient, record


def prescribe(client, record, rows, note="Uống sau ăn", token_path="/"):
    data = {
        "medicine_id[]": [str(m) for m, _, _ in rows],
        "quantity[]": [str(q) for _, q, _ in rows],
        "dosage[]": [d for _, _, d in rows],
        "note": note,
        "csrf_token": csrf_token(client, token_path),
    }
    return client.post(f"/records/{record.id}/prescriptions", data=data, follow_redirects=False)


def make_prescription(db, record, doctor, items):
    p = Prescription(record_id=record.id, patient_id=record.patient_id, doctor_id=doctor.id)
    db.add(p)
    db.flush()
    for med, qty in items:
        db.add(PrescriptionItem(prescription_id=p.id, medicine_id=med.id, quantity=qty,
                                dosage="1 viên/lần"))
    db.flush()
    db.refresh(p)
    return p


def test_attending_doctor_prescribes(client, db):
    _, doc, _, record = ward(db)
    m1, m2 = make_medicine(db), make_medicine(db, price=25000)
    login(client, doc)
    r = prescribe(client, record, [(m1.id, 3, "1 viên x 3 lần/ngày"), (m2.id, 2, "Tối")],
                  token_path=f"/records/{record.id}/prescriptions/new")
    assert r.status_code == 303 and r.headers["location"].startswith("/prescriptions/")
    p = db.scalar(select(Prescription).where(Prescription.record_id == record.id))
    assert p.doctor_id == doc.id and len(p.items) == 2
    audit = db.scalars(select(AuditLog).where(AuditLog.action == "CREATE_PRESCRIPTION")).all()
    assert [(a.entity_id, a.actor_id) for a in audit] == [(p.id, doc.id)]


def test_blank_rows_are_ignored(client, db):
    _, doc, _, record = ward(db)
    m1 = make_medicine(db)
    login(client, doc)
    r = prescribe(client, record, [(m1.id, 1, "Sáng"), ("", "", "")])
    assert r.status_code == 303


def test_nurse_cannot_prescribe(client, db):
    dept, _, _, record = ward(db)
    m1 = make_medicine(db)
    login(client, make_user(db, Role.NURSE, department=dept))
    assert prescribe(client, record, [(m1.id, 1, "Sáng")]).status_code == 403


def test_non_attending_doctor_cannot_prescribe(client, db):
    dept, _, _, record = ward(db)
    m1 = make_medicine(db)
    login(client, make_user(db, Role.DOCTOR, department=dept))
    assert prescribe(client, record, [(m1.id, 1, "Sáng")]).status_code == 404
    assert client.get(f"/records/{record.id}/prescriptions/new").status_code == 404


def test_quantity_must_be_positive(client, db):
    _, doc, _, record = ward(db)
    m1 = make_medicine(db)
    login(client, doc)
    assert prescribe(client, record, [(m1.id, 0, "Sáng")]).status_code == 400


def test_inactive_medicine_rejected(client, db):
    _, doc, _, record = ward(db)
    m1 = make_medicine(db)
    m1.is_active = False
    db.flush()
    login(client, doc)
    assert prescribe(client, record, [(m1.id, 1, "Sáng")]).status_code == 400


def test_empty_prescription_rejected(client, db):
    _, doc, _, record = ward(db)
    login(client, doc)
    assert prescribe(client, record, [("", "", "")]).status_code == 400


def test_prescription_total(db):
    _, doc, _, record = ward(db)
    p = make_prescription(db, record, doc, [(make_medicine(db, price=10_000), 3),
                                             (make_medicine(db, price=25_000), 2)])
    assert prescription_total(p) == Decimal(80000)


def test_view_prescription_scoped_and_audited(client, db):
    dept, doc, _, record = ward(db)
    p = make_prescription(db, record, doc, [(make_medicine(db), 1)])
    login(client, make_user(db, Role.NURSE, department=dept))
    assert client.get(f"/prescriptions/{p.id}").status_code == 200
    rows = db.scalars(select(AuditLog).where(AuditLog.action == "VIEW_PRESCRIPTION")).all()
    assert [r.entity_id for r in rows] == [p.id]


def test_receptionist_and_other_patient_cannot_view_prescription(client, db):
    _, doc, _, record = ward(db)
    p = make_prescription(db, record, doc, [(make_medicine(db), 1)])
    login(client, make_user(db, Role.RECEPTIONIST))
    assert client.get(f"/prescriptions/{p.id}").status_code == 404
    client.cookies.clear()
    login(client, make_user(db, Role.PATIENT, patient=make_patient(db)))
    assert client.get(f"/prescriptions/{p.id}").status_code == 404


def test_patient_views_own_prescription(client, db):
    _, doc, patient, record = ward(db)
    p = make_prescription(db, record, doc, [(make_medicine(db), 2)])
    login(client, make_user(db, Role.PATIENT, patient=patient))
    assert client.get(f"/prescriptions/{p.id}").status_code == 200


def test_admin_adds_medicine_and_doctor_cannot(client, db):
    login(client, make_user(db, Role.ADMIN))
    data = {"code": "PARA500", "name": "Paracetamol 500mg", "unit": "viên",
            "unit_price": "1500", "csrf_token": csrf_token(client, "/admin/medicines")}
    assert client.post("/admin/medicines", data=data, follow_redirects=False).status_code == 303
    med = db.scalar(select(Medicine).where(Medicine.code == "PARA500"))
    assert med is not None and med.unit_price == Decimal(1500)
    client.cookies.clear()
    login(client, make_user(db, Role.DOCTOR))
    data["csrf_token"] = csrf_token(client, "/")
    data["code"] = "OTHER1"
    assert client.post("/admin/medicines", data=data).status_code == 403
    assert client.get("/admin/medicines").status_code == 403


def test_duplicate_medicine_code_rejected(client, db):
    existing = make_medicine(db)
    login(client, make_user(db, Role.ADMIN))
    data = {"code": existing.code, "name": "Trùng mã", "unit": "viên", "unit_price": "100",
            "csrf_token": csrf_token(client, "/admin/medicines")}
    assert client.post("/admin/medicines", data=data).status_code == 400


def test_record_page_offers_prescribing_to_attending_only(client, db):
    dept, doc, _, record = ward(db)
    login(client, doc)
    assert f"/records/{record.id}/prescriptions/new" in client.get(f"/records/{record.id}").text
    client.cookies.clear()
    login(client, make_user(db, Role.NURSE, department=dept))
    assert f"/records/{record.id}/prescriptions/new" not in client.get(f"/records/{record.id}").text
