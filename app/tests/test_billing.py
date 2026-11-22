import itertools
from datetime import datetime
from decimal import Decimal

from sqlalchemy import select

from medicare.audit.models import AuditLog
from medicare.auth.models import Role
from medicare.billing.models import Invoice, InvoiceStatus
from medicare.common.templating import VN_TZ
from medicare.prescription.models import Prescription, PrescriptionItem
from tests.conftest import csrf_token, login
from tests.factories import make_department, make_medicine, make_patient, make_record, make_user

_dept_seq = itertools.count(1)


def visit(db, insurance_number="HT4010123456789", drug_cost=80_000):
    """A record whose prescriptions cost `drug_cost` in total (0 → no prescription)."""
    dept = make_department(db, f"K{next(_dept_seq)}")
    doc = make_user(db, Role.DOCTOR, department=dept)
    patient = make_patient(db, department=dept, attending=doc,
                           insurance_number=insurance_number)
    record = make_record(db, patient, doc)
    if drug_cost:
        p = Prescription(record_id=record.id, patient_id=patient.id, doctor_id=doc.id)
        db.add(p)
        db.flush()
        db.add(PrescriptionItem(prescription_id=p.id, medicine_id=make_medicine(db, drug_cost).id,
                                quantity=1, dosage="Sáng"))
        db.flush()
    return patient, record


def create_invoice(client, record, **extra):
    data = {"csrf_token": csrf_token(client, "/invoices")} | extra
    return client.post(f"/records/{record.id}/invoice", data=data, follow_redirects=False)


def invoice_of(db, record) -> Invoice:
    return db.scalar(select(Invoice).where(Invoice.record_id == record.id))


def test_invoice_with_80_percent_coverage(client, db):
    _, record = visit(db)
    login(client, make_user(db, Role.RECEPTIONIST))
    r = create_invoice(client, record)
    assert r.status_code == 303 and r.headers["location"].startswith("/invoices/")
    inv = invoice_of(db, record)
    assert (inv.total_amount, inv.coverage_rate, inv.insurance_amount, inv.patient_amount) == (
        Decimal(230000), Decimal("0.80"), Decimal(184000), Decimal(46000))
    assert inv.status == InvoiceStatus.UNPAID


def test_invoice_without_insurance(client, db):
    _, record = visit(db, insurance_number=None)
    login(client, make_user(db, Role.RECEPTIONIST))
    create_invoice(client, record)
    inv = invoice_of(db, record)
    assert inv.insurance_amount == Decimal(0) and inv.patient_amount == Decimal(230000)


def test_invoice_without_prescription_is_exam_fee_only(client, db):
    _, record = visit(db, drug_cost=0)
    login(client, make_user(db, Role.RECEPTIONIST))
    create_invoice(client, record)
    assert invoice_of(db, record).total_amount == Decimal(150000)


def test_coverage_rounds_half_up(client, db):
    _, record = visit(db, insurance_number="DN3010123456789", drug_cost=10)  # 95% of 150_010
    login(client, make_user(db, Role.RECEPTIONIST))
    create_invoice(client, record)
    inv = invoice_of(db, record)
    assert (inv.insurance_amount, inv.patient_amount) == (Decimal(142510), Decimal(7500))


def test_client_supplied_amounts_are_ignored(client, db):
    _, record = visit(db)
    login(client, make_user(db, Role.RECEPTIONIST))
    create_invoice(client, record, coverage_rate="1.0", total_amount="1",
                   insurance_amount="999999", patient_amount="0")
    inv = invoice_of(db, record)
    assert (inv.total_amount, inv.insurance_amount, inv.patient_amount) == (
        Decimal(230000), Decimal(184000), Decimal(46000))


def test_duplicate_invoice_conflict(client, db):
    _, record = visit(db)
    login(client, make_user(db, Role.RECEPTIONIST))
    assert create_invoice(client, record).status_code == 303
    assert create_invoice(client, record).status_code == 409


def test_invoice_for_missing_record_404(client, db):
    login(client, make_user(db, Role.RECEPTIONIST))
    r = client.post("/records/999999/invoice", data={"csrf_token": csrf_token(client, "/")})
    assert r.status_code == 404


def test_only_receptionist_creates_invoice(client, db):
    _, record = visit(db)
    login(client, make_user(db, Role.DOCTOR))
    assert create_invoice(client, record).status_code == 403


def test_invoice_creation_does_not_read_record_audit(client, db):
    _, record = visit(db)
    login(client, make_user(db, Role.RECEPTIONIST))
    create_invoice(client, record)
    assert db.scalars(select(AuditLog).where(AuditLog.action == "VIEW_RECORD")).all() == []


def test_patient_sees_only_own_invoice(client, db):
    me, mine = visit(db)
    _, theirs = visit(db)
    login(client, make_user(db, Role.RECEPTIONIST))
    create_invoice(client, mine)
    create_invoice(client, theirs)
    client.cookies.clear()
    login(client, make_user(db, Role.PATIENT, patient=me))
    assert client.get(f"/invoices/{invoice_of(db, mine).id}").status_code == 200
    assert client.get(f"/invoices/{invoice_of(db, theirs).id}").status_code == 404
    listing = client.get("/invoices").text
    assert f"/invoices/{invoice_of(db, mine).id}" in listing
    assert f"/invoices/{invoice_of(db, theirs).id}" not in listing


def test_nurse_cannot_list_invoices(client, db):
    login(client, make_user(db, Role.NURSE, department=make_department(db)))
    assert client.get("/invoices").status_code == 403


def test_receptionist_invoice_does_not_expose_diagnosis(client, db):
    _, record = visit(db)
    login(client, make_user(db, Role.RECEPTIONIST))
    assert record.diagnosis_text not in client.get("/invoices").text  # pending list
    create_invoice(client, record)
    page = client.get(f"/invoices/{invoice_of(db, record).id}").text
    assert record.diagnosis_text not in page and "184.000 ₫" in page


def test_pending_records_listed_for_receptionist(client, db):
    patient, record = visit(db)
    login(client, make_user(db, Role.RECEPTIONIST))
    html = client.get("/invoices").text
    assert f"/records/{record.id}/invoice" in html and patient.code in html


def test_receptionist_marks_invoice_paid_once(client, db):
    _, record = visit(db)
    login(client, make_user(db, Role.RECEPTIONIST))
    create_invoice(client, record)
    inv = invoice_of(db, record)
    token = csrf_token(client, "/invoices")
    r = client.post(f"/invoices/{inv.id}/pay", data={"csrf_token": token}, follow_redirects=False)
    assert r.status_code == 303
    db.refresh(inv)
    assert inv.status == InvoiceStatus.PAID
    assert client.post(f"/invoices/{inv.id}/pay", data={"csrf_token": token}).status_code == 409


def test_patient_cannot_mark_paid(client, db):
    me, record = visit(db)
    login(client, make_user(db, Role.RECEPTIONIST))
    create_invoice(client, record)
    inv = invoice_of(db, record)
    client.cookies.clear()
    login(client, make_user(db, Role.PATIENT, patient=me))
    r = client.post(f"/invoices/{inv.id}/pay", data={"csrf_token": csrf_token(client, "/")})
    assert r.status_code == 403


def issued_invoice(db, issued_at, patient_amount, status=InvoiceStatus.UNPAID):
    patient, record = visit(db, drug_cost=0)
    inv = Invoice(record_id=record.id, patient_id=patient.id,
                  created_by_id=make_user(db, Role.RECEPTIONIST).id,
                  total_amount=Decimal(150000), coverage_rate=Decimal(0),
                  insurance_amount=Decimal(150000) - patient_amount,
                  patient_amount=patient_amount, status=status, created_at=issued_at)
    db.add(inv)
    db.flush()
    return inv


def vn_time(day, hour=9):
    return datetime(2025, 3, day, hour, tzinfo=VN_TZ)


def unpaid(client, **params):
    return client.get("/invoices/unpaid", params=params)


def test_unpaid_invoices_filtered_by_issue_date_with_total_due(client, db):
    first = issued_invoice(db, vn_time(3), Decimal(30000))
    late_evening = issued_invoice(db, vn_time(10, hour=23), Decimal(45000))
    too_late = issued_invoice(db, vn_time(11, hour=0), Decimal(70000))
    paid = issued_invoice(db, vn_time(5), Decimal(90000), status=InvoiceStatus.PAID)
    login(client, make_user(db, Role.RECEPTIONIST))
    r = unpaid(client, date_from="2025-03-01", date_to="2025-03-10")
    assert r.status_code == 200
    assert f"/invoices/{first.id}" in r.text and f"/invoices/{late_evening.id}" in r.text
    assert f"/invoices/{too_late.id}" not in r.text and f"/invoices/{paid.id}" not in r.text
    assert "(2 hóa đơn)" in r.text and "75.000 ₫" in r.text


def test_unpaid_reversed_range_is_swapped(client, db):
    inv = issued_invoice(db, vn_time(4), Decimal(20000))
    login(client, make_user(db, Role.ADMIN))
    html = unpaid(client, date_from="2025-03-31", date_to="2025-03-01").text
    assert f"/invoices/{inv.id}" in html and 'value="2025-03-01"' in html


def test_unpaid_accepts_out_of_range_dates(client, db):
    inv = issued_invoice(db, vn_time(4), Decimal(20000))
    login(client, make_user(db, Role.RECEPTIONIST))
    r = unpaid(client, date_from="0001-01-02", date_to="9999-12-30")
    assert r.status_code == 200 and f"/invoices/{inv.id}" in r.text
    for value in ("0001-01-01", "9999-12-31", "99999-01-01", "03/2025", ""):
        assert unpaid(client, date_from=value, date_to=value).status_code == 200


def test_unpaid_page_for_billing_staff_only(client, db):
    me, _ = visit(db, drug_cost=0)
    for user in (make_user(db, Role.DOCTOR), make_user(db, Role.PATIENT, patient=me),
                 make_user(db, Role.NURSE, department=make_department(db, "KX"))):
        client.cookies.clear()
        login(client, user)
        assert unpaid(client).status_code == 403
    assert 'href="/invoices/unpaid"' not in client.get("/").text


def test_unpaid_page_linked_from_invoice_list(client, db):
    me, _ = visit(db, drug_cost=0)
    login(client, make_user(db, Role.RECEPTIONIST))
    assert 'href="/invoices/unpaid"' in client.get("/invoices").text
    client.cookies.clear()
    login(client, make_user(db, Role.PATIENT, patient=me))
    assert 'href="/invoices/unpaid"' not in client.get("/invoices").text
