"""Hospital fees and BHYT coverage, computed server-side only (R-04)."""

from decimal import ROUND_HALF_UP, Decimal

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from medicare import policy
from medicare.auth.models import Role, User
from medicare.billing.catalog import SERVICES
from medicare.billing.models import Invoice, InvoiceLine, InvoiceStatus
from medicare.common import metrics
from medicare.common.errors import Conflict, NotFound
from medicare.patient.models import Patient
from medicare.prescription.service import list_for_record, prescription_total
from medicare.record.models import MedicalRecord
from medicare.validators import coverage_rate

EXAM_FEE = Decimal(150000)
ALREADY_INVOICED = "Phiếu khám này đã có hóa đơn"
PENDING_LIMIT = 50
MAX_LINES = 30


class BillingError(ValueError):
    """Invalid billing input; the message is user-facing."""


def compute_amounts(total: Decimal, rate: Decimal) -> tuple[Decimal, Decimal]:
    """(insurance_amount, patient_amount), rounded to whole đồng, half up."""
    insurance = (total * rate).quantize(Decimal(1), rounding=ROUND_HALF_UP)
    return insurance, total - insurance


def visit_amount(db: Session, record_id: int) -> Decimal:
    """Exam fee plus the medicines prescribed during the visit."""
    return EXAM_FEE + sum(
        (prescription_total(p) for p in list_for_record(db, record_id)), Decimal(0)
    )


def create_invoice(db: Session, user: User, record_id: int) -> Invoice:
    """Bill one visit. Reception never reads clinical content, so no VIEW_RECORD (R-12)."""
    record = db.get(MedicalRecord, record_id)
    if record is None:
        raise NotFound
    if db.scalar(select(Invoice.id).where(Invoice.record_id == record.id)) is not None:
        raise Conflict(ALREADY_INVOICED)
    patient = db.get(Patient, record.patient_id)
    total = visit_amount(db, record.id)
    rate = coverage_rate(patient.insurance_number)
    insurance, patient_part = compute_amounts(total, rate)
    invoice = Invoice(
        record_id=record.id,
        patient_id=patient.id,
        created_by_id=user.id,
        total_amount=total,
        coverage_rate=rate,
        insurance_amount=insurance,
        patient_amount=patient_part,
        status=InvoiceStatus.UNPAID,
    )
    try:
        with db.begin_nested():
            db.add(invoice)
            db.flush()
    except IntegrityError as exc:  # concurrent invoicing of the same record
        raise Conflict(ALREADY_INVOICED) from exc
    return invoice


def list_invoices(db: Session, user: User) -> list[Invoice]:
    stmt = select(Invoice).order_by(Invoice.created_at.desc(), Invoice.id.desc())
    if user.role == Role.PATIENT:
        if user.patient_id is None:
            return []
        stmt = stmt.where(Invoice.patient_id == user.patient_id)
    elif user.role not in (Role.ADMIN, Role.RECEPTIONIST):
        return []
    return list(db.scalars(stmt).unique())


def pending_records(db: Session) -> list[MedicalRecord]:
    """Visits not yet billed: administrative columns only are shown to reception."""
    billed = select(Invoice.record_id)
    stmt = (
        select(MedicalRecord)
        .where(MedicalRecord.id.not_in(billed))
        .order_by(MedicalRecord.visit_date.desc(), MedicalRecord.id.desc())
        .limit(PENDING_LIMIT)
    )
    return list(db.scalars(stmt).unique())


def get_invoice_for(db: Session, user: User, invoice_id: int) -> Invoice:
    invoice = db.get(Invoice, invoice_id)
    if invoice is None:
        raise NotFound
    if not policy.can_view_invoice(user, invoice.patient):
        metrics.authz_denied("invoice")
        raise NotFound
    return invoice


def parse_lines(codes: list[str], quantities: list[str]) -> list[tuple[str, int]]:
    """Pair the submitted service codes with their quantities, skipping empty rows."""
    lines = []
    for code, quantity in zip(codes, quantities):
        code = code.strip()
        if not code:
            continue
        if code not in SERVICES:
            raise BillingError("Dịch vụ không có trong danh mục")
        try:
            lines.append((code, int(quantity)))
        except ValueError:
            raise BillingError("Số lượng phải là số nguyên") from None
    if not lines:
        raise BillingError("Chưa chọn dịch vụ nào")
    return lines


def add_lines(db: Session, user: User, invoice: Invoice, lines: list[tuple[str, int]]) -> None:
    """Add service lines priced from the catalog, then recompute the totals (R-04, R-17)."""
    if invoice.status != InvoiceStatus.UNPAID:
        raise Conflict("Hóa đơn đã thanh toán, không thể thêm dịch vụ")
    if len(invoice.lines) + len(lines) > MAX_LINES:
        raise BillingError(f"Mỗi hóa đơn có tối đa {MAX_LINES} dòng dịch vụ")
    for code, quantity in lines:
        description, unit_price = SERVICES[code]
        invoice.lines.append(InvoiceLine(
            service_code=code, description=description, quantity=quantity,
            unit_price=unit_price, amount=unit_price * quantity, created_by_id=user.id,
        ))
    total = visit_amount(db, invoice.record_id) + services_amount(invoice)
    invoice.total_amount = total
    invoice.insurance_amount, invoice.patient_amount = compute_amounts(
        total, invoice.coverage_rate
    )
    db.flush()


def services_amount(invoice: Invoice) -> Decimal:
    return sum((line.amount for line in invoice.lines), Decimal(0))


def change_status(invoice: Invoice, status: str) -> None:
    if status not in InvoiceStatus.__members__:
        raise BillingError("Trạng thái hóa đơn không hợp lệ")
    new_status = InvoiceStatus(status)
    if invoice.status == new_status:
        raise Conflict("Hóa đơn đã ở trạng thái này")
    invoice.status = new_status
