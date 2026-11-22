"""Hospital fees and BHYT coverage, computed server-side only (R-04)."""

from dataclasses import dataclass
from datetime import date, datetime, time, timedelta
from decimal import ROUND_HALF_UP, Decimal

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from medicare import policy
from medicare.auth.models import Role, User
from medicare.billing.models import Invoice, InvoiceStatus
from medicare.common import metrics
from medicare.common.errors import Conflict, NotFound
from medicare.common.templating import VN_TZ
from medicare.patient.models import Patient
from medicare.prescription.service import list_for_record, prescription_total
from medicare.record.models import MedicalRecord
from medicare.validators import coverage_rate

EXAM_FEE = Decimal(150000)
ALREADY_INVOICED = "Phiếu khám này đã có hóa đơn"
PENDING_LIMIT = 50
UNPAID_LIMIT = 200


def compute_amounts(total: Decimal, rate: Decimal) -> tuple[Decimal, Decimal]:
    """(insurance_amount, patient_amount), rounded to whole đồng, half up."""
    insurance = (total * rate).quantize(Decimal(1), rounding=ROUND_HALF_UP)
    return insurance, total - insurance


def create_invoice(db: Session, user: User, record_id: int) -> Invoice:
    """Bill one visit. Reception never reads clinical content, so no VIEW_RECORD (R-12)."""
    record = db.get(MedicalRecord, record_id)
    if record is None:
        raise NotFound
    if db.scalar(select(Invoice.id).where(Invoice.record_id == record.id)) is not None:
        raise Conflict(ALREADY_INVOICED)
    patient = db.get(Patient, record.patient_id)
    total = EXAM_FEE + sum(
        (prescription_total(p) for p in list_for_record(db, record.id)), Decimal(0)
    )
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


@dataclass
class UnpaidReport:
    invoices: list[Invoice]
    count: int
    total_due: Decimal


def unpaid_between(db: Session, first_day: date, last_day: date) -> UnpaidReport:
    """Unpaid invoices issued from `first_day` to `last_day` inclusive (Vietnam time).

    The count and the amount due cover the whole range; only the oldest UNPAID_LIMIT
    invoices are listed.
    """
    start = datetime.combine(first_day, time.min, tzinfo=VN_TZ)
    end = datetime.combine(last_day, time.min, tzinfo=VN_TZ) + timedelta(days=1)
    conditions = (
        Invoice.status == InvoiceStatus.UNPAID,
        Invoice.created_at >= start,
        Invoice.created_at < end,
    )
    count, total_due = db.execute(
        select(func.count(Invoice.id), func.coalesce(func.sum(Invoice.patient_amount), 0))
        .where(*conditions)
    ).one()
    stmt = (
        select(Invoice)
        .where(*conditions)
        .order_by(Invoice.created_at, Invoice.id)
        .limit(UNPAID_LIMIT)
    )
    return UnpaidReport(invoices=list(db.scalars(stmt).unique()), count=count,
                        total_due=Decimal(total_due))


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


def mark_paid(invoice: Invoice) -> None:
    if invoice.status != InvoiceStatus.UNPAID:
        raise Conflict("Hóa đơn đã được thanh toán")
    invoice.status = InvoiceStatus.PAID
