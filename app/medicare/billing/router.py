from decimal import Decimal, InvalidOperation

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse, Response
from sqlalchemy.orm import Session

from medicare.auth.models import Role, User
from medicare.billing import service
from medicare.billing.models import InvoiceStatus
from medicare.common.auth import get_current_user, require_roles
from medicare.common.csrf import verify_csrf
from medicare.common.errors import Conflict
from medicare.common.ids import ObjectId
from medicare.common.templating import flash, render
from medicare.db import get_db

router = APIRouter()

receptionist_user = require_roles(Role.RECEPTIONIST)
invoice_reader = require_roles(Role.RECEPTIONIST, Role.ADMIN, Role.PATIENT)

STATUS_LABELS = {"UNPAID": ("Chưa thanh toán", "warning"), "PAID": ("Đã thanh toán", "success")}
COVERAGE_CHOICES = [
    ("1.00", "100% (mức 1, 2, 5)"),
    ("0.95", "95% (mức 3)"),
    ("0.80", "80% (mức 4)"),
    ("0.40", "40% (trái tuyến, nội trú tuyến tỉnh)"),
    ("0.00", "Không hưởng BHYT"),
]


@router.post("/records/{record_id}/invoice", dependencies=[Depends(verify_csrf)])
def create_invoice(
    request: Request,
    record_id: ObjectId,
    user: User = Depends(receptionist_user),
    db: Session = Depends(get_db),
) -> Response:
    # R-04: no amount or rate is read from the request; everything is computed server-side.
    invoice = service.create_invoice(db, user, record_id)
    db.commit()
    flash(request, f"Đã lập hóa đơn #{invoice.id}")
    return RedirectResponse(f"/invoices/{invoice.id}", status_code=303)


@router.get("/invoices")
def list_invoices(
    request: Request,
    user: User = Depends(invoice_reader),
    db: Session = Depends(get_db),
) -> Response:
    is_reception = user.role == Role.RECEPTIONIST
    return render(request, "billing/list.html", {
        "invoices": service.list_invoices(db, user),
        "pending": service.pending_records(db) if is_reception else [],
        "is_reception": is_reception,
        "status_labels": STATUS_LABELS,
        "breadcrumbs": [("Trang chủ", "/"), ("Hóa đơn", None)],
    })


@router.get("/invoices/{invoice_id}")
def invoice_detail(
    request: Request,
    invoice_id: ObjectId,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Response:
    invoice = service.get_invoice_for(db, user, invoice_id)
    return render(request, "billing/detail.html", {
        "invoice": invoice,
        "exam_fee": service.EXAM_FEE,
        "drug_cost": invoice.total_amount - service.EXAM_FEE,
        "can_pay": user.role == Role.RECEPTIONIST,
        "coverage_choices": COVERAGE_CHOICES,
        "status_labels": STATUS_LABELS,
        "breadcrumbs": [("Trang chủ", "/"), ("Hóa đơn", "/invoices"),
                        (f"Hóa đơn #{invoice.id}", None)],
    })


@router.post("/invoices/{invoice_id}/pay", dependencies=[Depends(verify_csrf)])
def pay_invoice(
    request: Request,
    invoice_id: ObjectId,
    user: User = Depends(receptionist_user),
    db: Session = Depends(get_db),
) -> Response:
    invoice = service.get_invoice_for(db, user, invoice_id)
    service.mark_paid(invoice)
    db.commit()
    flash(request, f"Đã thu tiền hóa đơn #{invoice.id}")
    return RedirectResponse(f"/invoices/{invoice.id}", status_code=303)


@router.post("/invoices/{invoice_id}/coverage", dependencies=[Depends(verify_csrf)])
def adjust_coverage(
    request: Request,
    invoice_id: ObjectId,
    coverage_rate: str = Form(""),
    user: User = Depends(receptionist_user),
    db: Session = Depends(get_db),
) -> Response:
    """Re-split an unpaid invoice when the patient's BHYT benefit level changes at the desk."""
    invoice = service.get_invoice_for(db, user, invoice_id)
    if invoice.status != InvoiceStatus.UNPAID:
        raise Conflict("Hóa đơn đã được thanh toán")
    try:
        rate = Decimal(coverage_rate).quantize(Decimal("0.01"))
    except InvalidOperation:
        raise Conflict("Mức hưởng BHYT không hợp lệ") from None
    if not rate.is_finite() or not Decimal(0) <= rate <= Decimal(1):
        raise Conflict("Mức hưởng BHYT không hợp lệ")
    invoice.coverage_rate = rate
    invoice.insurance_amount, invoice.patient_amount = service.compute_amounts(
        invoice.total_amount, rate
    )
    db.commit()
    flash(request, f"Đã cập nhật mức hưởng BHYT cho hóa đơn #{invoice.id}")
    return RedirectResponse(f"/invoices/{invoice.id}", status_code=303)
