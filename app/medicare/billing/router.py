from datetime import date, datetime

from fastapi import APIRouter, Depends, Request
from fastapi.responses import RedirectResponse, Response
from sqlalchemy.orm import Session

from medicare.auth.models import Role, User
from medicare.billing import service
from medicare.common.auth import get_current_user, require_roles
from medicare.common.csrf import verify_csrf
from medicare.common.ids import ObjectId
from medicare.common.templating import VN_TZ, flash, render
from medicare.db import get_db

router = APIRouter()

receptionist_user = require_roles(Role.RECEPTIONIST)
invoice_reader = require_roles(Role.RECEPTIONIST, Role.ADMIN, Role.PATIENT)
billing_staff = require_roles(Role.RECEPTIONIST, Role.ADMIN)

STATUS_LABELS = {"UNPAID": ("Chưa thanh toán", "warning"), "PAID": ("Đã thanh toán", "success")}


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
        "is_billing_staff": user.role in (Role.RECEPTIONIST, Role.ADMIN),
        "status_labels": STATUS_LABELS,
        "breadcrumbs": [("Trang chủ", "/"), ("Hóa đơn", None)],
    })


def _parse_day(value: str, default: date) -> date:
    try:
        day = date.fromisoformat(value.strip())
    except ValueError:
        return default
    return day if date.min < day < date.max else default


@router.get("/invoices/unpaid")
def unpaid_invoices(
    request: Request,
    date_from: str = "",
    date_to: str = "",
    user: User = Depends(billing_staff),
    db: Session = Depends(get_db),
) -> Response:
    today = datetime.now(VN_TZ).date()
    first_day = _parse_day(date_from, today.replace(day=1))
    last_day = _parse_day(date_to, today)
    if first_day > last_day:
        first_day, last_day = last_day, first_day
    return render(request, "billing/unpaid.html", {
        "report": service.unpaid_between(db, first_day, last_day),
        "date_from": first_day,
        "date_to": last_day,
        "limit": service.UNPAID_LIMIT,
        "breadcrumbs": [("Trang chủ", "/"), ("Hóa đơn", "/invoices"),
                        ("Hóa đơn chưa thanh toán", None)],
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
