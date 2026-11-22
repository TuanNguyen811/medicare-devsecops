from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse, Response
from sqlalchemy.orm import Session

from medicare.auth.models import Role, User
from medicare.billing import service
from medicare.billing.catalog import SERVICES
from medicare.common.auth import get_current_user, require_roles
from medicare.common.csrf import verify_csrf
from medicare.common.ids import ObjectId
from medicare.common.templating import flash, render
from medicare.db import get_db

router = APIRouter()

receptionist_user = require_roles(Role.RECEPTIONIST)
invoice_reader = require_roles(Role.RECEPTIONIST, Role.ADMIN, Role.PATIENT)

STATUS_LABELS = {"UNPAID": ("Chưa thanh toán", "warning"), "PAID": ("Đã thanh toán", "success")}
LINE_ROWS = 5


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
    services_amount = service.services_amount(invoice)
    return render(request, "billing/detail.html", {
        "invoice": invoice,
        "exam_fee": service.EXAM_FEE,
        "drug_cost": invoice.total_amount - service.EXAM_FEE - services_amount,
        "services_amount": services_amount,
        "can_pay": user.role == Role.RECEPTIONIST,
        "catalog": SERVICES,
        "line_rows": LINE_ROWS,
        "status_labels": STATUS_LABELS,
        "breadcrumbs": [("Trang chủ", "/"), ("Hóa đơn", "/invoices"),
                        (f"Hóa đơn #{invoice.id}", None)],
    })


@router.post("/invoices/{invoice_id}/lines", dependencies=[Depends(verify_csrf)])
def add_invoice_lines(
    request: Request,
    invoice_id: ObjectId,
    service_code: list[str] = Form([]),
    quantity: list[str] = Form([]),
    user: User = Depends(receptionist_user),
    db: Session = Depends(get_db),
) -> Response:
    # R-17: only service codes and quantities are read; prices come from the catalog.
    invoice = service.get_invoice_for(db, user, invoice_id)
    try:
        service.add_lines(db, user, invoice, service.parse_lines(service_code, quantity))
    except service.BillingError as exc:
        flash(request, str(exc), "danger")
        return RedirectResponse(f"/invoices/{invoice.id}", status_code=303)
    db.commit()
    flash(request, f"Đã thêm dịch vụ vào hóa đơn #{invoice.id}")
    return RedirectResponse(f"/invoices/{invoice.id}", status_code=303)


@router.post("/invoices/{invoice_id}/status", dependencies=[Depends(verify_csrf)])
def change_invoice_status(
    request: Request,
    invoice_id: ObjectId,
    status: str = Form(""),
    user: User = Depends(receptionist_user),
    db: Session = Depends(get_db),
) -> Response:
    invoice = service.get_invoice_for(db, user, invoice_id)
    try:
        service.change_status(invoice, status)
    except service.BillingError as exc:
        flash(request, str(exc), "danger")
        return RedirectResponse(f"/invoices/{invoice.id}", status_code=303)
    db.commit()
    label, _ = STATUS_LABELS[invoice.status.value]
    flash(request, f"Hóa đơn #{invoice.id}: {label}")
    return RedirectResponse(f"/invoices/{invoice.id}", status_code=303)
