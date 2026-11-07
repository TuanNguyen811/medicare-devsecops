import re

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse, Response
from sqlalchemy.orm import Session

from medicare.auth.models import Role, User
from medicare.common.auth import get_current_user, require_roles
from medicare.common.csrf import verify_csrf
from medicare.common.ids import ObjectId
from medicare.common.templating import flash, render
from medicare.db import get_db
from medicare.patient.models import Patient
from medicare.prescription import service

router = APIRouter()

doctor_user = require_roles(Role.DOCTOR)
admin_user = require_roles(Role.ADMIN)
FORM_ROWS = 5
_MED_ID = re.compile(r"[0-9]{1,9}")  # always < INT4_MAX
_QTY = re.compile(r"-?[0-9]{1,9}")  # range is checked in the service


def _ip(request: Request) -> str | None:
    return request.client.host if request.client else None


def _parse_rows(medicine_ids, quantities, dosages) -> list[tuple[int, int, str]]:
    """Form rows → (medicine_id, quantity, dosage); fully blank rows are skipped."""
    if not (len(medicine_ids) == len(quantities) == len(dosages)):
        raise service.PrescriptionError("Dữ liệu đơn thuốc không hợp lệ")
    rows = []
    for med, qty, dosage in zip(medicine_ids, quantities, dosages, strict=True):
        med, qty, dosage = med.strip(), qty.strip(), dosage.strip()
        if not (med or qty or dosage):
            continue
        if not (_MED_ID.fullmatch(med) and _QTY.fullmatch(qty)):
            raise service.PrescriptionError("Thuốc và số lượng phải là số")
        rows.append((int(med), int(qty), dosage))
    return rows


def _form_page(request, db, record, *, values=None, errors=None, status_code=200):
    patient = db.get(Patient, record.patient_id)
    ctx = {
        "record": record,
        "patient": patient,
        "medicines": service.list_medicines(db, active_only=True),
        "rows": range(FORM_ROWS),
        "values": values or {},
        "errors": errors or [],
        "breadcrumbs": [("Trang chủ", "/"), ("Bệnh nhân", "/patients"),
                        (patient.code, f"/patients/{patient.id}"),
                        (f"Phiếu khám #{record.id}", f"/records/{record.id}"),
                        ("Kê đơn", None)],
    }
    return render(request, "prescription/form.html", ctx, status_code=status_code)


@router.get("/records/{record_id}/prescriptions/new")
def new_prescription_form(
    request: Request,
    record_id: ObjectId,
    user: User = Depends(doctor_user),
    db: Session = Depends(get_db),
) -> Response:
    record = service.get_record_for_prescribing(db, user, record_id)
    return _form_page(request, db, record)


@router.post("/records/{record_id}/prescriptions", dependencies=[Depends(verify_csrf)])
def create_prescription(
    request: Request,
    record_id: ObjectId,
    medicine_ids: list[str] = Form([], alias="medicine_id[]"),
    quantities: list[str] = Form([], alias="quantity[]"),
    dosages: list[str] = Form([], alias="dosage[]"),
    note: str = Form(""),
    user: User = Depends(doctor_user),
    db: Session = Depends(get_db),
) -> Response:
    record = service.get_record_for_prescribing(db, user, record_id)
    try:
        items = _parse_rows(medicine_ids, quantities, dosages)
        prescription = service.create_prescription(db, user, record.id, items, note.strip(),
                                                   _ip(request))
    except service.PrescriptionError as exc:
        return _form_page(request, db, record, values={"note": note}, errors=[str(exc)],
                          status_code=400)
    db.commit()
    flash(request, "Đã kê đơn thuốc")
    return RedirectResponse(f"/prescriptions/{prescription.id}", status_code=303)


@router.get("/prescriptions/{prescription_id}")
def prescription_detail(
    request: Request,
    prescription_id: ObjectId,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Response:
    prescription = service.get_prescription_for(db, user, prescription_id, _ip(request))
    db.commit()
    patient = db.get(Patient, prescription.patient_id)
    return render(request, "prescription/detail.html", {
        "prescription": prescription,
        "patient": patient,
        "total": service.prescription_total(prescription),
        "breadcrumbs": [("Trang chủ", "/"),
                        (f"Phiếu khám #{prescription.record_id}",
                         f"/records/{prescription.record_id}"),
                        (f"Đơn thuốc #{prescription.id}", None)],
    })


@router.get("/admin/medicines")
def medicines_page(
    request: Request,
    user: User = Depends(admin_user),
    db: Session = Depends(get_db),
) -> Response:
    return _medicines_page(request, db)


def _medicines_page(request, db, *, values=None, errors=None, status_code=200):
    return render(request, "prescription/medicines.html", {
        "medicines": service.list_medicines(db, active_only=False),
        "values": values or {},
        "errors": errors or [],
        "breadcrumbs": [("Trang chủ", "/"), ("Danh mục thuốc", None)],
    }, status_code=status_code)


@router.post("/admin/medicines", dependencies=[Depends(verify_csrf)])
def add_medicine(
    request: Request,
    code: str = Form(""),
    name: str = Form(""),
    unit: str = Form(""),
    unit_price: str = Form(""),
    user: User = Depends(admin_user),
    db: Session = Depends(get_db),
) -> Response:
    try:
        service.add_medicine(db, code, name, unit, unit_price)
    except service.PrescriptionError as exc:
        values = {"code": code, "name": name, "unit": unit, "unit_price": unit_price}
        return _medicines_page(request, db, values=values, errors=[str(exc)], status_code=400)
    db.commit()
    flash(request, "Đã thêm thuốc vào danh mục")
    return RedirectResponse("/admin/medicines", status_code=303)
