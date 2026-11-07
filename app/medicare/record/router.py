from datetime import date

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse, Response
from pydantic import ValidationError
from sqlalchemy.orm import Session

from medicare import policy
from medicare.audit import service as audit
from medicare.auth.models import Role, User
from medicare.common.auth import get_current_user, require_roles
from medicare.common.csrf import verify_csrf
from medicare.common.templating import flash, render
from medicare.db import get_db
from medicare.patient.models import Patient
from medicare.prescription import service as prescription_service
from medicare.record import service
from medicare.record.schemas import FIELD_LABELS, RecordForm, form_errors

router = APIRouter()

doctor_user = require_roles(Role.DOCTOR)
_FIELDS = tuple(FIELD_LABELS)


def _ip(request: Request) -> str | None:
    return request.client.host if request.client else None


def _crumbs(patient: Patient, *tail) -> list:
    return [("Trang chủ", "/"), ("Bệnh nhân", "/patients"),
            (patient.code, f"/patients/{patient.id}"),
            ("Bệnh án", f"/patients/{patient.id}/records"), *tail]


def _form_page(request, patient, *, action, title, values, errors=None, status_code=200):
    ctx = {"action": action, "title": title, "values": values, "errors": errors or [],
           "patient": patient, "breadcrumbs": _crumbs(patient, (title, None))}
    return render(request, "record/form.html", ctx, status_code=status_code)


@router.get("/patients/{patient_id}/records")
def list_records(
    request: Request,
    patient_id: int,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Response:
    patient = service.get_patient_for_records(db, user, patient_id)
    records = service.list_records(db, user, patient, _ip(request))
    db.commit()
    crumbs = _crumbs(patient)
    crumbs[-1] = ("Bệnh án", None)
    return render(request, "record/list.html", {
        "patient": patient, "records": records,
        "can_write": policy.can_write_record(user, patient), "breadcrumbs": crumbs,
    })


@router.get("/patients/{patient_id}/records/new")
def new_record_form(
    request: Request,
    patient_id: int,
    user: User = Depends(doctor_user),
    db: Session = Depends(get_db),
) -> Response:
    patient = service.get_patient_for_new_record(db, user, patient_id)
    return _form_page(request, patient, action=f"/patients/{patient.id}/records",
                      title="Thêm phiếu khám", values={"visit_date": date.today()})


@router.post("/patients/{patient_id}/records", dependencies=[Depends(verify_csrf)])
def create_record(
    request: Request,
    patient_id: int,
    visit_date: str = Form(""),
    symptoms: str = Form(""),
    diagnosis_code: str = Form(""),
    diagnosis_text: str = Form(""),
    notes: str = Form(""),
    user: User = Depends(doctor_user),
    db: Session = Depends(get_db),
) -> Response:
    patient = service.get_patient_for_new_record(db, user, patient_id)
    values = dict(zip(_FIELDS, (visit_date, symptoms, diagnosis_code, diagnosis_text, notes),
                      strict=True))
    try:
        data = RecordForm.model_validate(values)
    except ValidationError as exc:
        return _form_page(request, patient, action=f"/patients/{patient.id}/records",
                          title="Thêm phiếu khám", values=values, errors=form_errors(exc),
                          status_code=400)
    record = service.create_record(db, user, patient, data, _ip(request))
    db.commit()
    flash(request, "Đã lưu bệnh án")
    return RedirectResponse(f"/records/{record.id}", status_code=303)


@router.get("/records/{record_id}")
def record_detail(
    request: Request,
    record_id: int,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Response:
    record = service.get_record_for(db, user, record_id, _ip(request))
    db.commit()
    patient = db.get(Patient, record.patient_id)
    return render(request, "record/detail.html", {
        "record": record, "patient": patient,
        "can_write": policy.can_write_record(user, patient),
        "can_prescribe": policy.can_prescribe(user, patient),
        "prescriptions": prescription_service.list_for_record(db, record.id),
        "breadcrumbs": _crumbs(patient, (f"Phiếu khám #{record.id}", None)),
    })


@router.get("/records/{record_id}/edit")
def edit_record_form(
    request: Request,
    record_id: int,
    user: User = Depends(doctor_user),
    db: Session = Depends(get_db),
) -> Response:
    record = service.get_writable_record(db, user, record_id)
    audit.log_access(db, user, audit.VIEW_RECORD, service.ENTITY, record.id, _ip(request))
    db.commit()
    patient = db.get(Patient, record.patient_id)
    values = {f: getattr(record, f) for f in _FIELDS}
    return _form_page(request, patient, action=f"/records/{record.id}/edit",
                      title=f"Sửa phiếu khám #{record.id}", values=values)


@router.post("/records/{record_id}/edit", dependencies=[Depends(verify_csrf)])
def update_record(
    request: Request,
    record_id: int,
    visit_date: str = Form(""),
    symptoms: str = Form(""),
    diagnosis_code: str = Form(""),
    diagnosis_text: str = Form(""),
    notes: str = Form(""),
    user: User = Depends(doctor_user),
    db: Session = Depends(get_db),
) -> Response:
    record = service.get_writable_record(db, user, record_id)
    values = dict(zip(_FIELDS, (visit_date, symptoms, diagnosis_code, diagnosis_text, notes),
                      strict=True))
    try:
        data = RecordForm.model_validate(values)
    except ValidationError as exc:
        patient = db.get(Patient, record.patient_id)
        return _form_page(request, patient, action=f"/records/{record.id}/edit",
                          title=f"Sửa phiếu khám #{record.id}", values=values,
                          errors=form_errors(exc), status_code=400)
    service.update_record(db, user, record, data, _ip(request))
    db.commit()
    flash(request, "Đã cập nhật bệnh án")
    return RedirectResponse(f"/records/{record.id}", status_code=303)


@router.get("/api/v1/records/{record_id}")
def record_api(
    request: Request,
    record_id: int,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict:
    record = service.get_record_for(db, user, record_id, _ip(request))
    db.commit()
    return {
        "id": record.id,
        "patient_id": record.patient_id,
        "doctor_id": record.doctor_id,
        "visit_date": record.visit_date.isoformat(),
        "symptoms": record.symptoms,
        "diagnosis_code": record.diagnosis_code,
        "diagnosis_text": record.diagnosis_text,
        "notes": record.notes,
    }
