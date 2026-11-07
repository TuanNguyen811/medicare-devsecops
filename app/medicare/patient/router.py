from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse, Response
from pydantic import ValidationError
from sqlalchemy.orm import Session

from medicare import policy
from medicare.auth.models import Role, User
from medicare.common.auth import get_current_user, require_roles
from medicare.common.csrf import verify_csrf
from medicare.common.errors import NotFound
from medicare.common.templating import flash, render
from medicare.db import get_db
from medicare.patient import service
from medicare.patient.models import Patient
from medicare.patient.schemas import FIELD_LABELS, PatientForm, form_errors
from medicare.validators import mask

router = APIRouter()

STAFF = (Role.RECEPTIONIST, Role.ADMIN, Role.DOCTOR, Role.NURSE)
EDITORS = (Role.RECEPTIONIST, Role.ADMIN)
staff_user = require_roles(*STAFF)
editor_user = require_roles(*EDITORS)
patient_user = require_roles(Role.PATIENT)
_FORM_FIELDS = tuple(FIELD_LABELS)


def _identifiers(user: User, patient: Patient) -> dict[str, str | None]:
    """National ID / BHYT number, masked unless the user may see them in full (R-11)."""
    if policy.can_view_identifiers(user, patient):
        return {"national_id": patient.national_id, "insurance_number": patient.insurance_number}
    return {
        "national_id": mask(patient.national_id),
        "insurance_number": mask(patient.insurance_number) if patient.insurance_number else None,
    }


def _detail_ctx(user: User, patient: Patient, crumbs: list) -> dict:
    return {
        "patient": patient,
        "ids": _identifiers(user, patient),
        "can_edit": policy.can_edit_patient(user),
        "can_view_records": policy.can_view_record(user, patient),
        "breadcrumbs": crumbs,
    }


def _form_page(request, db, *, action, title, values, errors=None, status_code=200):
    ctx = {
        "action": action,
        "title": title,
        "values": values,
        "errors": errors or [],
        "breadcrumbs": [("Trang chủ", "/"), ("Bệnh nhân", "/patients"), (title, None)],
    } | service.form_choices(db)
    return render(request, "patient/form.html", ctx, status_code=status_code)


def _submitted(full_name, date_of_birth, gender, national_id, insurance_number, phone,
               address, department_id, attending_doctor_id) -> dict[str, str]:
    return dict(zip(_FORM_FIELDS, (full_name, date_of_birth, gender, national_id,
                                   insurance_number, phone, address, department_id,
                                   attending_doctor_id), strict=True))


@router.get("/patients")
def list_patients(
    request: Request,
    q: str | None = None,
    user: User = Depends(staff_user),
    db: Session = Depends(get_db),
) -> Response:
    patients = service.search_patients(db, user, q)
    rows = [(p, _identifiers(user, p)) for p in patients]
    return render(
        request,
        "patient/list.html",
        {
            "rows": rows,
            "q": q or "",
            "can_create": policy.can_edit_patient(user),
            "breadcrumbs": [("Trang chủ", "/"), ("Bệnh nhân", None)],
        },
    )


@router.get("/patients/new")
def new_patient_form(
    request: Request,
    user: User = Depends(editor_user),
    db: Session = Depends(get_db),
) -> Response:
    return _form_page(request, db, action="/patients", title="Tiếp nhận bệnh nhân", values={})


@router.post("/patients", dependencies=[Depends(verify_csrf)])
def create_patient(
    request: Request,
    full_name: str = Form(""),
    date_of_birth: str = Form(""),
    gender: str = Form(""),
    national_id: str = Form(""),
    insurance_number: str = Form(""),
    phone: str = Form(""),
    address: str = Form(""),
    department_id: str = Form(""),
    attending_doctor_id: str = Form(""),
    user: User = Depends(editor_user),
    db: Session = Depends(get_db),
) -> Response:
    values = _submitted(full_name, date_of_birth, gender, national_id, insurance_number,
                        phone, address, department_id, attending_doctor_id)
    page = {"action": "/patients", "title": "Tiếp nhận bệnh nhân", "values": values}
    try:
        patient = service.create_patient(db, PatientForm.model_validate(values))
    except ValidationError as exc:
        return _form_page(request, db, errors=form_errors(exc), status_code=400, **page)
    except service.PatientDataError as exc:
        return _form_page(request, db, errors=[str(exc)], status_code=400, **page)
    db.commit()
    flash(request, f"Đã tiếp nhận bệnh nhân {patient.code}")
    return RedirectResponse(f"/patients/{patient.id}", status_code=303)


@router.get("/patients/{patient_id}")
def patient_detail(
    request: Request,
    patient_id: int,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Response:
    patient = service.get_patient_for(db, user, patient_id)
    crumbs = [("Trang chủ", "/"), ("Bệnh nhân", "/patients"), (patient.code, None)]
    return render(request, "patient/detail.html", _detail_ctx(user, patient, crumbs))


@router.get("/patients/{patient_id}/edit")
def edit_patient_form(
    request: Request,
    patient_id: int,
    user: User = Depends(editor_user),
    db: Session = Depends(get_db),
) -> Response:
    patient = service.get_patient_for(db, user, patient_id)
    values = {f: getattr(patient, f) for f in _FORM_FIELDS}
    return _form_page(request, db, action=f"/patients/{patient.id}/edit",
                      title=f"Sửa hồ sơ {patient.code}", values=values)


@router.post("/patients/{patient_id}/edit", dependencies=[Depends(verify_csrf)])
def update_patient(
    request: Request,
    patient_id: int,
    full_name: str = Form(""),
    date_of_birth: str = Form(""),
    gender: str = Form(""),
    national_id: str = Form(""),
    insurance_number: str = Form(""),
    phone: str = Form(""),
    address: str = Form(""),
    department_id: str = Form(""),
    attending_doctor_id: str = Form(""),
    user: User = Depends(editor_user),
    db: Session = Depends(get_db),
) -> Response:
    patient = service.get_patient_for(db, user, patient_id)
    values = _submitted(full_name, date_of_birth, gender, national_id, insurance_number,
                        phone, address, department_id, attending_doctor_id)
    page = {"action": f"/patients/{patient.id}/edit", "title": f"Sửa hồ sơ {patient.code}",
            "values": values}
    try:
        service.update_patient(db, patient, PatientForm.model_validate(values))
    except ValidationError as exc:
        return _form_page(request, db, errors=form_errors(exc), status_code=400, **page)
    except service.PatientDataError as exc:
        return _form_page(request, db, errors=[str(exc)], status_code=400, **page)
    db.commit()
    flash(request, "Đã cập nhật hồ sơ bệnh nhân")
    return RedirectResponse(f"/patients/{patient.id}", status_code=303)


@router.get("/me")
def my_profile(
    request: Request,
    user: User = Depends(patient_user),
    db: Session = Depends(get_db),
) -> Response:
    if user.patient_id is None:
        raise NotFound
    patient = service.get_patient_for(db, user, user.patient_id)
    crumbs = [("Trang chủ", "/"), ("Hồ sơ của tôi", None)]
    return render(request, "patient/detail.html", _detail_ctx(user, patient, crumbs))


@router.get("/api/v1/patients/{patient_id}")
def patient_api(
    patient_id: int,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict:
    patient = service.get_patient_for(db, user, patient_id)
    return {
        "id": patient.id,
        "code": patient.code,
        "full_name": patient.full_name,
        "date_of_birth": patient.date_of_birth.isoformat(),
        **_identifiers(user, patient),
        "department_id": patient.department_id,
    }
