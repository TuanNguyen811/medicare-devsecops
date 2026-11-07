from datetime import UTC, datetime

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import RedirectResponse, Response
from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.orm import Session

from medicare import policy
from medicare.appointment import service
from medicare.appointment.schemas import FIELD_LABELS, AppointmentForm
from medicare.auth.models import Role, User
from medicare.common.auth import get_current_user, require_roles
from medicare.common.csrf import verify_csrf
from medicare.common.errors import Conflict
from medicare.common.ids import ObjectId
from medicare.common.templating import flash, render
from medicare.db import get_db
from medicare.patient.models import Patient

router = APIRouter()

booker_user = require_roles(Role.PATIENT, Role.RECEPTIONIST)
receptionist_user = require_roles(Role.RECEPTIONIST)

STATUS_LABELS = {
    "REQUESTED": ("Chờ duyệt", "warning"),
    "CONFIRMED": ("Đã xác nhận", "primary"),
    "COMPLETED": ("Hoàn thành", "success"),
    "CANCELLED": ("Đã hủy", "secondary"),
}
_CRUMBS = [("Trang chủ", "/"), ("Lịch hẹn", "/appointments")]


def _form_page(request, db, user, *, values, errors=None, status_code=200):
    patients = (
        list(db.scalars(select(Patient).order_by(Patient.code)).unique())
        if user.role == Role.RECEPTIONIST
        else []
    )
    ctx = {
        "values": values,
        "errors": errors or [],
        "patients": patients,
        "doctors": service.bookable_doctors(db),
        "breadcrumbs": [*_CRUMBS, ("Đặt lịch hẹn", None)],
    }
    return render(request, "appointment/form.html", ctx, status_code=status_code)


@router.get("/appointments")
def list_appointments(
    request: Request,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Response:
    rows = [(a, policy.can_cancel_appointment(user, a)) for a in service.list_for(db, user)]
    return render(
        request,
        "appointment/list.html",
        {
            "rows": rows,
            "status_labels": STATUS_LABELS,
            "can_book": user.role in (Role.PATIENT, Role.RECEPTIONIST),
            "can_confirm": user.role == Role.RECEPTIONIST,
            "breadcrumbs": [("Trang chủ", "/"), ("Lịch hẹn", None)],
        },
    )


@router.get("/appointments/new")
def new_appointment_form(
    request: Request,
    patient_id: str = "",
    user: User = Depends(booker_user),
    db: Session = Depends(get_db),
) -> Response:
    return _form_page(request, db, user, values={"patient_id": patient_id})


@router.post("/appointments", dependencies=[Depends(verify_csrf)])
def create_appointment(
    request: Request,
    patient_id: str = Form(""),
    doctor_id: str = Form(""),
    scheduled_at: str = Form(""),
    reason: str = Form(""),
    user: User = Depends(booker_user),
    db: Session = Depends(get_db),
) -> Response:
    values = {"patient_id": patient_id, "doctor_id": doctor_id,
              "scheduled_at": scheduled_at, "reason": reason}
    try:
        data = AppointmentForm.model_validate(values)
        service.book(db, user, data.patient_id, data.doctor_id, data.scheduled_at,
                     data.reason, datetime.now(UTC))
    except ValidationError as exc:
        errors = [f"{FIELD_LABELS.get(str(e['loc'][0]), e['loc'][0])}: giá trị không hợp lệ"
                  for e in exc.errors(include_input=False)]
        return _form_page(request, db, user, values=values, errors=errors, status_code=400)
    except service.AppointmentError as exc:
        return _form_page(request, db, user, values=values, errors=[str(exc)], status_code=400)
    except Conflict as exc:
        return _form_page(request, db, user, values=values, errors=[exc.detail], status_code=409)
    db.commit()
    flash(request, "Đã đặt lịch hẹn")
    return RedirectResponse("/appointments", status_code=303)


@router.post("/appointments/{appointment_id}/confirm", dependencies=[Depends(verify_csrf)])
def confirm_appointment(
    request: Request,
    appointment_id: ObjectId,
    user: User = Depends(receptionist_user),
    db: Session = Depends(get_db),
) -> Response:
    appt = service.get_appointment_for(db, user, appointment_id)
    service.confirm(appt)
    db.commit()
    flash(request, "Đã xác nhận lịch hẹn")
    return RedirectResponse("/appointments", status_code=303)


@router.post("/appointments/{appointment_id}/cancel", dependencies=[Depends(verify_csrf)])
def cancel_appointment(
    request: Request,
    appointment_id: ObjectId,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Response:
    appt = service.get_appointment_for(db, user, appointment_id)
    if not service.cancel(user, appt):
        raise HTTPException(status_code=403, detail="Forbidden")
    db.commit()
    flash(request, "Đã hủy lịch hẹn")
    return RedirectResponse("/appointments", status_code=303)


@router.get("/api/v1/appointments")
def appointments_api(
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> list[dict]:
    return [
        {
            "id": a.id,
            "patient_id": a.patient_id,
            "doctor_id": a.doctor_id,
            "scheduled_at": a.scheduled_at.isoformat(),
            "status": a.status.value,
            "reason": a.reason,
        }
        for a in service.list_for(db, user)
    ]
