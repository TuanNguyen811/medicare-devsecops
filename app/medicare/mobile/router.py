"""JSON API for the MediCare mobile app, authenticated with bearer tokens."""

from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from medicare.appointment import service as appointment_service
from medicare.auth.models import User
from medicare.auth.router import LOGIN_ERROR, MAX_PASSWORD_LENGTH
from medicare.common import metrics
from medicare.common.auth import authenticate
from medicare.common.ids import ObjectId
from medicare.db import get_db
from medicare.mobile.tokens import TOKEN_TTL, get_mobile_user, issue_token
from medicare.record import service as record_service
from medicare.record.models import MedicalRecord

router = APIRouter(prefix="/api/v1/mobile")


class TokenRequest(BaseModel):
    username: str = Field(max_length=50)
    password: str = Field(max_length=MAX_PASSWORD_LENGTH)


def _ip(request: Request) -> str | None:
    return request.client.host if request.client else None


def _record(record: MedicalRecord) -> dict:
    return {
        "id": record.id,
        "patient_id": record.patient_id,
        "doctor": record.doctor.full_name,
        "visit_date": record.visit_date.isoformat(),
        "symptoms": record.symptoms,
        "diagnosis_code": record.diagnosis_code,
        "diagnosis_text": record.diagnosis_text,
        "notes": record.notes,
    }


@router.post("/token")
def create_token(body: TokenRequest, db: Session = Depends(get_db)) -> dict:
    user = None
    if "\x00" not in body.username and "\x00" not in body.password:
        user = authenticate(db, body.username, body.password, datetime.now(UTC))
    else:
        metrics.login_attempt(metrics.LOGIN_FAILURE)
    db.commit()  # persists the failed-attempt counter and lock (R-07)
    if user is None:
        raise HTTPException(status_code=401, detail=LOGIN_ERROR)
    return {
        "access_token": issue_token(user, datetime.now(UTC)),
        "token_type": "bearer",
        "expires_in": int(TOKEN_TTL.total_seconds()),
    }


@router.get("/me")
def me(user: User = Depends(get_mobile_user)) -> dict:
    return {
        "id": user.id,
        "username": user.username,
        "full_name": user.full_name,
        "role": user.role.value,
        "department": user.department.name if user.department else None,
        "patient_id": user.patient_id,
    }


@router.get("/appointments")
def my_appointments(
    user: User = Depends(get_mobile_user), db: Session = Depends(get_db)
) -> list[dict]:
    return [
        {
            "id": appt.id,
            "scheduled_at": appt.scheduled_at.isoformat(),
            "status": appt.status.value,
            "doctor": appt.doctor.full_name,
            "patient_code": appt.patient.code,
            "patient_name": appt.patient.full_name,
            "reason": appt.reason,
        }
        for appt in appointment_service.list_for(db, user)
    ]


@router.get("/patients/{patient_id}/records")
def patient_records(
    request: Request,
    patient_id: ObjectId,
    user: User = Depends(get_mobile_user),
    db: Session = Depends(get_db),
) -> list[dict]:
    patient = record_service.get_patient_for_records(db, user, patient_id)
    records = record_service.list_records(db, user, patient, _ip(request))
    db.commit()
    return [
        {"id": r.id, "visit_date": r.visit_date.isoformat(), "diagnosis_code": r.diagnosis_code,
         "diagnosis_text": r.diagnosis_text, "doctor": r.doctor.full_name}
        for r in records
    ]


@router.get("/records/{record_id}")
def record_detail(
    request: Request,
    record_id: ObjectId,
    user: User = Depends(get_mobile_user),
    db: Session = Depends(get_db),
) -> dict:
    record = record_service.get_record_for(db, user, record_id, _ip(request))
    db.commit()
    return _record(record)
