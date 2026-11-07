import secrets

from sqlalchemy import false, or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from medicare import policy
from medicare.auth.models import Role, User
from medicare.common.errors import NotFound
from medicare.department.models import Department
from medicare.patient.models import Patient
from medicare.patient.schemas import PatientForm

SEARCH_LIMIT = 50


class PatientDataError(ValueError):
    """Business-rule violation in submitted patient data; message is user-facing."""


def get_patient_for(db: Session, user: User, patient_id: int) -> Patient:
    """Load a patient the user may see; missing and forbidden both raise NotFound (R-15)."""
    patient = db.get(Patient, patient_id)
    if patient is None or not policy.can_view_patient(user, patient):
        raise NotFound
    return patient


def _scope_filter(user: User):
    """SQL filter mirroring policy.can_view_patient for list queries (R-01, R-12)."""
    if user.role in (Role.ADMIN, Role.RECEPTIONIST):
        return None
    conditions = []
    if user.role in (Role.DOCTOR, Role.NURSE) and user.department_id is not None:
        conditions.append(Patient.department_id == user.department_id)
    if user.role == Role.DOCTOR:
        conditions.append(Patient.attending_doctor_id == user.id)
    if user.role == Role.PATIENT and user.patient_id is not None:
        conditions.append(Patient.id == user.patient_id)
    return or_(*conditions) if conditions else false()


def search_patients(db: Session, user: User, q: str | None) -> list[Patient]:
    stmt = select(Patient).order_by(Patient.code).limit(SEARCH_LIMIT)
    scope = _scope_filter(user)
    if scope is not None:
        stmt = stmt.where(scope)
    if q and q.strip():
        term = q.strip()
        stmt = stmt.where(
            or_(
                Patient.code.icontains(term, autoescape=True),
                Patient.full_name.icontains(term, autoescape=True),
            )
        )
    return list(db.scalars(stmt).unique())


def form_choices(db: Session) -> dict:
    departments = db.scalars(select(Department).order_by(Department.name)).all()
    doctors = db.scalars(
        select(User)
        .where(User.role == Role.DOCTOR, User.is_active.is_(True))
        .order_by(User.full_name)
    ).unique().all()
    return {"departments": departments, "doctors": doctors}


def _check_references(db: Session, data: PatientForm) -> None:
    if data.department_id is not None and db.get(Department, data.department_id) is None:
        raise PatientDataError("Khoa: giá trị không hợp lệ")
    if data.attending_doctor_id is not None:
        doctor = db.get(User, data.attending_doctor_id)
        if (
            doctor is None
            or doctor.role != Role.DOCTOR
            or not doctor.is_active
            or data.department_id is None
            or doctor.department_id != data.department_id
        ):
            raise PatientDataError(
                "Bác sĩ phụ trách: phải là bác sĩ đang hoạt động thuộc khoa điều trị"
            )


def _check_national_id_free(db: Session, national_id: str, exclude_id: int | None) -> None:
    stmt = select(Patient.id).where(Patient.national_id == national_id)
    if exclude_id is not None:
        stmt = stmt.where(Patient.id != exclude_id)
    if db.scalar(stmt) is not None:
        raise PatientDataError("CCCD: đã tồn tại trong hệ thống")


def _flush_unique(db: Session) -> None:
    try:
        with db.begin_nested():
            db.flush()
    except IntegrityError as exc:  # concurrent insert of the same CCCD
        raise PatientDataError("CCCD: đã tồn tại trong hệ thống") from exc


def create_patient(db: Session, data: PatientForm) -> Patient:
    _check_references(db, data)
    _check_national_id_free(db, data.national_id, None)
    # The code is derived from the id, so insert with a unique placeholder first.
    patient = Patient(code=f"TMP{secrets.token_hex(6)}", **data.model_dump())
    db.add(patient)
    _flush_unique(db)
    patient.code = f"BN{patient.id:06d}"
    db.flush()
    return patient


def update_patient(db: Session, patient: Patient, data: PatientForm) -> Patient:
    _check_references(db, data)
    _check_national_id_free(db, data.national_id, patient.id)
    for field, value in data.model_dump().items():
        setattr(patient, field, value)
    _flush_unique(db)
    return patient
