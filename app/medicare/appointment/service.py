from datetime import datetime

from sqlalchemy import Select, false, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from medicare import policy
from medicare.appointment.models import Appointment, AppointmentStatus
from medicare.auth.models import Role, User
from medicare.common.errors import Conflict, NotFound
from medicare.patient.models import Patient
from medicare.patient.service import get_patient_for

SLOT_MINUTES = (0, 30)
DOUBLE_BOOKED = "Bác sĩ đã có lịch hẹn vào thời gian này"


class AppointmentError(ValueError):
    """Invalid booking request; the message is user-facing."""


def _scoped(user: User) -> Select:
    """Appointments the user may see (R-01, R-13)."""
    stmt = select(Appointment)
    if user.role in (Role.ADMIN, Role.RECEPTIONIST):
        return stmt
    if user.role == Role.DOCTOR:
        return stmt.where(Appointment.doctor_id == user.id)
    if user.role == Role.NURSE and user.department_id is not None:
        return stmt.join(Patient, Patient.id == Appointment.patient_id).where(
            Patient.department_id == user.department_id
        )
    if user.role == Role.PATIENT and user.patient_id is not None:
        return stmt.where(Appointment.patient_id == user.patient_id)
    return stmt.where(false())


def list_for(db: Session, user: User) -> list[Appointment]:
    stmt = _scoped(user).order_by(Appointment.scheduled_at.desc(), Appointment.id)
    return list(db.scalars(stmt))


def get_appointment_for(db: Session, user: User, appointment_id: int) -> Appointment:
    """Missing and not-visible both raise NotFound (R-15)."""
    appt = db.scalar(_scoped(user).where(Appointment.id == appointment_id))
    if appt is None:
        raise NotFound
    return appt


def bookable_doctors(db: Session) -> list[User]:
    stmt = (
        select(User)
        .where(User.role == Role.DOCTOR, User.is_active.is_(True))
        .order_by(User.full_name)
    )
    return list(db.scalars(stmt).unique())


def book(
    db: Session,
    user: User,
    patient_id: int | None,
    doctor_id: int,
    scheduled_at: datetime,
    reason: str,
    now: datetime,
) -> Appointment:
    """Book a slot. Patients book for themselves, reception for anyone (R-01, R-13)."""
    if user.role == Role.PATIENT:
        if patient_id is not None and patient_id != user.patient_id:
            raise NotFound
        patient_id = user.patient_id
    if patient_id is None:
        raise AppointmentError("Bệnh nhân: chưa chọn bệnh nhân")
    patient = get_patient_for(db, user, patient_id)
    if scheduled_at <= now:
        raise AppointmentError("Không thể đặt lịch hẹn trong quá khứ")
    if scheduled_at.minute not in SLOT_MINUTES or scheduled_at.second or scheduled_at.microsecond:
        raise AppointmentError("Giờ hẹn phải theo mốc 30 phút (:00 hoặc :30)")
    doctor = db.get(User, doctor_id)
    if doctor is None or doctor.role != Role.DOCTOR or not doctor.is_active:
        raise AppointmentError("Bác sĩ: giá trị không hợp lệ")
    appt = Appointment(
        patient_id=patient.id,
        doctor_id=doctor.id,
        scheduled_at=scheduled_at,
        reason=reason,
        status=AppointmentStatus.REQUESTED,
        created_by_id=user.id,
    )
    try:
        with db.begin_nested():
            db.add(appt)
            db.flush()
    except IntegrityError as exc:  # uq_doctor_slot_active: the DB is the source of truth
        raise Conflict(DOUBLE_BOOKED) from exc
    return appt


def confirm(appt: Appointment) -> None:
    if appt.status != AppointmentStatus.REQUESTED:
        raise Conflict("Chỉ xác nhận được lịch hẹn đang chờ duyệt")
    appt.status = AppointmentStatus.CONFIRMED


def cancel(user: User, appt: Appointment) -> bool:
    """Cancel if allowed (R-13); returns False when the user may not cancel it."""
    if not policy.can_cancel_appointment(user, appt):
        return False
    appt.status = AppointmentStatus.CANCELLED
    return True
