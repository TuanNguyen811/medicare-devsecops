from dataclasses import dataclass
from datetime import date, datetime, time, timedelta

from sqlalchemy import Select, false, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from medicare import policy
from medicare.appointment.models import Appointment, AppointmentStatus
from medicare.auth.models import Role, User
from medicare.common import metrics
from medicare.common.errors import Conflict, NotFound
from medicare.common.templating import VN_TZ
from medicare.patient.models import Patient
from medicare.patient.service import get_patient_for

SLOT_MINUTES = (0, 30)
BOOKING_HORIZON = timedelta(days=365)
DOUBLE_BOOKED = "Bác sĩ đã có lịch hẹn vào thời gian này"
SCHEDULE_PAGE_SIZE = 20


class AppointmentError(ValueError):
    """Invalid booking request; the message is user-facing."""


def _scoped(user: User) -> Select:
    """SQL mirror of policy.can_view_appointment for list queries (R-01, R-13)."""
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


@dataclass
class SchedulePage:
    items: list[Appointment]
    total: int
    page: int
    pages: int


def schedule_for(
    db: Session,
    user: User,
    day: date,
    *,
    status: AppointmentStatus | None = None,
    doctor_id: int | None = None,
    page: int = 1,
) -> SchedulePage:
    """Appointments of one calendar day (Vietnam time) in the user's scope, one page at a time."""
    start = datetime.combine(day, time.min, tzinfo=VN_TZ)
    stmt = _scoped(user).where(
        Appointment.scheduled_at >= start,
        Appointment.scheduled_at < start + timedelta(days=1),
    )
    if status is not None:
        stmt = stmt.where(Appointment.status == status)
    if doctor_id is not None:
        stmt = stmt.where(Appointment.doctor_id == doctor_id)
    total = db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    pages = max(1, -(-total // SCHEDULE_PAGE_SIZE))
    page = min(max(page, 1), pages)
    stmt = (
        stmt.order_by(Appointment.scheduled_at, Appointment.id)
        .limit(SCHEDULE_PAGE_SIZE)
        .offset((page - 1) * SCHEDULE_PAGE_SIZE)
    )
    return SchedulePage(items=list(db.scalars(stmt)), total=total, page=page, pages=pages)


def get_appointment_for(db: Session, user: User, appointment_id: int) -> Appointment:
    """Missing and not-visible both raise NotFound (R-15)."""
    appt = db.get(Appointment, appointment_id)
    if appt is None:
        raise NotFound
    if not policy.can_view_appointment(user, appt, appt.patient):
        metrics.authz_denied("appointment")
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
            if db.get(Patient, patient_id) is not None:  # count refusals of real patients only
                metrics.authz_denied("appointment")
            raise NotFound
        patient_id = user.patient_id
    if patient_id is None:
        raise AppointmentError("Bệnh nhân: chưa chọn bệnh nhân")
    patient = get_patient_for(db, user, patient_id)
    if scheduled_at <= now:
        raise AppointmentError("Không thể đặt lịch hẹn trong quá khứ")
    if scheduled_at > now + BOOKING_HORIZON:
        raise AppointmentError("Chỉ đặt lịch trong vòng 365 ngày tới")
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
        # Count refusals about who may cancel, not about the appointment's status.
        staff_or_owner = user.role in (Role.ADMIN, Role.RECEPTIONIST) or (
            user.role == Role.PATIENT and user.patient_id == appt.patient_id
        )
        if not staff_or_owner:
            metrics.authz_denied("appointment")
        return False
    appt.status = AppointmentStatus.CANCELLED
    return True
