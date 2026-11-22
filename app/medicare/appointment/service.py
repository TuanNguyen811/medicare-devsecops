from datetime import date, datetime, time, timedelta

from sqlalchemy import Select, false, select
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
QUICK_SLOT_MINUTES = (0, 15, 30, 45)
VISIT_MINUTES = 30
QUICK_VISIT_MINUTES = 15
LONGEST_VISIT = timedelta(minutes=VISIT_MINUTES)
WORKING_HOURS = (time(8, 0), time(17, 0))
BOOKING_HORIZON = timedelta(days=365)
DOUBLE_BOOKED = "Bác sĩ đã có lịch hẹn vào thời gian này"


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


def _active_around(
    db: Session, doctor_id: int, start: datetime, end: datetime
) -> list[tuple[datetime, datetime]]:
    """(start, end) of the doctor's non-cancelled appointments overlapping [start, end)."""
    stmt = select(Appointment).where(
        Appointment.doctor_id == doctor_id,
        Appointment.status != AppointmentStatus.CANCELLED,
        Appointment.scheduled_at > start - LONGEST_VISIT,
        Appointment.scheduled_at < end,
    )
    busy = [(a.scheduled_at, a.scheduled_at + timedelta(minutes=a.duration_minutes))
            for a in db.scalars(stmt)]
    return [(s, e) for s, e in busy if e > start]


def free_slots(db: Session, doctor_id: int, day: date, now: datetime) -> list[datetime]:
    """Free quick-visit slots of a doctor on `day` (Vietnam time), within working hours."""
    start = datetime.combine(day, WORKING_HOURS[0], tzinfo=VN_TZ)
    end = datetime.combine(day, WORKING_HOURS[1], tzinfo=VN_TZ)
    step = timedelta(minutes=QUICK_VISIT_MINUTES)
    busy = _active_around(db, doctor_id, start, end)
    slots = []
    t = start
    while t + step <= end:
        if now < t <= now + BOOKING_HORIZON and not any(s < t + step and e > t for s, e in busy):
            slots.append(t)
        t += step
    return slots


def book(
    db: Session,
    user: User,
    patient_id: int | None,
    doctor_id: int,
    scheduled_at: datetime,
    reason: str,
    now: datetime,
    minutes: int = VISIT_MINUTES,
) -> Appointment:
    """Book a slot. Patients book for themselves, reception for anyone (R-01, R-13).

    `minutes` is VISIT_MINUTES for a regular visit, QUICK_VISIT_MINUTES for a quick one.
    """
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
    grid = QUICK_SLOT_MINUTES if minutes == QUICK_VISIT_MINUTES else SLOT_MINUTES
    if scheduled_at.minute not in grid or scheduled_at.second or scheduled_at.microsecond:
        raise AppointmentError(f"Giờ hẹn phải theo mốc {60 // len(grid)} phút")
    doctor = db.get(User, doctor_id)
    if doctor is None or doctor.role != Role.DOCTOR or not doctor.is_active:
        raise AppointmentError("Bác sĩ: giá trị không hợp lệ")
    end = scheduled_at + timedelta(minutes=minutes)
    if _active_around(db, doctor.id, scheduled_at, end):
        raise Conflict(DOUBLE_BOOKED)
    appt = Appointment(
        patient_id=patient.id,
        doctor_id=doctor.id,
        scheduled_at=scheduled_at,
        duration_minutes=minutes,
        reason=reason,
        status=AppointmentStatus.REQUESTED,
        created_by_id=user.id,
    )
    db.add(appt)
    db.flush()
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
