from datetime import datetime
from enum import StrEnum
from typing import TYPE_CHECKING

from sqlalchemy import DateTime, ForeignKey, Index, String, func, text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from medicare.db import Base, str_enum

if TYPE_CHECKING:
    from medicare.auth.models import User
    from medicare.patient.models import Patient


class AppointmentStatus(StrEnum):
    REQUESTED = "REQUESTED"
    CONFIRMED = "CONFIRMED"
    CANCELLED = "CANCELLED"
    COMPLETED = "COMPLETED"


class Appointment(Base):
    __tablename__ = "appointments"
    __table_args__ = (
        # A doctor cannot have two non-cancelled appointments at the same time.
        Index(
            "uq_doctor_slot_active",
            "doctor_id",
            "scheduled_at",
            unique=True,
            postgresql_where=text("status <> 'CANCELLED'"),
        ),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    patient_id: Mapped[int] = mapped_column(ForeignKey("patients.id"))
    doctor_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    scheduled_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    reason: Mapped[str] = mapped_column(String(500))
    status: Mapped[AppointmentStatus] = mapped_column(
        str_enum(AppointmentStatus, "appointment_status")
    )
    created_by_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    patient: Mapped["Patient"] = relationship(lazy="joined")
    doctor: Mapped["User"] = relationship(foreign_keys=[doctor_id], lazy="joined")
