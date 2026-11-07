from datetime import date, datetime
from typing import TYPE_CHECKING

from sqlalchemy import DateTime, ForeignKey, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from medicare.db import Base

if TYPE_CHECKING:
    from medicare.auth.models import User
    from medicare.patient.models import Patient


class MedicalRecord(Base):
    __tablename__ = "medical_records"

    id: Mapped[int] = mapped_column(primary_key=True)
    patient_id: Mapped[int] = mapped_column(ForeignKey("patients.id"))
    doctor_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    visit_date: Mapped[date]
    symptoms: Mapped[str] = mapped_column(Text)
    diagnosis_code: Mapped[str] = mapped_column(String(20))
    diagnosis_text: Mapped[str] = mapped_column(String(500))
    notes: Mapped[str] = mapped_column(Text, default="", server_default="")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    doctor: Mapped["User"] = relationship(lazy="joined")
    patient: Mapped["Patient"] = relationship(lazy="joined")
