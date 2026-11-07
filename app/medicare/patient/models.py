from datetime import date, datetime

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, String, func
from sqlalchemy.orm import Mapped, mapped_column

from medicare.db import Base


class Patient(Base):
    __tablename__ = "patients"
    __table_args__ = (
        CheckConstraint("gender IN ('M', 'F')", name="gender"),
        CheckConstraint("national_id ~ '^[0-9]{12}$'", name="national_id_format"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    code: Mapped[str] = mapped_column(String(20), unique=True)  # e.g. "BN000001"
    full_name: Mapped[str] = mapped_column(String(100))
    date_of_birth: Mapped[date]
    gender: Mapped[str] = mapped_column(String(1))
    national_id: Mapped[str] = mapped_column(String(12), unique=True)
    insurance_number: Mapped[str | None] = mapped_column(String(15))
    phone: Mapped[str] = mapped_column(String(20))
    address: Mapped[str] = mapped_column(String(255))
    department_id: Mapped[int | None] = mapped_column(ForeignKey("departments.id"))
    attending_doctor_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
