from datetime import datetime
from decimal import Decimal
from enum import StrEnum

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, Numeric, func
from sqlalchemy.orm import Mapped, mapped_column

from medicare.db import Base, str_enum


class InvoiceStatus(StrEnum):
    UNPAID = "UNPAID"
    PAID = "PAID"


class Invoice(Base):
    __tablename__ = "invoices"
    __table_args__ = (
        CheckConstraint("coverage_rate >= 0 AND coverage_rate <= 1", name="coverage_rate_range"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    record_id: Mapped[int] = mapped_column(ForeignKey("medical_records.id"), unique=True)
    patient_id: Mapped[int] = mapped_column(ForeignKey("patients.id"))
    created_by_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    total_amount: Mapped[Decimal] = mapped_column(Numeric(12, 0))
    coverage_rate: Mapped[Decimal] = mapped_column(Numeric(3, 2))
    insurance_amount: Mapped[Decimal] = mapped_column(Numeric(12, 0))
    patient_amount: Mapped[Decimal] = mapped_column(Numeric(12, 0))
    status: Mapped[InvoiceStatus] = mapped_column(str_enum(InvoiceStatus, "invoice_status"))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
