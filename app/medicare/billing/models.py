from datetime import datetime
from decimal import Decimal
from enum import StrEnum

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, Numeric, String, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from medicare.db import Base, str_enum
from medicare.patient.models import Patient


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

    patient: Mapped[Patient] = relationship(lazy="joined")
    lines: Mapped[list["InvoiceLine"]] = relationship(
        lazy="selectin", order_by="InvoiceLine.id"
    )


class InvoiceLine(Base):
    """A billed service; the unit price is copied from the catalog at billing time."""

    __tablename__ = "invoice_lines"

    id: Mapped[int] = mapped_column(primary_key=True)
    invoice_id: Mapped[int] = mapped_column(ForeignKey("invoices.id"), index=True)
    service_code: Mapped[str] = mapped_column(String(20))
    description: Mapped[str] = mapped_column(String(100))
    quantity: Mapped[int]
    unit_price: Mapped[Decimal] = mapped_column(Numeric(12, 0))
    amount: Mapped[Decimal] = mapped_column(Numeric(12, 0))
    created_by_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
