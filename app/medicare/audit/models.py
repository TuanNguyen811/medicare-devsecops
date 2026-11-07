from datetime import datetime

from sqlalchemy import DateTime, String, func
from sqlalchemy.orm import Mapped, mapped_column

from medicare.db import Base


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(primary_key=True)
    actor_id: Mapped[int]  # no FK: audit rows must survive deletion of the actor
    action: Mapped[str] = mapped_column(String(50))
    entity_type: Mapped[str] = mapped_column(String(50))
    entity_id: Mapped[int]
    ip: Mapped[str | None] = mapped_column(String(45))
    # Set by the database clock, not the application process (R-05, R-06).
    at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
