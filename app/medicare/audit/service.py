"""Append-only access log for clinical data (R-05, R-06)."""

from sqlalchemy.orm import Session

from medicare.audit.models import AuditLog
from medicare.auth.models import User

VIEW_RECORD = "VIEW_RECORD"
LIST_RECORDS = "LIST_RECORDS"
CREATE_RECORD = "CREATE_RECORD"
UPDATE_RECORD = "UPDATE_RECORD"
VIEW_PRESCRIPTION = "VIEW_PRESCRIPTION"
CREATE_PRESCRIPTION = "CREATE_PRESCRIPTION"


def log_access(
    db: Session, actor: User, action: str, entity_type: str, entity_id: int, ip: str | None
) -> None:
    """Record who touched which clinical object. Never stores the object's content."""
    db.add(
        AuditLog(actor_id=actor.id, action=action, entity_type=entity_type,
                 entity_id=entity_id, ip=ip)
    )
    db.flush()
