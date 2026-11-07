"""Read-only audit log viewer for ADMIN (R-06). Deliberately no write routes."""

from fastapi import APIRouter, Depends, Request
from fastapi.responses import Response
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from medicare.audit.models import AuditLog
from medicare.auth.models import Role, User
from medicare.common.auth import require_roles
from medicare.common.templating import render
from medicare.db import get_db

router = APIRouter()

admin_user = require_roles(Role.ADMIN)
PAGE_SIZE = 50


def _positive_int(value: str | None) -> int | None:
    if value and value.isascii() and value.isdigit() and len(value) <= 9:
        return int(value) or None
    return None


@router.get("/admin/audit")
def audit_page(
    request: Request,
    record_id: str | None = None,
    page: str | None = None,
    user: User = Depends(admin_user),
    db: Session = Depends(get_db),
) -> Response:
    rec = _positive_int(record_id)
    page_no = _positive_int(page) or 1
    stmt = select(AuditLog, User.username).outerjoin(User, User.id == AuditLog.actor_id)
    count = select(func.count()).select_from(AuditLog)
    if rec is not None:
        cond = (AuditLog.entity_type == "record") & (AuditLog.entity_id == rec)
        stmt, count = stmt.where(cond), count.where(cond)
    total = db.scalar(count) or 0
    rows = db.execute(
        stmt.order_by(AuditLog.at.desc(), AuditLog.id.desc())
        .limit(PAGE_SIZE)
        .offset((page_no - 1) * PAGE_SIZE)
    ).all()
    return render(request, "admin/audit.html", {
        "rows": rows,
        "record_id": rec,
        "page": page_no,
        "has_next": page_no * PAGE_SIZE < total,
        "total": total,
        "breadcrumbs": [("Trang chủ", "/"), ("Nhật ký truy cập", None)],
    })
