from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse, Response
from sqlalchemy.orm import Session

from medicare.announcement import service
from medicare.announcement.models import Announcement
from medicare.auth.models import Role, User
from medicare.common.auth import require_roles
from medicare.common.csrf import verify_csrf
from medicare.common.errors import NotFound
from medicare.common.ids import ObjectId
from medicare.common.templating import flash, render
from medicare.db import get_db

router = APIRouter()

admin_user = require_roles(Role.ADMIN)


def _page(request: Request, db: Session, *, values=None, errors=None, status_code=200):
    return render(request, "announcement/admin.html", {
        "announcements": service.latest(db, limit=50),
        "values": values or {},
        "errors": errors or [],
        "max_body": service.MAX_BODY,
        "breadcrumbs": [("Trang chủ", "/"), ("Thông báo", None)],
    }, status_code=status_code)


@router.get("/admin/announcements")
def announcements_page(
    request: Request, user: User = Depends(admin_user), db: Session = Depends(get_db)
) -> Response:
    return _page(request, db)


@router.post("/admin/announcements", dependencies=[Depends(verify_csrf)])
def create_announcement(
    request: Request,
    title: str = Form(""),
    body: str = Form(""),
    user: User = Depends(admin_user),
    db: Session = Depends(get_db),
) -> Response:
    try:
        service.create(db, user, title, body)
    except service.AnnouncementError as exc:
        return _page(request, db, values={"title": title, "body": body}, errors=[str(exc)],
                     status_code=400)
    db.commit()
    flash(request, "Đã đăng thông báo")
    return RedirectResponse("/admin/announcements", status_code=303)


@router.post("/admin/announcements/{announcement_id}/delete",
             dependencies=[Depends(verify_csrf)])
def delete_announcement(
    request: Request,
    announcement_id: ObjectId,
    user: User = Depends(admin_user),
    db: Session = Depends(get_db),
) -> Response:
    announcement = db.get(Announcement, announcement_id)
    if announcement is None:
        raise NotFound
    service.delete(db, announcement)
    db.commit()
    flash(request, "Đã gỡ thông báo")
    return RedirectResponse("/admin/announcements", status_code=303)
