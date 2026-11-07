from datetime import date, datetime, timedelta, timezone
from decimal import ROUND_HALF_UP, Decimal
from pathlib import Path
from typing import Any

from fastapi import Request
from fastapi.responses import Response
from fastapi.templating import Jinja2Templates

from medicare.auth.models import Role
from medicare.common.csrf import get_csrf_token

VN_TZ = timezone(timedelta(hours=7))  # Vietnam has no DST

ROLE_LABELS = {
    Role.ADMIN: "Quản trị viên",
    Role.RECEPTIONIST: "Lễ tân",
    Role.DOCTOR: "Bác sĩ",
    Role.NURSE: "Điều dưỡng",
    Role.PATIENT: "Bệnh nhân",
}

templates = Jinja2Templates(directory=str(Path(__file__).resolve().parent.parent / "templates"))


def date_vn(value: date | None) -> str:
    return "" if value is None else value.strftime("%d/%m/%Y")


def datetime_vn(value: datetime | None) -> str:
    if value is None:
        return ""
    if value.tzinfo is not None:
        value = value.astimezone(VN_TZ)
    return value.strftime("%d/%m/%Y %H:%M")


def vnd(value: Decimal | int | None) -> str:
    if value is None:
        return ""
    amount = Decimal(value).quantize(Decimal(1), rounding=ROUND_HALF_UP)
    return f"{amount:,}".replace(",", ".") + " ₫"


templates.env.filters["date_vn"] = date_vn
templates.env.filters["datetime_vn"] = datetime_vn
templates.env.filters["vnd"] = vnd
templates.env.globals["role_labels"] = ROLE_LABELS


def flash(request: Request, message: str, category: str = "success") -> None:
    request.session.setdefault("flash", []).append([category, message])


def render(
    request: Request, name: str, ctx: dict[str, Any] | None = None, status_code: int = 200
) -> Response:
    """Render a template with `current_user` and `csrf_token` always in its context.

    Works without a session (error pages rendered outside SessionMiddleware).
    """
    has_session = "session" in request.scope
    context: dict[str, Any] = {
        "current_user": getattr(request.state, "current_user", None),
        "csrf_token": get_csrf_token(request) if has_session else "",
        "flashes": request.session.pop("flash", []) if has_session else [],
    }
    context.update(ctx or {})
    return templates.TemplateResponse(request, name, context, status_code=status_code)
