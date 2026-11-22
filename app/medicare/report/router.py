from datetime import date, datetime

from fastapi import APIRouter, Depends, Request
from fastapi.responses import Response
from sqlalchemy.orm import Session

from medicare.auth.models import Role, User
from medicare.common.auth import require_roles
from medicare.common.templating import VN_TZ, render
from medicare.db import get_db
from medicare.report import service

router = APIRouter()

admin_user = require_roles(Role.ADMIN)


def _parse_day(value: str) -> date | None:
    try:
        day = date.fromisoformat(value.strip())
    except ValueError:
        return None
    return day if 2000 <= day.year <= 2100 else None


@router.get("/admin/reports/appointments")
def appointment_report(
    request: Request,
    start: str = "",
    end: str = "",
    period: str = service.DEFAULT_PERIOD,
    user: User = Depends(admin_user),
    db: Session = Depends(get_db),
) -> Response:
    today = datetime.now(VN_TZ).date()
    first = _parse_day(start) if start else date(today.year, 1, 1)
    last = _parse_day(end) if end else date(today.year, 12, 31)
    error, rows, status_code = None, [], 200
    if first is None or last is None:
        error, status_code = "Ngày không hợp lệ", 400
    elif last < first or last - first > service.MAX_RANGE:
        error, status_code = "Khoảng thời gian phải từ 1 đến 366 ngày", 400
    else:
        rows = service.appointment_stats(db, first, last, period or service.DEFAULT_PERIOD)
    return render(request, "admin/report_appointments.html", {
        "rows": rows,
        "totals": service.totals(rows),
        "form": {"start": first.isoformat() if first else start,
                 "end": last.isoformat() if last else end,
                 "period": period},
        "periods": service.PERIODS,
        "error": error,
        "breadcrumbs": [("Trang chủ", "/"), ("Thống kê lịch hẹn", None)],
    }, status_code=status_code)
