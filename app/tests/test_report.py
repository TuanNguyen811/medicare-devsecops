import re
from datetime import datetime

from medicare.appointment.models import Appointment, AppointmentStatus
from medicare.auth.models import Role
from medicare.common.templating import VN_TZ
from tests.conftest import login
from tests.factories import make_department, make_patient, make_user

URL = "/admin/reports/appointments"


def make_appt(db, doctor, when: datetime, status=AppointmentStatus.REQUESTED):
    appt = Appointment(patient_id=make_patient(db).id, doctor_id=doctor.id,
                       scheduled_at=when.replace(tzinfo=VN_TZ), reason="Khám định kỳ",
                       status=status, created_by_id=doctor.id)
    db.add(appt)
    db.flush()
    return appt


def stat_rows(html: str) -> list[list[str]]:
    rows = re.findall(r"<tr data-stat-row>(.*?)</tr>", html, re.DOTALL)
    return [[c.strip() for c in re.findall(r"<td[^>]*>(.*?)</td>", r, re.DOTALL)] for r in rows]


def seed(db):
    noi, ngoai = make_department(db, "NOI"), make_department(db, "NGOAI")
    doc_noi = make_user(db, Role.DOCTOR, department=noi)
    doc_ngoai = make_user(db, Role.DOCTOR, department=ngoai)
    make_appt(db, doc_noi, datetime(2026, 3, 2, 9, 0))
    make_appt(db, doc_noi, datetime(2026, 3, 2, 9, 30), AppointmentStatus.COMPLETED)
    make_appt(db, doc_noi, datetime(2026, 4, 6, 8, 0), AppointmentStatus.CANCELLED)
    make_appt(db, doc_ngoai, datetime(2026, 3, 20, 14, 0), AppointmentStatus.CONFIRMED)
    make_appt(db, doc_ngoai, datetime(2026, 5, 4, 10, 0))  # outside the range below


def test_admin_sees_monthly_counts_per_department(client, db):
    seed(db)
    login(client, make_user(db, Role.ADMIN))
    r = client.get(URL, params={"start": "2026-03-01", "end": "2026-04-30", "period": "month"})
    assert r.status_code == 200
    assert stat_rows(r.text) == [
        ["01/03/2026", "Khoa NGOAI", "1", "0", "1", "0", "0"],
        ["01/03/2026", "Khoa NOI", "2", "1", "0", "1", "0"],
        ["01/04/2026", "Khoa NOI", "1", "0", "0", "0", "1"],
    ]


def test_daily_grouping_uses_vietnam_local_date(client, db):
    dept = make_department(db)
    doc = make_user(db, Role.DOCTOR, department=dept)
    make_appt(db, doc, datetime(2026, 3, 2, 6, 30))  # 23:30 UTC on 1 March
    login(client, make_user(db, Role.ADMIN))
    r = client.get(URL, params={"start": "2026-03-01", "end": "2026-03-31", "period": "day"})
    assert [row[0] for row in stat_rows(r.text)] == ["02/03/2026"]


def test_default_range_is_current_year(client, db):
    login(client, make_user(db, Role.ADMIN))
    r = client.get(URL)
    year = datetime.now(VN_TZ).year
    assert r.status_code == 200
    assert f'value="{year}-01-01"' in r.text and f'value="{year}-12-31"' in r.text


def test_invalid_range_rejected(client, db):
    login(client, make_user(db, Role.ADMIN))
    r = client.get(URL, params={"start": "2026-04-01", "end": "2026-03-01"})
    assert r.status_code == 400 and "Khoảng thời gian" in r.text
    assert client.get(URL, params={"start": "01/03/2026"}).status_code == 400


def test_report_is_admin_only(client, db):
    for role in (Role.RECEPTIONIST, Role.DOCTOR):
        client.cookies.clear()
        login(client, make_user(db, role, department=make_department(db, f"K{role.value}")))
        assert client.get(URL).status_code == 403


def test_report_menu_link_for_admin(client, db):
    login(client, make_user(db, Role.ADMIN))
    assert f'href="{URL}"' in client.get("/").text
