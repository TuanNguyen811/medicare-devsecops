"""Regression tests for the final whole-branch review (C1, I1, I3)."""

from datetime import date, timedelta

import pytest

from medicare.auth.models import Role
from tests.conftest import csrf_token, login
from tests.factories import make_department, make_medicine, make_patient, make_record, make_user

BIG = 2**31  # one past PostgreSQL INTEGER max
MISSING = 999_999


# --- C1: appointment time must be Vietnam wall-clock, on a 30-minute slot, within a horizon


def _book(client, db, scheduled_at):
    doc = make_user(db, Role.DOCTOR, department=make_department(db))
    login(client, make_user(db, Role.PATIENT, patient=make_patient(db)))
    return client.post("/appointments", data={
        "doctor_id": str(doc.id), "scheduled_at": scheduled_at, "reason": "Khám",
        "csrf_token": csrf_token(client, "/appointments/new")}, follow_redirects=False)


@pytest.mark.parametrize("value", [
    "9999-12-31T23:30-12:00",  # overflows to year 10000 in UTC
    f"{date.today() + timedelta(days=3)}T09:00+05:45",  # off-slot once converted
])
def test_booking_with_timezone_offset_rejected(client, db, value):
    assert _book(client, db, value).status_code == 400
    assert client.get("/appointments").status_code == 200


def test_booking_beyond_horizon_rejected(client, db):
    assert _book(client, db, "9999-12-31T23:30").status_code == 400


# --- I1: out-of-range ids behave exactly like missing ids


HTML_GETS = ["/patients/{}", "/patients/{}/edit", "/patients/{}/records", "/records/{}",
             "/prescriptions/{}", "/invoices/{}"]
API_GETS = ["/api/v1/patients/{}", "/api/v1/records/{}"]
POSTS = ["/appointments/{}/cancel", "/admin/users/{}/deactivate", "/invoices/{}/pay",
         "/records/{}/invoice"]


@pytest.mark.parametrize("path", HTML_GETS + API_GETS)
def test_out_of_range_id_is_indistinguishable_from_missing(client, db, path):
    login(client, make_user(db, Role.ADMIN))
    # missing first: in tests all requests share one DB session, and a failed query
    # would poison the transaction for the request after it.
    missing = client.get(path.format(MISSING))
    big = client.get(path.format(BIG))
    assert big.status_code == missing.status_code
    assert big.text == missing.text


@pytest.mark.parametrize("path", POSTS)
def test_out_of_range_id_on_post_is_not_500(client, db, path):
    login(client, make_user(db, Role.RECEPTIONIST))
    token = csrf_token(client, "/")
    missing = client.post(path.format(MISSING), data={"csrf_token": token})  # see above
    big = client.post(path.format(BIG), data={"csrf_token": token})
    assert big.status_code == missing.status_code != 500


def test_non_numeric_id_is_404_not_422(client, db):
    login(client, make_user(db, Role.RECEPTIONIST))
    r = client.get("/patients/abc")
    assert r.status_code == 404 and "abc" not in r.text
    api = client.get("/api/v1/patients/abc")
    assert api.status_code == 404 and api.json() == {"detail": "Not Found"}


def test_nul_byte_in_login_gives_generic_message(client, db):
    r = client.post("/login", data={"username": "a\x00b", "password": "x",
                                    "csrf_token": csrf_token(client)})
    assert r.status_code == 200 and "Tên đăng nhập hoặc mật khẩu không đúng" in r.text


def test_nul_byte_in_search_is_400(client, db):
    login(client, make_user(db, Role.RECEPTIONIST))
    assert client.get("/patients", params={"q": "a\x00"}).status_code == 400


def test_form_ids_out_of_range_are_400(client, db):
    login(client, make_user(db, Role.RECEPTIONIST))
    r = client.post("/patients", data={
        "full_name": "A", "date_of_birth": "1990-01-01", "gender": "M",
        "national_id": "012345678901", "phone": "0901234567", "address": "x",
        "department_id": str(BIG), "csrf_token": csrf_token(client, "/patients/new")})
    assert r.status_code == 400
    r = client.post("/appointments", data={
        "patient_id": str(BIG), "doctor_id": "1", "reason": "x",
        "scheduled_at": f"{date.today() + timedelta(days=1)}T09:00",
        "csrf_token": csrf_token(client, "/appointments/new")})
    assert r.status_code == 400


def test_admin_form_huge_numbers_are_400(client, db):
    login(client, make_user(db, Role.ADMIN))
    token = csrf_token(client, "/admin/users")
    r = client.post("/admin/users", data={
        "username": "bn99", "full_name": "X", "role": "PATIENT", "patient_id": "9" * 5000,
        "department_id": "", "password": "Strong-pass-123", "csrf_token": token})
    assert r.status_code == 400
    r = client.post("/admin/medicines", data={
        "code": "BIG", "name": "X", "unit": "viên", "unit_price": "9" * 5000,
        "csrf_token": token})
    assert r.status_code == 400


@pytest.mark.parametrize("qty", ["--5", "-", "1e3", "9" * 20])
def test_malformed_quantity_is_400(client, db, qty):
    dept = make_department(db)
    doc = make_user(db, Role.DOCTOR, department=dept)
    record = make_record(db, make_patient(db, department=dept, attending=doc), doc)
    med = make_medicine(db)
    login(client, doc)
    r = client.post(f"/records/{record.id}/prescriptions", data={
        "medicine_id[]": [str(med.id)], "quantity[]": [qty], "dosage[]": ["Sáng"],
        "csrf_token": csrf_token(client, "/")})
    assert r.status_code == 400


def test_method_not_allowed_page_is_not_the_500_text(client, db):
    login(client, make_user(db, Role.DOCTOR))
    r = client.get("/logout")
    assert r.status_code == 405 and "Đã có lỗi xảy ra" not in r.text


# --- I3: navigation reaches every role's own pages


def test_patient_menu_links_own_profile(client, db):
    login(client, make_user(db, Role.PATIENT, patient=make_patient(db)))
    assert 'href="/me"' in client.get("/").text


def test_admin_menu_matches_admin_routes(client, db):
    login(client, make_user(db, Role.ADMIN))
    home = client.get("/").text
    for path in ("/patients", "/appointments", "/invoices", "/admin/medicines"):
        assert f'href="{path}"' in home
        assert client.get(path).status_code == 200
