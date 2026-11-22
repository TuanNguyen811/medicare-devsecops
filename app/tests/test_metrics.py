import urllib.request

from fastapi.testclient import TestClient
from prometheus_client import REGISTRY, generate_latest

from medicare.auth.models import Role
from medicare.config import Settings
from medicare.main import create_app
from tests.conftest import csrf_token, login
from tests.factories import make_department, make_patient, make_record, make_user


def value(name, **labels) -> float:
    return REGISTRY.get_sample_value(name, labels) or 0.0


def bad_login(client, username):
    client.post(
        "/login",
        data={"username": username, "password": "bad", "csrf_token": csrf_token(client)},
    )


def test_login_outcomes_and_lockout_are_counted(client, db):
    u = make_user(db, Role.NURSE)
    before = {r: value("medicare_login_total", result=r) for r in ("success", "failure", "locked")}
    locks = value("medicare_account_lockouts_total")
    for _ in range(5):
        bad_login(client, u.username)
    bad_login(client, u.username)  # account now locked
    bad_login(client, "no-such-user")
    assert value("medicare_login_total", result="failure") - before["failure"] == 6
    assert value("medicare_login_total", result="locked") - before["locked"] == 1
    assert value("medicare_account_lockouts_total") - locks == 1

    other = make_user(db, Role.NURSE)
    login(client, other)
    assert value("medicare_login_total", result="success") - before["success"] == 1


def test_record_access_counted_per_user_without_pii(client, db):
    dept = make_department(db)
    doc = make_user(db, Role.DOCTOR, department=dept)
    rec = make_record(db, make_patient(db, department=dept, attending=doc), doc)
    labels = {"action": "VIEW_RECORD", "role": doc.role.value, "user_id": str(doc.id)}
    before = value("medicare_record_access_total", **labels)
    login(client, doc)
    assert client.get(f"/records/{rec.id}").status_code == 200
    assert value("medicare_record_access_total", **labels) - before == 1


def test_denied_existing_record_counted_but_missing_one_not(client, db):
    dept = make_department(db)
    doc = make_user(db, Role.DOCTOR, department=dept)
    rec = make_record(db, make_patient(db, department=dept, attending=doc), doc)
    me = make_patient(db)
    login(client, make_user(db, Role.PATIENT, patient=me))
    before = value("medicare_authz_denied_total", resource="record")
    assert client.get(f"/api/v1/records/{rec.id}").status_code == 404
    assert value("medicare_authz_denied_total", resource="record") - before == 1
    assert client.get("/api/v1/records/999999").status_code == 404  # same answer (R-15)
    assert value("medicare_authz_denied_total", resource="record") - before == 1


def test_role_refusal_counted(client, db):
    login(client, make_user(db, Role.NURSE))
    before = value("medicare_authz_denied_total", resource="role")
    assert client.get("/admin/users").status_code == 403
    assert value("medicare_authz_denied_total", resource="role") - before == 1


def test_http_requests_labelled_by_route_template(client, db):
    p = make_patient(db)
    login(client, make_user(db, Role.RECEPTIONIST))
    labels = {"method": "GET", "route": "/patients/{patient_id}", "status": "200"}
    before = value("medicare_http_requests_total", **labels)
    assert client.get(f"/patients/{p.id}").status_code == 200
    assert value("medicare_http_requests_total", **labels) - before == 1
    unmatched = {"method": "GET", "route": "unmatched", "status": "404"}
    before = value("medicare_http_requests_total", **unmatched)
    client.get(f"/no-such-page/{p.national_id}")
    assert value("medicare_http_requests_total", **unmatched) - before == 1
    routes = {s.labels.get("route") for m in REGISTRY.collect() for s in m.samples}
    assert not any(p.national_id in (r or "") for r in routes)


def test_metrics_server_off_by_default_and_not_on_app_port(app):
    with TestClient(app) as c:
        assert app.state.metrics_server is None
        assert c.get("/metrics").status_code == 404


def test_metrics_server_serves_on_its_own_port(database_url):
    app = create_app(Settings(env="test", database_url=database_url, secret_key="x" * 32,
                              metrics_port=1))
    app.state.settings.metrics_port = 0  # any free port; Settings itself requires 1..65535
    with TestClient(app):
        server = app.state.metrics_server
        host, port = server.server_address[:2]
        assert host == "127.0.0.1"
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/metrics", timeout=5) as r:
            assert b"medicare_login_total" in r.read()
    app.state.engine.dispose()


def test_alerting_series_exported_before_any_event():
    """Login and refusal series exist from import (alerts use increase(), which misses the
    first increments of a series that appears mid-window). Run alone, nothing else has
    touched them, so their presence comes from the pre-initialisation."""
    out = generate_latest().decode()
    for result in ("success", "failure", "locked"):
        assert f'medicare_login_total{{result="{result}"}} ' in out
    for resource in ("patient", "record", "prescription", "appointment", "invoice", "role"):
        assert f'medicare_authz_denied_total{{resource="{resource}"}} ' in out
    assert "medicare_account_lockouts_total " in out


def test_unknown_http_method_does_not_create_new_series(client):
    before = value("medicare_http_requests_total", method="OTHER", route="unmatched", status="405")
    before += value("medicare_http_requests_total", method="OTHER", route="/login", status="405")
    client.request("BREW", "/login")
    after = value("medicare_http_requests_total", method="OTHER", route="unmatched", status="405")
    after += value("medicare_http_requests_total", method="OTHER", route="/login", status="405")
    assert after - before == 1
    names = {s.labels.get("method") for m in REGISTRY.collect() for s in m.samples}
    assert "BREW" not in names


def test_cancel_refused_for_status_is_not_an_authz_denial(client, db):
    from datetime import UTC, datetime, timedelta

    from medicare.appointment.models import Appointment, AppointmentStatus

    me = make_patient(db)
    doc = make_user(db, Role.DOCTOR)
    account = make_user(db, Role.PATIENT, patient=me)
    appt = Appointment(patient_id=me.id, doctor_id=doc.id, reason="x", created_by_id=account.id,
                       scheduled_at=datetime.now(UTC) + timedelta(days=3),
                       status=AppointmentStatus.CONFIRMED)
    db.add(appt)
    db.flush()
    login(client, account)
    before = value("medicare_authz_denied_total", resource="appointment")
    token = csrf_token(client, "/appointments")
    r = client.post(f"/appointments/{appt.id}/cancel", data={"csrf_token": token},
                    follow_redirects=False)
    assert r.status_code == 403  # own appointment, but already confirmed (R-13)
    assert value("medicare_authz_denied_total", resource="appointment") - before == 0
