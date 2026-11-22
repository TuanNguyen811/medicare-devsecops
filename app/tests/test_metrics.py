import urllib.request

from fastapi.testclient import TestClient
from prometheus_client import REGISTRY

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
                              metrics_port=19000))
    with TestClient(app):
        server = app.state.metrics_server
        assert server.server_address[0] == "127.0.0.1"
        with urllib.request.urlopen("http://127.0.0.1:19000/metrics", timeout=5) as r:
            assert b"medicare_login_total" in r.read()
    app.state.engine.dispose()
