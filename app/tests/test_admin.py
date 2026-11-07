from fastapi.testclient import TestClient
from sqlalchemy import select

from medicare.audit.models import AuditLog
from medicare.auth.models import Role, User
from tests.conftest import csrf_token, login
from tests.factories import make_department, make_patient, make_user

NEW_PASSWORD = "Strong-pass-123"


def create_user(client, **fields):
    data = {"username": "bacsimoi", "full_name": "BS. Mới", "role": "DOCTOR",
            "department_id": "", "patient_id": "", "password": NEW_PASSWORD}
    data |= fields
    data["csrf_token"] = csrf_token(client, "/admin/users")
    return client.post("/admin/users", data=data, follow_redirects=False)


def test_admin_creates_doctor_requires_department(client, db):
    dept = make_department(db)
    login(client, make_user(db, Role.ADMIN))
    assert create_user(client).status_code == 400
    assert create_user(client, department_id=str(dept.id)).status_code == 303
    user = db.scalar(select(User).where(User.username == "bacsimoi"))
    assert user.role == Role.DOCTOR and user.department_id == dept.id
    assert user.password_hash.startswith("$argon2id$")


def test_created_user_can_log_in(app, client, db):
    dept = make_department(db)
    login(client, make_user(db, Role.ADMIN))
    create_user(client, department_id=str(dept.id))
    fresh = TestClient(app, raise_server_exceptions=False)
    r = fresh.post("/login", data={"username": "bacsimoi", "password": NEW_PASSWORD,
                                   "csrf_token": csrf_token(fresh)}, follow_redirects=False)
    assert r.status_code == 303


def test_patient_account_requires_unlinked_patient(client, db):
    p = make_patient(db)
    make_user(db, Role.PATIENT, patient=p)  # already linked
    login(client, make_user(db, Role.ADMIN))
    assert create_user(client, username="bn1", role="PATIENT").status_code == 400
    assert create_user(client, username="bn1", role="PATIENT",
                       patient_id=str(p.id)).status_code == 400
    free = make_patient(db)
    assert create_user(client, username="bn1", role="PATIENT",
                       patient_id=str(free.id)).status_code == 303


def test_short_password_rejected(client, db):
    login(client, make_user(db, Role.ADMIN))
    assert create_user(client, role="RECEPTIONIST", password="short").status_code == 400


def test_duplicate_or_malformed_username_rejected(client, db):
    existing = make_user(db, Role.RECEPTIONIST)
    login(client, make_user(db, Role.ADMIN))
    assert create_user(client, role="RECEPTIONIST", username=existing.username).status_code == 400
    assert create_user(client, role="RECEPTIONIST", username="<b>x</b>").status_code == 400


def test_non_admin_cannot_access_admin(client, db):
    login(client, make_user(db, Role.DOCTOR))
    assert client.get("/admin/users").status_code == 403
    assert client.get("/admin/audit").status_code == 403
    r = client.post("/admin/users", data={"csrf_token": csrf_token(client, "/")})
    assert r.status_code == 403


def test_deactivate_user_kills_their_access(app, client, db):
    victim = make_user(db, Role.NURSE, department=make_department(db))
    victim_client = TestClient(app, raise_server_exceptions=False)
    login(victim_client, victim)
    login(client, make_user(db, Role.ADMIN))
    r = client.post(f"/admin/users/{victim.id}/deactivate",
                    data={"csrf_token": csrf_token(client, "/admin/users")},
                    follow_redirects=False)
    assert r.status_code == 303
    assert victim_client.get("/", follow_redirects=False).status_code == 303
    victim_client.cookies.clear()
    r = victim_client.post("/login", data={"username": victim.username, "password": "Passw0rd!",
                                           "csrf_token": csrf_token(victim_client)},
                           follow_redirects=False)
    assert r.status_code == 200 and "Tên đăng nhập hoặc mật khẩu không đúng" in r.text


def test_admin_cannot_deactivate_self(client, db):
    admin = make_user(db, Role.ADMIN)
    login(client, admin)
    r = client.post(f"/admin/users/{admin.id}/deactivate",
                    data={"csrf_token": csrf_token(client, "/admin/users")})
    assert r.status_code == 400
    db.refresh(admin)
    assert admin.is_active


def _audit(db, actor, entity_id, n=1, action="VIEW_RECORD"):
    for _ in range(n):
        db.add(AuditLog(actor_id=actor.id, action=action, entity_type="record",
                        entity_id=entity_id, ip="10.0.0.1"))
    db.flush()


def test_audit_page_filters_by_record(client, db):
    admin = make_user(db, Role.ADMIN)
    _audit(db, admin, 1001, n=2)
    _audit(db, admin, 2002, n=3)
    login(client, admin)
    html = client.get("/admin/audit", params={"record_id": "1001"}).text
    assert html.count("data-audit-row") == 2 and "2002" not in html


def test_audit_pagination_newest_first(client, db):
    admin = make_user(db, Role.ADMIN)
    _audit(db, admin, 7, n=55)
    login(client, admin)
    assert client.get("/admin/audit").text.count("data-audit-row") == 50
    assert client.get("/admin/audit", params={"page": "2"}).text.count("data-audit-row") == 5
    assert client.get("/admin/audit", params={"page": "abc"}).status_code == 200


def test_no_mutating_audit_routes(app):
    paths = [r.path for r in app.routes if getattr(r, "methods", None)
             and ({"PUT", "PATCH", "DELETE"} & r.methods or "POST" in r.methods)]
    assert not any("audit" in p for p in paths)
