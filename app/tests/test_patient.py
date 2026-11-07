from sqlalchemy import select

from medicare.auth.models import Role
from medicare.patient.models import Patient
from tests.conftest import csrf_token, login
from tests.factories import make_department, make_patient, make_user

VALID = {
    "full_name": "Nguyễn Văn A",
    "date_of_birth": "1990-01-01",
    "gender": "M",
    "national_id": "012345678901",
    "insurance_number": "DN4010123456789",
    "phone": "0901234567",
    "address": "Hà Nội",
}


def test_receptionist_creates_patient(client, db):
    login(client, make_user(db, Role.RECEPTIONIST))
    r = client.post(
        "/patients",
        data=VALID | {"csrf_token": csrf_token(client, "/patients/new")},
        follow_redirects=False,
    )
    assert r.status_code == 303 and r.headers["location"].startswith("/patients/")
    p = db.scalar(select(Patient).where(Patient.national_id == "012345678901"))
    assert p is not None and p.code == f"BN{p.id:06d}"


def test_invalid_national_id_rerenders_400(client, db):
    login(client, make_user(db, Role.RECEPTIONIST))
    r = client.post(
        "/patients",
        data={
            "full_name": "A",
            "date_of_birth": "1990-01-01",
            "gender": "M",
            "national_id": "123",
            "phone": "0901",
            "address": "x",
            "csrf_token": csrf_token(client, "/patients/new"),
        },
    )
    assert r.status_code == 400 and "CCCD" in r.text


def test_invalid_insurance_number_rerenders_400(client, db):
    login(client, make_user(db, Role.RECEPTIONIST))
    r = client.post(
        "/patients",
        data=VALID | {"insurance_number": "XX9", "csrf_token": csrf_token(client, "/patients/new")},
    )
    assert r.status_code == 400 and "Mã BHYT" in r.text


def test_duplicate_national_id_rerenders_400(client, db):
    make_patient(db, national_id="012345678901")
    login(client, make_user(db, Role.RECEPTIONIST))
    r = client.post(
        "/patients", data=VALID | {"csrf_token": csrf_token(client, "/patients/new")}
    )
    assert r.status_code == 400 and "CCCD" in r.text


def test_attending_must_be_doctor_of_patient_department(client, db):
    dept = make_department(db, "NOI")
    nurse = make_user(db, Role.NURSE, department=dept)
    login(client, make_user(db, Role.RECEPTIONIST))
    r = client.post(
        "/patients",
        data=VALID
        | {
            "department_id": str(dept.id),
            "attending_doctor_id": str(nurse.id),
            "csrf_token": csrf_token(client, "/patients/new"),
        },
    )
    assert r.status_code == 400


def test_doctor_cannot_create_patient(client, db):
    login(client, make_user(db, Role.DOCTOR))
    assert client.post("/patients", data={"csrf_token": csrf_token(client, "/")}).status_code == 403


def test_create_without_csrf_is_403(client, db):
    login(client, make_user(db, Role.RECEPTIONIST))
    assert client.post("/patients", data=VALID).status_code == 403


def test_receptionist_edits_patient(client, db):
    p = make_patient(db)
    login(client, make_user(db, Role.RECEPTIONIST))
    token = csrf_token(client, f"/patients/{p.id}/edit")
    data = VALID | {"national_id": p.national_id, "phone": "0912345678", "csrf_token": token}
    r = client.post(f"/patients/{p.id}/edit", data=data, follow_redirects=False)
    assert r.status_code == 303
    db.refresh(p)
    assert p.phone == "0912345678"


def test_nurse_cannot_edit_patient(client, db):
    dept = make_department(db, "NOI")
    p = make_patient(db, department=dept)
    login(client, make_user(db, Role.NURSE, department=dept))
    assert client.get(f"/patients/{p.id}/edit").status_code == 403


def test_patient_sees_only_self_via_api(client, db):
    me = make_patient(db)
    other = make_patient(db)
    login(client, make_user(db, Role.PATIENT, patient=me))
    assert client.get(f"/api/v1/patients/{me.id}").status_code == 200
    assert client.get(f"/api/v1/patients/{other.id}").status_code == 404


def test_patient_detail_forbidden_and_missing_are_identical(client, db):
    other = make_patient(db)
    login(client, make_user(db, Role.PATIENT, patient=make_patient(db)))
    a = client.get(f"/api/v1/patients/{other.id}")
    b = client.get("/api/v1/patients/999999")
    assert a.status_code == b.status_code == 404 and a.json() == b.json()


def test_html_detail_forbidden_and_missing_are_identical(client, db):
    other = make_patient(db)
    login(client, make_user(db, Role.PATIENT, patient=make_patient(db)))
    a = client.get(f"/patients/{other.id}")
    b = client.get("/patients/999999")
    assert a.status_code == b.status_code == 404 and a.text == b.text


def test_identifiers_masked_for_doctor(client, db):
    dept = make_department(db)
    doc = make_user(db, Role.DOCTOR, department=dept)
    p = make_patient(db, department=dept, attending=doc)
    login(client, doc)
    body = client.get(f"/api/v1/patients/{p.id}").json()
    assert body["national_id"].startswith("********") and len(body["national_id"]) == 12
    assert body["insurance_number"] == "***********6789"
    assert p.national_id not in client.get(f"/patients/{p.id}").text


def test_identifiers_full_for_receptionist_and_self(client, db):
    p = make_patient(db)
    login(client, make_user(db, Role.RECEPTIONIST))
    assert client.get(f"/api/v1/patients/{p.id}").json()["national_id"] == p.national_id
    assert p.national_id in client.get(f"/patients/{p.id}").text


def test_nurse_other_department_cannot_see(client, db):
    p = make_patient(db, department=make_department(db, "NGOAI"))
    login(client, make_user(db, Role.NURSE, department=make_department(db, "NHI")))
    assert client.get(f"/patients/{p.id}").status_code == 404


def test_search_is_scoped_to_department_for_nurse(client, db):
    noi, ngoai = make_department(db, "NOI"), make_department(db, "NGOAI")
    mine = make_patient(db, department=noi)
    theirs = make_patient(db, department=ngoai)
    login(client, make_user(db, Role.NURSE, department=noi))
    html = client.get("/patients").text
    assert mine.code in html and theirs.code not in html


def test_search_by_name_and_code(client, db):
    p = make_patient(db)
    other = make_patient(db)
    login(client, make_user(db, Role.RECEPTIONIST))
    html = client.get("/patients", params={"q": p.code}).text
    assert p.code in html and other.code not in html


def test_search_with_sql_metacharacters_is_safe(client, db):
    make_patient(db)
    login(client, make_user(db, Role.RECEPTIONIST))
    r = client.get("/patients", params={"q": "' OR 1=1 --"})
    assert r.status_code == 200 and "BN" not in r.text.split("<tbody>")[-1]


def test_search_wildcards_are_literal(client, db):
    make_patient(db)
    login(client, make_user(db, Role.RECEPTIONIST))
    assert "BN" not in client.get("/patients", params={"q": "%"}).text.split("<tbody>")[-1]


def test_patient_role_cannot_list_patients(client, db):
    login(client, make_user(db, Role.PATIENT, patient=make_patient(db)))
    assert client.get("/patients").status_code == 403


def test_me_shows_own_profile(client, db):
    me = make_patient(db)
    login(client, make_user(db, Role.PATIENT, patient=me))
    r = client.get("/me")
    assert r.status_code == 200 and me.code in r.text and me.national_id in r.text
