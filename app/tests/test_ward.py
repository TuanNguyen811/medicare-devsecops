from datetime import date, timedelta

from medicare.auth.models import Role
from tests.conftest import login
from tests.factories import make_department, make_patient, make_record, make_user


def test_nurse_sees_patients_of_own_department(client, db):
    noi, ngoai = make_department(db, "NOI"), make_department(db, "NGOAI")
    mine = make_patient(db, department=noi)
    theirs = make_patient(db, department=ngoai)
    login(client, make_user(db, Role.NURSE, department=noi))
    r = client.get("/ward/patients")
    assert r.status_code == 200
    assert mine.code in r.text and theirs.code not in r.text
    assert "Bệnh nhân Khoa NOI" in r.text


def test_ward_list_masks_identifiers(client, db):
    dept = make_department(db)
    p = make_patient(db, department=dept)
    login(client, make_user(db, Role.NURSE, department=dept))
    html = client.get("/ward/patients").text
    assert p.national_id not in html and p.insurance_number not in html
    assert "********" + p.national_id[-4:] in html
    assert "***********" + p.insurance_number[-4:] in html


def test_ward_list_shows_latest_visit(client, db):
    dept = make_department(db)
    doc = make_user(db, Role.DOCTOR, department=dept)
    p = make_patient(db, department=dept, attending=doc)
    older = make_record(db, p, doc)
    older.visit_date = date.today() - timedelta(days=30)
    make_record(db, p, doc)
    db.flush()
    login(client, make_user(db, Role.NURSE, department=dept))
    html = client.get("/ward/patients").text
    assert date.today().strftime("%d/%m/%Y") in html
    assert older.visit_date.strftime("%d/%m/%Y") not in html


def test_nurse_without_department_sees_empty_list(client, db):
    make_patient(db, department=make_department(db))
    login(client, make_user(db, Role.NURSE))
    assert "Khoa chưa có bệnh nhân" in client.get("/ward/patients").text


def test_ward_menu_link_only_for_nurse(client, db):
    dept = make_department(db)
    login(client, make_user(db, Role.NURSE, department=dept))
    assert 'href="/ward/patients"' in client.get("/").text
    client.cookies.clear()
    login(client, make_user(db, Role.DOCTOR, department=dept))
    assert 'href="/ward/patients"' not in client.get("/").text


def test_ward_list_forbidden_for_other_roles(client, db):
    dept = make_department(db)
    for role in (Role.DOCTOR, Role.RECEPTIONIST, Role.PATIENT):
        client.cookies.clear()
        login(client, make_user(db, role, department=dept if role == Role.DOCTOR else None))
        assert client.get("/ward/patients").status_code == 403
