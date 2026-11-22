from email.message import Message

import pytest
from sqlalchemy import select

from medicare.audit.models import AuditLog
from medicare.auth.models import Role
from medicare.record import lab
from medicare.record.models import LabResult
from tests.conftest import csrf_token, login
from tests.factories import make_department, make_patient, make_record, make_user

PDF = b"%PDF-1.7\n% ket qua xet nghiem\n"
LIS_URL = "https://lis.medicare.local/reports/2026/XN000123.pdf"


class FakeResponse:
    def __init__(self, body: bytes, content_type: str):
        self.body = body
        self.headers = Message()
        self.headers["Content-Type"] = content_type

    def read(self, n: int = -1) -> bytes:
        return self.body if n < 0 else self.body[:n]

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


@pytest.fixture
def lis(monkeypatch):
    """Stand-in for the laboratory system: serves one published report."""
    served = {"body": PDF, "type": "application/pdf", "requested": []}

    def fake_urlopen(request, timeout=None):
        served["requested"].append(request.full_url)
        return FakeResponse(served["body"], served["type"])

    monkeypatch.setattr(lab.urllib.request, "urlopen", fake_urlopen)
    return served


def ward(db):
    dept = make_department(db)
    doc = make_user(db, Role.DOCTOR, department=dept)
    patient = make_patient(db, department=dept, attending=doc)
    return dept, doc, patient, make_record(db, patient, doc)


def attach(client, record, title="Công thức máu", url=LIS_URL):
    data = {"title": title, "url": url, "csrf_token": csrf_token(client, f"/records/{record.id}")}
    return client.post(f"/records/{record.id}/lab-results", data=data, follow_redirects=False)


def test_attending_doctor_attaches_lab_result(client, db, lis):
    _, doc, _, record = ward(db)
    login(client, doc)
    r = attach(client, record)
    assert r.status_code == 303 and r.headers["location"] == f"/records/{record.id}"
    assert lis["requested"] == [LIS_URL]
    result = db.scalar(select(LabResult).where(LabResult.record_id == record.id))
    assert result.content == PDF and result.content_type == "application/pdf"
    assert result.source_url == LIS_URL and result.created_by_id == doc.id
    page = client.get(f"/records/{record.id}").text
    assert "Công thức máu" in page and f"/lab-results/{result.id}" in page


def test_lab_result_download_is_audited(client, db, lis):
    dept, doc, _, record = ward(db)
    login(client, doc)
    attach(client, record)
    result = db.scalar(select(LabResult).where(LabResult.record_id == record.id))
    client.cookies.clear()
    nurse = make_user(db, Role.NURSE, department=dept)
    login(client, nurse)
    r = client.get(f"/lab-results/{result.id}")
    assert r.status_code == 200 and r.content == PDF
    assert r.headers["content-type"] == "application/pdf"
    assert r.headers["content-disposition"].startswith("attachment;")
    rows = db.scalars(select(AuditLog).where(AuditLog.action == "VIEW_LAB_RESULT")).all()
    assert [(a.actor_id, a.entity_id) for a in rows] == [(nurse.id, record.id)]


def test_unsupported_content_type_is_rejected(client, db, lis):
    _, doc, _, record = ward(db)
    lis["body"], lis["type"] = b"<html></html>", "text/html"
    login(client, doc)
    assert attach(client, record).status_code == 303
    assert db.scalar(select(LabResult).where(LabResult.record_id == record.id)) is None
    assert "Kết quả phải là file PDF" in client.get(f"/records/{record.id}").text


def test_only_attending_doctor_attaches(client, db, lis):
    dept, _, _, record = ward(db)
    login(client, make_user(db, Role.DOCTOR, department=dept))
    assert attach(client, record).status_code == 404
    client.cookies.clear()
    login(client, make_user(db, Role.NURSE, department=dept))
    assert attach(client, record).status_code == 403
    assert lis["requested"] == []


def test_lab_result_hidden_outside_clinical_scope(client, db, lis):
    _, doc, _, record = ward(db)
    login(client, doc)
    attach(client, record)
    result = db.scalar(select(LabResult).where(LabResult.record_id == record.id))
    for role in (Role.RECEPTIONIST, Role.ADMIN):
        client.cookies.clear()
        login(client, make_user(db, role))
        assert client.get(f"/lab-results/{result.id}").status_code == 404
    client.cookies.clear()
    login(client, make_user(db, Role.DOCTOR, department=make_department(db, "NGOAI")))
    assert client.get(f"/lab-results/{result.id}").status_code == 404
