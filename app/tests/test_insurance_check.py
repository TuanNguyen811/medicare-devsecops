import subprocess
from datetime import date

import pytest

from medicare.auth.models import Role
from medicare.patient import insurance_check
from tests.conftest import csrf_token, login
from tests.factories import make_patient, make_user


class FakeTool:
    """Stands in for subprocess.run: records the call, answers like the BHXH tool."""

    def __init__(self, stdout="", returncode=0, error=None):
        self.stdout, self.returncode, self.error = stdout, returncode, error
        self.calls = []

    def __call__(self, args, **kwargs):
        self.calls.append((args, kwargs))
        if self.error is not None:
            raise self.error
        return subprocess.CompletedProcess(args, self.returncode, stdout=self.stdout, stderr="")


@pytest.fixture
def tool(monkeypatch):
    def install(**kwargs):
        fake = FakeTool(**kwargs)
        monkeypatch.setattr(insurance_check.subprocess, "run", fake)
        return fake

    return install


def check(client, patient):
    token = csrf_token(client, f"/patients/{patient.id}")
    return client.post(f"/patients/{patient.id}/insurance-check", data={"csrf_token": token})


def test_valid_card(client, db, tool):
    fake = tool(stdout='{"ma_ket_qua": "000", "den_ngay": "31/12/2026"}')
    p = make_patient(db)
    login(client, make_user(db, Role.RECEPTIONIST))
    r = check(client, p)
    assert r.status_code == 200
    assert "Thẻ BHYT còn giá trị sử dụng (hạn đến 31/12/2026)" in r.text
    (args, kwargs), = fake.calls
    assert args == ["/opt/bhxh/bin/tra-cuu-the", "--json", f"--ma-the={p.insurance_number}",
                    f"--ho-ten={p.full_name}", "--ngay-sinh=01/01/1990"]
    assert kwargs["timeout"] == insurance_check.TIMEOUT_SECONDS and not kwargs.get("shell")


def test_expired_card_is_a_warning(client, db, tool):
    tool(stdout='{"ma_ket_qua": "001"}')
    p = make_patient(db)
    login(client, make_user(db, Role.ADMIN))
    r = check(client, p)
    assert "alert-warning" in r.text and "Thẻ BHYT đã hết hạn sử dụng" in r.text


def test_tool_not_installed(client, db, tool):
    tool(error=FileNotFoundError())
    p = make_patient(db)
    login(client, make_user(db, Role.RECEPTIONIST))
    assert "chưa sẵn sàng công cụ tra cứu BHYT" in check(client, p).text


def test_portal_timeout(client, db, tool):
    tool(error=subprocess.TimeoutExpired(cmd="tra-cuu-the", timeout=15))
    p = make_patient(db)
    login(client, make_user(db, Role.RECEPTIONIST))
    assert "Cổng BHYT không phản hồi" in check(client, p).text


def test_unreadable_answer(client, db, tool):
    tool(stdout="Service Unavailable", returncode=0)
    p = make_patient(db)
    login(client, make_user(db, Role.RECEPTIONIST))
    assert "không đọc được" in check(client, p).text


def test_patient_without_card_is_not_looked_up(client, db, tool):
    fake = tool(stdout='{"ma_ket_qua": "000"}')
    p = make_patient(db, insurance_number=None)
    login(client, make_user(db, Role.RECEPTIONIST))
    assert "Bệnh nhân chưa có thẻ BHYT" in check(client, p).text
    assert fake.calls == []


def test_check_button_only_for_reception_and_admin(client, db):
    p = make_patient(db)
    login(client, make_user(db, Role.RECEPTIONIST))
    assert "Kiểm tra thẻ BHYT" in client.get(f"/patients/{p.id}").text
    client.cookies.clear()
    login(client, make_user(db, Role.PATIENT, patient=p))
    assert "Kiểm tra thẻ BHYT" not in client.get("/me").text


def test_doctor_cannot_check_card(client, db, tool):
    fake = tool(stdout='{"ma_ket_qua": "000"}')
    p = make_patient(db)
    login(client, make_user(db, Role.DOCTOR))
    r = client.post(f"/patients/{p.id}/insurance-check",
                    data={"csrf_token": csrf_token(client, "/")})
    assert r.status_code == 403 and fake.calls == []


def test_check_without_csrf_is_403(client, db, tool):
    tool(stdout='{"ma_ket_qua": "000"}')
    p = make_patient(db)
    login(client, make_user(db, Role.RECEPTIONIST))
    assert client.post(f"/patients/{p.id}/insurance-check").status_code == 403


def test_build_command_formats_birth_date():
    args = insurance_check.build_command("/opt/tool", "DN4010123456789", "Nguyễn  Văn An",
                                         date(1985, 3, 7))
    assert args[3:] == ["--ho-ten=Nguyễn Văn An", "--ngay-sinh=07/03/1985"]
