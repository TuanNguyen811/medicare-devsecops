from decimal import Decimal

from sqlalchemy import select

from medicare.auth.models import Role
from medicare.prescription.models import Medicine
from tests.conftest import csrf_token, login
from tests.factories import make_department, make_user

CATALOGUE = """\
medicines:
  - code: para500
    name: Paracetamol 500mg
    unit: viên
    unit_price: 1500
  - code: ORS
    name: Oresol 245
    unit: gói
    unit_price: 3000
"""


def upload(client, content, filename="danh-muc.yaml"):
    if isinstance(content, str):
        content = content.encode("utf-8")
    return client.post(
        "/admin/medicines/import",
        data={"csrf_token": csrf_token(client, "/admin/medicines")},
        files={"file": (filename, content, "application/yaml")},
        follow_redirects=False,
    )


def medicine(db, code):
    return db.scalar(select(Medicine).where(Medicine.code == code))


def test_admin_imports_catalogue(client, db):
    login(client, make_user(db, Role.ADMIN))
    r = upload(client, CATALOGUE)
    assert r.status_code == 303 and r.headers["location"] == "/admin/medicines"
    para = medicine(db, "PARA500")
    assert para.name == "Paracetamol 500mg" and para.unit_price == Decimal(1500)
    assert medicine(db, "ORS").unit == "gói"
    assert "thêm 2, cập nhật 0 thuốc" in client.get("/admin/medicines").text


def test_import_updates_existing_codes(client, db):
    db.add(Medicine(code="ORS", name="Oresol", unit="gói", unit_price=Decimal(2500)))
    db.flush()
    login(client, make_user(db, Role.ADMIN))
    assert upload(client, CATALOGUE).status_code == 303
    ors = medicine(db, "ORS")
    db.refresh(ors)
    assert ors.name == "Oresol 245" and ors.unit_price == Decimal(3000)


def test_invalid_row_imports_nothing(client, db):
    login(client, make_user(db, Role.ADMIN))
    bad = CATALOGUE + "  - code: SMEC\n    name: Smecta\n    unit: gói\n"
    r = upload(client, bad)
    assert r.status_code == 400 and "Thuốc thứ 3" in r.text
    assert medicine(db, "PARA500") is None


def test_price_must_be_whole_dong(client, db):
    login(client, make_user(db, Role.ADMIN))
    r = upload(client, CATALOGUE.replace("unit_price: 1500", "unit_price: 1500.5"))
    assert r.status_code == 400 and medicine(db, "PARA500") is None


def test_duplicate_code_in_file(client, db):
    login(client, make_user(db, Role.ADMIN))
    r = upload(client, CATALOGUE.replace("code: ORS", "code: PARA500"))
    assert r.status_code == 400 and "bị lặp" in r.text


def test_not_yaml_or_wrong_layout(client, db):
    login(client, make_user(db, Role.ADMIN))
    r = upload(client, "medicines: [unclosed\n")
    assert r.status_code == 400 and "không phải YAML hợp lệ" in r.text
    r = upload(client, "- code: PARA500\n")
    assert r.status_code == 400 and "khóa medicines" in r.text


def test_file_size_limited(client, db):
    login(client, make_user(db, Role.ADMIN))
    r = upload(client, "#" * (256 * 1024 + 1))
    assert r.status_code == 400 and "Tệp quá lớn" in r.text


def test_only_admin_imports(client, db):
    login(client, make_user(db, Role.DOCTOR, department=make_department(db)))
    r = client.post(
        "/admin/medicines/import",
        data={"csrf_token": csrf_token(client, "/")},
        files={"file": ("danh-muc.yaml", CATALOGUE.encode(), "application/yaml")},
    )
    assert r.status_code == 403 and medicine(db, "PARA500") is None


def test_import_without_csrf_is_403(client, db):
    login(client, make_user(db, Role.ADMIN))
    r = client.post("/admin/medicines/import",
                    files={"file": ("danh-muc.yaml", CATALOGUE.encode(), "application/yaml")})
    assert r.status_code == 403
