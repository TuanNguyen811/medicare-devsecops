from decimal import Decimal

from sqlalchemy import select

from medicare.auth.models import Role
from medicare.prescription.models import Medicine
from tests.conftest import csrf_token, login
from tests.factories import make_user

YAML_EXPORT = """\
danh_muc_thuoc:
  - ma_thuoc: PARA500
    ten_thuoc: Paracetamol 500mg
    don_vi: viên
    don_gia: 1500
  - ma_thuoc: ors
    ten_thuoc: Oresol 245
    don_vi: gói
    don_gia: 3000
"""

XML_EXPORT = """\
<?xml version="1.0" encoding="UTF-8"?>
<danh_muc_thuoc>
  <thuoc>
    <ma_thuoc>OMEP20</ma_thuoc>
    <ten_thuoc>Omeprazol 20mg</ten_thuoc>
    <don_vi>viên</don_vi>
    <don_gia>2500</don_gia>
  </thuoc>
</danh_muc_thuoc>
"""


def upload(client, filename, content, token=None):
    token = token or csrf_token(client, "/admin/medicines/import")
    return client.post("/admin/medicines/import", data={"csrf_token": token},
                       files={"file": (filename, content.encode("utf-8"))},
                       follow_redirects=False)


def medicine(db, code):
    return db.scalar(select(Medicine).where(Medicine.code == code))


def test_admin_imports_yaml_export(client, db):
    login(client, make_user(db, Role.ADMIN))
    r = upload(client, "danhmuc.yaml", YAML_EXPORT)
    assert r.status_code == 303 and r.headers["location"] == "/admin/medicines"
    para = medicine(db, "PARA500")
    assert para.name == "Paracetamol 500mg" and para.unit_price == Decimal(1500)
    assert medicine(db, "ORS").unit == "gói"
    assert "Đã nhập 2 thuốc, bỏ qua 0 mã đã có" in client.get("/admin/medicines").text


def test_admin_imports_xml_export(client, db):
    login(client, make_user(db, Role.ADMIN))
    assert upload(client, "DANHMUC.XML", XML_EXPORT).status_code == 303
    assert medicine(db, "OMEP20").unit_price == Decimal(2500)


def test_existing_codes_are_kept(client, db):
    db.add(Medicine(code="PARA500", name="Paracetamol", unit="viên", unit_price=Decimal(1200)))
    db.flush()
    login(client, make_user(db, Role.ADMIN))
    upload(client, "danhmuc.yml", YAML_EXPORT)
    assert medicine(db, "PARA500").unit_price == Decimal(1200)
    assert "bỏ qua 1 mã đã có" in client.get("/admin/medicines").text


def test_invalid_rows_reported_and_skipped(client, db):
    login(client, make_user(db, Role.ADMIN))
    export = "danh_muc_thuoc:\n  - {ma_thuoc: X1, ten_thuoc: Thuốc X, don_vi: viên, don_gia: abc}\n"
    assert upload(client, "danhmuc.yaml", export).status_code == 303
    assert medicine(db, "X1") is None
    assert "Dòng 1 (X1)" in client.get("/admin/medicines").text


def test_unsupported_or_malformed_file_is_400(client, db):
    login(client, make_user(db, Role.ADMIN))
    assert upload(client, "danhmuc.csv", "ma_thuoc,ten_thuoc").status_code == 400
    assert upload(client, "danhmuc.xml", "<danh_muc_thuoc><thuoc>").status_code == 400
    assert upload(client, "danhmuc.yaml", "chỉ là một dòng chữ").status_code == 400


def test_import_requires_admin(client, db):
    for role in (Role.RECEPTIONIST, Role.DOCTOR):
        client.cookies.clear()
        login(client, make_user(db, role))
        assert client.get("/admin/medicines/import").status_code == 403
        r = upload(client, "danhmuc.yaml", YAML_EXPORT, token=csrf_token(client, "/"))
        assert r.status_code == 403
    assert medicine(db, "PARA500") is None


def test_import_requires_csrf_token(client, db):
    login(client, make_user(db, Role.ADMIN))
    r = client.post("/admin/medicines/import",
                    files={"file": ("danhmuc.yaml", YAML_EXPORT.encode("utf-8"))})
    assert r.status_code == 403
    assert medicine(db, "PARA500") is None


def test_medicines_page_links_import(client, db):
    login(client, make_user(db, Role.ADMIN))
    assert 'href="/admin/medicines/import"' in client.get("/admin/medicines").text
