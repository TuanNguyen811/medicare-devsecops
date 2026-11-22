"""Supplier price lists (YAML exported by the pharmacy stock system) for the medicine catalogue.

Expected layout:

    nha_cung_cap: Công ty CP Dược phẩm Trung ương 1
    ngay_hieu_luc: 2026-12-01
    thuoc:
      - ma: PARA500
        ten: Paracetamol 500mg
        don_vi: viên
        don_gia: 1500
"""

from dataclasses import dataclass
from decimal import Decimal

import yaml
from sqlalchemy import select
from sqlalchemy.orm import Session

from medicare.prescription.models import Medicine
from medicare.prescription.service import PrescriptionError

MAX_FILE_BYTES = 1024 * 1024
MAX_ITEMS = 2000
MAX_UNIT_PRICE = 10**12 - 1  # Numeric(12, 0)


@dataclass(frozen=True)
class PriceLine:
    code: str
    name: str
    unit: str
    unit_price: Decimal


def parse(content: bytes) -> list[PriceLine]:
    if len(content) > MAX_FILE_BYTES:
        raise PrescriptionError("File bảng giá vượt quá 1 MB")
    try:
        doc = yaml.full_load(content)
    except yaml.YAMLError as exc:
        raise PrescriptionError("File bảng giá không đúng định dạng YAML") from exc
    items = doc.get("thuoc") if isinstance(doc, dict) else None
    if not isinstance(items, list) or not items:
        raise PrescriptionError("File bảng giá không có danh sách thuốc (thuoc)")
    if len(items) > MAX_ITEMS:
        raise PrescriptionError(f"Mỗi lần nhập tối đa {MAX_ITEMS} thuốc")
    return [_line(n, item) for n, item in enumerate(items, start=1)]


def _line(n: int, item: object) -> PriceLine:
    if not isinstance(item, dict):
        raise PrescriptionError(f"Dòng {n}: không đúng định dạng")
    code = str(item.get("ma") or "").strip().upper()
    name = str(item.get("ten") or "").strip()
    unit = str(item.get("don_vi") or "").strip()
    price = item.get("don_gia")
    if not (1 <= len(code) <= 20 and 1 <= len(name) <= 100 and 1 <= len(unit) <= 20):
        raise PrescriptionError(f"Dòng {n}: mã, tên và đơn vị thuốc là bắt buộc")
    if isinstance(price, bool) or not isinstance(price, int) or not 0 <= price <= MAX_UNIT_PRICE:
        raise PrescriptionError(f"Dòng {n}: đơn giá phải là số nguyên không âm (đồng)")
    return PriceLine(code, name, unit, Decimal(price))


def apply(db: Session, lines: list[PriceLine]) -> tuple[int, int]:
    """Add new medicines and update name, unit and price of existing ones by code."""
    existing = {m.code: m for m in db.scalars(select(Medicine))}
    added = updated = 0
    for line in lines:
        medicine = existing.get(line.code)
        if medicine is None:
            medicine = Medicine(code=line.code, name=line.name, unit=line.unit,
                                unit_price=line.unit_price)
            db.add(medicine)
            existing[line.code] = medicine
            added += 1
        else:
            medicine.name, medicine.unit = line.name, line.unit
            medicine.unit_price = line.unit_price
            updated += 1
    db.flush()
    return added, updated
