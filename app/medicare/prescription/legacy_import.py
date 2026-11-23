"""Import the medicine catalog from the old HIS export files (YAML or XML).

The old system exports one entry per medicine with the fields
`ma_thuoc`, `ten_thuoc`, `don_vi`, `don_gia`:

    danh_muc_thuoc:
      - {ma_thuoc: PARA500, ten_thuoc: Paracetamol 500mg, don_vi: viên, don_gia: 1500}

    <danh_muc_thuoc>
      <thuoc><ma_thuoc>PARA500</ma_thuoc>...<don_gia>1500</don_gia></thuoc>
    </danh_muc_thuoc>
"""

from dataclasses import dataclass, field

import yaml
from lxml import etree
from sqlalchemy import select
from sqlalchemy.orm import Session

from medicare.prescription.models import Medicine
from medicare.prescription.service import PrescriptionError, add_medicine

MAX_UPLOAD_BYTES = 2 * 1024 * 1024
MAX_ROWS = 5000
FIELDS = ("ma_thuoc", "ten_thuoc", "don_vi", "don_gia")
YAML_SUFFIXES = (".yaml", ".yml")
XML_SUFFIXES = (".xml",)
BAD_FILE = "File không đúng định dạng xuất của hệ thống cũ"


@dataclass
class ImportResult:
    added: int = 0
    skipped: int = 0
    errors: list[str] = field(default_factory=list)


def _parse_yaml(data: bytes) -> list[dict]:
    doc = yaml.load(data, Loader=yaml.Loader)
    rows = doc.get("danh_muc_thuoc") if isinstance(doc, dict) else doc
    if not isinstance(rows, list):
        raise PrescriptionError(BAD_FILE)
    return [row for row in rows if isinstance(row, dict)]


def _parse_xml(data: bytes) -> list[dict]:
    # The old HIS writes accented names as entities declared in the export's DOCTYPE.
    parser = etree.XMLParser(resolve_entities=True, remove_blank_text=True)
    root = etree.fromstring(data, parser)
    return [{name: el.findtext(name) for name in FIELDS} for el in root.iter("thuoc")]


def parse_export(filename: str, data: bytes) -> list[dict]:
    name = filename.lower()
    try:
        if name.endswith(YAML_SUFFIXES):
            rows = _parse_yaml(data)
        elif name.endswith(XML_SUFFIXES):
            rows = _parse_xml(data)
        else:
            raise PrescriptionError("Chỉ nhận file .yaml, .yml hoặc .xml")
    except (yaml.YAMLError, etree.XMLSyntaxError, UnicodeDecodeError) as exc:
        raise PrescriptionError(BAD_FILE) from exc
    if not rows:
        raise PrescriptionError("File không có thuốc nào")
    if len(rows) > MAX_ROWS:
        raise PrescriptionError(f"Mỗi lần nhập tối đa {MAX_ROWS} thuốc")
    return rows


def _text(value) -> str:
    return "" if value is None else str(value).strip()


def import_medicines(db: Session, rows: list[dict]) -> ImportResult:
    """Add medicines whose code is not in the catalog yet; existing codes are left as is."""
    result = ImportResult()
    existing = set(db.scalars(select(Medicine.code)))
    for n, row in enumerate(rows, start=1):
        code = _text(row.get("ma_thuoc")).upper()
        if code in existing:
            result.skipped += 1
            continue
        try:
            add_medicine(db, code, _text(row.get("ten_thuoc")), _text(row.get("don_vi")),
                         _text(row.get("don_gia")))
        except PrescriptionError as exc:
            result.errors.append(f"Dòng {n} ({code or 'không có mã'}): {exc}")
            continue
        existing.add(code)
        result.added += 1
    return result
