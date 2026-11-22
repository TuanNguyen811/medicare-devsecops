"""Printable / downloadable copy of a medical record ("Xuất bệnh án")."""

from datetime import datetime
from pathlib import Path

from sqlalchemy.orm import Session

from medicare.audit import service as audit
from medicare.auth.models import User
from medicare.common.errors import NotFound
from medicare.common.templating import VN_TZ, date_vn, datetime_vn
from medicare.patient.models import Patient
from medicare.record.models import MedicalRecord
from medicare.record.service import ENTITY

LETTERHEAD_DIR = Path(__file__).resolve().parent / "letterheads"
DEFAULT_LETTERHEAD = "benh-vien.txt"
FORMATS = {"html": "text/html", "txt": "text/plain"}
GENDERS = {"M": "Nam", "F": "Nữ"}


def letterheads() -> list[str]:
    """Letterhead files offered in the export form."""
    return sorted(p.name for p in LETTERHEAD_DIR.glob("*.txt"))


def read_letterhead(name: str) -> str:
    path = LETTERHEAD_DIR / (name or DEFAULT_LETTERHEAD)
    try:
        return path.read_text(encoding="utf-8").strip()
    except FileNotFoundError:
        return (LETTERHEAD_DIR / DEFAULT_LETTERHEAD).read_text(encoding="utf-8").strip()


def get_record_for_export(
    db: Session, user: User, record_id: int, ip: str | None
) -> tuple[MedicalRecord, Patient]:
    record = db.get(MedicalRecord, record_id)
    if record is None:
        raise NotFound
    audit.log_access(db, user, audit.EXPORT_RECORD, ENTITY, record.id, ip)
    return record, record.patient


def export_filename(record: MedicalRecord, fmt: str) -> str:
    return f"benh-an-{record.id}-{record.visit_date:%Y%m%d}.{fmt}"


def render_text(record: MedicalRecord, patient: Patient, letterhead: str, user: User) -> str:
    lines = [
        letterhead,
        "",
        f"PHIẾU KHÁM BỆNH #{record.id}".center(60),
        "",
        f"Bệnh nhân:   {patient.full_name} ({patient.code})",
        f"Ngày sinh:   {date_vn(patient.date_of_birth)}",
        f"Giới tính:   {GENDERS.get(patient.gender, '')}",
        f"Ngày khám:   {date_vn(record.visit_date)}",
        f"Bác sĩ khám: {record.doctor.full_name}",
        "",
        "Triệu chứng:",
        record.symptoms,
        "",
        f"Chẩn đoán:   {record.diagnosis_code} - {record.diagnosis_text}",
        "",
        "Ghi chú:",
        record.notes or "(không có)",
        "",
        f"In lúc {datetime_vn(datetime.now(VN_TZ))} bởi {user.full_name}",
    ]
    return "\n".join(lines) + "\n"
